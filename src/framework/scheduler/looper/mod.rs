// Copyright 2024-2025, dependabot[bot], shadow3aaa
//
// This file is part of fas-rs.
//
// fas-rs is free software: you can redistribute it and/or modify it under
// the terms of the GNU General Public License as published by the Free
// Software Foundation, either version 3 of the License, or (at your option)
// any later version.
//
// fas-rs is distributed in the hope that it will be useful, but WITHOUT ANY
// WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
// FOR A PARTICULAR PURPOSE. See the GNU General Public License for more
// details.
//
// You should have received a copy of the GNU General Public License along
// with fas-rs. If not, see <https://www.gnu.org/licenses/>.

mod buffer;
mod clean;
mod policy;

use std::{
    sync::mpsc::RecvTimeoutError,
    time::{Duration, Instant},
};

use buffer::{Buffer, BufferWorkingState};
use clean::Cleaner;
use cpcs_analyzer::Analyzer as CpcsAnalyzer;
use frame_analyzer::Analyzer;
use likely_stable::{likely, unlikely};
#[cfg(debug_assertions)]
use log::debug;
use log::{info, warn};
use policy::{ControlOutput, ControllerParams, controll::calculate_control};

use super::{FasData, thermal::Thermal, topapp::TopAppsWatcher};
use crate::{
    Controller,
    api::{trigger_load_fas, trigger_start_fas, trigger_stop_fas, trigger_unload_fas},
    framework::{
        Extension,
        config::Config,
        error::Result,
        node::{Mode, Node},
        pid_utils::get_process_name,
    },
};

const DELAY_TIME: Duration = Duration::from_secs(3);
const CPCS_ENABLED: bool = true;

#[derive(PartialEq, Debug)]
enum State {
    NotWorking,
    Waiting,
    Working,
}

struct FasState {
    mode: Mode,
    working_state: State,
    delay_timer: Instant,
    buffer: Option<Buffer>,
}

struct AnalyzerState {
    analyzer: Analyzer,
    restart_counter: u8,
    restart_timer: Instant,
}

struct CpcsState {
    analyzer: CpcsAnalyzer,
    last_missing_log: Instant,
}

struct ControllerState {
    controller: Controller,
    params: ControllerParams,
    target_fps_offset: f64,
    usage_sample_timer: Instant,
    error_ratio_ema: Option<f64>,
}

struct DiagState {
    last_log: Instant,
    frame_events: u64,
    cpcs_updates: u64,
    policy_calls: u64,
}

pub struct Looper {
    analyzer_state: AnalyzerState,
    cpcs_state: CpcsState,
    config: Config,
    node: Node,
    extension: Extension,
    therminal: Thermal,
    windows_watcher: TopAppsWatcher,
    cleaner: Cleaner,
    fas_state: FasState,
    controller_state: ControllerState,
    diag_state: DiagState,
}

impl Looper {
    pub fn new(
        analyzer: Analyzer,
        cpcs_analyzer: CpcsAnalyzer,
        config: Config,
        node: Node,
        extension: Extension,
        controller: Controller,
    ) -> Self {
        if !CPCS_ENABLED {
            info!("CPCS integration temporarily disabled");
        }

        Self {
            analyzer_state: AnalyzerState {
                analyzer,
                restart_counter: 0,
                restart_timer: Instant::now(),
            },
            cpcs_state: CpcsState {
                analyzer: cpcs_analyzer,
                last_missing_log: Instant::now(),
            },
            config,
            node,
            extension,
            therminal: Thermal::new().unwrap(),
            windows_watcher: TopAppsWatcher::new(),
            cleaner: Cleaner::new(),
            fas_state: FasState {
                mode: Mode::Balance,
                buffer: None,
                working_state: State::NotWorking,
                delay_timer: Instant::now(),
            },
            controller_state: ControllerState {
                controller,
                params: ControllerParams::default(),
                target_fps_offset: 0.0,
                usage_sample_timer: Instant::now(),
                error_ratio_ema: None,
            },
            diag_state: DiagState {
                last_log: Instant::now(),
                frame_events: 0,
                cpcs_updates: 0,
                policy_calls: 0,
            },
        }
    }

    pub fn enter_loop(&mut self) -> Result<()> {
        loop {
            self.switch_mode();
            if let Err(e) = self.update_analyzer() {
                warn!("update analyzer failed: {e:#}");
            }
            self.diag_state.cpcs_updates = self
                .diag_state
                .cpcs_updates
                .saturating_add(self.refresh_cpcs_weights() as u64);
            self.retain_topapp();

            if self.windows_watcher.visible_freeform_window() {
                self.disable_fas();
            }

            if let Some(data) = self.recv_message() {
                self.diag_state.frame_events = self.diag_state.frame_events.saturating_add(1);
                #[cfg(debug_assertions)]
                debug!("original frametime: {:?}", data.frametime);
                if let Some(state) = self.buffer_update(&data) {
                    match state {
                        BufferWorkingState::Usable => self.do_policy(),
                        BufferWorkingState::Unusable => self.disable_fas(),
                    }
                }
            } else if let Some(buffer) = self.fas_state.buffer.as_mut() {
                #[cfg(debug_assertions)]
                debug!("janked !");
                buffer.additional_frametime(&self.extension);

                match buffer.state.working_state {
                    BufferWorkingState::Unusable => {
                        self.restart_analyzer();
                        self.disable_fas();
                    }
                    BufferWorkingState::Usable => self.do_policy(),
                }
            }

            self.emit_diagnostics_if_needed();
        }
    }

    fn switch_mode(&mut self) {
        if let Ok(new_mode) = self.node.get_mode() {
            if likely(self.fas_state.mode != new_mode) {
                info!("Switch mode: {} -> {}", self.fas_state.mode, new_mode);
                self.fas_state.mode = new_mode;

                if self.fas_state.working_state == State::Working {
                    self.controller_state.controller.init_game(
                        self.fas_state.buffer.as_ref().unwrap().package_info.pid,
                        &self.extension,
                    );
                    self.controller_state.error_ratio_ema = None;
                }
            }
        }
    }

    fn recv_message(&mut self) -> Option<FasData> {
        self.analyzer_state
            .analyzer
            .recv_timeout(Duration::from_millis(100))
            .map(|(pid, frametime)| FasData { pid, frametime })
    }

    fn update_analyzer(&mut self) -> Result<()> {
        for pid in self.windows_watcher.topapp_pids().iter().copied() {
            let pkg = get_process_name(pid)?;
            if self.config.need_fas(&pkg) {
                self.analyzer_state.analyzer.attach_app(pid)?;
                if CPCS_ENABLED {
                    self.cpcs_state.analyzer.attach_app(pid)?;
                }
            }
        }
        Ok(())
    }

    fn refresh_cpcs_weights(&mut self) -> usize {
        if !CPCS_ENABLED {
            return 0;
        }

        let mut updates = 0usize;
        loop {
            match self
                .cpcs_state
                .analyzer
                .recv_timeout(Duration::from_millis(0))
            {
                Ok(_) => updates = updates.saturating_add(1),
                Err(RecvTimeoutError::Timeout) => break,
                Err(RecvTimeoutError::Disconnected) => {
                    warn!("cpcs analyzer disconnected");
                    break;
                }
            }
        }
        updates
    }

    fn restart_analyzer(&mut self) {
        if self.analyzer_state.restart_counter == 1 {
            if self.analyzer_state.restart_timer.elapsed() >= Duration::from_secs(1) {
                self.analyzer_state.restart_timer = Instant::now();
                self.analyzer_state.restart_counter = 0;
                self.analyzer_state.analyzer.detach_apps();
                let _ = self.update_analyzer();
            }
        } else {
            self.analyzer_state.restart_counter += 1;
        }
    }

    fn do_policy(&mut self) {
        if unlikely(self.fas_state.working_state != State::Working) {
            #[cfg(debug_assertions)]
            debug!("Not running policy!");
            return;
        }

        let (
            pid,
            control_ratio,
            is_janked,
            adjusted_target_fps,
            target_fps_offset,
            fps_short,
            fps_long,
            norm_frame_ms,
            norm_error_ms,
            norm_error_ratio,
            norm_error_ratio_smooth,
        ) = if let Some(buffer) = &self.fas_state.buffer {
            let target_fps_offset = self
                .therminal
                .target_fps_offset(&mut self.config, self.fas_state.mode);
            let result = calculate_control(
                buffer,
                &mut self.config,
                self.fas_state.mode,
                &mut self.controller_state,
                target_fps_offset,
            )
            .unwrap_or(ControlOutput {
                control_ratio: 0.0,
                is_janked: false,
                adjusted_target_fps: 0.0,
                target_fps_offset: 0.0,
                normalized_frame_ms: 1000.0,
                normalized_error_ms: 0.0,
                normalized_error_ratio: 0.0,
                normalized_error_ratio_smooth: 0.0,
            });
            (
                buffer.package_info.pid,
                result.control_ratio,
                result.is_janked,
                Some(result.adjusted_target_fps),
                Some(result.target_fps_offset),
                Some(buffer.frametime_state.current_fps_short),
                Some(buffer.frametime_state.current_fps_long),
                Some(result.normalized_frame_ms),
                Some(result.normalized_error_ms),
                Some(result.normalized_error_ratio),
                Some(result.normalized_error_ratio_smooth),
            )
        } else {
            return;
        };

        #[cfg(debug_assertions)]
        debug!("control_ratio: {control_ratio:.4}");

        let weights = if CPCS_ENABLED {
            let weights = self
                .cpcs_state
                .analyzer
                .latest_for(pid)
                .map(|weights| &weights.policy_weights);
            if weights.is_none()
                && self.cpcs_state.last_missing_log.elapsed() >= Duration::from_secs(1)
            {
                self.cpcs_state.last_missing_log = Instant::now();
                warn!("cpcs weights unavailable for pid={pid}");
            }
            weights
        } else {
            None
        };

        self.controller_state.controller.fas_update_freq_weighted(
            control_ratio,
            is_janked,
            weights,
            adjusted_target_fps,
            target_fps_offset,
            fps_short,
            fps_long,
            norm_frame_ms,
            norm_error_ms,
            norm_error_ratio,
            norm_error_ratio_smooth,
        );
        self.diag_state.policy_calls = self.diag_state.policy_calls.saturating_add(1);
    }

    fn emit_diagnostics_if_needed(&mut self) {
        if self.diag_state.last_log.elapsed() < Duration::from_secs(5) {
            return;
        }

        let frame_events = self.diag_state.frame_events;
        let cpcs_updates = self.diag_state.cpcs_updates;
        let policy_calls = self.diag_state.policy_calls;
        self.diag_state.last_log = Instant::now();
        self.diag_state.frame_events = 0;
        self.diag_state.cpcs_updates = 0;
        self.diag_state.policy_calls = 0;

        let topapps = self.windows_watcher.topapp_pids().len();
        let frame_analyzer_attached = self.analyzer_state.analyzer.pids().count();
        let cpcs_attached = if CPCS_ENABLED {
            self.cpcs_state.analyzer.pids().count()
        } else {
            0
        };

        if let Some(buffer) = self.fas_state.buffer.as_ref() {
            info!(
                "diag state={:?} topapps={} frame_attached={} cpcs_attached={} frame_events_5s={} cpcs_updates_5s={} policy_calls_5s={} buf_state={:?} target_fps={:?} fps_short={:.1} fps_long={:.1} frames_cached={}",
                self.fas_state.working_state,
                topapps,
                frame_analyzer_attached,
                cpcs_attached,
                frame_events,
                cpcs_updates,
                policy_calls,
                buffer.state.working_state,
                buffer.target_fps_state.target_fps,
                buffer.frametime_state.current_fps_short,
                buffer.frametime_state.current_fps_long,
                buffer.frametime_state.frametimes.len()
            );
        } else {
            info!(
                "diag state={:?} topapps={} frame_attached={} cpcs_attached={} frame_events_5s={} cpcs_updates_5s={} policy_calls_5s={} no_buffer",
                self.fas_state.working_state,
                topapps,
                frame_analyzer_attached,
                cpcs_attached,
                frame_events,
                cpcs_updates,
                policy_calls
            );
        }
    }

    pub fn retain_topapp(&mut self) {
        if let Some(buffer) = self.fas_state.buffer.as_ref() {
            if !self
                .windows_watcher
                .topapp_pids()
                .contains(&buffer.package_info.pid)
            {
                let _ = self
                    .analyzer_state
                    .analyzer
                    .detach_app(buffer.package_info.pid);
                if CPCS_ENABLED {
                    let _ = self.cpcs_state.analyzer.detach_app(buffer.package_info.pid);
                }
                let pkg = buffer.package_info.pkg.clone();
                trigger_unload_fas(&self.extension, buffer.package_info.pid, pkg);
                self.fas_state.buffer = None;
            }
        }

        if self.fas_state.buffer.is_none() {
            self.disable_fas();
        } else {
            self.enable_fas();
        }
    }

    pub fn disable_fas(&mut self) {
        match self.fas_state.working_state {
            State::Working => {
                self.fas_state.working_state = State::NotWorking;
                self.cleaner.undo_cleanup();
                self.controller_state
                    .controller
                    .init_default(&self.extension);
                self.controller_state.error_ratio_ema = None;
                trigger_stop_fas(&self.extension);
            }
            State::Waiting => self.fas_state.working_state = State::NotWorking,
            State::NotWorking => (),
        }
    }

    pub fn enable_fas(&mut self) {
        match self.fas_state.working_state {
            State::NotWorking => {
                self.fas_state.working_state = State::Waiting;
                self.fas_state.delay_timer = Instant::now();
                trigger_start_fas(&self.extension);
            }
            State::Waiting => {
                if self.fas_state.delay_timer.elapsed() > DELAY_TIME {
                    self.fas_state.working_state = State::Working;
                    self.cleaner.cleanup();
                    self.controller_state.target_fps_offset = 0.0;
                    self.controller_state.error_ratio_ema = None;
                    self.controller_state.controller.init_game(
                        self.fas_state.buffer.as_ref().unwrap().package_info.pid,
                        &self.extension,
                    );
                }
            }
            State::Working => (),
        }
    }

    pub fn buffer_update(&mut self, data: &FasData) -> Option<BufferWorkingState> {
        if unlikely(
            !self.windows_watcher.topapp_pids().contains(&data.pid) || data.frametime.is_zero(),
        ) {
            return None;
        }

        let pid = data.pid;
        let frametime = data.frametime;

        if let Some(buffer) = self.fas_state.buffer.as_mut() {
            buffer.push_frametime(frametime, &self.extension);
            Some(buffer.state.working_state)
        } else {
            let Ok(pkg) = get_process_name(data.pid) else {
                return None;
            };
            let target_fps = self.config.target_fps(&pkg)?;

            info!("New fas buffer on: [{pkg}]");

            trigger_load_fas(&self.extension, pid, pkg.clone());

            let mut buffer = Buffer::new(target_fps, pid, pkg);
            buffer.push_frametime(frametime, &self.extension);

            self.fas_state.buffer = Some(buffer);

            Some(BufferWorkingState::Unusable)
        }
    }
}
