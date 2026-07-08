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
    collections::{HashMap, HashSet},
    sync::{
        Arc, Mutex,
        atomic::{AtomicU64, Ordering},
        mpsc::RecvTimeoutError,
    },
    thread,
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
const CPCS_RECV_TIMEOUT: Duration = Duration::from_millis(150);
const CPCS_STALE_TIMEOUT: Duration = Duration::from_secs(2);
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
    desired: Arc<Mutex<HashSet<i32>>>,
    generation: Arc<AtomicU64>,
    latest: Arc<Mutex<HashMap<i32, TimedCpcsWeights>>>,
    worker: thread::Thread,
}

struct ControllerState {
    controller: Controller,
    params: ControllerParams,
    error_ratio_ema: Option<f64>,
}

#[derive(Clone)]
struct TimedCpcsWeights {
    received_at: Instant,
    data: cpcs_analyzer::PolicyWeights,
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
    cpcs_attached: HashSet<i32>,
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
        let cpcs_state = spawn_cpcs_worker(cpcs_analyzer);
        Self {
            analyzer_state: AnalyzerState {
                analyzer,
                restart_counter: 0,
                restart_timer: Instant::now(),
            },
            cpcs_state,
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
                error_ratio_ema: None,
            },
            cpcs_attached: HashSet::new(),
        }
    }

    pub fn enter_loop(&mut self) -> Result<()> {
        loop {
            self.switch_mode();
            self.update_analyzer();
            self.retain_topapp();

            if self.windows_watcher.visible_freeform_window() {
                self.disable_fas();
            }

            if let Some(data) = self.recv_message() {
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
        }
    }

    fn switch_mode(&mut self) {
        if let Ok(new_mode) = self.node.get_mode()
            && likely(self.fas_state.mode != new_mode)
        {
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

    fn recv_message(&mut self) -> Option<FasData> {
        self.analyzer_state
            .analyzer
            .recv_timeout(Duration::from_millis(100))
            .map(|(pid, frametime)| FasData { pid, frametime })
    }

    fn update_analyzer(&mut self) {
        let mut cpcs_changed = false;
        for pid in self.windows_watcher.topapp_pids().iter().copied() {
            let Ok(pkg) = get_process_name(pid) else {
                continue;
            };

            if !self.config.need_fas(&pkg) {
                continue;
            }

            let _ = self.analyzer_state.analyzer.attach_app(pid);
            if self.cpcs_attached.insert(pid) {
                cpcs_changed = true;
            }
        }

        self.publish_cpcs_targets(cpcs_changed);
    }

    fn cpcs_weights_for(&self, pid: i32) -> Option<cpcs_analyzer::PolicyWeights> {
        let now = Instant::now();
        let latest = self.cpcs_state.latest.lock().ok()?;
        let item = latest.get(&pid)?;
        if now.duration_since(item.received_at) > CPCS_STALE_TIMEOUT {
            drop(latest);
            return None;
        }
        let data = item.data.clone();
        drop(latest);
        Some(data)
    }

    fn restart_analyzer(&mut self) {
        if self.analyzer_state.restart_counter == 1 {
            if self.analyzer_state.restart_timer.elapsed() >= Duration::from_secs(1) {
                self.analyzer_state.restart_timer = Instant::now();
                self.analyzer_state.restart_counter = 0;
                self.analyzer_state.analyzer.detach_apps();
                self.update_analyzer();
            }
        } else {
            self.analyzer_state.restart_counter += 1;
        }
    }

    fn do_policy(&mut self) {
        if unlikely(self.fas_state.working_state != State::Working) {
            return;
        }

        let (pid, control_ratio, is_janked) = if let Some(buffer) = &self.fas_state.buffer {
            let target_fps_offset = self
                .therminal
                .target_fps_offset(&mut self.config, self.fas_state.mode);
            let result = calculate_control(
                buffer,
                &mut self.config,
                self.fas_state.mode,
                &mut self.controller_state,
                target_fps_offset,
            );
            let result = result.unwrap_or(ControlOutput {
                control_ratio: 0.0,
                is_janked: false,
            });
            (
                buffer.package_info.pid,
                result.control_ratio,
                result.is_janked,
            )
        } else {
            return;
        };

        let Some(cpcs) = self.cpcs_weights_for(pid) else {
            return;
        };
        let weights = &cpcs.policy_weights;

        self.controller_state.controller.fas_update_freq_weighted(
            control_ratio,
            is_janked,
            weights,
        );
    }

    pub fn retain_topapp(&mut self) {
        self.prune_stale_cpcs_attachments();

        let stale_buffer = self
            .fas_state
            .buffer
            .as_ref()
            .filter(|buffer| {
                !self
                    .windows_watcher
                    .topapp_pids()
                    .contains(&buffer.package_info.pid)
            })
            .map(|buffer| (buffer.package_info.pid, buffer.package_info.pkg.clone()));
        if let Some((pid, pkg)) = stale_buffer {
            let _ = self.analyzer_state.analyzer.detach_app(pid);
            let cpcs_changed = self.cpcs_attached.remove(&pid);
            self.publish_cpcs_targets(cpcs_changed);
            trigger_unload_fas(&self.extension, pid, pkg);
            self.fas_state.buffer = None;
        }

        if self.fas_state.buffer.is_none() {
            self.disable_fas();
        } else if self
            .fas_state
            .buffer
            .as_ref()
            .is_some_and(|buffer| buffer.state.working_state == BufferWorkingState::Unusable)
        {
            // Keep FAS disabled while the frame buffer is still warming up or
            // temporarily invalid. This avoids NotWorking<->Waiting thrash.
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

    fn prune_stale_cpcs_attachments(&mut self) {
        let topapps: HashSet<i32> = self.windows_watcher.topapp_pids().iter().copied().collect();
        let stale: Vec<i32> = self
            .cpcs_attached
            .iter()
            .copied()
            .filter(|pid| !topapps.contains(pid))
            .collect();

        let mut changed = false;
        for pid in stale {
            if self.cpcs_attached.remove(&pid) {
                changed = true;
            }
        }
        self.publish_cpcs_targets(changed);
    }

    fn publish_cpcs_targets(&self, changed: bool) {
        if !changed {
            return;
        }

        if let Ok(mut desired) = self.cpcs_state.desired.lock() {
            (*desired).clone_from(&self.cpcs_attached);
        }
        self.cpcs_state.generation.fetch_add(1, Ordering::Release);
        self.cpcs_state.worker.unpark();
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

fn spawn_cpcs_worker(analyzer: CpcsAnalyzer) -> CpcsState {
    let desired = Arc::new(Mutex::new(HashSet::new()));
    let generation = Arc::new(AtomicU64::new(0));
    let latest = Arc::new(Mutex::new(HashMap::new()));
    let desired_worker = Arc::clone(&desired);
    let generation_worker = Arc::clone(&generation);
    let latest_worker = Arc::clone(&latest);

    let worker = thread::Builder::new()
        .name("cpcs".to_string())
        .spawn(move || {
            cpcs_worker_loop(analyzer, desired_worker, generation_worker, latest_worker);
        })
        .expect("failed to spawn cpcs worker")
        .thread()
        .clone();

    CpcsState {
        desired,
        generation,
        latest,
        worker,
    }
}

#[allow(clippy::needless_pass_by_value)]
fn cpcs_worker_loop(
    mut analyzer: CpcsAnalyzer,
    desired: Arc<Mutex<HashSet<i32>>>,
    generation: Arc<AtomicU64>,
    latest: Arc<Mutex<HashMap<i32, TimedCpcsWeights>>>,
) {
    let mut attached = HashSet::new();
    let mut applied_generation = u64::MAX;

    loop {
        let latest_generation = generation.load(Ordering::Acquire);
        if latest_generation != applied_generation {
            reconcile_cpcs_targets(&mut analyzer, &desired, &latest, &mut attached);
            applied_generation = latest_generation;
        }

        if attached.is_empty() {
            thread::park_timeout(Duration::from_millis(250));
            continue;
        }

        match analyzer.recv_timeout(CPCS_RECV_TIMEOUT) {
            Ok((pid, weights)) => {
                if let Ok(mut guard) = latest.lock() {
                    guard.insert(
                        pid,
                        TimedCpcsWeights {
                            received_at: Instant::now(),
                            data: weights,
                        },
                    );
                    guard.retain(|_, item| item.received_at.elapsed() <= CPCS_STALE_TIMEOUT);
                }
            }
            Err(RecvTimeoutError::Timeout) => {}
            Err(RecvTimeoutError::Disconnected) => {
                warn!("cpcs worker recv disconnected");
                return;
            }
        }
    }
}

fn reconcile_cpcs_targets(
    analyzer: &mut CpcsAnalyzer,
    desired: &Arc<Mutex<HashSet<i32>>>,
    latest: &Arc<Mutex<HashMap<i32, TimedCpcsWeights>>>,
    attached: &mut HashSet<i32>,
) {
    let desired_snapshot = desired
        .lock()
        .map_or_else(|_| HashSet::new(), |set| set.clone());

    let stale: Vec<i32> = attached
        .iter()
        .copied()
        .filter(|pid| !desired_snapshot.contains(pid))
        .collect();
    for pid in stale {
        attached.remove(&pid);
        if let Err(e) = analyzer.detach_app(pid) {
            warn!("cpcs worker detach failed pid={pid}: {e:#}");
        }
        if let Ok(mut guard) = latest.lock() {
            guard.remove(&pid);
        }
    }

    for pid in desired_snapshot {
        if attached.insert(pid)
            && let Err(e) = analyzer.attach_app(pid)
        {
            warn!("cpcs worker attach failed pid={pid}: {e:#}");
            attached.remove(&pid);
            if let Ok(mut guard) = latest.lock() {
                guard.remove(&pid);
            }
        }
    }

    let live: HashSet<i32> = analyzer.pids().collect();
    if *attached != live {
        attached.clone_from(&live);
    }
    if let Ok(mut guard) = latest.lock() {
        guard.retain(|pid, _| live.contains(pid));
    }
}
