// Copyright 2023-2025, dependabot[bot], shadow3, shadow3aaa
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

mod cpu_info;
pub mod extra_policy;
mod process_monitor;

use std::{
    collections::HashMap,
    fs,
    path::Path,
    sync::{OnceLock, atomic::AtomicBool},
    thread,
    time::Duration,
};

use anyhow::{Context, Result};
use cpu_info::Info;
use extra_policy::ExtraPolicy;
#[cfg(debug_assertions)]
use log::debug;
use log::warn;
use parking_lot::Mutex;
use process_monitor::ProcessMonitor;

use crate::{
    Extension,
    api::{trigger_init_cpu_freq, trigger_reset_cpu_freq},
    file_handler::FileHandler,
};

pub static EXTRA_POLICY_MAP: OnceLock<HashMap<i32, Mutex<ExtraPolicy>>> = OnceLock::new();
pub static IGNORE_MAP: OnceLock<HashMap<i32, AtomicBool>> = OnceLock::new();

#[derive(Debug)]
pub struct Controller {
    cpu_infos: Vec<Info>,
    file_handler: FileHandler,
    process_monitor: ProcessMonitor,
    util_max: Option<f64>,
    total_budget_khz: Option<isize>,
}

impl Controller {
    pub fn new() -> Result<Self> {
        let mut cpu_infos = Self::load_cpu_infos()?;
        cpu_infos.sort_by_key(|cpu| cpu.policy);

        EXTRA_POLICY_MAP.get_or_init(|| {
            cpu_infos
                .iter()
                .map(|cpu| (cpu.policy, Mutex::new(ExtraPolicy::None)))
                .collect()
        });
        IGNORE_MAP.get_or_init(|| {
            cpu_infos
                .iter()
                .map(|cpu| (cpu.policy, AtomicBool::new(false)))
                .collect()
        });

        #[cfg(debug_assertions)]
        debug!("cpu infos: {cpu_infos:?}");

        Ok(Self {
            cpu_infos,
            file_handler: FileHandler::new(),
            process_monitor: ProcessMonitor::new(),
            util_max: None,
            total_budget_khz: None,
        })
    }

    fn load_cpu_infos() -> Result<Vec<Info>> {
        let mut cpu_infos = Vec::new();

        for entry in fs::read_dir("/sys/devices/system/cpu/cpufreq")? {
            let path = match entry {
                Ok(entry) => entry.path(),
                Err(e) => {
                    warn!("Failed to read entry: {e:?}");
                    continue;
                }
            };

            if !path.is_dir() {
                continue;
            }

            let Some(filename) = path.file_name().and_then(|s| s.to_str()) else {
                continue;
            };

            if !filename.starts_with("policy") {
                continue;
            }

            cpu_infos.push(Self::retry_load_info(&path));
        }

        Ok(cpu_infos)
    }

    fn retry_load_info(path: &Path) -> Info {
        loop {
            match Info::new(path) {
                Ok(info) => return info,
                Err(e) => {
                    warn!(
                        "Failed to read cpu info from: {}, reason: {e:?}",
                        path.display()
                    );
                    warn!("Retrying...");
                    thread::sleep(Duration::from_secs(1));
                }
            }
        }
    }

    pub fn init_game(&mut self, pid: i32, extension: &Extension) {
        trigger_init_cpu_freq(extension);
        self.reset_all_cpu_freq();
        self.process_monitor.set_pid(Some(pid));
        self.util_max = None;
        self.total_budget_khz = None;
    }

    pub fn init_default(&mut self, extension: &Extension) {
        trigger_reset_cpu_freq(extension);
        self.reset_all_cpu_freq();
        self.process_monitor.set_pid(None);
        self.util_max = None;
        self.total_budget_khz = None;
    }

    pub fn fas_update_freq_weighted(
        &mut self,
        control_ratio: f64,
        is_janked: bool,
        policy_weights: Option<&HashMap<i32, f64>>,
        adjusted_target_fps: Option<f64>,
        target_fps_offset: Option<f64>,
        fps_short: Option<f64>,
        fps_long: Option<f64>,
        normalized_frame_ms: Option<f64>,
        normalized_error_ms: Option<f64>,
        normalized_error_ratio: Option<f64>,
        normalized_error_ratio_smooth: Option<f64>,
    ) {
        let _ = (
            adjusted_target_fps,
            target_fps_offset,
            fps_short,
            fps_long,
            normalized_frame_ms,
            normalized_error_ms,
            normalized_error_ratio,
            normalized_error_ratio_smooth,
        );

        let (base_freqs, total_budget_khz, util_cap_hit) =
            self.compute_target_frequencies(control_ratio, is_janked);
        let weighted_freqs = if let Some(weights) = policy_weights {
            self.distribute_budget(total_budget_khz as f64, Some(weights))
        } else {
            base_freqs.clone()
        };
        let sorted_policies = self.sort_policies_topologically();
        let constrained_freqs = Self::apply_relative_constraints(
            Self::apply_absolute_constraints(weighted_freqs, &sorted_policies),
            &sorted_policies,
        );

        // Keep legacy no-extra-policy clamp for non-CPCS path.
        // When CPCS weights are available, preserve inter-policy skew so
        // critical-path weighting can take effect.
        let write_freqs = if no_extra_policy() && policy_weights.is_none() {
            let fas_freq_max = constrained_freqs
                .values()
                .max()
                .copied()
                .unwrap_or_default();
            constrained_freqs
                .iter()
                .map(|(policy, freq)| {
                    let freq = *freq;
                    (
                        *policy,
                        freq.clamp(
                            fas_freq_max.saturating_sub(100_000),
                            fas_freq_max.saturating_add(100_000),
                        ),
                    )
                })
                .collect::<HashMap<_, _>>()
        } else {
            constrained_freqs.clone()
        };
        let _ = (
            control_ratio,
            total_budget_khz,
            util_cap_hit,
            policy_weights,
            base_freqs,
        );

        for cpu in &mut self.cpu_infos {
            if let Some(freq) = write_freqs.get(&cpu.policy).copied() {
                let _ = cpu.write_freq(freq, &mut self.file_handler);
            }
        }
    }

    fn distribute_budget(
        &self,
        target_total_from_fas: f64,
        weights: Option<&HashMap<i32, f64>>,
    ) -> HashMap<i32, isize> {
        let mut out = HashMap::new();
        if self.cpu_infos.is_empty() {
            return out;
        }

        let mut policies = Vec::with_capacity(self.cpu_infos.len());
        let mut mins = Vec::with_capacity(self.cpu_infos.len());
        let mut maxs = Vec::with_capacity(self.cpu_infos.len());
        let mut caps = Vec::with_capacity(self.cpu_infos.len());
        let mut alloc = Vec::with_capacity(self.cpu_infos.len());
        let mut ws = Vec::with_capacity(self.cpu_infos.len());

        for info in &self.cpu_infos {
            let Some(min_freq) = info.freqs.first().copied() else {
                continue;
            };
            let Some(max_freq) = info.freqs.last().copied() else {
                continue;
            };

            policies.push(info.policy);
            mins.push(min_freq as f64);
            maxs.push(max_freq as f64);
            caps.push(max_freq.saturating_sub(min_freq).max(0) as f64);
            alloc.push(0.0);
            ws.push(
                weights
                    .and_then(|w| w.get(&info.policy).copied())
                    .unwrap_or(1.0)
                    .max(0.0),
            );
        }
        if policies.is_empty() {
            return out;
        }

        let total_min = mins.iter().sum::<f64>();
        let total_max = maxs.iter().sum::<f64>();
        let target_total = target_total_from_fas.clamp(total_min, total_max);
        let mut remaining_budget = (target_total - total_min).max(0.0);
        if remaining_budget <= f64::EPSILON {
            for idx in 0..policies.len() {
                out.insert(policies[idx], mins[idx].round() as isize);
            }
            return out;
        }

        let total_weight = ws.iter().sum::<f64>();
        if total_weight <= f64::EPSILON {
            ws.fill(1.0);
        }

        let mut active: Vec<usize> = (0..policies.len()).collect();

        while remaining_budget > f64::EPSILON && !active.is_empty() {
            let active_weight_sum = active.iter().map(|idx| ws[*idx]).sum::<f64>();

            let mut distributed = 0.0f64;
            let mut next_active = Vec::with_capacity(active.len());
            for idx in active.iter().copied() {
                let available = caps[idx] - alloc[idx];
                if available <= f64::EPSILON {
                    continue;
                }

                let share = if active_weight_sum <= f64::EPSILON {
                    remaining_budget / active.len() as f64
                } else {
                    remaining_budget * (ws[idx] / active_weight_sum)
                };
                let give = share.min(available);
                if give <= f64::EPSILON {
                    continue;
                }

                alloc[idx] += give;
                distributed += give;

                if caps[idx] - alloc[idx] > f64::EPSILON {
                    next_active.push(idx);
                }
            }

            if distributed <= f64::EPSILON {
                break;
            }
            remaining_budget -= distributed;
            active = next_active;
        }

        for idx in 0..policies.len() {
            let target = (mins[idx] + alloc[idx]).round() as isize;
            out.insert(policies[idx], target);
        }

        out
    }

    fn update_util_max(&mut self) {
        if let Some(util_max) = self.process_monitor.update() {
            self.util_max = Some(util_max);
        }
    }

    fn compute_target_frequencies(
        &mut self,
        control_ratio: f64,
        is_janked: bool,
    ) -> (HashMap<i32, isize>, isize, bool) {
        if self.cpu_infos.is_empty() {
            return (HashMap::new(), 0, false);
        }

        if !is_janked {
            self.update_util_max();
        }

        let mut total_min = 0isize;
        let mut total_max = 0isize;
        let mut cur_total = 0isize;
        for cpu in &self.cpu_infos {
            if let Some(min_freq) = cpu.freqs.first().copied() {
                total_min = total_min.saturating_add(min_freq);
            }
            if let Some(max_freq) = cpu.freqs.last().copied() {
                total_max = total_max.saturating_add(max_freq);
            }
            cur_total = cur_total.saturating_add(cpu.read_freq());
        }

        let base_total = self
            .total_budget_khz
            .unwrap_or(cur_total)
            .clamp(total_min, total_max);

        let bounded_ratio = control_ratio.clamp(-0.8, 1.0);
        let mut target_total = ((base_total as f64) * (1.0 + bounded_ratio)).round() as isize;
        target_total = target_total.clamp(total_min, total_max);

        let mut util_cap_hit = false;
        // util guard: only apply an upper bound when under-utilized.
        // If util < 50%, we consider additional boost wasteful and block further
        // upward movement beyond current frequency.
        if let Some(util_max) = self.util_max {
            if util_max < 0.5 {
                let util_cap = cur_total.clamp(total_min, total_max);
                util_cap_hit = target_total > util_cap;
                target_total = target_total.min(util_cap);
            }
        }

        // Symmetric slew limiter on total budget.
        if let Some(prev) = self.total_budget_khz {
            const MAX_STEP_RATIO: f64 = 0.10;
            const MIN_STEP_KHZ_PER_POLICY: isize = 30_000;
            let policy_count = self.cpu_infos.len().max(1) as isize;
            let min_step = MIN_STEP_KHZ_PER_POLICY.saturating_mul(policy_count);
            let step = ((prev as f64) * MAX_STEP_RATIO).round() as isize;
            let step = step.max(min_step);
            let lo = prev.saturating_sub(step);
            let hi = prev.saturating_add(step);
            target_total = target_total.clamp(lo, hi).clamp(total_min, total_max);
        }
        self.total_budget_khz = Some(target_total);

        let base_freqs = self.distribute_budget(target_total as f64, None);
        (base_freqs, target_total, util_cap_hit)
    }

    fn sort_policies_topologically(&self) -> Vec<i32> {
        let mut graph: HashMap<_, Vec<_>> = HashMap::new();
        let mut indegree: HashMap<_, _> = HashMap::new();

        for cpu in &self.cpu_infos {
            let policy = cpu.policy;

            if let ExtraPolicy::RelRangeBound(ref rel_bound) = *EXTRA_POLICY_MAP
                .get()
                .context("EXTRA_POLICY_MAP not initialized")
                .unwrap()
                .get(&policy)
                .context("CPU Policy not found")
                .unwrap()
                .lock()
            {
                graph.entry(rel_bound.rel_to).or_default().push(policy);
                *indegree.entry(policy).or_insert(0) += 1;
            }

            indegree.entry(policy).or_insert(0);
        }

        let mut queue: Vec<_> = indegree
            .iter()
            .filter(|&(_, &deg)| deg == 0)
            .map(|(&policy, _)| policy)
            .collect();
        let mut sorted_policies = Vec::new();

        while let Some(policy) = queue.pop() {
            sorted_policies.push(policy);
            if let Some(dependents) = graph.get(&policy) {
                for &dependent in dependents {
                    if let Some(deg) = indegree.get_mut(&dependent) {
                        *deg -= 1;
                        if *deg == 0 {
                            queue.push(dependent);
                        }
                    }
                }
            }
        }

        assert!(
            (sorted_policies.len() >= indegree.len()),
            "Circular dependency detected in CPU policies"
        );

        sorted_policies
    }

    fn apply_absolute_constraints(
        mut fas_freqs: HashMap<i32, isize>,
        sorted_policies: &[i32],
    ) -> HashMap<i32, isize> {
        for policy in sorted_policies {
            if let Some(freq) = fas_freqs.get(policy).copied() {
                if let ExtraPolicy::AbsRangeBound(ref abs_bound) = *EXTRA_POLICY_MAP
                    .get()
                    .context("EXTRA_POLICY_MAP not initialized")
                    .unwrap()
                    .get(policy)
                    .context("CPU Policy not found")
                    .unwrap()
                    .lock()
                {
                    let clamped_freq = freq.clamp(
                        abs_bound.min.unwrap_or(0),
                        abs_bound.max.unwrap_or(isize::MAX),
                    );
                    fas_freqs.insert(*policy, clamped_freq);
                }
            }
        }

        fas_freqs
    }

    fn apply_relative_constraints(
        mut fas_freqs: HashMap<i32, isize>,
        sorted_policies: &[i32],
    ) -> HashMap<i32, isize> {
        for policy in sorted_policies {
            if let Some(freq) = fas_freqs.get(policy).copied() {
                let adjusted_freq = match *EXTRA_POLICY_MAP
                    .get()
                    .context("EXTRA_POLICY_MAP not initialized")
                    .unwrap()
                    .get(policy)
                    .context("CPU Policy not found")
                    .unwrap()
                    .lock()
                {
                    ExtraPolicy::RelRangeBound(ref rel_bound) => {
                        let rel_to_freq = fas_freqs.get(&rel_bound.rel_to).copied().unwrap_or(0);

                        #[cfg(debug_assertions)]
                        debug!("policy{policy} rel_to {rel_to_freq}");

                        freq.clamp(
                            rel_to_freq + rel_bound.min.unwrap_or(isize::MIN),
                            rel_to_freq + rel_bound.max.unwrap_or(isize::MAX),
                        )
                    }
                    _ => freq,
                };

                #[cfg(debug_assertions)]
                debug!("policy{policy} freq after relative bound: {adjusted_freq}");

                fas_freqs.insert(*policy, adjusted_freq);
            }
        }

        fas_freqs
    }

    fn reset_all_cpu_freq(&mut self) {
        for cpu in &mut self.cpu_infos {
            let _ = cpu.reset(&mut self.file_handler);
        }
    }

    pub fn util_max(&self) -> f64 {
        self.util_max.unwrap_or_default()
    }
}

fn no_extra_policy() -> bool {
    EXTRA_POLICY_MAP
        .get()
        .context("EXTRA_POLICY_MAP not initialized")
        .unwrap()
        .values()
        .all(|policy| *policy.lock() == ExtraPolicy::None)
}
