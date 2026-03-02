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
mod cpu_usage_monitor;
pub mod extra_policy;

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
use cpu_usage_monitor::CpuUsageMonitor;

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
    usage_monitor: CpuUsageMonitor,
    util_cpu0: Option<f64>,
    total_budget_khz: Option<isize>,
}

impl Controller {
    const P0_POLICY: i32 = 0;
    const CPU0_UTIL_TARGET: f64 = 0.95;

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
            usage_monitor: CpuUsageMonitor::new(),
            util_cpu0: None,
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

    pub fn init_game(&mut self, _pid: i32, extension: &Extension) {
        trigger_init_cpu_freq(extension);
        self.reset_all_cpu_freq();
        self.sync_cur_freq_from_hw();
        self.util_cpu0 = None;
        self.total_budget_khz = None;
    }

    pub fn init_default(&mut self, extension: &Extension) {
        trigger_reset_cpu_freq(extension);
        self.reset_all_cpu_freq();
        self.sync_cur_freq_from_hw();
        self.util_cpu0 = None;
        self.total_budget_khz = None;
    }

    pub fn fas_update_freq_weighted(
        &mut self,
        control_ratio: f64,
        is_janked: bool,
        policy_weights: &HashMap<i32, f64>,
    ) {
        let total_budget_khz = self.compute_target_frequencies(control_ratio, is_janked);
        let weighted_freqs = self.distribute_budget(total_budget_khz as f64, policy_weights);

        let sorted_policies = self.sort_policies_topologically();
        let mut constrained_freqs = Self::apply_relative_constraints(
            Self::apply_absolute_constraints(weighted_freqs, &sorted_policies),
            &sorted_policies,
        );
        self.apply_p0_util_guard(&mut constrained_freqs);

        for cpu in &mut self.cpu_infos {
            if let Some(freq) = constrained_freqs.get(&cpu.policy).copied() {
                let _ = cpu.write_freq(freq, &mut self.file_handler);
            }
        }
    }

    fn distribute_budget(
        &self,
        target_total_from_fas: f64,
        weights: &HashMap<i32, f64>,
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
            ws.push(weights.get(&info.policy).copied().unwrap_or(1.0).max(0.0));
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

    fn update_cpu0_util(&mut self) {
        if let Some(snapshot) = self.usage_monitor.update() {
            self.util_cpu0 = Some(snapshot.cpu0_util);
        }
    }

    fn sync_cur_freq_from_hw(&mut self) {
        for cpu in &mut self.cpu_infos {
            let Some(min_freq) = cpu.freqs.first().copied() else {
                continue;
            };
            let Some(max_freq) = cpu.freqs.last().copied() else {
                continue;
            };
            let hw_freq = cpu.read_freq().clamp(min_freq, max_freq);
            cpu.sync_from_hw_freq(hw_freq);
        }
    }

    fn compute_p0_guard_freq_khz(&self) -> Option<isize> {
        let cpu0_util = self.util_cpu0?;
        if cpu0_util <= Self::CPU0_UTIL_TARGET {
            return None;
        }
        let p0_info = self
            .cpu_infos
            .iter()
            .find(|info| info.policy == Self::P0_POLICY)?;
        let min = *p0_info.freqs.first()?;
        let max = *p0_info.freqs.last()?;
        let current = p0_info.cur_fas_freq.clamp(min, max);
        let guarded = ((current as f64) * (cpu0_util / Self::CPU0_UTIL_TARGET)).round() as isize;
        Some(guarded.clamp(min, max))
    }

    fn apply_p0_util_guard(&self, freqs: &mut HashMap<i32, isize>) -> bool {
        let Some(p0_guard) = self.compute_p0_guard_freq_khz() else {
            return false;
        };
        if let Some(p0_target) = freqs.get_mut(&Self::P0_POLICY) {
            let hit = *p0_target < p0_guard;
            *p0_target = (*p0_target).max(p0_guard);
            return hit;
        }
        false
    }

    fn compute_target_frequencies(
        &mut self,
        control_ratio: f64,
        is_janked: bool,
    ) -> isize {
        if self.cpu_infos.is_empty() {
            return 0;
        }

        if !is_janked {
            self.update_cpu0_util();
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
            let cur = cpu.cur_fas_freq.clamp(
                cpu.freqs.first().copied().unwrap_or(cpu.cur_fas_freq),
                cpu.freqs.last().copied().unwrap_or(cpu.cur_fas_freq),
            );
            cur_total = cur_total.saturating_add(cur);
        }

        let base_total = self
            .total_budget_khz
            .unwrap_or(cur_total)
            .clamp(total_min, total_max);

        let bounded_ratio = control_ratio.clamp(-0.8, 1.0);
        let mut target_total = ((base_total as f64) * (1.0 + bounded_ratio)).round() as isize;
        target_total = target_total.clamp(total_min, total_max);

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
        target_total
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
}
