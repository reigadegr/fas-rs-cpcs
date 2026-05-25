// Copyright 2025-2025, shadow3, shadow3aaa
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
use std::{
    fs,
    time::{Duration, Instant},
};

use anyhow::Result;

#[derive(Debug, Clone, Copy)]
pub struct UsageSnapshot {
    pub cpu1_util: f64,
}

#[derive(Debug, Clone, Copy)]
struct CpuUsageTracker {
    cpu_label: &'static str,
    last_busy: u64,
    last_total: u64,
    initialized: bool,
}

impl CpuUsageTracker {
    const fn new(cpu_label: &'static str) -> Self {
        Self {
            cpu_label,
            last_busy: 0,
            last_total: 0,
            initialized: false,
        }
    }

    fn try_calculate(&mut self) -> Result<Option<f64>> {
        let (busy, total) = get_cpu_busy_total(self.cpu_label)?;
        if !self.initialized {
            self.last_busy = busy;
            self.last_total = total;
            self.initialized = true;
            return Ok(None);
        }

        let busy_delta = busy.saturating_sub(self.last_busy);
        let total_delta = total.saturating_sub(self.last_total);
        self.last_busy = busy;
        self.last_total = total;

        if total_delta == 0 {
            return Ok(None);
        }

        Ok(Some(
            (busy_delta as f64 / total_delta as f64).clamp(0.0, 1.0),
        ))
    }
}

#[derive(Debug)]
pub struct CpuUsageMonitor {
    cpu1_tracker: CpuUsageTracker,
    last_update: Instant,
}

impl CpuUsageMonitor {
    pub fn new() -> Self {
        Self {
            cpu1_tracker: CpuUsageTracker::new("cpu1"),
            last_update: Instant::now(),
        }
    }

    pub fn update(&mut self) -> Option<UsageSnapshot> {
        if self.last_update.elapsed() < Duration::from_millis(500) {
            return None;
        }

        self.last_update = Instant::now();
        let cpu1_util = self
            .cpu1_tracker
            .try_calculate()
            .ok()
            .flatten()
            .unwrap_or(0.0);

        Some(UsageSnapshot { cpu1_util })
    }
}

fn get_cpu_busy_total(cpu_label: &str) -> Result<(u64, u64)> {
    let stat = fs::read_to_string("/proc/stat")?;
    let Some(line) = stat.lines().find(|line| {
        line.starts_with(cpu_label)
            && line
                .as_bytes()
                .get(cpu_label.len())
                .is_some_and(u8::is_ascii_whitespace)
    }) else {
        return Ok((0, 0));
    };

    let mut has_fields = false;
    let mut busy = 0;
    let mut total = 0;
    for (idx, value) in line
        .split_whitespace()
        .skip(1)
        .filter_map(|value| value.parse::<u64>().ok())
        .enumerate()
    {
        has_fields = true;
        total += value;
        if matches!(idx, 0 | 1 | 2 | 5 | 6 | 7) {
            busy += value;
        }
    }

    if !has_fields {
        return Ok((0, 0));
    }

    Ok((busy, total))
}
