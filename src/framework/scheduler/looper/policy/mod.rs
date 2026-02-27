// Copyright 2024-2025, shadow3aaa
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

pub mod controll;

#[derive(Debug, Copy, Clone)]
pub struct ControllerParams {
    pub kp: f64,
    pub error_ema_alpha: f64,
    pub error_clip_ratio: f64,
}

impl Default for ControllerParams {
    fn default() -> Self {
        Self {
            kp: 0.4,
            error_ema_alpha: 0.5,
            error_clip_ratio: 0.8,
        }
    }
}

#[derive(Debug, Copy, Clone)]
pub struct ControlOutput {
    pub control_ratio: f64,
    pub is_janked: bool,
}
