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

use std::time::Duration;

use likely_stable::unlikely;

use super::{super::buffer::Buffer, ControlOutput};
use crate::framework::{config::MarginFps, prelude::*, scheduler::looper::ControllerState};

pub fn calculate_control(
    buffer: &Buffer,
    config: &mut Config,
    mode: Mode,
    controller_state: &mut ControllerState,
    target_fps_offset_thermal: f64,
) -> Option<ControlOutput> {
    if unlikely(buffer.frametime_state.frametimes.len() < 60) {
        return None;
    }

    let target_fps = f64::from(buffer.target_fps_state.target_fps?);
    let margin_fps: f64 = match &config.mode_config(mode).margin_fps {
        MarginFps::BaseOnly(base) => target_fps / 60.0 * f64::from(*base),
        MarginFps::Advanced { base, overrides } => overrides
            .get(&target_fps.to_string())
            .copied()
            .map_or_else(|| target_fps / 60.0 * f64::from(*base), f64::from),
    };

    assert!(margin_fps.is_sign_positive(), "margin_fps must be positive");

    let target_fps = (target_fps + target_fps_offset_thermal).clamp(0.0, target_fps);
    let adjusted_target_fps = target_fps - margin_fps;

    let adjusted_last_frame = get_normalized_last_frame(buffer, adjusted_target_fps);
    let target_frametime = Duration::from_secs(1);

    let control_ratio =
        calculate_control_inner(controller_state, adjusted_last_frame, target_frametime);

    Some(ControlOutput {
        control_ratio,
        is_janked: buffer.frametime_state.current_fps_long < target_fps - 2.0,
    })
}

fn get_normalized_last_frame(buffer: &Buffer, target_fps: f64) -> Duration {
    let last_frame = buffer
        .frametime_state
        .frametimes
        .front()
        .copied()
        .unwrap_or_default();
    let short_avg_frame = buffer.frametime_state.avg_time_short;

    // Symmetric blend between single-frame and short-window frame time.
    // This keeps responsiveness while reducing one-frame catch-up noise.
    const SHORT_AVG_BLEND: f64 = 0.30;
    let beta = SHORT_AVG_BLEND.clamp(0.0, 1.0);
    let representative = last_frame
        .mul_f64(1.0 - beta)
        .saturating_add(short_avg_frame.mul_f64(beta));

    if buffer.frametime_state.additional_frametime == Duration::ZERO {
        representative
    } else {
        buffer
            .frametime_state
            .additional_frametime
            .max(representative)
    }
    .mul_f64(target_fps)
}

fn calculate_control_inner(
    controller_state: &mut ControllerState,
    current_frametime: Duration,
    target_frametime: Duration,
) -> f64 {
    let raw_error_ratio = if target_frametime.is_zero() {
        0.0
    } else {
        current_frametime.as_secs_f64() / target_frametime.as_secs_f64() - 1.0
    };

    // Symmetric clip on raw error to prevent single outliers from polluting
    // the EMA state.
    let clip = controller_state.params.error_clip_ratio.max(0.01);
    let clipped_raw_error_ratio = raw_error_ratio.clamp(-clip, clip);

    // EMA filter suppresses one-frame noise before converting error into
    // control action.
    let alpha = controller_state.params.error_ema_alpha.clamp(0.0, 0.9999);
    let smooth_error_ratio = if let Some(prev) = controller_state.error_ratio_ema {
        alpha * prev + (1.0 - alpha) * clipped_raw_error_ratio
    } else {
        clipped_raw_error_ratio
    };
    controller_state.error_ratio_ema = Some(smooth_error_ratio);

    let error_p = smooth_error_ratio * controller_state.params.kp;

    error_p
}
