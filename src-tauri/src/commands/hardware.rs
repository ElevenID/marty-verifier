//! Hardware detection commands

use tauri::State;

use crate::error::AppResult;
use crate::hardware::{HardwareCapabilities, HardwareTier};
use crate::state::AppState;

/// Detect available hardware
#[tauri::command]
pub async fn detect_hardware(state: State<'_, AppState>) -> AppResult<HardwareCapabilities> {
    // Refresh hardware detection
    let caps = state.hardware.capabilities().clone();
    Ok(caps)
}

/// Get current hardware tier
#[tauri::command]
pub async fn get_hardware_tier(state: State<'_, AppState>) -> AppResult<HardwareTier> {
    let tier = state.hardware_tier.read().await;
    Ok(*tier)
}
