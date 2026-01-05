//! Trust anchor sync commands

use tauri::State;

use crate::error::AppResult;
use crate::state::AppState;

// Re-export types from the sync crate
pub use marty_sync::{SyncResult, SyncStatus, UsbImportResult};

/// Trigger trust anchor sync
#[tauri::command]
pub async fn sync_trust_anchors(
    force: Option<bool>,
    state: State<'_, AppState>,
) -> AppResult<SyncResult> {
    let force = force.unwrap_or(false);
    tracing::info!(force, "Starting trust anchor sync");

    let result = state.sync_engine.sync(force).await?;

    Ok(result)
}

/// Get current sync status
#[tauri::command]
pub async fn get_sync_status(state: State<'_, AppState>) -> AppResult<SyncStatus> {
    let status = state.sync_engine.get_status().await?;
    Ok(status)
}

/// Import trust anchors from USB drive (air-gapped deployments)
#[tauri::command]
pub async fn import_trust_anchors_usb(
    path: String,
    state: State<'_, AppState>,
) -> AppResult<UsbImportResult> {
    tracing::info!(path, "Importing trust anchors from USB");

    let result = state.sync_engine.import_from_usb(&path).await?;

    Ok(result)
}
