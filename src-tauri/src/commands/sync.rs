//! Trust anchor sync commands

use serde::Serialize;
use tauri::State;

use crate::error::AppResult;
use crate::state::AppState;

// Re-export types from the sync crate
pub use marty_sync::{SyncResult, SyncStatus, UsbImportResult};

#[derive(Debug, Serialize)]
pub struct NetworkTransitionResult {
    pub online: bool,
    pub flushed_events: usize,
    pub pending_events: usize,
    pub reporting_error: Option<String>,
}

/// Keep the Rust runtime's connectivity posture aligned with the webview and
/// drain durable audit evidence only after connectivity has actually returned.
#[tauri::command]
pub async fn set_network_status(
    online: bool,
    state: State<'_, AppState>,
) -> AppResult<NetworkTransitionResult> {
    state.set_online(online).await;

    #[cfg(feature = "reporting")]
    let (flushed_events, reporting_error) = if online {
        match state.reporter.flush().await {
            Ok(count) => (count, None),
            Err(error) => {
                tracing::warn!(%error, "Reconnect audit flush did not complete");
                (0, Some(error.to_string()))
            }
        }
    } else {
        (0, None)
    };
    #[cfg(not(feature = "reporting"))]
    let (flushed_events, reporting_error) = (0, None);
    let pending_events = state.trust_storage.get_queue_status().await?.pending_events;

    Ok(NetworkTransitionResult {
        online,
        flushed_events,
        pending_events,
        reporting_error,
    })
}

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
