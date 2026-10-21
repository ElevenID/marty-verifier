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
    pub pending_events: Option<usize>,
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
    let pending_events = state
        .trust_storage
        .get_queue_status()
        .await
        .map(|status| status.pending_events)
        .map_err(|error| error.to_string());
    // The connectivity change is already applied. Queue observation failure
    // must not turn its acknowledgement into an error with an ambiguous mode.
    Ok(applied_network_transition(
        online,
        flushed_events,
        pending_events,
        reporting_error,
    ))
}

fn applied_network_transition(
    online: bool,
    flushed_events: usize,
    pending_events: Result<usize, String>,
    reporting_error: Option<String>,
) -> NetworkTransitionResult {
    let (pending_events, reporting_error) = match pending_events {
        Ok(count) => (Some(count), reporting_error),
        Err(error) => {
            let queue_error = format!("Audit queue status unavailable: {error}");
            let message = match reporting_error {
                Some(error) => format!("{error}; {queue_error}"),
                None => queue_error,
            };
            (None, Some(message))
        }
    };
    NetworkTransitionResult {
        online,
        flushed_events,
        pending_events,
        reporting_error,
    }
}

#[cfg(test)]
mod network_transition_tests {
    use super::*;

    #[test]
    fn acknowledges_applied_mode_when_queue_observation_fails_and_recovers() {
        let failed = applied_network_transition(false, 0, Err("storage unavailable".into()), None);
        assert!(!failed.online);
        assert_eq!(failed.pending_events, None);
        assert!(failed
            .reporting_error
            .as_ref()
            .unwrap()
            .contains("storage unavailable"));
        let body = serde_json::to_value(&failed).unwrap();
        assert_eq!(body["online"], false);
        assert!(body["pending_events"].is_null());
        let recovered = applied_network_transition(true, 2, Ok(3), None);
        assert!(recovered.online);
        assert_eq!(recovered.pending_events, Some(3));
        assert_eq!(recovered.flushed_events, 2);
        assert!(recovered.reporting_error.is_none());
    }

    #[test]
    fn retains_flush_failure_alongside_unknown_queue_count() {
        let result = applied_network_transition(
            true,
            0,
            Err("queue read failed".into()),
            Some("upload failed".into()),
        );
        assert!(result.online);
        assert_eq!(result.pending_events, None);
        let error = result.reporting_error.unwrap();
        assert!(error.contains("upload failed") && error.contains("queue read failed"));
    }
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
