//! Storage management commands

use tauri::State;

use crate::error::AppResult;
use crate::state::AppState;

// Re-export from storage crate
pub use marty_secure_storage::OfflineQueueStatus;

/// Get offline queue status
#[tauri::command]
pub async fn get_offline_queue_status(state: State<'_, AppState>) -> AppResult<OfflineQueueStatus> {
    let status = state.storage.get_queue_status().await?;
    Ok(status)
}

/// Clear verification history (admin action)
#[tauri::command]
pub async fn clear_verification_history(
    older_than_days: Option<u32>,
    state: State<'_, AppState>,
) -> AppResult<usize> {
    let days = older_than_days.unwrap_or(0);
    let deleted = state.storage.clear_verification_history(days).await?;
    tracing::info!(deleted, days, "Cleared verification history");
    Ok(deleted)
}
