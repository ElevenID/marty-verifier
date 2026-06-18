//! Profile and lane sync commands for verifier

use marty_sync::{DeploymentProfile, Lane, ProfileSyncProvider};
use std::sync::Arc;
use tauri::State;

use crate::error::AppResult;
use crate::runtime_config::RuntimeConfig;
use crate::state::AppState;

/// Fetch and apply device configuration from backend
#[tauri::command]
pub async fn sync_device_config(
    device_id: String,
    state: State<'_, AppState>,
) -> AppResult<DeviceConfigSyncResult> {
    state.runtime_config.set_device_id(device_id).await;
    sync_device_config_impl(state.storage.clone(), state.runtime_config.clone()).await
}

/// Internal implementation shared by command and startup sync
pub async fn sync_device_config_impl(
    storage: Arc<marty_app_storage::SecureStorage>,
    runtime_config: RuntimeConfig,
) -> AppResult<DeviceConfigSyncResult> {
    // Get device ID from runtime config
    let device_id = runtime_config
        .get_device_id()
        .await
        .ok_or_else(|| crate::error::AppError::Config("Device ID not configured".into()))?;

    tracing::info!(device_id, "Syncing device configuration");

    // Get API endpoint and license JWT from config
    // TODO: Pass these as parameters once config is available in startup context
    let endpoint =
        std::env::var("MARTY_API_ENDPOINT").unwrap_or_else(|_| "http://localhost:8000".to_string());

    // Validate endpoint URL
    let _parsed = url::Url::parse(&endpoint).map_err(|e| {
        crate::error::AppError::Config(format!("Invalid MARTY_API_ENDPOINT URL: {e}"))
    })?;

    let license_jwt = std::env::var("MARTY_LICENSE_JWT").unwrap_or_default();

    // Fetch device configuration
    let provider = ProfileSyncProvider::new(endpoint, license_jwt);
    let device_config = provider
        .fetch_device_config(&device_id)
        .await
        .map_err(|e| crate::error::AppError::Sync(e))?;

    // Store deployment profile if present
    let profile_id = if let Some(profile) = &device_config.deployment_profile {
        store_deployment_profile(&storage, profile).await?;
        runtime_config
            .apply_deployment_profile(profile.clone())
            .await;
        Some(profile.id.clone())
    } else {
        None
    };

    // Store lane if present
    let lane_id = if let Some(lane) = &device_config.lane {
        store_lane(&storage, lane).await?;
        runtime_config.apply_lane(lane.clone()).await;
        Some(lane.id.clone())
    } else {
        None
    };

    // Update device config record
    store_device_config(
        &storage,
        &device_id,
        profile_id.as_deref(),
        lane_id.as_deref(),
    )
    .await?;

    tracing::info!(
        device_id,
        ?profile_id,
        ?lane_id,
        "Device configuration synced successfully"
    );

    Ok(DeviceConfigSyncResult {
        device_id,
        profile_synced: device_config.deployment_profile.is_some(),
        lane_synced: device_config.lane.is_some(),
        profile_id,
        lane_id,
    })
}

/// Get current runtime configuration snapshot
#[tauri::command]
pub async fn get_runtime_config(state: State<'_, AppState>) -> AppResult<serde_json::Value> {
    let snapshot = state.runtime_config.snapshot().await;
    Ok(
        serde_json::to_value(snapshot)
            .map_err(|e| crate::error::AppError::Config(e.to_string()))?,
    )
}

#[derive(Debug, serde::Serialize)]
pub struct DeviceConfigSyncResult {
    pub device_id: String,
    pub profile_synced: bool,
    pub lane_synced: bool,
    pub profile_id: Option<String>,
    pub lane_id: Option<String>,
}

// Storage helpers — persist deployment data to the app database.
// The runtime_config holds the live in-memory state; these helpers
// write through to SQLite for persistence across restarts.

async fn store_deployment_profile(
    storage: &Arc<marty_app_storage::SecureStorage>,
    profile: &DeploymentProfile,
) -> AppResult<()> {
    storage
        .store_deployment_profile(profile)
        .await
        .map_err(|e| crate::error::AppError::Config(e.to_string()))
}

async fn store_lane(storage: &Arc<marty_app_storage::SecureStorage>, lane: &Lane) -> AppResult<()> {
    storage
        .store_lane(lane)
        .await
        .map_err(|e| crate::error::AppError::Config(e.to_string()))
}

async fn store_device_config(
    storage: &Arc<marty_app_storage::SecureStorage>,
    device_id: &str,
    profile_id: Option<&str>,
    lane_id: Option<&str>,
) -> AppResult<()> {
    storage
        .store_device_config(device_id, profile_id, lane_id)
        .await
        .map_err(|e| crate::error::AppError::Config(e.to_string()))
}
