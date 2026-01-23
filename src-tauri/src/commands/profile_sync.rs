//! Profile and lane sync commands for verifier

use std::sync::Arc;
use tauri::State;
use marty_sync::{ProfileSyncProvider, DeploymentProfile, Lane};

use crate::error::AppResult;
use crate::runtime_config::RuntimeConfig;
use crate::state::AppState;

/// Fetch and apply device configuration from backend
#[tauri::command]
pub async fn sync_device_config(
    device_id: String,
    state: State<'_, AppState>,
) -> AppResult<DeviceConfigSyncResult> {
    sync_device_config_impl(
        state.storage.clone(),
        state.runtime_config.clone(),
    ).await
}

/// Internal implementation shared by command and startup sync
pub async fn sync_device_config_impl(
    storage: Arc<marty_app_storage::AppStorage>,
    runtime_config: Arc<RuntimeConfig>,
) -> AppResult<DeviceConfigSyncResult> {
    // Get device ID from runtime config
    let device_id = runtime_config.get_device_id().await
        .ok_or_else(|| crate::error::AppError::Config("Device ID not configured".into()))?;
    
    tracing::info!(device_id, "Syncing device configuration");

    // Get API endpoint and license JWT from config
    // TODO: Pass these as parameters once config is available in startup context
    let endpoint = std::env::var("MARTY_API_ENDPOINT")
        .unwrap_or_else(|_| "http://localhost:8000".to_string());
    
    let license_jwt = std::env::var("MARTY_LICENSE_JWT")
        .unwrap_or_default();

    // Fetch device configuration
    let provider = ProfileSyncProvider::new(endpoint, license_jwt);
    let device_config = provider.fetch_device_config(&device_id).await
        .map_err(|e| crate::error::AppError::Sync(e.to_string()))?;

    // Store deployment profile if present
    let profile_id = if let Some(profile) = &device_config.deployment_profile {
        store_deployment_profile(&storage, profile).await?;
        runtime_config.apply_deployment_profile(profile.clone()).await;
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
    store_device_config(&storage, &device_id, profile_id.as_deref(), lane_id.as_deref()).await?;

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
pub async fn get_runtime_config(
    state: State<'_, AppState>,
) -> AppResult<serde_json::Value> {
    let snapshot = state.runtime_config.snapshot().await;
    Ok(serde_json::to_value(snapshot)
        .map_err(|e| crate::error::AppError::Config(e.to_string()))?)
}

#[derive(Debug, serde::Serialize)]
pub struct DeviceConfigSyncResult {
    pub device_id: String,
    pub profile_synced: bool,
    pub lane_synced: bool,
    pub profile_id: Option<String>,
    pub lane_id: Option<String>,
}

// Storage helpers

async fn store_deployment_profile(
    storage: &Arc<marty_app_storage::AppStorage>,
    profile: &DeploymentProfile,
) -> AppResult<()> {
    let conn = storage.connection().await?;
    
    let ux_config_json = serde_json::to_string(&profile.ux_config)
        .map_err(|e| crate::error::AppError::Sync(e.to_string()))?;
    
    let update_policy_json = serde_json::to_string(&profile.update_policy)
        .map_err(|e| crate::error::AppError::Sync(e.to_string()))?;
    
    let now = chrono::Utc::now().to_rfc3339();

    conn.execute(
        r#"
        INSERT OR REPLACE INTO deployment_profiles 
        (id, name, site_id, network_mode, key_access_mode, ux_config, update_policy, 
         offline_cache_ttl_hours, biometric_required, audit_all_events, synced_at, updated_at)
        VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?11)
        "#,
        rusqlite::params![
            &profile.id,
            &profile.name,
            &profile.site_id,
            format!("{:?}", profile.network_mode).to_lowercase(),
            &profile.key_access_mode,
            ux_config_json,
            update_policy_json,
            profile.offline_cache_ttl_hours,
            if profile.biometric_required { 1 } else { 0 },
            if profile.audit_all_events { 1 } else { 0 },
            &now,
        ],
    ).map_err(|e| crate::error::AppError::Database(e.to_string()))?;

    Ok(())
}

async fn store_lane(
    storage: &Arc<marty_app_storage::AppStorage>,
    lane: &Lane,
) -> AppResult<()> {
    let conn = storage.connection().await?;
    
    let device_ids_json = serde_json::to_string(&lane.device_ids)
        .map_err(|e| crate::error::AppError::Sync(e.to_string()))?;
    
    let metadata_json = serde_json::to_string(&lane.metadata)
        .map_err(|e| crate::error::AppError::Sync(e.to_string()))?;
    
    let now = chrono::Utc::now().to_rfc3339();

    conn.execute(
        r#"
        INSERT OR REPLACE INTO lanes 
        (id, name, deployment_profile_id, default_policy_id, device_ids, metadata, synced_at, updated_at)
        VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?7)
        "#,
        rusqlite::params![
            &lane.id,
            &lane.name,
            &lane.deployment_profile_id,
            &lane.default_policy_id,
            device_ids_json,
            metadata_json,
            &now,
        ],
    ).map_err(|e| crate::error::AppError::Database(e.to_string()))?;

    Ok(())
}

async fn store_device_config(
    storage: &Arc<marty_app_storage::AppStorage>,
    device_id: &str,
    profile_id: Option<&str>,
    lane_id: Option<&str>,
) -> AppResult<()> {
    let conn = storage.connection().await?;
    
    let now = chrono::Utc::now().to_rfc3339();

    conn.execute(
        r#"
        INSERT OR REPLACE INTO device_config 
        (id, device_id, deployment_profile_id, lane_id, assigned_at, updated_at)
        VALUES ('current', ?1, ?2, ?3, ?4, ?4)
        "#,
        rusqlite::params![device_id, profile_id, lane_id, &now],
    ).map_err(|e| crate::error::AppError::Database(e.to_string()))?;

    Ok(())
}
