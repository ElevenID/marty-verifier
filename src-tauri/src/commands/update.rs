//! Update management commands

use serde::Serialize;
use tauri::{AppHandle, State};
use tauri_plugin_updater::UpdaterExt;
use url::Url;

use crate::error::{AppError, AppResult};
use crate::state::AppState;
use marty_sync::ProfileSyncProvider;

#[derive(Debug, Serialize)]
pub struct UpdateInfo {
    pub version: String,
    pub current_version: String,
    pub notes: Option<String>,
    pub pub_date: Option<i64>,
    pub channel: String,
    pub eligible_for_rollout: bool,
}

/// Check for updates using the requested or configured channel.
#[tauri::command]
pub async fn check_for_updates(
    channel: Option<String>,
    state: State<'_, AppState>,
    app: AppHandle,
) -> AppResult<Option<UpdateInfo>> {
    let update_config = { state.config.read().await.update_config.clone() };
    if !update_config.enabled {
        return Err(AppError::Update(
            "Updates are disabled in configuration".to_string(),
        ));
    }
    if update_config.public_key.trim().is_empty() {
        return Err(AppError::Update(
            "Update public key is not configured".to_string(),
        ));
    }

    let channel = resolve_update_channel(channel, &update_config.default_channel)?;
    let endpoint = build_update_endpoint(&update_config.base_url, &channel)?;

    let updater = app
        .updater_builder()
        .endpoints(vec![endpoint])
        .map_err(|e| AppError::Update(e.to_string()))?
        .pubkey(update_config.public_key.clone())
        .build()
        .map_err(|e| AppError::Update(e.to_string()))?;

    let update = updater
        .check()
        .await
        .map_err(|e| AppError::Update(e.to_string()))?;

    Ok(update.map(|update| {
        // Check deployment profile update policy
        let eligible_for_rollout = check_rollout_eligibility(&state, &update.version);

        UpdateInfo {
            version: update.version,
            current_version: update.current_version,
            notes: update.body,
            pub_date: update.date.map(|d| d.unix_timestamp()),
            channel,
            eligible_for_rollout,
        }
    }))
}

/// Download and install the latest update in the requested or configured channel.
#[tauri::command]
pub async fn download_and_install_update(
    channel: Option<String>,
    state: State<'_, AppState>,
    app: AppHandle,
) -> AppResult<bool> {
    let update_config = { state.config.read().await.update_config.clone() };
    if !update_config.enabled {
        return Err(AppError::Update(
            "Updates are disabled in configuration".to_string(),
        ));
    }
    if update_config.public_key.trim().is_empty() {
        return Err(AppError::Update(
            "Update public key is not configured".to_string(),
        ));
    }

    let channel = resolve_update_channel(channel, &update_config.default_channel)?;
    let endpoint = build_update_endpoint(&update_config.base_url, &channel)?;

    let updater = app
        .updater_builder()
        .endpoints(vec![endpoint])
        .map_err(|e| AppError::Update(e.to_string()))?
        .pubkey(update_config.public_key.clone())
        .build()
        .map_err(|e| AppError::Update(e.to_string()))?;

    let update = updater
        .check()
        .await
        .map_err(|e| AppError::Update(e.to_string()))?;

    let Some(update) = update else {
        return Ok(false);
    };

    // Check deployment profile update policy
    if !check_rollout_eligibility(&state, &update.version) {
        tracing::info!(
            version = %update.version,
            "Update available but device not eligible for rollout"
        );
        return Ok(false);
    }

    update
        .download_and_install(|_, _| {}, || {})
        .await
        .map_err(|e| AppError::Update(e.to_string()))?;

    Ok(true)
}

fn resolve_update_channel(
    requested: Option<String>,
    preferred: &str,
) -> Result<String, AppError> {
    let channel = requested.unwrap_or_else(|| preferred.to_string());
    if channel.is_empty()
        || !channel
            .chars()
            .all(|character| character.is_ascii_alphanumeric() || ".-_".contains(character))
    {
        return Err(AppError::Update("Invalid update channel".to_string()));
    }
    Ok(channel)
}

fn build_update_endpoint(base_url: &str, channel: &str) -> AppResult<Url> {
    let base = base_url.trim_end_matches('/');
    if base.is_empty() {
        return Err(AppError::Update(
            "Update base_url is not configured".to_string(),
        ));
    }

    let endpoint = format!(
        "{}/{}/{{{{target}}}}/{{{{arch}}}}/{{{{current_version}}}}",
        base, channel
    );
    Url::parse(&endpoint).map_err(|e| AppError::Update(format!("Invalid update endpoint: {}", e)))
}

/// Check if device is eligible for update based on deployment profile rollout policy
fn check_rollout_eligibility(state: &State<AppState>, update_version: &str) -> bool {
    // Get runtime config snapshot
    let snapshot = tokio::task::block_in_place(|| {
        tokio::runtime::Handle::current().block_on(state.runtime_config.snapshot())
    });

    // Get device ID
    let device_id = match snapshot.device_id {
        Some(id) => id,
        None => {
            tracing::warn!("Device ID not set, allowing update");
            return true;
        }
    };

    // Get update policy from deployment profile
    let update_policy = match snapshot.update_policy {
        Some(policy) => policy,
        None => {
            tracing::info!("No deployment profile, allowing update");
            return true;
        }
    };

    // Check if version is pinned
    if let Some(pinned_version) = &update_policy.version_pinned {
        if update_version != pinned_version {
            tracing::info!(
                current = update_version,
                pinned = pinned_version,
                "Update rejected: version pinned"
            );
            return false;
        }
    }

    // Check rollout percentage
    let rollout_percentage = update_policy.rollout_percentage;
    let eligible = ProfileSyncProvider::should_apply_update(&device_id, rollout_percentage);

    if !eligible {
        tracing::info!(
            device_id = %device_id,
            rollout_percentage = rollout_percentage,
            version = update_version,
            "Device not in rollout group"
        );
    }

    eligible
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn resolve_update_channel_prefers_requested() {
        let channel = resolve_update_channel(Some("beta".to_string()), "stable").unwrap();
        assert_eq!(channel, "beta");
    }

    #[test]
    fn resolve_update_channel_rejects_unsafe_values() {
        let err = resolve_update_channel(Some("../private".to_string()), "stable").unwrap_err();
        assert!(err.to_string().contains("Invalid update channel"));
    }

    #[test]
    fn resolve_update_channel_uses_configured_default() {
        let channel = resolve_update_channel(None, "stable").unwrap();
        assert_eq!(channel, "stable");
    }

    #[test]
    fn build_update_endpoint_validates_base_url() {
        let err = build_update_endpoint("", "stable").unwrap_err();
        assert!(err.to_string().contains("base_url"));
    }

    #[test]
    fn build_update_endpoint_includes_channel() {
        let url = build_update_endpoint("https://updates.example.com", "stable").unwrap();
        assert_eq!(url.scheme(), "https");
        assert_eq!(url.host_str(), Some("updates.example.com"));
        assert!(url.path().contains("/stable/"));
    }
}
