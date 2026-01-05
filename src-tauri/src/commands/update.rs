//! Update management commands

use serde::Serialize;
use tauri::{AppHandle, State};
use tauri_plugin_updater::UpdaterExt;
use url::Url;

use crate::error::{AppError, AppResult};
use crate::state::AppState;

#[derive(Debug, Serialize)]
pub struct UpdateInfo {
    pub version: String,
    pub current_version: String,
    pub notes: Option<String>,
    pub pub_date: Option<i64>,
    pub channel: String,
}

/// Check for updates using the licensed update channel.
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

    let claims = state.license.get_claims().await?;
    let channel = resolve_update_channel(channel, &update_config.default_channel, &claims)?;
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

    Ok(update.map(|update| UpdateInfo {
        version: update.version,
        current_version: update.current_version,
        notes: update.body,
        pub_date: update.date.map(|d| d.unix_timestamp()),
        channel,
    }))
}

/// Download and install the latest update in the licensed channel.
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

    let claims = state.license.get_claims().await?;
    let channel = resolve_update_channel(channel, &update_config.default_channel, &claims)?;
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

    update
        .download_and_install(|_, _| {}, || {})
        .await
        .map_err(|e| AppError::Update(e.to_string()))?;

    Ok(true)
}

fn resolve_update_channel(
    requested: Option<String>,
    preferred: &str,
    claims: &marty_license::LicenseClaims,
) -> Result<String, AppError> {
    if claims.update_channels.is_empty() {
        return Err(AppError::License(
            marty_license::LicenseError::UpdateChannelNotAllowed(
                "no update channels available".to_string(),
            ),
        ));
    }

    if let Some(requested) = requested {
        if claims.allows_update_channel(&requested) {
            return Ok(requested);
        }
        return Err(AppError::License(
            marty_license::LicenseError::UpdateChannelNotAllowed(requested),
        ));
    }

    if claims.allows_update_channel(preferred) {
        return Ok(preferred.to_string());
    }

    Ok(claims
        .update_channels
        .iter()
        .find(|channel| *channel != "*")
        .cloned()
        .unwrap_or_else(|| preferred.to_string()))
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
    Url::parse(&endpoint).map_err(|e| {
        AppError::Update(format!("Invalid update endpoint: {}", e))
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;

    fn sample_claims(channels: Vec<&str>) -> marty_license::LicenseClaims {
        let now = Utc::now().timestamp();
        marty_license::LicenseClaims {
            iss: "marty-license-issuer".to_string(),
            sub: "org-123".to_string(),
            iat: now,
            exp: now + 86400,
            nbf: None,
            jti: Some("license-abc".to_string()),
            features: vec!["mdl".to_string()],
            deployment_mode: None,
            max_verifications_total: 100,
            hardware_binding: None,
            hardware_tier: None,
            org_name: None,
            update_channels: channels.into_iter().map(|c| c.to_string()).collect(),
            grace_period_days: 30,
        }
    }

    #[test]
    fn resolve_update_channel_prefers_requested() {
        let claims = sample_claims(vec!["stable", "beta"]);
        let channel = resolve_update_channel(Some("beta".to_string()), "stable", &claims).unwrap();
        assert_eq!(channel, "beta");
    }

    #[test]
    fn resolve_update_channel_rejects_unlicensed() {
        let claims = sample_claims(vec!["stable"]);
        let err = resolve_update_channel(Some("beta".to_string()), "stable", &claims).unwrap_err();
        assert!(err.to_string().contains("Update channel not allowed"));
    }

    #[test]
    fn resolve_update_channel_falls_back_to_allowed() {
        let claims = sample_claims(vec!["beta"]);
        let channel = resolve_update_channel(None, "stable", &claims).unwrap();
        assert_eq!(channel, "beta");
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
