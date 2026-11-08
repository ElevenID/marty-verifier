//! Runtime configuration management
//!
//! Applies deployment profile settings to the running application,
//! including network mode, UX configuration, and policy selection.

use marty_sync::{DeploymentProfile, Lane, NetworkMode, UXConfig, UpdatePolicy};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use tokio::sync::RwLock;

/// Runtime configuration state
#[derive(Debug, Clone)]
pub struct RuntimeConfig {
    inner: Arc<RwLock<RuntimeConfigInner>>,
}

#[derive(Debug, Clone)]
struct RuntimeConfigInner {
    device_id: Option<String>,
    deployment_profile: Option<DeploymentProfile>,
    lane: Option<Lane>,
    active_policy_id: Option<String>,
}

impl RuntimeConfigInner {
    fn effective_policy_id(&self) -> Option<String> {
        self.lane
            .as_ref()
            .and_then(|lane| lane.default_policy_id.clone())
            .or_else(|| self.active_policy_id.clone())
            .or_else(|| {
                self.deployment_profile
                    .as_ref()
                    .and_then(|profile| profile.default_presentation_policy_id.clone())
            })
    }
}

impl RuntimeConfig {
    /// Create a new runtime configuration
    pub fn new() -> Self {
        Self {
            inner: Arc::new(RwLock::new(RuntimeConfigInner {
                device_id: None,
                deployment_profile: None,
                lane: None,
                active_policy_id: None,
            })),
        }
    }

    /// Set device ID
    pub async fn set_device_id(&self, device_id: String) {
        let mut inner = self.inner.write().await;
        inner.device_id = Some(device_id);
    }

    /// Get device ID
    pub async fn get_device_id(&self) -> Option<String> {
        let inner = self.inner.read().await;
        inner.device_id.clone()
    }

    /// Apply deployment profile configuration
    pub async fn apply_deployment_profile(&self, profile: DeploymentProfile) {
        let mut inner = self.inner.write().await;
        inner.deployment_profile = Some(profile);
    }

    /// Apply lane configuration
    pub async fn apply_lane(&self, lane: Lane) {
        let mut inner = self.inner.write().await;
        // Lane defaults are resolved dynamically, not copied into the explicit
        // selection. Otherwise changing lanes can retain the previous default.
        inner.lane = Some(lane);
    }

    /// Get current network mode
    pub async fn get_network_mode(&self) -> NetworkMode {
        let inner = self.inner.read().await;
        inner
            .deployment_profile
            .as_ref()
            .map(|p| p.network_mode.clone())
            .unwrap_or(NetworkMode::Online)
    }

    /// Get UX configuration
    pub async fn get_ux_config(&self) -> Option<UXConfig> {
        let inner = self.inner.read().await;
        inner
            .deployment_profile
            .as_ref()
            .map(|p| p.ux_config.clone())
    }

    /// Get active policy ID (from lane or profile default)
    pub async fn get_active_policy_id(&self) -> Option<String> {
        self.inner.read().await.effective_policy_id()
    }

    /// Get offline cache TTL in hours
    pub async fn get_offline_cache_ttl_hours(&self) -> u32 {
        let inner = self.inner.read().await;
        inner
            .deployment_profile
            .as_ref()
            .map(|p| p.offline_cache_ttl_hours)
            .unwrap_or(24)
    }

    /// Check if biometric authentication is required for the verifier operator.
    pub async fn is_operator_biometric_authentication_required(&self) -> bool {
        let inner = self.inner.read().await;
        inner
            .deployment_profile
            .as_ref()
            .map(|p| p.operator_biometric_authentication_required)
            .unwrap_or(false)
    }

    /// Check if all events should be audited
    pub async fn should_audit_all_events(&self) -> bool {
        let inner = self.inner.read().await;
        inner
            .deployment_profile
            .as_ref()
            .map(|p| p.audit_all_events)
            .unwrap_or(true)
    }

    /// Get current deployment profile ID
    pub async fn get_deployment_profile_id(&self) -> Option<String> {
        let inner = self.inner.read().await;
        inner.deployment_profile.as_ref().map(|p| p.id.clone())
    }

    /// Get current lane ID
    pub async fn get_lane_id(&self) -> Option<String> {
        let inner = self.inner.read().await;
        inner.lane.as_ref().map(|l| l.id.clone())
    }

    /// Clear all configuration (for testing or reset)
    pub async fn clear(&self) {
        let mut inner = self.inner.write().await;
        inner.deployment_profile = None;
        inner.lane = None;
        inner.active_policy_id = None;
    }
}

impl Default for RuntimeConfig {
    fn default() -> Self {
        Self::new()
    }
}

/// Configuration snapshot for serialization
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConfigSnapshot {
    pub device_id: Option<String>,
    pub deployment_profile_id: Option<String>,
    pub lane_id: Option<String>,
    pub update_policy: Option<UpdatePolicy>,
    pub network_mode: String,
    pub active_policy_id: Option<String>,
    pub offline_cache_ttl_hours: u32,
    pub operator_biometric_authentication_required: bool,
    pub ux_language: String,
    pub ux_theme: String,
}

impl RuntimeConfig {
    /// Get a snapshot of current configuration
    pub async fn snapshot(&self) -> ConfigSnapshot {
        let inner = self.inner.read().await;

        let network_mode = inner
            .deployment_profile
            .as_ref()
            .map(|p| format!("{:?}", p.network_mode))
            .unwrap_or_else(|| "Online".to_string());

        let ux_language = inner
            .deployment_profile
            .as_ref()
            .map(|p| p.ux_config.language.clone())
            .unwrap_or_else(|| "en".to_string());

        let ux_theme = inner
            .deployment_profile
            .as_ref()
            .map(|p| p.ux_config.theme.clone())
            .unwrap_or_else(|| "default".to_string());

        ConfigSnapshot {
            device_id: inner.device_id.clone(),
            deployment_profile_id: inner.deployment_profile.as_ref().map(|p| p.id.clone()),
            lane_id: inner.lane.as_ref().map(|l| l.id.clone()),
            update_policy: inner
                .deployment_profile
                .as_ref()
                .map(|p| p.update_policy.clone()),
            network_mode,
            active_policy_id: inner.effective_policy_id(),
            offline_cache_ttl_hours: inner
                .deployment_profile
                .as_ref()
                .map(|profile| profile.offline_cache_ttl_hours)
                .unwrap_or(24),
            operator_biometric_authentication_required: inner
                .deployment_profile
                .as_ref()
                .map(|profile| profile.operator_biometric_authentication_required)
                .unwrap_or(false),
            ux_language,
            ux_theme,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use marty_sync::{UXConfig, UpdatePolicy};

    #[tokio::test]
    async fn test_runtime_config() {
        let config = RuntimeConfig::new();

        // Initially empty
        assert!(config.get_deployment_profile_id().await.is_none());

        // Apply profile
        let profile = DeploymentProfile {
            id: "profile-1".to_string(),
            name: "Test Profile".to_string(),
            site_id: Some("site-1".to_string()),
            network_mode: NetworkMode::Hybrid,
            key_access_mode: "key_vault".to_string(),
            ux_config: UXConfig {
                language: "fr".to_string(),
                theme: "airport".to_string(),
                show_operator_mode: false,
                accessibility_enabled: true,
                custom_branding: serde_json::Value::Null,
                signage_text: None,
            },
            update_policy: UpdatePolicy {
                auto_update: true,
                update_channel: "stable".to_string(),
                rollout_percentage: 50,
                version_pinned: None,
                rollout_ring: None,
            },
            offline_cache_ttl_hours: 48,
            operator_biometric_authentication_required: true,
            audit_all_events: true,
            default_presentation_policy_id: Some("profile-policy".into()),
        };

        config.apply_deployment_profile(profile).await;

        // Verify applied
        assert_eq!(
            config.get_deployment_profile_id().await,
            Some("profile-1".to_string())
        );
        assert_eq!(config.get_offline_cache_ttl_hours().await, 48);
        assert!(config.is_operator_biometric_authentication_required().await);

        let ux = config.get_ux_config().await.unwrap();
        assert_eq!(ux.language, "fr");
        assert_eq!(ux.theme, "airport");

        assert_eq!(
            config.get_active_policy_id().await.as_deref(),
            Some("profile-policy")
        );
        assert_eq!(
            config.snapshot().await.active_policy_id.as_deref(),
            Some("profile-policy")
        );
        config
            .apply_lane(Lane {
                id: "lane-1".into(),
                name: "First lane".into(),
                deployment_profile_id: "profile-1".into(),
                default_policy_id: Some("lane-policy".into()),
                device_ids: Vec::new(),
                metadata: serde_json::Value::Null,
            })
            .await;
        assert_eq!(
            config.get_active_policy_id().await.as_deref(),
            Some("lane-policy")
        );
        assert_eq!(
            config.snapshot().await.active_policy_id.as_deref(),
            Some("lane-policy")
        );

        config
            .apply_lane(Lane {
                id: "lane-2".into(),
                name: "Second lane".into(),
                deployment_profile_id: "profile-1".into(),
                default_policy_id: None,
                device_ids: Vec::new(),
                metadata: serde_json::Value::Null,
            })
            .await;
        // Changing to a lane without an override restores the profile default.
        assert_eq!(
            config.get_active_policy_id().await.as_deref(),
            Some("profile-policy")
        );
        assert_eq!(
            config.snapshot().await.active_policy_id.as_deref(),
            Some("profile-policy")
        );
    }
}
