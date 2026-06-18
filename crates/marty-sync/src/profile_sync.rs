//! Deployment profile and lane sync provider

use crate::error::SyncError;
use reqwest::Client;
use serde::{Deserialize, Serialize};

/// Deployment profile configuration from backend
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeploymentProfile {
    pub id: String,
    pub name: String,
    pub site_id: Option<String>,
    pub network_mode: NetworkMode,
    pub key_access_mode: String,
    pub ux_config: UXConfig,
    pub update_policy: UpdatePolicy,
    pub offline_cache_ttl_hours: u32,
    pub biometric_required: bool,
    pub audit_all_events: bool,
    #[serde(default)]
    pub default_presentation_policy_id: Option<String>,
}

/// Network connectivity mode
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum NetworkMode {
    Online,
    Offline,
    Hybrid,
}

/// User experience configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UXConfig {
    pub language: String,
    pub theme: String,
    pub show_operator_mode: bool,
    pub accessibility_enabled: bool,
    #[serde(default)]
    pub custom_branding: serde_json::Value,
    pub signage_text: Option<std::collections::HashMap<String, String>>,
}

/// Update policy configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UpdatePolicy {
    pub auto_update: bool,
    pub update_channel: String,
    pub rollout_percentage: u8,
    pub version_pinned: Option<String>,
    pub rollout_ring: Option<String>,
}

/// Lane configuration from backend
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Lane {
    pub id: String,
    pub name: String,
    pub deployment_profile_id: String,
    pub default_policy_id: Option<String>,
    pub device_ids: Vec<String>,
    #[serde(default)]
    pub metadata: serde_json::Value,
}

/// Complete device configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeviceConfig {
    pub device_id: String,
    pub deployment_profile: Option<DeploymentProfile>,
    pub lane: Option<Lane>,
}

/// Profile sync provider for fetching deployment configuration from backend
pub struct ProfileSyncProvider {
    client: Client,
    endpoint: String,
    license_jwt: String,
}

impl ProfileSyncProvider {
    /// Create a new profile sync provider
    ///
    /// # Arguments
    /// * `endpoint` - Backend API endpoint (e.g., "https://api.example.com")
    /// * `license_jwt` - License JWT for authentication
    pub fn new(endpoint: String, license_jwt: String) -> Self {
        Self {
            client: Client::new(),
            endpoint,
            license_jwt,
        }
    }

    /// Fetch device configuration (profile + lane + policies)
    ///
    /// # Arguments
    /// * `device_id` - Device identifier
    pub async fn fetch_device_config(&self, device_id: &str) -> Result<DeviceConfig, SyncError> {
        let url = format!("{}/api/v1/devices/{}/config", self.endpoint, device_id);

        let response = self
            .client
            .get(&url)
            .bearer_auth(&self.license_jwt)
            .send()
            .await
            .map_err(|e| SyncError::NetworkError(e.to_string()))?;

        if !response.status().is_success() {
            return Err(SyncError::HttpError(
                response.status().as_u16(),
                format!("Failed to fetch device config: {}", response.status()),
            ));
        }

        let config: DeviceConfig = response
            .json()
            .await
            .map_err(|e| SyncError::ParseError(e.to_string()))?;

        Ok(config)
    }

    /// Fetch deployment profile by ID
    pub async fn fetch_deployment_profile(
        &self,
        profile_id: &str,
    ) -> Result<DeploymentProfile, SyncError> {
        let url = format!(
            "{}/api/v1/identity/deployment-profiles/{}",
            self.endpoint, profile_id
        );

        let response = self
            .client
            .get(&url)
            .bearer_auth(&self.license_jwt)
            .send()
            .await
            .map_err(|e| SyncError::NetworkError(e.to_string()))?;

        if !response.status().is_success() {
            return Err(SyncError::HttpError(
                response.status().as_u16(),
                format!("Failed to fetch deployment profile: {}", response.status()),
            ));
        }

        let profile: DeploymentProfile = response
            .json()
            .await
            .map_err(|e| SyncError::ParseError(e.to_string()))?;

        Ok(profile)
    }

    /// Fetch lanes for a deployment profile
    pub async fn fetch_lanes(&self, profile_id: &str) -> Result<Vec<Lane>, SyncError> {
        let url = format!(
            "{}/api/v1/identity/deployment-profiles/{}/lanes",
            self.endpoint, profile_id
        );

        let response = self
            .client
            .get(&url)
            .bearer_auth(&self.license_jwt)
            .send()
            .await
            .map_err(|e| SyncError::NetworkError(e.to_string()))?;

        if !response.status().is_success() {
            return Err(SyncError::HttpError(
                response.status().as_u16(),
                format!("Failed to fetch lanes: {}", response.status()),
            ));
        }

        let lanes: Vec<Lane> = response
            .json()
            .await
            .map_err(|e| SyncError::ParseError(e.to_string()))?;

        Ok(lanes)
    }

    /// Check if a device should receive an update based on rollout percentage
    ///
    /// # Arguments
    /// * `device_id` - Device identifier
    /// * `rollout_percentage` - Rollout percentage (0-100)
    pub fn should_apply_update(device_id: &str, rollout_percentage: u8) -> bool {
        use std::collections::hash_map::DefaultHasher;
        use std::hash::{Hash, Hasher};

        let mut hasher = DefaultHasher::new();
        device_id.hash(&mut hasher);
        let hash = hasher.finish();

        ((hash % 100) as u8) < rollout_percentage
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_rollout_percentage() {
        // Test rollout percentage calculation is deterministic
        let device_id = "test-device-123";

        let result1 = ProfileSyncProvider::should_apply_update(device_id, 50);
        let result2 = ProfileSyncProvider::should_apply_update(device_id, 50);

        assert_eq!(
            result1, result2,
            "Rollout calculation should be deterministic"
        );

        // Test edge cases
        assert!(
            ProfileSyncProvider::should_apply_update(device_id, 100),
            "100% rollout should always apply"
        );
        assert!(
            !ProfileSyncProvider::should_apply_update(device_id, 0),
            "0% rollout should never apply"
        );
    }
}
