//! Application state management

use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;

use marty_app_storage::SecureStorage;
use marty_entitlements::{AllowAllEntitlementProvider, EntitlementProvider};
use marty_secure_storage::SecureStorage as CoreSecureStorage;
use marty_sync::SyncEngine;

use crate::config::AppConfig;
use crate::error::AppResult;
use crate::hardware::{HardwareDetector, HardwareTier};
use crate::runtime_config::RuntimeConfig;

/// Stored liveness challenge metadata for replay protection
#[derive(Debug, Clone)]
pub struct StoredLivenessChallenge {
    pub challenge_id: String,
    pub nonce: String,
    pub session_id: String,
    #[allow(dead_code)]
    pub issued_at: chrono::DateTime<chrono::Utc>,
    pub expires_at: chrono::DateTime<chrono::Utc>,
    pub used: bool,
}

/// Shared application state managed by Tauri
pub struct AppState {
    /// Application configuration
    pub config: RwLock<AppConfig>,

    /// Secure storage for credentials, events, and trust anchors
    pub storage: Arc<SecureStorage>,

    /// Provider-neutral policy for optional compiled capabilities.
    pub entitlements: Arc<dyn EntitlementProvider>,

    /// Sync engine for trust anchor updates
    pub sync_engine: Arc<SyncEngine>,

    /// Runtime configuration (deployment profile, lane, UX settings)
    pub runtime_config: RuntimeConfig,

    /// Hardware detection and tier management
    pub hardware: Arc<HardwareDetector>,

    /// Current hardware tier (cached)
    pub hardware_tier: RwLock<HardwareTier>,

    /// Network connectivity status
    pub is_online: RwLock<bool>,

    /// Ephemeral secret for liveness challenge signing
    pub liveness_secret: Arc<Vec<u8>>,

    /// Issued liveness challenges for replay protection
    pub liveness_challenges: RwLock<HashMap<String, StoredLivenessChallenge>>,
}

impl AppState {
    /// Initialize application state
    pub fn new() -> AppResult<Self> {
        let config = AppConfig::load()?;

        // Initialize secure storage (app-level: verification events, trust anchors)
        let storage = Arc::new(SecureStorage::new(&config.data_dir)?);

        // Initialize core secure storage used by the sync engine.
        let core_storage = Arc::new(CoreSecureStorage::new(&config.data_dir).map_err(|e| {
            crate::error::AppError::Config(format!("Core storage init failed: {}", e))
        })?);

        // The open-source distribution enables every capability compiled into it.
        // Private downstream distributions can supply another provider.
        let entitlements: Arc<dyn EntitlementProvider> = Arc::new(AllowAllEntitlementProvider);

        // Initialize sync engine
        let sync_engine = Arc::new(SyncEngine::new(core_storage, config.sync_config.clone())?);

        // Detect hardware
        let hardware = Arc::new(HardwareDetector::new());
        let hardware_tier = hardware.detect_tier();

        tracing::info!(?hardware_tier, "Detected hardware tier");

        // Generate ephemeral liveness secret (not persisted)
        let mut secret = vec![0u8; 32];
        let rng = ring::rand::SystemRandom::new();
        ring::rand::SecureRandom::fill(&rng, &mut secret).map_err(|e| {
            crate::error::AppError::Config(format!("Failed to generate liveness secret: {}", e))
        })?;

        let state = Self {
            config: RwLock::new(config),
            storage,
            entitlements,
            sync_engine,
            runtime_config: RuntimeConfig::new(),
            hardware,
            hardware_tier: RwLock::new(hardware_tier),
            is_online: RwLock::new(false), // Assume offline until proven otherwise
            liveness_secret: Arc::new(secret),
            liveness_challenges: RwLock::new(HashMap::new()),
        };

        Ok(state)
    }

    /// Restore runtime configuration from persistent storage
    pub async fn restore_from_storage(&self) -> AppResult<()> {
        // Try to get the stored device configuration
        match self.storage.get_device_config().await {
            Ok(Some((device_id, profile_id, lane_id))) => {
                tracing::info!(
                    device_id = %device_id,
                    profile_id = ?profile_id,
                    lane_id = ?lane_id,
                    "Restoring device configuration from storage"
                );

                // Load the deployment profile
                let profile_id_str = profile_id.as_deref().unwrap_or("");
                let lane_id_str = lane_id.as_deref().unwrap_or("");
                if let Some(profile) = self
                    .storage
                    .get_deployment_profile(profile_id_str)
                    .await
                    .map_err(|e| crate::error::AppError::Config(e.to_string()))?
                {
                    self.runtime_config
                        .apply_deployment_profile(profile.clone())
                        .await;
                    tracing::info!(profile_id = %profile.id, "Restored deployment profile");

                    // Load the lane
                    let lanes = self
                        .storage
                        .get_lanes_for_profile(profile_id_str)
                        .await
                        .map_err(|e| crate::error::AppError::Config(e.to_string()))?;

                    if let Some(lane) = lanes.into_iter().find(|l| l.id.as_str() == lane_id_str) {
                        self.runtime_config.apply_lane(lane.clone()).await;
                        tracing::info!(lane_id = %lane.id, "Restored lane configuration");
                    } else {
                        tracing::warn!(lane_id = ?lane_id, "Lane not found in storage");
                    }
                } else {
                    tracing::warn!(profile_id = ?profile_id, "Deployment profile not found in storage");
                }
            }
            Ok(None) => {
                tracing::debug!("No device configuration found in storage");
            }
            Err(e) => {
                tracing::warn!("Failed to restore device configuration: {}", e);
                // Don't fail initialization if restore fails
            }
        }

        Ok(())
    }

    /// Check if a compiled feature is enabled and the hardware supports it.
    pub async fn check_feature(&self, feature: &str) -> AppResult<()> {
        let decision = self.entitlements.check(feature);
        if !decision.allowed {
            return Err(crate::error::AppError::EntitlementDenied {
                capability: feature.to_string(),
                reason: decision.reason,
            });
        }

        // Check hardware tier requirements
        let tier = self.hardware_tier.read().await;
        if !tier.supports_feature(feature) {
            return Err(crate::error::AppError::InsufficientHardware {
                required: feature.to_string(),
                available: format!("{:?}", *tier),
            });
        }

        Ok(())
    }

    /// Update online status
    #[allow(dead_code)]
    pub async fn set_online(&self, online: bool) {
        let mut is_online = self.is_online.write().await;
        if *is_online != online {
            tracing::info!(online, "Network status changed");
            *is_online = online;
        }
    }

    /// Record a newly issued liveness challenge for replay protection
    pub async fn record_liveness_challenge(&self, challenge: StoredLivenessChallenge) {
        let mut guard = self.liveness_challenges.write().await;
        // Periodic cleanup: remove expired challenges to prevent unbounded growth
        if guard.len() > 100 {
            let now = chrono::Utc::now();
            guard.retain(|_id, c| c.expires_at > now);
        }
        guard.insert(challenge.challenge_id.clone(), challenge);
    }

    /// Mark a challenge as used if it exists and not yet expired/used
    pub async fn consume_liveness_challenge(
        &self,
        challenge_id: &str,
    ) -> Option<StoredLivenessChallenge> {
        let mut guard = self.liveness_challenges.write().await;
        if let Some(entry) = guard.get_mut(challenge_id) {
            if entry.used {
                return None;
            }
            entry.used = true;
            return Some(entry.clone());
        }
        None
    }
}
