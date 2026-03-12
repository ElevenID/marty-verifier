//! Application state management

use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;

use marty_license::LicenseManager;
use marty_app_storage::SecureStorage;
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

    /// License manager for feature validation
    pub license: Arc<LicenseManager>,

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

        // Initialize core secure storage (used by license manager and sync engine)
        let core_storage = Arc::new(CoreSecureStorage::new(&config.data_dir)
            .map_err(|e| crate::error::AppError::Config(format!("Core storage init failed: {}", e)))?);

        // Initialize license manager
        let license = Arc::new(LicenseManager::new(
            core_storage.clone(),
            config.license_public_key.clone(),
        )?);

        // Initialize sync engine
        let sync_engine = Arc::new(SyncEngine::new(
            core_storage,
            config.sync_config.clone(),
        )?);

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
            license,
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
                    profile_id = %profile_id,
                    lane_id = %lane_id,
                    "Restoring device configuration from storage"
                );

                // Load the deployment profile
                if let Some(profile) = self.storage.get_deployment_profile(&profile_id).await
                    .map_err(|e| crate::error::AppError::Config(e.to_string()))? 
                {
                    self.runtime_config.apply_deployment_profile(profile.clone()).await;
                    tracing::info!(profile_id = %profile.id, "Restored deployment profile");

                    // Load the lane
                    let lanes = self.storage.get_lanes_for_profile(&profile_id).await
                        .map_err(|e| crate::error::AppError::Config(e.to_string()))?;
                    
                    if let Some(lane) = lanes.into_iter().find(|l| l.id == lane_id) {
                        self.runtime_config.apply_lane(lane.clone()).await;
                        tracing::info!(lane_id = %lane.id, "Restored lane configuration");
                    } else {
                        tracing::warn!(lane_id = %lane_id, "Lane not found in storage");
                    }
                } else {
                    tracing::warn!(profile_id = %profile_id, "Deployment profile not found in storage");
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

    /// Check if a feature is licensed and hardware supports it
    pub async fn check_feature(&self, feature: &str) -> AppResult<()> {
        // Check license
        if !self.license.is_feature_licensed(feature).await? {
            return Err(crate::error::AppError::FeatureNotLicensed(
                feature.to_string(),
            ));
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
