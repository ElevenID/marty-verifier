//! Application state management

use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;

use marty_license::LicenseManager;
use marty_secure_storage::SecureStorage;
use marty_sync::SyncEngine;

use crate::config::AppConfig;
use crate::error::AppResult;
use crate::hardware::{HardwareDetector, HardwareTier};

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

        // Initialize secure storage
        let storage = Arc::new(SecureStorage::new(&config.data_dir)?);

        // Initialize license manager
        let license = Arc::new(LicenseManager::new(
            storage.clone(),
            config.license_public_key.clone(),
        )?);

        // Initialize sync engine
        let sync_engine = Arc::new(SyncEngine::new(
            storage.clone(),
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
            hardware,
            hardware_tier: RwLock::new(hardware_tier),
            is_online: RwLock::new(false), // Assume offline until proven otherwise
            liveness_secret: Arc::new(secret),
            liveness_challenges: RwLock::new(HashMap::new()),
        };

        Ok(state)
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
