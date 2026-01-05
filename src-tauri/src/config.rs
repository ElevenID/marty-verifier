//! Application configuration

use std::path::PathBuf;

use directories::ProjectDirs;
use serde::{Deserialize, Serialize};

use crate::error::AppResult;

// Re-export crate types for convenience
pub use marty_reporting::ReportingConfig;
pub use marty_sync::SyncConfig;

/// Main application configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AppConfig {
    /// Data directory for secure storage
    pub data_dir: PathBuf,

    /// Ed25519 public key for license validation (base64 encoded)
    pub license_public_key: String,

    /// Liveness retention and media handling
    #[serde(default)]
    pub liveness_retention: LivenessRetentionConfig,

    /// PAD provider configuration (hexagonal adapter selection)
    #[serde(default)]
    pub pad_config: PadProviderConfig,

    /// Sync configuration
    #[serde(default)]
    pub sync_config: SyncConfig,

    /// Reporting configuration
    #[serde(default)]
    pub reporting_config: ReportingConfig,

    /// Update configuration
    #[serde(default)]
    pub update_config: UpdateConfig,

    /// UI configuration
    #[serde(default)]
    pub ui_config: UiConfig,

    /// Retention policy
    #[serde(default)]
    pub retention: RetentionConfig,

    /// Open Badge trust policy
    #[serde(default)]
    pub open_badge_trust: OpenBadgeTrustConfig,
}

/// Updater configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UpdateConfig {
    /// Enable update checks
    pub enabled: bool,
    /// Base URL for update endpoints
    pub base_url: String,
    /// Public key for update signature verification
    pub public_key: String,
    /// Preferred update channel when multiple are allowed
    pub default_channel: String,
}

/// UI configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UiConfig {
    /// Hardware tier override (None = auto-detect)
    pub hardware_tier_override: Option<String>,

    /// Kiosk mode (fullscreen, no exit)
    pub kiosk_mode: bool,

    /// Show offline status banner
    pub show_offline_banner: bool,

    /// Theme (light, dark, system)
    pub theme: String,

    /// Language code
    pub language: String,
}

/// Data retention configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RetentionConfig {
    /// Verification event retention in days
    pub verification_events_days: u32,

    /// Audit log retention in days
    pub audit_log_days: u32,

    /// Encrypt PII fields at rest
    pub encrypt_pii: bool,

    /// Fields to redact before reporting
    pub redacted_fields: Vec<String>,
}

/// Open Badge trust policy configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OpenBadgeTrustConfig {
    /// Trust policy for unknown keys
    #[serde(default)]
    pub policy: OpenBadgeTrustPolicy,
    /// Warning threshold for trust list staleness (hours)
    pub stale_warning_hours: u32,
    /// Critical threshold for trust list staleness (hours)
    pub stale_critical_hours: u32,
}

/// Open Badge trust policy
/// 
/// Determines how the verifier handles credentials signed by keys that are not
/// in the trusted key store.
/// 
/// # Security Considerations
/// 
/// - **FailClosed** (default): Most secure. Rejects any credential whose signing key
///   is not in the trusted store. Use this in production environments where you have
///   a curated list of trusted issuers.
/// 
/// - **FailOpen**: ⚠️ **SECURITY WARNING** - Allows verification to proceed even when
///   the signing key is not in the trusted store. This effectively disables trust
///   validation and should **only** be used in:
///   - Development and testing environments
///   - Demos and proof-of-concept scenarios
///   - Initial onboarding when building a trust list
///   **Never use FailOpen in production** as it allows any issuer's credentials to be
///   accepted without trust verification.
/// 
/// - **Selective**: Allows a hybrid approach where certain issuers (domains, DIDs) are
///   explicitly trusted while others are rejected. Useful for organizations with
///   multiple trusted partners.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OpenBadgeTrustPolicy {
    /// Reject credentials from unknown/untrusted keys (most secure, recommended for production)
    FailClosed,
    /// Allow credentials from unknown keys (insecure, for development only)
    FailOpen,
    /// Allow specific trusted issuers (hybrid approach)
    Selective,
}

/// Liveness-specific retention and media controls
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LivenessRetentionConfig {
    /// Default TTL for audit clips in seconds
    pub default_audit_clip_ttl_seconds: u32,
    /// Maximum TTL allowed for audit clips in seconds
    pub max_audit_clip_ttl_seconds: u32,
    /// Whether to encrypt temporary media at rest
    pub encrypt_temp_media: bool,
}

/// PAD provider selection
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PadProviderType {
    SelfHosted,
    Commercial,
    Mock,
}

/// PAD provider configuration (ports/adapters)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PadProviderConfig {
    /// Provider type (self-hosted HTTP, commercial API, or mock)
    pub provider: PadProviderType,
    /// Endpoint for self-hosted or commercial PAD API
    pub endpoint: Option<String>,
    /// API key or token for commercial provider
    pub api_key: Option<String>,
    /// Request timeout in milliseconds
    pub timeout_ms: u64,
}

impl Default for AppConfig {
    fn default() -> Self {
        Self {
            data_dir: default_data_dir(),
            license_public_key: String::new(),
            liveness_retention: LivenessRetentionConfig::default(),
            pad_config: PadProviderConfig::default(),
            sync_config: SyncConfig::default(),
            reporting_config: ReportingConfig::default(),
            update_config: UpdateConfig::default(),
            ui_config: UiConfig::default(),
            retention: RetentionConfig::default(),
            open_badge_trust: OpenBadgeTrustConfig::default(),
        }
    }
}

impl Default for UiConfig {
    fn default() -> Self {
        Self {
            hardware_tier_override: None,
            kiosk_mode: false,
            show_offline_banner: true,
            theme: "system".to_string(),
            language: "en".to_string(),
        }
    }
}

impl Default for UpdateConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            base_url: String::new(),
            public_key: String::new(),
            default_channel: "stable".to_string(),
        }
    }
}

impl Default for RetentionConfig {
    fn default() -> Self {
        Self {
            verification_events_days: 30,
            audit_log_days: 90,
            encrypt_pii: true,
            redacted_fields: vec![
                "portrait".to_string(),
                "signature".to_string(),
                "biometric_template".to_string(),
            ],
        }
    }
}

impl Default for OpenBadgeTrustConfig {
    fn default() -> Self {
        Self {
            policy: OpenBadgeTrustPolicy::FailClosed,
            stale_warning_hours: 24,
            stale_critical_hours: 48,
        }
    }
}

impl Default for OpenBadgeTrustPolicy {
    fn default() -> Self {
        OpenBadgeTrustPolicy::FailClosed
    }
}

impl Default for LivenessRetentionConfig {
    fn default() -> Self {
        Self {
            default_audit_clip_ttl_seconds: 30,
            max_audit_clip_ttl_seconds: 120,
            encrypt_temp_media: true,
        }
    }
}

impl Default for PadProviderType {
    fn default() -> Self {
        PadProviderType::Mock
    }
}

impl Default for PadProviderConfig {
    fn default() -> Self {
        Self {
            provider: PadProviderType::Mock,
            endpoint: None,
            api_key: None,
            timeout_ms: 5000,
        }
    }
}

impl AppConfig {
    /// Load configuration from disk or create default
    pub fn load() -> AppResult<Self> {
        let config_path = default_config_path();

        if config_path.exists() {
            let contents = std::fs::read_to_string(&config_path)?;
            let config: AppConfig = serde_json::from_str(&contents)?;
            Ok(config)
        } else {
            let config = AppConfig::default();
            config.save()?;
            Ok(config)
        }
    }

    /// Save configuration to disk
    pub fn save(&self) -> AppResult<()> {
        let config_path = default_config_path();

        if let Some(parent) = config_path.parent() {
            std::fs::create_dir_all(parent)?;
        }

        let contents = serde_json::to_string_pretty(self)?;
        std::fs::write(&config_path, contents)?;
        Ok(())
    }
}

fn default_data_dir() -> PathBuf {
    ProjectDirs::from("com", "marty", "verifier")
        .map(|dirs| dirs.data_dir().to_path_buf())
        .unwrap_or_else(|| PathBuf::from("./data"))
}

fn default_config_path() -> PathBuf {
    ProjectDirs::from("com", "marty", "verifier")
        .map(|dirs| dirs.config_dir().join("config.json"))
        .unwrap_or_else(|| PathBuf::from("./config.json"))
}
