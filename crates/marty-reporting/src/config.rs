//! Reporting configuration

use serde::{Deserialize, Serialize};

/// Reporting configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReportingConfig {
    /// Enable reporting
    pub enabled: bool,
    /// Primary API endpoint for real-time reporting
    pub api_endpoint: Option<String>,
    /// API key/token for authentication
    pub api_key: Option<String>,
    /// Batch upload endpoint (S3 presigned URL or blob storage)
    pub batch_endpoint: Option<String>,
    /// Local-only mode (no remote reporting)
    pub local_only: bool,
    /// Batch upload interval in minutes
    pub batch_interval_minutes: u32,
    /// Maximum queue size before dropping events
    pub max_queue_size: usize,
    /// Retry count for failed uploads
    pub max_retries: u32,
    /// Fields to redact from reports
    pub redacted_fields: Vec<String>,
    /// Include hardware info in reports
    pub include_hardware_info: bool,
}

impl Default for ReportingConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            api_endpoint: None,
            api_key: None,
            batch_endpoint: None,
            local_only: false,
            batch_interval_minutes: 15,
            max_queue_size: 10000,
            max_retries: 3,
            redacted_fields: vec![
                "portrait".to_string(),
                "signature".to_string(),
                "biometric_template".to_string(),
            ],
            include_hardware_info: true,
        }
    }
}
