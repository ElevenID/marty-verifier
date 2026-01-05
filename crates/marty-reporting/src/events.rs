//! Event types for reporting

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// Verification event for reporting
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VerificationEvent {
    /// Unique event ID
    pub event_id: String,
    /// Event type
    pub event_type: String,
    /// Timestamp
    pub timestamp: DateTime<Utc>,
    /// Event payload
    pub payload: EventPayload,
    /// Device/kiosk identifier
    pub device_id: Option<String>,
    /// Hardware tier
    pub hardware_tier: Option<String>,
    /// License organization ID
    pub org_id: Option<String>,
}

/// Event payload variants
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum EventPayload {
    /// Credential verification event
    Verification(VerificationPayload),
    /// Sync event
    Sync(SyncPayload),
    /// License event
    License(LicensePayload),
    /// Error event
    Error(ErrorPayload),
}

/// Verification event payload
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VerificationPayload {
    /// Verification ID
    pub verification_id: String,
    /// Credential type (mdl, emrtd, oid4vp, etc.)
    pub credential_type: String,
    /// Verification result
    pub result: String,
    /// Issuer jurisdiction
    pub jurisdiction: Option<String>,
    /// Trust chain type
    pub trust_chain_type: Option<String>,
    /// Verified offline
    pub offline_verified: bool,
    /// Processing time in milliseconds
    pub processing_time_ms: Option<u64>,
    /// Biometric verification performed
    pub biometric_verified: Option<bool>,
    /// Biometric similarity score
    pub biometric_score: Option<f32>,
}

/// Sync event payload
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SyncPayload {
    /// Sync type (iaca, csca, crl, usb_import)
    pub sync_type: String,
    /// Success
    pub success: bool,
    /// Certificates updated
    pub certificates_updated: usize,
    /// Duration in seconds
    pub duration_seconds: f64,
    /// Error message if failed
    pub error: Option<String>,
}

/// License event payload
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LicensePayload {
    /// Event subtype (validated, expired, grace_period, limit_exceeded)
    pub subtype: String,
    /// License expiration date
    pub expires_at: Option<String>,
    /// Days until expiry
    pub days_until_expiry: Option<i64>,
    /// Total verifications
    pub verifications_total: Option<u64>,
    /// Max total verifications
    pub max_verifications_total: Option<u64>,
    /// Remaining verifications
    pub verifications_remaining: Option<u64>,
}

/// Error event payload
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ErrorPayload {
    /// Error category
    pub category: String,
    /// Error message
    pub message: String,
    /// Error code
    pub code: Option<String>,
    /// Stack trace (debug builds only)
    pub stack_trace: Option<String>,
}

impl VerificationEvent {
    /// Create a new verification event
    pub fn verification(verification_id: String, credential_type: String, result: String) -> Self {
        Self {
            event_id: uuid::Uuid::new_v4().to_string(),
            event_type: "verification".to_string(),
            timestamp: Utc::now(),
            payload: EventPayload::Verification(VerificationPayload {
                verification_id,
                credential_type,
                result,
                jurisdiction: None,
                trust_chain_type: None,
                offline_verified: false,
                processing_time_ms: None,
                biometric_verified: None,
                biometric_score: None,
            }),
            device_id: None,
            hardware_tier: None,
            org_id: None,
        }
    }

    /// Create a sync event
    pub fn sync(sync_type: String, success: bool, certificates_updated: usize) -> Self {
        Self {
            event_id: uuid::Uuid::new_v4().to_string(),
            event_type: "sync".to_string(),
            timestamp: Utc::now(),
            payload: EventPayload::Sync(SyncPayload {
                sync_type,
                success,
                certificates_updated,
                duration_seconds: 0.0,
                error: None,
            }),
            device_id: None,
            hardware_tier: None,
            org_id: None,
        }
    }

    /// Create an error event
    pub fn error(category: String, message: String) -> Self {
        Self {
            event_id: uuid::Uuid::new_v4().to_string(),
            event_type: "error".to_string(),
            timestamp: Utc::now(),
            payload: EventPayload::Error(ErrorPayload {
                category,
                message,
                code: None,
                stack_trace: None,
            }),
            device_id: None,
            hardware_tier: None,
            org_id: None,
        }
    }
}
