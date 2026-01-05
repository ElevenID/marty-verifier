//! License error types

use thiserror::Error;

#[derive(Error, Debug)]
pub enum LicenseError {
    #[error("No license installed")]
    NoLicense,

    #[error("License expired on {0}")]
    Expired(String),

    #[error("License signature invalid")]
    InvalidSignature,

    #[error("License claims invalid: {0}")]
    InvalidClaims(String),

    #[error("Hardware binding mismatch")]
    HardwareBindingMismatch,

    #[error("Feature not licensed: {0}")]
    FeatureNotLicensed(String),

    #[error("Verification limit exceeded: {used}/{max}")]
    VerificationLimitExceeded { used: u64, max: u64 },

    #[error("Update channel not allowed: {0}")]
    UpdateChannelNotAllowed(String),

    #[error("Grace period expired")]
    GracePeriodExpired,

    #[error("Storage error: {0}")]
    Storage(#[from] marty_secure_storage::StorageError),

    #[error("JWT error: {0}")]
    Jwt(String),

    #[error("Crypto error: {0}")]
    Crypto(String),
}

impl serde::Serialize for LicenseError {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(&self.to_string())
    }
}
