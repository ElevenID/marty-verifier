//! Application error types

use thiserror::Error;

/// Main application error type
#[derive(Error, Debug)]
pub enum AppError {
    #[error("License error: {0}")]
    License(#[from] marty_license::LicenseError),

    #[error("Storage error: {0}")]
    Storage(#[from] marty_secure_storage::StorageError),

    #[error("Sync error: {0}")]
    Sync(#[from] marty_sync::SyncError),

    #[error("Verification error: {0}")]
    Verification(String),

    #[error("Hardware error: {0}")]
    #[allow(dead_code)]
    Hardware(String),

    #[error("Configuration error: {0}")]
    Config(String),

    #[error("Update error: {0}")]
    Update(String),

    #[error("Feature not licensed: {0}")]
    FeatureNotLicensed(String),

    #[error("Hardware tier insufficient: required {required}, available {available}")]
    InsufficientHardware { required: String, available: String },

    #[error("Offline operation failed: {0}")]
    #[allow(dead_code)]
    Offline(String),

    #[error(transparent)]
    Io(#[from] std::io::Error),

    #[error(transparent)]
    Serde(#[from] serde_json::Error),
}

impl serde::Serialize for AppError {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(&self.to_string())
    }
}

pub type AppResult<T> = Result<T, AppError>;
