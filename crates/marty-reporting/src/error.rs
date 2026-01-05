//! Reporting error types

use thiserror::Error;

#[derive(Error, Debug)]
pub enum ReportingError {
    #[error("Network error: {0}")]
    Network(String),

    #[error("Storage error: {0}")]
    Storage(#[from] marty_secure_storage::StorageError),

    #[error("Serialization error: {0}")]
    Serialization(#[from] serde_json::Error),

    #[error("Configuration error: {0}")]
    Configuration(String),

    #[error("Queue full: {size}/{max}")]
    QueueFull { size: usize, max: usize },

    #[error("Reporting disabled")]
    Disabled,

    #[error("Rate limited")]
    RateLimited,
}

impl serde::Serialize for ReportingError {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(&self.to_string())
    }
}
