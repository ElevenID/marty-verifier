//! Sync error types

use thiserror::Error;

#[derive(Error, Debug)]
pub enum SyncError {
    #[error("Network error: {0}")]
    Network(String),

    #[error("Storage error: {0}")]
    Storage(#[from] marty_secure_storage::StorageError),

    #[error("Parse error: {0}")]
    Parse(String),

    #[error("Certificate error: {0}")]
    Certificate(String),

    #[error("USB import error: {0}")]
    UsbImport(String),

    #[error("Signature verification failed")]
    SignatureVerification,

    #[error("Sync already in progress")]
    SyncInProgress,

    #[error("Source not available: {0}")]
    SourceUnavailable(String),

    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    #[error("Network error: {0}")]
    NetworkError(String),

    #[error("HTTP error {0}: {1}")]
    HttpError(u16, String),

    #[error("Parse error: {0}")]
    ParseError(String),
}

impl serde::Serialize for SyncError {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(&self.to_string())
    }
}
