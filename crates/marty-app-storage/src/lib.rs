//! Marty App Storage
//!
//! Encrypted local storage for the Marty Verifier application.
//! Uses SQLCipher for encrypted SQLite and platform keychain for key storage.

mod database;
mod encryption;
mod error;
mod keychain;
mod models;
mod schema;

pub use database::SecureStorage;
pub use error::StorageError;
pub use models::*;

/// Re-export for command handlers
pub use database::{OfflineQueueStatus, VerificationHistoryEntry};

/// Re-export sync types to avoid duplication
pub use marty_sync::{DeploymentProfile, Lane, NetworkMode, UXConfig, UpdatePolicy};

/// Re-export policy types
pub use marty_verification::policy::PresentationPolicy;
