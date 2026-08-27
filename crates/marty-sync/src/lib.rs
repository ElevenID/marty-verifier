//! Marty Sync Engine
//!
//! Trust anchor synchronization for offline-first verification.
//! Supports AAMVA DTS (IACA) and ICAO PKD (CSCA/DSC) sources.

mod engine;
mod error;
mod policy;
mod profile_sync;
mod signing_key;
mod sources;
mod usb;

#[cfg(feature = "demo-fixtures")]
pub mod demo_fixtures;
#[cfg(feature = "demo-fixtures")]
pub mod emrtd_demo_fixtures;

pub use engine::{SyncConfig, SyncEngine, SyncResult, SyncStatus};
pub use error::SyncError;
pub use policy::{PolicyStorage, PolicySyncProvider};
pub use profile_sync::{
    DeploymentProfile, DeviceConfig, Lane, NetworkMode, ProfileSyncProvider, UXConfig, UpdatePolicy,
};
pub use usb::UsbImportResult;
