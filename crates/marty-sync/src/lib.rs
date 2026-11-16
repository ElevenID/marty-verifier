//! Marty Sync Engine
//!
//! Trust anchor synchronization for offline-first verification.
//! Supports AAMVA DTS (IACA) and ICAO PKD (CSCA/DSC) sources.

#[cfg(all(feature = "native-sync", target_arch = "wasm32"))]
compile_error!("native-sync requires a native target; browser policy/profile HTTP clients use default-features = false");

#[cfg(feature = "native-sync")]
mod engine;
mod error;
mod http;
mod policy;
mod profile_sync;
#[cfg(feature = "native-sync")]
mod signing_key;
#[cfg(feature = "native-sync")]
mod sources;
#[cfg(feature = "native-sync")]
mod usb;

#[cfg(feature = "demo-fixtures")]
pub mod demo_fixtures;
#[cfg(feature = "demo-fixtures")]
pub mod emrtd_demo_fixtures;

#[cfg(feature = "native-sync")]
pub use engine::{SyncConfig, SyncEngine, SyncResult, SyncStatus};
pub use error::SyncError;
pub use policy::{PolicyStorage, PolicySyncProvider};
pub use profile_sync::{
    DeploymentProfile, DeviceConfig, Lane, NetworkMode, ProfileSyncProvider, UXConfig, UpdatePolicy,
};
#[cfg(feature = "native-sync")]
pub use usb::UsbImportResult;
