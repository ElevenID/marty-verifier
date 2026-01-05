//! Marty Sync Engine
//!
//! Trust anchor synchronization for offline-first verification.
//! Supports AAMVA DTS (IACA) and ICAO PKD (CSCA/DSC) sources.

mod engine;
mod error;
mod sources;
mod usb;

pub use engine::{SyncConfig, SyncEngine, SyncResult, SyncStatus};
pub use error::SyncError;
pub use usb::UsbImportResult;
