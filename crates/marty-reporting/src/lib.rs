//! Marty Reporting
//!
//! Reporting and analytics module for the Marty Verifier.
//! Supports REST API, batch upload, and local-only modes.
//! Can be excluded from builds entirely via Cargo feature flags.

mod config;
#[cfg(feature = "api")]
mod durable_ack;
mod error;
mod events;
mod reporter;

pub use config::{ApiAcknowledgement, ReportingConfig};
pub use error::ReportingError;
pub use events::{EventPayload, VerificationEvent};
pub use reporter::Reporter;
