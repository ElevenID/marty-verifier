//! Marty License Management
//!
//! Cryptographic license validation for the Marty Verifier application.
//! Supports JWT-based licenses with Ed25519 signatures and optional hardware binding.

mod claims;
mod error;
mod fingerprint;
mod manager;
mod validation;

pub use claims::LicenseClaims;
pub use error::LicenseError;
pub use manager::{LicenseManager, LicenseStatus, LicenseValidationResult};
