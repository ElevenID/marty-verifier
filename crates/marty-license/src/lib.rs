//! Marty License Management
//!
//! Cryptographic license validation for all Marty products: verifier app, backend containers, and CLI.
//! Supports JWT-based licenses with Ed25519 signatures and optional hardware binding.

mod claims;
mod error;
mod fingerprint;
mod manager;
mod validation;

pub use claims::{products, LicenseClaims, PlanTier};
pub use error::LicenseError;
pub use manager::{LicenseManager, LicenseStatus, LicenseValidationResult};
