//! Marty Verifier — library target.
//!
//! Exposes all internal modules under a single crate root so that integration
//! tests in `tests/` can link against the verification logic without a live
//! Tauri runtime or `AppState`.
//!
//! The binary entry point remains `main.rs`, which imports from this crate.

pub mod commands;
pub mod config;
pub mod error;
pub mod hardware;
pub mod runtime_config;
pub mod state;
