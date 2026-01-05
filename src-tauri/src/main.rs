//! Marty Verifier - Offline-first edge verification kiosk
//!
//! A Tauri-based application for verifying digital credentials at edge checkpoints.
//! Supports mDL (ISO 18013-5), eMRTD (ICAO 9303), OID4VP, and SD-JWT credentials.

#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

mod commands;
mod config;
mod error;
mod hardware;
mod state;

use state::AppState;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

fn main() {
    // Initialize tracing
    tracing_subscriber::registry()
        .with(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "marty_verifier=debug,marty_secure_storage=debug".into()),
        )
        .with(tracing_subscriber::fmt::layer())
        .init();

    tracing::info!("Starting Marty Verifier");

    // Initialize app state
    let app_state = AppState::new().expect("Failed to initialize application state");

    // Clone license manager for async setup
    let license_for_setup = app_state.license.clone();
    let config_public_key = app_state.config.blocking_read().license_public_key.clone();

    tauri::Builder::default()
        .plugin(tauri_plugin_shell::init())
        .plugin(tauri_plugin_updater::Builder::new().build())
        .manage(app_state)
        .setup(move |_app| {
            // Auto-install dev license on startup if in dev mode
            if config_public_key.is_empty() {
                tauri::async_runtime::spawn(async move {
                    // Check if license already valid
                    if let Ok(status) = license_for_setup.get_status().await {
                        if status.valid {
                            tracing::info!("License already active");
                            return;
                        }
                    }

                    // Generate and install dev license
                    let dev_license = generate_dev_license_jwt();
                    tracing::info!("Installing development license");

                    match license_for_setup.validate_license(&dev_license).await {
                        Ok(result) => {
                            tracing::info!(
                                org_id = ?result.org_id,
                                features = ?result.features,
                                "Development license activated"
                            );
                        }
                        Err(e) => {
                            tracing::warn!("Failed to install dev license: {}", e);
                        }
                    }
                });
            }
            Ok(())
        })
        .invoke_handler(tauri::generate_handler![
            // License commands
            commands::license::validate_license,
            commands::license::get_license_status,
            commands::license::get_licensed_features,
            // Verification commands
            commands::verification::issue_liveness_challenge,
            commands::verification::verify_credential,
            commands::verification::get_verification_history,
            commands::biometrics::verify_face_match,
            // Storage commands
            commands::storage::get_offline_queue_status,
            commands::storage::clear_verification_history,
            // Sync commands
            commands::sync::sync_trust_anchors,
            commands::sync::get_sync_status,
            commands::sync::import_trust_anchors_usb,
            // Hardware commands
            commands::hardware::detect_hardware,
            commands::hardware::get_hardware_tier,
            // Config commands
            commands::config::get_config,
            commands::config::update_config,
            // Update commands
            commands::update::check_for_updates,
            commands::update::download_and_install_update,
        ])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}

/// Generate a development JWT license
fn generate_dev_license_jwt() -> String {
    use base64::Engine;

    let now = chrono::Utc::now().timestamp();
    let exp = now + 365 * 24 * 60 * 60; // 1 year

    let header = r#"{"alg":"EdDSA","typ":"JWT"}"#;
    let claims = format!(
        r#"{{"iss":"marty-license-issuer","sub":"dev-org-001","iat":{},"exp":{},"jti":"dev-license-auto","features":["mdl","emrtd","oid4vp","sd-jwt","dtc","open-badge","usb-sync","reporting"],"deployment_mode":"development","max_verifications_total":100000,"org_name":"Development License","update_channels":["stable","beta","dev"],"grace_period_days":90}}"#,
        now, exp
    );

    let header_b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(header);
    let claims_b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(&claims);

    format!("{}.{}.dev_signature", header_b64, claims_b64)
}
