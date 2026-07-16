//! Marty Verifier - Offline-first edge verification kiosk
//!
//! A Tauri-based application for verifying digital credentials at edge checkpoints.
//! Supports mDL (ISO 18013-5), eMRTD (ICAO 9303), OID4VP, and SD-JWT credentials.

#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

use marty_verifier::commands;
use marty_verifier::state::AppState;
use tauri::Manager;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

fn main() {
    // Initialize tracing
    tracing_subscriber::registry()
        .with(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "marty_verifier=debug,marty_app_storage=debug".into()),
        )
        .with(tracing_subscriber::fmt::layer())
        .init();

    tracing::info!("Starting Marty Verifier");

    // Initialize app state
    let app_state = AppState::new().expect("Failed to initialize application state");

    // Clone storage and runtime config for profile sync
    let storage_for_sync = app_state.storage.clone();
    let runtime_config_for_sync = app_state.runtime_config.clone();

    tauri::Builder::default()
        .plugin(tauri_plugin_shell::init())
        .plugin(tauri_plugin_updater::Builder::new().build())
        .manage(app_state)
        .setup(move |app| {
            // Restore runtime configuration from storage
            let handle = app.handle().clone();
            tauri::async_runtime::spawn(async move {
                let state = handle.state::<AppState>();
                if let Err(e) = state.restore_from_storage().await {
                    tracing::warn!("Failed to restore runtime config from storage: {}", e);
                }
            });

            // Sync device configuration on startup
            tauri::async_runtime::spawn(async move {
                tracing::info!("Syncing device configuration on startup");
                match commands::profile_sync::sync_device_config_impl(
                    storage_for_sync,
                    runtime_config_for_sync,
                )
                .await
                {
                    Ok(result) => {
                        tracing::info!(
                            profile_id = ?result.profile_id,
                            lane_id = ?result.lane_id,
                            "Device configuration synced successfully"
                        );
                    }
                    Err(e) => {
                        tracing::warn!("Failed to sync device config on startup: {}", e);
                    }
                }
            });
            Ok(())
        })
        .invoke_handler(tauri::generate_handler![
            // Verification commands
            commands::verification::issue_liveness_challenge,
            commands::verification::verify_credential,
            commands::verification::get_verification_history,
            commands::biometrics::verify_face_match,
            #[cfg(feature = "biometrics")]
            commands::biometrics::assess_face_quality,
            // Storage commands
            commands::storage::get_offline_queue_status,
            commands::storage::clear_verification_history,
            // Sync commands
            commands::sync::sync_trust_anchors,
            commands::sync::get_sync_status,
            commands::sync::import_trust_anchors_usb,
            // Profile sync commands
            commands::profile_sync::sync_device_config,
            commands::profile_sync::get_runtime_config,
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
