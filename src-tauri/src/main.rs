//! Marty Verifier - Offline-first edge verification kiosk
//!
//! A Tauri-based application for verifying digital credentials at edge checkpoints.
//! Supports mDL (ISO 18013-5), eMRTD (ICAO 9303), OID4VP, and SD-JWT credentials.

#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

use marty_verifier::state::AppState;
use marty_verifier::{app, commands, startup_self_check};
use tauri::Manager;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

fn main() {
    if let Some(exit_code) = startup_self_check::run_if_requested() {
        std::process::exit(exit_code);
    }

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
        .invoke_handler(app::command_handler())
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}
