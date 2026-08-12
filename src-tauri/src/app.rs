//! Shared Tauri application wiring.

use crate::commands;

/// Build the single command registry used by both production startup and the
/// packaged startup self-check.
pub fn command_handler() -> impl Fn(tauri::ipc::Invoke<tauri::Wry>) -> bool + Send + Sync + 'static
{
    tauri::generate_handler![
        commands::verification::issue_liveness_challenge,
        commands::verification::verify_credential,
        commands::verification::get_verification_history,
        commands::biometrics::verify_face_match,
        #[cfg(feature = "biometrics")]
        commands::biometrics::assess_face_quality,
        commands::storage::get_offline_queue_status,
        commands::storage::clear_verification_history,
        commands::sync::sync_trust_anchors,
        commands::sync::get_sync_status,
        commands::sync::import_trust_anchors_usb,
        commands::profile_sync::sync_device_config,
        commands::profile_sync::get_runtime_config,
        commands::hardware::detect_hardware,
        commands::hardware::get_hardware_tier,
        commands::config::get_config,
        commands::config::update_config,
        commands::update::check_for_updates,
        commands::update::download_and_install_update,
    ]
}
