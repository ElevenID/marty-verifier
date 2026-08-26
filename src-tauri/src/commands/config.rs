//! Configuration commands

use tauri::State;

use crate::config::AppConfig;
use crate::error::AppResult;
use crate::state::AppState;

/// Get current configuration
#[tauri::command]
pub async fn get_config(state: State<'_, AppState>) -> AppResult<AppConfig> {
    let config = state.config.read().await;
    Ok(config.clone())
}

/// Update configuration
#[tauri::command]
pub async fn update_config(new_config: AppConfig, state: State<'_, AppState>) -> AppResult<()> {
    new_config.save()?;
    state
        .reporter
        .set_config(new_config.reporting_config.clone())
        .await;
    let mut config = state.config.write().await;
    *config = new_config;
    tracing::info!("Configuration updated");
    Ok(())
}
