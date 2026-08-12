//! Bounded, offline startup validation for packaged release payloads.

use std::ffi::OsString;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::{any::Any, collections::HashMap};

use anyhow::{anyhow, Context, Result};
use base64::Engine;
use serde::Serialize;
use tauri::utils::assets::AssetKey;

use crate::config::{AppConfig, OpenBadgeTrustPolicy};
use crate::state::AppState;

const CHECKS: [&str; 6] = [
    "embedded_frontend",
    "configuration_defaults",
    "app_storage_migrations",
    "trust_storage_initialization",
    "runtime_storage_restore",
    "command_registration",
];
const MAX_FAILURE_DIAGNOSTIC_CHARS: usize = 2_048;

type LegacySecrets = Arc<Mutex<HashMap<String, Vec<u8>>>>;

#[derive(Debug, Default)]
struct LegacyMemoryBuilder {
    secrets: LegacySecrets,
}

#[derive(Debug)]
struct LegacyMemoryCredential {
    key: String,
    secrets: LegacySecrets,
}

impl keyring_legacy::credential::CredentialBuilderApi for LegacyMemoryBuilder {
    fn build(
        &self,
        target: Option<&str>,
        service: &str,
        user: &str,
    ) -> keyring_legacy::Result<Box<keyring_legacy::Credential>> {
        Ok(Box::new(LegacyMemoryCredential {
            key: format!("{}\0{service}\0{user}", target.unwrap_or_default()),
            secrets: Arc::clone(&self.secrets),
        }))
    }

    fn as_any(&self) -> &dyn Any {
        self
    }

    fn persistence(&self) -> keyring_legacy::credential::CredentialPersistence {
        keyring_legacy::credential::CredentialPersistence::ProcessOnly
    }
}

impl keyring_legacy::credential::CredentialApi for LegacyMemoryCredential {
    fn set_secret(&self, secret: &[u8]) -> keyring_legacy::Result<()> {
        self.secrets
            .lock()
            .expect("legacy self-check keyring lock poisoned")
            .insert(self.key.clone(), secret.to_vec());
        Ok(())
    }

    fn get_secret(&self) -> keyring_legacy::Result<Vec<u8>> {
        self.secrets
            .lock()
            .expect("legacy self-check keyring lock poisoned")
            .get(&self.key)
            .cloned()
            .ok_or(keyring_legacy::Error::NoEntry)
    }

    fn delete_credential(&self) -> keyring_legacy::Result<()> {
        self.secrets
            .lock()
            .expect("legacy self-check keyring lock poisoned")
            .remove(&self.key)
            .map(|_| ())
            .ok_or(keyring_legacy::Error::NoEntry)
    }

    fn as_any(&self) -> &dyn Any {
        self
    }
}

#[derive(Debug, Serialize)]
struct SelfCheckReport<'a> {
    schema_version: u8,
    application: &'a str,
    version: &'a str,
    status: &'a str,
    checks: &'a [&'a str],
}

/// Run self-check mode when the exact self-check CLI contract was requested.
/// Returns `None` for normal GUI startup and an exit code for self-check mode.
pub fn run_if_requested() -> Option<i32> {
    let args: Vec<OsString> = std::env::args_os().skip(1).collect();
    if args.first().and_then(|arg| arg.to_str()) != Some("--self-check") {
        return None;
    }

    let report_path = match parse_report_path(&args) {
        Ok(path) => path,
        Err(error) => {
            emit_failure_diagnostic("arguments", &error);
            return Some(2);
        }
    };

    match perform_self_check() {
        Ok(()) => {
            let report = SelfCheckReport {
                schema_version: 1,
                application: "marty-verifier",
                version: env!("CARGO_PKG_VERSION"),
                status: "passed",
                checks: &CHECKS,
            };
            match write_report(&report_path, &report) {
                Ok(()) => Some(0),
                Err(error) => {
                    emit_failure_diagnostic("report", &error);
                    Some(1)
                }
            }
        }
        Err(error) => {
            emit_failure_diagnostic("startup", &error);
            Some(1)
        }
    }
}

fn emit_failure_diagnostic(stage: &str, error: &anyhow::Error) {
    let bounded = failure_diagnostic(error);
    eprintln!("marty-verifier self-check failed ({stage}): {bounded}");
}

fn failure_diagnostic(error: &anyhow::Error) -> String {
    let detail = format!("{error:#}");
    let mut bounded = String::with_capacity(detail.len().min(MAX_FAILURE_DIAGNOSTIC_CHARS));
    let mut truncated = false;
    for (index, character) in detail.chars().enumerate() {
        if index == MAX_FAILURE_DIAGNOSTIC_CHARS {
            truncated = true;
            break;
        }
        match character {
            '\n' | '\r' => bounded.push_str("; "),
            character if character.is_control() => bounded.push(' '),
            character => bounded.push(character),
        }
    }
    if truncated {
        bounded.push_str("...");
    }
    bounded
}

fn parse_report_path(args: &[OsString]) -> Result<PathBuf> {
    if args.len() != 3 || args.get(1).and_then(|arg| arg.to_str()) != Some("--report") {
        return Err(anyhow!("invalid self-check arguments"));
    }
    let path = PathBuf::from(&args[2]);
    if path.as_os_str().is_empty() {
        return Err(anyhow!("self-check report path is empty"));
    }
    Ok(path)
}

fn write_report(path: &Path, report: &SelfCheckReport<'_>) -> Result<()> {
    let parent = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .ok_or_else(|| anyhow!("self-check report requires a parent directory"))?;
    if !parent.is_dir() {
        return Err(anyhow!("self-check report parent does not exist"));
    }
    let bytes = serde_json::to_vec_pretty(report)?;
    std::fs::write(path, bytes).context("write self-check report")
}

fn perform_self_check() -> Result<()> {
    install_ephemeral_keyrings()?;

    let context: tauri::Context<tauri::Wry> = tauri::generate_context!();
    validate_context(&context)?;

    let temporary = tempfile::tempdir().context("create isolated self-check directory")?;
    let config = AppConfig {
        data_dir: temporary.path().join("data"),
        ..AppConfig::default()
    };
    validate_safe_defaults(&config)?;

    let state = AppState::from_config(config).context("initialize application state")?;
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .context("create self-check runtime")?;
    runtime.block_on(async {
        state
            .storage
            .health_check()
            .await
            .context("validate app storage migration")?;
        state
            .trust_storage
            .get_sync_state()
            .await
            .context("validate governed trust storage")?;
        state
            .restore_from_storage()
            .await
            .context("restore runtime storage")?;
        Result::<()>::Ok(())
    })?;

    let _handler = crate::app::command_handler();
    Ok(())
}

fn install_ephemeral_keyrings() -> Result<()> {
    keyring_core::set_default_store(
        keyring_core::mock::Store::new().context("create current keyring store")?,
    );
    keyring_legacy::set_default_credential_builder(Box::new(LegacyMemoryBuilder::default()));

    let database_key = base64::engine::general_purpose::STANDARD.encode([0x42_u8; 32]);
    let pii_key = base64::engine::general_purpose::STANDARD.encode([0x24_u8; 32]);
    seed_current_keyring("database_encryption_key", &database_key)?;
    seed_current_keyring("pii_encryption_key", &pii_key)?;
    seed_legacy_keyring("database_encryption_key", &database_key)?;
    Ok(())
}

fn seed_current_keyring(name: &str, value: &str) -> Result<()> {
    keyring::Entry::new("com.marty.verifier", name)
        .context("create current keyring entry")?
        .set_password(value)
        .context("seed current keyring")
}

fn seed_legacy_keyring(name: &str, value: &str) -> Result<()> {
    keyring_legacy::Entry::new("com.marty.verifier", name)
        .context("create legacy keyring entry")?
        .set_password(value)
        .context("seed legacy keyring")
}

fn validate_context(context: &tauri::Context<tauri::Wry>) -> Result<()> {
    let index = context.assets().get(&AssetKey::from("index.html"));
    validate_frontend_asset(index.as_deref())?;

    let config = context.config();
    if config.identifier != "com.marty.verifier" {
        return Err(anyhow!("unexpected application identifier"));
    }
    if config.version.as_deref() != Some(env!("CARGO_PKG_VERSION")) {
        return Err(anyhow!("embedded application version mismatch"));
    }
    if config.app.windows.is_empty() {
        return Err(anyhow!("no application window is configured"));
    }
    Ok(())
}

fn validate_frontend_asset(index: Option<&[u8]>) -> Result<()> {
    let index = index.ok_or_else(|| anyhow!("embedded index asset is missing"))?;
    if index.is_empty() || !String::from_utf8_lossy(index).contains("<html") {
        return Err(anyhow!("embedded index asset is invalid"));
    }
    Ok(())
}

fn validate_safe_defaults(config: &AppConfig) -> Result<()> {
    if config.update_config.enabled
        || config.oid4vp.credentials_api_url.is_some()
        || config.oid4vp.credentials_api_token.is_some()
        || !matches!(
            config.open_badge_trust.policy,
            OpenBadgeTrustPolicy::FailClosed
        )
    {
        return Err(anyhow!("unsafe startup defaults"));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn complete_startup_self_check_initializes_owned_runtime() {
        if tauri::is_dev() {
            // Cargo's ordinary test profile intentionally uses the dev URL and
            // has no embedded frontend. Release payloads exercise this path.
            return;
        }
        perform_self_check().expect("complete startup self-check must pass");
    }

    #[test]
    fn missing_or_invalid_frontend_asset_fails_closed() {
        assert!(validate_frontend_asset(None).is_err());
        assert!(validate_frontend_asset(Some(b"")).is_err());
        assert!(validate_frontend_asset(Some(b"not html")).is_err());
        validate_frontend_asset(Some(b"<!doctype html><html></html>"))
            .expect("valid embedded HTML");
    }

    #[test]
    fn unsafe_network_or_trust_defaults_fail_closed() {
        let mut config = AppConfig::default();
        validate_safe_defaults(&config).expect("owned defaults must be safe");

        config.update_config.enabled = true;
        assert!(validate_safe_defaults(&config).is_err());

        config.update_config.enabled = false;
        config.open_badge_trust.policy = OpenBadgeTrustPolicy::FailOpen;
        assert!(validate_safe_defaults(&config).is_err());
    }

    #[test]
    fn failure_diagnostic_is_bounded_and_single_line() {
        let error = anyhow!("{}\nprivate second line", "x".repeat(4_096));
        let bounded = failure_diagnostic(&error);
        assert_eq!(bounded.chars().count(), MAX_FAILURE_DIAGNOSTIC_CHARS + 3);
        assert!(!bounded.contains('\n'));
        assert!(!bounded.contains("private second line"));
        assert!(bounded.ends_with("..."));
    }
}
