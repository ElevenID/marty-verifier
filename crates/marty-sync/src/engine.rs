//! Sync engine

use std::path::Path;
use std::sync::Arc;
use std::time::Instant;

use chrono::Utc;
use serde::{Deserialize, Serialize};
use tokio::sync::RwLock;

use marty_secure_storage::{SecureStorage, SyncState, TrustAnchorType};

use crate::error::SyncError;
use crate::usb::{import_from_usb, UsbImportResult};

/// Sync configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SyncConfig {
    /// AAMVA DTS endpoint
    pub aamva_dts_url: Option<String>,
    /// ICAO PKD endpoint
    pub icao_pkd_url: Option<String>,
    /// Open Badge trust store endpoint
    pub open_badge_keys_url: Option<String>,
    /// Sync interval in hours
    pub sync_interval_hours: u32,
    /// Enable USB import
    pub enable_usb_import: bool,
    /// Maximum offline hours before warning
    pub max_offline_hours: u32,
}

impl Default for SyncConfig {
    fn default() -> Self {
        Self {
            aamva_dts_url: None,
            icao_pkd_url: None,
            open_badge_keys_url: None,
            sync_interval_hours: 24,
            enable_usb_import: true,
            max_offline_hours: 72,
        }
    }
}

/// Sync status
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SyncStatus {
    pub last_sync: Option<String>,
    pub hours_since_sync: Option<f64>,
    pub iaca_certificates: usize,
    pub csca_certificates: usize,
    pub dsc_certificates: usize,
    pub open_badge_keys: usize,
    pub open_badge_last_sync: Option<String>,
    pub open_badge_hours_since_sync: Option<f64>,
    pub open_badge_sync_overdue: bool,
    pub crl_cache_age_hours: Option<f64>,
    pub sync_overdue: bool,
    pub sync_in_progress: bool,
    pub last_error: Option<String>,
}

/// Sync result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SyncResult {
    pub success: bool,
    pub iaca_updated: usize,
    pub csca_updated: usize,
    pub dsc_updated: usize,
    pub open_badge_keys_updated: usize,
    pub crl_updated: bool,
    pub duration_seconds: f64,
    pub error: Option<String>,
}

/// Sync engine for trust anchor updates
pub struct SyncEngine {
    storage: Arc<SecureStorage>,
    config: SyncConfig,
    sync_in_progress: RwLock<bool>,
}

impl SyncEngine {
    /// Create new sync engine
    pub fn new(storage: Arc<SecureStorage>, config: SyncConfig) -> Result<Self, SyncError> {
        Ok(Self {
            storage,
            config,
            sync_in_progress: RwLock::new(false),
        })
    }

    /// Get current sync status
    pub async fn get_status(&self) -> Result<SyncStatus, SyncError> {
        let state = self.storage.get_sync_state().await?;
        let sync_in_progress = *self.sync_in_progress.read().await;

        // Count certificates
        let iaca_count = self
            .storage
            .count_trust_anchors(TrustAnchorType::Iaca)
            .await?;
        let csca_count = self
            .storage
            .count_trust_anchors(TrustAnchorType::Csca)
            .await?;
        let dsc_count = self
            .storage
            .count_trust_anchors(TrustAnchorType::Dsc)
            .await?;
        let open_badge_count = self.storage.count_open_badge_keys().await?;
        let open_badge_last_sync = self.storage.get_latest_open_badge_sync().await?;

        // Calculate hours since last sync
        let (last_sync, hours_since_sync) = if let Some(ref state) = state {
            let last = state.last_iaca_sync.or(state.last_csca_sync);
            let hours = last.map(|dt| (Utc::now() - dt).num_minutes() as f64 / 60.0);
            (last.map(|dt| dt.to_rfc3339()), hours)
        } else {
            (None, None)
        };

        // Check if sync is overdue
        let sync_overdue = hours_since_sync
            .map(|h| h > self.config.max_offline_hours as f64)
            .unwrap_or(true);

        let (open_badge_last_sync_str, open_badge_hours_since_sync) =
            if let Some(last) = open_badge_last_sync {
                (
                    Some(last.to_rfc3339()),
                    Some((Utc::now() - last).num_minutes() as f64 / 60.0),
                )
            } else {
                (None, None)
            };

        let open_badge_sync_overdue = open_badge_hours_since_sync
            .map(|h| h > self.config.max_offline_hours as f64)
            .unwrap_or(true);

        Ok(SyncStatus {
            last_sync,
            hours_since_sync,
            iaca_certificates: iaca_count,
            csca_certificates: csca_count,
            dsc_certificates: dsc_count,
            open_badge_keys: open_badge_count,
            open_badge_last_sync: open_badge_last_sync_str,
            open_badge_hours_since_sync,
            open_badge_sync_overdue,
            crl_cache_age_hours: state.as_ref().and_then(|s| {
                s.last_crl_sync
                    .map(|dt| (Utc::now() - dt).num_minutes() as f64 / 60.0)
            }),
            sync_overdue,
            sync_in_progress,
            last_error: state.and_then(|s| s.last_error),
        })
    }

    /// Perform sync
    pub async fn sync(&self, force: bool) -> Result<SyncResult, SyncError> {
        // Check if already in progress
        {
            let mut in_progress = self.sync_in_progress.write().await;
            if *in_progress && !force {
                return Err(SyncError::SyncInProgress);
            }
            *in_progress = true;
        }

        let start = Instant::now();
        let mut result = SyncResult {
            success: false,
            iaca_updated: 0,
            csca_updated: 0,
            dsc_updated: 0,
            open_badge_keys_updated: 0,
            crl_updated: false,
            duration_seconds: 0.0,
            error: None,
        };

        // Perform sync operations
        let sync_result = self.do_sync(&mut result).await;

        // Update sync state
        let mut state = self.storage.get_sync_state().await?.unwrap_or(SyncState {
            last_iaca_sync: None,
            last_csca_sync: None,
            last_crl_sync: None,
            iaca_version: None,
            csca_version: None,
            sync_in_progress: false,
            last_error: None,
        });

        state.sync_in_progress = false;

        match &sync_result {
            Ok(_) => {
                state.last_iaca_sync = Some(Utc::now());
                state.last_csca_sync = Some(Utc::now());
                state.last_error = None;
                result.success = true;
            }
            Err(e) => {
                state.last_error = Some(e.to_string());
                result.error = Some(e.to_string());
            }
        }

        self.storage.update_sync_state(&state).await?;

        result.duration_seconds = start.elapsed().as_secs_f64();

        // Release lock
        *self.sync_in_progress.write().await = false;

        tracing::info!(
            success = result.success,
            iaca = result.iaca_updated,
            csca = result.csca_updated,
            dsc = result.dsc_updated,
            open_badge_keys = result.open_badge_keys_updated,
            duration_secs = result.duration_seconds,
            "Sync completed"
        );

        Ok(result)
    }

    async fn do_sync(&self, _result: &mut SyncResult) -> Result<(), SyncError> {
        // Sync IACA from AAMVA DTS
        #[cfg(feature = "aamva")]
        if let Some(ref url) = self.config.aamva_dts_url {
            tracing::info!(url, "Syncing IACA from AAMVA DTS");
            // TODO: Implement actual sync
            // For now, just log
        }

        // Sync CSCA/DSC from ICAO PKD
        #[cfg(feature = "icao")]
        if let Some(ref url) = self.config.icao_pkd_url {
            tracing::info!(url, "Syncing CSCA/DSC from ICAO PKD");
            // TODO: Implement actual sync
        }

        // Sync Open Badge verification methods
        if let Some(ref url) = self.config.open_badge_keys_url {
            tracing::info!(url, "Syncing Open Badge verification methods");
            // TODO: Implement trust store sync from endpoint
        }

        // If no sources configured, that's still a "success" (offline mode)
        if self.config.aamva_dts_url.is_none()
            && self.config.icao_pkd_url.is_none()
            && self.config.open_badge_keys_url.is_none()
        {
            tracing::warn!("No sync sources configured - operating in offline mode");
        }

        Ok(())
    }

    /// Import trust anchors from USB
    pub async fn import_from_usb(&self, path: &str) -> Result<UsbImportResult, SyncError> {
        if !self.config.enable_usb_import {
            return Err(SyncError::UsbImport("USB import disabled".to_string()));
        }

        let path = Path::new(path);
        let (anchors, open_badge_keys, mut result) = import_from_usb(path).await?;

        // Store imported anchors
        for anchor in anchors {
            self.storage.store_trust_anchor(&anchor).await?;
        }

        // Store Open Badge verification methods
        for method in open_badge_keys {
            self.storage.store_open_badge_key(&method).await?;
        }

        // Update sync state
        let mut state = self.storage.get_sync_state().await?.unwrap_or(SyncState {
            last_iaca_sync: None,
            last_csca_sync: None,
            last_crl_sync: None,
            iaca_version: None,
            csca_version: None,
            sync_in_progress: false,
            last_error: None,
        });

        state.last_iaca_sync = Some(Utc::now());
        state.last_csca_sync = Some(Utc::now());
        state.iaca_version = result.package_version.clone();
        state.csca_version = result.package_version.clone();

        self.storage.update_sync_state(&state).await?;

        // Log audit event
        self.storage
            .add_audit_log(
                "usb_import",
                None,
                Some(path.to_string_lossy().as_ref()),
                Some(&serde_json::json!({
                    "certificates_imported": result.certificates_imported,
                    "open_badge_keys_imported": result.open_badge_keys_imported,
                    "package_version": result.package_version
                })),
            )
            .await?;

        result.success = true;
        Ok(result)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sync_config_default() {
        let config = SyncConfig::default();

        assert!(config.aamva_dts_url.is_none());
        assert!(config.icao_pkd_url.is_none());
        assert!(config.open_badge_keys_url.is_none());
        assert_eq!(config.sync_interval_hours, 24);
        assert!(config.enable_usb_import);
        assert_eq!(config.max_offline_hours, 72);
    }

    #[test]
    fn test_sync_config_custom() {
        let config = SyncConfig {
            aamva_dts_url: Some("https://dts.aamva.org".to_string()),
            icao_pkd_url: Some("https://pkd.icao.int".to_string()),
            open_badge_keys_url: Some("https://trust.example.org/open-badges".to_string()),
            sync_interval_hours: 12,
            enable_usb_import: false,
            max_offline_hours: 48,
        };

        assert_eq!(config.aamva_dts_url.unwrap(), "https://dts.aamva.org");
        assert_eq!(config.sync_interval_hours, 12);
        assert!(!config.enable_usb_import);
        assert_eq!(
            config.open_badge_keys_url.unwrap(),
            "https://trust.example.org/open-badges"
        );
    }

    #[test]
    fn test_sync_status_serialization() {
        let status = SyncStatus {
            last_sync: Some("2025-01-01T00:00:00Z".to_string()),
            hours_since_sync: Some(5.5),
            iaca_certificates: 50,
            csca_certificates: 100,
            dsc_certificates: 400,
            open_badge_keys: 12,
            open_badge_last_sync: Some("2025-01-01T01:00:00Z".to_string()),
            open_badge_hours_since_sync: Some(4.5),
            open_badge_sync_overdue: false,
            crl_cache_age_hours: Some(2.0),
            sync_overdue: false,
            sync_in_progress: false,
            last_error: None,
        };

        let json = serde_json::to_string(&status).unwrap();
        let deserialized: SyncStatus = serde_json::from_str(&json).unwrap();

        assert_eq!(deserialized.iaca_certificates, 50);
        assert_eq!(deserialized.csca_certificates, 100);
        assert_eq!(deserialized.open_badge_keys, 12);
        assert!(!deserialized.sync_overdue);
    }

    #[test]
    fn test_sync_result_success() {
        let result = SyncResult {
            success: true,
            iaca_updated: 10,
            csca_updated: 20,
            dsc_updated: 50,
            open_badge_keys_updated: 4,
            crl_updated: true,
            duration_seconds: 3.5,
            error: None,
        };

        assert!(result.success);
        assert_eq!(result.iaca_updated, 10);
        assert!(result.error.is_none());
    }

    #[test]
    fn test_sync_result_failure() {
        let result = SyncResult {
            success: false,
            iaca_updated: 0,
            csca_updated: 0,
            dsc_updated: 0,
            open_badge_keys_updated: 0,
            crl_updated: false,
            duration_seconds: 0.1,
            error: Some("Network timeout".to_string()),
        };

        assert!(!result.success);
        assert_eq!(result.error.unwrap(), "Network timeout");
    }
}
