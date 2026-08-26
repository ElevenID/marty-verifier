//! Sync engine

use std::path::Path;
use std::sync::Arc;
use std::time::Instant;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use tokio::sync::RwLock;

use marty_secure_storage::{SecureStorage, SyncState, TrustAnchorType};

use crate::error::SyncError;
use crate::usb::{import_from_usb, validate_trust_domain, UsbImportResult, VerifiedTrustPackage};

fn default_usb_trust_domain() -> String {
    "usb:default".to_string()
}

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
    /// Out-of-band trust domain packages must declare exactly.
    #[serde(default = "default_usb_trust_domain")]
    pub usb_trust_domain: String,
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
            usb_trust_domain: default_usb_trust_domain(),
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
        validate_trust_domain(&config.usb_trust_domain)?;
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

    /// Require a recently synchronized CSCA cache before a verification path
    /// consumes locally stored passport or DTC trust anchors.
    ///
    /// A configured network connection is not itself evidence that the cache
    /// is current: verification remains fail-closed until a signed package has
    /// actually advanced the CSCA synchronization timestamp.
    pub async fn ensure_csca_cache_fresh(&self) -> Result<(), SyncError> {
        let last_sync = self
            .storage
            .get_sync_state()
            .await?
            .and_then(|state| state.last_csca_sync);
        ensure_cache_fresh_at(last_sync, Utc::now(), self.config.max_offline_hours, "CSCA")
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
        let configured_sources = [
            self.config.aamva_dts_url.as_deref().map(|_| "AAMVA DTS"),
            self.config.icao_pkd_url.as_deref().map(|_| "ICAO PKD"),
            self.config
                .open_badge_keys_url
                .as_deref()
                .map(|_| "Open Badge trust"),
        ]
        .into_iter()
        .flatten()
        .collect::<Vec<_>>();

        if configured_sources.is_empty() {
            return Err(SyncError::SourceUnavailable(
                "no network trust source is configured; import a signed trust package".to_string(),
            ));
        }

        // The network source adapters are not yet capable of authenticating a
        // complete trust-package transition. Never refresh the freshness clock
        // merely because a URL was configured or reachable.
        Err(SyncError::SourceUnavailable(format!(
            "authenticated network synchronization is unavailable for {}",
            configured_sources.join(", ")
        )))
    }

    /// Import trust anchors from USB
    pub async fn import_from_usb(&self, path: &str) -> Result<UsbImportResult, SyncError> {
        if !self.config.enable_usb_import {
            return Err(SyncError::UsbImport("USB import disabled".to_string()));
        }

        let path = Path::new(path);
        let package = import_from_usb(path).await?;
        self.apply_verified_package(package).await
    }

    async fn apply_verified_package(
        &self,
        package: VerifiedTrustPackage,
    ) -> Result<UsbImportResult, SyncError> {
        if package.provenance.trust_domain != self.config.usb_trust_domain {
            return Err(SyncError::UsbImport(format!(
                "Package trust domain {} does not match configured domain {}",
                package.provenance.trust_domain, self.config.usb_trust_domain
            )));
        }

        let package_version = package.provenance.package_version.clone();
        let applied = self
            .storage
            .apply_trust_package_with_signer_policy(
                &package.provenance,
                &package.anchors,
                &package.open_badge_methods,
                &package.signer_policy,
            )
            .await?;

        Ok(UsbImportResult {
            success: true,
            certificates_imported: applied.trust_anchors,
            open_badge_keys_imported: applied.open_badge_methods,
            signature_valid: true,
            package_version: Some(package_version),
            error: None,
        })
    }
}

fn ensure_cache_fresh_at(
    last_sync: Option<DateTime<Utc>>,
    now: DateTime<Utc>,
    max_offline_hours: u32,
    cache_name: &str,
) -> Result<(), SyncError> {
    let last_sync = last_sync.ok_or_else(|| {
        SyncError::SourceUnavailable(format!(
            "{cache_name} trust cache has never been synchronized"
        ))
    })?;
    if last_sync > now {
        return Err(SyncError::SourceUnavailable(format!(
            "{cache_name} trust cache timestamp is in the future"
        )));
    }

    let age = now - last_sync;
    if age > chrono::Duration::hours(i64::from(max_offline_hours)) {
        return Err(SyncError::SourceUnavailable(format!(
            "{cache_name} trust cache is expired; maximum offline age is {max_offline_hours} hours"
        )));
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use marty_secure_storage::{
        OpenBadgeKeySource, OpenBadgeVerificationMethod, StorageError, TrustAnchor,
        TrustAnchorSource, TrustPackageProvenance,
    };

    use super::*;

    #[test]
    fn cache_freshness_fails_closed_without_a_sync() {
        let error = ensure_cache_fresh_at(None, Utc::now(), 72, "CSCA").unwrap_err();
        assert!(error.to_string().contains("never been synchronized"));
    }

    #[test]
    fn cache_freshness_accepts_the_configured_boundary() {
        let now = Utc::now();
        ensure_cache_fresh_at(Some(now - chrono::Duration::hours(72)), now, 72, "CSCA").unwrap();
    }

    #[test]
    fn cache_freshness_rejects_expired_and_future_timestamps() {
        let now = Utc::now();
        let expired =
            ensure_cache_fresh_at(Some(now - chrono::Duration::hours(73)), now, 72, "CSCA")
                .unwrap_err();
        assert!(expired.to_string().contains("expired"));

        let future =
            ensure_cache_fresh_at(Some(now + chrono::Duration::seconds(1)), now, 72, "CSCA")
                .unwrap_err();
        assert!(future.to_string().contains("future"));
    }

    #[tokio::test]
    async fn unsupported_network_sync_never_advances_the_trust_clock() {
        for config in [
            SyncConfig::default(),
            SyncConfig {
                icao_pkd_url: Some("https://pkd.example.test/trust".to_string()),
                ..SyncConfig::default()
            },
        ] {
            let data_dir = tempfile::tempdir().unwrap();
            let storage = Arc::new(SecureStorage::new(data_dir.path()).unwrap());
            let engine = SyncEngine::new(Arc::clone(&storage), config).unwrap();

            let result = engine.sync(false).await.unwrap();
            assert!(!result.success);
            assert!(result.error.as_deref().is_some_and(|error| {
                error.contains("no network trust source")
                    || error.contains("authenticated network synchronization")
            }));
            let state = storage.get_sync_state().await.unwrap().unwrap();
            assert!(state.last_iaca_sync.is_none());
            assert!(state.last_csca_sync.is_none());
            assert!(state.last_error.is_some());
        }
    }

    fn trust_anchor(bytes: &[u8], created_at: chrono::DateTime<Utc>) -> TrustAnchor {
        let digest = blake3::hash(bytes).to_hex().to_string();
        TrustAnchor {
            id: digest.clone(),
            anchor_type: TrustAnchorType::Iaca,
            jurisdiction: "US-CO".to_string(),
            subject: None,
            issuer: None,
            serial_number: None,
            not_before: None,
            not_after: None,
            certificate_der: bytes.to_vec(),
            certificate_hash: digest,
            source: TrustAnchorSource::UsbImport,
            synced_at: created_at,
        }
    }

    fn open_badge_method(created_at: chrono::DateTime<Utc>) -> OpenBadgeVerificationMethod {
        OpenBadgeVerificationMethod {
            id: "did:example:issuer#key-1".to_string(),
            document: serde_json::json!({
                "id": "did:example:issuer#key-1",
                "type": "JsonWebKey2020",
                "controller": "did:example:issuer",
                "publicKeyJwk": {
                    "kty": "OKP",
                    "crv": "Ed25519",
                    "x": "11qYAYdk9JwqPceJUchO3G0VQJq4aW8QjJwA8Yl5b4o"
                }
            }),
            controller: Some("did:example:issuer".to_string()),
            issuer: None,
            kid: None,
            not_before: Some(created_at - chrono::Duration::hours(1)),
            not_after: Some(created_at + chrono::Duration::days(1)),
            status: Some("active".to_string()),
            source: OpenBadgeKeySource::UsbImport,
            synced_at: created_at,
        }
    }

    fn verified_package(
        sequence: u64,
        created_at: chrono::DateTime<Utc>,
        digest_byte: char,
        anchors: Vec<TrustAnchor>,
        open_badge_methods: Vec<OpenBadgeVerificationMethod>,
    ) -> VerifiedTrustPackage {
        VerifiedTrustPackage {
            signer_policy: marty_secure_storage::TrustPackageSignerPolicy {
                next_signer_key_id: None,
                recovery_signer_key_id: format!("ed25519:{}", "f".repeat(64)),
            },
            provenance: TrustPackageProvenance {
                trust_domain: "usb:default".to_string(),
                sequence,
                package_version: format!("{sequence}.0.0"),
                created_at,
                expires_at: created_at + chrono::Duration::days(30),
                signer_key_id: format!("ed25519:{}", "a".repeat(64)),
                package_digest: digest_byte.to_string().repeat(64),
                imported_at: Utc::now(),
            },
            anchors,
            open_badge_methods,
        }
    }

    #[test]
    fn test_sync_config_default() {
        let config = SyncConfig::default();

        assert!(config.aamva_dts_url.is_none());
        assert!(config.icao_pkd_url.is_none());
        assert!(config.open_badge_keys_url.is_none());
        assert_eq!(config.sync_interval_hours, 24);
        assert!(config.enable_usb_import);
        assert_eq!(config.usb_trust_domain, "usb:default");
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
            usb_trust_domain: "usb:air-gap-one".to_string(),
            max_offline_hours: 48,
        };

        assert_eq!(config.aamva_dts_url.unwrap(), "https://dts.aamva.org");
        assert_eq!(config.sync_interval_hours, 12);
        assert!(!config.enable_usb_import);
        assert_eq!(config.usb_trust_domain, "usb:air-gap-one");
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

    #[tokio::test]
    async fn verified_usb_package_uses_one_monotonic_whole_package_transition() {
        let data_dir = tempfile::tempdir().unwrap();
        let storage = Arc::new(SecureStorage::new(data_dir.path()).unwrap());
        let engine = SyncEngine::new(storage.clone(), SyncConfig::default()).unwrap();
        let created_at = Utc::now();
        let first_anchor = trust_anchor(&[1, 2, 3], created_at);
        let first_method = open_badge_method(created_at);
        let first = verified_package(
            1,
            created_at,
            'b',
            vec![first_anchor.clone()],
            vec![first_method.clone()],
        );

        let imported = engine.apply_verified_package(first).await.unwrap();
        assert_eq!(imported.certificates_imported, 1);
        assert_eq!(imported.open_badge_keys_imported, 1);
        assert!(imported.signature_valid);

        let next_created_at = created_at + chrono::Duration::seconds(1);
        let replacement = trust_anchor(&[4, 5, 6], next_created_at);
        let second = verified_package(2, next_created_at, 'c', vec![replacement.clone()], vec![]);
        engine.apply_verified_package(second).await.unwrap();

        let anchors = storage
            .get_trust_anchor_records(TrustAnchorType::Iaca, None)
            .await
            .unwrap();
        assert_eq!(anchors.len(), 1);
        assert_eq!(anchors[0].anchor.id, replacement.id);
        assert!(storage.get_open_badge_keys().await.unwrap().is_empty());

        let replay = verified_package(1, created_at, 'b', vec![first_anchor], vec![first_method]);
        assert!(matches!(
            engine.apply_verified_package(replay).await,
            Err(SyncError::Storage(
                StorageError::TrustPackageRollback { .. }
            ))
        ));
        let anchors_after_replay = storage
            .get_trust_anchor_records(TrustAnchorType::Iaca, None)
            .await
            .unwrap();
        assert_eq!(anchors_after_replay.len(), 1);
        assert_eq!(anchors_after_replay[0].anchor.id, replacement.id);
    }

    #[tokio::test]
    async fn signed_complete_package_advances_the_csca_freshness_clock() {
        let data_dir = tempfile::tempdir().unwrap();
        let storage = Arc::new(SecureStorage::new(data_dir.path()).unwrap());
        let engine = SyncEngine::new(storage.clone(), SyncConfig::default()).unwrap();
        let created_at = Utc::now();

        engine
            .apply_verified_package(verified_package(
                1,
                created_at,
                '7',
                vec![trust_anchor(&[21, 22, 23], created_at)],
                vec![],
            ))
            .await
            .unwrap();

        engine.ensure_csca_cache_fresh().await.unwrap();
        let state = storage.get_sync_state().await.unwrap().unwrap();
        assert_eq!(state.last_iaca_sync, Some(created_at));
        assert_eq!(state.last_csca_sync, Some(created_at));
        assert_eq!(state.csca_version.as_deref(), Some("1.0.0"));
    }

    #[tokio::test]
    async fn mismatched_usb_trust_domain_is_rejected_without_mutation() {
        let data_dir = tempfile::tempdir().unwrap();
        let storage = Arc::new(SecureStorage::new(data_dir.path()).unwrap());
        let engine = SyncEngine::new(storage.clone(), SyncConfig::default()).unwrap();
        let created_at = Utc::now();
        let anchor = trust_anchor(&[7, 8, 9], created_at);
        let mut package = verified_package(1, created_at, 'd', vec![anchor], vec![]);
        package.provenance.trust_domain = "usb:another-environment".to_string();

        assert!(matches!(
            engine.apply_verified_package(package).await,
            Err(SyncError::UsbImport(message))
                if message.contains("does not match configured domain")
        ));
        assert!(storage
            .get_trust_anchor_records(TrustAnchorType::Iaca, None)
            .await
            .unwrap()
            .is_empty());
        assert!(storage.get_open_badge_keys().await.unwrap().is_empty());
    }

    #[tokio::test]
    async fn signed_next_signer_is_activated_once_and_old_signer_fails_closed() {
        let data_dir = tempfile::tempdir().unwrap();
        let storage = Arc::new(SecureStorage::new(data_dir.path()).unwrap());
        let engine = SyncEngine::new(storage.clone(), SyncConfig::default()).unwrap();
        let created_at = Utc::now();
        let next_signer = format!("ed25519:{}", "b".repeat(64));

        let mut bootstrap = verified_package(
            1,
            created_at,
            '4',
            vec![trust_anchor(&[10, 11, 12], created_at)],
            vec![],
        );
        bootstrap.signer_policy.next_signer_key_id = Some(next_signer.clone());
        engine.apply_verified_package(bootstrap).await.unwrap();

        let next_created_at = created_at + chrono::Duration::seconds(1);
        let next_anchor = trust_anchor(&[13, 14, 15], next_created_at);
        let mut activated =
            verified_package(2, next_created_at, '5', vec![next_anchor.clone()], vec![]);
        activated.provenance.signer_key_id = next_signer;
        engine.apply_verified_package(activated).await.unwrap();

        let old_created_at = created_at + chrono::Duration::seconds(2);
        let old_signer = verified_package(3, old_created_at, '6', vec![], vec![]);
        assert!(matches!(
            engine.apply_verified_package(old_signer).await,
            Err(SyncError::Storage(StorageError::TrustPackageSignerChange(
                _
            )))
        ));
        let anchors = storage
            .get_trust_anchor_records(TrustAnchorType::Iaca, None)
            .await
            .unwrap();
        assert_eq!(anchors.len(), 1);
        assert_eq!(anchors[0].anchor.id, next_anchor.id);
    }
}
