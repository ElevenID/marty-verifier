//! Secure database operations

use std::path::Path;
use std::sync::Arc;

use chrono::Utc;
use marty_secure_storage::SecureStorage as CoreSecureStorage;
use rusqlite::{Connection, OptionalExtension};
use serde::Serialize;
use serde_json::Value;

use crate::error::StorageError;
use crate::models::*;
use crate::schema::{SCHEMA, SCHEMA_VERSION};
use marty_secure_storage::PiiEncryptor;

/// Offline queue status
#[derive(Debug, Serialize)]
pub struct OfflineQueueStatus {
    pub pending_events: usize,
    pub oldest_event: Option<String>,
    pub data_size_bytes: usize,
    pub last_sync_attempt: Option<String>,
    pub last_successful_sync: Option<String>,
}

/// Verification history entry for API
#[derive(Debug, Serialize)]
pub struct VerificationHistoryEntry {
    pub id: String,
    pub credential_type: String,
    pub status: String,
    pub verified_at: String,
    pub jurisdiction: Option<String>,
    pub synced: bool,
}

/// Secure storage manager
pub struct SecureStorage {
    core: Arc<CoreSecureStorage>,
    #[allow(dead_code)]
    pii_encryptor: Option<PiiEncryptor>,
}

impl SecureStorage {
    /// Create storage with one core-owned database connection and migration owner.
    pub fn new(data_dir: &Path) -> Result<Self, StorageError> {
        Self::new_with_core(
            CoreSecureStorage::new(data_dir)?,
            PiiEncryptor::from_platform_keyring,
        )
    }

    /// Create storage using a caller-installed process-local keyring.
    pub fn new_with_process_local_keyring(data_dir: &Path) -> Result<Self, StorageError> {
        Self::new_with_core(
            CoreSecureStorage::new_with_process_local_keyring(data_dir)?,
            PiiEncryptor::from_process_local_keyring,
        )
    }

    fn new_with_core(
        mut core: CoreSecureStorage,
        initialize_pii: fn() -> Result<PiiEncryptor, marty_secure_storage::StorageError>,
    ) -> Result<Self, StorageError> {
        core.initialize_extension(initialize_app_schema)?;
        // Preserve app startup key access while core owns encryption and keyring behavior.
        let pii_encryptor = Some(initialize_pii()?);
        Ok(Self {
            core: Arc::new(core),
            pii_encryptor,
        })
    }

    /// Shared storage owner for sync, reporting and governed trust operations.
    pub fn core_storage(&self) -> &Arc<CoreSecureStorage> {
        &self.core
    }

    /// Verify that startup migrations produced the schema required by the app.
    pub async fn health_check(&self) -> Result<(), StorageError> {
        self.core
            .with_connection(|conn| validate_schema(conn))
            .await
    }

    /// Store a verification event
    pub async fn store_verification_event<S: Serialize>(
        &self,
        id: &str,
        credential_type: &str,
        status: &S,
    ) -> Result<(), StorageError> {
        self.core
            .with_connection(|conn| {
                let status_str = serde_json::to_string(status)?;
                let now = Utc::now().to_rfc3339();

                conn.execute(
                    r#"
            INSERT INTO verification_events 
                (id, credential_type, status, verified_at, offline_verified)
            VALUES (?, ?, ?, ?, ?)
            "#,
                    rusqlite::params![id, credential_type, status_str, now, false],
                )?;

                Ok(())
            })
            .await
    }

    /// Get verification history
    pub async fn get_verification_history(
        &self,
        limit: usize,
    ) -> Result<Vec<VerificationHistoryEntry>, StorageError> {
        self.core
            .with_connection(|conn| {
                let mut stmt = conn.prepare(
                    r#"
            SELECT id, credential_type, status, verified_at, issuer_jurisdiction, synced
            FROM verification_events
            ORDER BY verified_at DESC
            LIMIT ?
            "#,
                )?;

                let sql_limit = i64::try_from(limit).unwrap_or(i64::MAX);
                let rows = stmt.query_map([sql_limit], |row| {
                    Ok(VerificationHistoryEntry {
                        id: row.get(0)?,
                        credential_type: row.get(1)?,
                        status: row.get(2)?,
                        verified_at: row.get(3)?,
                        jurisdiction: row.get(4)?,
                        synced: row.get(5)?,
                    })
                })?;

                let mut history = Vec::new();
                for row in rows {
                    history.push(row?);
                }

                Ok(history)
            })
            .await
    }

    /// Clear verification history older than N days
    pub async fn clear_verification_history(
        &self,
        older_than_days: u32,
    ) -> Result<usize, StorageError> {
        self.core
            .with_connection(|conn| {
                let deleted = if older_than_days == 0 {
                    conn.execute("DELETE FROM verification_events", [])?
                } else {
                    conn.execute(
                        r#"
                DELETE FROM verification_events 
                WHERE verified_at < datetime('now', ? || ' days')
                "#,
                        [format!("-{}", older_than_days)],
                    )?
                };

                Ok(deleted)
            })
            .await
    }

    /// Get offline queue status
    pub async fn get_queue_status(&self) -> Result<OfflineQueueStatus, StorageError> {
        self.core
            .with_connection(|conn| {
                let pending_events: i64 =
                    conn.query_row("SELECT COUNT(*) FROM offline_queue", [], |row| row.get(0))?;
                let pending_events = usize::try_from(pending_events).unwrap_or_default();

                let oldest_event: Option<String> = conn
                    .query_row("SELECT MIN(created_at) FROM offline_queue", [], |row| {
                        row.get(0)
                    })
                    .ok();

                // Estimate data size
                let data_size_bytes: i64 = conn.query_row(
                    "SELECT COALESCE(SUM(LENGTH(payload)), 0) FROM offline_queue",
                    [],
                    |row| row.get(0),
                )?;
                let data_size_bytes = usize::try_from(data_size_bytes).unwrap_or_default();

                // Get last sync times from sync_state
                let (last_sync_attempt, last_successful_sync): (Option<String>, Option<String>) =
                    conn.query_row(
                        "SELECT last_error, last_iaca_sync FROM sync_state WHERE id = 'current'",
                        [],
                        |row| Ok((row.get(0)?, row.get(1)?)),
                    )
                    .unwrap_or((None, None));

                Ok(OfflineQueueStatus {
                    pending_events,
                    oldest_event,
                    data_size_bytes,
                    last_sync_attempt,
                    last_successful_sync,
                })
            })
            .await
    }

    /// Store a trust anchor certificate
    pub async fn store_trust_anchor(&self, anchor: &TrustAnchor) -> Result<(), StorageError> {
        self.core
            .with_connection(|conn| {
                conn.execute(
                    r#"
            INSERT OR REPLACE INTO trust_anchors 
                (id, anchor_type, jurisdiction, subject, issuer, serial_number,
                 not_before, not_after, certificate_der, certificate_hash, source, synced_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            "#,
                    rusqlite::params![
                        anchor.id,
                        anchor.anchor_type.to_string(),
                        anchor.jurisdiction,
                        anchor.subject,
                        anchor.issuer,
                        anchor.serial_number,
                        anchor.not_before.map(|dt| dt.to_rfc3339()),
                        anchor.not_after.map(|dt| dt.to_rfc3339()),
                        anchor.certificate_der,
                        anchor.certificate_hash,
                        anchor.source.to_string(),
                        anchor.synced_at.to_rfc3339(),
                    ],
                )?;

                Ok(())
            })
            .await
    }

    /// Store a trusted Open Badge verification method
    pub async fn store_open_badge_key(
        &self,
        method: &OpenBadgeVerificationMethod,
    ) -> Result<(), StorageError> {
        self.core.with_connection(|conn| {

        let document_json = serde_json::to_string(&method.document)?;

        conn.execute(
            r#"
            INSERT OR REPLACE INTO open_badge_keys
                (id, document_json, controller, issuer, kid, not_before, not_after, status, source, synced_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            "#,
            rusqlite::params![
                method.id,
                document_json,
                method.controller,
                method.issuer,
                method.kid,
                method.not_before.map(|dt| dt.to_rfc3339()),
                method.not_after.map(|dt| dt.to_rfc3339()),
                method.status,
                method.source.to_string(),
                method.synced_at.to_rfc3339(),
            ],
        )?;

        Ok(())
        }).await
    }

    /// Get trust anchors by type and jurisdiction
    pub async fn get_trust_anchors(
        &self,
        anchor_type: TrustAnchorType,
        jurisdiction: Option<&str>,
    ) -> Result<Vec<TrustAnchor>, StorageError> {
        self.core
            .with_connection(|conn| {
                let sql = if jurisdiction.is_some() {
                    r#"
            SELECT id, anchor_type, jurisdiction, subject, issuer, serial_number,
                   not_before, not_after, certificate_der, certificate_hash, source, synced_at
            FROM trust_anchors
            WHERE anchor_type = ? AND jurisdiction = ?
            "#
                } else {
                    r#"
            SELECT id, anchor_type, jurisdiction, subject, issuer, serial_number,
                   not_before, not_after, certificate_der, certificate_hash, source, synced_at
            FROM trust_anchors
            WHERE anchor_type = ?
            "#
                };

                let mut stmt = conn.prepare(sql)?;

                let rows = if let Some(jur) = jurisdiction {
                    stmt.query_map(
                        [anchor_type.to_string(), jur.to_string()],
                        Self::map_trust_anchor,
                    )?
                } else {
                    stmt.query_map([anchor_type.to_string()], Self::map_trust_anchor)?
                };

                let mut anchors = Vec::new();
                for row in rows {
                    anchors.push(row?);
                }

                Ok(anchors)
            })
            .await
    }

    fn map_trust_anchor(row: &rusqlite::Row<'_>) -> rusqlite::Result<TrustAnchor> {
        let anchor_type_str: String = row.get(1)?;
        let source_str: String = row.get(10)?;

        Ok(TrustAnchor {
            id: row.get(0)?,
            anchor_type: match anchor_type_str.as_str() {
                "iaca" => TrustAnchorType::Iaca,
                "csca" => TrustAnchorType::Csca,
                "dsc" => TrustAnchorType::Dsc,
                _ => TrustAnchorType::Iaca,
            },
            jurisdiction: row.get(2)?,
            subject: row.get(3)?,
            issuer: row.get(4)?,
            serial_number: row.get(5)?,
            not_before: row.get::<_, Option<String>>(6)?.and_then(|s| {
                chrono::DateTime::parse_from_rfc3339(&s)
                    .ok()
                    .map(|dt| dt.with_timezone(&Utc))
            }),
            not_after: row.get::<_, Option<String>>(7)?.and_then(|s| {
                chrono::DateTime::parse_from_rfc3339(&s)
                    .ok()
                    .map(|dt| dt.with_timezone(&Utc))
            }),
            certificate_der: row.get(8)?,
            certificate_hash: row.get(9)?,
            source: match source_str.as_str() {
                "aamva_dts" => TrustAnchorSource::AamvaDts,
                "icao_pkd" => TrustAnchorSource::IcaoPkd,
                "usb_import" => TrustAnchorSource::UsbImport,
                _ => TrustAnchorSource::Manual,
            },
            synced_at: row
                .get::<_, String>(11)
                .ok()
                .and_then(|s| {
                    chrono::DateTime::parse_from_rfc3339(&s)
                        .ok()
                        .map(|dt| dt.with_timezone(&Utc))
                })
                .unwrap_or_else(Utc::now),
        })
    }

    /// Get all trusted Open Badge verification methods
    pub async fn get_open_badge_keys(
        &self,
    ) -> Result<Vec<OpenBadgeVerificationMethod>, StorageError> {
        self.core.with_connection(|conn| {

        let mut stmt = conn.prepare(
            r#"
            SELECT id, document_json, controller, issuer, kid, not_before, not_after, status, source, synced_at
            FROM open_badge_keys
            "#,
        )?;

        let rows = stmt.query_map([], Self::map_open_badge_key)?;
        let mut methods = Vec::new();
        for row in rows {
            methods.push(row?);
        }

        Ok(methods)
        }).await
    }

    /// Count trusted Open Badge verification methods
    pub async fn count_open_badge_keys(&self) -> Result<usize, StorageError> {
        self.core
            .with_connection(|conn| {
                let count: i64 =
                    conn.query_row("SELECT COUNT(*) FROM open_badge_keys", [], |row| row.get(0))?;
                Ok(usize::try_from(count).unwrap_or_default())
            })
            .await
    }

    /// Get latest Open Badge trust list sync timestamp
    pub async fn get_latest_open_badge_sync(
        &self,
    ) -> Result<Option<chrono::DateTime<chrono::Utc>>, StorageError> {
        self.core
            .with_connection(|conn| {
                let synced_at: Option<String> = conn
                    .query_row("SELECT MAX(synced_at) FROM open_badge_keys", [], |row| {
                        row.get(0)
                    })
                    .ok()
                    .flatten();

                Ok(synced_at.and_then(|s| {
                    chrono::DateTime::parse_from_rfc3339(&s)
                        .ok()
                        .map(|dt| dt.with_timezone(&Utc))
                }))
            })
            .await
    }

    fn map_open_badge_key(
        row: &rusqlite::Row<'_>,
    ) -> rusqlite::Result<OpenBadgeVerificationMethod> {
        let source_str: String = row.get(8)?;
        let document_json: String = row.get(1)?;
        let document: Value =
            serde_json::from_str(&document_json).unwrap_or(serde_json::Value::Null);

        Ok(OpenBadgeVerificationMethod {
            id: row.get(0)?,
            document,
            controller: row.get(2)?,
            issuer: row.get(3)?,
            kid: row.get(4)?,
            not_before: row.get::<_, Option<String>>(5)?.and_then(|s| {
                chrono::DateTime::parse_from_rfc3339(&s)
                    .ok()
                    .map(|dt| dt.with_timezone(&Utc))
            }),
            not_after: row.get::<_, Option<String>>(6)?.and_then(|s| {
                chrono::DateTime::parse_from_rfc3339(&s)
                    .ok()
                    .map(|dt| dt.with_timezone(&Utc))
            }),
            status: row.get(7)?,
            source: match source_str.as_str() {
                "sync" => OpenBadgeKeySource::Sync,
                "usb_import" => OpenBadgeKeySource::UsbImport,
                _ => OpenBadgeKeySource::Manual,
            },
            synced_at: row
                .get::<_, String>(9)
                .ok()
                .and_then(|s| {
                    chrono::DateTime::parse_from_rfc3339(&s)
                        .ok()
                        .map(|dt| dt.with_timezone(&Utc))
                })
                .unwrap_or_else(Utc::now),
        })
    }

    /// Count trust anchors by type
    pub async fn count_trust_anchors(
        &self,
        anchor_type: TrustAnchorType,
    ) -> Result<usize, StorageError> {
        self.core
            .with_connection(|conn| {
                let count: i64 = conn.query_row(
                    "SELECT COUNT(*) FROM trust_anchors WHERE anchor_type = ?",
                    [anchor_type.to_string()],
                    |row| row.get(0),
                )?;
                Ok(usize::try_from(count).unwrap_or_default())
            })
            .await
    }

    /// Get sync state
    pub async fn get_sync_state(&self) -> Result<Option<SyncState>, StorageError> {
        self.core
            .with_connection(|conn| {
                let result = conn.query_row(
                    r#"
            SELECT last_iaca_sync, last_csca_sync, last_crl_sync,
                   iaca_version, csca_version, sync_in_progress, last_error
            FROM sync_state WHERE id = 'current'
            "#,
                    [],
                    |row| {
                        Ok(SyncState {
                            last_iaca_sync: row.get::<_, Option<String>>(0)?.and_then(|s| {
                                chrono::DateTime::parse_from_rfc3339(&s)
                                    .ok()
                                    .map(|dt| dt.with_timezone(&Utc))
                            }),
                            last_csca_sync: row.get::<_, Option<String>>(1)?.and_then(|s| {
                                chrono::DateTime::parse_from_rfc3339(&s)
                                    .ok()
                                    .map(|dt| dt.with_timezone(&Utc))
                            }),
                            last_crl_sync: row.get::<_, Option<String>>(2)?.and_then(|s| {
                                chrono::DateTime::parse_from_rfc3339(&s)
                                    .ok()
                                    .map(|dt| dt.with_timezone(&Utc))
                            }),
                            iaca_version: row.get(3)?,
                            csca_version: row.get(4)?,
                            sync_in_progress: row.get::<_, i32>(5)? != 0,
                            last_error: row.get(6)?,
                        })
                    },
                );

                match result {
                    Ok(state) => Ok(Some(state)),
                    Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
                    Err(e) => Err(e.into()),
                }
            })
            .await
    }

    /// Update sync state
    pub async fn update_sync_state(&self, state: &SyncState) -> Result<(), StorageError> {
        self.core
            .with_connection(|conn| {
                let now = Utc::now().to_rfc3339();

                conn.execute(
                    r#"
            INSERT OR REPLACE INTO sync_state 
                (id, last_iaca_sync, last_csca_sync, last_crl_sync,
                 iaca_version, csca_version, sync_in_progress, last_error, updated_at)
            VALUES ('current', ?, ?, ?, ?, ?, ?, ?, ?)
            "#,
                    rusqlite::params![
                        state.last_iaca_sync.map(|dt| dt.to_rfc3339()),
                        state.last_csca_sync.map(|dt| dt.to_rfc3339()),
                        state.last_crl_sync.map(|dt| dt.to_rfc3339()),
                        state.iaca_version,
                        state.csca_version,
                        state.sync_in_progress as i32,
                        state.last_error,
                        now,
                    ],
                )?;

                Ok(())
            })
            .await
    }

    /// Queue an event for offline reporting
    pub async fn queue_event(
        &self,
        event_type: &str,
        payload: &serde_json::Value,
    ) -> Result<String, StorageError> {
        self.core
            .with_connection(|conn| {
                let id = uuid::Uuid::new_v4().to_string();
                let now = Utc::now().to_rfc3339();
                let payload_str = serde_json::to_string(payload)?;

                conn.execute(
                    r#"
            INSERT INTO offline_queue (id, event_type, payload, created_at)
            VALUES (?, ?, ?, ?)
            "#,
                    rusqlite::params![id, event_type, payload_str, now],
                )?;

                Ok(id)
            })
            .await
    }

    /// Get pending events from offline queue
    pub async fn get_pending_events(
        &self,
        limit: usize,
    ) -> Result<Vec<OfflineQueueEntry>, StorageError> {
        self.core
            .with_connection(|conn| {
                let mut stmt = conn.prepare(
                    r#"
            SELECT id, event_type, payload, created_at, retry_count, last_retry_at, error
            FROM offline_queue
            ORDER BY created_at ASC
            LIMIT ?
            "#,
                )?;

                let sql_limit = i64::try_from(limit).unwrap_or(i64::MAX);
                let rows = stmt.query_map([sql_limit], |row| {
                    let payload_str: String = row.get(2)?;
                    Ok(OfflineQueueEntry {
                        id: row.get(0)?,
                        event_type: row.get(1)?,
                        payload: serde_json::from_str(&payload_str)
                            .unwrap_or(serde_json::Value::Null),
                        created_at: row
                            .get::<_, String>(3)
                            .ok()
                            .and_then(|s| {
                                chrono::DateTime::parse_from_rfc3339(&s)
                                    .ok()
                                    .map(|dt| dt.with_timezone(&Utc))
                            })
                            .unwrap_or_else(Utc::now),
                        retry_count: row.get(4)?,
                        last_retry_at: row.get::<_, Option<String>>(5)?.and_then(|s| {
                            chrono::DateTime::parse_from_rfc3339(&s)
                                .ok()
                                .map(|dt| dt.with_timezone(&Utc))
                        }),
                        error: row.get(6)?,
                    })
                })?;

                let mut entries = Vec::new();
                for row in rows {
                    entries.push(row?);
                }

                Ok(entries)
            })
            .await
    }

    /// Remove event from offline queue (after successful sync)
    pub async fn remove_queued_event(&self, id: &str) -> Result<(), StorageError> {
        self.core
            .with_connection(|conn| {
                conn.execute("DELETE FROM offline_queue WHERE id = ?", [id])?;
                Ok(())
            })
            .await
    }

    /// Add audit log entry
    pub async fn add_audit_log(
        &self,
        event_type: &str,
        actor: Option<&str>,
        target: Option<&str>,
        details: Option<&serde_json::Value>,
    ) -> Result<(), StorageError> {
        self.core
            .with_connection(|conn| {
                let id = uuid::Uuid::new_v4().to_string();
                let details_str = details.map(serde_json::to_string).transpose()?;

                conn.execute(
                    r#"
            INSERT INTO audit_log (id, event_type, actor, target, details)
            VALUES (?, ?, ?, ?, ?)
            "#,
                    rusqlite::params![id, event_type, actor, target, details_str],
                )?;

                Ok(())
            })
            .await
    }

    /// Store deployment profile
    pub async fn store_deployment_profile(
        &self,
        profile: &crate::DeploymentProfile,
    ) -> Result<(), StorageError> {
        self.core
            .with_connection(|conn| {
                let now = Utc::now().to_rfc3339();

                let ux_config_json = serde_json::to_string(&profile.ux_config)?;
                let update_policy_json = serde_json::to_string(&profile.update_policy)?;
                let network_mode = format!("{:?}", profile.network_mode).to_lowercase();

                conn.execute(
                    r#"
            INSERT OR REPLACE INTO deployment_profiles 
            (id, name, site_id, network_mode, key_access_mode, ux_config, update_policy,
             offline_cache_ttl_hours, biometric_required, audit_all_events, synced_at, updated_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            "#,
                    rusqlite::params![
                        profile.id,
                        profile.name,
                        profile.site_id,
                        network_mode,
                        profile.key_access_mode,
                        ux_config_json,
                        update_policy_json,
                        profile.offline_cache_ttl_hours as i64,
                        if profile.operator_biometric_authentication_required {
                            1
                        } else {
                            0
                        },
                        if profile.audit_all_events { 1 } else { 0 },
                        now,
                        now,
                    ],
                )?;

                Ok(())
            })
            .await
    }

    /// Get deployment profile by ID
    pub async fn get_deployment_profile(
        &self,
        id: &str,
    ) -> Result<Option<crate::DeploymentProfile>, StorageError> {
        self.core
            .with_connection(|conn| {
                let result = conn.query_row(
                    r#"
            SELECT id, name, site_id, network_mode, key_access_mode, ux_config, update_policy,
                   offline_cache_ttl_hours, biometric_required, audit_all_events
            FROM deployment_profiles WHERE id = ?
            "#,
                    [id],
                    |row| {
                        let ux_config_json: String = row.get(5)?;
                        let update_policy_json: String = row.get(6)?;
                        let network_mode_str: String = row.get(3)?;

                        let ux_config: crate::UXConfig = serde_json::from_str(&ux_config_json)
                            .map_err(|e| rusqlite::Error::ToSqlConversionFailure(Box::new(e)))?;
                        let update_policy: crate::UpdatePolicy =
                            serde_json::from_str(&update_policy_json).map_err(|e| {
                                rusqlite::Error::ToSqlConversionFailure(Box::new(e))
                            })?;
                        let network_mode = match network_mode_str.as_str() {
                            "online" => crate::NetworkMode::Online,
                            "offline" => crate::NetworkMode::Offline,
                            "hybrid" => crate::NetworkMode::Hybrid,
                            _ => crate::NetworkMode::Online,
                        };

                        Ok(crate::DeploymentProfile {
                            id: row.get(0)?,
                            name: row.get(1)?,
                            site_id: row.get(2)?,
                            network_mode,
                            key_access_mode: row.get(4)?,
                            ux_config,
                            update_policy,
                            offline_cache_ttl_hours: row.get::<_, i64>(7)? as u32,
                            operator_biometric_authentication_required: row.get::<_, i32>(8)? != 0,
                            audit_all_events: row.get::<_, i32>(9)? != 0,
                            default_presentation_policy_id: None, // Not stored in DB
                        })
                    },
                );

                match result {
                    Ok(profile) => Ok(Some(profile)),
                    Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
                    Err(e) => Err(e.into()),
                }
            })
            .await
    }

    /// Store lane
    pub async fn store_lane(&self, lane: &crate::Lane) -> Result<(), StorageError> {
        self.core.with_connection(|conn| {

        let now = Utc::now().to_rfc3339();

        let device_ids_json = serde_json::to_string(&lane.device_ids)?;
        let metadata_json = serde_json::to_string(&lane.metadata)?;

        conn.execute(
            r#"
            INSERT OR REPLACE INTO lanes 
            (id, name, deployment_profile_id, default_policy_id, device_ids, metadata, synced_at, updated_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            "#,
            rusqlite::params![
                lane.id,
                lane.name,
                lane.deployment_profile_id,
                lane.default_policy_id,
                device_ids_json,
                metadata_json,
                now,
                now,
            ],
        )?;

        Ok(())
        }).await
    }

    /// Get lanes for a deployment profile
    pub async fn get_lanes_for_profile(
        &self,
        profile_id: &str,
    ) -> Result<Vec<crate::Lane>, StorageError> {
        self.core
            .with_connection(|conn| {
                let mut stmt = conn.prepare(
                    r#"
            SELECT id, name, deployment_profile_id, default_policy_id, device_ids, metadata
            FROM lanes WHERE deployment_profile_id = ?
            "#,
                )?;

                let lanes = stmt
                    .query_map([profile_id], |row| {
                        let device_ids_json: String = row.get(4)?;
                        let metadata_json: String = row.get(5)?;

                        let device_ids: Vec<String> = serde_json::from_str(&device_ids_json)
                            .map_err(|e| rusqlite::Error::ToSqlConversionFailure(Box::new(e)))?;
                        let metadata: serde_json::Value = serde_json::from_str(&metadata_json)
                            .map_err(|e| rusqlite::Error::ToSqlConversionFailure(Box::new(e)))?;

                        Ok(crate::Lane {
                            id: row.get(0)?,
                            name: row.get(1)?,
                            deployment_profile_id: row.get(2)?,
                            default_policy_id: row.get(3)?,
                            device_ids,
                            metadata,
                        })
                    })?
                    .collect::<Result<Vec<_>, _>>()?;

                Ok(lanes)
            })
            .await
    }

    /// Store device configuration (singleton pattern)
    pub async fn store_device_config(
        &self,
        device_id: &str,
        deployment_profile_id: Option<&str>,
        lane_id: Option<&str>,
    ) -> Result<(), StorageError> {
        self.core
            .with_connection(|conn| {
                let now = Utc::now().to_rfc3339();

                conn.execute(
                    r#"
            INSERT OR REPLACE INTO device_config 
            (id, device_id, deployment_profile_id, lane_id, assigned_at, updated_at)
            VALUES ('current', ?, ?, ?, ?, ?)
            "#,
                    rusqlite::params![device_id, deployment_profile_id, lane_id, now, now],
                )?;

                Ok(())
            })
            .await
    }

    /// Get device configuration (singleton)
    pub async fn get_device_config(
        &self,
    ) -> Result<Option<(String, Option<String>, Option<String>)>, StorageError> {
        self.core
            .with_connection(|conn| {
                let result = conn.query_row(
                    r#"
            SELECT device_id, deployment_profile_id, lane_id
            FROM device_config WHERE id = 'current'
            "#,
                    [],
                    |row| {
                        Ok((
                            row.get::<_, Option<String>>(0)?,
                            row.get::<_, Option<String>>(1)?,
                            row.get::<_, Option<String>>(2)?,
                        ))
                    },
                );

                match result {
                    Ok((Some(device_id), profile_id, lane_id)) => {
                        Ok(Some((device_id, profile_id, lane_id)))
                    }
                    Ok((None, _, _)) => Ok(None),
                    Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
                    Err(e) => Err(e.into()),
                }
            })
            .await
    }

    /// Store presentation policy
    pub async fn store_presentation_policy(
        &self,
        policy: &crate::PresentationPolicy,
        deployment_profile_id: Option<&str>,
    ) -> Result<(), StorageError> {
        self.core
            .with_connection(|conn| {
                let now = Utc::now().to_rfc3339();

                let policy_json = serde_json::to_string(policy)?;

                conn.execute(
                    r#"
            INSERT OR REPLACE INTO presentation_policies 
            (id, policy_json, version, deployment_profile_id, synced_at, updated_at)
            VALUES (?, ?, ?, ?, ?, ?)
            "#,
                    rusqlite::params![
                        policy.id,
                        policy_json,
                        policy.version,
                        deployment_profile_id,
                        now,
                        now,
                    ],
                )?;

                Ok(())
            })
            .await
    }

    /// Get presentation policy by ID
    pub async fn get_presentation_policy(
        &self,
        id: &str,
    ) -> Result<Option<crate::PresentationPolicy>, StorageError> {
        self.core
            .with_connection(|conn| {
                let result = conn.query_row(
                    "SELECT policy_json FROM presentation_policies WHERE id = ?",
                    [id],
                    |row| {
                        let json: String = row.get(0)?;
                        serde_json::from_str(&json)
                            .map_err(|e| rusqlite::Error::ToSqlConversionFailure(Box::new(e)))
                    },
                );

                match result {
                    Ok(policy) => Ok(Some(policy)),
                    Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
                    Err(e) => Err(e.into()),
                }
            })
            .await
    }

    /// Get all presentation policies, optionally filtered by deployment profile
    pub async fn get_presentation_policies(
        &self,
        deployment_profile_id: Option<&str>,
    ) -> Result<Vec<crate::PresentationPolicy>, StorageError> {
        self.core
            .with_connection(|conn| {
                let (query, params): (&str, Vec<&str>) = match deployment_profile_id {
            Some(profile_id) => (
                "SELECT policy_json FROM presentation_policies WHERE deployment_profile_id = ?",
                vec![profile_id],
            ),
            None => ("SELECT policy_json FROM presentation_policies", vec![]),
        };

                let mut stmt = conn.prepare(query)?;
                let policies = stmt
                    .query_map(rusqlite::params_from_iter(params.iter()), |row| {
                        let json: String = row.get(0)?;
                        serde_json::from_str(&json)
                            .map_err(|e| rusqlite::Error::ToSqlConversionFailure(Box::new(e)))
                    })?
                    .collect::<Result<Vec<_>, _>>()?;

                Ok(policies)
            })
            .await
    }

    /// Get last policy sync timestamp from sync_state
    pub async fn get_last_policy_sync(&self) -> Result<Option<String>, StorageError> {
        self.core
            .with_connection(|conn| {
                conn.query_row(
                    "SELECT value FROM config WHERE key = 'app.last_policy_sync'",
                    [],
                    |row| row.get(0),
                )
                .optional()
                .map_err(Into::into)
            })
            .await
    }

    /// Update last policy sync timestamp in sync_state
    pub async fn update_last_policy_sync(&self, timestamp: String) -> Result<(), StorageError> {
        self.core.with_connection(|conn| {
            conn.execute("INSERT INTO config (key, value) VALUES ('app.last_policy_sync', ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value, updated_at = datetime('now')", [timestamp])?;
            Ok(())
        }).await
    }
}

/// Implement PolicyStorage trait from marty-sync
#[cfg_attr(test, allow(unused))]
impl marty_sync::PolicyStorage for SecureStorage {
    async fn store(
        &self,
        policies: &[crate::PresentationPolicy],
    ) -> Result<(), marty_sync::SyncError> {
        for policy in policies {
            self.store_presentation_policy(policy, None)
                .await
                .map_err(|e| marty_sync::SyncError::StorageError(e.to_string()))?;
        }
        Ok(())
    }

    async fn get_all(&self) -> Result<Vec<crate::PresentationPolicy>, marty_sync::SyncError> {
        self.get_presentation_policies(None)
            .await
            .map_err(|e| marty_sync::SyncError::StorageError(e.to_string()))
    }

    async fn get_by_id(
        &self,
        id: &str,
    ) -> Result<Option<crate::PresentationPolicy>, marty_sync::SyncError> {
        self.get_presentation_policy(id)
            .await
            .map_err(|e| marty_sync::SyncError::StorageError(e.to_string()))
    }

    async fn get_last_sync(&self) -> Result<Option<String>, marty_sync::SyncError> {
        self.get_last_policy_sync()
            .await
            .map_err(|e| marty_sync::SyncError::StorageError(e.to_string()))
    }

    async fn update_last_sync(&self, timestamp: String) -> Result<(), marty_sync::SyncError> {
        self.update_last_policy_sync(timestamp)
            .await
            .map_err(|e| marty_sync::SyncError::StorageError(e.to_string()))
    }
}

fn get_schema_version(conn: &Connection) -> Result<i32, StorageError> {
    let version: Option<String> = conn
        .query_row(
            "SELECT value FROM config WHERE key = 'app_schema_version'",
            [],
            |row| row.get(0),
        )
        .optional()?;
    Ok(version.and_then(|v| v.parse::<i32>().ok()).unwrap_or(0))
}

fn initialize_app_schema(conn: &mut Connection) -> Result<(), StorageError> {
    let transaction = conn.transaction()?;
    transaction.execute_batch(SCHEMA)?;
    if column_exists(&transaction, "sync_state", "last_policy_sync")? {
        transaction.execute_batch("INSERT OR IGNORE INTO config (key, value) SELECT 'app.last_policy_sync', last_policy_sync FROM sync_state WHERE id = 'current' AND last_policy_sync IS NOT NULL;")?;
    }
    let version = get_schema_version(&transaction)?.max(SCHEMA_VERSION);
    transaction.execute("INSERT INTO config (key, value) VALUES ('app_schema_version', ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value", [version.to_string()])?;
    validate_schema(&transaction)?;
    transaction.commit()?;
    Ok(())
}

fn column_exists(conn: &Connection, table: &str, column: &str) -> Result<bool, StorageError> {
    let mut statement = conn.prepare(&format!("PRAGMA table_info({table})"))?;
    let mut rows = statement.query([])?;
    while let Some(row) = rows.next()? {
        if row.get::<_, String>(1)? == column {
            return Ok(true);
        }
    }
    Ok(false)
}

fn validate_schema(conn: &Connection) -> Result<(), StorageError> {
    let version = get_schema_version(conn)?;
    if version < SCHEMA_VERSION {
        return Err(StorageError::Schema(format!(
            "expected version {SCHEMA_VERSION} or newer, found {version}"
        )));
    }

    for table in [
        "verification_events",
        "trust_anchors",
        "open_badge_keys",
        "trust_packages",
        "crl_cache",
        "ocsp_cache",
        "offline_queue",
        "audit_log",
        "sync_state",
        "config",
        "presentation_policies",
        "deployment_profiles",
        "lanes",
        "device_config",
    ] {
        let exists: bool = conn.query_row(
            "SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = ?)",
            [table],
            |row| row.get(0),
        )?;
        if !exists {
            return Err(StorageError::Schema(format!(
                "required table is missing: {table}"
            )));
        }
    }

    Ok(())
}

#[cfg(test)]
mod startup_schema_tests {
    use super::*;

    fn initialized_connection() -> Connection {
        let mut conn = Connection::open_in_memory().expect("open in-memory database");
        conn.execute_batch(include_str!("../tests/fixtures/legacy_app_v5.sql"))
            .expect("initialize legacy schema");
        conn.execute(
            "INSERT INTO config (key, value) VALUES ('app_schema_version', ?)",
            [SCHEMA_VERSION.to_string()],
        )
        .expect("record schema version");
        initialize_app_schema(&mut conn).unwrap();
        conn
    }

    #[test]
    fn startup_schema_validation_accepts_complete_current_schema() {
        validate_schema(&initialized_connection()).expect("current schema must be healthy");
    }

    #[test]
    fn startup_schema_validation_accepts_newer_app_schema_version() {
        let conn = initialized_connection();
        conn.execute(
            "UPDATE config SET value = ? WHERE key = 'app_schema_version'",
            [(SCHEMA_VERSION + 1).to_string()],
        )
        .expect("record newer app schema version");

        validate_schema(&conn).expect("newer app schema marker must remain compatible");
    }

    #[test]
    fn startup_schema_validation_rejects_missing_migration_state() {
        let conn = initialized_connection();
        conn.execute("DELETE FROM config WHERE key = 'app_schema_version'", [])
            .expect("remove migration marker");

        let error = validate_schema(&conn).expect_err("missing migration state must fail");
        assert!(error.to_string().contains("expected version"));
    }

    #[test]
    fn startup_schema_validation_rejects_missing_required_table() {
        let conn = initialized_connection();
        conn.execute("DROP TABLE offline_queue", [])
            .expect("remove required table");

        let error = validate_schema(&conn).expect_err("missing table must fail");
        assert!(error.to_string().contains("offline_queue"));
    }

    #[test]
    fn failed_app_initialization_rolls_back_tables_and_marker() {
        let mut conn = Connection::open_in_memory().unwrap();
        conn.execute_batch("CREATE TABLE config (key TEXT PRIMARY KEY, value TEXT);")
            .unwrap();
        assert!(initialize_app_schema(&mut conn).is_err());
        assert_eq!(get_schema_version(&conn).unwrap(), 0);
        let count: i32 = conn
            .query_row(
                "SELECT count(*) FROM sqlite_master WHERE name = 'presentation_policies'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(count, 0);
    }
}

#[cfg(test)]
mod shared_owner_tests {
    use super::*;
    use base64::Engine;

    struct RestoreStore(Option<Arc<keyring_core::CredentialStore>>);
    impl Drop for RestoreStore {
        fn drop(&mut self) {
            keyring_core::unset_default_store();
            if let Some(store) = self.0.take() {
                keyring_core::set_default_store(store);
            }
        }
    }

    #[tokio::test]
    async fn legacy_databases_survive_both_initialization_orders_and_reopen() {
        let _guard = crate::TEST_KEYRING_LOCK.lock().await;
        let _restore = RestoreStore(keyring_core::get_default_store());
        let store: Arc<keyring_core::CredentialStore> = keyring_core::mock::Store::new().unwrap();
        keyring_core::set_default_store(store);
        let key = [0x53u8; 32];
        keyring_core::Entry::new("com.marty.verifier", "database_encryption_key")
            .unwrap()
            .set_password(&base64::engine::general_purpose::STANDARD.encode(key))
            .unwrap();
        keyring_core::Entry::new("com.marty.verifier", "pii_encryption_key")
            .unwrap()
            .set_password(&base64::engine::general_purpose::STANDARD.encode([0; 32]))
            .unwrap();
        let legacy_pii = base64::engine::general_purpose::STANDARD.encode(
            hex::decode("000000000000000000000000530f8afbc74536b9a963b4f1c4cb738b").unwrap(),
        );
        for (schema, legacy_version, has_policy_sync) in [
            (include_str!("../tests/fixtures/legacy_app_v5.sql"), 5, true),
            (
                include_str!("../tests/fixtures/legacy_core_v4.sql"),
                4,
                false,
            ),
        ] {
            for core_first in [true, false] {
                let directory = tempfile::tempdir().unwrap();
                {
                    let conn =
                        Connection::open(directory.path().join("marty_verifier.db")).unwrap();
                    conn.pragma_update(None, "key", format!("x'{}'", hex::encode(key)))
                        .unwrap();
                    conn.execute_batch(schema).unwrap();
                    conn.execute(
                        "INSERT INTO config (key, value) VALUES ('schema_version', ?)",
                        [legacy_version.to_string()],
                    )
                    .unwrap();
                    conn.execute("INSERT INTO offline_queue (id, event_type, payload, created_at) VALUES ('legacy', 'verification', '{}', '2026-01-01T00:00:00Z')", []).unwrap();
                    if has_policy_sync {
                        conn.execute("INSERT INTO sync_state (id, last_policy_sync) VALUES ('current', '2026-01-02T00:00:00Z')", []).unwrap();
                    }
                }
                let app = if core_first {
                    let core = CoreSecureStorage::new_with_process_local_keyring(directory.path())
                        .unwrap();
                    SecureStorage::new_with_core(core, PiiEncryptor::from_process_local_keyring)
                        .unwrap()
                } else {
                    let app =
                        SecureStorage::new_with_process_local_keyring(directory.path()).unwrap();
                    // A later standalone core consumer must also accept the app migration.
                    let core = CoreSecureStorage::new_with_process_local_keyring(directory.path())
                        .unwrap();
                    assert_eq!(core.get_pending_events(10).await.unwrap()[0].id, "legacy");
                    drop(core);
                    app
                };
                app.health_check().await.unwrap();
                let profile: crate::DeploymentProfile = serde_json::from_value(serde_json::json!({
                    "id": "profile-1", "name": "Offline verifier", "site_id": "site-1",
                    "network_mode": "hybrid", "key_access_mode": "device",
                    "ux_config": { "language": "en", "theme": "dark", "show_operator_mode": true,
                        "accessibility_enabled": true, "custom_branding": {"title": "Welcome"}, "signage_text": null },
                    "update_policy": { "auto_update": false, "update_channel": "stable",
                        "rollout_percentage": 25, "version_pinned": "1.0", "rollout_ring": null },
                    "offline_cache_ttl_hours": 48, "operator_biometric_authentication_required": true,
                    "audit_all_events": true
                })).unwrap();
                let policy: crate::PresentationPolicy = serde_json::from_value(serde_json::json!({
                    "id": "policy-1", "name": "Entry", "description": null, "purpose": "entry",
                    "accepted_credential_types": ["emrtd"], "required_claims": [], "holder_binding": "device_key",
                    "trust_profile_id": null, "allowed_issuers": [],
                    "freshness_requirements": { "max_credential_age_seconds": null, "max_proof_age_seconds": 300,
                        "require_live_revocation_check": true },
                    "prefer_predicates": true, "single_presentation": true, "derived_attribute_preferences": {},
                    "credential_ranking_strategy": "freshest_first", "credential_ranking_weights": {},
                    "metadata": {"site": "site-1"}, "version": 2
                })).unwrap();
                app.store_deployment_profile(&profile).await.unwrap();
                app.store_presentation_policy(&policy, Some("profile-1"))
                    .await
                    .unwrap();
                assert_eq!(
                    app.get_last_policy_sync().await.unwrap().as_deref(),
                    has_policy_sync.then_some("2026-01-02T00:00:00Z")
                );
                app.store_verification_event("app-event", "emrtd", &"valid")
                    .await
                    .unwrap();
                assert_eq!(
                    app.core_storage()
                        .get_verification_history(10)
                        .await
                        .unwrap()
                        .len(),
                    1
                );
                app.core_storage()
                    .store_verification_event("core-event", "dtc", &"valid")
                    .await
                    .unwrap();
                assert_eq!(app.get_verification_history(10).await.unwrap().len(), 2);
                app.store_device_config("device-1", Some("profile-1"), Some("lane-1"))
                    .await
                    .unwrap();
                app.update_last_policy_sync("2026-02-01T00:00:00Z".to_string())
                    .await
                    .unwrap();
                let shared_version: String = app
                    .core_storage()
                    .with_connection(|conn| {
                        conn.query_row(
                            "SELECT value FROM config WHERE key = 'schema_version'",
                            [],
                            |row| row.get(0),
                        )
                    })
                    .await
                    .unwrap();
                assert_eq!(shared_version, legacy_version.to_string());
                drop(app);
                let app = SecureStorage::new_with_process_local_keyring(directory.path()).unwrap();
                app.health_check().await.unwrap();
                assert_eq!(
                    app.pii_encryptor
                        .as_ref()
                        .unwrap()
                        .decrypt(&legacy_pii)
                        .unwrap(),
                    ""
                );
                assert_eq!(app.get_verification_history(10).await.unwrap().len(), 2);
                assert_eq!(
                    app.core_storage().get_pending_events(10).await.unwrap()[0].id,
                    "legacy"
                );
                assert_eq!(app.get_pending_events(10).await.unwrap()[0].id, "legacy");
                assert_eq!(
                    serde_json::to_value(
                        app.get_deployment_profile("profile-1")
                            .await
                            .unwrap()
                            .unwrap()
                    )
                    .unwrap(),
                    serde_json::to_value(profile).unwrap()
                );
                assert_eq!(
                    serde_json::to_value(
                        app.get_presentation_policy("policy-1")
                            .await
                            .unwrap()
                            .unwrap()
                    )
                    .unwrap(),
                    serde_json::to_value(policy).unwrap()
                );
                assert_eq!(
                    app.get_presentation_policies(Some("profile-1"))
                        .await
                        .unwrap()
                        .len(),
                    1
                );
                assert_eq!(
                    app.get_device_config().await.unwrap(),
                    Some((
                        "device-1".to_string(),
                        Some("profile-1".to_string()),
                        Some("lane-1".to_string())
                    ))
                );
                assert_eq!(
                    app.get_last_policy_sync().await.unwrap().as_deref(),
                    Some("2026-02-01T00:00:00Z")
                );
            }
        }
    }
}
