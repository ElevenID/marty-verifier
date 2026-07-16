//! Database schema definitions

/// SQL schema for secure storage
pub const SCHEMA: &str = r#"
-- Verification events table
CREATE TABLE IF NOT EXISTS verification_events (
    id TEXT PRIMARY KEY,
    credential_type TEXT NOT NULL,
    status TEXT NOT NULL,
    issuer_jurisdiction TEXT,
    trust_chain_type TEXT,
    offline_verified INTEGER NOT NULL DEFAULT 0,
    verified_at TEXT NOT NULL,
    synced INTEGER NOT NULL DEFAULT 0,
    synced_at TEXT,
    -- Encrypted PII fields (optional, based on config)
    encrypted_subject_hash TEXT,
    created_at TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE INDEX IF NOT EXISTS idx_verification_events_verified_at 
    ON verification_events(verified_at);
CREATE INDEX IF NOT EXISTS idx_verification_events_synced 
    ON verification_events(synced);
CREATE INDEX IF NOT EXISTS idx_verification_events_credential_type 
    ON verification_events(credential_type);

-- Trust anchors cache (IACA/CSCA certificates)
CREATE TABLE IF NOT EXISTS trust_anchors (
    id TEXT PRIMARY KEY,
    anchor_type TEXT NOT NULL, -- 'iaca', 'csca', 'dsc'
    jurisdiction TEXT NOT NULL,
    subject TEXT,
    issuer TEXT,
    serial_number TEXT,
    not_before TEXT,
    not_after TEXT,
    certificate_der BLOB NOT NULL,
    certificate_hash TEXT NOT NULL,
    source TEXT, -- 'aamva_dts', 'icao_pkd', 'usb_import', 'manual'
    synced_at TEXT NOT NULL,
    created_at TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE INDEX IF NOT EXISTS idx_trust_anchors_type_jurisdiction 
    ON trust_anchors(anchor_type, jurisdiction);
CREATE INDEX IF NOT EXISTS idx_trust_anchors_hash 
    ON trust_anchors(certificate_hash);

-- Open Badge verification methods (trusted public keys)
CREATE TABLE IF NOT EXISTS open_badge_keys (
    id TEXT PRIMARY KEY,
    document_json TEXT NOT NULL, -- JSON verification method document
    controller TEXT,
    issuer TEXT,
    kid TEXT,
    not_before TEXT,
    not_after TEXT,
    status TEXT,
    source TEXT, -- 'sync', 'usb_import', 'manual'
    synced_at TEXT NOT NULL,
    created_at TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE INDEX IF NOT EXISTS idx_open_badge_keys_controller
    ON open_badge_keys(controller);
CREATE INDEX IF NOT EXISTS idx_open_badge_keys_status
    ON open_badge_keys(status);

-- CRL cache
CREATE TABLE IF NOT EXISTS crl_cache (
    id TEXT PRIMARY KEY,
    issuer_hash TEXT NOT NULL,
    crl_der BLOB NOT NULL,
    next_update TEXT,
    fetched_at TEXT NOT NULL,
    created_at TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE INDEX IF NOT EXISTS idx_crl_cache_issuer 
    ON crl_cache(issuer_hash);

-- OCSP cache
CREATE TABLE IF NOT EXISTS ocsp_cache (
    id TEXT PRIMARY KEY,
    cert_hash TEXT NOT NULL,
    response_der BLOB NOT NULL,
    status TEXT NOT NULL, -- 'good', 'revoked', 'unknown'
    this_update TEXT,
    next_update TEXT,
    fetched_at TEXT NOT NULL,
    created_at TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE INDEX IF NOT EXISTS idx_ocsp_cache_cert 
    ON ocsp_cache(cert_hash);

-- Offline reporting queue
CREATE TABLE IF NOT EXISTS offline_queue (
    id TEXT PRIMARY KEY,
    event_type TEXT NOT NULL,
    payload TEXT NOT NULL, -- JSON
    created_at TEXT NOT NULL,
    retry_count INTEGER NOT NULL DEFAULT 0,
    last_retry_at TEXT,
    error TEXT
);

CREATE INDEX IF NOT EXISTS idx_offline_queue_created 
    ON offline_queue(created_at);

-- Audit log
CREATE TABLE IF NOT EXISTS audit_log (
    id TEXT PRIMARY KEY,
    event_type TEXT NOT NULL,
    actor TEXT, -- operator ID if applicable
    target TEXT, -- what was acted upon
    details TEXT, -- JSON
    ip_address TEXT,
    created_at TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE INDEX IF NOT EXISTS idx_audit_log_created 
    ON audit_log(created_at);
CREATE INDEX IF NOT EXISTS idx_audit_log_event_type 
    ON audit_log(event_type);

-- Sync state
CREATE TABLE IF NOT EXISTS sync_state (
    id TEXT PRIMARY KEY DEFAULT 'current',
    last_iaca_sync TEXT,
    last_csca_sync TEXT,
    last_crl_sync TEXT,
    last_policy_sync TEXT,
    iaca_version TEXT,
    csca_version TEXT,
    sync_in_progress INTEGER NOT NULL DEFAULT 0,
    last_error TEXT,
    created_at TEXT NOT NULL DEFAULT (datetime('now')),
    updated_at TEXT NOT NULL DEFAULT (datetime('now'))
);

-- Configuration storage
CREATE TABLE IF NOT EXISTS config (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL,
    updated_at TEXT NOT NULL DEFAULT (datetime('now'))
);

-- Presentation policies cache
CREATE TABLE IF NOT EXISTS presentation_policies (
    id TEXT PRIMARY KEY,
    policy_json TEXT NOT NULL, -- Full policy definition as JSON
    version INTEGER NOT NULL,
    synced_at TEXT NOT NULL,
    deployment_profile_id TEXT, -- Optional link to deployment profile
    created_at TEXT NOT NULL DEFAULT (datetime('now')),
    updated_at TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE INDEX IF NOT EXISTS idx_presentation_policies_synced_at 
    ON presentation_policies(synced_at);
CREATE INDEX IF NOT EXISTS idx_presentation_policies_deployment_profile 
    ON presentation_policies(deployment_profile_id);

-- Deployment profiles cache
CREATE TABLE IF NOT EXISTS deployment_profiles (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    site_id TEXT,
    network_mode TEXT NOT NULL, -- 'online', 'offline', 'hybrid'
    key_access_mode TEXT NOT NULL,
    ux_config TEXT NOT NULL, -- JSON: {language, theme, signage_text, show_operator_mode, accessibility_enabled}
    update_policy TEXT NOT NULL, -- JSON: {auto_update, update_channel, rollout_percentage, rollout_ring}
    offline_cache_ttl_hours INTEGER NOT NULL DEFAULT 24,
    biometric_required INTEGER NOT NULL DEFAULT 0,
    audit_all_events INTEGER NOT NULL DEFAULT 1,
    synced_at TEXT NOT NULL,
    created_at TEXT NOT NULL DEFAULT (datetime('now')),
    updated_at TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE INDEX IF NOT EXISTS idx_deployment_profiles_site_id 
    ON deployment_profiles(site_id);

-- Lanes cache
CREATE TABLE IF NOT EXISTS lanes (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    deployment_profile_id TEXT NOT NULL,
    default_policy_id TEXT,
    device_ids TEXT NOT NULL, -- JSON array of device IDs
    metadata TEXT, -- JSON
    synced_at TEXT NOT NULL,
    created_at TEXT NOT NULL DEFAULT (datetime('now')),
    updated_at TEXT NOT NULL DEFAULT (datetime('now')),
    FOREIGN KEY (deployment_profile_id) REFERENCES deployment_profiles(id)
);

CREATE INDEX IF NOT EXISTS idx_lanes_deployment_profile 
    ON lanes(deployment_profile_id);

-- Device configuration (current device assignment)
CREATE TABLE IF NOT EXISTS device_config (
    id TEXT PRIMARY KEY DEFAULT 'current',
    device_id TEXT,
    lane_id TEXT,
    deployment_profile_id TEXT,
    assigned_at TEXT,
    created_at TEXT NOT NULL DEFAULT (datetime('now')),
    updated_at TEXT NOT NULL DEFAULT (datetime('now'))
);
"#;

/// Schema version for migrations
pub const SCHEMA_VERSION: i32 = 4;
