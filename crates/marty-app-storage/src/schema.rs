//! App-owned schema; shared tables are migrated by marty-secure-storage.

pub const SCHEMA: &str = r#"
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

/// Independent app migration history (legacy shared marker is preserved).
pub const SCHEMA_VERSION: i32 = 1;
