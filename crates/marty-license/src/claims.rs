//! License JWT claims
//!
//! Unified license format for all Marty products: verifier app, backend containers, and CLI.

use std::collections::HashMap;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// Canonical subscription plan tiers (aligned across frontend and backend)
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PlanTier {
    Sandbox,
    Program,
    Institution,
    System,
}

impl PlanTier {
    pub fn is_self_hosted(&self) -> bool {
        matches!(self, PlanTier::System)
    }

    pub fn allows_registry_access(&self) -> bool {
        !matches!(self, PlanTier::Sandbox)
    }
}

impl std::fmt::Display for PlanTier {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PlanTier::Sandbox => write!(f, "sandbox"),
            PlanTier::Program => write!(f, "program"),
            PlanTier::Institution => write!(f, "institution"),
            PlanTier::System => write!(f, "system"),
        }
    }
}

/// Known product identifiers for entitlement checks
pub mod products {
    pub const VERIFIER: &str = "verifier";
    pub const DOCUMENT_SIGNER: &str = "document-signer";
    pub const PASSPORT_ENGINE: &str = "passport-engine";
    pub const CSCA_SERVICE: &str = "csca-service";
    pub const INSPECTION_SYSTEM: &str = "inspection-system";
    pub const MDL_ENGINE: &str = "mdl-engine";
    pub const MDOC_ENGINE: &str = "mdoc-engine";
    pub const DTC_ENGINE: &str = "dtc-engine";
    pub const PKD_SERVICE: &str = "pkd-service";
    pub const TRUST_ANCHOR: &str = "trust-anchor";
    pub const UI_APP: &str = "ui-app";
    pub const OID4VC_API: &str = "oid4vc-api";
    pub const OPEN_BADGES: &str = "open-badges";
}

/// License JWT claims
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LicenseClaims {
    /// Issuer (marty-license-issuer)
    pub iss: String,

    /// Subject (organization ID)
    pub sub: String,

    /// Issued at timestamp
    pub iat: i64,

    /// Expiration timestamp
    pub exp: i64,

    /// Not before timestamp (optional)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub nbf: Option<i64>,

    /// JWT ID (unique license ID)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub jti: Option<String>,

    /// Licensed features (verifier-specific: "mdl", "emrtd", "oid4vp", etc.)
    #[serde(default)]
    pub features: Vec<String>,

    /// Deployment mode
    #[serde(skip_serializing_if = "Option::is_none")]
    pub deployment_mode: Option<String>,

    /// Maximum total verifications (0 = unlimited)
    #[serde(default)]
    pub max_verifications_total: u64,

    /// Hardware binding hash (optional, verifier only)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub hardware_binding: Option<String>,

    /// Hardware tier restriction
    #[serde(skip_serializing_if = "Option::is_none")]
    pub hardware_tier: Option<String>,

    /// Organization name for display
    #[serde(skip_serializing_if = "Option::is_none")]
    pub org_name: Option<String>,

    /// Allowed update channels (empty = no updates)
    #[serde(default)]
    pub update_channels: Vec<String>,

    /// Grace period days for offline renewal
    #[serde(default = "default_grace_period")]
    pub grace_period_days: i64,

    // --- Unified licensing fields (Phase 1) ---
    /// Subscription plan tier
    #[serde(skip_serializing_if = "Option::is_none")]
    pub plan_tier: Option<PlanTier>,

    /// Products this license grants access to (e.g. "verifier", "document-signer")
    /// Empty = verifier-only (backward compatible with pre-unified licenses)
    #[serde(default)]
    pub entitled_products: Vec<String>,

    /// Per-product maximum concurrent instance count (0 = unlimited)
    /// Products not listed default to 1 instance
    #[serde(default)]
    pub max_instances: HashMap<String, u32>,

    /// Whether this license grants container registry pull access
    #[serde(default)]
    pub registry_access: bool,

    /// Monthly API call limit across all products (0 = unlimited)
    #[serde(default)]
    pub api_calls_limit: u64,
}

fn default_grace_period() -> i64 {
    30
}

impl LicenseClaims {
    /// Check if the license has expired
    pub fn is_expired(&self) -> bool {
        let now = Utc::now().timestamp();
        now > self.exp
    }

    /// Get expiration as DateTime
    pub fn expires_at(&self) -> Option<DateTime<Utc>> {
        DateTime::from_timestamp(self.exp, 0)
    }

    /// Get days until expiration
    pub fn days_until_expiry(&self) -> i64 {
        let now = Utc::now().timestamp();
        let seconds_remaining = self.exp - now;
        seconds_remaining / 86400
    }

    /// Check if a feature is licensed
    pub fn has_feature(&self, feature: &str) -> bool {
        // Check for wildcard
        if self.features.contains(&"*".to_string()) {
            return true;
        }

        // Check for exact match
        if self.features.contains(&feature.to_string()) {
            return true;
        }

        // Check for category match (e.g., "mdl" matches "mdl_qr", "mdl_ble")
        self.features.iter().any(|f| feature.starts_with(f))
    }

    /// Check if hardware binding is required
    pub fn requires_hardware_binding(&self) -> bool {
        self.hardware_binding.is_some()
    }

    /// Check if an update channel is allowed
    pub fn allows_update_channel(&self, channel: &str) -> bool {
        if self.update_channels.is_empty() {
            return false;
        }

        if self.update_channels.iter().any(|c| c == "*") {
            return true;
        }

        self.update_channels.iter().any(|c| c == channel)
    }

    /// Validate hardware binding
    pub fn validate_hardware_binding(&self, fingerprint: &str) -> bool {
        match &self.hardware_binding {
            Some(expected) => expected == fingerprint,
            None => true, // No binding required
        }
    }

    // --- Unified licensing helpers ---

    /// Check if a product is entitled by this license
    pub fn has_product(&self, product: &str) -> bool {
        // Empty entitled_products = legacy verifier-only license
        if self.entitled_products.is_empty() {
            return product == products::VERIFIER;
        }

        // Wildcard grants all products
        if self.entitled_products.iter().any(|p| p == "*") {
            return true;
        }

        self.entitled_products.iter().any(|p| p == product)
    }

    /// Get maximum concurrent instances allowed for a product (0 = unlimited)
    pub fn max_instances_for(&self, product: &str) -> u32 {
        match self.max_instances.get(product) {
            Some(&0) => 0, // explicitly unlimited
            Some(&n) => n,
            None => {
                // System tier defaults to unlimited, others default to 1
                if self
                    .plan_tier
                    .as_ref()
                    .is_some_and(|t| *t == PlanTier::System)
                {
                    0
                } else {
                    1
                }
            }
        }
    }

    /// Check if API call limit is unlimited
    pub fn has_unlimited_api_calls(&self) -> bool {
        self.api_calls_limit == 0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_claims() -> LicenseClaims {
        let now = Utc::now().timestamp();
        LicenseClaims {
            iss: "marty-license-issuer".to_string(),
            sub: "org-123".to_string(),
            iat: now,
            exp: now + 86400 * 365, // 1 year
            nbf: None,
            jti: Some("license-456".to_string()),
            features: vec!["mdl".to_string(), "emrtd".to_string(), "oid4vp".to_string()],
            deployment_mode: Some("airport_kiosk".to_string()),
            max_verifications_total: 10000,
            hardware_binding: None,
            hardware_tier: Some("complex".to_string()),
            org_name: Some("Example Airport Authority".to_string()),
            update_channels: vec!["stable".to_string()],
            grace_period_days: 30,
            plan_tier: Some(PlanTier::Institution),
            entitled_products: vec![
                products::VERIFIER.to_string(),
                products::DOCUMENT_SIGNER.to_string(),
            ],
            max_instances: HashMap::from([(products::VERIFIER.to_string(), 10)]),
            registry_access: true,
            api_calls_limit: 0,
        }
    }

    /// Legacy license without unified fields (backward compatibility)
    fn legacy_claims() -> LicenseClaims {
        let now = Utc::now().timestamp();
        LicenseClaims {
            iss: "marty-license-issuer".to_string(),
            sub: "org-legacy".to_string(),
            iat: now,
            exp: now + 86400 * 365,
            nbf: None,
            jti: None,
            features: vec!["mdl".to_string()],
            deployment_mode: None,
            max_verifications_total: 0,
            hardware_binding: None,
            hardware_tier: None,
            org_name: None,
            update_channels: vec![],
            grace_period_days: 30,
            plan_tier: None,
            entitled_products: vec![],
            max_instances: HashMap::new(),
            registry_access: false,
            api_calls_limit: 0,
        }
    }

    #[test]
    fn test_feature_check() {
        let claims = sample_claims();
        assert!(claims.has_feature("mdl"));
        assert!(claims.has_feature("mdl_qr"));
        assert!(claims.has_feature("emrtd"));
        assert!(!claims.has_feature("biometrics"));
    }

    #[test]
    fn test_wildcard_features() {
        let mut claims = sample_claims();
        claims.features = vec!["*".to_string()];
        assert!(claims.has_feature("anything"));
        assert!(claims.has_feature("mdl"));
        assert!(claims.has_feature("biometrics"));
    }

    #[test]
    fn test_expiration() {
        let mut claims = sample_claims();
        assert!(!claims.is_expired());

        // Set to past
        claims.exp = Utc::now().timestamp() - 86400;
        assert!(claims.is_expired());
    }

    #[test]
    fn test_update_channel_check() {
        let claims = sample_claims();
        assert!(claims.allows_update_channel("stable"));
        assert!(!claims.allows_update_channel("beta"));

        let mut wildcard = claims.clone();
        wildcard.update_channels = vec!["*".to_string()];
        assert!(wildcard.allows_update_channel("beta"));
    }

    // --- Unified licensing tests ---

    #[test]
    fn test_product_entitlement() {
        let claims = sample_claims();
        assert!(claims.has_product(products::VERIFIER));
        assert!(claims.has_product(products::DOCUMENT_SIGNER));
        assert!(!claims.has_product(products::PASSPORT_ENGINE));
    }

    #[test]
    fn test_product_wildcard() {
        let mut claims = sample_claims();
        claims.entitled_products = vec!["*".to_string()];
        assert!(claims.has_product(products::VERIFIER));
        assert!(claims.has_product(products::PASSPORT_ENGINE));
        assert!(claims.has_product("anything"));
    }

    #[test]
    fn test_legacy_license_defaults_to_verifier() {
        let claims = legacy_claims();
        assert!(claims.has_product(products::VERIFIER));
        assert!(!claims.has_product(products::DOCUMENT_SIGNER));
    }

    #[test]
    fn test_max_instances() {
        let claims = sample_claims();
        // Explicitly set
        assert_eq!(claims.max_instances_for(products::VERIFIER), 10);
        // Not set, non-system tier → defaults to 1
        assert_eq!(claims.max_instances_for(products::DOCUMENT_SIGNER), 1);
    }

    #[test]
    fn test_max_instances_system_tier_defaults_unlimited() {
        let mut claims = sample_claims();
        claims.plan_tier = Some(PlanTier::System);
        claims.max_instances = HashMap::new();
        // System tier with no explicit limit → unlimited (0)
        assert_eq!(claims.max_instances_for(products::VERIFIER), 0);
    }

    #[test]
    fn test_plan_tier_serde_roundtrip() {
        let claims = sample_claims();
        let json = serde_json::to_string(&claims).unwrap();
        assert!(json.contains("\"plan_tier\":\"institution\""));
        let deserialized: LicenseClaims = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.plan_tier, Some(PlanTier::Institution));
    }

    #[test]
    fn test_legacy_jwt_deserializes_without_new_fields() {
        // Simulates a JWT issued before unified licensing — no new fields present
        let json = r#"{
            "iss": "marty-license-issuer",
            "sub": "org-old",
            "iat": 1700000000,
            "exp": 1800000000,
            "features": ["mdl"],
            "max_verifications_total": 1000,
            "grace_period_days": 30
        }"#;
        let claims: LicenseClaims = serde_json::from_str(json).unwrap();
        assert_eq!(claims.sub, "org-old");
        assert!(claims.plan_tier.is_none());
        assert!(claims.entitled_products.is_empty());
        assert!(claims.max_instances.is_empty());
        assert!(!claims.registry_access);
        assert_eq!(claims.api_calls_limit, 0);
        // Legacy behavior: defaults to verifier product
        assert!(claims.has_product(products::VERIFIER));
        assert!(!claims.has_product(products::DOCUMENT_SIGNER));
    }

    #[test]
    fn test_plan_tier_properties() {
        assert!(!PlanTier::Sandbox.allows_registry_access());
        assert!(PlanTier::Program.allows_registry_access());
        assert!(PlanTier::Institution.allows_registry_access());
        assert!(PlanTier::System.allows_registry_access());

        assert!(!PlanTier::Sandbox.is_self_hosted());
        assert!(!PlanTier::Program.is_self_hosted());
        assert!(PlanTier::System.is_self_hosted());
    }

    #[test]
    fn test_api_calls_limit() {
        let mut claims = sample_claims();
        claims.api_calls_limit = 0;
        assert!(claims.has_unlimited_api_calls());
        claims.api_calls_limit = 50000;
        assert!(!claims.has_unlimited_api_calls());
    }
}
