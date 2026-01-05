//! License JWT claims

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

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

    /// Licensed features
    #[serde(default)]
    pub features: Vec<String>,

    /// Deployment mode
    #[serde(skip_serializing_if = "Option::is_none")]
    pub deployment_mode: Option<String>,

    /// Maximum total verifications (0 = unlimited)
    #[serde(default)]
    pub max_verifications_total: u64,

    /// Hardware binding hash (optional)
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
}
