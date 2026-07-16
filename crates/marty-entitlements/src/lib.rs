//! Provider-neutral entitlement checks for optional verifier capabilities.

use serde::Serialize;

/// Result returned by an entitlement provider.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct EntitlementDecision {
    pub allowed: bool,
    pub reason: Option<String>,
}

impl EntitlementDecision {
    pub fn allow() -> Self {
        Self {
            allowed: true,
            reason: None,
        }
    }
}

/// Extension point for downstream distributions that apply entitlement policy.
pub trait EntitlementProvider: Send + Sync {
    fn check(&self, capability: &str) -> EntitlementDecision;
}

/// OSS default: all compiled capabilities are available without a license key.
#[derive(Debug, Default)]
pub struct AllowAllEntitlementProvider;

impl EntitlementProvider for AllowAllEntitlementProvider {
    fn check(&self, _capability: &str) -> EntitlementDecision {
        EntitlementDecision::allow()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn oss_provider_allows_compiled_capabilities() {
        assert!(AllowAllEntitlementProvider.check("oid4vp").allowed);
    }
}
