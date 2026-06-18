//! JWT validation logic

use jsonwebtoken::{decode, Algorithm, DecodingKey, Validation};

use crate::claims::LicenseClaims;
use crate::error::LicenseError;

/// Validate a license JWT with Ed25519 signature
pub fn validate_jwt(token: &str, public_key_pem: &str) -> Result<LicenseClaims, LicenseError> {
    // Parse the public key
    let decoding_key = DecodingKey::from_ed_pem(public_key_pem.as_bytes())
        .map_err(|e| LicenseError::Crypto(format!("Invalid public key: {}", e)))?;

    // Set up validation
    let mut validation = Validation::new(Algorithm::EdDSA);
    validation.set_issuer(&["marty-license-issuer"]);
    validation.validate_exp = true;
    validation.validate_nbf = true;

    // Decode and validate
    let token_data =
        decode::<LicenseClaims>(token, &decoding_key, &validation).map_err(|e| match e.kind() {
            jsonwebtoken::errors::ErrorKind::ExpiredSignature => {
                LicenseError::Expired("License has expired".to_string())
            }
            jsonwebtoken::errors::ErrorKind::InvalidSignature => LicenseError::InvalidSignature,
            _ => LicenseError::Jwt(e.to_string()),
        })?;

    Ok(token_data.claims)
}

/// Validate license claims beyond JWT validation
pub fn validate_claims(claims: &LicenseClaims) -> Result<(), LicenseError> {
    // Check required fields
    if claims.sub.is_empty() {
        return Err(LicenseError::InvalidClaims(
            "Missing organization ID".to_string(),
        ));
    }

    if claims.features.is_empty()
        && claims.entitled_products.is_empty()
        && claims.plan_tier.is_none()
    {
        return Err(LicenseError::InvalidClaims(
            "License must include features, entitled products, or a plan tier".to_string(),
        ));
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use chrono::Utc;

    use super::validate_claims;
    use crate::{
        claims::{products, LicenseClaims, PlanTier},
        LicenseError,
    };

    fn sample_claims() -> LicenseClaims {
        let now = Utc::now().timestamp();
        LicenseClaims {
            iss: "marty-license-issuer".to_string(),
            sub: "org-123".to_string(),
            iat: now,
            exp: now + 86400,
            nbf: None,
            jti: Some("license-123".to_string()),
            features: vec!["mdl".to_string()],
            deployment_mode: Some("production".to_string()),
            max_verifications_total: 0,
            hardware_binding: None,
            hardware_tier: None,
            org_name: Some("Example Org".to_string()),
            update_channels: vec!["stable".to_string()],
            grace_period_days: 30,
            plan_tier: None,
            entitled_products: Vec::new(),
            max_instances: HashMap::new(),
            registry_access: false,
            api_calls_limit: 0,
        }
    }

    #[test]
    fn accepts_product_only_license() {
        let mut claims = sample_claims();
        claims.features.clear();
        claims.plan_tier = Some(PlanTier::System);
        claims.entitled_products = vec![products::UI_APP.to_string()];

        assert!(validate_claims(&claims).is_ok());
    }

    #[test]
    fn accepts_plan_tier_only_license() {
        let mut claims = sample_claims();
        claims.features.clear();
        claims.plan_tier = Some(PlanTier::System);

        assert!(validate_claims(&claims).is_ok());
    }

    #[test]
    fn rejects_license_without_any_entitlement_signal() {
        let mut claims = sample_claims();
        claims.features.clear();

        let error = validate_claims(&claims).unwrap_err();

        assert!(matches!(error, LicenseError::InvalidClaims(_)));
        assert_eq!(
            error.to_string(),
            "License claims invalid: License must include features, entitled products, or a plan tier"
        );
    }
}
