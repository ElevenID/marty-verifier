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

    if claims.features.is_empty() {
        return Err(LicenseError::InvalidClaims(
            "No features licensed".to_string(),
        ));
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    // JWT validation tests would require generating test keys
}
