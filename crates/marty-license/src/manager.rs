//! License manager

use std::sync::Arc;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use tokio::sync::RwLock;

use marty_secure_storage::{LicenseState, SecureStorage};

use crate::claims::LicenseClaims;
use crate::error::LicenseError;
use crate::fingerprint::generate_hardware_fingerprint;
use crate::validation::{validate_claims, validate_jwt};

/// License validation result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LicenseValidationResult {
    pub valid: bool,
    pub org_id: Option<String>,
    pub expires_at: Option<DateTime<Utc>>,
    pub days_until_expiry: Option<i64>,
    pub features: Vec<String>,
    pub hardware_bound: bool,
    pub grace_period_active: bool,
    pub grace_period_days: Option<i64>,
    pub deployment_mode: Option<String>,
    pub max_verifications_total: Option<u64>,
    pub verifications_total: u64,
    pub verifications_remaining: Option<u64>,
    pub update_channels: Vec<String>,
}

/// License status (current state)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LicenseStatus {
    pub valid: bool,
    pub org_id: Option<String>,
    pub expires_at: Option<DateTime<Utc>>,
    pub days_until_expiry: Option<i64>,
    pub features: Vec<String>,
    pub hardware_bound: bool,
    pub grace_period_active: bool,
    pub grace_period_days: Option<i64>,
    pub deployment_mode: Option<String>,
    pub max_verifications_total: Option<u64>,
    pub verifications_total: u64,
    pub verifications_remaining: Option<u64>,
    pub update_channels: Vec<String>,
}

/// License manager for validation and tracking
pub struct LicenseManager {
    storage: Arc<SecureStorage>,
    public_key_pem: String,
    cached_claims: RwLock<Option<LicenseClaims>>,
    hardware_fingerprint: String,
}

impl LicenseManager {
    /// Create new license manager
    pub fn new(storage: Arc<SecureStorage>, public_key_pem: String) -> Result<Self, LicenseError> {
        let hardware_fingerprint = generate_hardware_fingerprint();

        tracing::debug!(fingerprint = %hardware_fingerprint, "Hardware fingerprint generated");

        Ok(Self {
            storage,
            public_key_pem,
            cached_claims: RwLock::new(None),
            hardware_fingerprint,
        })
    }

    /// Validate and install a new license
    pub async fn validate_license(
        &self,
        license_jwt: &str,
    ) -> Result<LicenseValidationResult, LicenseError> {
        // Skip JWT validation if no public key configured (development mode)
        let claims = if self.public_key_pem.is_empty() {
            tracing::warn!("No license public key configured - accepting all licenses (dev mode)");
            // Parse claims without signature validation
            let parts: Vec<&str> = license_jwt.split('.').collect();
            if parts.len() != 3 {
                return Err(LicenseError::Jwt("Invalid JWT format".to_string()));
            }
            use base64::Engine;
            let claims_json = base64::engine::general_purpose::URL_SAFE_NO_PAD
                .decode(parts[1])
                .map_err(|e| LicenseError::Jwt(format!("Invalid base64: {}", e)))?;
            serde_json::from_slice::<LicenseClaims>(&claims_json)
                .map_err(|e| LicenseError::InvalidClaims(e.to_string()))?
        } else {
            // Validate JWT signature
            validate_jwt(license_jwt, &self.public_key_pem)?
        };

        // Validate claims
        validate_claims(&claims)?;

        // Check hardware binding if required
        if claims.requires_hardware_binding() {
            if !claims.validate_hardware_binding(&self.hardware_fingerprint) {
                return Err(LicenseError::HardwareBindingMismatch);
            }
        }

        // Get current verification count
        let license_state = self.storage.get_license_state().await?;
        let verifications_total = self.get_total_verifications(&license_state).await;
        let (max_verifications_total, verifications_remaining) =
            Self::compute_total_limit(claims.max_verifications_total, verifications_total);

        // Store license
        let new_state = LicenseState {
            license_jwt: Some(license_jwt.to_string()),
            validated_at: Some(Utc::now()),
            hardware_fingerprint: Some(self.hardware_fingerprint.clone()),
            verifications_today: license_state
                .as_ref()
                .map(|s| s.verifications_today)
                .unwrap_or(0),
            verifications_date: license_state
                .as_ref()
                .and_then(|s| s.verifications_date.clone()),
            verifications_total: verifications_total as i64,
            grace_period_started: None,
        };
        self.storage.update_license_state(&new_state).await?;

        // Cache claims
        *self.cached_claims.write().await = Some(claims.clone());

        tracing::info!(
            org_id = %claims.sub,
            features = ?claims.features,
            expires_at = ?claims.expires_at(),
            "License validated and installed"
        );

        Ok(LicenseValidationResult {
            valid: true,
            org_id: Some(claims.sub.clone()),
            expires_at: claims.expires_at(),
            days_until_expiry: Some(claims.days_until_expiry()),
            features: claims.features.clone(),
            hardware_bound: claims.requires_hardware_binding(),
            grace_period_active: false,
            grace_period_days: None,
            deployment_mode: claims.deployment_mode.clone(),
            max_verifications_total,
            verifications_total,
            verifications_remaining,
            update_channels: claims.update_channels.clone(),
        })
    }

    /// Get current license status
    pub async fn get_status(&self) -> Result<LicenseStatus, LicenseError> {
        // Try cached claims first
        if let Some(claims) = self.cached_claims.read().await.as_ref() {
            return self.build_status(claims).await;
        }

        // Load from storage
        let state = self.storage.get_license_state().await?;
        let license_jwt = state
            .and_then(|s| s.license_jwt)
            .ok_or(LicenseError::NoLicense)?;

        // Re-validate (without storing)
        let claims = if self.public_key_pem.is_empty() {
            let parts: Vec<&str> = license_jwt.split('.').collect();
            if parts.len() != 3 {
                return Err(LicenseError::Jwt("Invalid JWT format".to_string()));
            }
            use base64::Engine;
            let claims_json = base64::engine::general_purpose::URL_SAFE_NO_PAD
                .decode(parts[1])
                .map_err(|e| LicenseError::Jwt(format!("Invalid base64: {}", e)))?;
            serde_json::from_slice::<LicenseClaims>(&claims_json)
                .map_err(|e| LicenseError::InvalidClaims(e.to_string()))?
        } else {
            validate_jwt(&license_jwt, &self.public_key_pem)?
        };

        // Cache claims
        *self.cached_claims.write().await = Some(claims.clone());

        self.build_status(&claims).await
    }

    /// Get cached or stored license claims
    pub async fn get_claims(&self) -> Result<LicenseClaims, LicenseError> {
        if let Some(claims) = self.cached_claims.read().await.as_ref() {
            return Ok(claims.clone());
        }

        // Load from storage
        let state = self.storage.get_license_state().await?;
        let license_jwt = state
            .and_then(|s| s.license_jwt)
            .ok_or(LicenseError::NoLicense)?;

        let claims = if self.public_key_pem.is_empty() {
            let parts: Vec<&str> = license_jwt.split('.').collect();
            if parts.len() != 3 {
                return Err(LicenseError::Jwt("Invalid JWT format".to_string()));
            }
            use base64::Engine;
            let claims_json = base64::engine::general_purpose::URL_SAFE_NO_PAD
                .decode(parts[1])
                .map_err(|e| LicenseError::Jwt(format!("Invalid base64: {}", e)))?;
            serde_json::from_slice::<LicenseClaims>(&claims_json)
                .map_err(|e| LicenseError::InvalidClaims(e.to_string()))?
        } else {
            validate_jwt(&license_jwt, &self.public_key_pem)?
        };

        *self.cached_claims.write().await = Some(claims.clone());
        Ok(claims)
    }

    /// Check if a feature is licensed
    pub async fn is_feature_licensed(&self, feature: &str) -> Result<bool, LicenseError> {
        let status = self.get_status().await?;
        if !status.valid {
            return Ok(false);
        }
        Ok(status
            .features
            .iter()
            .any(|f| f == "*" || f == feature || feature.starts_with(f)))
    }

    /// Increment total verification count
    pub async fn increment_verification_count(&self) -> Result<u64, LicenseError> {
        let mut state = self
            .storage
            .get_license_state()
            .await?
            .unwrap_or(LicenseState {
                license_jwt: None,
                validated_at: None,
                hardware_fingerprint: None,
                verifications_today: 0,
                verifications_date: None,
                verifications_total: 0,
                grace_period_started: None,
            });

        state.verifications_total += 1;
        self.storage.update_license_state(&state).await?;

        Ok(state.verifications_total as u64)
    }

    /// Check if verification limit is exceeded
    pub async fn check_verification_limit(&self) -> Result<(), LicenseError> {
        let claims = self.get_claims().await?;

        if claims.max_verifications_total == 0 {
            return Ok(()); // Unlimited
        }

        let state = self.storage.get_license_state().await?;
        let count = self.get_total_verifications(&state).await;

        if count >= claims.max_verifications_total {
            return Err(LicenseError::VerificationLimitExceeded {
                used: count,
                max: claims.max_verifications_total,
            });
        }

        Ok(())
    }

    async fn get_total_verifications(&self, state: &Option<LicenseState>) -> u64 {
        state
            .as_ref()
            .map(|s| s.verifications_total.max(0) as u64)
            .unwrap_or(0)
    }

    fn compute_total_limit(max: u64, used: u64) -> (Option<u64>, Option<u64>) {
        if max == 0 {
            (None, None)
        } else {
            (Some(max), Some(max.saturating_sub(used)))
        }
    }

    async fn build_status(&self, claims: &LicenseClaims) -> Result<LicenseStatus, LicenseError> {
        let state = self.storage.get_license_state().await?;
        let verifications_total = self.get_total_verifications(&state).await;
        let (max_verifications_total, verifications_remaining) =
            Self::compute_total_limit(claims.max_verifications_total, verifications_total);

        let is_expired = claims.is_expired();
        let grace_period_active = if is_expired {
            // Check if within grace period
            if let Some(state) = &state {
                if let Some(grace_started) = state.grace_period_started {
                    let grace_end =
                        grace_started + chrono::Duration::days(claims.grace_period_days);
                    Utc::now() < grace_end
                } else {
                    // Start grace period
                    let mut new_state = state.clone();
                    new_state.grace_period_started = Some(Utc::now());
                    self.storage.update_license_state(&new_state).await?;
                    true
                }
            } else {
                false
            }
        } else {
            false
        };

        let valid = !is_expired || grace_period_active;

        let grace_period_days = if grace_period_active {
            state.as_ref().and_then(|s| {
                s.grace_period_started.map(|started| {
                    let grace_end = started + chrono::Duration::days(claims.grace_period_days);
                    (grace_end - Utc::now()).num_days()
                })
            })
        } else {
            None
        };

        Ok(LicenseStatus {
            valid,
            org_id: Some(claims.sub.clone()),
            expires_at: claims.expires_at(),
            days_until_expiry: Some(claims.days_until_expiry()),
            features: claims.features.clone(),
            hardware_bound: claims.requires_hardware_binding(),
            grace_period_active,
            grace_period_days,
            deployment_mode: claims.deployment_mode.clone(),
            max_verifications_total,
            verifications_total,
            verifications_remaining,
            update_channels: claims.update_channels.clone(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::LicenseManager;

    #[test]
    fn compute_total_limit_unlimited() {
        let (max, remaining) = LicenseManager::compute_total_limit(0, 10);
        assert!(max.is_none());
        assert!(remaining.is_none());
    }

    #[test]
    fn compute_total_limit_remaining() {
        let (max, remaining) = LicenseManager::compute_total_limit(100, 30);
        assert_eq!(max, Some(100));
        assert_eq!(remaining, Some(70));
    }

    #[test]
    fn compute_total_limit_saturates() {
        let (max, remaining) = LicenseManager::compute_total_limit(50, 80);
        assert_eq!(max, Some(50));
        assert_eq!(remaining, Some(0));
    }
}
