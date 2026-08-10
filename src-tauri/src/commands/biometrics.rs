//! Face match and liveness commands
//!
//! Uses ONNX Runtime (SCRFD + ArcFace) only when production model files are
//! available. Mock providers are never selected by a production command.

#[cfg(feature = "biometrics")]
use std::path::Path;

use serde::{Deserialize, Serialize};
use tauri::State;

use crate::error::{AppError, AppResult};
use crate::state::AppState;

#[cfg(feature = "biometrics")]
use marty_biometrics::{FaceVerificationRequest, FaceVerifier};

#[cfg(feature = "biometrics")]
const MIN_FACE_MATCH_THRESHOLD: f32 = 0.8;
#[cfg(feature = "biometrics")]
const MAX_FACE_MATCH_THRESHOLD: f32 = 1.0;

#[derive(Debug, Deserialize)]
pub struct FaceMatchRequest {
    /// Reference image (enrollment) base64
    pub reference_image: String,
    /// Probe image (live capture) base64
    pub probe_image: String,
    /// Optional similarity threshold. Values may make the production floor
    /// stricter, but cannot lower it.
    #[serde(default)]
    pub threshold: Option<f32>,
    /// Optional liveness challenge metadata (nonce/session/signature)
    #[serde(default)]
    pub liveness_challenge: Option<crate::commands::verification::LivenessChallenge>,
    /// Require liveness validation
    #[serde(default)]
    pub require_liveness: bool,
}

#[derive(Debug, Serialize)]
pub struct FaceMatchResponse {
    pub verified: bool,
    pub similarity: f32,
    pub threshold: f32,
    pub provider: String,
    /// Quality score for the reference image (0.0 - 1.0)
    pub reference_quality: Option<f32>,
    /// Quality score for the probe image (0.0 - 1.0)
    pub probe_quality: Option<f32>,
}

/// Face match with optional liveness validation.
///
/// Requires [`BiometricProvider::onnx`] and fails closed when its model files
/// are absent or invalid.
#[tauri::command]
pub async fn verify_face_match(
    request: FaceMatchRequest,
    state: State<'_, AppState>,
) -> AppResult<FaceMatchResponse> {
    // Capability + hardware gate
    state.check_feature("biometrics").await?;

    // Liveness challenge validation (if requested)
    if request.require_liveness || request.liveness_challenge.is_some() {
        let challenge = request.liveness_challenge.as_ref().ok_or_else(|| {
            AppError::Verification(
                "Liveness challenge required when liveness detection is requested".to_string(),
            )
        })?;
        crate::commands::verification::validate_liveness_challenge(challenge, None, state.inner())
            .await?;
    }

    #[cfg(not(feature = "biometrics"))]
    {
        Err(AppError::EntitlementDenied {
            capability: "biometrics".to_string(),
            reason: Some("biometrics was not compiled into this build".to_string()),
        })
    }

    #[cfg(feature = "biometrics")]
    {
        let threshold = resolve_face_match_threshold(request.threshold)?;
        let provider = resolve_biometric_provider(state.inner()).await?;

        let result = provider
            .verify(FaceVerificationRequest {
                reference_image: request.reference_image.clone(),
                probe_image: request.probe_image.clone(),
                threshold: Some(threshold),
                liveness_challenge: request.liveness_challenge.clone().map(|c| c.into()),
                preferred_liveness_mode: None,
                allow_network_fallback: false,
                accessibility_mode: false,
                retain_audit_clip: false,
                audit_clip_ttl_seconds: None,
            })
            .await
            .map_err(|e| AppError::Verification(e.to_string()))?;

        Ok(FaceMatchResponse {
            verified: result.verified,
            similarity: result.similarity,
            threshold: result.threshold,
            provider: result.provider,
            reference_quality: result.reference_quality,
            probe_quality: result.probe_quality,
        })
    }
}

#[cfg(feature = "biometrics")]
fn resolve_face_match_threshold(requested: Option<f32>) -> AppResult<f32> {
    let threshold = requested.unwrap_or(MIN_FACE_MATCH_THRESHOLD);
    if !threshold.is_finite()
        || !(MIN_FACE_MATCH_THRESHOLD..=MAX_FACE_MATCH_THRESHOLD).contains(&threshold)
    {
        return Err(AppError::Verification(format!(
            "Face match threshold must be between {MIN_FACE_MATCH_THRESHOLD} and {MAX_FACE_MATCH_THRESHOLD}"
        )));
    }

    Ok(threshold)
}

/// Assess quality of a face image before verification.
#[cfg(feature = "biometrics")]
#[tauri::command]
pub async fn assess_face_quality(
    image: String,
    state: State<'_, AppState>,
) -> AppResult<serde_json::Value> {
    state.check_feature("biometrics").await?;

    let provider = resolve_biometric_provider(state.inner()).await?;
    let assessment = provider
        .assess_quality(&image)
        .await
        .map_err(|e| AppError::Verification(e.to_string()))?;

    serde_json::to_value(&assessment).map_err(|e| AppError::Verification(e.to_string()))
}

/// Resolve the best available biometric provider.
///
/// Checks `<data_dir>/models/` for a usable ONNX provider. Missing or invalid
/// production models are an unavailable capability, never mock success.
#[cfg(feature = "biometrics")]
async fn resolve_biometric_provider(
    state: &AppState,
) -> AppResult<marty_biometrics::BiometricProvider> {
    let models_dir = {
        let config = state.config.read().await;
        config.data_dir.join("models")
    };

    resolve_biometric_provider_from_models(&models_dir)
}

#[cfg(feature = "biometrics")]
fn resolve_biometric_provider_from_models(
    models_dir: &Path,
) -> AppResult<marty_biometrics::BiometricProvider> {
    if !models_dir.is_dir() {
        tracing::error!(
            models_dir = %models_dir.display(),
            "Production biometric models directory is unavailable"
        );
        return Err(AppError::Verification(
            "Production biometric models are not configured".to_string(),
        ));
    }

    marty_biometrics::BiometricProvider::onnx(models_dir).map_err(|error| {
        tracing::error!(
            error = %error,
            models_dir = %models_dir.display(),
            "Production biometric provider initialization failed"
        );
        AppError::Verification("Production biometric provider is unavailable".to_string())
    })
}

#[cfg(all(test, feature = "biometrics"))]
mod tests {
    use super::*;

    #[test]
    fn face_match_threshold_defaults_to_production_floor() {
        assert_eq!(
            resolve_face_match_threshold(None).expect("default threshold"),
            MIN_FACE_MATCH_THRESHOLD
        );
    }

    #[test]
    fn face_match_threshold_allows_stricter_values() {
        assert_eq!(
            resolve_face_match_threshold(Some(0.9)).expect("stricter threshold"),
            0.9
        );
        assert_eq!(
            resolve_face_match_threshold(Some(MAX_FACE_MATCH_THRESHOLD))
                .expect("maximum threshold"),
            MAX_FACE_MATCH_THRESHOLD
        );
    }

    #[test]
    fn face_match_threshold_rejects_values_below_production_floor() {
        assert!(resolve_face_match_threshold(Some(MIN_FACE_MATCH_THRESHOLD - 0.01)).is_err());
        assert!(resolve_face_match_threshold(Some(-1.0)).is_err());
    }

    #[test]
    fn face_match_threshold_rejects_non_finite_or_out_of_range_values() {
        assert!(resolve_face_match_threshold(Some(f32::NAN)).is_err());
        assert!(resolve_face_match_threshold(Some(f32::INFINITY)).is_err());
        assert!(resolve_face_match_threshold(Some(MAX_FACE_MATCH_THRESHOLD + 0.01)).is_err());
    }

    #[test]
    fn missing_models_never_fall_back_to_mock() {
        let temp = tempfile::tempdir().expect("temporary directory");
        let missing = temp.path().join("missing-models");

        let error = match resolve_biometric_provider_from_models(&missing) {
            Ok(_) => panic!("missing production models must not select a provider"),
            Err(error) => error,
        };

        assert!(error
            .to_string()
            .contains("Production biometric models are not configured"));
    }

    #[test]
    fn invalid_models_never_fall_back_to_mock() {
        let empty_models = tempfile::tempdir().expect("temporary models directory");

        let error = match resolve_biometric_provider_from_models(empty_models.path()) {
            Ok(_) => panic!("invalid production models must not select a provider"),
            Err(error) => error,
        };

        assert!(error
            .to_string()
            .contains("Production biometric provider is unavailable"));
    }
}
