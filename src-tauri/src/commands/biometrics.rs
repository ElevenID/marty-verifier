//! Face match and liveness commands
//!
//! Uses ONNX Runtime (SCRFD + ArcFace) when model files are available,
//! falling back to the mock provider for development / testing.

use serde::{Deserialize, Serialize};
use tauri::State;

use crate::error::{AppError, AppResult};
use crate::state::AppState;

#[cfg(feature = "biometrics")]
use marty_biometrics::{FaceVerificationRequest, FaceVerifier};

#[derive(Debug, Deserialize)]
pub struct FaceMatchRequest {
    /// Reference image (enrollment) base64
    pub reference_image: String,
    /// Probe image (live capture) base64
    pub probe_image: String,
    /// Optional similarity threshold
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
/// Prefers [`BiometricProvider::onnx`] when ONNX model files are present in
/// the application data directory, otherwise falls back to
/// [`BiometricProvider::mock`].
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
        let provider = resolve_biometric_provider(state.inner()).await;
        let threshold = request.threshold.unwrap_or(0.8);

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

/// Assess quality of a face image before verification.
#[cfg(feature = "biometrics")]
#[tauri::command]
pub async fn assess_face_quality(
    image: String,
    state: State<'_, AppState>,
) -> AppResult<serde_json::Value> {
    state.check_feature("biometrics").await?;

    let provider = resolve_biometric_provider(state.inner()).await;
    let assessment = provider
        .assess_quality(&image)
        .await
        .map_err(|e| AppError::Verification(e.to_string()))?;

    serde_json::to_value(&assessment).map_err(|e| AppError::Verification(e.to_string()))
}

/// Resolve the best available biometric provider.
///
/// Checks `<data_dir>/models/` for ONNX model files. If present, uses the
/// ONNX provider for real on-device inference; otherwise falls back to mock.
#[cfg(feature = "biometrics")]
async fn resolve_biometric_provider(state: &AppState) -> marty_biometrics::BiometricProvider {
    let models_dir = {
        let config = state.config.read().await;
        config.data_dir.join("models")
    };

    if models_dir.is_dir() {
        match marty_biometrics::BiometricProvider::onnx(&models_dir) {
            Ok(provider) => {
                tracing::debug!(models_dir = %models_dir.display(), "Using ONNX biometric provider");
                return provider;
            }
            Err(e) => {
                tracing::warn!(
                    error = %e,
                    models_dir = %models_dir.display(),
                    "ONNX provider init failed, falling back to mock"
                );
            }
        }
    } else {
        tracing::info!(
            models_dir = %models_dir.display(),
            "Models directory not found, using mock biometric provider"
        );
    }

    marty_biometrics::BiometricProvider::mock()
}
