//! Face match and liveness commands (placeholder implementation)

use serde::{Deserialize, Serialize};
use tauri::State;

use crate::error::{AppError, AppResult};
use crate::state::AppState;

#[derive(Debug, Deserialize)]
pub struct FaceMatchRequest {
    /// Reference image (enrollment) base64
    #[allow(dead_code)]
    pub reference_image: String,
    /// Probe image (live capture) base64
    #[allow(dead_code)]
    pub probe_image: String,
    /// Optional similarity threshold
    #[serde(default)]
    #[allow(dead_code)]
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
}

/// Face match with optional liveness validation (mock implementation for now).
#[tauri::command]
pub async fn verify_face_match(
    request: FaceMatchRequest,
    state: State<'_, AppState>,
) -> AppResult<FaceMatchResponse> {
    // Feature/license check (reuse biometrics feature flag string)
    state.check_feature("biometrics").await?;

    if request.require_liveness || request.liveness_challenge.is_some() {
        let challenge = request.liveness_challenge.as_ref().ok_or_else(|| {
            AppError::Verification(
                "Liveness challenge required when liveness detection is requested".to_string(),
            )
        })?;

        // Reuse shared validation logic
        crate::commands::verification::validate_liveness_challenge(challenge, None, state.inner())
            .await?;
    }

    #[cfg(not(feature = "biometrics"))]
    {
        return Err(AppError::FeatureNotLicensed(
            "biometrics feature not enabled".to_string(),
        ));
    }

    #[cfg(feature = "biometrics")]
    {
        use marty_biometrics::{BiometricProvider, FaceVerificationRequest};

        let provider = BiometricProvider::mock();
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

        return Ok(FaceMatchResponse {
            verified: result.verified,
            similarity: result.similarity,
            threshold: result.threshold,
            provider: result.provider,
        });
    }
}
