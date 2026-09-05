//! Liveness verification operations.

use super::{
    hmac, AppError, AppResult, AppState, DateTime, Duration, FaceMatchPayload, LivenessChallenge,
    LivenessResultPayload, LivenessStep, LivenessStepType, PadProviderConfig, PadProviderType, Utc,
    Uuid, VerifyRequest, DEFAULT_STEP_TIME_LIMIT_MS, MAX_CLOCK_SKEW_SECS, URL_SAFE_NO_PAD,
};
use base64::Engine;

pub(super) fn build_liveness_steps(accessibility_mode: bool) -> Vec<LivenessStep> {
    let pose_options = ["left", "right", "up", "down"];
    let phrase_options = [
        "secure systems stay safe",
        "trust but verify always",
        "liveness check in progress",
        "identity matters today",
        "security starts with you",
    ];

    let pick_pose = pose_options[(Uuid::new_v4().as_u128() % pose_options.len() as u128) as usize];
    let pick_phrase =
        phrase_options[(Uuid::new_v4().as_u128() % phrase_options.len() as u128) as usize];

    let mut steps = vec![
        LivenessStep {
            step_id: Uuid::new_v4().to_string(),
            step_type: LivenessStepType::HeadPose,
            prompt: Some(format!("Turn your head {}", pick_pose)),
            pose_direction: Some(pick_pose.to_string()),
            time_limit_ms: Some(DEFAULT_STEP_TIME_LIMIT_MS),
        },
        LivenessStep {
            step_id: Uuid::new_v4().to_string(),
            step_type: LivenessStepType::Blink,
            prompt: Some("Blink twice".to_string()),
            pose_direction: None,
            time_limit_ms: Some(DEFAULT_STEP_TIME_LIMIT_MS),
        },
    ];

    if !accessibility_mode {
        steps.push(LivenessStep {
            step_id: Uuid::new_v4().to_string(),
            step_type: LivenessStepType::Phrase,
            prompt: Some(pick_phrase.to_string()),
            pose_direction: None,
            time_limit_ms: Some(DEFAULT_STEP_TIME_LIMIT_MS),
        });
    }

    steps
}

pub(super) fn signing_payload(challenge: &LivenessChallenge) -> String {
    let step_parts: Vec<String> = challenge
        .steps
        .iter()
        .map(|step| {
            format!(
                "{}:{}:{}:{}:{}",
                step.step_id,
                step.step_type.as_str(),
                step.pose_direction.as_deref().unwrap_or(""),
                step.prompt.as_deref().unwrap_or(""),
                step.time_limit_ms.unwrap_or(DEFAULT_STEP_TIME_LIMIT_MS)
            )
        })
        .collect();

    format!(
        "{}|{}|{}|{}|{}|{}|{}|{}|{}",
        challenge.challenge_id,
        challenge.nonce,
        challenge.session_id,
        challenge.issued_at,
        challenge.expires_at,
        challenge.preferred_mode.as_str(),
        challenge.allow_network_fallback,
        challenge.accessibility_mode,
        step_parts.join(";")
    )
}

pub(super) fn sign_challenge(challenge: &LivenessChallenge, secret: &[u8]) -> String {
    let key = hmac::Key::new(hmac::HMAC_SHA256, secret);
    let payload = signing_payload(challenge);
    let tag = hmac::sign(&key, payload.as_bytes());
    URL_SAFE_NO_PAD.encode(tag.as_ref())
}

pub(crate) fn verify_challenge_signature(challenge: &LivenessChallenge, secret: &[u8]) -> bool {
    let expected = sign_challenge(challenge, secret);
    expected == challenge.signature
}

pub(crate) async fn validate_liveness_challenge(
    challenge: &LivenessChallenge,
    expected_session_id: Option<&str>,
    state: &AppState,
) -> AppResult<()> {
    if !verify_challenge_signature(challenge, state.liveness_secret.as_slice()) {
        return Err(AppError::Verification(
            "Invalid liveness challenge signature".to_string(),
        ));
    }

    let issued_at = DateTime::parse_from_rfc3339(&challenge.issued_at)
        .map_err(|e| AppError::Verification(format!("Invalid issued_at: {}", e)))?
        .with_timezone(&Utc);
    let expires_at = DateTime::parse_from_rfc3339(&challenge.expires_at)
        .map_err(|e| AppError::Verification(format!("Invalid expires_at: {}", e)))?
        .with_timezone(&Utc);

    let now = Utc::now();
    if now > expires_at {
        return Err(AppError::Verification(
            "Liveness challenge expired".to_string(),
        ));
    }

    if now + Duration::seconds(MAX_CLOCK_SKEW_SECS) < issued_at {
        return Err(AppError::Verification(
            "Liveness capture started before challenge issuance".to_string(),
        ));
    }

    if expires_at < issued_at {
        return Err(AppError::Verification(
            "Liveness challenge expiry precedes issuance".to_string(),
        ));
    }

    if let Some(expected_session) = expected_session_id {
        if expected_session != challenge.session_id {
            return Err(AppError::Verification(
                "Session mismatch for liveness challenge".to_string(),
            ));
        }
    }

    // Replay protection: challenge must be issued by this instance and unused
    let recorded = state
        .consume_liveness_challenge(&challenge.challenge_id)
        .await
        .ok_or_else(|| {
            AppError::Verification("Liveness challenge not recognized or already used".to_string())
        })?;

    if recorded.nonce != challenge.nonce || recorded.session_id != challenge.session_id {
        return Err(AppError::Verification(
            "Liveness challenge metadata mismatch".to_string(),
        ));
    }

    if recorded.expires_at < now {
        return Err(AppError::Verification(
            "Liveness challenge expired in storage".to_string(),
        ));
    }

    Ok(())
}

pub(super) async fn run_face_match(_request: &VerifyRequest) -> AppResult<FaceMatchPayload> {
    Err(AppError::Verification(
        "No production face-match provider is configured".to_string(),
    ))
}

pub(super) async fn evaluate_pad(
    _challenge: &LivenessChallenge,
    pad_config: &PadProviderConfig,
) -> AppResult<LivenessResultPayload> {
    match pad_config.provider {
        PadProviderType::Mock => Err(AppError::Verification(
            "Mock PAD cannot authorize a production verification".to_string(),
        )),
        PadProviderType::SelfHosted => {
            if pad_config.endpoint.is_none() {
                return Err(AppError::Verification(
                    "PAD self-hosted endpoint not configured".to_string(),
                ));
            }
            Err(AppError::Verification(
                "Self-hosted PAD adapter is not implemented".to_string(),
            ))
        }
        PadProviderType::Commercial => Err(AppError::Verification(
            "Commercial PAD adapter is not implemented".to_string(),
        )),
    }
}
