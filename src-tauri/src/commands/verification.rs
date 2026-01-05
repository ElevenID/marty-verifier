//! Credential verification commands

use std::collections::HashMap;

use base64::engine::general_purpose::STANDARD as BASE64_STANDARD;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use chrono::{DateTime, Duration, Utc};
use marty_secure_storage::{OpenBadgeVerificationMethod, TrustAnchorType};
use marty_verification::chip_io::{verify_from_reader, MockPassportReader};
use marty_verification::open_badges::{
    detect_version as detect_open_badges_version, verify_ob2_json, verify_ob3_json_async,
    DocumentStore, OpenBadgesVersion,
};
use marty_verification::trust_anchor::CscaRegistry;
use marty_verification::verification::emrtd::{verify_emrtd, SecurityObject};
use ring::hmac;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use tauri::State;
use uuid::Uuid;
use x509_cert::der::Decode;
use x509_cert::Certificate;

use crate::config::{
    LivenessRetentionConfig, OpenBadgeTrustPolicy, PadProviderConfig, PadProviderType,
};
use crate::error::{AppError, AppResult};
use crate::state::{AppState, StoredLivenessChallenge};

// Re-export storage type
pub use marty_secure_storage::VerificationHistoryEntry;

const DEFAULT_CHALLENGE_TTL_SECS: i64 = 60;
const MAX_CLOCK_SKEW_SECS: i64 = 5;
const DEFAULT_STEP_TIME_LIMIT_MS: i32 = 5000;

#[derive(Debug, Clone, Copy, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum LivenessMode {
    #[default]
    Unknown,
    OnDevice,
    Network,
}

impl LivenessMode {
    fn as_str(&self) -> &'static str {
        match self {
            LivenessMode::Unknown => "unknown",
            LivenessMode::OnDevice => "on_device",
            LivenessMode::Network => "network",
        }
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum LivenessStepType {
    #[default]
    Unknown,
    HeadPose,
    Blink,
    Phrase,
}

impl LivenessStepType {
    fn as_str(&self) -> &'static str {
        match self {
            LivenessStepType::Unknown => "unknown",
            LivenessStepType::HeadPose => "head_pose",
            LivenessStepType::Blink => "blink",
            LivenessStepType::Phrase => "phrase",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LivenessStep {
    pub step_id: String,
    pub step_type: LivenessStepType,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub prompt: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pose_direction: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub time_limit_ms: Option<i32>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LivenessChallenge {
    pub challenge_id: String,
    pub nonce: String,
    pub session_id: String,
    pub steps: Vec<LivenessStep>,
    pub issued_at: String,
    pub expires_at: String,
    pub signature: String,
    pub preferred_mode: LivenessMode,
    pub allow_network_fallback: bool,
    pub accessibility_mode: bool,
}

#[derive(Debug, Deserialize)]
pub struct IssueLivenessChallengeRequest {
    #[serde(default)]
    pub session_id: Option<String>,
    #[serde(default)]
    pub preferred_mode: Option<LivenessMode>,
    #[serde(default)]
    pub allow_network_fallback: Option<bool>,
    #[serde(default)]
    pub accessibility_mode: Option<bool>,
    #[serde(default)]
    pub ttl_seconds: Option<i64>,
}

#[derive(Debug, Serialize)]
pub struct IssueLivenessChallengeResponse {
    pub challenge: LivenessChallenge,
}

#[cfg(feature = "biometrics")]
impl From<LivenessChallenge> for marty_biometrics::LivenessChallenge {
    fn from(value: LivenessChallenge) -> Self {
        marty_biometrics::LivenessChallenge {
            challenge_id: value.challenge_id,
            nonce: value.nonce,
            session_id: value.session_id,
            steps: value.steps.into_iter().map(|s| s.into()).collect(),
            issued_at: value.issued_at,
            expires_at: value.expires_at,
            signature: value.signature,
            preferred_mode: Some(value.preferred_mode.into()),
            allow_network_fallback: value.allow_network_fallback,
            accessibility_mode: value.accessibility_mode,
        }
    }
}

#[cfg(feature = "biometrics")]
impl From<LivenessStep> for marty_biometrics::LivenessStep {
    fn from(step: LivenessStep) -> Self {
        marty_biometrics::LivenessStep {
            step_id: step.step_id,
            step_type: step.step_type.into(),
            prompt: step.prompt,
            pose_direction: step.pose_direction,
            time_limit_ms: step.time_limit_ms.map(|v| v as u32),
        }
    }
}

#[cfg(feature = "biometrics")]
impl From<LivenessMode> for marty_biometrics::LivenessMode {
    fn from(mode: LivenessMode) -> Self {
        match mode {
            LivenessMode::OnDevice => marty_biometrics::LivenessMode::OnDevice,
            LivenessMode::Network => marty_biometrics::LivenessMode::Network,
            LivenessMode::Unknown => marty_biometrics::LivenessMode::Unknown,
        }
    }
}

#[cfg(feature = "biometrics")]
impl From<LivenessStepType> for marty_biometrics::LivenessStepType {
    fn from(step: LivenessStepType) -> Self {
        match step {
            LivenessStepType::HeadPose => marty_biometrics::LivenessStepType::HeadPose,
            LivenessStepType::Blink => marty_biometrics::LivenessStepType::Blink,
            LivenessStepType::Phrase => marty_biometrics::LivenessStepType::Phrase,
            LivenessStepType::Unknown => marty_biometrics::LivenessStepType::Unknown,
        }
    }
}

/// Issue a signed liveness challenge (nonce + steps) for the UI to present.
#[tauri::command]
pub async fn issue_liveness_challenge(
    request: IssueLivenessChallengeRequest,
    state: State<'_, AppState>,
) -> AppResult<IssueLivenessChallengeResponse> {
    let accessibility_mode = request.accessibility_mode.unwrap_or(false);
    let ttl_secs = request
        .ttl_seconds
        .unwrap_or(DEFAULT_CHALLENGE_TTL_SECS)
        .clamp(15, 120);

    let issued_at = Utc::now();
    let expires_at = issued_at + Duration::seconds(ttl_secs);

    let preferred_mode = request.preferred_mode.unwrap_or(LivenessMode::OnDevice);

    let challenge = LivenessChallenge {
        challenge_id: Uuid::new_v4().to_string(),
        nonce: Uuid::new_v4().to_string(),
        session_id: request
            .session_id
            .unwrap_or_else(|| Uuid::new_v4().to_string()),
        steps: build_liveness_steps(accessibility_mode),
        issued_at: issued_at.to_rfc3339(),
        expires_at: expires_at.to_rfc3339(),
        signature: String::new(),
        preferred_mode,
        allow_network_fallback: request.allow_network_fallback.unwrap_or(true),
        accessibility_mode,
    };

    let signature = sign_challenge(&challenge, state.liveness_secret.as_slice());
    let mut signed_challenge = challenge;
    signed_challenge.signature = signature.clone();

    state
        .record_liveness_challenge(StoredLivenessChallenge {
            challenge_id: signed_challenge.challenge_id.clone(),
            nonce: signed_challenge.nonce.clone(),
            session_id: signed_challenge.session_id.clone(),
            issued_at,
            expires_at,
            used: false,
        })
        .await;

    Ok(IssueLivenessChallengeResponse {
        challenge: signed_challenge,
    })
}

fn build_liveness_steps(accessibility_mode: bool) -> Vec<LivenessStep> {
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

fn signing_payload(challenge: &LivenessChallenge) -> String {
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

fn sign_challenge(challenge: &LivenessChallenge, secret: &[u8]) -> String {
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

/// Verification request
#[derive(Debug, Deserialize)]
pub struct VerifyRequest {
    /// Credential type: "mdl", "emrtd", "oid4vp", "sd-jwt", "dtc", "open-badge"
    pub credential_type: String,
    /// Raw credential data (base64, JWT, or QR content)
    pub credential_data: String,
    /// Whether to use NFC/reader (eMRTD only)
    #[serde(default)]
    pub use_nfc: bool,
    /// Optional liveness challenge to validate (nonce + signed steps)
    #[serde(default)]
    pub liveness_challenge: Option<LivenessChallenge>,
    /// Require liveness validation for this verification
    #[serde(default)]
    pub require_liveness: bool,
    /// Preferred liveness mode (on-device vs network)
    #[serde(default)]
    #[allow(dead_code)]
    pub preferred_liveness_mode: Option<LivenessMode>,
    /// Allow network fallback if preferred mode unavailable
    #[serde(default)]
    #[allow(dead_code)]
    pub allow_network_fallback: Option<bool>,
    /// Accessibility adjustments (pose/blink only)
    #[serde(default)]
    #[allow(dead_code)]
    pub accessibility_mode: Option<bool>,
    /// Request retention of a short audit clip
    #[serde(default)]
    pub retain_audit_clip: Option<bool>,
    /// TTL for audit clip retention (seconds)
    #[serde(default)]
    pub audit_clip_ttl_seconds: Option<u32>,
    /// Session identifier to bind challenge to caller
    #[serde(default)]
    pub session_id: Option<String>,
    /// Perform face match (optional)
    #[serde(default)]
    pub perform_face_match: bool,
    /// Reference image for face match (base64)
    #[serde(default)]
    #[allow(dead_code)]
    pub reference_image: Option<String>,
    /// Probe image for face match (base64)
    #[serde(default)]
    #[allow(dead_code)]
    pub probe_image: Option<String>,
    /// Optional threshold for face match
    #[serde(default)]
    pub face_threshold: Option<f32>,
    /// Verification policy to apply
    #[allow(dead_code)]
    pub policy: Option<VerificationPolicy>,
}

/// Verification policy configuration
#[allow(dead_code)]
#[derive(Debug, Deserialize)]
pub struct VerificationPolicy {
    /// Required claims to verify
    pub required_claims: Vec<String>,
    /// Age threshold for age verification (e.g., 21 for alcohol)
    pub age_threshold: Option<u8>,
    /// Allow expired credentials within grace period
    pub allow_expired_grace: bool,
}

/// Verification result
#[derive(Debug, Serialize)]
pub struct VerificationResult {
    /// Verification ID for tracking
    pub verification_id: String,
    /// Overall verification status
    pub status: VerificationStatus,
    /// Credential type verified
    pub credential_type: String,
    /// Issuer information
    pub issuer: Option<IssuerInfo>,
    /// Disclosed claims (per policy)
    pub disclosed_claims: serde_json::Value,
    /// Trust chain status
    pub trust_chain: TrustChainStatus,
    /// Revocation status
    pub revocation_status: RevocationStatus,
    /// Timestamp of verification
    pub verified_at: String,
    /// Warnings (e.g., offline verification, cached CRL)
    pub warnings: Vec<String>,
    /// eMRTD-specific details (present when credential_type == "emrtd")
    #[serde(skip_serializing_if = "Option::is_none")]
    pub emrtd_details: Option<EmrtdDetails>,
    /// DTC-specific details (present when credential_type == "dtc")
    #[serde(skip_serializing_if = "Option::is_none")]
    pub dtc_details: Option<DtcDetails>,
    /// Open Badge verification details (present when credential_type == "open-badge")
    #[serde(skip_serializing_if = "Option::is_none")]
    pub open_badge_details: Option<OpenBadgeDetails>,
    /// Liveness evaluation (if performed)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub liveness: Option<LivenessResultPayload>,
    /// Face match summary (if performed)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub face_match: Option<FaceMatchPayload>,
}

/// eMRTD verification details.
#[derive(Debug, Serialize)]
pub struct EmrtdDetails {
    pub dsc_chain_status: String,
    pub sod_signature_status: String,
    pub dg_hash_status: String,
    pub errors: Vec<String>,
}

/// DTC verification details.
#[derive(Debug, Serialize)]
pub struct DtcDetails {
    pub checks: Vec<VerificationCheck>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub dtc_type: Option<i32>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub errors: Vec<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub error_codes: Vec<String>,
}

/// Verification check result.
#[derive(Debug, Serialize)]
pub struct VerificationCheck {
    pub check_name: String,
    pub passed: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub details: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error_code: Option<String>,
}

/// Open Badge verification details.
#[derive(Debug, Serialize)]
pub struct OpenBadgeDetails {
    pub version: String,
    pub errors: Vec<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub error_codes: Vec<String>,
    pub warnings: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub normalized: Option<Value>,
}

/// Liveness result payload
#[derive(Debug, Serialize, Clone)]
pub struct LivenessResultPayload {
    pub passed: bool,
    pub fused_score: f32,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mode_used: Option<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub errors: Vec<String>,
}

/// Face match payload (placeholder)
#[derive(Debug, Serialize, Clone)]
pub struct FaceMatchPayload {
    pub verified: bool,
    pub similarity: f32,
    pub threshold: f32,
    pub provider: String,
}

async fn run_face_match(request: &VerifyRequest) -> AppResult<FaceMatchPayload> {
    let threshold = request.face_threshold.unwrap_or(0.75);

    #[cfg(feature = "biometrics")]
    {
        use marty_biometrics::{BiometricProvider, FaceVerificationRequest};

        let reference_image = request.reference_image.clone().unwrap_or_default();
        let probe_image = request.probe_image.clone().unwrap_or_default();
        if reference_image.is_empty() || probe_image.is_empty() {
            return Err(AppError::Verification(
                "Face match requested but reference/probe images missing".to_string(),
            ));
        }

        let provider = BiometricProvider::mock();
        let result = provider
            .verify(FaceVerificationRequest {
                reference_image,
                probe_image,
                threshold: Some(threshold),
                liveness_challenge: None,
                preferred_liveness_mode: None,
                allow_network_fallback: false,
                accessibility_mode: false,
                retain_audit_clip: false,
                audit_clip_ttl_seconds: None,
            })
            .await
            .map_err(|e| AppError::Verification(e.to_string()))?;

        return Ok(FaceMatchPayload {
            verified: result.verified,
            similarity: result.similarity,
            threshold: result.threshold,
            provider: result.provider,
        });
    }

    #[cfg(not(feature = "biometrics"))]
    {
        // Placeholder when biometrics feature is disabled
        Ok(FaceMatchPayload {
            verified: true,
            similarity: 0.9,
            threshold,
            provider: "placeholder".to_string(),
        })
    }
}

async fn evaluate_pad(
    challenge: &LivenessChallenge,
    pad_config: &PadProviderConfig,
) -> AppResult<LivenessResultPayload> {
    match pad_config.provider {
        PadProviderType::Mock => Ok(LivenessResultPayload {
            passed: true,
            fused_score: 0.85,
            mode_used: Some(challenge.preferred_mode.as_str().to_string()),
            errors: vec!["PAD provider set to mock".to_string()],
        }),
        PadProviderType::SelfHosted => {
            if pad_config.endpoint.is_none() {
                return Err(AppError::Verification(
                    "PAD self-hosted endpoint not configured".to_string(),
                ));
            }
            // TODO: Implement HTTP call to self-hosted PAD endpoint with media + challenge metadata
            Ok(LivenessResultPayload {
                passed: true,
                fused_score: 0.82,
                mode_used: Some("self_hosted".to_string()),
                errors: vec!["Self-hosted PAD placeholder; implement HTTP adapter".to_string()],
            })
        }
        PadProviderType::Commercial => {
            // TODO: Implement commercial PAD adapter (e.g., Rekognition/iProov) using endpoint/api_key
            Ok(LivenessResultPayload {
                passed: true,
                fused_score: 0.88,
                mode_used: Some("commercial".to_string()),
                errors: vec!["Commercial PAD placeholder; implement API client".to_string()],
            })
        }
    }
}

/// Verification status enum
#[derive(Debug, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum VerificationStatus {
    /// Credential is valid
    Valid,
    /// Credential is invalid
    Invalid,
    /// Credential verification failed
    Failed,
    /// Credential expired
    #[allow(dead_code)]
    Expired,
    /// Credential revoked
    #[allow(dead_code)]
    Revoked,
    /// Verification pending (offline, queued)
    #[allow(dead_code)]
    Pending,
}

/// Issuer information
#[derive(Debug, Serialize)]
pub struct IssuerInfo {
    /// Issuer name
    pub name: Option<String>,
    /// Issuer country/jurisdiction
    pub jurisdiction: Option<String>,
    /// Issuer certificate subject
    pub subject: Option<String>,
}

/// Trust chain verification status
#[derive(Debug, Serialize)]
pub struct TrustChainStatus {
    /// Trust chain is valid
    pub valid: bool,
    /// Chain type: "iaca", "csca", "did", "x509"
    pub chain_type: String,
    /// Trust anchor used
    pub trust_anchor: Option<String>,
    /// Verification was performed offline with cached anchors
    pub offline_verified: bool,
}

/// Revocation status
#[derive(Debug, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RevocationStatus {
    /// Not revoked
    Valid,
    /// Revoked
    Revoked,
    /// Revocation check failed (offline)
    Unknown,
    /// Using cached revocation data
    CachedValid,
}

/// Verify a credential
#[tauri::command]
pub async fn verify_credential(
    request: VerifyRequest,
    state: State<'_, AppState>,
) -> AppResult<VerificationResult> {
    tracing::info!(
        credential_type = %request.credential_type,
        "Verifying credential"
    );

    // Check if feature is licensed
    state.check_feature(&request.credential_type).await?;
    state.license.check_verification_limit().await?;
    state.license.increment_verification_count().await?;

    let mut liveness_result: Option<LivenessResultPayload> = None;
    if request.require_liveness || request.liveness_challenge.is_some() {
        let challenge = request.liveness_challenge.as_ref().ok_or_else(|| {
            AppError::Verification(
                "Liveness challenge required when liveness detection is requested".to_string(),
            )
        })?;

        validate_liveness_challenge(challenge, request.session_id.as_deref(), state.inner())
            .await?;

        tracing::info!(
            liveness_challenge_id = %challenge.challenge_id,
            session_id = %challenge.session_id,
            preferred_mode = %challenge.preferred_mode.as_str(),
            allow_network_fallback = challenge.allow_network_fallback,
            accessibility_mode = challenge.accessibility_mode,
            "Liveness challenge validated"
        );

        let pad_config = state.config.read().await.pad_config.clone();
        liveness_result = Some(
            evaluate_pad(challenge, &pad_config)
                .await
                .unwrap_or_else(|e| LivenessResultPayload {
                    passed: false,
                    fused_score: 0.0,
                    mode_used: Some(challenge.preferred_mode.as_str().to_string()),
                    errors: vec![format!("PAD unavailable: {}", e.to_string())],
                }),
        );
    }

    // Clamp audit clip TTL based on config
    let (audit_clip_ttl, liveness_retention_cfg) = {
        let cfg = state.config.read().await;
        let lr: LivenessRetentionConfig = cfg.liveness_retention.clone();
        let requested = request
            .audit_clip_ttl_seconds
            .unwrap_or(lr.default_audit_clip_ttl_seconds);
        (requested.min(lr.max_audit_clip_ttl_seconds), lr)
    };

    tracing::debug!(
        retain_audit_clip = request.retain_audit_clip,
        requested_ttl = request.audit_clip_ttl_seconds,
        applied_ttl = audit_clip_ttl,
        encrypt_temp_media = liveness_retention_cfg.encrypt_temp_media,
        "Liveness retention parameters applied"
    );

    // Generate verification ID
    let verification_id = uuid::Uuid::new_v4().to_string();

    // Check online status
    let is_online = *state.is_online.read().await;

    let credential_type = request.credential_type.to_lowercase();
    let mut result = match credential_type.as_str() {
        "emrtd" => verify_emrtd_payload(&request, &state, is_online).await?,
        "dtc" => verify_dtc_payload(&request, is_online).await?,
        "open-badge" => verify_open_badge_payload(&request, &state, is_online).await?,
        _ => placeholder_success(&request, is_online),
    };

    // Face match (placeholder/mock)
    if request.perform_face_match {
        match run_face_match(&request).await {
            Ok(payload) => {
                if !payload.verified {
                    result.status = VerificationStatus::Invalid;
                    result
                        .warnings
                        .push("Face match failed (placeholder)".to_string());
                }
                result.face_match = Some(payload);
            }
            Err(e) => {
                result
                    .warnings
                    .push(format!("Face match unavailable: {}", e.to_string()));
            }
        }
    }

    // Attach liveness placeholder if evaluated
    if liveness_result.is_some() {
        if liveness_result
            .as_ref()
            .map(|lr| !lr.passed)
            .unwrap_or(false)
        {
            result.status = VerificationStatus::Invalid;
        }
        result.liveness = liveness_result;
        result.warnings.push(
            "Liveness evaluated via PAD adapter; replace mock when provider is ready".to_string(),
        );
    }

    // Store verification event
    state
        .storage
        .store_verification_event(&verification_id, &request.credential_type, &result.status)
        .await?;

    // TODO: Queue for reporting if enabled and reporter is added to AppState

    Ok(result)
}

async fn verify_dtc_payload(
    request: &VerifyRequest,
    is_online: bool,
) -> AppResult<VerificationResult> {
    let raw = parse_json_input(&request.credential_data, "DTC")?;
    let payload = build_dtc_verify_payload(&raw)?;
    let verify_json = serde_json::to_string(&payload)?;
    let verify_result = marty_verification::dtc::verify_dtc_json(&verify_json)
        .map_err(|e| AppError::Verification(format!("DTC verification failed: {}", e)))?;
    let value: Value = serde_json::from_str(&verify_result).map_err(|e| {
        AppError::Verification(format!("Invalid DTC verify response: {}", e))
    })?;

    let is_valid = value
        .get("is_valid")
        .and_then(|v| v.as_bool())
        .unwrap_or(false);

    let dtc_data = value.get("dtc_data").cloned().unwrap_or(Value::Null);
    let checks = parse_dtc_checks(&value);
    let dtc_errors = extract_string_list(value.get("errors"));
    let dtc_error_codes = extract_string_list(value.get("error_codes"));
    let dtc_type = dtc_data
        .get("dtc_type")
        .and_then(|v| v.as_i64())
        .map(|v| v as i32);

    let issuer = dtc_data
        .get("issuing_authority")
        .and_then(|v| v.as_str())
        .map(|s| s.to_string());

    let mut warnings = Vec::new();
    if let Some(msg) = value.get("error_message").and_then(|v| v.as_str()) {
        if !msg.is_empty() {
            warnings.push(msg.to_string());
        }
    }
    if !is_online {
        warnings.push("Verified offline with local DTC trust data".to_string());
    }

    let trust_chain_valid = dtc_trust_chain_valid(&checks);
    let revocation_status = if dtc_data
        .get("is_revoked")
        .and_then(|v| v.as_bool())
        .unwrap_or(false)
    {
        RevocationStatus::Revoked
    } else {
        RevocationStatus::Unknown
    };

    Ok(VerificationResult {
        verification_id: uuid::Uuid::new_v4().to_string(),
        status: if is_valid {
            VerificationStatus::Valid
        } else {
            VerificationStatus::Invalid
        },
        credential_type: request.credential_type.clone(),
        issuer: issuer.map(|issuer| IssuerInfo {
            name: Some(issuer.clone()),
            jurisdiction: Some(issuer),
            subject: None,
        }),
        disclosed_claims: build_dtc_claims(&dtc_data),
        trust_chain: TrustChainStatus {
            valid: trust_chain_valid,
            chain_type: "x509".to_string(),
            trust_anchor: None,
            offline_verified: !is_online,
        },
        revocation_status,
        verified_at: chrono::Utc::now().to_rfc3339(),
        warnings,
        emrtd_details: None,
        dtc_details: Some(DtcDetails {
            checks,
            dtc_type,
            errors: dtc_errors,
            error_codes: dtc_error_codes,
        }),
        open_badge_details: None,
        liveness: None,
        face_match: None,
    })
}

async fn verify_open_badge_payload(
    request: &VerifyRequest,
    state: &AppState,
    is_online: bool,
) -> AppResult<VerificationResult> {
    let raw = parse_json_input(&request.credential_data, "Open Badge")?;
    let (version, mut req_value) = build_open_badge_request(&raw)?;

    let trust_config = state.config.read().await.open_badge_trust.clone();
    let trusted_methods = state.storage.get_open_badge_keys().await?;
    let mut store = build_trusted_open_badge_store(&trusted_methods);
    let mut warnings = Vec::new();

    if store.is_empty() {
        warnings.push("Open Badge trust store is empty".to_string());
    }

    let method_id = extract_open_badge_method_id(&req_value, version);
    if let Some(method_id) = method_id.as_deref() {
        if !open_badge_method_trusted(&store, method_id) {
            warnings.push(format!(
                "Open Badge verification method not trusted: {}",
                method_id
            ));
            if matches!(trust_config.policy, OpenBadgeTrustPolicy::FailClosed) {
                return Ok(build_open_badge_result(
                    request,
                    version,
                    false,
                    warnings,
                    Some(method_id.to_string()),
                    None,
                    is_online,
                    OpenBadgeDetails {
                        version: open_badge_version_label(version).to_string(),
                        errors: vec!["Verification method not trusted".to_string()],
                        error_codes: Vec::new(),
                        warnings: Vec::new(),
                        normalized: None,
                    },
                ));
            }
        }
    }

    let request_store = extract_open_badge_document_store(&req_value)?;
    let allow_untrusted_keys = matches!(trust_config.policy, OpenBadgeTrustPolicy::FailOpen);
    merge_open_badge_store(&mut store, &request_store, allow_untrusted_keys);

    if let Value::Object(ref mut obj) = req_value {
        obj.insert(
            "document_store".to_string(),
            serde_json::to_value(&store)?,
        );
    }

    let req_json = serde_json::to_string(&req_value)?;
    let verify_result_json = match version {
        OpenBadgesVersion::V2 => verify_ob2_json(&req_json)
            .map_err(|e| AppError::Verification(format!("Open Badge verify failed: {}", e)))?,
        OpenBadgesVersion::V3 => verify_ob3_json_async(&req_json)
            .await
            .map_err(|e| AppError::Verification(format!("Open Badge verify failed: {}", e)))?,
        OpenBadgesVersion::Unknown => {
            return Err(AppError::Verification(
                "Unable to detect Open Badge version".to_string(),
            ))
        }
    };

    let result_value: Value = serde_json::from_str(&verify_result_json).map_err(|e| {
        AppError::Verification(format!("Invalid Open Badge verify response: {}", e))
    })?;

    let valid = result_value
        .get("valid")
        .and_then(|v| v.as_bool())
        .unwrap_or(false);
    let errors = extract_string_list(result_value.get("errors"));
    let error_codes = extract_string_list(result_value.get("error_codes"));
    let warnings_from_result = extract_string_list(result_value.get("warnings"));
    let normalized = result_value.get("normalized").cloned();

    let details = OpenBadgeDetails {
        version: result_value
            .get("version")
            .and_then(|v| v.as_str())
            .unwrap_or(open_badge_version_label(version))
            .to_string(),
        errors,
        error_codes,
        warnings: warnings_from_result,
        normalized: normalized.clone(),
    };

    let (stale_warning, stale_critical) =
        open_badge_trust_staleness(state, &trust_config).await?;
    if let Some(msg) = stale_warning {
        warnings.push(msg);
    }
    if let Some(msg) = stale_critical {
        warnings.push(msg);
    }

    Ok(build_open_badge_result(
        request,
        version,
        valid,
        warnings,
        method_id,
        normalized,
        is_online,
        details,
    ))
}

fn parse_json_input(input: &str, label: &str) -> AppResult<Value> {
    serde_json::from_str(input).map_err(|e| {
        AppError::Verification(format!("{} credential data must be JSON: {}", label, e))
    })
}

fn build_dtc_verify_payload(raw: &Value) -> AppResult<Value> {
    let mut payload = match raw.get("dtc_data") {
        Some(dtc) => dtc.clone(),
        None => raw.clone(),
    };

    if !payload.is_object() {
        return Err(AppError::Verification(
            "DTC payload must be a JSON object".to_string(),
        ));
    }

    if let Value::Object(ref mut obj) = payload {
        for key in ["signer_public_key_pem", "trust_anchors_pem", "certificate_chain_pem"] {
            if let Some(value) = raw.get(key) {
                obj.insert(key.to_string(), value.clone());
            }
        }
    }

    Ok(payload)
}

fn parse_dtc_checks(value: &Value) -> Vec<VerificationCheck> {
    value
        .get("verification_results")
        .and_then(|v| v.as_array())
        .map(|items| {
            items
                .iter()
                .filter_map(|item| {
                    let check_name = item.get("check_name")?.as_str()?.to_string();
                    let passed = item.get("passed").and_then(|v| v.as_bool()).unwrap_or(false);
                    let details = item
                        .get("details")
                        .and_then(|v| v.as_str())
                        .map(|s| s.to_string());
                    let error_code = item
                        .get("error_code")
                        .and_then(|v| v.as_str())
                        .map(|s| s.to_string());
                    Some(VerificationCheck {
                        check_name,
                        passed,
                        details,
                        error_code,
                    })
                })
                .collect()
        })
        .unwrap_or_default()
}

fn dtc_trust_chain_valid(checks: &[VerificationCheck]) -> bool {
    let chain_ok = checks
        .iter()
        .find(|c| c.check_name == "TrustChain")
        .map(|c| c.passed)
        .unwrap_or(true);
    let signer_ok = checks
        .iter()
        .find(|c| c.check_name == "SignerKeyMatchesCertificate")
        .map(|c| c.passed)
        .unwrap_or(true);
    chain_ok && signer_ok
}

fn build_dtc_claims(dtc_data: &Value) -> Value {
    let mut claims = serde_json::Map::new();

    if let Some(id) = dtc_data.get("dtc_id").and_then(|v| v.as_str()) {
        claims.insert("dtc_id".to_string(), Value::String(id.to_string()));
    }
    if let Some(num) = dtc_data.get("passport_number").and_then(|v| v.as_str()) {
        claims.insert("passport_number".to_string(), Value::String(num.to_string()));
    }
    if let Some(value) = dtc_data.get("issue_date").and_then(|v| v.as_str()) {
        claims.insert("issue_date".to_string(), Value::String(value.to_string()));
    }
    if let Some(value) = dtc_data.get("expiry_date").and_then(|v| v.as_str()) {
        claims.insert("expiry_date".to_string(), Value::String(value.to_string()));
    }
    if let Some(value) = dtc_data.get("dtc_type").and_then(|v| v.as_i64()) {
        claims.insert("dtc_type".to_string(), Value::Number(value.into()));
    }

    if let Some(details) = dtc_data.get("personal_details").and_then(|v| v.as_object()) {
        for (key, field) in [
            ("first_name", "first_name"),
            ("last_name", "last_name"),
            ("date_of_birth", "date_of_birth"),
            ("nationality", "nationality"),
        ] {
            if let Some(value) = details.get(field).and_then(|v| v.as_str()) {
                claims.insert(key.to_string(), Value::String(value.to_string()));
            }
        }
    }

    Value::Object(claims)
}

fn build_open_badge_request(raw: &Value) -> AppResult<(OpenBadgesVersion, Value)> {
    if let Value::Object(obj) = raw {
        if let Some(assertion) = obj.get("assertion") {
            let version = detect_open_badges_version(assertion);
            return Ok((version, raw.clone()));
        }
        if let Some(credential) = obj.get("credential") {
            let version = detect_open_badges_version(credential);
            return Ok((version, raw.clone()));
        }
    }

    let version = detect_open_badges_version(raw);
    match version {
        OpenBadgesVersion::V2 => Ok((version, serde_json::json!({ "assertion": raw }))),
        OpenBadgesVersion::V3 => Ok((version, serde_json::json!({ "credential": raw }))),
        OpenBadgesVersion::Unknown => Err(AppError::Verification(
            "Unable to detect Open Badge version".to_string(),
        )),
    }
}

fn build_trusted_open_badge_store(
    methods: &[OpenBadgeVerificationMethod],
) -> DocumentStore {
    let mut store = DocumentStore::new();
    for method in methods {
        store.insert(method.id.clone(), method.document.clone());
    }
    store
}

fn extract_open_badge_method_id(
    request: &Value,
    version: OpenBadgesVersion,
) -> Option<String> {
    match version {
        OpenBadgesVersion::V2 => request
            .get("assertion")
            .and_then(extract_ob2_method_id),
        OpenBadgesVersion::V3 => request
            .get("credential")
            .and_then(extract_ob3_method_id),
        OpenBadgesVersion::Unknown => None,
    }
}

fn extract_ob2_method_id(assertion: &Value) -> Option<String> {
    let verification = assertion.get("verification")?;
    extract_ob2_verification_value(verification)
}

fn extract_ob2_verification_value(value: &Value) -> Option<String> {
    match value {
        Value::String(_) => extract_method_id_from_value(value),
        Value::Object(obj) => {
            if let Some(creator) = obj.get("creator") {
                return extract_method_id_from_value(creator);
            }
            if let Some(method) = obj.get("verificationMethod") {
                return extract_method_id_from_value(method);
            }
            None
        }
        Value::Array(items) => items.iter().find_map(extract_ob2_verification_value),
        _ => None,
    }
}

fn extract_ob3_method_id(credential: &Value) -> Option<String> {
    let proof = credential.get("proof")?;
    extract_ob3_proof_method_id(proof)
}

fn extract_ob3_proof_method_id(value: &Value) -> Option<String> {
    match value {
        Value::String(_) => extract_method_id_from_value(value),
        Value::Object(obj) => {
            if let Some(method) = obj.get("verificationMethod") {
                if let Some(found) = extract_method_id_from_value(method) {
                    return Some(found);
                }
            }
            if let Some(creator) = obj.get("creator") {
                if let Some(found) = extract_method_id_from_value(creator) {
                    return Some(found);
                }
            }
            obj.get("id")
                .and_then(|v| v.as_str())
                .map(|s| s.to_string())
        }
        Value::Array(items) => items.iter().find_map(extract_ob3_proof_method_id),
        _ => None,
    }
}

fn extract_method_id_from_value(value: &Value) -> Option<String> {
    match value {
        Value::String(method) => Some(method.to_string()),
        Value::Object(obj) => obj
            .get("id")
            .and_then(|v| v.as_str())
            .map(|s| s.to_string()),
        _ => None,
    }
}

fn extract_open_badge_document_store(request: &Value) -> AppResult<DocumentStore> {
    match request.get("document_store") {
        None | Some(Value::Null) => Ok(DocumentStore::new()),
        Some(Value::Object(map)) => {
            let mut store = DocumentStore::new();
            for (key, value) in map {
                store.insert(key.clone(), value.clone());
            }
            Ok(store)
        }
        _ => Err(AppError::Verification(
            "document_store must be a JSON object".to_string(),
        )),
    }
}

fn merge_open_badge_store(
    base: &mut DocumentStore,
    supplemental: &DocumentStore,
    allow_untrusted_keys: bool,
) {
    for (key, value) in supplemental {
        if base.contains_key(key) {
            continue;
        }
        if !allow_untrusted_keys && is_open_badge_key_document(value) {
            continue;
        }
        base.insert(key.clone(), value.clone());
    }
}

fn open_badge_method_trusted(store: &DocumentStore, method_id: &str) -> bool {
    if store.contains_key(method_id) {
        return true;
    }

    if let Some((base, _)) = method_id.split_once('#') {
        if store.contains_key(base) {
            return true;
        }
    }

    false
}

fn is_open_badge_key_document(value: &Value) -> bool {
    let Some(obj) = value.as_object() else {
        return false;
    };

    obj.contains_key("publicKeyJwk")
        || obj.contains_key("publicKeyPem")
        || obj.contains_key("publicKey")
        || obj.contains_key("publicKeyBase58")
        || obj.contains_key("publicKeyMultibase")
        || obj.contains_key("verificationMethod")
}

fn extract_string_list(value: Option<&Value>) -> Vec<String> {
    value
        .and_then(|v| v.as_array())
        .map(|items| {
            items
                .iter()
                .filter_map(|item| item.as_str().map(|s| s.to_string()))
                .collect()
        })
        .unwrap_or_default()
}

async fn open_badge_trust_staleness(
    state: &AppState,
    config: &crate::config::OpenBadgeTrustConfig,
) -> AppResult<(Option<String>, Option<String>)> {
    let last_sync = state.storage.get_latest_open_badge_sync().await?;
    let Some(last_sync) = last_sync else {
        return Ok((None, None));
    };

    let age_hours = (Utc::now() - last_sync).num_minutes() as f64 / 60.0;

    if age_hours > config.stale_critical_hours as f64 {
        return Ok((
            None,
            Some(format!(
                "Open Badge trust list critically stale ({:.1} hours old)",
                age_hours
            )),
        ));
    }

    if age_hours > config.stale_warning_hours as f64 {
        return Ok((
            Some(format!(
                "Open Badge trust list stale ({:.1} hours old)",
                age_hours
            )),
            None,
        ));
    }

    Ok((None, None))
}

fn open_badge_version_label(version: OpenBadgesVersion) -> &'static str {
    match version {
        OpenBadgesVersion::V2 => "2.0",
        OpenBadgesVersion::V3 => "3.0",
        OpenBadgesVersion::Unknown => "unknown",
    }
}

fn build_open_badge_result(
    request: &VerifyRequest,
    version: OpenBadgesVersion,
    valid: bool,
    warnings: Vec<String>,
    trust_anchor: Option<String>,
    normalized: Option<Value>,
    is_online: bool,
    details: OpenBadgeDetails,
) -> VerificationResult {
    let disclosed_claims = normalized
        .as_ref()
        .map(open_badge_claims_from_normalized)
        .unwrap_or_else(|| serde_json::json!({}));
    let issuer = normalized
        .as_ref()
        .and_then(open_badge_issuer_from_normalized);

    VerificationResult {
        verification_id: uuid::Uuid::new_v4().to_string(),
        status: if valid {
            VerificationStatus::Valid
        } else {
            VerificationStatus::Invalid
        },
        credential_type: request.credential_type.clone(),
        issuer,
        disclosed_claims,
        trust_chain: TrustChainStatus {
            valid,
            chain_type: match version {
                OpenBadgesVersion::V2 | OpenBadgesVersion::V3 => "did".to_string(),
                OpenBadgesVersion::Unknown => "unknown".to_string(),
            },
            trust_anchor,
            offline_verified: !is_online,
        },
        revocation_status: RevocationStatus::Unknown,
        verified_at: chrono::Utc::now().to_rfc3339(),
        warnings,
        emrtd_details: None,
        dtc_details: None,
        open_badge_details: Some(details),
        liveness: None,
        face_match: None,
    }
}

fn open_badge_claims_from_normalized(normalized: &Value) -> Value {
    let mut claims = serde_json::Map::new();

    for (key, field) in [
        ("assertion_id", "assertion_id"),
        ("badge_id", "badge_id"),
        ("issuer_id", "issuer_id"),
        ("credential_id", "credential_id"),
        ("issuer", "issuer"),
    ] {
        if let Some(value) = normalized.get(field).and_then(|v| v.as_str()) {
            claims.insert(key.to_string(), Value::String(value.to_string()));
        }
    }

    if let Some(recipient) = normalized.get("recipient") {
        if let Some(identity) = recipient.get("identity").and_then(|v| v.as_str()) {
            claims.insert("recipient".to_string(), Value::String(identity.to_string()));
        } else if let Some(value) = recipient.as_str() {
            claims.insert("recipient".to_string(), Value::String(value.to_string()));
        }
    }

    if let Some(subject) = normalized.get("credential_subject") {
        if let Some(subject_id) = subject.get("id").and_then(|v| v.as_str()) {
            claims.insert("subject_id".to_string(), Value::String(subject_id.to_string()));
        }
    }

    Value::Object(claims)
}

fn open_badge_issuer_from_normalized(normalized: &Value) -> Option<IssuerInfo> {
    let issuer_value = normalized
        .get("issuer")
        .or_else(|| normalized.get("issuer_id"))?;

    issuer_value.as_str().map(|issuer| IssuerInfo {
        name: Some(issuer.to_string()),
        jurisdiction: None,
        subject: None,
    })
}

/// Placeholder response for non-eMRTD types (to be replaced as other types are wired up).
fn placeholder_success(request: &VerifyRequest, is_online: bool) -> VerificationResult {
    VerificationResult {
        verification_id: uuid::Uuid::new_v4().to_string(),
        status: VerificationStatus::Valid,
        credential_type: request.credential_type.clone(),
        issuer: Some(IssuerInfo {
            name: Some("Example Issuer".to_string()),
            jurisdiction: Some("US".to_string()),
            subject: None,
        }),
        disclosed_claims: serde_json::json!({
            "given_name": "John",
            "family_name": "Doe",
            "age_over_21": true
        }),
        trust_chain: TrustChainStatus {
            valid: true,
            chain_type: "iaca".to_string(),
            trust_anchor: Some("US-CA".to_string()),
            offline_verified: !is_online,
        },
        revocation_status: if is_online {
            RevocationStatus::Valid
        } else {
            RevocationStatus::CachedValid
        },
        verified_at: chrono::Utc::now().to_rfc3339(),
        warnings: if is_online {
            vec![]
        } else {
            vec!["Verified offline with cached trust anchors".to_string()]
        },
        emrtd_details: None,
        dtc_details: None,
        open_badge_details: None,
        liveness: None,
        face_match: None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn sample_challenge() -> LivenessChallenge {
        LivenessChallenge {
            challenge_id: "challenge-1".to_string(),
            nonce: "nonce-1".to_string(),
            session_id: "session-1".to_string(),
            steps: vec![LivenessStep {
                step_id: "step-1".to_string(),
                step_type: LivenessStepType::HeadPose,
                prompt: Some("Turn left".to_string()),
                pose_direction: Some("left".to_string()),
                time_limit_ms: Some(5000),
            }],
            issued_at: Utc::now().to_rfc3339(),
            expires_at: (Utc::now() + Duration::seconds(30)).to_rfc3339(),
            signature: String::new(),
            preferred_mode: LivenessMode::OnDevice,
            allow_network_fallback: true,
            accessibility_mode: false,
        }
    }

    #[test]
    fn sign_and_verify_round_trip() {
        let secret = b"secret";
        let mut challenge = sample_challenge();
        challenge.signature = sign_challenge(&challenge, secret);

        assert!(verify_challenge_signature(&challenge, secret));
    }

    #[test]
    fn tampered_challenge_fails_signature() {
        let secret = b"secret";
        let mut challenge = sample_challenge();
        challenge.signature = sign_challenge(&challenge, secret);

        // Tamper with nonce
        let mut tampered = challenge.clone();
        tampered.nonce = "wrong".to_string();

        assert!(!verify_challenge_signature(&tampered, secret));
    }

    #[test]
    fn open_badge_request_auto_detects_versions() {
        let ob2 = json!({
            "@context": "https://w3id.org/openbadges/v2",
            "type": "Assertion"
        });
        let (version, request) = build_open_badge_request(&ob2).expect("ob2 request");
        assert_eq!(version, OpenBadgesVersion::V2);
        assert!(request.get("assertion").is_some());

        let ob3 = json!({
            "@context": "https://purl.imsglobal.org/spec/ob/v3p0/context.json",
            "type": ["OpenBadgeCredential"]
        });
        let (version, request) = build_open_badge_request(&ob3).expect("ob3 request");
        assert_eq!(version, OpenBadgesVersion::V3);
        assert!(request.get("credential").is_some());
    }

    #[test]
    fn open_badge_store_filters_untrusted_keys() {
        let mut base = DocumentStore::new();
        base.insert(
            "trusted-key".to_string(),
            json!({ "publicKeyJwk": { "kty": "OKP", "crv": "Ed25519", "x": "abc" } }),
        );

        let mut supplemental = DocumentStore::new();
        supplemental.insert(
            "untrusted-key".to_string(),
            json!({ "publicKeyJwk": { "kty": "OKP", "crv": "Ed25519", "x": "def" } }),
        );
        supplemental.insert("badge".to_string(), json!({ "id": "badge-1" }));

        merge_open_badge_store(&mut base, &supplemental, false);

        assert!(base.contains_key("trusted-key"));
        assert!(base.contains_key("badge"));
        assert!(!base.contains_key("untrusted-key"));
    }

    #[test]
    fn extract_open_badge_method_id_from_ob2_creator() {
        let request = json!({
            "assertion": {
                "verification": { "creator": "https://issuer.example.org/keys/1" }
            }
        });
        let method =
            extract_open_badge_method_id(&request, OpenBadgesVersion::V2).expect("method id");
        assert_eq!(method, "https://issuer.example.org/keys/1");
    }

    #[test]
    fn extract_open_badge_method_id_from_proof() {
        let request = json!({
            "credential": {
                "proof": { "verificationMethod": "did:example:issuer#key-1" }
            }
        });
        let method =
            extract_open_badge_method_id(&request, OpenBadgesVersion::V3).expect("method id");
        assert_eq!(method, "did:example:issuer#key-1");
    }

    #[test]
    fn open_badge_method_trusted_with_did_document() {
        let mut store = DocumentStore::new();
        store.insert(
            "did:example:issuer".to_string(),
            json!({ "verificationMethod": [{ "id": "did:example:issuer#key-1" }] }),
        );

        assert!(open_badge_method_trusted(
            &store,
            "did:example:issuer#key-1"
        ));
    }
}

#[derive(Debug, Deserialize)]
struct EmrtdPayload {
    /// Base64-encoded EF.SOD
    sod_base64: String,
    /// Map of DG names (e.g., "DG1") to base64-encoded contents
    data_groups: HashMap<String, String>,
    /// Optional country hint (ISO 3166)
    country: Option<String>,
}

async fn verify_emrtd_payload(
    request: &VerifyRequest,
    state: &AppState,
    is_online: bool,
) -> AppResult<VerificationResult> {
    // NFC-only mode with no payload currently not implemented
    if request.use_nfc && request.credential_data.trim().is_empty() {
        return Err(AppError::Verification(
            "NFC read requested but no reader integration is configured yet. Provide an eMRTD payload or disable use_nfc.".to_string(),
        ));
    }

    let payload: EmrtdPayload = serde_json::from_str(&request.credential_data)
        .map_err(|e| AppError::Verification(format!("Invalid eMRTD payload JSON: {}", e)))?;

    let sod_bytes = BASE64_STANDARD
        .decode(payload.sod_base64.as_bytes())
        .map_err(|e| AppError::Verification(format!("Invalid SOD base64: {}", e)))?;

    // Build security object from SOD
    let security_object = SecurityObject::from_sod_der(&sod_bytes, payload.country.clone())
        .map_err(|e| {
            AppError::Verification(format!("Failed to parse SOD for verification: {}", e))
        })?;

    // Decode DGs
    let mut dg_map: HashMap<u8, Vec<u8>> = HashMap::new();
    for (dg_name, b64) in payload.data_groups {
        let num = dg_name
            .trim_start_matches("DG")
            .parse::<u8>()
            .map_err(|_| AppError::Verification(format!("Invalid data group name: {}", dg_name)))?;
        let dg_bytes = BASE64_STANDARD.decode(b64.as_bytes()).map_err(|e| {
            AppError::Verification(format!("Invalid base64 for {}: {}", dg_name, e))
        })?;
        dg_map.insert(num, dg_bytes);
    }

    // Build CSCA registry from secure storage
    let registry = build_csca_registry(&state).await?;

    // NFC path: route through reader abstraction to exercise chip I/O flow.
    let verification = if request.use_nfc {
        let reader =
            MockPassportReader::new(sod_bytes.clone(), dg_map.clone(), payload.country.clone());
        verify_from_reader(&reader, &registry)
    } else {
        // Build security object from SOD
        let security_object = SecurityObject::from_sod_der(&sod_bytes, payload.country.clone())
            .map_err(|e| {
                AppError::Verification(format!("Failed to parse SOD for verification: {}", e))
            })?;
        verify_emrtd(&security_object, &dg_map, &registry)
    };

    let status = if verification.verified {
        VerificationStatus::Valid
    } else if verification
        .errors
        .iter()
        .any(|e| e.contains("expired") || e.contains("not yet valid"))
    {
        VerificationStatus::Invalid
    } else {
        VerificationStatus::Failed
    };

    let warnings = if is_online {
        Vec::new()
    } else {
        vec!["Verified offline with cached CSCA anchors".to_string()]
    };

    let issuer_subject = security_object
        .signer_certificate
        .certificate
        .tbs_certificate
        .subject
        .to_string();

    let country = security_object
        .signer_certificate
        .country
        .or(verification.country.clone());

    Ok(VerificationResult {
        verification_id: request
            .credential_data
            .get(0..12)
            .map(|s| s.to_string())
            .unwrap_or_else(|| uuid::Uuid::new_v4().to_string()),
        status,
        credential_type: request.credential_type.clone(),
        issuer: Some(IssuerInfo {
            name: Some("Passport Issuer".to_string()),
            jurisdiction: country.clone(),
            subject: Some(issuer_subject),
        }),
        disclosed_claims: serde_json::json!({ "document_type": "passport" }),
        trust_chain: TrustChainStatus {
            valid: verification.dsc_chain_status
                == marty_verification::verification::emrtd::ChainStatus::Valid,
            chain_type: "csca".to_string(),
            trust_anchor: country,
            offline_verified: !is_online,
        },
        revocation_status: RevocationStatus::Unknown,
        verified_at: chrono::Utc::now().to_rfc3339(),
        warnings: if verification.errors.is_empty() {
            warnings
        } else {
            let mut w = warnings;
            w.extend(verification.errors.clone());
            w
        },
        emrtd_details: Some(EmrtdDetails {
            dsc_chain_status: format!("{:?}", verification.dsc_chain_status),
            sod_signature_status: format!("{:?}", verification.sod_signature_status),
            dg_hash_status: format!("{:?}", verification.dg_hash_status),
            errors: verification.errors,
        }),
        dtc_details: None,
        open_badge_details: None,
        liveness: None,
        face_match: None,
    })
}

async fn build_csca_registry(state: &AppState) -> AppResult<CscaRegistry> {
    let anchors = state
        .storage
        .get_trust_anchors(TrustAnchorType::Csca, None)
        .await?;

    let mut registry = CscaRegistry::new();
    for anchor in anchors {
        let cert = Certificate::from_der(&anchor.certificate_der).map_err(|e| {
            AppError::Verification(format!(
                "Failed to parse CSCA certificate {}: {}",
                anchor.id, e
            ))
        })?;
        registry
            .add_country_csca(&anchor.jurisdiction, cert)
            .map_err(|e| AppError::Verification(e.to_string()))?;
    }

    Ok(registry)
}

/// Get verification history
#[tauri::command]
pub async fn get_verification_history(
    limit: Option<usize>,
    state: State<'_, AppState>,
) -> AppResult<Vec<VerificationHistoryEntry>> {
    let limit = limit.unwrap_or(100);
    let history = state.storage.get_verification_history(limit).await?;
    Ok(history)
}
