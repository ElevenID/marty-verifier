//! Credential verification commands

use std::collections::{HashMap, HashSet};
use std::io::Read;

use base64::engine::general_purpose::STANDARD as BASE64_STANDARD;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use chrono::{DateTime, Duration, Utc};
use marty_app_storage::{OpenBadgeVerificationMethod, TrustAnchorType};
#[cfg(feature = "oid4vp")]
use marty_oid4vci::verifier::{PresentationDefinition, PresentationSubmission, VerificationEngine};
use marty_secure_storage::{OpenBadgeTrustRecord, TrustPackageProvenance};
use marty_verification::chip_io::{verify_from_reader, MockPassportReader};
use marty_verification::open_badges::{
    detect_version as detect_open_badges_version, verify_ob2_json, verify_ob3_json_async,
    verify_ob3_json_with_status_lists_async, ArtifactProvenance, AuthenticatedStatusList,
    DocumentStore, OpenBadgesVersion, StatusAuthorityProvenance,
};
use marty_verification::policy::{IssuerConstraintChecker, PresentationPolicy};
use marty_verification::trust_anchor::CscaRegistry;
use marty_verification::verification::emrtd::{verify_emrtd, SecurityObject};
use ring::hmac;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use tauri::State;
use tokio::sync::OnceCell;
use uuid::Uuid;
use x509_cert::der::Decode;
use x509_cert::Certificate;

use crate::config::{
    LivenessRetentionConfig, OpenBadgeTrustConfig, OpenBadgeTrustPolicy, PadProviderConfig,
    PadProviderType,
};
use crate::error::{AppError, AppResult};
use crate::state::{AppState, StoredLivenessChallenge};

// Re-export storage type
pub use marty_app_storage::VerificationHistoryEntry;

const DEFAULT_CHALLENGE_TTL_SECS: i64 = 60;
const MAX_CLOCK_SKEW_SECS: i64 = 5;
const DEFAULT_STEP_TIME_LIMIT_MS: i32 = 5000;
const MAX_OPEN_BADGE_TRUST_AGE_HOURS: u32 = 48;
const MAX_OPEN_BADGE_STATUS_LIST_SIGNED_AGE_HOURS: u32 = 24;
const MAX_OPEN_BADGE_STATUS_IRI_CHARS: usize = 4096;

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
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub status_checks: Vec<OpenBadgeStatusEvidence>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub normalized: Option<Value>,
}

/// Authenticated Open Badge status evidence projected from marty-core.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct OpenBadgeStatusEvidence {
    pub status_list_url: String,
    pub status_issuer: String,
    pub status_purpose: String,
    pub status_list_index: u64,
    pub status_size: u8,
    pub status_value: u16,
    pub outcome: OpenBadgeStatusEvidenceOutcome,
    pub checked_at: DateTime<Utc>,
    pub retrieved_at: DateTime<Utc>,
    pub fresh_until: DateTime<Utc>,
    pub authority_provenance: OpenBadgeStatusAuthorityEvidence,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum OpenBadgeStatusEvidenceOutcome {
    Good,
    Revoked,
    Suspended,
    Message,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct OpenBadgeStatusAuthorityEvidence {
    pub trust_profile: OpenBadgeArtifactEvidence,
    pub resolver: OpenBadgeArtifactEvidence,
    pub software: OpenBadgeArtifactEvidence,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct OpenBadgeArtifactEvidence {
    pub id: String,
    pub version: String,
    pub digest: String,
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

/// Face match payload.
#[derive(Debug, Serialize, Clone)]
pub struct FaceMatchPayload {
    pub verified: bool,
    pub similarity: f32,
    pub threshold: f32,
    pub provider: String,
}

async fn run_face_match(_request: &VerifyRequest) -> AppResult<FaceMatchPayload> {
    Err(AppError::Verification(
        "No production face-match provider is configured".to_string(),
    ))
}

async fn evaluate_pad(
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

/// Verification status enum
#[derive(Debug, Serialize, PartialEq)]
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
#[derive(Debug, Serialize, PartialEq)]
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

/// Load cached presentation policies from storage
async fn load_cached_policies(state: &AppState) -> AppResult<Vec<PresentationPolicy>> {
    // Get current deployment profile ID from runtime config
    let profile_id = state.runtime_config.get_deployment_profile_id().await;

    // Load policies for this profile (or all if no profile set)
    state
        .storage
        .get_presentation_policies(profile_id.as_deref())
        .await
        .map_err(|e| crate::error::AppError::Config(e.to_string()))
}

/// Evaluate policy constraints for a verification request
async fn evaluate_policy_constraints(
    request: &VerifyRequest,
    issuer_id: &str,
    trust_verified: bool,
    state: &AppState,
) -> AppResult<Vec<String>> {
    let mut violations = Vec::new();

    // Load cached policies
    let policies = load_cached_policies(state).await?;

    // Find applicable policy by credential type
    let policy = policies.iter().find(|p| {
        p.accepted_credential_types
            .contains(&request.credential_type)
    });

    if let Some(policy) = policy {
        // Check issuer constraints
        let issuer_checker =
            IssuerConstraintChecker::new(policy.trust_profile_id.as_ref(), &policy.allowed_issuers);
        let issuer_result = issuer_checker.check_issuer(issuer_id, trust_verified);
        if let Some(msg) = issuer_result.violation_message() {
            violations.push(msg.to_string());
        }

        // Check trust profile requirement
        if policy.trust_profile_id.is_some() && !trust_verified {
            violations.push("Credential does not meet trust profile requirements".to_string());
        }

        // Check freshness if specified
        if let Some(max_age_seconds) = policy.freshness_requirements.max_credential_age_seconds {
            violations.push(format!(
                "Credential freshness could not be established (max age: {} seconds)",
                max_age_seconds
            ));
        }
    }

    Ok(violations)
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

    // Check provider-neutral capability policy and hardware support.
    state.check_feature(&request.credential_type).await?;

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
        "oid4vp" | "sd-jwt" => {
            #[cfg(feature = "oid4vp")]
            {
                verify_oid4vp_payload(&request, &state, is_online).await?
            }
            #[cfg(not(feature = "oid4vp"))]
            {
                unsupported_result(&request, "OID4VP support is not included in this build")
            }
        }
        _ => unsupported_result(&request, "Unsupported credential type"),
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
                result.status = VerificationStatus::Failed;
                result
                    .warnings
                    .push(format!("Face match unavailable: {}", e));
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

    // Evaluate policy constraints if credential verified
    if result.status == VerificationStatus::Valid {
        // Extract issuer_id from result (placeholder for now)
        let issuer_id = result
            .issuer
            .as_ref()
            .and_then(|i| i.subject.as_deref())
            .unwrap_or("unknown");

        let trust_verified = result.trust_chain.valid;

        match evaluate_policy_constraints(&request, issuer_id, trust_verified, state.inner()).await
        {
            Ok(violations) if !violations.is_empty() => {
                result.status = VerificationStatus::Invalid;
                result.warnings.extend(violations);
            }
            Ok(_) => {}
            Err(error) => {
                result.status = VerificationStatus::Failed;
                result
                    .warnings
                    .push(format!("Policy evaluation unavailable: {error}"));
            }
        }
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
    let value: Value = serde_json::from_str(&verify_result)
        .map_err(|e| AppError::Verification(format!("Invalid DTC verify response: {}", e)))?;

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
    ensure_production_open_badge_policy(&trust_config.policy)?;
    let now = Utc::now();
    let trust_records = state.trust_storage.get_open_badge_trust_records().await?;
    let mut warnings = Vec::new();
    let (governed_store, rejected_records) =
        build_governed_open_badge_store(&trust_records, now, trust_config.stale_critical_hours);

    if rejected_records > 0 {
        warnings.push(format!(
            "Rejected {rejected_records} Open Badge trust record(s) with invalid lifecycle or binding metadata"
        ));
    }

    if governed_store.documents.is_empty() {
        warnings.push("Governed Open Badge trust store is empty".to_string());
    }

    let method_id = extract_open_badge_method_id(&req_value, version);
    let method_trusted =
        open_badge_request_method_trusted(&governed_store.documents, method_id.as_deref());
    if !method_trusted {
        let (warning, error) = match method_id.as_deref() {
            Some(_) => (
                "Open Badge verification method is not trusted".to_string(),
                "Verification method not trusted",
            ),
            None => (
                "Open Badge verification method is missing".to_string(),
                "Verification method missing",
            ),
        };
        warnings.push(warning);
        return Ok(build_open_badge_result(
            request,
            version,
            false,
            warnings,
            None,
            None,
            is_online,
            OpenBadgeDetails {
                version: open_badge_version_label(version).to_string(),
                errors: vec![error.to_string()],
                error_codes: Vec::new(),
                warnings: Vec::new(),
                status_checks: Vec::new(),
                normalized: None,
            },
        ));
    }

    let (authenticated_status_lists, status_adapter_warnings) =
        build_authenticated_status_lists(&req_value, &governed_store, now, &trust_config).await?;
    warnings.extend(status_adapter_warnings);

    replace_open_badge_document_store(&mut req_value, &governed_store.documents)?;

    let req_json = serde_json::to_string(&req_value)?;
    let verify_result_json = match version {
        OpenBadgesVersion::V2 => verify_ob2_json(&req_json)
            .map_err(|e| AppError::Verification(format!("Open Badge verify failed: {}", e)))?,
        OpenBadgesVersion::V3 => {
            verify_ob3_json_with_status_lists_async(&req_json, &authenticated_status_lists)
                .await
                .map_err(|e| AppError::Verification(format!("Open Badge verify failed: {}", e)))?
        }
        OpenBadgesVersion::Unknown => {
            return Err(AppError::Verification(
                "Unable to detect Open Badge version".to_string(),
            ))
        }
    };

    let result_value: Value = serde_json::from_str(&verify_result_json).map_err(|e| {
        AppError::Verification(format!("Invalid Open Badge verify response: {}", e))
    })?;

    let mut valid = result_value
        .get("valid")
        .and_then(|v| v.as_bool())
        .unwrap_or(false);
    let errors = extract_string_list(result_value.get("errors"));
    let error_codes = extract_string_list(result_value.get("error_codes"));
    let warnings_from_result = extract_string_list(result_value.get("warnings"));
    let status_checks = extract_open_badge_status_evidence(&result_value)?;
    let normalized = result_value.get("normalized").cloned();

    let mut details = OpenBadgeDetails {
        version: result_value
            .get("version")
            .and_then(|v| v.as_str())
            .unwrap_or(open_badge_version_label(version))
            .to_string(),
        errors,
        error_codes,
        warnings: warnings_from_result,
        status_checks,
        normalized: normalized.clone(),
    };

    match open_badge_trust_freshness(state, &trust_config).await? {
        OpenBadgeTrustFreshness::Fresh => {}
        OpenBadgeTrustFreshness::Warning(message) => warnings.push(message),
        OpenBadgeTrustFreshness::Unavailable(message) => {
            valid = false;
            warnings.push(message);
            details
                .errors
                .push("Open Badge trust data unavailable".to_string());
        }
    }

    Ok(build_open_badge_result(
        request, version, valid, warnings, method_id, normalized, is_online, details,
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
        for key in [
            "signer_public_key_pem",
            "trust_anchors_pem",
            "certificate_chain_pem",
        ] {
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
                    let passed = item
                        .get("passed")
                        .and_then(|v| v.as_bool())
                        .unwrap_or(false);
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
    exactly_one_dtc_check_passed(checks, "TrustChain")
        && exactly_one_dtc_check_passed(checks, "SignerKeyMatchesCertificate")
}

fn exactly_one_dtc_check_passed(checks: &[VerificationCheck], check_name: &str) -> bool {
    let mut matching = checks.iter().filter(|check| check.check_name == check_name);
    match (matching.next(), matching.next()) {
        (Some(check), None) => check.passed,
        _ => false,
    }
}

fn build_dtc_claims(dtc_data: &Value) -> Value {
    let mut claims = serde_json::Map::new();

    if let Some(id) = dtc_data.get("dtc_id").and_then(|v| v.as_str()) {
        claims.insert("dtc_id".to_string(), Value::String(id.to_string()));
    }
    if let Some(num) = dtc_data.get("passport_number").and_then(|v| v.as_str()) {
        claims.insert(
            "passport_number".to_string(),
            Value::String(num.to_string()),
        );
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

#[derive(Debug, Default)]
struct GovernedOpenBadgeStore {
    documents: DocumentStore,
    provenance_by_document: HashMap<String, TrustPackageProvenance>,
}

impl GovernedOpenBadgeStore {
    fn provenance_for_method(&self, method_id: &str) -> Option<&TrustPackageProvenance> {
        if let Some(provenance) = self.provenance_by_document.get(method_id) {
            return Some(provenance);
        }

        method_id
            .split_once('#')
            .and_then(|(base, _)| self.provenance_by_document.get(base))
    }

    fn authority_documents(&self, provenance: &TrustPackageProvenance) -> DocumentStore {
        self.documents
            .iter()
            .filter(|(id, _)| self.provenance_by_document.get(*id) == Some(provenance))
            .map(|(id, document)| (id.clone(), document.clone()))
            .collect()
    }
}

fn build_governed_open_badge_store(
    records: &[OpenBadgeTrustRecord],
    now: DateTime<Utc>,
    stale_critical_hours: u32,
) -> (GovernedOpenBadgeStore, usize) {
    let mut governed = GovernedOpenBadgeStore::default();
    let mut ambiguous_ids = HashSet::new();
    let mut rejected_records = 0;

    for record in records {
        if !open_badge_governed_record_is_usable(record, now, stale_critical_hours) {
            rejected_records += 1;
            continue;
        }
        let Some(provenance) = record.provenance.as_ref() else {
            rejected_records += 1;
            continue;
        };
        let method = &record.method;

        if ambiguous_ids.contains(&method.id) {
            rejected_records += 1;
        } else if governed.documents.remove(&method.id).is_some() {
            governed.provenance_by_document.remove(&method.id);
            ambiguous_ids.insert(method.id.clone());
            rejected_records += 2;
        } else {
            governed
                .documents
                .insert(method.id.clone(), method.document.clone());
            governed
                .provenance_by_document
                .insert(method.id.clone(), provenance.clone());
        }
    }

    (governed, rejected_records)
}

fn open_badge_governed_record_is_usable(
    record: &OpenBadgeTrustRecord,
    now: DateTime<Utc>,
    stale_critical_hours: u32,
) -> bool {
    let Some(provenance) = record.provenance.as_ref() else {
        return false;
    };
    if provenance.created_at != record.method.synced_at
        || provenance.created_at > now
        || provenance.expires_at <= now
        || provenance.created_at >= provenance.expires_at
        || provenance.imported_at < provenance.created_at
        || provenance.imported_at > now
    {
        return false;
    }

    open_badge_trust_record_is_usable(&record.method, now, stale_critical_hours)
}

#[cfg(test)]
fn build_trusted_open_badge_store(
    methods: &[OpenBadgeVerificationMethod],
    now: DateTime<Utc>,
    stale_critical_hours: u32,
) -> (DocumentStore, usize) {
    let mut store = DocumentStore::new();
    let mut ambiguous_ids = HashSet::new();
    let mut rejected_records = 0;

    for method in methods {
        if !open_badge_trust_record_is_usable(method, now, stale_critical_hours) {
            rejected_records += 1;
            continue;
        }

        if ambiguous_ids.contains(&method.id) {
            rejected_records += 1;
        } else if store.remove(&method.id).is_some() {
            ambiguous_ids.insert(method.id.clone());
            rejected_records += 2;
        } else {
            store.insert(method.id.clone(), method.document.clone());
        }
    }

    (store, rejected_records)
}

fn open_badge_trust_record_is_usable(
    method: &OpenBadgeVerificationMethod,
    now: DateTime<Utc>,
    stale_critical_hours: u32,
) -> bool {
    if method.status.as_deref() != Some("active") || method.synced_at > now {
        return false;
    }

    let (Some(not_before), Some(not_after)) = (method.not_before, method.not_after) else {
        return false;
    };
    if not_before > now || not_after <= now || not_before >= not_after {
        return false;
    }

    let critical_age = Duration::hours(i64::from(
        stale_critical_hours.min(MAX_OPEN_BADGE_TRUST_AGE_HOURS),
    ));
    if critical_age <= Duration::zero()
        || now.signed_duration_since(method.synced_at) >= critical_age
    {
        return false;
    }

    let Some(document) = method.document.as_object() else {
        return false;
    };
    if document.get("id").and_then(Value::as_str) != Some(method.id.as_str()) {
        return false;
    }

    let Some(controller) = method.controller.as_deref() else {
        return false;
    };
    if document.get("controller").and_then(Value::as_str) != Some(controller) {
        return false;
    }

    !contains_private_jwk(&method.document)
}

fn contains_private_jwk(value: &Value) -> bool {
    match value {
        Value::Object(object) => object.iter().any(|(key, nested)| {
            if key.starts_with("privateKey") || key == "secretKeyJwk" {
                return true;
            }

            if key == "publicKeyJwk" {
                return nested.as_object().is_none_or(|jwk| {
                    matches!(jwk.get("kty").and_then(Value::as_str), Some("oct") | None)
                        || ["d", "p", "q", "dp", "dq", "qi", "oth", "k"]
                            .iter()
                            .any(|private| jwk.contains_key(*private))
                });
            }

            contains_private_jwk(nested)
        }),
        Value::Array(items) => items.iter().any(contains_private_jwk),
        _ => false,
    }
}

fn extract_open_badge_method_id(request: &Value, version: OpenBadgesVersion) -> Option<String> {
    match version {
        OpenBadgesVersion::V2 => request.get("assertion").and_then(extract_ob2_method_id),
        OpenBadgesVersion::V3 => request.get("credential").and_then(extract_ob3_method_id),
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

static VERIFIER_SOFTWARE_PROVENANCE: OnceCell<ArtifactProvenance> = OnceCell::const_new();

async fn build_authenticated_status_lists(
    request: &Value,
    governed_store: &GovernedOpenBadgeStore,
    observed_at: DateTime<Utc>,
    config: &OpenBadgeTrustConfig,
) -> AppResult<(Vec<AuthenticatedStatusList>, Vec<String>)> {
    let status_list_urls = extract_status_list_urls(request);
    let request_store = extract_stapled_status_documents(request, &status_list_urls)?;
    if status_list_urls.is_empty() {
        return Ok((Vec::new(), Vec::new()));
    }

    let software = verifier_software_provenance().await?;
    let mut authenticated = Vec::new();
    let mut warnings = Vec::new();
    for status_list_url in status_list_urls {
        match build_authenticated_status_list(
            &status_list_url,
            &request_store,
            governed_store,
            observed_at,
            config,
            &software,
        ) {
            Ok(status_list) => authenticated.push(status_list),
            Err(reason) => warnings.push(format!(
                "A declared status list was not admitted as authenticated context: {reason}"
            )),
        }
    }

    Ok((authenticated, warnings))
}

fn extract_stapled_status_documents(
    request: &Value,
    status_list_urls: &[String],
) -> AppResult<DocumentStore> {
    let Some(value) = request.get("document_store") else {
        return Ok(DocumentStore::new());
    };
    if value.is_null() {
        return Ok(DocumentStore::new());
    }
    let Value::Object(request_store) = value else {
        return Err(AppError::Verification(
            "document_store must be a JSON object".to_string(),
        ));
    };

    Ok(status_list_urls
        .iter()
        .filter_map(|url| {
            request_store
                .get(url)
                .map(|credential| (url.clone(), credential.clone()))
        })
        .collect())
}

fn extract_status_list_urls(request: &Value) -> Vec<String> {
    let Some(status) = request
        .get("credential")
        .and_then(|credential| credential.get("credentialStatus"))
    else {
        return Vec::new();
    };
    let entries: Vec<&Value> = match status {
        Value::Array(entries) if entries.len() <= 32 => entries.iter().collect(),
        Value::Object(_) => vec![status],
        _ => return Vec::new(),
    };

    let mut seen = HashSet::new();
    entries
        .into_iter()
        .filter(|entry| {
            entry.get("type").and_then(Value::as_str) == Some("BitstringStatusListEntry")
        })
        .filter_map(|entry| {
            entry
                .get("statusListCredential")
                .and_then(Value::as_str)
                .filter(|url| {
                    !url.is_empty() && url.chars().count() <= MAX_OPEN_BADGE_STATUS_IRI_CHARS
                })
                .map(str::to_string)
        })
        .filter(|url| seen.insert(url.clone()))
        .collect()
}

fn build_authenticated_status_list(
    status_list_url: &str,
    request_store: &DocumentStore,
    governed_store: &GovernedOpenBadgeStore,
    observed_at: DateTime<Utc>,
    config: &OpenBadgeTrustConfig,
    software: &ArtifactProvenance,
) -> Result<AuthenticatedStatusList, String> {
    let credential = request_store.get(status_list_url).cloned().ok_or_else(|| {
        "the request did not staple a credential at the exact status URL".to_string()
    })?;
    let status_issuer = credential_issuer_id(&credential)
        .ok_or_else(|| "the stapled credential has no scalar issuer identifier".to_string())?;
    let status_method = extract_ob3_method_id(&credential).ok_or_else(|| {
        "the stapled credential has no scalar proof method identifier".to_string()
    })?;
    let provenance = governed_store
        .provenance_for_method(&status_method)
        .ok_or_else(|| "the status proof method is not in governed trust storage".to_string())?;
    let authority_documents = governed_store.authority_documents(provenance);
    if authority_documents.is_empty() {
        return Err("the governed package has no resolver-owned authority documents".to_string());
    }

    let valid_from = parse_status_list_time(&credential, "validFrom")?;
    let valid_until = parse_status_list_time(&credential, "validUntil")?;
    if valid_from > observed_at || valid_until <= observed_at || valid_until <= valid_from {
        return Err("the stapled credential is outside its signed validity period".to_string());
    }
    if config.status_list_max_age_hours == 0 || config.stale_critical_hours == 0 {
        return Err("status or trust freshness policy is disabled".to_string());
    }

    let status_list_max_age_hours = config
        .status_list_max_age_hours
        .min(MAX_OPEN_BADGE_STATUS_LIST_SIGNED_AGE_HOURS);
    let trust_max_age_hours = config
        .stale_critical_hours
        .min(MAX_OPEN_BADGE_TRUST_AGE_HOURS);
    let signed_age_deadline = valid_from
        .checked_add_signed(Duration::hours(i64::from(status_list_max_age_hours)))
        .ok_or_else(|| "status freshness deadline exceeds the supported range".to_string())?;
    let trust_age_deadline = provenance
        .created_at
        .checked_add_signed(Duration::hours(i64::from(trust_max_age_hours)))
        .ok_or_else(|| "trust freshness deadline exceeds the supported range".to_string())?;
    let fresh_until = [
        valid_until,
        signed_age_deadline,
        trust_age_deadline,
        provenance.expires_at,
    ]
    .into_iter()
    .min()
    .ok_or_else(|| "no status freshness deadline is available".to_string())?;
    if fresh_until <= observed_at {
        return Err("the stapled credential exceeds the configured signed-age limit".to_string());
    }

    let package_digest = format!("blake3:{}", provenance.package_digest);
    let trust_profile = ArtifactProvenance::new(
        provenance.trust_domain.clone(),
        provenance.package_version.clone(),
        package_digest.clone(),
    )?;
    let resolver = ArtifactProvenance::new(
        provenance.signer_key_id.clone(),
        provenance.sequence.to_string(),
        package_digest,
    )?;
    let authority_provenance =
        StatusAuthorityProvenance::new(trust_profile, resolver, software.clone());

    AuthenticatedStatusList::new(
        status_list_url,
        credential,
        status_issuer,
        authority_documents,
        observed_at,
        fresh_until,
        authority_provenance,
    )
}

fn credential_issuer_id(credential: &Value) -> Option<String> {
    match credential.get("issuer")? {
        Value::String(issuer) if !issuer.is_empty() => Some(issuer.clone()),
        Value::Object(issuer) => issuer
            .get("id")
            .and_then(Value::as_str)
            .filter(|id| !id.is_empty())
            .map(str::to_string),
        _ => None,
    }
}

fn parse_status_list_time(credential: &Value, field: &str) -> Result<DateTime<Utc>, String> {
    let value = credential
        .get(field)
        .and_then(Value::as_str)
        .ok_or_else(|| format!("the stapled credential is missing scalar {field}"))?;
    DateTime::parse_from_rfc3339(value)
        .map(|time| time.with_timezone(&Utc))
        .map_err(|_| format!("the stapled credential has invalid {field}"))
}

async fn verifier_software_provenance() -> AppResult<ArtifactProvenance> {
    let provenance = VERIFIER_SOFTWARE_PROVENANCE
        .get_or_try_init(|| async {
            tokio::task::spawn_blocking(compute_verifier_software_provenance)
                .await
                .map_err(|error| {
                    AppError::Verification(format!("Software provenance task failed: {error}"))
                })?
                .map_err(|error| {
                    AppError::Verification(format!("Software provenance unavailable: {error}"))
                })
        })
        .await?;
    Ok(provenance.clone())
}

fn compute_verifier_software_provenance() -> Result<ArtifactProvenance, String> {
    let executable = std::env::current_exe()
        .map_err(|error| format!("could not locate the running executable: {error}"))?;
    let mut file = std::fs::File::open(&executable)
        .map_err(|error| format!("could not read the running executable: {error}"))?;
    let mut context = ring::digest::Context::new(&ring::digest::SHA256);
    let mut buffer = [0_u8; 64 * 1024];
    loop {
        let count = file
            .read(&mut buffer)
            .map_err(|error| format!("could not hash the running executable: {error}"))?;
        if count == 0 {
            break;
        }
        context.update(&buffer[..count]);
    }
    let digest = context.finish();
    let mut digest_hex = String::with_capacity(digest.as_ref().len() * 2);
    const HEX: &[u8; 16] = b"0123456789abcdef";
    for byte in digest.as_ref() {
        digest_hex.push(HEX[usize::from(byte >> 4)] as char);
        digest_hex.push(HEX[usize::from(byte & 0x0f)] as char);
    }

    ArtifactProvenance::new(
        "marty-verifier-executable",
        env!("CARGO_PKG_VERSION"),
        format!("sha256:{digest_hex}"),
    )
}

fn merge_open_badge_offline_store(base: &mut DocumentStore, supplemental: &DocumentStore) {
    for (key, value) in supplemental {
        if base.contains_key(key) {
            continue;
        }
        base.insert(key.clone(), value.clone());
    }
}

fn replace_open_badge_document_store(
    request: &mut Value,
    trusted_store: &DocumentStore,
) -> AppResult<()> {
    let Value::Object(obj) = request else {
        return Err(AppError::Verification(
            "Open Badge verification request must be a JSON object".to_string(),
        ));
    };

    obj.insert(
        "document_store".to_string(),
        serde_json::to_value(trusted_store)?,
    );
    Ok(())
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

fn open_badge_request_method_trusted(store: &DocumentStore, method_id: Option<&str>) -> bool {
    method_id
        .map(|method_id| open_badge_method_trusted(store, method_id))
        .unwrap_or(false)
}

fn ensure_production_open_badge_policy(policy: &OpenBadgeTrustPolicy) -> AppResult<()> {
    if matches!(policy, OpenBadgeTrustPolicy::FailOpen) {
        return Err(AppError::Config(
            "Open Badge fail-open trust policy is not permitted for production verification"
                .to_string(),
        ));
    }

    Ok(())
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

fn extract_open_badge_status_evidence(result: &Value) -> AppResult<Vec<OpenBadgeStatusEvidence>> {
    match result.get("status_checks") {
        None => Ok(Vec::new()),
        Some(Value::Array(checks)) => {
            serde_json::from_value(Value::Array(checks.clone())).map_err(|error| {
                AppError::Verification(format!(
                    "Invalid authenticated Open Badge status evidence: {error}"
                ))
            })
        }
        Some(_) => Err(AppError::Verification(
            "Authenticated Open Badge status evidence must be an array".to_string(),
        )),
    }
}

fn open_badge_revocation_status(
    status_checks: &[OpenBadgeStatusEvidence],
    verification_valid: bool,
) -> RevocationStatus {
    if status_checks
        .iter()
        .any(|check| check.outcome == OpenBadgeStatusEvidenceOutcome::Revoked)
    {
        return RevocationStatus::Revoked;
    }
    if verification_valid
        && status_checks.iter().any(|check| {
            check.status_purpose == "revocation"
                && check.outcome == OpenBadgeStatusEvidenceOutcome::Good
        })
    {
        return RevocationStatus::Valid;
    }

    RevocationStatus::Unknown
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum OpenBadgeTrustFreshness {
    Fresh,
    Warning(String),
    Unavailable(String),
}

fn classify_open_badge_trust_freshness(
    last_sync: Option<DateTime<Utc>>,
    now: DateTime<Utc>,
    config: &OpenBadgeTrustConfig,
) -> OpenBadgeTrustFreshness {
    let Some(last_sync) = last_sync else {
        return OpenBadgeTrustFreshness::Unavailable(
            "Open Badge trust list has never been synchronized".to_string(),
        );
    };

    let age = now.signed_duration_since(last_sync);
    if age < Duration::zero() {
        return OpenBadgeTrustFreshness::Unavailable(
            "Open Badge trust list synchronization timestamp is in the future".to_string(),
        );
    }

    let age_hours = age.num_minutes() as f64 / 60.0;
    if age
        >= Duration::hours(i64::from(
            config
                .stale_critical_hours
                .min(MAX_OPEN_BADGE_TRUST_AGE_HOURS),
        ))
    {
        return OpenBadgeTrustFreshness::Unavailable(format!(
            "Open Badge trust list critically stale ({age_hours:.1} hours old)"
        ));
    }

    if age >= Duration::hours(i64::from(config.stale_warning_hours)) {
        return OpenBadgeTrustFreshness::Warning(format!(
            "Open Badge trust list stale ({age_hours:.1} hours old)"
        ));
    }

    OpenBadgeTrustFreshness::Fresh
}

async fn open_badge_trust_freshness(
    state: &AppState,
    config: &OpenBadgeTrustConfig,
) -> AppResult<OpenBadgeTrustFreshness> {
    let last_sync = state.trust_storage.get_latest_open_badge_sync().await?;
    Ok(classify_open_badge_trust_freshness(
        last_sync,
        Utc::now(),
        config,
    ))
}

fn open_badge_version_label(version: OpenBadgesVersion) -> &'static str {
    match version {
        OpenBadgesVersion::V2 => "2.0",
        OpenBadgesVersion::V3 => "3.0",
        OpenBadgesVersion::Unknown => "unknown",
    }
}

#[allow(clippy::too_many_arguments)]
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
    let revocation_status = open_badge_revocation_status(&details.status_checks, valid);
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
        revocation_status,
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
            claims.insert(
                "subject_id".to_string(),
                Value::String(subject_id.to_string()),
            );
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

/// Parse and verify an OID4VP credential (JWT VP or SD-JWT VP).
///
/// `credential_data` must be a JSON object with:
/// - `vp_token`               — compact JWT VP token from the wallet (required)
/// - `nonce`                  — nonce from the authorization request (required)
/// - `presentation_submission`  — wallet's descriptor mapping (optional)
/// - `presentation_definition`  — original request definition (optional; enables
///   structural validation when paired with `presentation_submission`)
#[cfg(feature = "oid4vp")]
async fn verify_oid4vp_payload(
    request: &VerifyRequest,
    state: &AppState,
    is_online: bool,
) -> AppResult<VerificationResult> {
    let raw = parse_json_input(&request.credential_data, "OID4VP")?;

    let vp_token = raw
        .get("vp_token")
        .and_then(|v| v.as_str())
        .ok_or_else(|| AppError::Verification("OID4VP payload missing 'vp_token' field".into()))?
        .to_string();

    let nonce = raw
        .get("nonce")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();

    let oid4vp_cfg = state.config.read().await.oid4vp.clone();

    // ── Online path — delegate to marty-credentials API ──────────────
    if is_online {
        if let Some(ref api_url) = oid4vp_cfg.credentials_api_url {
            return verify_oid4vp_online(
                &raw,
                &vp_token,
                &oid4vp_cfg.verifier_id,
                api_url,
                oid4vp_cfg.credentials_api_token.as_deref(),
                oid4vp_cfg.online_timeout_ms,
                request,
            )
            .await;
        }
    }

    // ── Offline path — call VerificationEngine directly ───────────────
    let engine = VerificationEngine::new(
        oid4vp_cfg.verifier_id.clone(),
        oid4vp_cfg.response_uri.clone(),
    );

    let token_result = engine.verify_vp_token(&vp_token, &nonce);

    // Optional structural check when presentation_submission + definition are both present.
    let structural_errors: Vec<String> = if token_result.valid {
        let sub_val = raw.get("presentation_submission");
        let def_val = raw.get("presentation_definition");

        if let (Some(sub_val), Some(def_val)) = (sub_val, def_val) {
            let submission: Option<PresentationSubmission> =
                serde_json::from_value(sub_val.clone()).ok();
            let definition: Option<PresentationDefinition> =
                serde_json::from_value(def_val.clone()).ok();

            if let (Some(submission), Some(definition)) = (submission, definition) {
                // Decode the VP token payload for PEX field constraint evaluation.
                let vp_payload = decode_vp_token_payload(&vp_token);
                let pex_result =
                    engine.verify_presentation(&definition, &submission, vp_payload.as_ref());
                if !pex_result.valid {
                    pex_result
                        .errors
                        .into_iter()
                        .chain(
                            pex_result
                                .descriptor_results
                                .into_iter()
                                .filter(|r| !r.valid)
                                .filter_map(|r| r.error),
                        )
                        .collect()
                } else {
                    vec![]
                }
            } else {
                vec![]
            }
        } else {
            vec![]
        }
    } else {
        vec![]
    };

    let holder_presentation_valid = token_result.valid && structural_errors.is_empty();

    let mut warnings: Vec<String> = vec![];
    if !is_online {
        warnings.push("Verified offline — revocation and trust anchoring not available".into());
    }
    warnings.extend(structural_errors.iter().cloned());
    for err in &token_result.errors {
        warnings.push(format!("Verification error: {}", err));
    }

    if holder_presentation_valid {
        warnings.push(
            "Holder presentation proof is valid, but embedded credential issuer proofs, trust, and status were not verified"
                .into(),
        );
    }

    Ok(VerificationResult {
        verification_id: uuid::Uuid::new_v4().to_string(),
        status: if holder_presentation_valid {
            VerificationStatus::Failed
        } else {
            VerificationStatus::Invalid
        },
        credential_type: request.credential_type.clone(),
        issuer: None,
        disclosed_claims: serde_json::json!({}),
        trust_chain: TrustChainStatus {
            valid: false,
            chain_type: "oid4vp".to_string(),
            trust_anchor: None,
            offline_verified: !is_online,
        },
        revocation_status: RevocationStatus::Unknown,
        verified_at: chrono::Utc::now().to_rfc3339(),
        warnings,
        emrtd_details: None,
        dtc_details: None,
        open_badge_details: None,
        liveness: None,
        face_match: None,
    })
}

/// Decode the JWT payload segment of a compact VP token (or any JWT) without
/// signature verification.  Returns `None` if the string is not a valid
/// three-part compact JWT with base64url-encoded JSON in the second segment.
#[cfg(feature = "oid4vp")]
fn decode_vp_token_payload(token: &str) -> Option<serde_json::Value> {
    let mut parts = token.splitn(4, '.');
    parts.next(); // header
    let payload_b64 = parts.next()?;
    let bytes = URL_SAFE_NO_PAD.decode(payload_b64).ok()?;
    serde_json::from_slice(&bytes).ok()
}

/// Public offline OID4VP verification entry point — exposed for integration
/// tests in `tests/oid4vp_conformance.rs`.
///
/// Exercises the same offline path as [`verify_oid4vp_payload`] but accepts
/// raw JSON and explicit verifier configuration rather than `AppState`, so
/// tests can run without a Tauri runtime.
///
/// `credential_data_json` is the same JSON object format accepted by the
/// `verify_credential` Tauri command (fields: `vp_token`, `nonce`, and
/// optionally `presentation_submission` + `presentation_definition`).
///
/// `verifier_id` must match the `aud` claim in the VP token.
#[cfg(feature = "oid4vp")]
pub fn verify_oid4vp_offline(
    credential_data_json: &str,
    verifier_id: &str,
    response_uri: &str,
) -> crate::error::AppResult<VerificationResult> {
    let raw = parse_json_input(credential_data_json, "OID4VP")?;

    let vp_token = raw
        .get("vp_token")
        .and_then(|v| v.as_str())
        .ok_or_else(|| AppError::Verification("OID4VP payload missing 'vp_token' field".into()))?
        .to_string();

    let nonce = raw
        .get("nonce")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();

    let engine = VerificationEngine::new(verifier_id.to_string(), response_uri.to_string());

    let token_result = engine.verify_vp_token(&vp_token, &nonce);

    let structural_errors: Vec<String> = if token_result.valid {
        let sub_val = raw.get("presentation_submission");
        let def_val = raw.get("presentation_definition");

        if let (Some(sub_val), Some(def_val)) = (sub_val, def_val) {
            let submission: Option<PresentationSubmission> =
                serde_json::from_value(sub_val.clone()).ok();
            let definition: Option<PresentationDefinition> =
                serde_json::from_value(def_val.clone()).ok();

            if let (Some(submission), Some(definition)) = (submission, definition) {
                // Decode the VP token payload for PEX field constraint evaluation.
                let vp_payload = decode_vp_token_payload(&vp_token);
                let pex_result =
                    engine.verify_presentation(&definition, &submission, vp_payload.as_ref());
                if !pex_result.valid {
                    pex_result
                        .errors
                        .into_iter()
                        .chain(
                            pex_result
                                .descriptor_results
                                .into_iter()
                                .filter(|r| !r.valid)
                                .filter_map(|r| r.error),
                        )
                        .collect()
                } else {
                    vec![]
                }
            } else {
                vec![]
            }
        } else {
            vec![]
        }
    } else {
        vec![]
    };

    let holder_presentation_valid = token_result.valid && structural_errors.is_empty();

    let mut warnings: Vec<String> =
        vec!["Verified offline — revocation and trust anchoring not available".into()];
    warnings.extend(structural_errors.iter().cloned());
    for err in &token_result.errors {
        warnings.push(format!("Verification error: {}", err));
    }

    if holder_presentation_valid {
        warnings.push(
            "Holder presentation proof is valid, but embedded credential issuer proofs, trust, and status were not verified"
                .into(),
        );
    }

    Ok(VerificationResult {
        verification_id: uuid::Uuid::new_v4().to_string(),
        status: if holder_presentation_valid {
            VerificationStatus::Failed
        } else {
            VerificationStatus::Invalid
        },
        credential_type: "oid4vp".to_string(),
        issuer: None,
        disclosed_claims: serde_json::json!({}),
        trust_chain: TrustChainStatus {
            valid: false,
            chain_type: "oid4vp".to_string(),
            trust_anchor: None,
            offline_verified: true,
        },
        revocation_status: RevocationStatus::Unknown,
        verified_at: chrono::Utc::now().to_rfc3339(),
        warnings,
        emrtd_details: None,
        dtc_details: None,
        open_badge_details: None,
        liveness: None,
        face_match: None,
    })
}

/// Testable offline entry point for eMRTD verification (no `AppState`).
///
/// Accepts the same JSON shape as `verify_credential` for `credential_type == "emrtd"`:
/// ```json
/// { "sod_base64": "<base64 SOD DER>", "data_groups": {"DG1": "<b64>"}, "country": "DEU" }
/// ```
///
/// Uses an **empty** CSCA registry (no trust anchors loaded), so chain validation will
/// return `ChainStatus::Invalid` on any real credential.  This is intentional — the
/// function is designed for testing JSON parsing, error paths, and `VerificationResult`
/// shape without a running database or Tauri runtime.
pub fn verify_emrtd_offline(
    credential_data_json: &str,
) -> crate::error::AppResult<VerificationResult> {
    let payload: EmrtdPayload = serde_json::from_str(credential_data_json)
        .map_err(|e| AppError::Verification(format!("Invalid eMRTD payload JSON: {}", e)))?;

    if payload.sod_base64.trim().is_empty() {
        return Err(AppError::Verification(
            "eMRTD payload missing or empty sod_base64".to_string(),
        ));
    }

    let sod_bytes = BASE64_STANDARD
        .decode(payload.sod_base64.as_bytes())
        .map_err(|e| AppError::Verification(format!("Invalid SOD base64: {}", e)))?;

    let security_object = SecurityObject::from_sod_der(&sod_bytes, payload.country.clone())
        .map_err(|e| AppError::Verification(format!("Failed to parse SOD: {}", e)))?;

    let mut dg_map: HashMap<u8, Vec<u8>> = HashMap::new();
    for (dg_name, b64) in payload.data_groups {
        let num = dg_name
            .trim_start_matches("DG")
            .parse::<u8>()
            .map_err(|_| AppError::Verification(format!("Invalid data group name: {}", dg_name)))?;
        if num == 0 {
            return Err(AppError::Verification(format!(
                "Invalid data group name: {} (DG0 is not defined in ICAO 9303)",
                dg_name
            )));
        }
        let dg_bytes = BASE64_STANDARD.decode(b64.as_bytes()).map_err(|e| {
            AppError::Verification(format!("Invalid base64 for {}: {}", dg_name, e))
        })?;
        dg_map.insert(num, dg_bytes);
    }

    // Empty registry — chain will show Invalid, but all other fields are populated
    let registry = CscaRegistry::new();
    let verification = verify_emrtd(&security_object, &dg_map, &registry);

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
        verification_id: uuid::Uuid::new_v4().to_string(),
        status,
        credential_type: "emrtd".to_string(),
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
            offline_verified: true,
        },
        revocation_status: RevocationStatus::Unknown,
        verified_at: chrono::Utc::now().to_rfc3339(),
        warnings: {
            let mut w = vec!["Verified offline with empty CSCA registry".to_string()];
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

/// Testable offline entry point for DTC verification (no `AppState`).
///
/// Accepts the same JSON shape as `verify_credential` for `credential_type == "dtc"`.
/// Unlike the Tauri command path, this function is synchronous and requires no
/// app state, making it suitable for unit and integration tests.
pub fn verify_dtc_offline(
    credential_data_json: &str,
) -> crate::error::AppResult<VerificationResult> {
    let raw = parse_json_input(credential_data_json, "DTC")?;
    let payload = build_dtc_verify_payload(&raw)?;
    let verify_json = serde_json::to_string(&payload)?;
    let verify_result = marty_verification::dtc::verify_dtc_json(&verify_json)
        .map_err(|e| AppError::Verification(format!("DTC verification failed: {}", e)))?;
    let value: Value = serde_json::from_str(&verify_result)
        .map_err(|e| AppError::Verification(format!("Invalid DTC verify response: {}", e)))?;

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
    warnings.push("Verified offline with local DTC trust data".to_string());

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
        credential_type: "dtc".to_string(),
        issuer: issuer.map(|i| IssuerInfo {
            name: Some(i.clone()),
            jurisdiction: Some(i),
            subject: None,
        }),
        disclosed_claims: build_dtc_claims(&dtc_data),
        trust_chain: TrustChainStatus {
            valid: trust_chain_valid,
            chain_type: "x509".to_string(),
            trust_anchor: None,
            offline_verified: true,
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

/// Testable offline entry point for Open Badge verification (no `AppState`).
///
/// Uses an empty trusted-key store and the `FailOpen` policy so that badges
/// with embedded key documents can be verified without a running database.
/// Useful for testing JSON parsing, version detection, and `VerificationResult`
/// shape without Tauri/storage plumbing.
pub async fn verify_open_badge_offline(
    credential_data_json: &str,
) -> crate::error::AppResult<VerificationResult> {
    let raw = parse_json_input(credential_data_json, "Open Badge")?;
    let (version, mut req_value) = build_open_badge_request(&raw)?;

    // Empty store + explicit offline merge so embedded documents are accepted.
    let mut store = DocumentStore::new();

    let request_store = extract_open_badge_document_store(&req_value)?;
    merge_open_badge_offline_store(&mut store, &request_store);
    replace_open_badge_document_store(&mut req_value, &store)?;

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
    let status_checks = extract_open_badge_status_evidence(&result_value)?;
    let normalized = result_value.get("normalized").cloned();

    let version_label = result_value
        .get("version")
        .and_then(|v| v.as_str())
        .unwrap_or(open_badge_version_label(version))
        .to_string();

    let details = OpenBadgeDetails {
        version: version_label,
        errors,
        error_codes,
        warnings: warnings_from_result,
        status_checks: status_checks.clone(),
        normalized: normalized.clone(),
    };

    let method_id = extract_open_badge_method_id(&req_value, version);
    let disclosed_claims = normalized
        .as_ref()
        .map(open_badge_claims_from_normalized)
        .unwrap_or_else(|| serde_json::json!({}));
    let issuer = normalized
        .as_ref()
        .and_then(open_badge_issuer_from_normalized);

    Ok(VerificationResult {
        verification_id: uuid::Uuid::new_v4().to_string(),
        status: if valid {
            VerificationStatus::Valid
        } else {
            VerificationStatus::Invalid
        },
        credential_type: "open-badge".to_string(),
        issuer,
        disclosed_claims,
        trust_chain: TrustChainStatus {
            valid,
            chain_type: match version {
                OpenBadgesVersion::V2 | OpenBadgesVersion::V3 => "did".to_string(),
                OpenBadgesVersion::Unknown => "unknown".to_string(),
            },
            trust_anchor: method_id,
            offline_verified: true,
        },
        revocation_status: open_badge_revocation_status(&status_checks, valid),
        verified_at: chrono::Utc::now().to_rfc3339(),
        warnings: vec!["Verified offline — empty trust store".to_string()],
        emrtd_details: None,
        dtc_details: None,
        open_badge_details: Some(details),
        liveness: None,
        face_match: None,
    })
}

/// Online path: POST vp_token to marty-credentials `/v1/verification/verify`.
#[cfg(feature = "oid4vp")]
async fn verify_oid4vp_online(
    raw: &Value,
    vp_token: &str,
    verifier_did: &str,
    api_url: &str,
    api_token: Option<&str>,
    timeout_ms: u64,
    request: &VerifyRequest,
) -> AppResult<VerificationResult> {
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_millis(timeout_ms))
        .build()
        .map_err(|e| AppError::Verification(format!("HTTP client build error: {}", e)))?;

    let presentation_definition = raw.get("presentation_definition").cloned().ok_or_else(|| {
        AppError::Verification(
            "OID4VP online verification requires the original presentation_definition".to_string(),
        )
    })?;
    let has_required_descriptors = presentation_definition
        .get("input_descriptors")
        .and_then(Value::as_array)
        .is_some_and(|descriptors| !descriptors.is_empty());
    if !has_required_descriptors {
        return Err(AppError::Verification(
            "OID4VP presentation_definition must contain at least one input descriptor".to_string(),
        ));
    }

    let body = serde_json::json!({
        "organization_id": "marty-verifier",
        "presentation": vp_token,
        "presentation_definition": presentation_definition,
        "verifier_did": verifier_did,
        "trusted_issuers": [],
    });

    let mut req_builder = client
        .post(format!(
            "{}/v1/verification/verify",
            api_url.trim_end_matches('/')
        ))
        .json(&body);

    if let Some(token) = api_token {
        req_builder = req_builder.bearer_auth(token);
    }

    let response = req_builder.send().await.map_err(|e| {
        AppError::Verification(format!("OID4VP online verification request failed: {}", e))
    })?;

    if !response.status().is_success() {
        let status = response.status();
        let err_body = response.text().await.unwrap_or_default();
        return Err(AppError::Verification(format!(
            "Credentials API returned {}: {}",
            status, err_body
        )));
    }

    let api_result: Value = response
        .json()
        .await
        .map_err(|e| AppError::Verification(format!("Invalid JSON from credentials API: {}", e)))?;

    let legacy_valid = api_result
        .get("valid")
        .and_then(|v| v.as_bool())
        .unwrap_or(false);
    let overall_passed = api_result.get("overall_result").and_then(Value::as_str) == Some("PASS");
    let trust_chain_valid =
        api_result.get("trust_chain_valid").and_then(Value::as_bool) == Some(true);
    let revocation_checked = api_result
        .get("revocation_checked")
        .and_then(Value::as_bool)
        == Some(true);
    let revocation_valid = api_result
        .get("revocation_status")
        .and_then(Value::as_str)
        .is_some_and(|status| status.eq_ignore_ascii_case("VALID"));
    let valid = legacy_valid
        && overall_passed
        && trust_chain_valid
        && revocation_checked
        && revocation_valid;
    let verified_claims = if valid {
        api_result
            .get("verified_claims")
            .cloned()
            .unwrap_or(serde_json::json!({}))
    } else {
        serde_json::json!({})
    };

    let mut warnings: Vec<String> = vec![];
    if let Some(err) = api_result.get("error").and_then(|v| v.as_str()) {
        warnings.push(format!("Verification note: {}", err));
    }
    if legacy_valid && !valid {
        warnings.push(
            "Credentials API did not provide passing trust and revocation evidence".to_string(),
        );
    }

    Ok(VerificationResult {
        verification_id: uuid::Uuid::new_v4().to_string(),
        status: if valid {
            VerificationStatus::Valid
        } else if legacy_valid {
            VerificationStatus::Failed
        } else {
            VerificationStatus::Invalid
        },
        credential_type: request.credential_type.clone(),
        issuer: None,
        disclosed_claims: verified_claims,
        trust_chain: TrustChainStatus {
            valid: trust_chain_valid,
            chain_type: "oid4vp".to_string(),
            trust_anchor: None,
            offline_verified: false,
        },
        revocation_status: if revocation_checked && revocation_valid {
            RevocationStatus::Valid
        } else {
            RevocationStatus::Unknown
        },
        verified_at: chrono::Utc::now().to_rfc3339(),
        warnings,
        emrtd_details: None,
        dtc_details: None,
        open_badge_details: None,
        liveness: None,
        face_match: None,
    })
}

/// Return a non-authorizing result for an unavailable verifier capability.
fn unsupported_result(request: &VerifyRequest, reason: &str) -> VerificationResult {
    VerificationResult {
        verification_id: uuid::Uuid::new_v4().to_string(),
        status: VerificationStatus::Failed,
        credential_type: request.credential_type.clone(),
        issuer: None,
        disclosed_claims: serde_json::json!({}),
        trust_chain: TrustChainStatus {
            valid: false,
            chain_type: "unavailable".to_string(),
            trust_anchor: None,
            offline_verified: false,
        },
        revocation_status: RevocationStatus::Unknown,
        verified_at: chrono::Utc::now().to_rfc3339(),
        warnings: vec![reason.to_string()],
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
    fn unsupported_credential_result_cannot_authorize() {
        let request: VerifyRequest = serde_json::from_value(json!({
            "credential_type": "unknown-format",
            "credential_data": "opaque"
        }))
        .expect("request");

        let result = unsupported_result(&request, "Unsupported credential type");

        assert_eq!(result.status, VerificationStatus::Failed);
        assert!(!result.trust_chain.valid);
        assert_eq!(result.revocation_status, RevocationStatus::Unknown);
        assert_eq!(result.disclosed_claims, json!({}));
        assert!(result.issuer.is_none());
    }

    fn dtc_check(check_name: &str, passed: bool) -> VerificationCheck {
        VerificationCheck {
            check_name: check_name.to_string(),
            passed,
            details: None,
            error_code: None,
        }
    }

    #[test]
    fn dtc_trust_requires_both_explicit_checks() {
        assert!(!dtc_trust_chain_valid(&[]));
        assert!(!dtc_trust_chain_valid(&[dtc_check("TrustChain", true)]));
        assert!(!dtc_trust_chain_valid(&[dtc_check(
            "SignerKeyMatchesCertificate",
            true,
        )]));
    }

    #[test]
    fn dtc_trust_requires_both_checks_to_pass() {
        assert!(!dtc_trust_chain_valid(&[
            dtc_check("TrustChain", false),
            dtc_check("SignerKeyMatchesCertificate", true),
        ]));
        assert!(!dtc_trust_chain_valid(&[
            dtc_check("TrustChain", true),
            dtc_check("SignerKeyMatchesCertificate", false),
        ]));
    }

    #[test]
    fn dtc_trust_accepts_exactly_one_passed_instance_of_each_check() {
        assert!(dtc_trust_chain_valid(&[
            dtc_check("Signature", true),
            dtc_check("TrustChain", true),
            dtc_check("SignerKeyMatchesCertificate", true),
        ]));
    }

    #[test]
    fn dtc_trust_rejects_duplicate_required_checks() {
        assert!(!dtc_trust_chain_valid(&[
            dtc_check("TrustChain", true),
            dtc_check("TrustChain", true),
            dtc_check("SignerKeyMatchesCertificate", true),
        ]));
        assert!(!dtc_trust_chain_valid(&[
            dtc_check("TrustChain", true),
            dtc_check("SignerKeyMatchesCertificate", true),
            dtc_check("SignerKeyMatchesCertificate", false),
        ]));
    }

    #[tokio::test]
    async fn mock_pad_cannot_authorize() {
        let error = evaluate_pad(&sample_challenge(), &PadProviderConfig::default())
            .await
            .expect_err("mock PAD must be unavailable");

        assert!(error.to_string().contains("Mock PAD cannot authorize"));
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

    fn active_open_badge_method(now: DateTime<Utc>) -> OpenBadgeVerificationMethod {
        OpenBadgeVerificationMethod {
            id: "did:example:issuer#key-1".to_string(),
            document: json!({
                "id": "did:example:issuer#key-1",
                "type": "JsonWebKey2020",
                "controller": "did:example:issuer",
                "publicKeyJwk": {
                    "kty": "OKP",
                    "crv": "Ed25519",
                    "x": "11qYAYdk9JbF9h5H4fGxM7yJFMw9qkE3vZ8LxJ8rV5M"
                }
            }),
            controller: Some("did:example:issuer".to_string()),
            issuer: None,
            kid: None,
            not_before: Some(now - Duration::hours(1)),
            not_after: Some(now + Duration::hours(1)),
            status: Some("active".to_string()),
            source: marty_app_storage::OpenBadgeKeySource::Sync,
            synced_at: now - Duration::hours(1),
        }
    }

    fn governed_open_badge_record(
        method: OpenBadgeVerificationMethod,
        trust_domain: &str,
        digest_byte: char,
        now: DateTime<Utc>,
    ) -> OpenBadgeTrustRecord {
        OpenBadgeTrustRecord {
            provenance: Some(TrustPackageProvenance {
                trust_domain: trust_domain.to_string(),
                sequence: 7,
                package_version: "7.0.0".to_string(),
                created_at: method.synced_at,
                expires_at: now + Duration::hours(12),
                signer_key_id: format!("ed25519:{}", "a".repeat(64)),
                package_digest: digest_byte.to_string().repeat(64),
                imported_at: now - Duration::minutes(30),
            }),
            method,
        }
    }

    fn method_with_id(
        mut method: OpenBadgeVerificationMethod,
        id: &str,
        controller: &str,
    ) -> OpenBadgeVerificationMethod {
        method.id = id.to_string();
        method.controller = Some(controller.to_string());
        method.document["id"] = json!(id);
        method.document["controller"] = json!(controller);
        method
    }

    fn software_artifact() -> ArtifactProvenance {
        ArtifactProvenance::new(
            "marty-verifier-executable",
            "1.0.0",
            format!("sha256:{}", "f".repeat(64)),
        )
        .expect("software provenance")
    }

    #[test]
    fn production_governed_store_rejects_provenance_less_records() {
        let now = Utc::now();
        let legacy = OpenBadgeTrustRecord {
            method: active_open_badge_method(now),
            provenance: None,
        };

        let (store, rejected) = build_governed_open_badge_store(&[legacy], now, 48);

        assert!(store.documents.is_empty());
        assert!(store.provenance_by_document.is_empty());
        assert_eq!(rejected, 1);
    }

    #[test]
    fn production_governed_store_isolates_package_domains() {
        let now = Utc::now();
        let first = governed_open_badge_record(
            method_with_id(
                active_open_badge_method(now),
                "did:example:first#key-1",
                "did:example:first",
            ),
            "trust.example/first",
            '1',
            now,
        );
        let second = governed_open_badge_record(
            method_with_id(
                active_open_badge_method(now),
                "did:example:second#key-1",
                "did:example:second",
            ),
            "trust.example/second",
            '2',
            now,
        );

        let (store, rejected) = build_governed_open_badge_store(&[first, second], now, 48);
        let first_provenance = store
            .provenance_for_method("did:example:first#key-1")
            .expect("first provenance");
        let authority = store.authority_documents(first_provenance);

        assert_eq!(rejected, 0);
        assert!(authority.contains_key("did:example:first#key-1"));
        assert!(!authority.contains_key("did:example:second#key-1"));
    }

    #[test]
    fn status_adapter_requires_exact_url_and_bounds_signed_age() {
        let now = Utc::now();
        let method_id = "did:example:status#key-1";
        let record = governed_open_badge_record(
            method_with_id(
                active_open_badge_method(now),
                method_id,
                "did:example:status",
            ),
            "trust.example/status",
            '3',
            now,
        );
        let (store, rejected) = build_governed_open_badge_store(&[record], now, 48);
        assert_eq!(rejected, 0);

        let status_url = "https://status.example/lists/1";
        let credential = json!({
            "issuer": "did:example:status",
            "validFrom": (now - Duration::hours(1)).to_rfc3339(),
            "validUntil": (now + Duration::hours(4)).to_rfc3339(),
            "proof": { "verificationMethod": method_id }
        });
        let mut request_store = DocumentStore::new();
        request_store.insert(status_url.to_string(), credential.clone());

        let admitted = build_authenticated_status_list(
            status_url,
            &request_store,
            &store,
            now,
            &OpenBadgeTrustConfig::default(),
            &software_artifact(),
        )
        .expect("admit exact governed status context");
        assert_eq!(admitted.url(), status_url);
        assert_eq!(admitted.trusted_issuer(), "did:example:status");
        assert!(admitted.authority_documents().contains_key(method_id));
        assert!(admitted.fresh_until() <= now + Duration::hours(4));

        assert!(build_authenticated_status_list(
            "https://status.example/lists/other",
            &request_store,
            &store,
            now,
            &OpenBadgeTrustConfig::default(),
            &software_artifact(),
        )
        .is_err());

        let mut stale_store = DocumentStore::new();
        let mut stale = credential;
        stale["validFrom"] = json!((now - Duration::hours(25)).to_rfc3339());
        stale_store.insert(status_url.to_string(), stale);
        let relaxed_config = OpenBadgeTrustConfig {
            status_list_max_age_hours: 10_000,
            stale_critical_hours: 10_000,
            ..OpenBadgeTrustConfig::default()
        };
        assert!(build_authenticated_status_list(
            status_url,
            &stale_store,
            &store,
            now,
            &relaxed_config,
            &software_artifact(),
        )
        .is_err());
    }

    #[tokio::test]
    async fn status_adapter_bounds_and_does_not_reflect_declared_urls() {
        let malformed_store_request = json!({"document_store": []});
        assert!(build_authenticated_status_lists(
            &malformed_store_request,
            &GovernedOpenBadgeStore::default(),
            Utc::now(),
            &OpenBadgeTrustConfig::default(),
        )
        .await
        .is_err());

        let prefix = "https://status.example/";
        let maximum = format!(
            "{prefix}{}",
            "é".repeat(MAX_OPEN_BADGE_STATUS_IRI_CHARS - prefix.chars().count())
        );
        let maximum_request = json!({
            "credential": {
                "credentialStatus": {
                    "type": "BitstringStatusListEntry",
                    "statusListCredential": maximum,
                }
            }
        });
        assert_eq!(extract_status_list_urls(&maximum_request), vec![maximum]);

        let oversized = format!("{prefix}{}", "a".repeat(MAX_OPEN_BADGE_STATUS_IRI_CHARS));
        let oversized_request = json!({
            "credential": {
                "credentialStatus": {
                    "type": "BitstringStatusListEntry",
                    "statusListCredential": oversized,
                }
            }
        });
        assert!(extract_status_list_urls(&oversized_request).is_empty());

        let private_marker = "private-query-value";
        let status_url = format!("https://status.example/list?token={private_marker}");
        let request = json!({
            "credential": {
                "credentialStatus": {
                    "type": "BitstringStatusListEntry",
                    "statusListCredential": status_url,
                }
            },
            "document_store": {
                "https://unrelated.example/1": {"large": "caller-controlled"}
            }
        });
        let selected =
            extract_stapled_status_documents(&request, std::slice::from_ref(&status_url))
                .expect("select exact stapled status documents");
        assert!(selected.is_empty());
        let (_, warnings) = build_authenticated_status_lists(
            &request,
            &GovernedOpenBadgeStore::default(),
            Utc::now(),
            &OpenBadgeTrustConfig::default(),
        )
        .await
        .expect("missing stapled status context remains a typed warning");

        assert_eq!(warnings.len(), 1);
        assert!(!warnings[0].contains(private_marker));
        assert!(!warnings[0].contains(&status_url));
    }

    fn status_evidence(
        purpose: &str,
        outcome: OpenBadgeStatusEvidenceOutcome,
    ) -> OpenBadgeStatusEvidence {
        let now = Utc::now();
        let artifact = OpenBadgeArtifactEvidence {
            id: "artifact".to_string(),
            version: "1".to_string(),
            digest: format!("sha256:{}", "a".repeat(64)),
        };
        OpenBadgeStatusEvidence {
            status_list_url: "https://status.example/lists/1".to_string(),
            status_issuer: "did:example:status".to_string(),
            status_purpose: purpose.to_string(),
            status_list_index: 1,
            status_size: 1,
            status_value: u16::from(outcome != OpenBadgeStatusEvidenceOutcome::Good),
            outcome,
            checked_at: now,
            retrieved_at: now,
            fresh_until: now + Duration::hours(1),
            authority_provenance: OpenBadgeStatusAuthorityEvidence {
                trust_profile: artifact.clone(),
                resolver: artifact.clone(),
                software: artifact,
            },
        }
    }

    #[test]
    fn revocation_projection_requires_explicit_authenticated_evidence() {
        assert_eq!(
            open_badge_revocation_status(&[], true),
            RevocationStatus::Unknown
        );
        assert_eq!(
            open_badge_revocation_status(
                &[status_evidence(
                    "revocation",
                    OpenBadgeStatusEvidenceOutcome::Good,
                )],
                true
            ),
            RevocationStatus::Valid
        );
        assert_eq!(
            open_badge_revocation_status(
                &[status_evidence(
                    "revocation",
                    OpenBadgeStatusEvidenceOutcome::Good,
                )],
                false
            ),
            RevocationStatus::Unknown
        );
        assert_eq!(
            open_badge_revocation_status(
                &[status_evidence(
                    "revocation",
                    OpenBadgeStatusEvidenceOutcome::Revoked,
                )],
                false
            ),
            RevocationStatus::Revoked
        );
        assert_eq!(
            open_badge_revocation_status(
                &[status_evidence(
                    "suspension",
                    OpenBadgeStatusEvidenceOutcome::Good,
                )],
                true
            ),
            RevocationStatus::Unknown
        );
    }

    #[test]
    fn software_provenance_hashes_the_running_executable() {
        let provenance = compute_verifier_software_provenance().expect("software provenance");

        assert_eq!(provenance.id(), "marty-verifier-executable");
        assert_eq!(provenance.version(), env!("CARGO_PKG_VERSION"));
        assert!(provenance.digest().starts_with("sha256:"));
        assert_eq!(provenance.digest().len(), "sha256:".len() + 64);
    }

    #[tokio::test]
    async fn software_provenance_is_stable_across_concurrent_requests() {
        let (first, second, third) = tokio::join!(
            verifier_software_provenance(),
            verifier_software_provenance(),
            verifier_software_provenance(),
        );
        let first = first.expect("first software provenance");
        assert_eq!(first, second.expect("second software provenance"));
        assert_eq!(first, third.expect("third software provenance"));
    }

    #[test]
    fn production_open_badge_store_admits_only_active_in_window_records() {
        let now = Utc::now();
        let active = active_open_badge_method(now);
        let (store, rejected) =
            build_trusted_open_badge_store(std::slice::from_ref(&active), now, 48);
        assert_eq!(store.len(), 1);
        assert_eq!(rejected, 0);

        let mut inactive = active.clone();
        inactive.status = Some("revoked".to_string());
        assert!(!open_badge_trust_record_is_usable(&inactive, now, 48));

        let mut not_yet_valid = active.clone();
        not_yet_valid.not_before = Some(now + Duration::seconds(1));
        assert!(!open_badge_trust_record_is_usable(&not_yet_valid, now, 48));

        let mut expired = active.clone();
        expired.not_after = Some(now);
        assert!(!open_badge_trust_record_is_usable(&expired, now, 48));

        let mut critically_stale = active;
        critically_stale.synced_at = now - Duration::hours(48);
        assert!(!open_badge_trust_record_is_usable(
            &critically_stale,
            now,
            48
        ));
        assert!(!open_badge_trust_record_is_usable(
            &critically_stale,
            now,
            10_000
        ));
    }

    #[test]
    fn production_open_badge_store_rejects_binding_conflicts_and_private_keys() {
        let now = Utc::now();
        let active = active_open_badge_method(now);

        let mut wrong_id = active.clone();
        wrong_id.document["id"] = json!("did:example:issuer#other-key");
        assert!(!open_badge_trust_record_is_usable(&wrong_id, now, 48));

        let mut wrong_controller = active.clone();
        wrong_controller.document["controller"] = json!("did:example:other");
        assert!(!open_badge_trust_record_is_usable(
            &wrong_controller,
            now,
            48
        ));

        let mut private_key = active;
        private_key.document["publicKeyJwk"]["d"] = json!("private-material");
        assert!(!open_badge_trust_record_is_usable(&private_key, now, 48));
    }

    #[test]
    fn production_open_badge_store_rejects_duplicate_method_ids() {
        let now = Utc::now();
        let method = active_open_badge_method(now);
        let (store, rejected) = build_trusted_open_badge_store(&[method.clone(), method], now, 48);

        assert!(store.is_empty());
        assert_eq!(rejected, 2);
    }

    #[test]
    fn production_open_badge_store_replaces_credential_documents() {
        let mut request = json!({
            "credential": {},
            "document_store": {
                "did:example:untrusted": {
                    "publicKeyJwk": { "kty": "OKP", "crv": "Ed25519", "x": "def" }
                },
                "https://issuer.example/status": {
                    "credentialSubject": { "encodedList": "credential-controlled" }
                }
            }
        });
        let mut trusted_store = DocumentStore::new();
        trusted_store.insert(
            "did:example:trusted".to_string(),
            json!({ "publicKeyJwk": { "kty": "OKP", "crv": "Ed25519", "x": "abc" } }),
        );

        replace_open_badge_document_store(&mut request, &trusted_store)
            .expect("replace document store");
        let installed_store = extract_open_badge_document_store(&request).expect("document store");

        assert_eq!(installed_store, trusted_store);
        assert!(!installed_store.contains_key("did:example:untrusted"));
        assert!(!installed_store.contains_key("https://issuer.example/status"));
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

    #[test]
    fn production_open_badge_policy_rejects_fail_open() {
        ensure_production_open_badge_policy(&OpenBadgeTrustPolicy::FailClosed)
            .expect("fail-closed policy");
        ensure_production_open_badge_policy(&OpenBadgeTrustPolicy::Selective)
            .expect("selective policy");

        let error = ensure_production_open_badge_policy(&OpenBadgeTrustPolicy::FailOpen)
            .expect_err("fail-open policy must be rejected");
        assert!(matches!(error, AppError::Config(message) if message.contains("fail-open")));
    }

    #[test]
    fn production_open_badge_requires_a_trusted_method() {
        let mut store = DocumentStore::new();
        store.insert(
            "did:example:trusted".to_string(),
            json!({ "verificationMethod": [{ "id": "did:example:trusted#key-1" }] }),
        );

        assert!(!open_badge_request_method_trusted(&store, None));
        assert!(!open_badge_request_method_trusted(
            &store,
            Some("did:example:untrusted#key-1")
        ));
        assert!(open_badge_request_method_trusted(
            &store,
            Some("did:example:trusted#key-1")
        ));
    }

    #[test]
    fn open_badge_trust_freshness_fails_closed_without_sync() {
        let freshness =
            classify_open_badge_trust_freshness(None, Utc::now(), &OpenBadgeTrustConfig::default());

        assert!(matches!(
            freshness,
            OpenBadgeTrustFreshness::Unavailable(message)
                if message.contains("never been synchronized")
        ));
    }

    #[test]
    fn open_badge_trust_freshness_fails_closed_for_future_sync() {
        let now = Utc::now();
        let freshness = classify_open_badge_trust_freshness(
            Some(now + Duration::seconds(1)),
            now,
            &OpenBadgeTrustConfig::default(),
        );

        assert!(matches!(
            freshness,
            OpenBadgeTrustFreshness::Unavailable(message) if message.contains("future")
        ));
    }

    #[test]
    fn open_badge_trust_freshness_enforces_warning_and_critical_boundaries() {
        let now = Utc::now();
        let config = OpenBadgeTrustConfig::default();

        assert_eq!(
            classify_open_badge_trust_freshness(Some(now - Duration::hours(23)), now, &config,),
            OpenBadgeTrustFreshness::Fresh
        );
        assert!(matches!(
            classify_open_badge_trust_freshness(Some(now - Duration::hours(24)), now, &config,),
            OpenBadgeTrustFreshness::Warning(_)
        ));
        assert!(matches!(
            classify_open_badge_trust_freshness(Some(now - Duration::hours(48)), now, &config,),
            OpenBadgeTrustFreshness::Unavailable(_)
        ));

        let mut relaxed = config;
        relaxed.stale_critical_hours = 10_000;
        assert!(matches!(
            classify_open_badge_trust_freshness(Some(now - Duration::hours(48)), now, &relaxed,),
            OpenBadgeTrustFreshness::Unavailable(_)
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
    let registry = build_csca_registry(state).await?;

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
