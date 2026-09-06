//! Credential verification commands

use std::collections::{HashMap, HashSet};

use base64::engine::general_purpose::STANDARD as BASE64_STANDARD;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use chrono::{DateTime, Duration, Utc};
use marty_app_storage::OpenBadgeVerificationMethod;
#[cfg(feature = "oid4vp")]
use marty_oid4vci::verifier::{
    PresentationDefinition, PresentationSubmission, VerificationCheckStatus as Oid4vpCheckStatus,
    VerificationEngine, VerificationResult as Oid4vpCoreVerificationResult,
    VerificationScope as Oid4vpScope,
};
use marty_secure_storage::{
    OpenBadgeTrustRecord, TrustAnchorRecord, TrustAnchorType as CoreTrustAnchorType,
    TrustPackageProvenance,
};
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
use x509_cert::Certificate;

use crate::config::{
    LivenessRetentionConfig, OpenBadgeTrustConfig, OpenBadgeTrustPolicy, PadProviderConfig,
    PadProviderType,
};
use crate::error::{AppError, AppResult};
use crate::state::{AppState, StoredLivenessChallenge};

mod liveness;
pub(crate) use liveness::validate_liveness_challenge;
use liveness::*;
mod policy;
use policy::*;
mod dtc;
pub use dtc::verify_dtc_offline;
use dtc::*;
mod open_badges;
pub use open_badges::verify_open_badge_offline;
use open_badges::*;
#[cfg(feature = "oid4vp")]
mod oid4vp;
#[cfg(feature = "oid4vp")]
pub use oid4vp::verify_oid4vp_offline;
#[cfg(feature = "oid4vp")]
use oid4vp::*;
mod emrtd;
pub use emrtd::verify_emrtd_offline;
use emrtd::*;

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
    pub outcome: VerificationCheckOutcome,
    /// Compatibility projection for existing IPC consumers.
    ///
    /// `outcome` is authoritative and this value is true only for `Passed`.
    pub passed: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub details: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error_code: Option<String>,
}

/// Explicit outcome of a verifier check.
#[derive(Debug, Clone, Copy, Serialize, PartialEq, Eq)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum VerificationCheckOutcome {
    Passed,
    Failed,
    NotPerformed,
    Error,
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

/// Verify a credential
#[tauri::command]
pub async fn verify_credential(
    request: VerifyRequest,
    state: State<'_, AppState>,
) -> AppResult<VerificationResult> {
    #[cfg(feature = "reporting")]
    let started_at = std::time::Instant::now();
    tracing::info!(
        credential_type = %request.credential_type,
        "Verifying credential"
    );

    // Keep the credential entitlement distinct from its acquisition hardware.
    // A complete eMRTD payload can be verified cryptographically without an
    // NFC reader; NFC acquisition continues to require the complex tier.
    let hardware_feature = verification_hardware_feature(&request.credential_type, request.use_nfc);
    state
        .check_feature_with_hardware(&request.credential_type, hardware_feature)
        .await?;

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
    if matches!(credential_type.as_str(), "emrtd" | "dtc") {
        state.sync_engine.ensure_csca_cache_fresh().await?;
    }
    let mut result = match credential_type.as_str() {
        "emrtd" => verify_emrtd_payload(&request, &state, is_online).await?,
        "dtc" => verify_dtc_payload(&request, &state, is_online).await?,
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
    result.verification_id = verification_id.clone();
    state
        .storage
        .store_verification_event(&verification_id, &request.credential_type, &result.status)
        .await?;

    #[cfg(feature = "reporting")]
    if state.config.read().await.reporting_config.enabled
        && state.runtime_config.should_audit_all_events().await
    {
        let event = marty_reporting::VerificationEvent::verification(
            verification_id,
            request.credential_type.clone(),
            format!("{:?}", result.status).to_lowercase(),
        )
        .with_verification_context(
            result
                .issuer
                .as_ref()
                .and_then(|issuer| issuer.jurisdiction.clone()),
            Some(result.trust_chain.chain_type.clone()),
            result.trust_chain.offline_verified,
            Some(
                started_at
                    .elapsed()
                    .as_millis()
                    .try_into()
                    .unwrap_or(u64::MAX),
            ),
            result
                .face_match
                .as_ref()
                .map(|match_result| match_result.verified),
        );
        state.reporter.queue_event(event).await?;
    }

    Ok(result)
}

fn verification_hardware_feature(credential_type: &str, use_nfc: bool) -> &str {
    if credential_type.eq_ignore_ascii_case("emrtd") && !use_nfc {
        "basic_verification"
    } else {
        credential_type
    }
}

fn parse_json_input(input: &str, label: &str) -> AppResult<Value> {
    serde_json::from_str(input).map_err(|e| {
        AppError::Verification(format!("{} credential data must be JSON: {}", label, e))
    })
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

static VERIFIER_SOFTWARE_PROVENANCE: OnceCell<ArtifactProvenance> = OnceCell::const_new();

#[derive(Debug, Clone, PartialEq, Eq)]
enum OpenBadgeTrustFreshness {
    Fresh,
    Warning(String),
    Unavailable(String),
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
mod tests;

#[derive(Debug, Deserialize)]
struct EmrtdPayload {
    /// Base64-encoded EF.SOD
    sod_base64: String,
    /// Map of DG names (e.g., "DG1") to base64-encoded contents
    data_groups: HashMap<String, String>,
    /// Optional country hint (ISO 3166)
    country: Option<String>,
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
