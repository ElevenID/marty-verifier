//! Bind the configured policy to protocol-verified facts and delegate decisions to Core.

use marty_verification::policy::{PolicyEvaluationInput, PolicyEvaluationResult, PolicyEvaluator};

use super::{
    AppError, AppResult, AppState, HashMap, PresentationPolicy, RevocationStatus, Value,
    VerificationResult, VerificationStatus,
};

/// Resolve the active policy from one runtime-configuration snapshot. A policy
/// accepting the same format is not a substitute for the configured policy.
pub(super) async fn load_active_policy(state: &AppState) -> AppResult<PresentationPolicy> {
    let configuration = state.runtime_config.snapshot().await;
    let policies = state
        .storage
        .get_presentation_policies(configuration.deployment_profile_id.as_deref())
        .await
        .map_err(|error| AppError::Config(error.to_string()))?;

    select_active_policy(configuration.active_policy_id.as_deref(), policies)
}

fn select_active_policy(
    active_policy_id: Option<&str>,
    policies: Vec<PresentationPolicy>,
) -> AppResult<PresentationPolicy> {
    let active_policy_id = active_policy_id
        .filter(|id| !id.is_empty())
        .ok_or_else(|| AppError::Config("No active presentation policy is configured".into()))?;
    let mut selected = policies
        .into_iter()
        .filter(|policy| policy.id == active_policy_id);
    let policy = selected.next().ok_or_else(|| {
        AppError::Config(format!(
            "Active presentation policy {active_policy_id} is unavailable for this deployment profile"
        ))
    })?;
    if selected.next().is_some() {
        return Err(AppError::Config(format!(
            "Active presentation policy {active_policy_id} is ambiguous"
        )));
    }
    Ok(policy)
}

/// The local IPC label selects a protocol adapter, not a credential template.
/// Normalize it once before entitlement checks, dispatch, policy and reporting.
pub(super) fn normalize_credential_type(credential_type: &str) -> String {
    credential_type.to_ascii_lowercase()
}

/// Project only facts established by a successful protocol adapter. In
/// particular, request labels, display timestamps, online connectivity and the
/// placeholder biometric adapters do not prove policy requirements.
fn verified_policy_input(
    result: &VerificationResult,
    evaluation_time_epoch_seconds: u64,
) -> PolicyEvaluationInput {
    let mut credential_types = Vec::new();
    let mut claims = HashMap::new();
    let mut presentation_count = 0;

    if result.status == VerificationStatus::Valid {
        // These adapters verify one credential of the indicated protocol. The
        // online OID4VP compatibility response has no authenticated credential
        // type/count evidence, so its request label cannot fill these fields.
        let protocol = if result.emrtd_details.is_some() {
            Some("emrtd")
        } else if result.dtc_details.is_some() {
            Some("dtc")
        } else if result.open_badge_details.is_some() {
            Some("open-badge")
        } else {
            None
        };
        if let Some(protocol) = protocol {
            credential_types.push(protocol.to_owned());
            presentation_count = 1;
        }
        if let Some(values) = result.disclosed_claims.as_object() {
            claims.extend(values.clone());
        }
        // Open Badge display claims intentionally contain only a small summary.
        // Core's normalized subject contains the authenticated claim values.
        if let Some(subject) = result
            .open_badge_details
            .as_ref()
            .and_then(|details| details.normalized.as_ref())
            .and_then(|normalized| normalized.get("credential_subject"))
            .and_then(Value::as_object)
        {
            claims.extend(subject.clone());
        }
    }

    PolicyEvaluationInput {
        credential_types,
        claims,
        issuer_id: result
            .issuer
            .as_ref()
            .and_then(|issuer| issuer.subject.clone())
            .unwrap_or_default(),
        // The adapters verify their governed trust stores, but do not return
        // evidence identifying the PresentationPolicy's selected TrustProfile.
        trust_profile_verified: false,
        trust_profile_id: None,
        issued_at_epoch_seconds: None,
        proof_epoch_seconds: None,
        evaluation_time_epoch_seconds,
        holder_binding_verified: false,
        // Cached authenticated status can establish a known revocation state;
        // it does not establish that the policy's live check was performed.
        revocation_checked: false,
        not_revoked: match result.revocation_status {
            RevocationStatus::Valid | RevocationStatus::CachedValid => Some(true),
            RevocationStatus::Revoked => Some(false),
            RevocationStatus::Unknown => None,
        },
        presentation_count,
    }
}

pub(super) fn evaluate_policy_constraints(
    policy: &PresentationPolicy,
    result: &VerificationResult,
    evaluation_time_epoch_seconds: u64,
) -> PolicyEvaluationResult {
    PolicyEvaluator::new(policy.clone()).evaluate(&verified_policy_input(
        result,
        evaluation_time_epoch_seconds,
    ))
}

pub(super) fn apply_presentation_policy(
    policy: &PresentationPolicy,
    result: &mut VerificationResult,
    evaluation_time_epoch_seconds: u64,
) {
    // Policy evaluation must never promote a failed protocol verification.
    if result.status != VerificationStatus::Valid {
        return;
    }
    let evaluation = evaluate_policy_constraints(policy, result, evaluation_time_epoch_seconds);
    tracing::info!(
        policy_id = %policy.id,
        policy_version = policy.version,
        satisfied = evaluation.is_satisfied,
        "Evaluated active presentation policy"
    );
    if !evaluation.is_satisfied {
        result.status = VerificationStatus::Invalid;
        result
            .warnings
            .extend(evaluation.errors.into_iter().map(|error| error.message));
    }
    result.warnings.extend(evaluation.warnings);
}

#[cfg(test)]
mod tests;
