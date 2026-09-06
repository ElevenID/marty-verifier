//! Policy verification operations.

use super::{AppResult, AppState, IssuerConstraintChecker, PresentationPolicy, VerifyRequest};

/// Load cached presentation policies from storage
pub(super) async fn load_cached_policies(state: &AppState) -> AppResult<Vec<PresentationPolicy>> {
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
pub(super) async fn evaluate_policy_constraints(
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
