use super::*;
use crate::commands::verification::{
    open_badge_issuer_from_normalized, unsupported_result, DtcDetails, IssuerInfo,
    OpenBadgeDetails, VerifyRequest,
};
use marty_verification::policy::{
    CredentialRankingStrategy, FreshnessRequirements, HolderBindingMethod, PolicyErrorCode,
    RequiredClaim,
};
use serde_json::json;

fn policy(id: &str) -> PresentationPolicy {
    PresentationPolicy {
        id: id.into(),
        name: "Checkpoint policy".into(),
        description: None,
        purpose: "Verify the selected checkpoint requirements".into(),
        accepted_credential_types: vec!["dtc".into()],
        required_claims: vec![RequiredClaim {
            claim_name: "nationality".into(),
            credential_type: "dtc".into(),
            accept_predicate: false,
            required_value: Some(json!("DEU")),
        }],
        holder_binding: HolderBindingMethod::None,
        trust_profile_id: None,
        allowed_issuers: vec!["DEU".into()],
        freshness_requirements: FreshnessRequirements {
            max_credential_age_seconds: None,
            max_proof_age_seconds: 300,
            require_live_revocation_check: false,
        },
        prefer_predicates: false,
        single_presentation: true,
        derived_attribute_preferences: HashMap::new(),
        credential_ranking_strategy: CredentialRankingStrategy::FreshestFirst,
        credential_ranking_weights: HashMap::new(),
        metadata: HashMap::new(),
        version: 3,
    }
}

/// Facts at the successful protocol-adapter boundary, before policy evaluation.
fn verified_dtc() -> VerificationResult {
    let request: VerifyRequest = serde_json::from_value(json!({
        "credential_type": "dtc",
        "credential_data": "policy evaluation must not parse raw credential data"
    }))
    .unwrap();
    let mut result = unsupported_result(&request, "fixture");
    result.status = VerificationStatus::Valid;
    result.warnings.clear();
    result.issuer = Some(IssuerInfo {
        name: Some("Display name is not the issuer identity".into()),
        jurisdiction: Some("DEU".into()),
        subject: Some("DEU".into()),
    });
    result.disclosed_claims = json!({ "nationality": "DEU" });
    result.trust_chain.valid = true;
    result.revocation_status = RevocationStatus::Valid;
    result.dtc_details = Some(DtcDetails {
        checks: Vec::new(),
        dtc_type: Some(1),
        errors: Vec::new(),
        error_codes: Vec::new(),
    });
    result
}

fn errors(policy: &PresentationPolicy, result: &VerificationResult) -> Vec<PolicyErrorCode> {
    evaluate_policy_constraints(policy, result, 1_000)
        .errors
        .into_iter()
        .map(|error| error.code)
        .collect()
}

#[test]
fn active_policy_wins_independently_of_cache_order() {
    let permissive = policy("other-policy");
    let mut active = policy("active-policy");
    active.required_claims[0].required_value = Some(json!("FRA"));
    for cached in [
        vec![permissive.clone(), active.clone()],
        vec![active.clone(), permissive.clone()],
    ] {
        let selected = select_active_policy(Some("active-policy"), cached).unwrap();
        assert_eq!(selected.id, active.id);
        assert_eq!(selected.version, active.version);
        let mut result = verified_dtc();
        apply_presentation_policy(&selected, &mut result, 1_000);
        assert_eq!(result.status, VerificationStatus::Invalid);
        assert!(!result.warnings.is_empty());
    }
}

#[test]
fn absent_unavailable_or_ambiguous_active_policy_cannot_fall_back() {
    assert!(select_active_policy(None, vec![policy("cached")]).is_err());
    assert!(select_active_policy(Some("missing"), vec![policy("cached")]).is_err());
    assert!(select_active_policy(Some("cached"), Vec::new()).is_err());
    assert!(
        select_active_policy(Some("cached"), vec![policy("cached"), policy("cached")]).is_err()
    );
}

#[test]
fn complete_policy_enforces_claim_presence_value_and_issuer() {
    let selected = policy("active");
    let mut valid = verified_dtc();
    apply_presentation_policy(&selected, &mut valid, 1_000);
    assert_eq!(valid.status, VerificationStatus::Valid);

    for claims in [json!({}), json!({"nationality": "FRA"})] {
        let mut result = verified_dtc();
        result.disclosed_claims = claims;
        assert!(errors(&selected, &result).contains(&PolicyErrorCode::ClaimRequirementNotSatisfied));
        apply_presentation_policy(&selected, &mut result, 1_000);
        assert_eq!(result.status, VerificationStatus::Invalid);
    }
    let mut wrong_issuer = verified_dtc();
    wrong_issuer.issuer.as_mut().unwrap().subject = Some("FRA".into());
    assert!(errors(&selected, &wrong_issuer).contains(&PolicyErrorCode::IssuerNotAllowed));
}

#[test]
fn request_case_and_claimed_type_do_not_bypass_policy() {
    let mut selected = policy("active");
    selected.required_claims[0].required_value = Some(json!("FRA"));
    for label in ["dtc", "DTC", "DtC"] {
        let mut result = verified_dtc();
        result.credential_type = normalize_credential_type(label);
        assert_eq!(result.credential_type, "dtc");
        apply_presentation_policy(&selected, &mut result, 1_000);
        assert_eq!(result.status, VerificationStatus::Invalid);
    }

    let mut wrong_type = policy("active");
    wrong_type.accepted_credential_types = vec!["EmployeeCredential".into()];
    let mut result = verified_dtc();
    result.credential_type = "EmployeeCredential".into();
    assert!(errors(&wrong_type, &result).contains(&PolicyErrorCode::CredentialTypeNotAccepted));
}

#[test]
fn unavailable_policy_evidence_fails_closed_without_using_display_metadata() {
    let mut selected = policy("active");
    selected.trust_profile_id = Some("required-trust-profile".into());
    selected.holder_binding = HolderBindingMethod::DeviceKey;
    selected.freshness_requirements.max_credential_age_seconds = Some(3_600);
    selected
        .freshness_requirements
        .require_live_revocation_check = true;
    let mut result = verified_dtc();
    result.verified_at = "1970-01-01T00:16:39Z".into();
    result.trust_chain.offline_verified = false;
    let codes = errors(&selected, &result);
    for expected in [
        PolicyErrorCode::IssuerNotTrusted,
        PolicyErrorCode::HolderBindingRequired,
        PolicyErrorCode::CredentialTimestampMissing,
        PolicyErrorCode::ProofTimestampMissing,
        PolicyErrorCode::RevocationCheckRequired,
    ] {
        assert!(codes.contains(&expected), "missing {expected:?}: {codes:?}");
    }
}

#[test]
fn unknown_presentation_count_and_known_revocation_are_not_success() {
    let selected = policy("active");
    let mut presentation = verified_dtc();
    presentation.dtc_details = None;
    presentation.credential_type = "oid4vp".into();
    assert!(errors(&selected, &presentation).contains(&PolicyErrorCode::SinglePresentationRequired));

    let mut revoked = verified_dtc();
    revoked.revocation_status = RevocationStatus::Revoked;
    assert!(errors(&selected, &revoked).contains(&PolicyErrorCode::CredentialRevoked));
}

#[test]
fn open_badge_policy_uses_authenticated_subject_and_issuer() {
    let normalized = json!({
        "issuer": { "id": "did:example:issuer", "name": "Issuer display name" },
        "credential_subject": { "role": "staff" }
    });
    let mut result = verified_dtc();
    result.dtc_details = None;
    result.issuer = open_badge_issuer_from_normalized(&normalized);
    result.disclosed_claims = json!({ "credential_id": "badge-1" });
    result.open_badge_details = Some(OpenBadgeDetails {
        version: "3.0".into(),
        errors: Vec::new(),
        error_codes: Vec::new(),
        warnings: Vec::new(),
        status_checks: Vec::new(),
        normalized: Some(normalized),
    });
    let mut selected = policy("active");
    selected.accepted_credential_types = vec!["open-badge".into()];
    selected.allowed_issuers = vec!["did:example:issuer".into()];
    selected.required_claims = vec![RequiredClaim {
        claim_name: "role".into(),
        credential_type: "open-badge".into(),
        accept_predicate: false,
        required_value: Some(json!("staff")),
    }];
    assert!(evaluate_policy_constraints(&selected, &result, 1_000).is_satisfied);
    selected.required_claims[0].required_value = Some(json!("admin"));
    assert!(!evaluate_policy_constraints(&selected, &result, 1_000).is_satisfied);
}

#[test]
fn policy_cannot_promote_unsuccessful_protocol_verification() {
    for (status, expected) in [
        (VerificationStatus::Invalid, VerificationStatus::Invalid),
        (VerificationStatus::Failed, VerificationStatus::Failed),
    ] {
        let mut result = verified_dtc();
        result.status = status;
        apply_presentation_policy(&policy("active"), &mut result, 1_000);
        assert_eq!(result.status, expected);
        assert!(verified_policy_input(&result, 1_000).claims.is_empty());
    }
}
