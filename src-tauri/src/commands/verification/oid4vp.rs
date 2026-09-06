//! Oid4vp verification operations.

use super::{
    parse_json_input, AppError, AppResult, AppState, Oid4vpCheckStatus,
    Oid4vpCoreVerificationResult, Oid4vpScope, PresentationDefinition, PresentationSubmission,
    RevocationStatus, TrustChainStatus, Value, VerificationEngine, VerificationResult,
    VerificationStatus, VerifyRequest, URL_SAFE_NO_PAD,
};
use base64::Engine;

/// Parse and verify an OID4VP credential (JWT VP or SD-JWT VP).
///
/// `credential_data` must be a JSON object with:
/// - `vp_token`               — compact JWT VP token from the wallet (required)
/// - `nonce`                  — nonce from the authorization request (required)
/// - `presentation_submission`  — wallet's descriptor mapping (optional)
/// - `presentation_definition`  — original request definition (optional; enables
///   structural validation when paired with `presentation_submission`)
#[cfg(feature = "oid4vp")]
pub(super) async fn verify_oid4vp_payload(
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

    // Optional structural check when neither PEX object is present; fail closed
    // when the pair is partial or malformed.
    let holder_proof_valid = oid4vp_presentation_proof_passed(&token_result);
    let structural_errors = if holder_proof_valid {
        oid4vp_presentation_exchange_errors(&engine, &raw, &vp_token)
    } else {
        vec![]
    };

    let holder_presentation_valid = holder_proof_valid && structural_errors.is_empty();

    let mut warnings: Vec<String> = vec![];
    if !is_online {
        warnings.push("OID4VP offline mode — revocation and trust anchoring not available".into());
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

#[cfg(feature = "oid4vp")]
pub(super) fn oid4vp_presentation_proof_passed(result: &Oid4vpCoreVerificationResult) -> bool {
    result.check_valid
        && result.scope == Oid4vpScope::PresentationProof
        && result.evidence.presentation_proof == Oid4vpCheckStatus::Passed
        && result.evidence.transaction_binding == Oid4vpCheckStatus::Passed
}

#[cfg(feature = "oid4vp")]
pub(super) fn oid4vp_presentation_exchange_passed(result: &Oid4vpCoreVerificationResult) -> bool {
    result.check_valid
        && result.scope == Oid4vpScope::PresentationExchange
        && result.evidence.presentation_structure == Oid4vpCheckStatus::Passed
        && result.evidence.presentation_constraints == Oid4vpCheckStatus::Passed
}

#[cfg(feature = "oid4vp")]
pub(super) fn oid4vp_presentation_exchange_errors(
    engine: &VerificationEngine,
    raw: &serde_json::Value,
    vp_token: &str,
) -> Vec<String> {
    let submission = raw.get("presentation_submission");
    let definition = raw.get("presentation_definition");

    let (submission, definition) = match (submission, definition) {
        (None, None) => return vec![],
        (Some(_), None) | (None, Some(_)) => {
            return vec![
                "OID4VP presentation_submission and presentation_definition must be provided together"
                    .into(),
            ];
        }
        (Some(submission), Some(definition)) => (submission, definition),
    };

    let submission: PresentationSubmission = match serde_json::from_value(submission.clone()) {
        Ok(submission) => submission,
        Err(_) => return vec!["OID4VP presentation_submission is malformed".into()],
    };
    let definition: PresentationDefinition = match serde_json::from_value(definition.clone()) {
        Ok(definition) => definition,
        Err(_) => return vec!["OID4VP presentation_definition is malformed".into()],
    };

    // The payload is consumed only after verify_vp_token authenticated the JWT.
    let vp_payload = decode_vp_token_payload(vp_token);
    let result = engine.verify_presentation(&definition, &submission, vp_payload.as_ref());
    if oid4vp_presentation_exchange_passed(&result) {
        return vec![];
    }

    let mut errors: Vec<String> = result
        .errors
        .into_iter()
        .chain(
            result
                .descriptor_results
                .into_iter()
                .filter(|descriptor| !descriptor.valid)
                .filter_map(|descriptor| descriptor.error),
        )
        .collect();
    if errors.is_empty() {
        errors.push("OID4VP presentation exchange checks did not pass".into());
    }
    errors
}

/// Decode the JWT payload segment of a compact VP token (or any JWT) without
/// signature verification.  Returns `None` if the string is not a valid
/// three-part compact JWT with base64url-encoded JSON in the second segment.
#[cfg(feature = "oid4vp")]
pub(super) fn decode_vp_token_payload(token: &str) -> Option<serde_json::Value> {
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

    let holder_proof_valid = oid4vp_presentation_proof_passed(&token_result);
    let structural_errors = if holder_proof_valid {
        oid4vp_presentation_exchange_errors(&engine, &raw, &vp_token)
    } else {
        vec![]
    };

    let holder_presentation_valid = holder_proof_valid && structural_errors.is_empty();

    let mut warnings: Vec<String> =
        vec!["OID4VP offline mode — revocation and trust anchoring not available".into()];
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

/// Online path: POST vp_token to marty-credentials `/v1/verification/verify`.
#[cfg(feature = "oid4vp")]
pub(super) async fn verify_oid4vp_online(
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
