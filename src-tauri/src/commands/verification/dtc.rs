//! Dtc verification operations.

use super::{
    extract_string_list, parse_json_input, AppError, AppResult, AppState, Certificate,
    CoreTrustAnchorType, DateTime, DtcDetails, Duration, HashSet, IssuerInfo, RevocationStatus,
    TrustAnchorRecord, TrustChainStatus, Utc, Value, VerificationCheck, VerificationCheckOutcome,
    VerificationResult, VerificationStatus, VerifyRequest, BASE64_STANDARD,
};
use base64::Engine;
use x509_cert::der::Decode;

pub(super) async fn verify_dtc_payload(
    request: &VerifyRequest,
    state: &AppState,
    is_online: bool,
) -> AppResult<VerificationResult> {
    let raw = parse_json_input(&request.credential_data, "DTC")?;
    let supplied_trust_anchors = dtc_contains_presented_trust_anchors(&raw);
    let records = state
        .trust_storage
        .get_trust_anchor_records(CoreTrustAnchorType::Csca, None)
        .await?;
    let max_offline_hours = state.config.read().await.sync_config.max_offline_hours;
    let (governed_trust_anchors, rejected_records) =
        build_governed_dtc_csca_store(&records, Utc::now(), max_offline_hours)?;
    let payload = build_dtc_verify_payload(&raw, &governed_trust_anchors)?;
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
    if supplied_trust_anchors {
        tracing::warn!("Ignoring credential-supplied DTC trust anchors");
        warnings.push("Credential-supplied DTC trust anchors were ignored".to_string());
    }
    if rejected_records > 0 {
        warnings.push(format!(
            "Ignored {rejected_records} CSCA trust record(s) without authenticated package provenance"
        ));
    }
    if governed_trust_anchors.is_empty() {
        warnings.push("Governed DTC CSCA trust store is empty".to_string());
    }
    if let Some(msg) = value.get("error_message").and_then(|v| v.as_str()) {
        if !msg.is_empty() {
            warnings.push(msg.to_string());
        }
    }
    if !is_online {
        warnings.push("DTC verification used locally cached governed trust data".to_string());
    }

    let trust_chain_valid = dtc_trust_chain_valid(&checks);
    let revocation_status = parse_dtc_revocation_status(&value, &checks);

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

pub(super) fn build_dtc_verify_payload(
    raw: &Value,
    governed_trust_anchors: &[String],
) -> AppResult<Value> {
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
        obj.remove("trust_anchors_pem");
        for key in ["signer_public_key_pem", "certificate_chain_pem"] {
            if let Some(value) = raw.get(key) {
                obj.insert(key.to_string(), value.clone());
            }
        }
        obj.insert(
            "trust_anchors_pem".to_string(),
            Value::Array(
                governed_trust_anchors
                    .iter()
                    .cloned()
                    .map(Value::String)
                    .collect(),
            ),
        );
    }

    Ok(payload)
}

pub(super) fn dtc_contains_presented_trust_anchors(raw: &Value) -> bool {
    raw.get("trust_anchors_pem").is_some()
        || raw
            .get("dtc_data")
            .and_then(Value::as_object)
            .is_some_and(|dtc| dtc.contains_key("trust_anchors_pem"))
}

pub(super) fn build_governed_dtc_csca_store(
    records: &[TrustAnchorRecord],
    now: DateTime<Utc>,
    max_offline_hours: u32,
) -> AppResult<(Vec<String>, usize)> {
    let mut anchors = Vec::new();
    let mut seen = HashSet::new();
    let mut rejected_records = 0;

    for record in records {
        if !governed_csca_record_is_usable(record, now, max_offline_hours) {
            rejected_records += 1;
            continue;
        }
        if !seen.insert(record.anchor.certificate_hash.as_str()) {
            continue;
        }

        Certificate::from_der(&record.anchor.certificate_der).map_err(|_| {
            AppError::Verification("Stored governed DTC CSCA certificate is malformed".to_string())
        })?;
        anchors.push(certificate_der_to_pem(&record.anchor.certificate_der));
    }

    Ok((anchors, rejected_records))
}

pub(super) fn governed_csca_record_is_usable(
    record: &TrustAnchorRecord,
    now: DateTime<Utc>,
    max_offline_hours: u32,
) -> bool {
    let Some(provenance) = record.provenance.as_ref() else {
        return false;
    };
    let maximum_age = Duration::hours(i64::from(max_offline_hours));
    provenance.created_at <= now
        && provenance.imported_at <= now
        && provenance.created_at < provenance.expires_at
        && provenance.expires_at > now
        && now - provenance.created_at <= maximum_age
        && record.anchor.synced_at == provenance.created_at
        && record.anchor.not_before.is_none_or(|value| value <= now)
        && record.anchor.not_after.is_none_or(|value| value > now)
}

pub(super) fn certificate_der_to_pem(certificate_der: &[u8]) -> String {
    let encoded = BASE64_STANDARD.encode(certificate_der);
    let mut pem = String::from("-----BEGIN CERTIFICATE-----\n");
    for start in (0..encoded.len()).step_by(64) {
        let end = (start + 64).min(encoded.len());
        pem.push_str(&encoded[start..end]);
        pem.push('\n');
    }
    pem.push_str("-----END CERTIFICATE-----\n");
    pem
}

pub(super) fn parse_dtc_checks(value: &Value) -> Vec<VerificationCheck> {
    value
        .get("verification_results")
        .and_then(|v| v.as_array())
        .map(|items| {
            items
                .iter()
                .filter_map(|item| {
                    let check_name = item.get("check_name")?.as_str()?.to_string();
                    let outcome = parse_dtc_check_outcome(item);
                    let passed = outcome == VerificationCheckOutcome::Passed;
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
                        outcome,
                        passed,
                        details,
                        error_code,
                    })
                })
                .collect()
        })
        .unwrap_or_default()
}

pub(super) fn parse_dtc_check_outcome(item: &Value) -> VerificationCheckOutcome {
    let outcome = match item.get("outcome").and_then(Value::as_str) {
        Some("PASSED") => VerificationCheckOutcome::Passed,
        Some("FAILED") => VerificationCheckOutcome::Failed,
        Some("NOT_PERFORMED") => VerificationCheckOutcome::NotPerformed,
        Some("ERROR") => VerificationCheckOutcome::Error,
        _ => return VerificationCheckOutcome::Error,
    };

    // Core retains `passed` as a compatibility projection. Reject a missing or
    // contradictory projection rather than allowing malformed output to pass.
    if item.get("passed").and_then(Value::as_bool)
        != Some(outcome == VerificationCheckOutcome::Passed)
    {
        return VerificationCheckOutcome::Error;
    }

    outcome
}

pub(super) fn parse_dtc_revocation_status(
    value: &Value,
    checks: &[VerificationCheck],
) -> RevocationStatus {
    match value.get("revocation_status").and_then(Value::as_str) {
        // Current-good is accepted only when Core's explicit status and check
        // agree. Missing, duplicate, or malformed evidence remains unknown.
        Some("GOOD") if exactly_one_dtc_check_passed(checks, "RevocationStatus") => {
            RevocationStatus::Valid
        }
        Some("REVOKED") => RevocationStatus::Revoked,
        Some("GOOD") | Some("UNKNOWN") | Some(_) | None => RevocationStatus::Unknown,
    }
}

pub(super) fn dtc_trust_chain_valid(checks: &[VerificationCheck]) -> bool {
    exactly_one_dtc_check_passed(checks, "TrustChain")
        && exactly_one_dtc_check_passed(checks, "SignerKeyMatchesCertificate")
}

pub(super) fn exactly_one_dtc_check_passed(checks: &[VerificationCheck], check_name: &str) -> bool {
    let mut matching = checks.iter().filter(|check| check.check_name == check_name);
    match (matching.next(), matching.next()) {
        (Some(check), None) => check.outcome == VerificationCheckOutcome::Passed,
        _ => false,
    }
}

pub(super) fn build_dtc_claims(dtc_data: &Value) -> Value {
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

/// Testable offline entry point for DTC verification (no `AppState`).
///
/// Accepts the same JSON shape as `verify_credential` for `credential_type == "dtc"`.
/// Unlike the Tauri command path, this function is synchronous and requires no
/// app state, making it suitable for unit and integration tests.
pub fn verify_dtc_offline(
    credential_data_json: &str,
) -> crate::error::AppResult<VerificationResult> {
    let raw = parse_json_input(credential_data_json, "DTC")?;
    let supplied_trust_anchors = dtc_contains_presented_trust_anchors(&raw);
    let payload = build_dtc_verify_payload(&raw, &[])?;
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
    if supplied_trust_anchors {
        warnings.push("Credential-supplied DTC trust anchors were ignored".to_string());
    }
    warnings.push(
        "Offline helper has no governed CSCA store; DTC trust cannot be established".to_string(),
    );

    let trust_chain_valid = dtc_trust_chain_valid(&checks);
    let revocation_status = parse_dtc_revocation_status(&value, &checks);

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
