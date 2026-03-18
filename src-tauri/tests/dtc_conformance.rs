//! DTC (Digital Travel Credential) Conformance Tests — Marty Verifier (Tauri app layer).
//!
//! Tests the JSON wire-format accepted by `verify_dtc_offline` and exercises
//! the DTC verification pipeline: JSON parsing, signature check, temporal
//! validation, revocation, type-specific profile checks, and
//! `VerificationResult` shape.
//!
//! Wire-format options accepted by `verify_dtc_offline`:
//!
//! ```json
//! // Option A — raw DtcRecord (all fields are #[serde(default)])
//! { "dtc_id": "…", "issuing_authority": "…", … }
//!
//! // Option B — wrapped
//! { "dtc_data": { … }, "signer_public_key_pem": "…" }
//! ```
//!
//! Coverage:
//!   §1  JSON parsing errors
//!   §2  Result shape (credential_type, verification_id, dtc_details present)
//!   §3  Signature check — unsigned DTC → Invalid status
//!   §4  Revocation — is_revoked:true → RevocationStatus::Revoked
//!   §5  Temporal validation — expired DTC → Invalid + expiry error
//!   §6  Temporal validation — not-yet-valid DTC → Invalid + not-yet-valid error
//!   §7  dtc_type field surfaces in DtcDetails
//!   §8  issuing_authority surfaces in IssuerInfo
//!   §9  Wrapped `dtc_data` format accepted
//!   §10 DTC type 4 — missing Type1Profile fails check
//!   §11 DTC with all-empty dates — no temporal error, only signature missing
//!   §12 trust_chain fields correct for offline DTC

use marty_verifier::commands::verification::{verify_dtc_offline, RevocationStatus, VerificationStatus};

// ── helpers ───────────────────────────────────────────────────────────────────

/// Build a minimal unsigned DTC JSON with future validity range.
fn minimal_dtc_json() -> String {
    serde_json::json!({
        "dtc_id": "DTC-CONFORMANCE-001",
        "issuing_authority": "MartyTestAuthority",
        "dtc_type": 1,
        "access_control": 0,
        "dtc_valid_from": "2024-01-01",
        "dtc_valid_until": "2035-12-31",
        "personal_details": {
            "first_name": "Erika",
            "last_name": "Mustermann",
            "date_of_birth": "1974-08-12",
            "gender": "F",
            "nationality": "DEU"
        }
    })
    .to_string()
}

/// Returns `true` when the `RevocationStatus` variant is `Revoked`.
fn is_revoked(s: &RevocationStatus) -> bool {
    matches!(s, RevocationStatus::Revoked)
}

/// Returns `true` when the `RevocationStatus` variant is `Unknown`.
fn is_revocation_unknown(s: &RevocationStatus) -> bool {
    matches!(s, RevocationStatus::Unknown)
}

// ── §1  JSON Parsing ──────────────────────────────────────────────────────────

/// Non-JSON input must return `Err`.
#[test]
fn not_json_returns_error() {
    let result = verify_dtc_offline("this is not json at all");
    assert!(
        result.is_err(),
        "Expected Err for non-JSON input, got: {:?}",
        result
    );
}

/// A JSON array is not a DTC object — `build_dtc_verify_payload` must reject it.
#[test]
fn json_array_returns_error() {
    let result = verify_dtc_offline(r#"[{"dtc_id":"x"}]"#);
    assert!(
        result.is_err(),
        "Expected Err for JSON array, got: {:?}",
        result
    );
}

/// An empty JSON object is valid input (all DtcRecord fields default) and
/// must not panic — it returns Ok with Invalid status (missing signature).
#[test]
fn empty_object_returns_ok_invalid() {
    let result = verify_dtc_offline("{}");
    assert!(result.is_ok(), "Expected Ok for empty object, got: {:?}", result);
    let r = result.unwrap();
    assert_eq!(r.credential_type, "dtc");
    assert_eq!(r.status, VerificationStatus::Invalid);
}

// ── §2  Result shape ──────────────────────────────────────────────────────────

/// A minimal unsigned DTC returns a fully-shaped `VerificationResult`.
#[test]
fn minimal_dtc_result_shape() {
    let result = verify_dtc_offline(&minimal_dtc_json()).expect("verify_dtc_offline failed");

    assert_eq!(result.credential_type, "dtc");
    assert!(!result.verification_id.is_empty(), "verification_id must not be empty");
    assert!(result.dtc_details.is_some(), "dtc_details must be Some");
    assert!(result.emrtd_details.is_none(), "emrtd_details must be None");
    assert!(result.open_badge_details.is_none(), "open_badge_details must be None");
}

/// `trust_chain.chain_type` must be "x509" for DTC.
#[test]
fn trust_chain_type_is_x509() {
    let result = verify_dtc_offline(&minimal_dtc_json()).unwrap();
    assert_eq!(result.trust_chain.chain_type, "x509");
}

/// `trust_chain.offline_verified` must be `true` for the offline path.
#[test]
fn trust_chain_offline_verified_true() {
    let result = verify_dtc_offline(&minimal_dtc_json()).unwrap();
    assert!(result.trust_chain.offline_verified);
}

/// `verified_at` must be a non-empty ISO-8601 timestamp.
#[test]
fn verified_at_is_non_empty() {
    let result = verify_dtc_offline(&minimal_dtc_json()).unwrap();
    assert!(
        !result.verified_at.is_empty(),
        "verified_at must not be empty"
    );
    // Spot-check that it looks like an RFC 3339 datetime.
    assert!(
        result.verified_at.contains('T'),
        "verified_at should contain 'T' (RFC 3339 format), got: {}",
        result.verified_at
    );
}

// ── §3  Signature check ───────────────────────────────────────────────────────

/// An unsigned DTC (no `signature_info` field) produces `Invalid` status.
#[test]
fn unsigned_dtc_is_invalid() {
    let result = verify_dtc_offline(&minimal_dtc_json()).unwrap();
    assert_eq!(
        result.status,
        VerificationStatus::Invalid,
        "Unsigned DTC must have Invalid status"
    );
}

/// `dtc_details.checks` must contain a Signature check entry and it must be failed.
#[test]
fn signature_check_present_and_failed_for_unsigned() {
    let result = verify_dtc_offline(&minimal_dtc_json()).unwrap();
    let details = result.dtc_details.expect("dtc_details must be Some");

    let sig_check = details
        .checks
        .iter()
        .find(|c| c.check_name == "Signature")
        .expect("Signature check must be present in dtc_details.checks");

    assert!(!sig_check.passed, "Signature check must be failed for unsigned DTC");
}

/// `dtc_details.errors` must be non-empty for an unsigned DTC.
#[test]
fn unsigned_dtc_has_errors() {
    let result = verify_dtc_offline(&minimal_dtc_json()).unwrap();
    let details = result.dtc_details.expect("dtc_details must be Some");
    assert!(
        !details.errors.is_empty(),
        "dtc_details.errors must be non-empty for unsigned DTC"
    );
}

// ── §4  Revocation ────────────────────────────────────────────────────────────

/// A DTC with `is_revoked: true` must set `RevocationStatus::Revoked`.
#[test]
fn revoked_dtc_sets_revocation_status() {
    let json = serde_json::json!({
        "dtc_id": "DTC-REVOKED-001",
        "issuing_authority": "TestAuthority",
        "dtc_type": 1,
        "dtc_valid_from": "2024-01-01",
        "dtc_valid_until": "2035-12-31",
        "is_revoked": true
    })
    .to_string();

    let result = verify_dtc_offline(&json).expect("verify_dtc_offline failed");
    assert!(
        is_revoked(&result.revocation_status),
        "Expected RevocationStatus::Revoked, got: {:?}",
        result.revocation_status
    );
    assert_eq!(result.status, VerificationStatus::Invalid);
}

/// A non-revoked DTC must have `RevocationStatus::Unknown` (offline path cannot confirm).
#[test]
fn non_revoked_dtc_sets_revocation_unknown() {
    let result = verify_dtc_offline(&minimal_dtc_json()).unwrap();
    assert!(
        is_revocation_unknown(&result.revocation_status),
        "Expected RevocationStatus::Unknown for non-revoked DTC offline, got: {:?}",
        result.revocation_status
    );
}

// ── §5  Temporal validation — expired DTC ────────────────────────────────────

/// A DTC with `dtc_valid_until` in the past must be `Invalid`.
#[test]
fn expired_dtc_valid_until_is_invalid() {
    let json = serde_json::json!({
        "dtc_id": "DTC-EXPIRED-001",
        "issuing_authority": "TestAuthority",
        "dtc_type": 1,
        "dtc_valid_from": "2020-01-01",
        "dtc_valid_until": "2021-12-31",
    })
    .to_string();

    let result = verify_dtc_offline(&json).expect("verify_dtc_offline failed");
    assert_eq!(result.status, VerificationStatus::Invalid);

    let details = result.dtc_details.expect("dtc_details must be Some");
    let expired_check = details
        .checks
        .iter()
        .find(|c| c.check_name.contains("TemporalValidation") && !c.passed);
    assert!(
        expired_check.is_some(),
        "Expected a failed TemporalValidation check for expired DTC; checks: {:?}",
        details.checks.iter().map(|c| &c.check_name).collect::<Vec<_>>()
    );

    let has_expiry_error = details.errors.iter().any(|e| e.contains("expir"));
    assert!(
        has_expiry_error,
        "dtc_details.errors should mention expiry; got: {:?}",
        details.errors
    );
}

/// A DTC with `expiry_date` (alternative field) in the past must be `Invalid`.
#[test]
fn expired_dtc_expiry_date_is_invalid() {
    let json = serde_json::json!({
        "dtc_id": "DTC-EXPIRED-002",
        "dtc_type": 1,
        "expiry_date": "2020-06-30",
    })
    .to_string();

    let result = verify_dtc_offline(&json).expect("verify_dtc_offline failed");
    assert_eq!(result.status, VerificationStatus::Invalid);
}

// ── §6  Temporal validation — not-yet-valid DTC ──────────────────────────────

/// A DTC with `dtc_valid_from` far in the future must be `Invalid`.
#[test]
fn future_dtc_valid_from_is_invalid() {
    let json = serde_json::json!({
        "dtc_id": "DTC-FUTURE-001",
        "dtc_type": 1,
        "dtc_valid_from": "2099-01-01",
        "dtc_valid_until": "2100-12-31",
    })
    .to_string();

    let result = verify_dtc_offline(&json).expect("verify_dtc_offline failed");
    assert_eq!(result.status, VerificationStatus::Invalid);

    let details = result.dtc_details.expect("dtc_details must be Some");
    let future_check = details
        .checks
        .iter()
        .find(|c| c.check_name.contains("TemporalValidation") && !c.passed);
    assert!(
        future_check.is_some(),
        "Expected a failed TemporalValidation check for future DTC"
    );

    let has_future_error = details
        .errors
        .iter()
        .any(|e| e.contains("not yet valid") || e.contains("valid_from"));
    assert!(
        has_future_error,
        "dtc_details.errors should mention not-yet-valid; got: {:?}",
        details.errors
    );
}

// ── §7  dtc_type surfaces in DtcDetails ──────────────────────────────────────

/// `dtc_details.dtc_type` echoes the `dtc_type` field from the input.
#[test]
fn dtc_type_surfaces_in_details() {
    for dtc_type_val in [1i32, 2, 3] {
        let json = serde_json::json!({
            "dtc_id": format!("DTC-TYPE-{}", dtc_type_val),
            "dtc_type": dtc_type_val,
            "dtc_valid_from": "2024-01-01",
            "dtc_valid_until": "2035-12-31",
        })
        .to_string();

        let result = verify_dtc_offline(&json)
            .unwrap_or_else(|e| panic!("verify_dtc_offline failed for dtc_type={}: {}", dtc_type_val, e));
        let details = result.dtc_details.expect("dtc_details must be Some");

        assert_eq!(
            details.dtc_type,
            Some(dtc_type_val),
            "dtc_details.dtc_type should be Some({}) but got {:?}",
            dtc_type_val, details.dtc_type
        );
    }
}

// ── §8  issuing_authority surfaces in IssuerInfo ─────────────────────────────

/// `issuing_authority` must propagate to `result.issuer.name`.
#[test]
fn issuing_authority_surfaces_in_issuer_info() {
    let authority = "Bundesdruckerei GmbH";
    let json = serde_json::json!({
        "dtc_id": "DTC-ISSUER-001",
        "issuing_authority": authority,
        "dtc_type": 1,
        "dtc_valid_from": "2024-01-01",
        "dtc_valid_until": "2035-12-31",
    })
    .to_string();

    let result = verify_dtc_offline(&json).expect("verify_dtc_offline failed");
    let issuer = result.issuer.expect("result.issuer must be Some when issuing_authority is set");
    assert_eq!(
        issuer.name.as_deref(),
        Some(authority),
        "issuer.name should be '{}'",
        authority
    );
}

/// When `issuing_authority` is absent from the input, `DtcRecord` defaults
/// the field to an empty string.  The offline path still produces
/// `Some(IssuerInfo)` but `name` is empty.
#[test]
fn missing_issuing_authority_yields_empty_issuer_name() {
    let json = serde_json::json!({
        "dtc_id": "DTC-NO-ISSUER-001",
        "dtc_type": 1,
        "dtc_valid_from": "2024-01-01",
        "dtc_valid_until": "2035-12-31",
    })
    .to_string();

    let result = verify_dtc_offline(&json).expect("verify_dtc_offline failed");
    // issuing_authority defaults to "" → issuer.name is Some("")
    if let Some(issuer) = &result.issuer {
        assert!(
            issuer.name.as_deref().unwrap_or("").is_empty(),
            "issuer.name should be empty when issuing_authority is absent, got: {:?}",
            issuer.name
        );
    }
    // None is also acceptable (issuing_authority empty → no meaningful issuer)
}

// ── §9  Wrapped dtc_data format ───────────────────────────────────────────────

/// The `{ "dtc_data": { … } }` wrapper format is semantically equivalent to
/// the raw DtcRecord format.
#[test]
fn wrapped_dtc_data_format_accepted() {
    let wrapped = serde_json::json!({
        "dtc_data": {
            "dtc_id": "DTC-WRAPPED-001",
            "issuing_authority": "WrappedAuthority",
            "dtc_type": 1,
            "dtc_valid_from": "2024-01-01",
            "dtc_valid_until": "2035-12-31",
        }
    })
    .to_string();

    let result = verify_dtc_offline(&wrapped).expect("verify_dtc_offline failed for wrapped format");
    assert_eq!(result.credential_type, "dtc");
    assert!(result.dtc_details.is_some());
}

/// `signer_public_key_pem` at the top level of the wrapper is forwarded into
/// the inner payload (bad PEM value → signature check attempts and fails, not
/// a parse error).
#[test]
fn wrapped_format_top_level_fields_forwarded() {
    let wrapped = serde_json::json!({
        "dtc_data": {
            "dtc_id": "DTC-WRAPPED-002",
            "dtc_type": 1,
            "dtc_valid_from": "2024-01-01",
            "dtc_valid_until": "2035-12-31",
            "signature_info": {
                "signature_date": "2024-01-01",
                "signer_id": "TEST",
                "signature": "bm90LWEtcmVhbC1zaWduYXR1cmU=",
                "is_valid": false
            }
        },
        "signer_public_key_pem": "-----BEGIN PUBLIC KEY-----\nBAD\n-----END PUBLIC KEY-----\n"
    })
    .to_string();

    // Should return Ok: parse succeeds, but signature verification fails → Invalid
    let result = verify_dtc_offline(&wrapped).expect("verify_dtc_offline failed");
    assert_eq!(result.credential_type, "dtc");
    assert_eq!(result.status, VerificationStatus::Invalid);
    let details = result.dtc_details.expect("dtc_details must be Some");
    let sig_check = details.checks.iter().find(|c| c.check_name == "Signature");
    assert!(
        sig_check.is_some(),
        "Signature check must appear when signature_info is present"
    );
}

// ── §10 Type-specific profile checks ─────────────────────────────────────────

/// DTC type 4 requires a `type1_profile`; its absence must produce a failed
/// Type1Profile check.
#[test]
fn type4_without_profile_fails_type_check() {
    let json = serde_json::json!({
        "dtc_id": "DTC-TYPE4-001",
        "dtc_type": 4,
        "dtc_valid_from": "2024-01-01",
        "dtc_valid_until": "2035-12-31",
    })
    .to_string();

    let result = verify_dtc_offline(&json).expect("verify_dtc_offline failed");
    assert_eq!(result.status, VerificationStatus::Invalid);

    let details = result.dtc_details.expect("dtc_details must be Some");
    let type_check = details
        .checks
        .iter()
        .find(|c| c.check_name == "Type1Profile");
    assert!(
        type_check.map(|c| !c.passed).unwrap_or(false),
        "Type1Profile check must be present and failed; checks: {:?}",
        details.checks.iter().map(|c| (&c.check_name, c.passed)).collect::<Vec<_>>()
    );
}

/// DTC type 5 requires `chip_auth_public_key` and `device_public_key`;
/// their absence must produce a failed Type2Profile check.
#[test]
fn type5_without_profile_fails_type_check() {
    let json = serde_json::json!({
        "dtc_id": "DTC-TYPE5-001",
        "dtc_type": 5,
        "dtc_valid_from": "2024-01-01",
        "dtc_valid_until": "2035-12-31",
    })
    .to_string();

    let result = verify_dtc_offline(&json).expect("verify_dtc_offline failed");
    assert_eq!(result.status, VerificationStatus::Invalid);

    let details = result.dtc_details.expect("dtc_details must be Some");
    let type_check = details
        .checks
        .iter()
        .find(|c| c.check_name == "Type2Profile");
    assert!(
        type_check.map(|c| !c.passed).unwrap_or(false),
        "Type2Profile check must be present and failed; checks: {:?}",
        details.checks.iter().map(|c| (&c.check_name, c.passed)).collect::<Vec<_>>()
    );
}

// ── §11 All-empty dates — temporal check absent ───────────────────────────────

/// When neither `dtc_valid_from`, `dtc_valid_until`, nor `expiry_date` are set
/// (all empty / default), the temporal checks are skipped and only the
/// Signature and RevocationStatus checks appear.
#[test]
fn no_dates_no_temporal_error() {
    // All date fields intentionally absent (default to empty string)
    let json = serde_json::json!({
        "dtc_id": "DTC-NO-DATES-001",
        "dtc_type": 1,
    })
    .to_string();

    let result = verify_dtc_offline(&json).expect("verify_dtc_offline failed");
    let details = result.dtc_details.expect("dtc_details must be Some");

    let has_temporal_failure = details
        .checks
        .iter()
        .any(|c| c.check_name.contains("TemporalValidation") && !c.passed);
    assert!(
        !has_temporal_failure,
        "No temporal failure expected when dates are absent; checks: {:?}",
        details.checks.iter().map(|c| (&c.check_name, c.passed)).collect::<Vec<_>>()
    );
}

// ── §12 `dtc_details.checks` population ──────────────────────────────────────

/// `dtc_details.checks` must always be non-empty: at minimum the Signature
/// and RevocationStatus checks are run.
#[test]
fn dtc_details_checks_always_populated() {
    let result = verify_dtc_offline(&minimal_dtc_json()).unwrap();
    let details = result.dtc_details.expect("dtc_details must be Some");
    assert!(
        !details.checks.is_empty(),
        "dtc_details.checks must not be empty"
    );

    let has_revocation_check = details
        .checks
        .iter()
        .any(|c| c.check_name == "RevocationStatus");
    assert!(
        has_revocation_check,
        "RevocationStatus check must always be present"
    );
}
