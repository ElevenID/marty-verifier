//! Open Badges 3.0 conformance and retired OB2 rejection at the Tauri boundary.
//!
//! The supported wire formats are a raw OB3 credential or a request with a
//! `credential` field and optional `document_store`. Historical OB2 assertions
//! remain below as negative vectors; neither raw assertions nor the retired
//! `assertion` request wrapper may enter a verification path.
//!
//! Positive signature tests use the reviewed public-only OB3 vector. The
//! offline helper accepts supplied public key documents without a database;
//! production trust-store enrollment is tested separately.

use marty_verifier::commands::verification::{verify_open_badge_offline, VerificationStatus};

// Retired OB2 context retained only for rejection vectors.
const OBV2_CONTEXT: &str = "https://w3id.org/openbadges/v2";
// ── OBv3 context constant (matches contexts.rs CONTEXT_OPENBADGES_V3) ────────
const OBV3_CONTEXT: &str = "https://purl.imsglobal.org/spec/ob/v3p0/context.json";

// ── helpers ───────────────────────────────────────────────────────────────────

/// Historical hosted OB2 assertion, retained as a negative vector.
/// It must be rejected before any trust or cryptographic verification.
fn ob2_hosted_assertion() -> serde_json::Value {
    serde_json::json!({
        "@context": OBV2_CONTEXT,
        "type": "Assertion",
        "id": "https://example.org/assertions/conformance-001",
        "badge": {
            "type": "BadgeClass",
            "id": "https://example.org/badges/conformance",
            "name": "Conformance Test Badge",
            "description": "Awarded by the Marty conformance suite.",
            "image": "https://example.org/badge.png",
            "criteria": { "narrative": "Pass the conformance tests." },
            "issuer": {
                "type": "Issuer",
                "id": "https://example.org",
                "name": "Marty Test Issuer",
                "url": "https://example.org"
            }
        },
        "recipient": {
            "type": "email",
            "identity": "test@example.org",
            "hashed": false
        },
        "issuedOn": "2024-01-01T00:00:00Z",
        "verification": { "type": "HostedBadge" }
    })
}

// ── §1  JSON Parsing ──────────────────────────────────────────────────────────

/// Non-JSON input must return `Err`.
#[tokio::test]
async fn not_json_returns_error() {
    let result = verify_open_badge_offline("this is not json at all").await;
    assert!(
        result.is_err(),
        "Expected Err for non-JSON input, got: {:?}",
        result
    );
}

/// Plain text (looks like a string but is not valid JSON object/array) must
/// return `Err`.
#[tokio::test]
async fn bare_string_returns_error() {
    let result = verify_open_badge_offline(r#""just a string""#).await;
    assert!(
        result.is_err(),
        "Expected Err for bare JSON string, got: {:?}",
        result
    );
}

// ── §2  Unknown version ───────────────────────────────────────────────────────

/// An empty JSON object has no recognisable Open Badges context → `Err`.
#[tokio::test]
async fn empty_object_unknown_version_returns_error() {
    let result = verify_open_badge_offline("{}").await;
    assert!(
        result.is_err(),
        "Expected Err for unknown-version input, got Ok: {:?}",
        result.as_ref().ok()
    );
    let msg = result.unwrap_err().to_string();
    assert!(
        msg.contains("detect") || msg.contains("version") || msg.contains("Open Badge"),
        "Error message should mention version detection, got: {msg}"
    );
}

/// A JSON object without any `@context` key must be rejected as unknown version.
#[tokio::test]
async fn no_context_field_returns_error() {
    let json = serde_json::json!({
        "type": "Assertion",
        "id": "https://example.org/assertions/no-context"
    })
    .to_string();
    let result = verify_open_badge_offline(&json).await;
    assert!(
        result.is_err(),
        "Expected Err for missing @context, got: {:?}",
        result
    );
}

/// A JSON array is not a badge object → `Err`.
#[tokio::test]
async fn json_array_returns_error() {
    let result = verify_open_badge_offline(r#"[{"type":"Assertion"}]"#).await;
    assert!(
        result.is_err(),
        "Expected Err for JSON array, got: {:?}",
        result
    );
}

async fn assert_ob2_retired(value: serde_json::Value) {
    let error = verify_open_badge_offline(&value.to_string())
        .await
        .expect_err("retired OB2 input must not produce a verification result");
    let message = error.to_string();
    assert!(
        message.contains("Open Badges 2.0 is retired") && message.contains("Open Badges 3.0"),
        "Retired input must explain the migration: {message}"
    );
}

#[tokio::test]
async fn ob2_raw_and_context_array_are_retired() {
    let assertion = ob2_hosted_assertion();
    assert_ob2_retired(assertion.clone()).await;
    let mut context_array = assertion;
    context_array["@context"] = serde_json::json!([OBV2_CONTEXT]);
    assert_ob2_retired(context_array).await;
}

#[tokio::test]
async fn ob2_wrappers_are_retired() {
    let assertion = ob2_hosted_assertion();
    for field in ["assertion", "credential", "vc"] {
        let mut wrapper = serde_json::Map::new();
        wrapper.insert(field.to_string(), assertion.clone());
        assert_ob2_retired(serde_json::Value::Object(wrapper)).await;
    }
}

#[tokio::test]
async fn ob2_partial_and_malformed_assertions_still_report_retirement() {
    let mut missing_context = ob2_hosted_assertion();
    missing_context.as_object_mut().unwrap().remove("@context");
    assert_ob2_retired(missing_context.clone()).await;
    assert_ob2_retired(serde_json::json!({ "assertion": missing_context })).await;

    let mut wrong_context = ob2_hosted_assertion();
    wrong_context["@context"] = serde_json::json!("https://schema.org/");
    assert_ob2_retired(wrong_context).await;

    let mut missing_type = ob2_hosted_assertion();
    missing_type.as_object_mut().unwrap().remove("type");
    assert_ob2_retired(missing_type).await;

    let mut missing_issuer = ob2_hosted_assertion();
    missing_issuer["badge"]
        .as_object_mut()
        .unwrap()
        .remove("issuer");
    assert_ob2_retired(missing_issuer).await;

    let mut unresolved_badge = ob2_hosted_assertion();
    unresolved_badge["badge"] = serde_json::json!("https://example.org/badges/unreachable");
    assert_ob2_retired(unresolved_badge).await;
}

#[tokio::test]
async fn mixed_ob2_and_ob3_inputs_cannot_use_the_ob3_path() {
    let mut credential = signed_ob3_public_request()["credential"].clone();
    credential["@context"]
        .as_array_mut()
        .unwrap()
        .push(serde_json::json!(OBV2_CONTEXT));
    assert_ob2_retired(credential).await;

    let mut credential = signed_ob3_public_request()["credential"].clone();
    credential["type"]
        .as_array_mut()
        .unwrap()
        .push(serde_json::json!("Assertion"));
    assert_ob2_retired(serde_json::json!({ "credential": credential })).await;

    let mut request = signed_ob3_public_request();
    request["assertion"] = ob2_hosted_assertion();
    assert_ob2_retired(request).await;
}

#[tokio::test]
async fn retired_assertion_wrapper_is_not_an_alias_for_ob3() {
    let credential = signed_ob3_public_request()["credential"].clone();
    assert_ob2_retired(serde_json::json!({ "assertion": credential })).await;
    assert_ob2_retired(serde_json::json!({ "assertion": null })).await;
}

// ── OBv3 — parse error returns Err ───────────────────────────────────────

/// A raw JSON object with an OBv3 context but no valid VC structure (missing
/// `issuer`, `@type`, proof, etc.) cannot be deserialized by the SSI library
/// and must therefore return `Err`, not panic.
#[tokio::test]
async fn ob3_malformed_vc_returns_error() {
    let json = serde_json::json!({
        "@context": [
            "https://www.w3.org/2018/credentials/v1",
            OBV3_CONTEXT
        ],
        "type": ["VerifiableCredential", "OpenBadgeCredential"],
        "id": "https://example.org/vc/1"
        // missing issuer, credentialSubject, proof → SSI parse failure
    })
    .to_string();

    let result = verify_open_badge_offline(&json).await;
    assert!(
        result.is_err(),
        "Malformed OBv3 credential must return Err, got Ok"
    );
}

// ── OBv3 wrapper `{ "credential": … }` ───────────────────────────────────

/// When the outer key is `"credential"` the version is detected as V3 and
/// the OBv3 path is taken.  The SSI library can still deserialise a VC
/// without a proof; the proof check then fails and is recorded as an error
/// in the verify result.  The function returns `Ok(VerificationResult)`
/// with `status = Invalid` and a proof-related error in `open_badge_details`.
#[tokio::test]
async fn ob3_credential_wrapper_takes_v3_path() {
    let minimal_v3 = serde_json::json!({
        "@context": [
            "https://www.w3.org/2018/credentials/v1",
            OBV3_CONTEXT
        ],
        "type": ["VerifiableCredential", "OpenBadgeCredential"],
        "issuer": "https://example.org",
        "issuanceDate": "2024-01-01T00:00:00Z",
        "credentialSubject": {
            "type": "AchievementSubject",
            "achievement": { "name": "Test" }
        }
        // no proof
    });
    let wrapped = serde_json::json!({ "credential": minimal_v3 }).to_string();

    let result = verify_open_badge_offline(&wrapped)
        .await
        .expect("verify_open_badge_offline should return Ok for V3 credential");

    // SSI deserialises the VC without a proof, then the proof check fails.
    assert_eq!(
        result.status,
        VerificationStatus::Invalid,
        "OBv3 without proof must be Invalid"
    );
    assert_eq!(result.credential_type, "open-badge");
    let details = result
        .open_badge_details
        .expect("open_badge_details must be Some");
    assert_eq!(details.version, "3.0", "Version label must be '3.0'");
    let has_proof_error = details
        .errors
        .iter()
        .any(|e| e.to_lowercase().contains("proof") || e.to_lowercase().contains("invalid"));
    assert!(
        has_proof_error,
        "Expected a proof-related error for missing-proof OBv3; got: {:?}",
        details.errors
    );
}

// ── OBv3 signed credential — DataIntegrityProof (Ed25519) ─────────────────
//
// These tests use Core's reviewed public-only OBv3 Ed25519 signature vector.
// The credential is verified with its public method in `document_store`;
// tampering that method must still fail without local issuer signing.
// The fixed signature also preserves a real cryptographic verification path.

/// Reviewed public-only OBv3 signature vector shared with Marty Core's
/// conformance suite. Verification must not create or handle an issuer key.
fn signed_ob3_public_request() -> serde_json::Value {
    let vector: serde_json::Value =
        serde_json::from_str(include_str!("fixtures/open_badges_ob3_public.json"))
            .expect("public OBv3 vector is valid JSON");
    let vm_id = vector["credential"]["proof"]["verificationMethod"]
        .as_str()
        .expect("public OBv3 vector has verification method");
    let controller = vector["did"]
        .as_str()
        .expect("public OBv3 vector has controller")
        .split('#')
        .next()
        .expect("public OBv3 controller is nonempty");
    let mut document_store = serde_json::Map::new();
    document_store.insert(
        vm_id.to_owned(),
        json_web_key_vm_doc(vm_id, controller, &vector["public_jwk"]),
    );
    serde_json::json!({
        "credential": vector["credential"],
        "document_store": document_store,
    })
}

/// Build a `JsonWebKey2020` verification-method document for the document store.
fn json_web_key_vm_doc(
    vm_id: &str,
    controller: &str,
    public_jwk: &serde_json::Value,
) -> serde_json::Value {
    serde_json::json!({
        "id": vm_id,
        "type": "JsonWebKey2020",
        "controller": controller,
        "publicKeyJwk": public_jwk
    })
}

/// A correctly signed OBv3 credential (JsonWebSignature2020 over Ed25519)
/// verifies as `Valid` when the verification method is in the document store.
#[tokio::test]
async fn ob3_signed_credential_with_jwk2020_is_valid() {
    let request = signed_ob3_public_request();

    let result = verify_open_badge_offline(&request.to_string())
        .await
        .expect("verify_open_badge_offline failed");

    assert_eq!(
        result.status,
        VerificationStatus::Valid,
        "Signed OBv3 credential must be Valid; errors: {:?}",
        result.open_badge_details.as_ref().map(|d| &d.errors)
    );
    assert!(!result.verification_id.is_empty());
    assert!(result.emrtd_details.is_none());
    assert!(result.dtc_details.is_none());
    assert!(result.trust_chain.offline_verified);
    assert_eq!(result.trust_chain.chain_type, "did");
    assert!(result
        .warnings
        .iter()
        .any(|warning| warning.contains("offline")));
}

/// The signed credential's `open_badge_details.version` must be `"3.0"`.
#[tokio::test]
async fn ob3_signed_credential_version_label_is_three_point_zero() {
    let request = signed_ob3_public_request();

    let result = verify_open_badge_offline(&request.to_string())
        .await
        .expect("verify_open_badge_offline failed");

    let details = result
        .open_badge_details
        .expect("open_badge_details must be Some");
    assert_eq!(details.version, "3.0");
}

/// The `credential_type` field must be `"open-badge"` for a signed OBv3 credential.
#[tokio::test]
async fn ob3_signed_credential_type_field_is_open_badge() {
    let request = signed_ob3_public_request();

    let result = verify_open_badge_offline(&request.to_string())
        .await
        .expect("verify_open_badge_offline failed");

    assert_eq!(result.credential_type, "open-badge");
}

/// Using the wrong public key in the document store (key mismatch) must
/// produce `Invalid` status with a proof-related error.
#[tokio::test]
async fn ob3_signed_credential_wrong_public_key_is_invalid() {
    let mut request = signed_ob3_public_request();
    let vm_id = request["credential"]["proof"]["verificationMethod"]
        .as_str()
        .expect("public OBv3 vector has verification method")
        .to_owned();
    // Match Core's reviewed substituted-public-key negative vector.
    request["document_store"][&vm_id]["publicKeyJwk"]["x"] =
        serde_json::json!("11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo");

    let result = verify_open_badge_offline(&request.to_string())
        .await
        .expect("verify_open_badge_offline should return Ok");

    assert_eq!(
        result.status,
        VerificationStatus::Invalid,
        "Wrong public key must yield Invalid; errors: {:?}",
        result.open_badge_details.as_ref().map(|d| &d.errors)
    );
}
