//! Open Badges v2 / v3 Conformance Tests — Marty Verifier (Tauri app layer).
//!
//! Tests the JSON wire-format accepted by `verify_open_badge_offline` covering
//! version detection, result shape, error propagation, and the `FailOpen` trust
//! policy used by the offline path (empty trusted-key store, embedded key
//! documents accepted without prior enrollment).
//!
//! Wire-format options:
//!
//! ```json
//! // Option A — raw credential (version auto-detected from @context)
//! { "@context": "https://w3id.org/openbadges/v2", "type": "Assertion", … }
//!
//! // Option B — OBv2 wrapper
//! { "assertion": { "@context": "https://w3id.org/openbadges/v2", … } }
//!
//! // Option C — OBv3 wrapper
//! { "credential": { "@context": "https://purl.imsglobal.org/spec/ob/v3p0/context.json", … } }
//! ```
//!
//! All tests call the `async` function via `#[tokio::test]`.
//!
//! Coverage:
//!   §1  JSON parsing errors
//!   §2  Unknown-version error
//!   §3  OBv2 hosted-badge happy path — raw credential
//!   §4  OBv2 hosted-badge happy path — explicit `assertion` wrapper
//!   §5  OBv2 result shape (credential_type, verification_id, open_badge_details)
//!   §6  OBv2 version label in open_badge_details
//!   §7  OBv2 — missing @context produces context error
//!   §8  OBv2 — missing Assertion type produces type error
//!   §9  OBv2 — inline badge without inline issuer produces issuer-missing error
//!   §10 OBv2 offline warning always present
//!   §11 OBv3 context triggers V3 path (parse error → Err, not panic)
//!   §12 OBv3 wrapper `{ "credential": … }` is forwarded to OBv3 path
//!   §13 OBv3 signed credential — valid Ed25519 DataIntegrityProof → Valid

use marty_verifier::commands::verification::{verify_open_badge_offline, VerificationStatus};

// ── OBv2 context constant (matches contexts.rs CONTEXT_OPENBADGES_V2) ────────
const OBV2_CONTEXT: &str = "https://w3id.org/openbadges/v2";
// ── OBv3 context constant (matches contexts.rs CONTEXT_OPENBADGES_V3) ────────
const OBV3_CONTEXT: &str = "https://purl.imsglobal.org/spec/ob/v3p0/context.json";

// ── helpers ───────────────────────────────────────────────────────────────────

/// Minimal OBv2 Assertion with inline badge and issuer.
///
/// Uses `verification.type = "HostedBadge"` so no cryptographic proof is
/// required; the verifier adds a warning rather than an error.
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
    assert!(result.is_err(), "Expected Err for missing @context, got: {:?}", result);
}

/// A JSON array is not a badge object → `Err`.
#[tokio::test]
async fn json_array_returns_error() {
    let result = verify_open_badge_offline(r#"[{"type":"Assertion"}]"#).await;
    assert!(result.is_err(), "Expected Err for JSON array, got: {:?}", result);
}

// ── §3  OBv2 hosted-badge happy path — raw credential ────────────────────────

/// A well-formed Hosted OBv2 assertion supplied as-is (not wrapped) must
/// return `Ok` with `status = Valid`.
#[tokio::test]
async fn ob2_raw_hosted_assertion_is_valid() {
    let json = ob2_hosted_assertion().to_string();
    let result = verify_open_badge_offline(&json)
        .await
        .expect("verify_open_badge_offline failed");

    assert_eq!(
        result.status,
        VerificationStatus::Valid,
        "Hosted OBv2 assertion should be Valid; errors: {:?}",
        result
            .open_badge_details
            .as_ref()
            .map(|d| &d.errors)
    );
}

/// Same assertion passes with a JSON @context array that includes the OBv2 URI.
#[tokio::test]
async fn ob2_context_array_is_accepted() {
    let mut assertion = ob2_hosted_assertion();
    assertion["@context"] = serde_json::json!([OBV2_CONTEXT]);
    let result = verify_open_badge_offline(&assertion.to_string())
        .await
        .expect("verify_open_badge_offline failed");
    assert_eq!(result.status, VerificationStatus::Valid);
}

// ── §4  OBv2 hosted-badge happy path — explicit `assertion` wrapper ───────────

/// Same assertion wrapped in `{ "assertion": … }` must also return `Valid`.
#[tokio::test]
async fn ob2_explicit_assertion_wrapper_is_valid() {
    let wrapped = serde_json::json!({ "assertion": ob2_hosted_assertion() }).to_string();
    let result = verify_open_badge_offline(&wrapped)
        .await
        .expect("verify_open_badge_offline failed for wrapped assertion");
    assert_eq!(result.status, VerificationStatus::Valid);
}

// ── §5  OBv2 result shape ─────────────────────────────────────────────────────

/// The `VerificationResult` for a valid OBv2 badge must carry the expected fields.
#[tokio::test]
async fn ob2_result_shape() {
    let json = ob2_hosted_assertion().to_string();
    let result = verify_open_badge_offline(&json)
        .await
        .expect("verify_open_badge_offline failed");

    assert_eq!(result.credential_type, "open-badge");
    assert!(
        !result.verification_id.is_empty(),
        "verification_id must not be empty"
    );
    assert!(result.open_badge_details.is_some(), "open_badge_details must be Some");
    assert!(result.emrtd_details.is_none(), "emrtd_details must be None");
    assert!(result.dtc_details.is_none(), "dtc_details must be None");
}

/// `trust_chain.offline_verified` must be `true` for the offline path.
#[tokio::test]
async fn ob2_trust_chain_offline_verified() {
    let json = ob2_hosted_assertion().to_string();
    let result = verify_open_badge_offline(&json).await.unwrap();
    assert!(result.trust_chain.offline_verified);
}

// ── §6  OBv2 version label ────────────────────────────────────────────────────

/// `open_badge_details.version` must report `"2.0"` for an OBv2 assertion.
#[tokio::test]
async fn ob2_version_label_is_two_point_zero() {
    let json = ob2_hosted_assertion().to_string();
    let result = verify_open_badge_offline(&json).await.unwrap();
    let details = result.open_badge_details.expect("open_badge_details must be Some");
    assert_eq!(
        details.version, "2.0",
        "OBv2 version label must be '2.0', got: {}",
        details.version
    );
}

// ── §7  OBv2 — missing @context ───────────────────────────────────────────────

/// An assertion where `@context` is a different URI (not OBv2) that nevertheless
/// contains `"Assertion"` type but wrong context must be detected as v2 only if
/// context matches.  When no known context is present the call returns `Err`
/// (unknown version) rather than an `Ok` with errors.
///
/// This test verifies that the context-detection gate fires *before* the
/// verifier layer.
#[tokio::test]
async fn ob2_wrong_context_uri_is_unknown_version() {
    let json = serde_json::json!({
        "@context": "https://schema.org/",
        "type": "Assertion",
        "badge": { "type": "BadgeClass", "name": "Test",
                    "issuer": { "type": "Issuer", "name": "Test", "url": "https://example.org" } },
        "verification": { "type": "HostedBadge" }
    })
    .to_string();

    let result = verify_open_badge_offline(&json).await;
    assert!(
        result.is_err(),
        "Non-OB context should be rejected as unknown version, got Ok: {:?}",
        result.as_ref().ok()
    );
}

/// A correctly-shaped OBv2 assertion but with `@context` removed returns `Err`
/// (unknown version — not an `Ok` with errors).
#[tokio::test]
async fn ob2_missing_context_is_unknown_version() {
    let mut assertion = ob2_hosted_assertion();
    assertion
        .as_object_mut()
        .unwrap()
        .remove("@context");
    let result = verify_open_badge_offline(&assertion.to_string()).await;
    assert!(
        result.is_err(),
        "Assertion without @context should be Err (unknown version), got Ok"
    );
}

/// An OBv2 assertion that has the context but is missing `@context` in
/// the *wrapped* format (i.e., the assertion value has no context) must
/// return `Err` because version detection runs on the *inner* value:
/// `detect_open_badges_version` finds no OBv2 context → `Unknown` → `Err`.
#[tokio::test]
async fn ob2_wrapped_missing_context_returns_error() {
    let mut inner = ob2_hosted_assertion();
    inner.as_object_mut().unwrap().remove("@context");

    let wrapped = serde_json::json!({ "assertion": inner }).to_string();
    // Version is detected from the inner value, not the wrapper key:
    // inner has no @context → Unknown → Err.
    let result = verify_open_badge_offline(&wrapped).await;
    assert!(
        result.is_err(),
        "Wrapped assertion without @context must return Err (Unknown version), got Ok"
    );
}

// ── §8  OBv2 — missing Assertion type ────────────────────────────────────────

/// An OBv2 assertion where `type` is absent or wrong must be `Invalid` with a
/// type-related error.
#[tokio::test]
async fn ob2_missing_type_returns_invalid() {
    let mut assertion = ob2_hosted_assertion();
    assertion.as_object_mut().unwrap().remove("type");
    let result = verify_open_badge_offline(&assertion.to_string())
        .await
        .expect("verify_open_badge_offline failed for missing-type assertion");

    assert_eq!(result.status, VerificationStatus::Invalid);
    let details = result.open_badge_details.expect("open_badge_details must be Some");
    let has_type_error = details
        .errors
        .iter()
        .any(|e| e.to_lowercase().contains("type") || e.to_lowercase().contains("assertion"));
    assert!(
        has_type_error,
        "Expected a type-related error; got: {:?}",
        details.errors
    );
}

// ── §9  OBv2 — badge without inline issuer ───────────────────────────────────

/// When the `badge` object omits the `issuer` field altogether the verifier
/// must return `Invalid` with an issuer-related error (badge resolve is Ok,
/// but issuer resolve fails).
#[tokio::test]
async fn ob2_badge_without_issuer_is_invalid() {
    let json = serde_json::json!({
        "@context": OBV2_CONTEXT,
        "type": "Assertion",
        "badge": {
            "type": "BadgeClass",
            "name": "No-Issuer Badge"
            // no "issuer" key
        },
        "verification": { "type": "HostedBadge" }
    })
    .to_string();

    let result = verify_open_badge_offline(&json)
        .await
        .expect("verify_open_badge_offline failed");

    assert_eq!(result.status, VerificationStatus::Invalid);
    let details = result.open_badge_details.expect("open_badge_details must be Some");
    let has_issuer_error = details
        .errors
        .iter()
        .any(|e| e.to_lowercase().contains("issuer"));
    assert!(
        has_issuer_error,
        "Expected issuer-related error; got: {:?}",
        details.errors
    );
}

/// When `badge` is a string URL reference the verifier attempts document-store
/// resolution.  With an empty store this must fail to resolve the badge and
/// return `Invalid`.
#[tokio::test]
async fn ob2_badge_url_reference_unresolvable_is_invalid() {
    let json = serde_json::json!({
        "@context": OBV2_CONTEXT,
        "type": "Assertion",
        "badge": "https://example.org/badges/unreachable",
        "verification": { "type": "HostedBadge" }
    })
    .to_string();

    let result = verify_open_badge_offline(&json)
        .await
        .expect("verify_open_badge_offline failed");

    assert_eq!(result.status, VerificationStatus::Invalid);
}

// ── §10 OBv2 offline warning ──────────────────────────────────────────────────

/// The offline path must always carry a warning that the empty trust store has
/// been used (so callers are aware this is not a fully-trusted verification).
#[tokio::test]
async fn ob2_offline_warning_present() {
    let json = ob2_hosted_assertion().to_string();
    let result = verify_open_badge_offline(&json).await.unwrap();
    let has_offline_warning = result
        .warnings
        .iter()
        .any(|w| w.to_lowercase().contains("offline") || w.to_lowercase().contains("trust"));
    assert!(
        has_offline_warning,
        "Expected an offline / trust-store warning; got: {:?}",
        result.warnings
    );
}

/// The hosted-assertion warning ("Hosted assertion not cryptographically verified")
/// is passed through by the offline path as part of `open_badge_details.warnings`.
#[tokio::test]
async fn ob2_hosted_assertion_carries_crypto_warning() {
    let json = ob2_hosted_assertion().to_string();
    let result = verify_open_badge_offline(&json).await.unwrap();
    let details = result.open_badge_details.expect("open_badge_details must be Some");
    let has_hosted_warning = details
        .warnings
        .iter()
        .any(|w| w.to_lowercase().contains("hosted") || w.to_lowercase().contains("cryptograph"));
    assert!(
        has_hosted_warning,
        "Expected a hosted-badge crypto warning in open_badge_details.warnings; got: {:?}",
        details.warnings
    );
}

// ── §11 OBv3 — parse error returns Err ───────────────────────────────────────

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

// ── §12 OBv3 wrapper `{ "credential": … }` ───────────────────────────────────

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
    let details = result.open_badge_details.expect("open_badge_details must be Some");
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

// ── §13 OBv3 signed credential — DataIntegrityProof (Ed25519) ─────────────────
//
// These tests use `issue_ob3_json` to produce a real, signed OBv3 credential
// with an Ed25519 DataIntegrityProof (JsonWebSignature2020 suite).
// The signed credential is then verified via `verify_open_badge_offline` with
// the verification-method document embedded in the `document_store` field.
// This exercises the full signing → verification round-trip that existing
// tests never reached.

/// Generate a fresh Ed25519 JWK (public + private) from raw byte slices.
///
/// Returns `(private_jwk_json, public_jwk_json, public_key_bytes)`.
fn ed25519_jwk_pair() -> (serde_json::Value, serde_json::Value, Vec<u8>) {
    use base64::Engine as _;
    use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64URL;
    use marty_crypto::keygen::{generate_keypair, KeyType};

    let key = generate_keypair(KeyType::Ed25519).expect("Ed25519 key gen");
    let x = B64URL.encode(&key.public_key);
    let d = B64URL.encode(&key.private_key);

    let private_jwk = serde_json::json!({
        "kty": "OKP",
        "crv": "Ed25519",
        "x": x,
        "d": d,
    });
    let public_jwk = serde_json::json!({
        "kty": "OKP",
        "crv": "Ed25519",
        "x": x,
    });
    (private_jwk, public_jwk, key.public_key)
}

/// Issue a minimal signed OBv3 `OpenBadgeCredential` using `issue_ob3_json`
/// and return the signed credential JSON `Value`.
///
/// The credential uses only OBv3-context-mapped properties to avoid JSON-LD
/// expansion failures.  Specifically:
///  - `Achievement.achievementType`: mapped as `xsd:string` in the OBv3 context
///  - no unqualified `name` or `description` (not in bundled context)
fn issue_minimal_ob3_credential(
    vm_id: &str,
    controller: &str,
    private_jwk: &serde_json::Value,
) -> serde_json::Value {
    use marty_verification::open_badges::issue_ob3_json;

    let issue_req = serde_json::json!({
        "credential": {
            "@context": [
                "https://www.w3.org/2018/credentials/v1",
                OBV3_CONTEXT
            ],
            "type": ["VerifiableCredential", "OpenBadgeCredential"],
            "id": "https://example.org/vc/signed-conformance-test",
            "issuer": controller,
            "issuanceDate": "2024-01-01T00:00:00Z",
            "credentialSubject": {
                "type": "AchievementSubject",
                "achievement": {
                    "type": "Achievement",
                    "achievementType": "Certificate"
                }
            }
        },
        "signing": {
            "jwk": private_jwk,
            "verification_method": vm_id,
            "verification_method_type": "JsonWebKey2020",
            "controller": controller,
            "proof_purpose": "assertionMethod"
        }
    });

    let issued_json =
        issue_ob3_json(&issue_req.to_string()).expect("issue_ob3_json failed");
    let issued: serde_json::Value =
        serde_json::from_str(&issued_json).expect("parse issue result");
    issued["credential"].clone()
}

/// Build a `JsonWebKey2020` verification-method document for the document store.
fn json_web_key_vm_doc(vm_id: &str, controller: &str, public_jwk: &serde_json::Value) -> serde_json::Value {
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
    let vm_id = "https://example.org/issuer#key-1";
    let controller = "https://example.org/issuer";

    let (private_jwk, public_jwk, _) = ed25519_jwk_pair();
    let signed_cred = issue_minimal_ob3_credential(vm_id, controller, &private_jwk);
    let vm_doc = json_web_key_vm_doc(vm_id, controller, &public_jwk);

    let request = serde_json::json!({
        "credential": signed_cred,
        "document_store": { vm_id: vm_doc }
    });

    let result = verify_open_badge_offline(&request.to_string())
        .await
        .expect("verify_open_badge_offline failed");

    assert_eq!(
        result.status,
        VerificationStatus::Valid,
        "Signed OBv3 credential must be Valid; errors: {:?}",
        result.open_badge_details.as_ref().map(|d| &d.errors)
    );
}

/// The signed credential's `open_badge_details.version` must be `"3.0"`.
#[tokio::test]
async fn ob3_signed_credential_version_label_is_three_point_zero() {
    let vm_id = "https://example.org/issuer#key-2";
    let controller = "https://example.org/issuer";

    let (private_jwk, public_jwk, _) = ed25519_jwk_pair();
    let signed_cred = issue_minimal_ob3_credential(vm_id, controller, &private_jwk);
    let vm_doc = json_web_key_vm_doc(vm_id, controller, &public_jwk);

    let request = serde_json::json!({
        "credential": signed_cred,
        "document_store": { vm_id: vm_doc }
    });

    let result = verify_open_badge_offline(&request.to_string())
        .await
        .expect("verify_open_badge_offline failed");

    let details = result.open_badge_details.expect("open_badge_details must be Some");
    assert_eq!(details.version, "3.0");
}

/// The `credential_type` field must be `"open-badge"` for a signed OBv3 credential.
#[tokio::test]
async fn ob3_signed_credential_type_field_is_open_badge() {
    let vm_id = "https://example.org/issuer#key-3";
    let controller = "https://example.org/issuer";

    let (private_jwk, public_jwk, _) = ed25519_jwk_pair();
    let signed_cred = issue_minimal_ob3_credential(vm_id, controller, &private_jwk);
    let vm_doc = json_web_key_vm_doc(vm_id, controller, &public_jwk);

    let request = serde_json::json!({
        "credential": signed_cred,
        "document_store": { vm_id: vm_doc }
    });

    let result = verify_open_badge_offline(&request.to_string())
        .await
        .expect("verify_open_badge_offline failed");

    assert_eq!(result.credential_type, "open-badge");
}

/// Using the wrong public key in the document store (key mismatch) must
/// produce `Invalid` status with a proof-related error.
#[tokio::test]
async fn ob3_signed_credential_wrong_public_key_is_invalid() {
    let vm_id = "https://example.org/issuer#key-4";
    let controller = "https://example.org/issuer";

    let (private_jwk, _correct_pub, _) = ed25519_jwk_pair();
    let (_, wrong_pub, _) = ed25519_jwk_pair();

    let signed_cred = issue_minimal_ob3_credential(vm_id, controller, &private_jwk);
    // Deliberately supply the wrong (different) public key.
    let vm_doc = json_web_key_vm_doc(vm_id, controller, &wrong_pub);

    let request = serde_json::json!({
        "credential": signed_cred,
        "document_store": { vm_id: vm_doc }
    });

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
