//! eMRTD / ICAO 9303 Conformance Tests — Marty Verifier (Tauri app layer).
//!
//! Tests the JSON wire format accepted by `verify_emrtd_offline` and exercises
//! end-to-end eMRTD verification using **real** DER-encoded `EF.SOD` blobs
//! constructed by `marty_crypto::sod_builder`.
//!
//! Wire format (credential_data JSON):
//! ```json
//! {
//!   "sod_base64": "<base64-encoded EF.SOD ContentInfo DER>",
//!   "data_groups": { "DG1": "<base64>", "DG2": "<base64>", ... },
//!   "country": "DEU"
//! }
//! ```
//!
//! Coverage:
//!   §1  JSON parsing errors (malformed, missing fields)
//!   §2  Base64 decoding errors (bad base64, empty SOD)
//!   §3  DER / SOD parsing errors (garbled bytes)
//!   §4  Happy-path: real SOD, valid signature (empty CSCA registry → Failed)
//!   §5  Hash tampering: altered DG content detected
//!   §6  Multi-DG SOD (DG1 + DG2)
//!   §7  Country hint propagation
//!   §8  Data-group numbering edge cases

use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine as _;

use marty_crypto::cert_builder::{create_csca_certificate, create_dsc_certificate};
use marty_crypto::keygen::KeyType;
use marty_crypto::sod_builder::build_emrtd_sod_der;
use marty_verifier::commands::verification::{verify_emrtd_offline, VerificationStatus};

// ── helpers ──────────────────────────────────────────────────────────────────

/// Standard DG1 mock content: two 44-char TD3 MRZ lines for Erika Mustermann.
const DG1_MRZ: &[u8] = b"P<DEUTMUSTER<<ERIKA<<<<<<<<<<<<<<<<<<<<<<<<\
      L898902C36DEU7408125F1204159<<<<<<<<<<<<<<<6";

/// Build a minimal valid-JSON eMRTD payload.
fn emrtd_payload(sod_b64: &str, dgs: &[(&str, &str)], country: Option<&str>) -> String {
    let mut dg_obj = serde_json::Map::new();
    for (name, b64) in dgs {
        dg_obj.insert(name.to_string(), serde_json::Value::String(b64.to_string()));
    }
    let mut obj = serde_json::Map::new();
    obj.insert(
        "sod_base64".to_string(),
        serde_json::Value::String(sod_b64.to_string()),
    );
    obj.insert("data_groups".to_string(), serde_json::Value::Object(dg_obj));
    if let Some(c) = country {
        obj.insert(
            "country".to_string(),
            serde_json::Value::String(c.to_string()),
        );
    }
    serde_json::Value::Object(obj).to_string()
}

/// Generate a fresh CSCA → DSC chain and a signed EF.SOD for `data_groups`.
///
/// Returns `(sod_der, csca_cert_der, dsc_cert_der, dsc_key_pem)`.
fn make_sod(data_groups: &[(u8, Vec<u8>)]) -> (Vec<u8>, Vec<u8>, Vec<u8>, String) {
    let (csca_der, csca_key) =
        create_csca_certificate("DEU", "Bundesdruckerei", 3650, KeyType::EcdsaP256)
            .expect("CSCA creation failed");

    let (dsc_der, dsc_key) = create_dsc_certificate(
        "DEU",
        "Bundesdruckerei",
        &csca_der,
        &csca_key,
        730,
        KeyType::EcdsaP256,
    )
    .expect("DSC creation failed");

    let sod_der = build_emrtd_sod_der(data_groups, &dsc_der, &dsc_key).expect("SOD build failed");

    (sod_der, csca_der, dsc_der, dsc_key)
}

// ── §1  JSON Parsing ──────────────────────────────────────────────────────────

#[test]
fn not_json_returns_error() {
    let result = verify_emrtd_offline("this is not json at all");
    assert!(result.is_err(), "Expected Err for non-JSON input");
}

#[test]
fn empty_object_returns_error() {
    let result = verify_emrtd_offline("{}");
    assert!(
        result.is_err(),
        "Expected Err for empty JSON object — sod_base64 is missing"
    );
}

#[test]
fn missing_sod_base64_field_returns_error() {
    let json = r#"{"data_groups": {"DG1": "aGVsbG8="}, "country": "DEU"}"#;
    let result = verify_emrtd_offline(json);
    assert!(result.is_err(), "Expected Err when sod_base64 is absent");
}

#[test]
fn null_sod_base64_returns_error() {
    let json = r#"{"sod_base64": null, "data_groups": {}}"#;
    let result = verify_emrtd_offline(json);
    assert!(result.is_err(), "Expected Err for null sod_base64");
}

// ── §2  Base64 Decoding Errors ────────────────────────────────────────────────

#[test]
fn invalid_base64_returns_error() {
    let payload = emrtd_payload(
        "NOT!VALID!BASE64!!!@@@",
        &[("DG1", "aGVsbG8=")],
        Some("DEU"),
    );
    let result = verify_emrtd_offline(&payload);
    assert!(result.is_err(), "Expected Err for invalid base64");
}

#[test]
fn empty_sod_base64_returns_error() {
    let payload = emrtd_payload("", &[], None);
    let result = verify_emrtd_offline(&payload);
    assert!(result.is_err(), "Expected Err for empty sod_base64");
}

#[test]
fn whitespace_only_sod_base64_returns_error() {
    let payload = emrtd_payload("   ", &[], None);
    let result = verify_emrtd_offline(&payload);
    assert!(
        result.is_err(),
        "Expected Err for whitespace-only sod_base64"
    );
}

// ── §3  DER Parsing Errors ────────────────────────────────────────────────────

#[test]
fn garbled_der_returns_error() {
    let garbage = BASE64.encode(b"this is not a DER-encoded SOD structure at all!!!");
    let payload = emrtd_payload(&garbage, &[("DG1", "aGVsbG8=")], Some("DEU"));
    let result = verify_emrtd_offline(&payload);
    assert!(result.is_err(), "Expected Err for garbled DER");
}

#[test]
fn truncated_der_returns_error() {
    // A valid-looking DER prefix — SEQUENCE tag + long-form length prefix, but truncated.
    let truncated = BASE64.encode(&[0x30, 0x82, 0x01, 0xFF, 0x30, 0x0A]);
    let payload = emrtd_payload(&truncated, &[], None);
    let result = verify_emrtd_offline(&payload);
    assert!(result.is_err(), "Expected Err for truncated DER");
}

// ── §4  Happy-path: real SOD, valid signature ─────────────────────────────────
//
// Since `verify_emrtd_offline` uses an *empty* CSCA registry, the chain
// validation fails (DSC is not anchored), so the overall status is `Failed`
// (not `Invalid` which would mean the certificate was expired or revoked).
// The important assertion is that the function returns `Ok`, the SOD DER is
// parsed and the signature is checked without a hard error.

#[test]
fn real_sod_single_dg1_parses_and_returns_ok() {
    let dgs = vec![(1u8, DG1_MRZ.to_vec())];
    let (sod_der, _, _, _) = make_sod(&dgs);
    let sod_b64 = BASE64.encode(&sod_der);
    let dg1_b64 = BASE64.encode(DG1_MRZ);
    let payload = emrtd_payload(&sod_b64, &[("DG1", &dg1_b64)], Some("DEU"));

    let result = verify_emrtd_offline(&payload);
    assert!(
        result.is_ok(),
        "Expected Ok for valid SOD, got: {:?}",
        result.unwrap_err()
    );
}

#[test]
fn real_sod_status_is_failed_with_empty_registry() {
    // Without a registered CSCA, chain validation fails → status == Failed
    // (not Invalid — no cert expiry, just untrusted chain).
    let dgs = vec![(1u8, DG1_MRZ.to_vec())];
    let (sod_der, _, _, _) = make_sod(&dgs);
    let sod_b64 = BASE64.encode(&sod_der);
    let dg1_b64 = BASE64.encode(DG1_MRZ);
    let payload = emrtd_payload(&sod_b64, &[("DG1", &dg1_b64)], Some("DEU"));

    let result = verify_emrtd_offline(&payload).expect("should return Ok");
    assert_eq!(
        result.status,
        VerificationStatus::Failed,
        "Expected Failed (untrusted chain) with empty registry"
    );
}

#[test]
fn real_sod_credential_type_is_emrtd() {
    let dgs = vec![(1u8, DG1_MRZ.to_vec())];
    let (sod_der, _, _, _) = make_sod(&dgs);
    let sod_b64 = BASE64.encode(&sod_der);
    let dg1_b64 = BASE64.encode(DG1_MRZ);
    let payload = emrtd_payload(&sod_b64, &[("DG1", &dg1_b64)], Some("DEU"));

    let result = verify_emrtd_offline(&payload).expect("should return Ok");
    assert_eq!(result.credential_type, "emrtd");
}

#[test]
fn real_sod_result_has_verification_id() {
    let dgs = vec![(1u8, DG1_MRZ.to_vec())];
    let (sod_der, _, _, _) = make_sod(&dgs);
    let sod_b64 = BASE64.encode(&sod_der);
    let dg1_b64 = BASE64.encode(DG1_MRZ);
    let payload = emrtd_payload(&sod_b64, &[("DG1", &dg1_b64)], Some("DEU"));

    let result = verify_emrtd_offline(&payload).expect("should return Ok");
    assert!(
        !result.verification_id.is_empty(),
        "verification_id should be a UUID"
    );
}

// ── §5  Hash Tampering ────────────────────────────────────────────────────────
//
// The SOD stores SHA-256 of DG1.  If the caller supplies different DG1 bytes,
// the hash check fails — but `verify_emrtd_offline` still returns Ok (the
// verification ran); the status is simply Failed or the result reflects the
// mismatch rather than panicking.

#[test]
fn tampered_dg1_still_returns_ok_result() {
    let original_dg1 = DG1_MRZ.to_vec();
    let dgs = vec![(1u8, original_dg1)];
    let (sod_der, _, _, _) = make_sod(&dgs);
    let sod_b64 = BASE64.encode(&sod_der);

    // Supply a *different* DG1 — the hash in the SOD won't match.
    let tampered_dg1 = b"P<DEUTFAKE<<<PERSON<<<<<<<<<<<<<<<<<<<<<<<<\
                          X000000007DEU0101015M2512319<<<<<<<<<<<<<<<2";
    let tampered_b64 = BASE64.encode(tampered_dg1);
    let payload = emrtd_payload(&sod_b64, &[("DG1", &tampered_b64)], Some("DEU"));

    let result = verify_emrtd_offline(&payload);
    // The function must not panic; it returns Ok with a non-Valid status
    // or returns Err due to hash mismatch — either is acceptable.
    match result {
        Ok(r) => assert_ne!(
            r.status,
            VerificationStatus::Valid,
            "Tampered DG1 should not yield Valid status"
        ),
        Err(_) => {} // Error is also acceptable for tampered content
    }
}

// ── §6  Multi-DG SOD ──────────────────────────────────────────────────────────

#[test]
fn real_sod_with_dg1_and_dg2_parses_correctly() {
    let portrait_mock = vec![0xFF, 0xD8, 0xFF, 0xE0]; // JPEG SOI + APP0 marker
    let dgs = vec![(1u8, DG1_MRZ.to_vec()), (2u8, portrait_mock.clone())];
    let (sod_der, _, _, _) = make_sod(&dgs);

    let sod_b64 = BASE64.encode(&sod_der);
    let dg1_b64 = BASE64.encode(DG1_MRZ);
    let dg2_b64 = BASE64.encode(&portrait_mock);
    let payload = emrtd_payload(
        &sod_b64,
        &[("DG1", &dg1_b64), ("DG2", &dg2_b64)],
        Some("DEU"),
    );

    let result = verify_emrtd_offline(&payload);
    assert!(
        result.is_ok(),
        "Multi-DG SOD should parse: {:?}",
        result.unwrap_err()
    );
}

#[test]
fn sod_with_many_data_groups_builds_and_parses() {
    // DG1–DG5 with distinct content
    let dgs: Vec<(u8, Vec<u8>)> = (1..=5)
        .map(|n| (n, format!("mock content for DG{n}").into_bytes()))
        .collect();
    let (sod_der, _, _, _) = make_sod(&dgs);

    let sod_b64 = BASE64.encode(&sod_der);
    let dg_payload: Vec<(String, String)> = dgs
        .iter()
        .map(|(n, c)| (format!("DG{n}"), BASE64.encode(c)))
        .collect();
    let dg_refs: Vec<(&str, &str)> = dg_payload
        .iter()
        .map(|(k, v)| (k.as_str(), v.as_str()))
        .collect();
    let payload = emrtd_payload(&sod_b64, &dg_refs, Some("DEU"));

    let result = verify_emrtd_offline(&payload);
    assert!(
        result.is_ok(),
        "5-DG SOD should parse: {:?}",
        result.unwrap_err()
    );
}

// ── §7  Country Hint Propagation ─────────────────────────────────────────────

#[test]
fn country_hint_absent_does_not_error() {
    let dgs = vec![(1u8, DG1_MRZ.to_vec())];
    let (sod_der, _, _, _) = make_sod(&dgs);
    let sod_b64 = BASE64.encode(&sod_der);
    let dg1_b64 = BASE64.encode(DG1_MRZ);
    // No `country` field
    let payload = emrtd_payload(&sod_b64, &[("DG1", &dg1_b64)], None);

    let result = verify_emrtd_offline(&payload);
    assert!(result.is_ok(), "Missing country hint should not error");
}

// ── §8  Data-group numbering ──────────────────────────────────────────────────

#[test]
fn invalid_dg_name_returns_error() {
    let dgs = vec![(1u8, DG1_MRZ.to_vec())];
    let (sod_der, _, _, _) = make_sod(&dgs);
    let sod_b64 = BASE64.encode(&sod_der);
    // "BOGUS" is not a valid DG name
    let payload = emrtd_payload(&sod_b64, &[("BOGUS", "aGVsbG8=")], Some("DEU"));

    let result = verify_emrtd_offline(&payload);
    assert!(result.is_err(), "Invalid DG name 'BOGUS' should return Err");
}

#[test]
fn dg_with_zero_number_returns_error() {
    let dgs = vec![(1u8, DG1_MRZ.to_vec())];
    let (sod_der, _, _, _) = make_sod(&dgs);
    let sod_b64 = BASE64.encode(&sod_der);
    // DG0 does not exist in ICAO 9303
    let payload = emrtd_payload(&sod_b64, &[("DG0", "aGVsbG8=")], None);

    let result = verify_emrtd_offline(&payload);
    assert!(result.is_err(), "DG0 should return Err (invalid DG number)");
}

// ── §9  SOD signature round-trip verification ─────────────────────────────────
//
// These tests call the low-level `verify_sod_signature` directly, bypassing
// the JSON layer, to assert that the built SOD is cryptographically valid.

#[test]
fn sod_signature_roundtrip_is_valid() {
    use marty_verification::asn1::sod::verify_sod_signature;

    let dgs = vec![(1u8, DG1_MRZ.to_vec())];
    let (sod_der, _, _, _) = make_sod(&dgs);

    let valid = verify_sod_signature(&sod_der)
        .expect("verify_sod_signature must not return Err for a well-formed SOD");
    assert!(
        valid,
        "ECDSA signature over the built SOD must verify correctly"
    );
}

#[test]
fn sod_signature_fails_after_mutation() {
    use marty_verification::asn1::sod::verify_sod_signature;

    let dgs = vec![(1u8, DG1_MRZ.to_vec())];
    let (mut sod_der, _, _, _) = make_sod(&dgs);

    // Flip a bit near the end of the DER blob (where the signature lives).
    let last = sod_der.len() - 10;
    sod_der[last] ^= 0xFF;

    // After mutation the verification might return Err (parse failure) or
    // Ok(false) depending on where the bit landed.  It must not return Ok(true).
    let result = verify_sod_signature(&sod_der);
    match result {
        Ok(valid) => assert!(!valid, "Mutated SOD signature must not verify"),
        Err(_) => {} // Err is also acceptable — the DER is corrupted
    }
}

// ── §10 CSCA Trust Chain with Populated Registry ──────────────────────────────
//
// These tests call `verify_emrtd` directly with a registry that contains the
// CSCA cert used to sign the DSC, confirming end-to-end chain validation
// succeeds when the anchor is present.

#[test]
fn csca_chain_valid_with_populated_registry() {
    use marty_verification::trust_anchor::CscaRegistry;
    use marty_verification::verification::emrtd::{verify_emrtd, ChainStatus, SecurityObject};
    use std::collections::HashMap;
    use x509_cert::der::Decode;
    use x509_cert::Certificate;

    let dgs = vec![(1u8, DG1_MRZ.to_vec())];
    let (sod_der, csca_der, _, _) = make_sod(&dgs);

    // Populate the registry with the CSCA that signed this chain.
    let csca_cert = Certificate::from_der(&csca_der).expect("parse CSCA DER");
    let mut registry = CscaRegistry::new();
    registry
        .add_country_csca("DEU", csca_cert)
        .expect("add_country_csca failed");

    let security_object = SecurityObject::from_sod_der(&sod_der, Some("DEU".to_string()))
        .expect("parse SOD into SecurityObject");

    let mut dg_map: HashMap<u8, Vec<u8>> = HashMap::new();
    dg_map.insert(1, DG1_MRZ.to_vec());

    let result = verify_emrtd(&security_object, &dg_map, &registry);

    assert_eq!(
        result.dsc_chain_status,
        ChainStatus::Valid,
        "DSC chain must be Valid when CSCA is in the registry; errors: {:?}",
        result.errors
    );
}

#[test]
fn full_emrtd_verification_succeeds_with_csca_in_registry() {
    use marty_verification::trust_anchor::CscaRegistry;
    use marty_verification::verification::emrtd::{verify_emrtd, SecurityObject};
    use std::collections::HashMap;
    use x509_cert::der::Decode;
    use x509_cert::Certificate;

    let dgs = vec![(1u8, DG1_MRZ.to_vec())];
    let (sod_der, csca_der, _, _) = make_sod(&dgs);

    let csca_cert = Certificate::from_der(&csca_der).expect("parse CSCA DER");
    let mut registry = CscaRegistry::new();
    registry
        .add_country_csca("DEU", csca_cert)
        .expect("add csca");

    let security_object =
        SecurityObject::from_sod_der(&sod_der, Some("DEU".to_string())).expect("parse SOD");

    let mut dg_map: HashMap<u8, Vec<u8>> = HashMap::new();
    dg_map.insert(1, DG1_MRZ.to_vec());

    let result = verify_emrtd(&security_object, &dg_map, &registry);

    assert!(
        result.verified,
        "Full eMRTD verification must succeed with CSCA in registry; errors: {:?}",
        result.errors
    );
}

#[test]
fn wrong_csca_cert_fails_chain_validation() {
    use marty_verification::trust_anchor::CscaRegistry;
    use marty_verification::verification::emrtd::{verify_emrtd, ChainStatus, SecurityObject};
    use std::collections::HashMap;
    use x509_cert::der::Decode;
    use x509_cert::Certificate;

    // SOD signed with csca_a's DSC; registry will contain csca_b instead.
    let dgs = vec![(1u8, DG1_MRZ.to_vec())];
    let (sod_der, _csca_a_der, _, _) = make_sod(&dgs);

    // Generate a completely independent CSCA cert (csca_b) and add that to registry.
    let (csca_b_der, _) = marty_crypto::cert_builder::create_csca_certificate(
        "DEU",
        "WrongCA",
        3650,
        marty_crypto::keygen::KeyType::EcdsaP256,
    )
    .expect("create csca_b");
    let csca_b_cert = Certificate::from_der(&csca_b_der).expect("parse csca_b DER");

    let mut registry = CscaRegistry::new();
    registry
        .add_country_csca("DEU", csca_b_cert)
        .expect("add wrong csca");

    let security_object =
        SecurityObject::from_sod_der(&sod_der, Some("DEU".to_string())).expect("parse SOD");

    let mut dg_map: HashMap<u8, Vec<u8>> = HashMap::new();
    dg_map.insert(1, DG1_MRZ.to_vec());

    let result = verify_emrtd(&security_object, &dg_map, &registry);

    assert_ne!(
        result.dsc_chain_status,
        ChainStatus::Valid,
        "Chain must NOT be Valid when registry contains the wrong CSCA"
    );
    assert!(
        !result.verified,
        "Full verification must fail with wrong CSCA in registry"
    );
}

#[test]
fn multi_dg_full_verification_succeeds_with_csca() {
    use marty_verification::trust_anchor::CscaRegistry;
    use marty_verification::verification::emrtd::{verify_emrtd, SecurityObject};
    use std::collections::HashMap;
    use x509_cert::der::Decode;
    use x509_cert::Certificate;

    let portrait_mock = vec![0xFF, 0xD8, 0xFF, 0xE0]; // JPEG SOI
    let dgs = vec![(1u8, DG1_MRZ.to_vec()), (2u8, portrait_mock.clone())];
    let (sod_der, csca_der, _, _) = make_sod(&dgs);

    let csca_cert = Certificate::from_der(&csca_der).expect("parse CSCA");
    let mut registry = CscaRegistry::new();
    registry
        .add_country_csca("DEU", csca_cert)
        .expect("add csca");

    let security_object =
        SecurityObject::from_sod_der(&sod_der, Some("DEU".to_string())).expect("parse SOD");

    let mut dg_map: HashMap<u8, Vec<u8>> = HashMap::new();
    dg_map.insert(1, DG1_MRZ.to_vec());
    dg_map.insert(2, portrait_mock);

    let result = verify_emrtd(&security_object, &dg_map, &registry);

    assert!(
        result.verified,
        "Multi-DG eMRTD verification must succeed with CSCA; errors: {:?}",
        result.errors
    );
}
