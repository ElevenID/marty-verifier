use super::liveness::verify_challenge_signature;
use super::*;

#[test]
fn software_emrtd_verification_uses_the_simple_hardware_path() {
    let hardware_feature = verification_hardware_feature("emrtd", false);

    assert_eq!(hardware_feature, "basic_verification");
    assert!(crate::hardware::HardwareTier::Simple.supports_feature(hardware_feature));
}

#[test]
fn software_emrtd_hardware_selection_is_case_insensitive() {
    assert_eq!(
        verification_hardware_feature("eMRTD", false),
        "basic_verification"
    );
}

#[test]
fn nfc_emrtd_verification_still_requires_complex_hardware() {
    let hardware_feature = verification_hardware_feature("emrtd", true);

    assert_eq!(hardware_feature, "emrtd");
    assert!(!crate::hardware::HardwareTier::Simple.supports_feature(hardware_feature));
    assert!(crate::hardware::HardwareTier::Complex.supports_feature(hardware_feature));
}

#[test]
fn unrelated_credential_hardware_requirements_are_unchanged() {
    assert_eq!(verification_hardware_feature("dtc", false), "dtc");
    assert_eq!(verification_hardware_feature("oid4vp", false), "oid4vp");
}

#[cfg(feature = "demo-fixtures")]
#[test]
fn generated_dtc_passes_the_exact_app_payload_adapter_with_governed_csca() {
    let output = tempfile::tempdir().unwrap();
    let manifest = match std::env::var_os("MARTY_DEMO_FIXTURE_DIRECTORY") {
        Some(directory) => serde_json::from_str(
            &std::fs::read_to_string(std::path::PathBuf::from(directory).join("manifest.json"))
                .unwrap(),
        )
        .unwrap(),
        None => marty_sync::demo_fixtures::generate_demo_fixtures(output.path()).unwrap(),
    };
    let raw: Value =
        serde_json::from_str(&std::fs::read_to_string(manifest.dtc_path).unwrap()).unwrap();
    let package: Value =
        serde_json::from_str(&std::fs::read_to_string(manifest.trust_package_path).unwrap())
            .unwrap();
    let certificate_der = BASE64_STANDARD
        .decode(
            package["csca_certificates"][0]["certificate_der_b64"]
                .as_str()
                .unwrap(),
        )
        .unwrap();
    let payload =
        build_dtc_verify_payload(&raw, &[certificate_der_to_pem(&certificate_der)]).unwrap();
    let verified = marty_verification::dtc::verify_dtc_json(&payload.to_string()).unwrap();
    let verified: Value = serde_json::from_str(&verified).unwrap();
    assert_eq!(verified["is_valid"], true, "{verified:#}");
}
use serde_json::json;

fn sample_challenge() -> LivenessChallenge {
    LivenessChallenge {
        challenge_id: "challenge-1".to_string(),
        nonce: "nonce-1".to_string(),
        session_id: "session-1".to_string(),
        steps: vec![LivenessStep {
            step_id: "step-1".to_string(),
            step_type: LivenessStepType::HeadPose,
            prompt: Some("Turn left".to_string()),
            pose_direction: Some("left".to_string()),
            time_limit_ms: Some(5000),
        }],
        issued_at: Utc::now().to_rfc3339(),
        expires_at: (Utc::now() + Duration::seconds(30)).to_rfc3339(),
        signature: String::new(),
        preferred_mode: LivenessMode::OnDevice,
        allow_network_fallback: true,
        accessibility_mode: false,
    }
}

#[test]
fn sign_and_verify_round_trip() {
    let secret = b"secret";
    let mut challenge = sample_challenge();
    challenge.signature = sign_challenge(&challenge, secret);

    assert!(verify_challenge_signature(&challenge, secret));
}

#[test]
fn tampered_challenge_fails_signature() {
    let secret = b"secret";
    let mut challenge = sample_challenge();
    challenge.signature = sign_challenge(&challenge, secret);

    // Tamper with nonce
    let mut tampered = challenge.clone();
    tampered.nonce = "wrong".to_string();

    assert!(!verify_challenge_signature(&tampered, secret));
}

#[test]
fn unsupported_credential_result_cannot_authorize() {
    let request: VerifyRequest = serde_json::from_value(json!({
        "credential_type": "unknown-format",
        "credential_data": "opaque"
    }))
    .expect("request");

    let result = unsupported_result(&request, "Unsupported credential type");

    assert_eq!(result.status, VerificationStatus::Failed);
    assert!(!result.trust_chain.valid);
    assert_eq!(result.revocation_status, RevocationStatus::Unknown);
    assert_eq!(result.disclosed_claims, json!({}));
    assert!(result.issuer.is_none());
}

fn dtc_check(check_name: &str, passed: bool) -> VerificationCheck {
    let outcome = if passed {
        VerificationCheckOutcome::Passed
    } else {
        VerificationCheckOutcome::Failed
    };
    VerificationCheck {
        check_name: check_name.to_string(),
        outcome,
        passed,
        details: None,
        error_code: None,
    }
}

#[test]
fn dtc_checks_preserve_explicit_core_outcomes() {
    let value = json!({
        "verification_results": [
            {"check_name": "Signature", "outcome": "PASSED", "passed": true},
            {"check_name": "TrustChain", "outcome": "FAILED", "passed": false},
            {
                "check_name": "RevocationStatus",
                "outcome": "NOT_PERFORMED",
                "passed": false,
                "error_code": "E810"
            },
            {"check_name": "StatusEvidence", "outcome": "ERROR", "passed": false}
        ]
    });

    let checks = parse_dtc_checks(&value);

    assert_eq!(
        checks.iter().map(|check| check.outcome).collect::<Vec<_>>(),
        vec![
            VerificationCheckOutcome::Passed,
            VerificationCheckOutcome::Failed,
            VerificationCheckOutcome::NotPerformed,
            VerificationCheckOutcome::Error,
        ]
    );
    assert_eq!(
        checks.iter().map(|check| check.passed).collect::<Vec<_>>(),
        vec![true, false, false, false]
    );
}

#[test]
fn dtc_checks_fail_safe_on_missing_unknown_or_inconsistent_outcomes() {
    let value = json!({
        "verification_results": [
            {"check_name": "MissingOutcome", "passed": true},
            {"check_name": "UnknownOutcome", "outcome": "SKIPPED", "passed": false},
            {"check_name": "MissingProjection", "outcome": "PASSED"},
            {"check_name": "ContradictoryPass", "outcome": "PASSED", "passed": false},
            {"check_name": "ContradictoryFailure", "outcome": "FAILED", "passed": true}
        ]
    });

    let checks = parse_dtc_checks(&value);

    assert_eq!(checks.len(), 5);
    assert!(checks
        .iter()
        .all(|check| check.outcome == VerificationCheckOutcome::Error && !check.passed));
}

#[test]
fn dtc_current_good_requires_one_explicit_passed_status_check() {
    let value = json!({
        "revocation_status": "GOOD",
        "verification_results": [
            {"check_name": "RevocationStatus", "outcome": "PASSED", "passed": true}
        ]
    });
    let checks = parse_dtc_checks(&value);

    assert_eq!(
        parse_dtc_revocation_status(&value, &checks),
        RevocationStatus::Valid
    );

    let malformed = json!({
        "revocation_status": "GOOD",
        "verification_results": [
            {"check_name": "RevocationStatus", "outcome": "PASSED", "passed": false}
        ]
    });
    assert_eq!(
        parse_dtc_revocation_status(&malformed, &parse_dtc_checks(&malformed)),
        RevocationStatus::Unknown
    );

    let duplicate = json!({
        "revocation_status": "GOOD",
        "verification_results": [
            {"check_name": "RevocationStatus", "outcome": "PASSED", "passed": true},
            {"check_name": "RevocationStatus", "outcome": "PASSED", "passed": true}
        ]
    });
    assert_eq!(
        parse_dtc_revocation_status(&duplicate, &parse_dtc_checks(&duplicate)),
        RevocationStatus::Unknown
    );
}

#[test]
fn dtc_revoked_and_unknown_statuses_are_not_promoted() {
    for (status, expected) in [
        (Some("REVOKED"), RevocationStatus::Revoked),
        (Some("UNKNOWN"), RevocationStatus::Unknown),
        (Some("FUTURE_VALUE"), RevocationStatus::Unknown),
        (None, RevocationStatus::Unknown),
    ] {
        let mut value = json!({"verification_results": []});
        if let Some(status) = status {
            value["revocation_status"] = Value::String(status.to_string());
        }
        assert_eq!(
            parse_dtc_revocation_status(&value, &parse_dtc_checks(&value)),
            expected
        );
    }
}

#[test]
fn dtc_trust_requires_both_explicit_checks() {
    assert!(!dtc_trust_chain_valid(&[]));
    assert!(!dtc_trust_chain_valid(&[dtc_check("TrustChain", true)]));
    assert!(!dtc_trust_chain_valid(&[dtc_check(
        "SignerKeyMatchesCertificate",
        true,
    )]));
}

#[test]
fn dtc_trust_requires_both_checks_to_pass() {
    assert!(!dtc_trust_chain_valid(&[
        dtc_check("TrustChain", false),
        dtc_check("SignerKeyMatchesCertificate", true),
    ]));
    assert!(!dtc_trust_chain_valid(&[
        dtc_check("TrustChain", true),
        dtc_check("SignerKeyMatchesCertificate", false),
    ]));
}

#[test]
fn dtc_trust_accepts_exactly_one_passed_instance_of_each_check() {
    assert!(dtc_trust_chain_valid(&[
        dtc_check("Signature", true),
        dtc_check("TrustChain", true),
        dtc_check("SignerKeyMatchesCertificate", true),
    ]));
}

#[test]
fn dtc_trust_rejects_duplicate_required_checks() {
    assert!(!dtc_trust_chain_valid(&[
        dtc_check("TrustChain", true),
        dtc_check("TrustChain", true),
        dtc_check("SignerKeyMatchesCertificate", true),
    ]));
    assert!(!dtc_trust_chain_valid(&[
        dtc_check("TrustChain", true),
        dtc_check("SignerKeyMatchesCertificate", true),
        dtc_check("SignerKeyMatchesCertificate", false),
    ]));
}

#[test]
fn dtc_payload_replaces_presented_anchors_with_governed_anchors() {
    let raw = json!({
        "dtc_data": {
            "dtc_id": "DTC-1",
            "trust_anchors_pem": ["presented-nested-anchor"]
        },
        "trust_anchors_pem": ["presented-envelope-anchor"],
        "certificate_chain_pem": ["presented-signer-certificate"]
    });
    let governed = vec!["governed-csca".to_string()];

    let payload = build_dtc_verify_payload(&raw, &governed).expect("payload");

    assert!(dtc_contains_presented_trust_anchors(&raw));
    assert_eq!(payload["trust_anchors_pem"], json!(["governed-csca"]));
    assert_eq!(
        payload["certificate_chain_pem"],
        json!(["presented-signer-certificate"])
    );
}

#[test]
fn stateless_dtc_payload_cannot_use_presented_trust_anchors() {
    let raw = json!({
        "dtc_id": "DTC-1",
        "trust_anchors_pem": ["presented-anchor"]
    });

    let payload = build_dtc_verify_payload(&raw, &[]).expect("payload");

    assert_eq!(payload["trust_anchors_pem"], json!([]));
}

#[test]
fn governed_dtc_store_rejects_provenance_less_records() {
    let record = TrustAnchorRecord {
        anchor: marty_secure_storage::TrustAnchor {
            id: "legacy".to_string(),
            anchor_type: CoreTrustAnchorType::Csca,
            jurisdiction: "US".to_string(),
            subject: None,
            issuer: None,
            serial_number: None,
            not_before: None,
            not_after: None,
            certificate_der: vec![1, 2, 3],
            certificate_hash: "legacy".to_string(),
            source: marty_secure_storage::TrustAnchorSource::Manual,
            synced_at: Utc::now(),
        },
        provenance: None,
    };

    let (anchors, rejected) =
        build_governed_dtc_csca_store(&[record], Utc::now(), 72).expect("legacy record is ignored");

    assert!(anchors.is_empty());
    assert_eq!(rejected, 1);
}

#[test]
fn governed_dtc_store_encodes_authenticated_csca_der() {
    let (certificate_der, _) = marty_crypto::cert_builder::create_csca_certificate(
        "USA",
        "Marty DTC Test CSCA",
        365,
        marty_crypto::keygen::KeyType::EcdsaP256,
    )
    .expect("CSCA");
    let now = Utc::now();
    let record = TrustAnchorRecord {
        anchor: marty_secure_storage::TrustAnchor {
            id: "governed".to_string(),
            anchor_type: CoreTrustAnchorType::Csca,
            jurisdiction: "USA".to_string(),
            subject: None,
            issuer: None,
            serial_number: None,
            not_before: None,
            not_after: None,
            certificate_der,
            certificate_hash: "governed".to_string(),
            source: marty_secure_storage::TrustAnchorSource::UsbImport,
            synced_at: now,
        },
        provenance: Some(TrustPackageProvenance {
            trust_domain: "usb:dtc-test".to_string(),
            sequence: 1,
            package_version: "1.0.0".to_string(),
            created_at: now,
            expires_at: now + Duration::hours(1),
            signer_key_id: "dtc-test-signer".to_string(),
            package_digest: "a".repeat(64),
            imported_at: now,
        }),
    };

    let (anchors, rejected) =
        build_governed_dtc_csca_store(&[record], now, 72).expect("governed record");

    assert_eq!(rejected, 0);
    assert_eq!(anchors.len(), 1);
    assert!(anchors[0].starts_with("-----BEGIN CERTIFICATE-----\n"));
    assert!(anchors[0].ends_with("-----END CERTIFICATE-----\n"));
}

#[test]
fn governed_dtc_store_rejects_expired_package_provenance() {
    let now = Utc::now();
    let record = TrustAnchorRecord {
        anchor: marty_secure_storage::TrustAnchor {
            id: "expired".to_string(),
            anchor_type: CoreTrustAnchorType::Csca,
            jurisdiction: "USA".to_string(),
            subject: None,
            issuer: None,
            serial_number: None,
            not_before: None,
            not_after: None,
            certificate_der: vec![1, 2, 3],
            certificate_hash: "expired".to_string(),
            source: marty_secure_storage::TrustAnchorSource::UsbImport,
            synced_at: now - Duration::hours(73),
        },
        provenance: Some(TrustPackageProvenance {
            trust_domain: "usb:expired-test".to_string(),
            sequence: 1,
            package_version: "1.0.0".to_string(),
            created_at: now - Duration::hours(73),
            expires_at: now + Duration::hours(1),
            signer_key_id: "expired-test-signer".to_string(),
            package_digest: "a".repeat(64),
            imported_at: now - Duration::hours(73),
        }),
    };

    let (anchors, rejected) = build_governed_dtc_csca_store(&[record], now, 72)
        .expect("expired record is ignored before parsing its certificate");

    assert!(anchors.is_empty());
    assert_eq!(rejected, 1);
}

#[tokio::test]
async fn mock_pad_cannot_authorize() {
    let error = evaluate_pad(&sample_challenge(), &PadProviderConfig::default())
        .await
        .expect_err("mock PAD must be unavailable");

    assert!(error.to_string().contains("Mock PAD cannot authorize"));
}

#[test]
fn open_badge_request_auto_detects_versions() {
    let ob2 = json!({
        "@context": "https://w3id.org/openbadges/v2",
        "type": "Assertion"
    });
    let (version, request) = build_open_badge_request(&ob2).expect("ob2 request");
    assert_eq!(version, OpenBadgesVersion::V2);
    assert!(request.get("assertion").is_some());

    let ob3 = json!({
        "@context": "https://purl.imsglobal.org/spec/ob/v3p0/context.json",
        "type": ["OpenBadgeCredential"]
    });
    let (version, request) = build_open_badge_request(&ob3).expect("ob3 request");
    assert_eq!(version, OpenBadgesVersion::V3);
    assert!(request.get("credential").is_some());
}

fn active_open_badge_method(now: DateTime<Utc>) -> OpenBadgeVerificationMethod {
    OpenBadgeVerificationMethod {
        id: "did:example:issuer#key-1".to_string(),
        document: json!({
            "id": "did:example:issuer#key-1",
            "type": "JsonWebKey2020",
            "controller": "did:example:issuer",
            "publicKeyJwk": {
                "kty": "OKP",
                "crv": "Ed25519",
                "x": "11qYAYdk9JbF9h5H4fGxM7yJFMw9qkE3vZ8LxJ8rV5M"
            }
        }),
        controller: Some("did:example:issuer".to_string()),
        issuer: None,
        kid: None,
        not_before: Some(now - Duration::hours(1)),
        not_after: Some(now + Duration::hours(1)),
        status: Some("active".to_string()),
        source: marty_app_storage::OpenBadgeKeySource::Sync,
        synced_at: now - Duration::hours(1),
    }
}

fn governed_open_badge_record(
    method: OpenBadgeVerificationMethod,
    trust_domain: &str,
    digest_byte: char,
    now: DateTime<Utc>,
) -> OpenBadgeTrustRecord {
    OpenBadgeTrustRecord {
        provenance: Some(TrustPackageProvenance {
            trust_domain: trust_domain.to_string(),
            sequence: 7,
            package_version: "7.0.0".to_string(),
            created_at: method.synced_at,
            expires_at: now + Duration::hours(12),
            signer_key_id: format!("ed25519:{}", "a".repeat(64)),
            package_digest: digest_byte.to_string().repeat(64),
            imported_at: now - Duration::minutes(30),
        }),
        method,
    }
}

fn method_with_id(
    mut method: OpenBadgeVerificationMethod,
    id: &str,
    controller: &str,
) -> OpenBadgeVerificationMethod {
    method.id = id.to_string();
    method.controller = Some(controller.to_string());
    method.document["id"] = json!(id);
    method.document["controller"] = json!(controller);
    method
}

fn software_artifact() -> ArtifactProvenance {
    ArtifactProvenance::new(
        "marty-verifier-executable",
        "1.0.0",
        format!("sha256:{}", "f".repeat(64)),
    )
    .expect("software provenance")
}

#[test]
fn production_governed_store_rejects_provenance_less_records() {
    let now = Utc::now();
    let legacy = OpenBadgeTrustRecord {
        method: active_open_badge_method(now),
        provenance: None,
    };

    let (store, rejected) = build_governed_open_badge_store(&[legacy], now, 48);

    assert!(store.documents.is_empty());
    assert!(store.provenance_by_document.is_empty());
    assert_eq!(rejected, 1);
}

#[test]
fn production_governed_store_isolates_package_domains() {
    let now = Utc::now();
    let first = governed_open_badge_record(
        method_with_id(
            active_open_badge_method(now),
            "did:example:first#key-1",
            "did:example:first",
        ),
        "trust.example/first",
        '1',
        now,
    );
    let second = governed_open_badge_record(
        method_with_id(
            active_open_badge_method(now),
            "did:example:second#key-1",
            "did:example:second",
        ),
        "trust.example/second",
        '2',
        now,
    );

    let (store, rejected) = build_governed_open_badge_store(&[first, second], now, 48);
    let first_provenance = store
        .provenance_for_method("did:example:first#key-1")
        .expect("first provenance");
    let authority = store.authority_documents(first_provenance);

    assert_eq!(rejected, 0);
    assert!(authority.contains_key("did:example:first#key-1"));
    assert!(!authority.contains_key("did:example:second#key-1"));
}

#[test]
fn status_adapter_requires_exact_url_and_bounds_signed_age() {
    let now = Utc::now();
    let method_id = "did:example:status#key-1";
    let record = governed_open_badge_record(
        method_with_id(
            active_open_badge_method(now),
            method_id,
            "did:example:status",
        ),
        "trust.example/status",
        '3',
        now,
    );
    let (store, rejected) = build_governed_open_badge_store(&[record], now, 48);
    assert_eq!(rejected, 0);

    let status_url = "https://status.example/lists/1";
    let credential = json!({
        "issuer": "did:example:status",
        "validFrom": (now - Duration::hours(1)).to_rfc3339(),
        "validUntil": (now + Duration::hours(4)).to_rfc3339(),
        "proof": { "verificationMethod": method_id }
    });
    let mut request_store = DocumentStore::new();
    request_store.insert(status_url.to_string(), credential.clone());

    let admitted = build_authenticated_status_list(
        status_url,
        &request_store,
        &store,
        now,
        &OpenBadgeTrustConfig::default(),
        &software_artifact(),
    )
    .expect("admit exact governed status context");
    assert_eq!(admitted.url(), status_url);
    assert_eq!(admitted.trusted_issuer(), "did:example:status");
    assert!(admitted.authority_documents().contains_key(method_id));
    assert!(admitted.fresh_until() <= now + Duration::hours(4));

    assert!(build_authenticated_status_list(
        "https://status.example/lists/other",
        &request_store,
        &store,
        now,
        &OpenBadgeTrustConfig::default(),
        &software_artifact(),
    )
    .is_err());

    let mut stale_store = DocumentStore::new();
    let mut stale = credential;
    stale["validFrom"] = json!((now - Duration::hours(25)).to_rfc3339());
    stale_store.insert(status_url.to_string(), stale);
    let relaxed_config = OpenBadgeTrustConfig {
        status_list_max_age_hours: 10_000,
        stale_critical_hours: 10_000,
        ..OpenBadgeTrustConfig::default()
    };
    assert!(build_authenticated_status_list(
        status_url,
        &stale_store,
        &store,
        now,
        &relaxed_config,
        &software_artifact(),
    )
    .is_err());
}

#[tokio::test]
async fn status_adapter_bounds_and_does_not_reflect_declared_urls() {
    let malformed_store_request = json!({"document_store": []});
    assert!(build_authenticated_status_lists(
        &malformed_store_request,
        &GovernedOpenBadgeStore::default(),
        Utc::now(),
        &OpenBadgeTrustConfig::default(),
    )
    .await
    .is_err());

    let prefix = "https://status.example/";
    let maximum = format!(
        "{prefix}{}",
        "é".repeat(MAX_OPEN_BADGE_STATUS_IRI_CHARS - prefix.chars().count())
    );
    let maximum_request = json!({
        "credential": {
            "credentialStatus": {
                "type": "BitstringStatusListEntry",
                "statusListCredential": maximum,
            }
        }
    });
    assert_eq!(extract_status_list_urls(&maximum_request), vec![maximum]);

    let oversized = format!("{prefix}{}", "a".repeat(MAX_OPEN_BADGE_STATUS_IRI_CHARS));
    let oversized_request = json!({
        "credential": {
            "credentialStatus": {
                "type": "BitstringStatusListEntry",
                "statusListCredential": oversized,
            }
        }
    });
    assert!(extract_status_list_urls(&oversized_request).is_empty());

    let private_marker = "private-query-value";
    let status_url = format!("https://status.example/list?token={private_marker}");
    let request = json!({
        "credential": {
            "credentialStatus": {
                "type": "BitstringStatusListEntry",
                "statusListCredential": status_url,
            }
        },
        "document_store": {
            "https://unrelated.example/1": {"large": "caller-controlled"}
        }
    });
    let selected = extract_stapled_status_documents(&request, std::slice::from_ref(&status_url))
        .expect("select exact stapled status documents");
    assert!(selected.is_empty());
    let (_, warnings) = build_authenticated_status_lists(
        &request,
        &GovernedOpenBadgeStore::default(),
        Utc::now(),
        &OpenBadgeTrustConfig::default(),
    )
    .await
    .expect("missing stapled status context remains a typed warning");

    assert_eq!(warnings.len(), 1);
    assert!(!warnings[0].contains(private_marker));
    assert!(!warnings[0].contains(&status_url));
}

fn status_evidence(
    purpose: &str,
    outcome: OpenBadgeStatusEvidenceOutcome,
) -> OpenBadgeStatusEvidence {
    let now = Utc::now();
    let artifact = OpenBadgeArtifactEvidence {
        id: "artifact".to_string(),
        version: "1".to_string(),
        digest: format!("sha256:{}", "a".repeat(64)),
    };
    OpenBadgeStatusEvidence {
        status_list_url: "https://status.example/lists/1".to_string(),
        status_issuer: "did:example:status".to_string(),
        status_purpose: purpose.to_string(),
        status_list_index: 1,
        status_size: 1,
        status_value: u16::from(outcome != OpenBadgeStatusEvidenceOutcome::Good),
        outcome,
        checked_at: now,
        retrieved_at: now,
        fresh_until: now + Duration::hours(1),
        authority_provenance: OpenBadgeStatusAuthorityEvidence {
            trust_profile: artifact.clone(),
            resolver: artifact.clone(),
            software: artifact,
        },
    }
}

#[test]
fn revocation_projection_requires_explicit_authenticated_evidence() {
    assert_eq!(
        open_badge_revocation_status(&[], true),
        RevocationStatus::Unknown
    );
    assert_eq!(
        open_badge_revocation_status(
            &[status_evidence(
                "revocation",
                OpenBadgeStatusEvidenceOutcome::Good,
            )],
            true
        ),
        RevocationStatus::Valid
    );
    assert_eq!(
        open_badge_revocation_status(
            &[status_evidence(
                "revocation",
                OpenBadgeStatusEvidenceOutcome::Good,
            )],
            false
        ),
        RevocationStatus::Unknown
    );
    assert_eq!(
        open_badge_revocation_status(
            &[status_evidence(
                "revocation",
                OpenBadgeStatusEvidenceOutcome::Revoked,
            )],
            false
        ),
        RevocationStatus::Revoked
    );
    assert_eq!(
        open_badge_revocation_status(
            &[status_evidence(
                "suspension",
                OpenBadgeStatusEvidenceOutcome::Good,
            )],
            true
        ),
        RevocationStatus::Unknown
    );
}

#[test]
fn software_provenance_hashes_the_running_executable() {
    let provenance = compute_verifier_software_provenance().expect("software provenance");

    assert_eq!(provenance.id(), "marty-verifier-executable");
    assert_eq!(provenance.version(), env!("CARGO_PKG_VERSION"));
    assert!(provenance.digest().starts_with("sha256:"));
    assert_eq!(provenance.digest().len(), "sha256:".len() + 64);
}

#[tokio::test]
async fn software_provenance_is_stable_across_concurrent_requests() {
    let (first, second, third) = tokio::join!(
        verifier_software_provenance(),
        verifier_software_provenance(),
        verifier_software_provenance(),
    );
    let first = first.expect("first software provenance");
    assert_eq!(first, second.expect("second software provenance"));
    assert_eq!(first, third.expect("third software provenance"));
}

#[test]
fn production_open_badge_store_admits_only_active_in_window_records() {
    let now = Utc::now();
    let active = active_open_badge_method(now);
    let (store, rejected) = build_trusted_open_badge_store(std::slice::from_ref(&active), now, 48);
    assert_eq!(store.len(), 1);
    assert_eq!(rejected, 0);

    let mut inactive = active.clone();
    inactive.status = Some("revoked".to_string());
    assert!(!open_badge_trust_record_is_usable(&inactive, now, 48));

    let mut not_yet_valid = active.clone();
    not_yet_valid.not_before = Some(now + Duration::seconds(1));
    assert!(!open_badge_trust_record_is_usable(&not_yet_valid, now, 48));

    let mut expired = active.clone();
    expired.not_after = Some(now);
    assert!(!open_badge_trust_record_is_usable(&expired, now, 48));

    let mut critically_stale = active;
    critically_stale.synced_at = now - Duration::hours(48);
    assert!(!open_badge_trust_record_is_usable(
        &critically_stale,
        now,
        48
    ));
    assert!(!open_badge_trust_record_is_usable(
        &critically_stale,
        now,
        10_000
    ));
}

#[test]
fn production_open_badge_store_rejects_binding_conflicts_and_private_keys() {
    let now = Utc::now();
    let active = active_open_badge_method(now);

    let mut wrong_id = active.clone();
    wrong_id.document["id"] = json!("did:example:issuer#other-key");
    assert!(!open_badge_trust_record_is_usable(&wrong_id, now, 48));

    let mut wrong_controller = active.clone();
    wrong_controller.document["controller"] = json!("did:example:other");
    assert!(!open_badge_trust_record_is_usable(
        &wrong_controller,
        now,
        48
    ));

    let mut private_key = active;
    private_key.document["publicKeyJwk"]["d"] = json!("private-material");
    assert!(!open_badge_trust_record_is_usable(&private_key, now, 48));
}

#[test]
fn production_open_badge_store_rejects_duplicate_method_ids() {
    let now = Utc::now();
    let method = active_open_badge_method(now);
    let (store, rejected) = build_trusted_open_badge_store(&[method.clone(), method], now, 48);

    assert!(store.is_empty());
    assert_eq!(rejected, 2);
}

#[test]
fn production_open_badge_store_replaces_credential_documents() {
    let mut request = json!({
        "credential": {},
        "document_store": {
            "did:example:untrusted": {
                "publicKeyJwk": { "kty": "OKP", "crv": "Ed25519", "x": "def" }
            },
            "https://issuer.example/status": {
                "credentialSubject": { "encodedList": "credential-controlled" }
            }
        }
    });
    let mut trusted_store = DocumentStore::new();
    trusted_store.insert(
        "did:example:trusted".to_string(),
        json!({ "publicKeyJwk": { "kty": "OKP", "crv": "Ed25519", "x": "abc" } }),
    );

    replace_open_badge_document_store(&mut request, &trusted_store)
        .expect("replace document store");
    let installed_store = extract_open_badge_document_store(&request).expect("document store");

    assert_eq!(installed_store, trusted_store);
    assert!(!installed_store.contains_key("did:example:untrusted"));
    assert!(!installed_store.contains_key("https://issuer.example/status"));
}

#[test]
fn extract_open_badge_method_id_from_ob2_creator() {
    let request = json!({
        "assertion": {
            "verification": { "creator": "https://issuer.example.org/keys/1" }
        }
    });
    let method = extract_open_badge_method_id(&request, OpenBadgesVersion::V2).expect("method id");
    assert_eq!(method, "https://issuer.example.org/keys/1");
}

#[test]
fn extract_open_badge_method_id_from_proof() {
    let request = json!({
        "credential": {
            "proof": { "verificationMethod": "did:example:issuer#key-1" }
        }
    });
    let method = extract_open_badge_method_id(&request, OpenBadgesVersion::V3).expect("method id");
    assert_eq!(method, "did:example:issuer#key-1");
}

#[test]
fn open_badge_method_trusted_with_did_document() {
    let mut store = DocumentStore::new();
    store.insert(
        "did:example:issuer".to_string(),
        json!({ "verificationMethod": [{ "id": "did:example:issuer#key-1" }] }),
    );

    assert!(open_badge_method_trusted(
        &store,
        "did:example:issuer#key-1"
    ));
}

#[test]
fn production_open_badge_policy_rejects_fail_open() {
    ensure_production_open_badge_policy(&OpenBadgeTrustPolicy::FailClosed)
        .expect("fail-closed policy");
    ensure_production_open_badge_policy(&OpenBadgeTrustPolicy::Selective)
        .expect("selective policy");

    let error = ensure_production_open_badge_policy(&OpenBadgeTrustPolicy::FailOpen)
        .expect_err("fail-open policy must be rejected");
    assert!(matches!(error, AppError::Config(message) if message.contains("fail-open")));
}

#[test]
fn production_open_badge_requires_a_trusted_method() {
    let mut store = DocumentStore::new();
    store.insert(
        "did:example:trusted".to_string(),
        json!({ "verificationMethod": [{ "id": "did:example:trusted#key-1" }] }),
    );

    assert!(!open_badge_request_method_trusted(&store, None));
    assert!(!open_badge_request_method_trusted(
        &store,
        Some("did:example:untrusted#key-1")
    ));
    assert!(open_badge_request_method_trusted(
        &store,
        Some("did:example:trusted#key-1")
    ));
}

#[test]
fn open_badge_trust_freshness_fails_closed_without_sync() {
    let freshness =
        classify_open_badge_trust_freshness(None, Utc::now(), &OpenBadgeTrustConfig::default());

    assert!(matches!(
        freshness,
        OpenBadgeTrustFreshness::Unavailable(message)
            if message.contains("never been synchronized")
    ));
}

#[test]
fn open_badge_trust_freshness_fails_closed_for_future_sync() {
    let now = Utc::now();
    let freshness = classify_open_badge_trust_freshness(
        Some(now + Duration::seconds(1)),
        now,
        &OpenBadgeTrustConfig::default(),
    );

    assert!(matches!(
        freshness,
        OpenBadgeTrustFreshness::Unavailable(message) if message.contains("future")
    ));
}

#[test]
fn open_badge_trust_freshness_enforces_warning_and_critical_boundaries() {
    let now = Utc::now();
    let config = OpenBadgeTrustConfig::default();

    assert_eq!(
        classify_open_badge_trust_freshness(Some(now - Duration::hours(23)), now, &config,),
        OpenBadgeTrustFreshness::Fresh
    );
    assert!(matches!(
        classify_open_badge_trust_freshness(Some(now - Duration::hours(24)), now, &config,),
        OpenBadgeTrustFreshness::Warning(_)
    ));
    assert!(matches!(
        classify_open_badge_trust_freshness(Some(now - Duration::hours(48)), now, &config,),
        OpenBadgeTrustFreshness::Unavailable(_)
    ));

    let mut relaxed = config;
    relaxed.stale_critical_hours = 10_000;
    assert!(matches!(
        classify_open_badge_trust_freshness(Some(now - Duration::hours(48)), now, &relaxed,),
        OpenBadgeTrustFreshness::Unavailable(_)
    ));
}

#[test]
fn minimal_wire_request_keeps_optional_checks_disabled() {
    let request: VerifyRequest = serde_json::from_value(serde_json::json!({
        "credential_type": "emrtd", "credential_data": "{}"
    }))
    .unwrap();
    assert!(!request.use_nfc);
    assert!(!request.require_liveness);
    assert!(!request.perform_face_match);
    assert!(request.liveness_challenge.is_none());
    assert!(request.session_id.is_none());
    assert!(request.policy.is_none());
}

#[test]
fn public_emrtd_entry_point_keeps_input_error_context() {
    for (input, expected) in [
        ("not-json", "Invalid eMRTD payload JSON"),
        (
            r#"{"sod_base64":"","data_groups":{}}"#,
            "missing or empty sod_base64",
        ),
        (
            r#"{"sod_base64":"!","data_groups":{}}"#,
            "Invalid SOD base64",
        ),
    ] {
        let error = verify_emrtd_offline(input).unwrap_err();
        assert!(error.to_string().contains(expected), "{error}");
    }
}
