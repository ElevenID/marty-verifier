//! Emrtd verification operations.

use super::{
    governed_csca_record_is_usable, verify_emrtd, verify_from_reader, AppError, AppResult,
    AppState, Certificate, CoreTrustAnchorType, CscaRegistry, EmrtdDetails, EmrtdPayload, HashMap,
    IssuerInfo, MockPassportReader, RevocationStatus, SecurityObject, TrustChainStatus, Utc,
    VerificationResult, VerificationStatus, VerifyRequest, BASE64_STANDARD,
};
use base64::Engine;
use x509_cert::der::Decode;

/// Testable offline entry point for eMRTD verification (no `AppState`).
///
/// Accepts the same JSON shape as `verify_credential` for `credential_type == "emrtd"`:
/// ```json
/// { "sod_base64": "<base64 SOD DER>", "data_groups": {"DG1": "<b64>"}, "country": "DEU" }
/// ```
///
/// Uses an **empty** CSCA registry (no trust anchors loaded), so chain validation will
/// return `ChainStatus::Invalid` on any real credential.  This is intentional — the
/// function is designed for testing JSON parsing, error paths, and `VerificationResult`
/// shape without a running database or Tauri runtime.
pub fn verify_emrtd_offline(
    credential_data_json: &str,
) -> crate::error::AppResult<VerificationResult> {
    let payload: EmrtdPayload = serde_json::from_str(credential_data_json)
        .map_err(|e| AppError::Verification(format!("Invalid eMRTD payload JSON: {}", e)))?;

    if payload.sod_base64.trim().is_empty() {
        return Err(AppError::Verification(
            "eMRTD payload missing or empty sod_base64".to_string(),
        ));
    }

    let sod_bytes = BASE64_STANDARD
        .decode(payload.sod_base64.as_bytes())
        .map_err(|e| AppError::Verification(format!("Invalid SOD base64: {}", e)))?;

    let security_object = SecurityObject::from_sod_der(&sod_bytes, payload.country.clone())
        .map_err(|e| AppError::Verification(format!("Failed to parse SOD: {}", e)))?;

    let mut dg_map: HashMap<u8, Vec<u8>> = HashMap::new();
    for (dg_name, b64) in payload.data_groups {
        let num = dg_name
            .trim_start_matches("DG")
            .parse::<u8>()
            .map_err(|_| AppError::Verification(format!("Invalid data group name: {}", dg_name)))?;
        if num == 0 {
            return Err(AppError::Verification(format!(
                "Invalid data group name: {} (DG0 is not defined in ICAO 9303)",
                dg_name
            )));
        }
        let dg_bytes = BASE64_STANDARD.decode(b64.as_bytes()).map_err(|e| {
            AppError::Verification(format!("Invalid base64 for {}: {}", dg_name, e))
        })?;
        dg_map.insert(num, dg_bytes);
    }

    // Empty registry — chain will show Invalid, but all other fields are populated
    let registry = CscaRegistry::new();
    let verification = verify_emrtd(&security_object, &dg_map, &registry);

    let status = if verification.verified {
        VerificationStatus::Valid
    } else if verification
        .errors
        .iter()
        .any(|e| e.contains("expired") || e.contains("not yet valid"))
    {
        VerificationStatus::Invalid
    } else {
        VerificationStatus::Failed
    };

    let issuer_subject = security_object
        .signer_certificate
        .certificate
        .tbs_certificate
        .subject
        .to_string();

    let country = security_object
        .signer_certificate
        .country
        .or(verification.country.clone());

    Ok(VerificationResult {
        verification_id: uuid::Uuid::new_v4().to_string(),
        status,
        credential_type: "emrtd".to_string(),
        issuer: Some(IssuerInfo {
            name: Some("Passport Issuer".to_string()),
            jurisdiction: country.clone(),
            subject: Some(issuer_subject),
        }),
        disclosed_claims: serde_json::json!({ "document_type": "passport" }),
        trust_chain: TrustChainStatus {
            valid: verification.dsc_chain_status
                == marty_verification::verification::emrtd::ChainStatus::Valid,
            chain_type: "csca".to_string(),
            trust_anchor: country,
            offline_verified: true,
        },
        revocation_status: RevocationStatus::Unknown,
        verified_at: chrono::Utc::now().to_rfc3339(),
        warnings: {
            let mut w = vec!["Verified offline with empty CSCA registry".to_string()];
            w.extend(verification.errors.clone());
            w
        },
        emrtd_details: Some(EmrtdDetails {
            dsc_chain_status: format!("{:?}", verification.dsc_chain_status),
            sod_signature_status: format!("{:?}", verification.sod_signature_status),
            dg_hash_status: format!("{:?}", verification.dg_hash_status),
            errors: verification.errors,
        }),
        dtc_details: None,
        open_badge_details: None,
        liveness: None,
        face_match: None,
    })
}

pub(super) async fn verify_emrtd_payload(
    request: &VerifyRequest,
    state: &AppState,
    is_online: bool,
) -> AppResult<VerificationResult> {
    // NFC-only mode with no payload currently not implemented
    if request.use_nfc && request.credential_data.trim().is_empty() {
        return Err(AppError::Verification(
            "NFC read requested but no reader integration is configured yet. Provide an eMRTD payload or disable use_nfc.".to_string(),
        ));
    }

    let payload: EmrtdPayload = serde_json::from_str(&request.credential_data)
        .map_err(|e| AppError::Verification(format!("Invalid eMRTD payload JSON: {}", e)))?;

    let sod_bytes = BASE64_STANDARD
        .decode(payload.sod_base64.as_bytes())
        .map_err(|e| AppError::Verification(format!("Invalid SOD base64: {}", e)))?;

    // Build security object from SOD
    let security_object = SecurityObject::from_sod_der(&sod_bytes, payload.country.clone())
        .map_err(|e| {
            AppError::Verification(format!("Failed to parse SOD for verification: {}", e))
        })?;

    // Decode DGs
    let mut dg_map: HashMap<u8, Vec<u8>> = HashMap::new();
    for (dg_name, b64) in payload.data_groups {
        let num = dg_name
            .trim_start_matches("DG")
            .parse::<u8>()
            .map_err(|_| AppError::Verification(format!("Invalid data group name: {}", dg_name)))?;
        let dg_bytes = BASE64_STANDARD.decode(b64.as_bytes()).map_err(|e| {
            AppError::Verification(format!("Invalid base64 for {}: {}", dg_name, e))
        })?;
        dg_map.insert(num, dg_bytes);
    }

    // Build CSCA registry from secure storage
    let registry = build_csca_registry(state).await?;

    // NFC path: route through reader abstraction to exercise chip I/O flow.
    let verification = if request.use_nfc {
        let reader =
            MockPassportReader::new(sod_bytes.clone(), dg_map.clone(), payload.country.clone());
        verify_from_reader(&reader, &registry)
    } else {
        // Build security object from SOD
        let security_object = SecurityObject::from_sod_der(&sod_bytes, payload.country.clone())
            .map_err(|e| {
                AppError::Verification(format!("Failed to parse SOD for verification: {}", e))
            })?;
        verify_emrtd(&security_object, &dg_map, &registry)
    };

    let status = if verification.verified {
        VerificationStatus::Valid
    } else if verification
        .errors
        .iter()
        .any(|e| e.contains("expired") || e.contains("not yet valid"))
    {
        VerificationStatus::Invalid
    } else {
        VerificationStatus::Failed
    };

    let warnings = if is_online {
        Vec::new()
    } else {
        vec!["Verified offline with cached CSCA anchors".to_string()]
    };

    let issuer_subject = security_object
        .signer_certificate
        .certificate
        .tbs_certificate
        .subject
        .to_string();

    let country = security_object
        .signer_certificate
        .country
        .or(verification.country.clone());

    Ok(VerificationResult {
        verification_id: request
            .credential_data
            .get(0..12)
            .map(|s| s.to_string())
            .unwrap_or_else(|| uuid::Uuid::new_v4().to_string()),
        status,
        credential_type: request.credential_type.clone(),
        issuer: Some(IssuerInfo {
            name: Some("Passport Issuer".to_string()),
            jurisdiction: country.clone(),
            subject: Some(issuer_subject),
        }),
        disclosed_claims: serde_json::json!({ "document_type": "passport" }),
        trust_chain: TrustChainStatus {
            valid: verification.dsc_chain_status
                == marty_verification::verification::emrtd::ChainStatus::Valid,
            chain_type: "csca".to_string(),
            trust_anchor: country,
            offline_verified: !is_online,
        },
        revocation_status: RevocationStatus::Unknown,
        verified_at: chrono::Utc::now().to_rfc3339(),
        warnings: if verification.errors.is_empty() {
            warnings
        } else {
            let mut w = warnings;
            w.extend(verification.errors.clone());
            w
        },
        emrtd_details: Some(EmrtdDetails {
            dsc_chain_status: format!("{:?}", verification.dsc_chain_status),
            sod_signature_status: format!("{:?}", verification.sod_signature_status),
            dg_hash_status: format!("{:?}", verification.dg_hash_status),
            errors: verification.errors,
        }),
        dtc_details: None,
        open_badge_details: None,
        liveness: None,
        face_match: None,
    })
}

pub(super) async fn build_csca_registry(state: &AppState) -> AppResult<CscaRegistry> {
    let records = state
        .trust_storage
        .get_trust_anchor_records(CoreTrustAnchorType::Csca, None)
        .await?;
    let max_offline_hours = state.config.read().await.sync_config.max_offline_hours;
    let now = Utc::now();

    let mut registry = CscaRegistry::new();
    for record in records
        .into_iter()
        .filter(|record| governed_csca_record_is_usable(record, now, max_offline_hours))
    {
        let anchor = record.anchor;
        let cert = Certificate::from_der(&anchor.certificate_der).map_err(|e| {
            AppError::Verification(format!(
                "Failed to parse CSCA certificate {}: {}",
                anchor.id, e
            ))
        })?;
        registry
            .add_country_csca(&anchor.jurisdiction, cert)
            .map_err(|e| AppError::Verification(e.to_string()))?;
    }

    Ok(registry)
}
