//! Open badges verification operations.

use super::VERIFIER_SOFTWARE_PROVENANCE;
use super::{
    detect_open_badges_version, parse_json_input, AppError, AppResult, AppState,
    ArtifactProvenance, AuthenticatedStatusList, DateTime, DocumentStore, Duration,
    GovernedOpenBadgeStore, HashSet, IssuerInfo, OpenBadgeDetails, OpenBadgeStatusEvidence,
    OpenBadgeStatusEvidenceOutcome, OpenBadgeTrustConfig, OpenBadgeTrustFreshness,
    OpenBadgeTrustPolicy, OpenBadgeTrustRecord, OpenBadgeVerificationMethod, OpenBadgesVersion,
    RevocationStatus, StatusAuthorityProvenance, TrustChainStatus, Utc, Value, VerificationResult,
    VerificationStatus, VerifyRequest, MAX_OPEN_BADGE_STATUS_IRI_CHARS,
    MAX_OPEN_BADGE_STATUS_LIST_SIGNED_AGE_HOURS, MAX_OPEN_BADGE_TRUST_AGE_HOURS,
};
use marty_verification::open_badges::{
    verify_ob2, verify_ob3_with_status_lists_async, OpenBadgeStatusCheck, OpenBadgeStatusOutcome,
    OpenBadgesVerificationResult, VerifyOb2Request, VerifyOb3Request,
};
use std::io::Read;

pub(super) async fn verify_open_badge_payload(
    request: &VerifyRequest,
    state: &AppState,
    is_online: bool,
) -> AppResult<VerificationResult> {
    let raw = parse_json_input(&request.credential_data, "Open Badge")?;
    let (version, mut req_value) = build_open_badge_request(&raw)?;

    let trust_config = state.config.read().await.open_badge_trust.clone();
    ensure_production_open_badge_policy(&trust_config.policy)?;
    let now = Utc::now();
    let trust_records = state.trust_storage.get_open_badge_trust_records().await?;
    let mut warnings = Vec::new();
    let (governed_store, rejected_records) =
        build_governed_open_badge_store(&trust_records, now, trust_config.stale_critical_hours);

    if rejected_records > 0 {
        warnings.push(format!(
            "Rejected {rejected_records} Open Badge trust record(s) with invalid lifecycle or binding metadata"
        ));
    }

    if governed_store.documents.is_empty() {
        warnings.push("Governed Open Badge trust store is empty".to_string());
    }

    let method_id = extract_open_badge_method_id(&req_value, version);
    let method_trusted =
        open_badge_request_method_trusted(&governed_store.documents, method_id.as_deref());
    if !method_trusted {
        let (warning, error) = match method_id.as_deref() {
            Some(_) => (
                "Open Badge verification method is not trusted".to_string(),
                "Verification method not trusted",
            ),
            None => (
                "Open Badge verification method is missing".to_string(),
                "Verification method missing",
            ),
        };
        warnings.push(warning);
        return Ok(build_open_badge_result(
            request,
            version,
            false,
            warnings,
            None,
            None,
            is_online,
            OpenBadgeDetails {
                version: open_badge_version_label(version).to_string(),
                errors: vec![error.to_string()],
                error_codes: Vec::new(),
                warnings: Vec::new(),
                status_checks: Vec::new(),
                normalized: None,
            },
        ));
    }

    let (authenticated_status_lists, status_adapter_warnings) =
        build_authenticated_status_lists(&req_value, &governed_store, now, &trust_config).await?;
    warnings.extend(status_adapter_warnings);

    replace_open_badge_document_store(&mut req_value, &governed_store.documents)?;

    let result = verify_open_badge_request(version, req_value, &authenticated_status_lists).await?;
    let mut valid = result.valid;
    let mut details = open_badge_details(result);
    let normalized = details.normalized.clone();

    match open_badge_trust_freshness(state, &trust_config).await? {
        OpenBadgeTrustFreshness::Fresh => {}
        OpenBadgeTrustFreshness::Warning(message) => warnings.push(message),
        OpenBadgeTrustFreshness::Unavailable(message) => {
            valid = false;
            warnings.push(message);
            details
                .errors
                .push("Open Badge trust data unavailable".to_string());
        }
    }

    Ok(build_open_badge_result(
        request, version, valid, warnings, method_id, normalized, is_online, details,
    ))
}

pub(super) fn build_open_badge_request(raw: &Value) -> AppResult<(OpenBadgesVersion, Value)> {
    if let Value::Object(obj) = raw {
        if let Some(assertion) = obj.get("assertion") {
            let version = detect_open_badges_version(assertion);
            return Ok((version, raw.clone()));
        }
        if let Some(credential) = obj.get("credential") {
            let version = detect_open_badges_version(credential);
            return Ok((version, raw.clone()));
        }
    }

    let version = detect_open_badges_version(raw);
    match version {
        OpenBadgesVersion::V2 => Ok((version, serde_json::json!({ "assertion": raw }))),
        OpenBadgesVersion::V3 => Ok((version, serde_json::json!({ "credential": raw }))),
        OpenBadgesVersion::Unknown => Err(AppError::Verification(
            "Unable to detect Open Badge version".to_string(),
        )),
    }
}

pub(super) fn build_governed_open_badge_store(
    records: &[OpenBadgeTrustRecord],
    now: DateTime<Utc>,
    stale_critical_hours: u32,
) -> (GovernedOpenBadgeStore, usize) {
    let mut governed = GovernedOpenBadgeStore::default();
    let mut ambiguous_ids = HashSet::new();
    let mut rejected_records = 0;

    for record in records {
        if !open_badge_governed_record_is_usable(record, now, stale_critical_hours) {
            rejected_records += 1;
            continue;
        }
        let Some(provenance) = record.provenance.as_ref() else {
            rejected_records += 1;
            continue;
        };
        let method = &record.method;

        if ambiguous_ids.contains(&method.id) {
            rejected_records += 1;
        } else if governed.documents.remove(&method.id).is_some() {
            governed.provenance_by_document.remove(&method.id);
            ambiguous_ids.insert(method.id.clone());
            rejected_records += 2;
        } else {
            governed
                .documents
                .insert(method.id.clone(), method.document.clone());
            governed
                .provenance_by_document
                .insert(method.id.clone(), provenance.clone());
        }
    }

    (governed, rejected_records)
}

pub(super) fn open_badge_governed_record_is_usable(
    record: &OpenBadgeTrustRecord,
    now: DateTime<Utc>,
    stale_critical_hours: u32,
) -> bool {
    let Some(provenance) = record.provenance.as_ref() else {
        return false;
    };
    if provenance.created_at != record.method.synced_at
        || provenance.created_at > now
        || provenance.expires_at <= now
        || provenance.created_at >= provenance.expires_at
        || provenance.imported_at < provenance.created_at
        || provenance.imported_at > now
    {
        return false;
    }

    open_badge_trust_record_is_usable(&record.method, now, stale_critical_hours)
}

#[cfg(test)]
pub(super) fn build_trusted_open_badge_store(
    methods: &[OpenBadgeVerificationMethod],
    now: DateTime<Utc>,
    stale_critical_hours: u32,
) -> (DocumentStore, usize) {
    let mut store = DocumentStore::new();
    let mut ambiguous_ids = HashSet::new();
    let mut rejected_records = 0;

    for method in methods {
        if !open_badge_trust_record_is_usable(method, now, stale_critical_hours) {
            rejected_records += 1;
            continue;
        }

        if ambiguous_ids.contains(&method.id) {
            rejected_records += 1;
        } else if store.remove(&method.id).is_some() {
            ambiguous_ids.insert(method.id.clone());
            rejected_records += 2;
        } else {
            store.insert(method.id.clone(), method.document.clone());
        }
    }

    (store, rejected_records)
}

pub(super) fn open_badge_trust_record_is_usable(
    method: &OpenBadgeVerificationMethod,
    now: DateTime<Utc>,
    stale_critical_hours: u32,
) -> bool {
    if method.status.as_deref() != Some("active") || method.synced_at > now {
        return false;
    }

    let (Some(not_before), Some(not_after)) = (method.not_before, method.not_after) else {
        return false;
    };
    if not_before > now || not_after <= now || not_before >= not_after {
        return false;
    }

    let critical_age = Duration::hours(i64::from(
        stale_critical_hours.min(MAX_OPEN_BADGE_TRUST_AGE_HOURS),
    ));
    if critical_age <= Duration::zero()
        || now.signed_duration_since(method.synced_at) >= critical_age
    {
        return false;
    }

    let Some(document) = method.document.as_object() else {
        return false;
    };
    if document.get("id").and_then(Value::as_str) != Some(method.id.as_str()) {
        return false;
    }

    let Some(controller) = method.controller.as_deref() else {
        return false;
    };
    if document.get("controller").and_then(Value::as_str) != Some(controller) {
        return false;
    }

    !contains_private_jwk(&method.document)
}

pub(super) fn contains_private_jwk(value: &Value) -> bool {
    match value {
        Value::Object(object) => object.iter().any(|(key, nested)| {
            if key.starts_with("privateKey") || key == "secretKeyJwk" {
                return true;
            }

            if key == "publicKeyJwk" {
                return nested.as_object().is_none_or(|jwk| {
                    matches!(jwk.get("kty").and_then(Value::as_str), Some("oct") | None)
                        || ["d", "p", "q", "dp", "dq", "qi", "oth", "k"]
                            .iter()
                            .any(|private| jwk.contains_key(*private))
                });
            }

            contains_private_jwk(nested)
        }),
        Value::Array(items) => items.iter().any(contains_private_jwk),
        _ => false,
    }
}

pub(super) fn extract_open_badge_method_id(
    request: &Value,
    version: OpenBadgesVersion,
) -> Option<String> {
    match version {
        OpenBadgesVersion::V2 => request.get("assertion").and_then(extract_ob2_method_id),
        OpenBadgesVersion::V3 => request.get("credential").and_then(extract_ob3_method_id),
        OpenBadgesVersion::Unknown => None,
    }
}

pub(super) fn extract_ob2_method_id(assertion: &Value) -> Option<String> {
    let verification = assertion.get("verification")?;
    extract_ob2_verification_value(verification)
}

pub(super) fn extract_ob2_verification_value(value: &Value) -> Option<String> {
    match value {
        Value::String(_) => extract_method_id_from_value(value),
        Value::Object(obj) => {
            if let Some(creator) = obj.get("creator") {
                return extract_method_id_from_value(creator);
            }
            if let Some(method) = obj.get("verificationMethod") {
                return extract_method_id_from_value(method);
            }
            None
        }
        Value::Array(items) => items.iter().find_map(extract_ob2_verification_value),
        _ => None,
    }
}

pub(super) fn extract_ob3_method_id(credential: &Value) -> Option<String> {
    let proof = credential.get("proof")?;
    extract_ob3_proof_method_id(proof)
}

pub(super) fn extract_ob3_proof_method_id(value: &Value) -> Option<String> {
    match value {
        Value::String(_) => extract_method_id_from_value(value),
        Value::Object(obj) => {
            if let Some(method) = obj.get("verificationMethod") {
                if let Some(found) = extract_method_id_from_value(method) {
                    return Some(found);
                }
            }
            if let Some(creator) = obj.get("creator") {
                if let Some(found) = extract_method_id_from_value(creator) {
                    return Some(found);
                }
            }
            obj.get("id")
                .and_then(|v| v.as_str())
                .map(|s| s.to_string())
        }
        Value::Array(items) => items.iter().find_map(extract_ob3_proof_method_id),
        _ => None,
    }
}

pub(super) fn extract_method_id_from_value(value: &Value) -> Option<String> {
    match value {
        Value::String(method) => Some(method.to_string()),
        Value::Object(obj) => obj
            .get("id")
            .and_then(|v| v.as_str())
            .map(|s| s.to_string()),
        _ => None,
    }
}

pub(super) fn extract_open_badge_document_store(request: &Value) -> AppResult<DocumentStore> {
    match request.get("document_store") {
        None | Some(Value::Null) => Ok(DocumentStore::new()),
        Some(Value::Object(map)) => {
            let mut store = DocumentStore::new();
            for (key, value) in map {
                store.insert(key.clone(), value.clone());
            }
            Ok(store)
        }
        _ => Err(AppError::Verification(
            "document_store must be a JSON object".to_string(),
        )),
    }
}

pub(super) async fn build_authenticated_status_lists(
    request: &Value,
    governed_store: &GovernedOpenBadgeStore,
    observed_at: DateTime<Utc>,
    config: &OpenBadgeTrustConfig,
) -> AppResult<(Vec<AuthenticatedStatusList>, Vec<String>)> {
    let status_list_urls = extract_status_list_urls(request);
    let request_store = extract_stapled_status_documents(request, &status_list_urls)?;
    if status_list_urls.is_empty() {
        return Ok((Vec::new(), Vec::new()));
    }

    let software = verifier_software_provenance().await?;
    let mut authenticated = Vec::new();
    let mut warnings = Vec::new();
    for status_list_url in status_list_urls {
        match build_authenticated_status_list(
            &status_list_url,
            &request_store,
            governed_store,
            observed_at,
            config,
            &software,
        ) {
            Ok(status_list) => authenticated.push(status_list),
            Err(reason) => warnings.push(format!(
                "A declared status list was not admitted as authenticated context: {reason}"
            )),
        }
    }

    Ok((authenticated, warnings))
}

pub(super) fn extract_stapled_status_documents(
    request: &Value,
    status_list_urls: &[String],
) -> AppResult<DocumentStore> {
    let Some(value) = request.get("document_store") else {
        return Ok(DocumentStore::new());
    };
    if value.is_null() {
        return Ok(DocumentStore::new());
    }
    let Value::Object(request_store) = value else {
        return Err(AppError::Verification(
            "document_store must be a JSON object".to_string(),
        ));
    };

    Ok(status_list_urls
        .iter()
        .filter_map(|url| {
            request_store
                .get(url)
                .map(|credential| (url.clone(), credential.clone()))
        })
        .collect())
}

pub(super) fn extract_status_list_urls(request: &Value) -> Vec<String> {
    let Some(status) = request
        .get("credential")
        .and_then(|credential| credential.get("credentialStatus"))
    else {
        return Vec::new();
    };
    let entries: Vec<&Value> = match status {
        Value::Array(entries) if entries.len() <= 32 => entries.iter().collect(),
        Value::Object(_) => vec![status],
        _ => return Vec::new(),
    };

    let mut seen = HashSet::new();
    entries
        .into_iter()
        .filter(|entry| {
            entry.get("type").and_then(Value::as_str) == Some("BitstringStatusListEntry")
        })
        .filter_map(|entry| {
            entry
                .get("statusListCredential")
                .and_then(Value::as_str)
                .filter(|url| {
                    !url.is_empty() && url.chars().count() <= MAX_OPEN_BADGE_STATUS_IRI_CHARS
                })
                .map(str::to_string)
        })
        .filter(|url| seen.insert(url.clone()))
        .collect()
}

pub(super) fn build_authenticated_status_list(
    status_list_url: &str,
    request_store: &DocumentStore,
    governed_store: &GovernedOpenBadgeStore,
    observed_at: DateTime<Utc>,
    config: &OpenBadgeTrustConfig,
    software: &ArtifactProvenance,
) -> Result<AuthenticatedStatusList, String> {
    let credential = request_store.get(status_list_url).cloned().ok_or_else(|| {
        "the request did not staple a credential at the exact status URL".to_string()
    })?;
    let status_issuer = credential_issuer_id(&credential)
        .ok_or_else(|| "the stapled credential has no scalar issuer identifier".to_string())?;
    let status_method = extract_ob3_method_id(&credential).ok_or_else(|| {
        "the stapled credential has no scalar proof method identifier".to_string()
    })?;
    let provenance = governed_store
        .provenance_for_method(&status_method)
        .ok_or_else(|| "the status proof method is not in governed trust storage".to_string())?;
    let authority_documents = governed_store.authority_documents(provenance);
    if authority_documents.is_empty() {
        return Err("the governed package has no resolver-owned authority documents".to_string());
    }

    let valid_from = parse_status_list_time(&credential, "validFrom")?;
    let valid_until = parse_status_list_time(&credential, "validUntil")?;
    if valid_from > observed_at || valid_until <= observed_at || valid_until <= valid_from {
        return Err("the stapled credential is outside its signed validity period".to_string());
    }
    if config.status_list_max_age_hours == 0 || config.stale_critical_hours == 0 {
        return Err("status or trust freshness policy is disabled".to_string());
    }

    let status_list_max_age_hours = config
        .status_list_max_age_hours
        .min(MAX_OPEN_BADGE_STATUS_LIST_SIGNED_AGE_HOURS);
    let trust_max_age_hours = config
        .stale_critical_hours
        .min(MAX_OPEN_BADGE_TRUST_AGE_HOURS);
    let signed_age_deadline = valid_from
        .checked_add_signed(Duration::hours(i64::from(status_list_max_age_hours)))
        .ok_or_else(|| "status freshness deadline exceeds the supported range".to_string())?;
    let trust_age_deadline = provenance
        .created_at
        .checked_add_signed(Duration::hours(i64::from(trust_max_age_hours)))
        .ok_or_else(|| "trust freshness deadline exceeds the supported range".to_string())?;
    let fresh_until = [
        valid_until,
        signed_age_deadline,
        trust_age_deadline,
        provenance.expires_at,
    ]
    .into_iter()
    .min()
    .ok_or_else(|| "no status freshness deadline is available".to_string())?;
    if fresh_until <= observed_at {
        return Err("the stapled credential exceeds the configured signed-age limit".to_string());
    }

    let package_digest = format!("blake3:{}", provenance.package_digest);
    let trust_profile = ArtifactProvenance::new(
        provenance.trust_domain.clone(),
        provenance.package_version.clone(),
        package_digest.clone(),
    )?;
    let resolver = ArtifactProvenance::new(
        provenance.signer_key_id.clone(),
        provenance.sequence.to_string(),
        package_digest,
    )?;
    let authority_provenance =
        StatusAuthorityProvenance::new(trust_profile, resolver, software.clone());

    AuthenticatedStatusList::new(
        status_list_url,
        credential,
        status_issuer,
        authority_documents,
        observed_at,
        fresh_until,
        authority_provenance,
    )
}

pub(super) fn credential_issuer_id(credential: &Value) -> Option<String> {
    match credential.get("issuer")? {
        Value::String(issuer) if !issuer.is_empty() => Some(issuer.clone()),
        Value::Object(issuer) => issuer
            .get("id")
            .and_then(Value::as_str)
            .filter(|id| !id.is_empty())
            .map(str::to_string),
        _ => None,
    }
}

pub(super) fn parse_status_list_time(
    credential: &Value,
    field: &str,
) -> Result<DateTime<Utc>, String> {
    let value = credential
        .get(field)
        .and_then(Value::as_str)
        .ok_or_else(|| format!("the stapled credential is missing scalar {field}"))?;
    DateTime::parse_from_rfc3339(value)
        .map(|time| time.with_timezone(&Utc))
        .map_err(|_| format!("the stapled credential has invalid {field}"))
}

pub(super) async fn verifier_software_provenance() -> AppResult<ArtifactProvenance> {
    let provenance = VERIFIER_SOFTWARE_PROVENANCE
        .get_or_try_init(|| async {
            tokio::task::spawn_blocking(compute_verifier_software_provenance)
                .await
                .map_err(|error| {
                    AppError::Verification(format!("Software provenance task failed: {error}"))
                })?
                .map_err(|error| {
                    AppError::Verification(format!("Software provenance unavailable: {error}"))
                })
        })
        .await?;
    Ok(provenance.clone())
}

pub(super) fn compute_verifier_software_provenance() -> Result<ArtifactProvenance, String> {
    let executable = std::env::current_exe()
        .map_err(|error| format!("could not locate the running executable: {error}"))?;
    let mut file = std::fs::File::open(&executable)
        .map_err(|error| format!("could not read the running executable: {error}"))?;
    let mut context = ring::digest::Context::new(&ring::digest::SHA256);
    let mut buffer = [0_u8; 64 * 1024];
    loop {
        let count = file
            .read(&mut buffer)
            .map_err(|error| format!("could not hash the running executable: {error}"))?;
        if count == 0 {
            break;
        }
        context.update(&buffer[..count]);
    }
    let digest = context.finish();
    let mut digest_hex = String::with_capacity(digest.as_ref().len() * 2);
    const HEX: &[u8; 16] = b"0123456789abcdef";
    for byte in digest.as_ref() {
        digest_hex.push(HEX[usize::from(byte >> 4)] as char);
        digest_hex.push(HEX[usize::from(byte & 0x0f)] as char);
    }

    ArtifactProvenance::new(
        "marty-verifier-executable",
        env!("CARGO_PKG_VERSION"),
        format!("sha256:{digest_hex}"),
    )
}

pub(super) fn merge_open_badge_offline_store(
    base: &mut DocumentStore,
    supplemental: &DocumentStore,
) {
    for (key, value) in supplemental {
        if base.contains_key(key) {
            continue;
        }
        base.insert(key.clone(), value.clone());
    }
}

pub(super) fn replace_open_badge_document_store(
    request: &mut Value,
    trusted_store: &DocumentStore,
) -> AppResult<()> {
    let Value::Object(obj) = request else {
        return Err(AppError::Verification(
            "Open Badge verification request must be a JSON object".to_string(),
        ));
    };

    obj.insert(
        "document_store".to_string(),
        serde_json::to_value(trusted_store)?,
    );
    Ok(())
}

pub(super) fn open_badge_method_trusted(store: &DocumentStore, method_id: &str) -> bool {
    if store.contains_key(method_id) {
        return true;
    }

    if let Some((base, _)) = method_id.split_once('#') {
        if store.contains_key(base) {
            return true;
        }
    }

    false
}

pub(super) fn open_badge_request_method_trusted(
    store: &DocumentStore,
    method_id: Option<&str>,
) -> bool {
    method_id
        .map(|method_id| open_badge_method_trusted(store, method_id))
        .unwrap_or(false)
}

pub(super) fn ensure_production_open_badge_policy(policy: &OpenBadgeTrustPolicy) -> AppResult<()> {
    if matches!(policy, OpenBadgeTrustPolicy::FailOpen) {
        return Err(AppError::Config(
            "Open Badge fail-open trust policy is not permitted for production verification"
                .to_string(),
        ));
    }

    Ok(())
}

pub(super) fn extract_string_list(value: Option<&Value>) -> Vec<String> {
    value
        .and_then(|v| v.as_array())
        .map(|items| {
            items
                .iter()
                .filter_map(|item| item.as_str().map(|s| s.to_string()))
                .collect()
        })
        .unwrap_or_default()
}

async fn verify_open_badge_request(
    version: OpenBadgesVersion,
    request: Value,
    status_lists: &[AuthenticatedStatusList],
) -> AppResult<OpenBadgesVerificationResult> {
    let result = match version {
        OpenBadgesVersion::V2 => {
            let request: VerifyOb2Request = serde_json::from_value(request).map_err(|error| {
                AppError::Verification(format!(
                    "Open Badge verify failed: {}",
                    marty_verification::VerificationError::open_badges(format!(
                        "Invalid OB2 verify request: {error}"
                    ))
                ))
            })?;
            verify_ob2(request)
        }
        OpenBadgesVersion::V3 => {
            let request: VerifyOb3Request = serde_json::from_value(request).map_err(|error| {
                AppError::Verification(format!(
                    "Open Badge verify failed: {}",
                    marty_verification::VerificationError::open_badges(format!(
                        "Invalid OB3 verify request: {error}"
                    ))
                ))
            })?;
            // Keep the cryptographic verifier's large future out of the Tauri
            // command future's layout and stack footprint.
            Box::pin(verify_ob3_with_status_lists_async(request, status_lists)).await
        }
        OpenBadgesVersion::Unknown => {
            return Err(AppError::Verification(
                "Unable to detect Open Badge version".to_string(),
            ))
        }
    };
    result.map_err(|error| AppError::Verification(format!("Open Badge verify failed: {error}")))
}

fn open_badge_details(result: OpenBadgesVerificationResult) -> OpenBadgeDetails {
    OpenBadgeDetails {
        version: result.version,
        errors: result.errors,
        error_codes: result.error_codes,
        warnings: result.warnings,
        status_checks: result.status_checks.into_iter().map(Into::into).collect(),
        normalized: result.normalized,
    }
}

impl From<OpenBadgeStatusCheck> for OpenBadgeStatusEvidence {
    fn from(check: OpenBadgeStatusCheck) -> Self {
        Self {
            status_list_url: check.status_list_url,
            status_issuer: check.status_issuer,
            status_purpose: check.status_purpose,
            status_list_index: check.status_list_index,
            status_size: check.status_size,
            status_value: check.status_value,
            outcome: match check.outcome {
                OpenBadgeStatusOutcome::Good => OpenBadgeStatusEvidenceOutcome::Good,
                OpenBadgeStatusOutcome::Revoked => OpenBadgeStatusEvidenceOutcome::Revoked,
                OpenBadgeStatusOutcome::Suspended => OpenBadgeStatusEvidenceOutcome::Suspended,
                OpenBadgeStatusOutcome::Message => OpenBadgeStatusEvidenceOutcome::Message,
            },
            checked_at: check.checked_at,
            retrieved_at: check.retrieved_at,
            fresh_until: check.fresh_until,
            authority_provenance: super::OpenBadgeStatusAuthorityEvidence {
                trust_profile: check.authority_provenance.trust_profile().into(),
                resolver: check.authority_provenance.resolver().into(),
                software: check.authority_provenance.software().into(),
            },
        }
    }
}

impl From<&ArtifactProvenance> for super::OpenBadgeArtifactEvidence {
    fn from(provenance: &ArtifactProvenance) -> Self {
        Self {
            id: provenance.id().to_owned(),
            version: provenance.version().to_owned(),
            digest: provenance.digest().to_owned(),
        }
    }
}

pub(super) fn open_badge_revocation_status(
    status_checks: &[OpenBadgeStatusEvidence],
    verification_valid: bool,
) -> RevocationStatus {
    if status_checks
        .iter()
        .any(|check| check.outcome == OpenBadgeStatusEvidenceOutcome::Revoked)
    {
        return RevocationStatus::Revoked;
    }
    if verification_valid
        && status_checks.iter().any(|check| {
            check.status_purpose == "revocation"
                && check.outcome == OpenBadgeStatusEvidenceOutcome::Good
        })
    {
        return RevocationStatus::Valid;
    }

    RevocationStatus::Unknown
}

pub(super) fn classify_open_badge_trust_freshness(
    last_sync: Option<DateTime<Utc>>,
    now: DateTime<Utc>,
    config: &OpenBadgeTrustConfig,
) -> OpenBadgeTrustFreshness {
    let Some(last_sync) = last_sync else {
        return OpenBadgeTrustFreshness::Unavailable(
            "Open Badge trust list has never been synchronized".to_string(),
        );
    };

    let age = now.signed_duration_since(last_sync);
    if age < Duration::zero() {
        return OpenBadgeTrustFreshness::Unavailable(
            "Open Badge trust list synchronization timestamp is in the future".to_string(),
        );
    }

    let age_hours = age.num_minutes() as f64 / 60.0;
    if age
        >= Duration::hours(i64::from(
            config
                .stale_critical_hours
                .min(MAX_OPEN_BADGE_TRUST_AGE_HOURS),
        ))
    {
        return OpenBadgeTrustFreshness::Unavailable(format!(
            "Open Badge trust list critically stale ({age_hours:.1} hours old)"
        ));
    }

    if age >= Duration::hours(i64::from(config.stale_warning_hours)) {
        return OpenBadgeTrustFreshness::Warning(format!(
            "Open Badge trust list stale ({age_hours:.1} hours old)"
        ));
    }

    OpenBadgeTrustFreshness::Fresh
}

pub(super) async fn open_badge_trust_freshness(
    state: &AppState,
    config: &OpenBadgeTrustConfig,
) -> AppResult<OpenBadgeTrustFreshness> {
    let last_sync = state.trust_storage.get_latest_open_badge_sync().await?;
    Ok(classify_open_badge_trust_freshness(
        last_sync,
        Utc::now(),
        config,
    ))
}

pub(super) fn open_badge_version_label(version: OpenBadgesVersion) -> &'static str {
    match version {
        OpenBadgesVersion::V2 => "2.0",
        OpenBadgesVersion::V3 => "3.0",
        OpenBadgesVersion::Unknown => "unknown",
    }
}

#[allow(clippy::too_many_arguments)]
pub(super) fn build_open_badge_result(
    request: &VerifyRequest,
    version: OpenBadgesVersion,
    valid: bool,
    warnings: Vec<String>,
    trust_anchor: Option<String>,
    normalized: Option<Value>,
    is_online: bool,
    details: OpenBadgeDetails,
) -> VerificationResult {
    let revocation_status = open_badge_revocation_status(&details.status_checks, valid);
    let disclosed_claims = normalized
        .as_ref()
        .map(open_badge_claims_from_normalized)
        .unwrap_or_else(|| serde_json::json!({}));
    let issuer = normalized
        .as_ref()
        .and_then(open_badge_issuer_from_normalized);

    VerificationResult {
        verification_id: uuid::Uuid::new_v4().to_string(),
        status: if valid {
            VerificationStatus::Valid
        } else {
            VerificationStatus::Invalid
        },
        credential_type: request.credential_type.clone(),
        issuer,
        disclosed_claims,
        trust_chain: TrustChainStatus {
            valid,
            chain_type: match version {
                OpenBadgesVersion::V2 | OpenBadgesVersion::V3 => "did".to_string(),
                OpenBadgesVersion::Unknown => "unknown".to_string(),
            },
            trust_anchor,
            offline_verified: !is_online,
        },
        revocation_status,
        verified_at: chrono::Utc::now().to_rfc3339(),
        warnings,
        emrtd_details: None,
        dtc_details: None,
        open_badge_details: Some(details),
        liveness: None,
        face_match: None,
    }
}

pub(super) fn open_badge_claims_from_normalized(normalized: &Value) -> Value {
    let mut claims = serde_json::Map::new();

    for (key, field) in [
        ("assertion_id", "assertion_id"),
        ("badge_id", "badge_id"),
        ("issuer_id", "issuer_id"),
        ("credential_id", "credential_id"),
        ("issuer", "issuer"),
    ] {
        if let Some(value) = normalized.get(field).and_then(|v| v.as_str()) {
            claims.insert(key.to_string(), Value::String(value.to_string()));
        }
    }

    if let Some(recipient) = normalized.get("recipient") {
        if let Some(identity) = recipient.get("identity").and_then(|v| v.as_str()) {
            claims.insert("recipient".to_string(), Value::String(identity.to_string()));
        } else if let Some(value) = recipient.as_str() {
            claims.insert("recipient".to_string(), Value::String(value.to_string()));
        }
    }

    if let Some(subject) = normalized.get("credential_subject") {
        if let Some(subject_id) = subject.get("id").and_then(|v| v.as_str()) {
            claims.insert(
                "subject_id".to_string(),
                Value::String(subject_id.to_string()),
            );
        }
    }

    Value::Object(claims)
}

pub(super) fn open_badge_issuer_from_normalized(normalized: &Value) -> Option<IssuerInfo> {
    let issuer_value = normalized
        .get("issuer")
        .or_else(|| normalized.get("issuer_id"))?;

    issuer_value.as_str().map(|issuer| IssuerInfo {
        name: Some(issuer.to_string()),
        jurisdiction: None,
        subject: None,
    })
}

/// Testable offline entry point for Open Badge verification (no `AppState`).
///
/// Uses an empty trusted-key store and the `FailOpen` policy so that badges
/// with embedded key documents can be verified without a running database.
/// Useful for testing JSON parsing, version detection, and `VerificationResult`
/// shape without Tauri/storage plumbing.
pub async fn verify_open_badge_offline(
    credential_data_json: &str,
) -> crate::error::AppResult<VerificationResult> {
    let raw = parse_json_input(credential_data_json, "Open Badge")?;
    let (version, mut req_value) = build_open_badge_request(&raw)?;

    // Empty store + explicit offline merge so embedded documents are accepted.
    let mut store = DocumentStore::new();

    let request_store = extract_open_badge_document_store(&req_value)?;
    merge_open_badge_offline_store(&mut store, &request_store);
    replace_open_badge_document_store(&mut req_value, &store)?;

    let method_id = extract_open_badge_method_id(&req_value, version);
    let result = verify_open_badge_request(version, req_value, &[]).await?;
    let valid = result.valid;
    let details = open_badge_details(result);
    let normalized = details.normalized.clone();
    let status_checks = &details.status_checks;

    let disclosed_claims = normalized
        .as_ref()
        .map(open_badge_claims_from_normalized)
        .unwrap_or_else(|| serde_json::json!({}));
    let issuer = normalized
        .as_ref()
        .and_then(open_badge_issuer_from_normalized);

    Ok(VerificationResult {
        verification_id: uuid::Uuid::new_v4().to_string(),
        status: if valid {
            VerificationStatus::Valid
        } else {
            VerificationStatus::Invalid
        },
        credential_type: "open-badge".to_string(),
        issuer,
        disclosed_claims,
        trust_chain: TrustChainStatus {
            valid,
            chain_type: match version {
                OpenBadgesVersion::V2 | OpenBadgesVersion::V3 => "did".to_string(),
                OpenBadgesVersion::Unknown => "unknown".to_string(),
            },
            trust_anchor: method_id,
            offline_verified: true,
        },
        revocation_status: open_badge_revocation_status(status_checks, valid),
        verified_at: chrono::Utc::now().to_rfc3339(),
        warnings: vec!["Verified offline — empty trust store".to_string()],
        emrtd_details: None,
        dtc_details: None,
        open_badge_details: Some(details),
        liveness: None,
        face_match: None,
    })
}

#[cfg(test)]
mod typed_adapter_tests {
    use super::*;

    #[test]
    fn typed_status_projection_preserves_all_evidence_fields_and_outcomes() {
        let now = DateTime::parse_from_rfc3339("2026-09-01T00:00:00Z")
            .unwrap()
            .with_timezone(&Utc);
        for outcome in [
            OpenBadgeStatusOutcome::Good,
            OpenBadgeStatusOutcome::Revoked,
            OpenBadgeStatusOutcome::Suspended,
            OpenBadgeStatusOutcome::Message,
        ] {
            let artifact = |id: &str| {
                ArtifactProvenance::new(id, "v1", format!("sha256:{}", "a".repeat(64))).unwrap()
            };
            let check = OpenBadgeStatusCheck {
                status_list_url: "https://status.example/list".into(),
                status_issuer: "did:example:status".into(),
                status_purpose: "message".into(),
                status_list_index: 42,
                status_size: 8,
                status_value: 7,
                outcome,
                checked_at: now,
                retrieved_at: now - Duration::minutes(1),
                fresh_until: now + Duration::hours(1),
                authority_provenance: StatusAuthorityProvenance::new(
                    artifact("profile"),
                    artifact("resolver"),
                    artifact("software"),
                ),
            };
            let wire = serde_json::to_value(&check).unwrap();
            let evidence = OpenBadgeStatusEvidence::from(check);
            assert_eq!(serde_json::to_value(evidence).unwrap(), wire);
        }
    }

    #[test]
    fn typed_details_preserve_absent_normalization_and_diagnostics() {
        let details = open_badge_details(OpenBadgesVerificationResult {
            valid: false,
            version: "3.0".into(),
            errors: vec!["failure".into()],
            error_codes: vec!["code".into()],
            warnings: vec!["warning".into()],
            status_checks: vec![],
            normalized: None,
        });
        assert_eq!(details.errors, ["failure"]);
        assert_eq!(details.error_codes, ["code"]);
        assert_eq!(details.warnings, ["warning"]);
        assert!(details.status_checks.is_empty());
        assert!(details.normalized.is_none());
    }

    #[tokio::test]
    async fn typed_request_adapter_rejects_missing_fields_and_unknown_versions() {
        for version in [
            OpenBadgesVersion::V2,
            OpenBadgesVersion::V3,
            OpenBadgesVersion::Unknown,
        ] {
            assert!(
                verify_open_badge_request(version, serde_json::json!({}), &[])
                    .await
                    .is_err()
            );
        }
    }
}
