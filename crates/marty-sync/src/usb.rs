//! USB import for air-gapped deployments

use std::collections::HashSet;
use std::fmt;
use std::path::Path;

use chrono::{DateTime, Utc};
use der::Decode;
use serde::de::{self, MapAccess, SeqAccess, Visitor};
use serde::{Deserialize, Deserializer, Serialize};
use serde_json::Value;
use x509_cert::Certificate;

use crate::{error::SyncError, signing_key::decode_signing_public_key};
use marty_secure_storage::{
    OpenBadgeKeySource, OpenBadgeVerificationMethod, TrustAnchor, TrustPackageProvenance,
    TrustPackageSignerPolicy,
};

const MAX_PACKAGE_BYTES: u64 = 16 * 1024 * 1024;
const MAX_PACKAGE_ENTRIES: usize = 4096;
const MAX_CERTIFICATE_BYTES: usize = 128 * 1024;
const MAX_IDENTIFIER_LEN: usize = 512;
const MAX_TRUST_DOMAIN_LEN: usize = 128;
const MAX_INFORMATIONAL_CERT_LEN: usize = 4096;
const MAX_PACKAGE_FUTURE_SKEW_SECONDS: i64 = 300;
const MAX_SAFE_JSON_INTEGER: u64 = 9_007_199_254_740_991;

/// USB import result
#[derive(Debug, Serialize, Deserialize)]
pub struct UsbImportResult {
    pub success: bool,
    pub certificates_imported: usize,
    pub open_badge_keys_imported: usize,
    pub signature_valid: bool,
    pub package_version: Option<String>,
    pub error: Option<String>,
}

/// USB trust anchor package format
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TrustAnchorPackage {
    /// Configured trust domain whose complete active set this package replaces.
    pub trust_domain: String,
    /// Strictly increasing sequence within the configured trust domain.
    pub sequence: u64,
    /// Package version
    pub version: String,
    /// Package creation timestamp
    pub created_at: String,
    /// Signed package expiry timestamp.
    pub expires_at: String,
    /// Stable identifier derived from the actual pinned verification key.
    pub signer_key_id: String,
    /// Optional exact key id authorized to sign one subsequent package.
    #[serde(deserialize_with = "deserialize_required_optional_string")]
    pub next_signer_key_id: Option<String>,
    /// Stable offline recovery key id. It cannot change after bootstrap.
    pub recovery_signer_key_id: String,
    /// Informational legacy certificate field. Trust comes only from the pinned key.
    #[serde(rename = "signing_cert")]
    pub _signing_cert: String,
    /// Package signature (base64)
    pub signature: String,
    /// IACA certificates (DER, base64 encoded)
    pub iaca_certificates: Vec<CertificateEntry>,
    /// CSCA certificates (DER, base64 encoded)
    pub csca_certificates: Vec<CertificateEntry>,
    /// DSC certificates (DER, base64 encoded)
    pub dsc_certificates: Vec<CertificateEntry>,
    /// Open Badge verification methods (trusted public keys)
    #[serde(default)]
    pub open_badge_verification_methods: Vec<serde_json::Value>,
}

/// Fully authenticated and strictly parsed package ready for one storage transition.
pub(crate) struct VerifiedTrustPackage {
    pub(crate) provenance: TrustPackageProvenance,
    pub(crate) signer_policy: TrustPackageSignerPolicy,
    pub(crate) anchors: Vec<TrustAnchor>,
    pub(crate) open_badge_methods: Vec<OpenBadgeVerificationMethod>,
}

struct VerifiedSignature {
    signer_key_id: String,
    package_digest: String,
}

/// Certificate entry in package
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CertificateEntry {
    /// Jurisdiction code
    pub jurisdiction: String,
    /// Certificate subject
    pub subject: Option<String>,
    /// Certificate issuer
    pub issuer: Option<String>,
    /// Certificate serial
    pub serial: Option<String>,
    /// Not before date
    #[serde(default, deserialize_with = "deserialize_declared_value")]
    not_before: DeclaredValue,
    /// Not after date
    #[serde(default, deserialize_with = "deserialize_declared_value")]
    not_after: DeclaredValue,
    /// DER-encoded certificate (base64)
    pub certificate_der_b64: String,
}

#[derive(Debug, Default)]
enum DeclaredValue {
    #[default]
    Missing,
    Present(Value),
}

fn deserialize_declared_value<'de, D>(deserializer: D) -> Result<DeclaredValue, D::Error>
where
    D: Deserializer<'de>,
{
    Value::deserialize(deserializer).map(DeclaredValue::Present)
}

fn deserialize_required_optional_string<'de, D>(deserializer: D) -> Result<Option<String>, D::Error>
where
    D: Deserializer<'de>,
{
    Option::<String>::deserialize(deserializer)
}

/// Import trust anchors from USB package
pub(crate) async fn import_from_usb(path: &Path) -> Result<VerifiedTrustPackage, SyncError> {
    tracing::info!(path = ?path, "Importing trust anchors from USB");

    // Check path exists
    if !path.exists() {
        return Err(SyncError::UsbImport(format!(
            "Package not found: {:?}",
            path
        )));
    }

    let package_size = std::fs::metadata(path)?.len();
    if package_size == 0 || package_size > MAX_PACKAGE_BYTES {
        return Err(SyncError::UsbImport(format!(
            "Package must contain between 1 and {MAX_PACKAGE_BYTES} bytes"
        )));
    }

    // Read package file
    let package_json = std::fs::read_to_string(path)?;

    // Parse without permitting duplicate JSON members or schema drift.
    let (package, package_value) = parse_strict_package(&package_json)?;

    // Verify against the configured/embedded key and bind the signed key id to
    // that actual key before deriving any records.
    let trusted_public_key = load_trusted_signing_public_key()?;
    let trusted_recovery_public_key = load_trusted_recovery_public_key()?;
    let verified_signature =
        verify_package_signature(&package_value, &package, &trusted_public_key)?;

    let created_at = parse_required_timestamp(&package.created_at, "package created_at")?;
    let expires_at = parse_required_timestamp(&package.expires_at, "package expires_at")?;
    let imported_at = Utc::now();
    validate_package_times(created_at, expires_at, imported_at)?;
    validate_package_metadata(
        &package,
        &verified_signature.signer_key_id,
        &signer_key_id(&trusted_recovery_public_key),
    )?;

    // Convert certificates to TrustAnchor format
    let mut anchors = Vec::new();
    let mut anchor_ids = HashSet::new();

    // Process IACA certificates
    for cert in &package.iaca_certificates {
        let anchor = parse_certificate_entry(
            cert,
            marty_secure_storage::TrustAnchorType::Iaca,
            created_at,
        )?;
        insert_unique_anchor(&mut anchors, &mut anchor_ids, anchor)?;
    }

    // Process CSCA certificates
    for cert in &package.csca_certificates {
        let anchor = parse_certificate_entry(
            cert,
            marty_secure_storage::TrustAnchorType::Csca,
            created_at,
        )?;
        insert_unique_anchor(&mut anchors, &mut anchor_ids, anchor)?;
    }

    // Process DSC certificates
    for cert in &package.dsc_certificates {
        let anchor =
            parse_certificate_entry(cert, marty_secure_storage::TrustAnchorType::Dsc, created_at)?;
        insert_unique_anchor(&mut anchors, &mut anchor_ids, anchor)?;
    }

    // Convert Open Badge verification methods
    let mut open_badge_keys = Vec::new();
    let mut method_ids = HashSet::new();
    for method in &package.open_badge_verification_methods {
        let entry = parse_open_badge_method(method, created_at)?;
        if !method_ids.insert(entry.id.clone()) {
            return Err(SyncError::Parse(format!(
                "Duplicate Open Badge method id {}",
                entry.id
            )));
        }
        open_badge_keys.push(entry);
    }

    tracing::info!(
        anchor_count = anchors.len(),
        open_badge_count = open_badge_keys.len(),
        trust_domain = %package.trust_domain,
        sequence = package.sequence,
        version = %package.version,
        "Authenticated trust materials from USB package"
    );

    Ok(VerifiedTrustPackage {
        signer_policy: TrustPackageSignerPolicy {
            next_signer_key_id: package.next_signer_key_id,
            recovery_signer_key_id: package.recovery_signer_key_id,
        },
        provenance: TrustPackageProvenance {
            trust_domain: package.trust_domain,
            sequence: package.sequence,
            package_version: package.version,
            created_at,
            expires_at,
            signer_key_id: verified_signature.signer_key_id,
            package_digest: verified_signature.package_digest,
            imported_at,
        },
        anchors,
        open_badge_methods: open_badge_keys,
    })
}

struct StrictJson(Value);

impl<'de> Deserialize<'de> for StrictJson {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer.deserialize_any(StrictJsonVisitor)
    }
}

struct StrictJsonVisitor;

impl<'de> Visitor<'de> for StrictJsonVisitor {
    type Value = StrictJson;

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("JSON without duplicate object members")
    }

    fn visit_bool<E>(self, value: bool) -> Result<Self::Value, E> {
        Ok(StrictJson(Value::Bool(value)))
    }

    fn visit_i64<E>(self, value: i64) -> Result<Self::Value, E> {
        Ok(StrictJson(Value::Number(value.into())))
    }

    fn visit_u64<E>(self, value: u64) -> Result<Self::Value, E> {
        Ok(StrictJson(Value::Number(value.into())))
    }

    fn visit_f64<E>(self, value: f64) -> Result<Self::Value, E>
    where
        E: de::Error,
    {
        serde_json::Number::from_f64(value)
            .map(Value::Number)
            .map(StrictJson)
            .ok_or_else(|| E::custom("non-finite JSON number"))
    }

    fn visit_str<E>(self, value: &str) -> Result<Self::Value, E> {
        Ok(StrictJson(Value::String(value.to_string())))
    }

    fn visit_string<E>(self, value: String) -> Result<Self::Value, E> {
        Ok(StrictJson(Value::String(value)))
    }

    fn visit_none<E>(self) -> Result<Self::Value, E> {
        Ok(StrictJson(Value::Null))
    }

    fn visit_unit<E>(self) -> Result<Self::Value, E> {
        Ok(StrictJson(Value::Null))
    }

    fn visit_some<D>(self, deserializer: D) -> Result<Self::Value, D::Error>
    where
        D: Deserializer<'de>,
    {
        StrictJson::deserialize(deserializer)
    }

    fn visit_seq<A>(self, mut sequence: A) -> Result<Self::Value, A::Error>
    where
        A: SeqAccess<'de>,
    {
        let mut values = Vec::new();
        while let Some(StrictJson(value)) = sequence.next_element()? {
            values.push(value);
        }
        Ok(StrictJson(Value::Array(values)))
    }

    fn visit_map<A>(self, mut object: A) -> Result<Self::Value, A::Error>
    where
        A: MapAccess<'de>,
    {
        let mut values = serde_json::Map::new();
        while let Some(key) = object.next_key::<String>()? {
            if values.contains_key(&key) {
                return Err(de::Error::custom(format!(
                    "duplicate JSON object member '{key}'"
                )));
            }
            let StrictJson(value) = object.next_value()?;
            values.insert(key, value);
        }
        Ok(StrictJson(Value::Object(values)))
    }
}

fn parse_strict_package(raw_json: &str) -> Result<(TrustAnchorPackage, Value), SyncError> {
    let mut deserializer = serde_json::Deserializer::from_str(raw_json);
    let StrictJson(value) = StrictJson::deserialize(&mut deserializer)
        .map_err(|error| SyncError::UsbImport(format!("Invalid package format: {error}")))?;
    deserializer
        .end()
        .map_err(|error| SyncError::UsbImport(format!("Invalid package format: {error}")))?;
    let package = serde_json::from_value(value.clone())
        .map_err(|error| SyncError::UsbImport(format!("Invalid package schema: {error}")))?;
    Ok((package, value))
}

fn validate_package_metadata(
    package: &TrustAnchorPackage,
    actual_signer_key_id: &str,
    configured_recovery_key_id: &str,
) -> Result<(), SyncError> {
    validate_trust_domain(&package.trust_domain)?;
    if package.sequence == 0 || package.sequence > MAX_SAFE_JSON_INTEGER {
        return Err(SyncError::Parse(
            "Package sequence must be within the interoperable JSON integer range".to_string(),
        ));
    }
    validate_identifier("package version", &package.version)?;
    validate_ed25519_key_id("package signer_key_id", &package.signer_key_id)?;
    if let Some(next_signer_key_id) = package.next_signer_key_id.as_deref() {
        validate_ed25519_key_id("package next_signer_key_id", next_signer_key_id)?;
        if next_signer_key_id == package.signer_key_id
            || next_signer_key_id == package.recovery_signer_key_id
        {
            return Err(SyncError::Parse(
                "Package next signer must differ from current and recovery signers".to_string(),
            ));
        }
    }
    validate_ed25519_key_id(
        "package recovery_signer_key_id",
        &package.recovery_signer_key_id,
    )?;
    if package.recovery_signer_key_id != configured_recovery_key_id {
        return Err(SyncError::SignatureVerification);
    }
    if package.signer_key_id != actual_signer_key_id {
        return Err(SyncError::SignatureVerification);
    }
    if package._signing_cert.len() > MAX_INFORMATIONAL_CERT_LEN
        || package._signing_cert.chars().any(char::is_control)
    {
        return Err(SyncError::Parse(
            "Informational signing_cert is oversized or contains control characters".to_string(),
        ));
    }
    let entries = package
        .iaca_certificates
        .len()
        .checked_add(package.csca_certificates.len())
        .and_then(|count| count.checked_add(package.dsc_certificates.len()))
        .and_then(|count| count.checked_add(package.open_badge_verification_methods.len()))
        .ok_or_else(|| SyncError::Parse("Package entry count overflow".to_string()))?;
    if entries > MAX_PACKAGE_ENTRIES {
        return Err(SyncError::Parse(format!(
            "Package exceeds the {MAX_PACKAGE_ENTRIES}-entry limit"
        )));
    }
    Ok(())
}

fn validate_package_times(
    created_at: DateTime<Utc>,
    expires_at: DateTime<Utc>,
    imported_at: DateTime<Utc>,
) -> Result<(), SyncError> {
    if created_at > imported_at + chrono::Duration::seconds(MAX_PACKAGE_FUTURE_SKEW_SECONDS) {
        return Err(SyncError::Parse(
            "Package created_at is beyond the allowed clock skew".to_string(),
        ));
    }
    if created_at >= expires_at {
        return Err(SyncError::Parse(
            "Package expires_at must be after created_at".to_string(),
        ));
    }
    if imported_at > expires_at {
        return Err(SyncError::Parse(
            "Package has passed its signed expires_at".to_string(),
        ));
    }
    Ok(())
}

pub(crate) fn validate_trust_domain(value: &str) -> Result<(), SyncError> {
    if value.is_empty()
        || value.len() > MAX_TRUST_DOMAIN_LEN
        || !value
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-' | ':'))
    {
        return Err(SyncError::Parse(
            "Package trust_domain must be a bounded ASCII identifier".to_string(),
        ));
    }
    Ok(())
}

fn validate_identifier(name: &str, value: &str) -> Result<(), SyncError> {
    if value.is_empty()
        || value.len() > MAX_IDENTIFIER_LEN
        || value.trim() != value
        || value.chars().any(char::is_control)
    {
        return Err(SyncError::Parse(format!(
            "{name} must be a bounded non-empty value without surrounding whitespace"
        )));
    }
    Ok(())
}

fn validate_ed25519_key_id(name: &str, value: &str) -> Result<(), SyncError> {
    let digest = value.strip_prefix("ed25519:").ok_or_else(|| {
        SyncError::Parse(format!(
            "{name} must be ed25519: followed by a lowercase BLAKE3 digest"
        ))
    })?;
    if digest.len() != 64
        || !digest
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(SyncError::Parse(format!(
            "{name} must be ed25519: followed by 64 lowercase hexadecimal characters"
        )));
    }
    Ok(())
}

fn insert_unique_anchor(
    anchors: &mut Vec<TrustAnchor>,
    ids: &mut HashSet<String>,
    anchor: TrustAnchor,
) -> Result<(), SyncError> {
    if !ids.insert(anchor.id.clone()) {
        return Err(SyncError::Parse(format!(
            "Duplicate certificate id {}",
            anchor.id
        )));
    }
    anchors.push(anchor);
    Ok(())
}

fn parse_certificate_entry(
    entry: &CertificateEntry,
    anchor_type: marty_secure_storage::TrustAnchorType,
    package_created_at: DateTime<Utc>,
) -> Result<TrustAnchor, SyncError> {
    use base64::Engine;

    validate_identifier("certificate jurisdiction", &entry.jurisdiction)?;
    for (name, value) in [
        ("certificate subject", entry.subject.as_deref()),
        ("certificate issuer", entry.issuer.as_deref()),
        ("certificate serial", entry.serial.as_deref()),
    ] {
        if let Some(value) = value {
            validate_identifier(name, value)?;
        }
    }

    let certificate_der = base64::engine::general_purpose::STANDARD
        .decode(&entry.certificate_der_b64)
        .map_err(|e| SyncError::Parse(format!("Invalid base64: {}", e)))?;
    if certificate_der.is_empty() || certificate_der.len() > MAX_CERTIFICATE_BYTES {
        return Err(SyncError::Certificate(format!(
            "Certificate must contain between 1 and {MAX_CERTIFICATE_BYTES} DER bytes"
        )));
    }
    Certificate::from_der(&certificate_der)
        .map_err(|error| SyncError::Certificate(format!("Malformed certificate DER: {error}")))?;

    let not_before = parse_declared_timestamp(&entry.not_before, "certificate not_before")?;
    let not_after = parse_declared_timestamp(&entry.not_after, "certificate not_after")?;
    if matches!((not_before, not_after), (Some(start), Some(end)) if start >= end) {
        return Err(SyncError::Parse(
            "Certificate not_before must be earlier than not_after".to_string(),
        ));
    }

    // Hash the certificate for ID
    let hash = blake3::hash(&certificate_der);
    let id = format!("{}-{}", anchor_type, &hash.to_hex()[..16]);

    Ok(TrustAnchor {
        id,
        anchor_type,
        jurisdiction: entry.jurisdiction.clone(),
        subject: entry.subject.clone(),
        issuer: entry.issuer.clone(),
        serial_number: entry.serial.clone(),
        not_before,
        not_after,
        certificate_der,
        certificate_hash: hash.to_hex().to_string(),
        source: marty_secure_storage::TrustAnchorSource::UsbImport,
        synced_at: package_created_at,
    })
}

fn parse_open_badge_method(
    value: &Value,
    package_created_at: DateTime<Utc>,
) -> Result<OpenBadgeVerificationMethod, SyncError> {
    let object = value
        .as_object()
        .ok_or_else(|| SyncError::Parse("Open Badge method must be an object".to_string()))?;
    let id = object
        .get("id")
        .and_then(|v| v.as_str())
        .ok_or_else(|| SyncError::Parse("Open Badge method missing id".to_string()))?;
    validate_identifier("Open Badge method id", id)?;

    let controller = object
        .get("controller")
        .and_then(|v| v.as_str())
        .map(|s| s.to_string());
    let Some(controller_value) = controller.as_deref() else {
        return Err(SyncError::Parse(
            "Open Badge method missing controller".to_string(),
        ));
    };
    validate_identifier("Open Badge method controller", controller_value)?;
    let issuer = optional_string(object.get("issuer"), "Open Badge method issuer")?;
    let kid = optional_string(object.get("kid"), "Open Badge method kid")?;
    let status = optional_string(object.get("status"), "Open Badge method status")?
        .ok_or_else(|| SyncError::Parse("Open Badge method missing status".to_string()))?;
    if !matches!(status.as_str(), "active" | "inactive" | "revoked") {
        return Err(SyncError::Parse(
            "Open Badge method status must be active, inactive, or revoked".to_string(),
        ));
    }
    let not_before = parse_timestamp_alias(value, "not_before", "notBefore")?
        .ok_or_else(|| SyncError::Parse("Open Badge method missing not_before".to_string()))?;
    let not_after = parse_timestamp_alias(value, "not_after", "notAfter")?
        .ok_or_else(|| SyncError::Parse("Open Badge method missing not_after".to_string()))?;
    if not_before >= not_after {
        return Err(SyncError::Parse(
            "Open Badge method not_before must be earlier than not_after".to_string(),
        ));
    }
    if contains_private_key_material(value) {
        return Err(SyncError::Parse(format!(
            "Open Badge method {id} contains private or symmetric key material"
        )));
    }
    validate_open_badge_key_material(object)?;

    Ok(OpenBadgeVerificationMethod {
        id: id.to_string(),
        document: value.clone(),
        controller,
        issuer,
        kid,
        not_before: Some(not_before),
        not_after: Some(not_after),
        status: Some(status),
        source: OpenBadgeKeySource::UsbImport,
        synced_at: package_created_at,
    })
}

fn validate_open_badge_key_material(
    object: &serde_json::Map<String, Value>,
) -> Result<(), SyncError> {
    let method_type = required_string(object.get("type"), "Open Badge method type")?;
    match method_type {
        "JsonWebKey2020" => validate_public_jwk(object),
        "Ed25519VerificationKey2018" => {
            required_string(
                object.get("publicKeyBase58"),
                "Ed25519VerificationKey2018 publicKeyBase58",
            )?;
            reject_unexpected_key_fields(object, "publicKeyBase58")
        }
        "Ed25519VerificationKey2020" | "Multikey" => {
            let public_key = required_string(
                object.get("publicKeyMultibase"),
                "multibase verification key",
            )?;
            if !public_key.starts_with('z') {
                return Err(SyncError::Parse(
                    "Open Badge publicKeyMultibase must use base58btc multibase".to_string(),
                ));
            }
            reject_unexpected_key_fields(object, "publicKeyMultibase")
        }
        _ => Err(SyncError::Parse(format!(
            "Unsupported Open Badge verification method type {method_type}"
        ))),
    }
}

fn validate_public_jwk(object: &serde_json::Map<String, Value>) -> Result<(), SyncError> {
    reject_unexpected_key_fields(object, "publicKeyJwk")?;
    let jwk = object
        .get("publicKeyJwk")
        .and_then(Value::as_object)
        .ok_or_else(|| {
            SyncError::Parse("JsonWebKey2020 publicKeyJwk must be an object".to_string())
        })?;
    match required_string(jwk.get("kty"), "public JWK kty")? {
        "OKP" => {
            required_string(jwk.get("crv"), "public OKP JWK crv")?;
            required_string(jwk.get("x"), "public OKP JWK x")?;
        }
        "EC" => {
            required_string(jwk.get("crv"), "public EC JWK crv")?;
            required_string(jwk.get("x"), "public EC JWK x")?;
            required_string(jwk.get("y"), "public EC JWK y")?;
        }
        "RSA" => {
            required_string(jwk.get("n"), "public RSA JWK n")?;
            required_string(jwk.get("e"), "public RSA JWK e")?;
        }
        other => {
            return Err(SyncError::Parse(format!(
                "Unsupported public JWK kty {other}"
            )));
        }
    }
    Ok(())
}

fn reject_unexpected_key_fields(
    object: &serde_json::Map<String, Value>,
    expected: &str,
) -> Result<(), SyncError> {
    const KEY_FIELDS: [&str; 4] = [
        "publicKeyJwk",
        "publicKeyBase58",
        "publicKeyMultibase",
        "publicKeyPem",
    ];
    if KEY_FIELDS
        .iter()
        .any(|field| *field != expected && object.contains_key(*field))
    {
        return Err(SyncError::Parse(format!(
            "Open Badge method type permits only {expected} key material"
        )));
    }
    Ok(())
}

fn required_string<'a>(value: Option<&'a Value>, name: &str) -> Result<&'a str, SyncError> {
    let value = value
        .and_then(Value::as_str)
        .ok_or_else(|| SyncError::Parse(format!("{name} must be a string")))?;
    validate_identifier(name, value)?;
    Ok(value)
}

fn optional_string(value: Option<&Value>, name: &str) -> Result<Option<String>, SyncError> {
    let Some(value) = value else {
        return Ok(None);
    };
    let value = value
        .as_str()
        .ok_or_else(|| SyncError::Parse(format!("{name} must be a string when present")))?;
    validate_identifier(name, value)?;
    Ok(Some(value.to_string()))
}

fn parse_timestamp_alias(
    value: &Value,
    snake_case: &str,
    camel_case: &str,
) -> Result<Option<DateTime<Utc>>, SyncError> {
    let snake = value.get(snake_case);
    let camel = value.get(camel_case);
    if snake.is_some() && camel.is_some() {
        return Err(SyncError::Parse(format!(
            "Open Badge method cannot contain both {snake_case} and {camel_case}"
        )));
    }
    parse_optional_timestamp(snake.or(camel), &format!("Open Badge method {snake_case}"))
}

fn parse_optional_timestamp(
    value: Option<&Value>,
    name: &str,
) -> Result<Option<DateTime<Utc>>, SyncError> {
    let Some(value) = value else {
        return Ok(None);
    };
    let text = value
        .as_str()
        .ok_or_else(|| SyncError::Parse(format!("{name} must be an RFC 3339 string")))?;
    parse_required_timestamp(text, name).map(Some)
}

fn parse_declared_timestamp(
    value: &DeclaredValue,
    name: &str,
) -> Result<Option<DateTime<Utc>>, SyncError> {
    match value {
        DeclaredValue::Missing => Ok(None),
        DeclaredValue::Present(value) => parse_optional_timestamp(Some(value), name),
    }
}

fn parse_required_timestamp(value: &str, name: &str) -> Result<DateTime<Utc>, SyncError> {
    DateTime::parse_from_rfc3339(value)
        .map(|timestamp| timestamp.with_timezone(&Utc))
        .map_err(|_| SyncError::Parse(format!("{name} must be RFC 3339")))
}

fn contains_private_key_material(value: &Value) -> bool {
    match value {
        Value::Object(object) => object.iter().any(|(key, nested)| {
            if key.starts_with("privateKey") || key.starts_with("secretKey") {
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
            contains_private_key_material(nested)
        }),
        Value::Array(values) => values.iter().any(contains_private_key_material),
        _ => false,
    }
}

fn load_trusted_signing_public_key() -> Result<[u8; 32], SyncError> {
    // Trust is configured out of band. `signing_cert` in the package is
    // deliberately informational and never enters this path.
    let pub_key_path = std::env::var("USB_SIGNING_PUBLIC_KEY_PATH").ok();
    let pub_key_bytes = if let Some(ref path) = pub_key_path {
        let raw = std::fs::read_to_string(path).map_err(|error| {
            SyncError::UsbImport(format!("Cannot read public key {path}: {error}"))
        })?;
        decode_signing_public_key(&raw)?
    } else {
        let embedded_pubkey = option_env!("USB_SIGNING_PUBLIC_KEY")
            .unwrap_or(include_str!("../../../marty-verifier.key.pub"));
        decode_signing_public_key(embedded_pubkey)?
    };

    pub_key_bytes
        .try_into()
        .map_err(|_| SyncError::UsbImport("Public key must be 32 bytes".to_string()))
}

fn load_trusted_recovery_public_key() -> Result<[u8; 32], SyncError> {
    let raw = if let Ok(path) = std::env::var("USB_RECOVERY_PUBLIC_KEY_PATH") {
        std::fs::read_to_string(&path).map_err(|error| {
            SyncError::UsbImport(format!("Cannot read recovery public key {path}: {error}"))
        })?
    } else if let Some(embedded) = option_env!("USB_RECOVERY_PUBLIC_KEY") {
        embedded.to_string()
    } else {
        return Err(SyncError::UsbImport(
            "USB recovery public key is not configured".to_string(),
        ));
    };
    let bytes = decode_signing_public_key(&raw)?;
    bytes
        .try_into()
        .map_err(|_| SyncError::UsbImport("USB recovery public key must be 32 bytes".to_string()))
}

fn signer_key_id(public_key: &[u8; 32]) -> String {
    format!("ed25519:{}", blake3::hash(public_key).to_hex())
}

fn canonical_signed_payload(package_value: &Value) -> Result<Vec<u8>, SyncError> {
    let mut signed = package_value.clone();
    let object = signed
        .as_object_mut()
        .ok_or_else(|| SyncError::UsbImport("Trust package must be a JSON object".to_string()))?;
    if object.remove("signature").is_none() {
        return Err(SyncError::UsbImport(
            "Trust package is missing signature".to_string(),
        ));
    }
    let mut canonical = Vec::new();
    write_jcs_value(&signed, &mut canonical)?;
    Ok(canonical)
}

fn write_jcs_value(value: &Value, output: &mut Vec<u8>) -> Result<(), SyncError> {
    match value {
        Value::Null => output.extend_from_slice(b"null"),
        Value::Bool(true) => output.extend_from_slice(b"true"),
        Value::Bool(false) => output.extend_from_slice(b"false"),
        Value::Number(number) => {
            let value = number
                .as_f64()
                .filter(|value| value.is_finite())
                .ok_or_else(|| {
                    SyncError::UsbImport(
                        "Canonicalization requires an IEEE 754 finite JSON number".to_string(),
                    )
                })?;
            let mut buffer = ryu_js::Buffer::new();
            output.extend_from_slice(buffer.format_finite(value).as_bytes());
        }
        Value::String(text) => serde_json::to_writer(output, text)
            .map_err(|error| SyncError::UsbImport(format!("Canonicalization failed: {error}")))?,
        Value::Array(values) => {
            output.push(b'[');
            for (index, nested) in values.iter().enumerate() {
                if index != 0 {
                    output.push(b',');
                }
                write_jcs_value(nested, output)?;
            }
            output.push(b']');
        }
        Value::Object(object) => {
            let mut entries = object.iter().collect::<Vec<_>>();
            entries.sort_by(|left, right| left.0.encode_utf16().cmp(right.0.encode_utf16()));
            output.push(b'{');
            for (index, (key, nested)) in entries.into_iter().enumerate() {
                if index != 0 {
                    output.push(b',');
                }
                serde_json::to_writer(&mut *output, key).map_err(|error| {
                    SyncError::UsbImport(format!("Canonicalization failed: {error}"))
                })?;
                output.push(b':');
                write_jcs_value(nested, output)?;
            }
            output.push(b'}');
        }
    }
    Ok(())
}

/// Verify the Ed25519 signature on a trust-anchor USB package.
///
/// The signature covers RFC 8785 JSON Canonicalization Scheme bytes for every
/// field except `signature`. Identity and digest are derived from the actual pinned
/// key and these exact signed bytes, never from `signing_cert`.
fn verify_package_signature(
    package_value: &Value,
    package: &TrustAnchorPackage,
    trusted_public_key: &[u8; 32],
) -> Result<VerifiedSignature, SyncError> {
    use ed25519_dalek::{Signature, Verifier, VerifyingKey};

    // ── Load the trusted public key ─────────────────────────────────
    let verifying_key = VerifyingKey::from_bytes(trusted_public_key)
        .map_err(|e| SyncError::UsbImport(format!("Invalid Ed25519 public key: {e}")))?;

    // ── Decode the signature from the package ───────────────────────
    use base64::Engine;
    let sig_bytes = base64::engine::general_purpose::STANDARD
        .decode(&package.signature)
        .map_err(|e| SyncError::UsbImport(format!("Invalid signature base64: {e}")))?;
    let signature = Signature::from_slice(&sig_bytes)
        .map_err(|e| SyncError::UsbImport(format!("Invalid Ed25519 signature: {e}")))?;

    // ── Build the signed payload (JSON without the "signature" field)
    let canonical = canonical_signed_payload(package_value)?;

    // ── Verify ──────────────────────────────────────────────────────
    match verifying_key.verify(&canonical, &signature) {
        Ok(()) => {
            tracing::info!("USB package signature verified successfully");
            Ok(VerifiedSignature {
                signer_key_id: signer_key_id(trusted_public_key),
                package_digest: blake3::hash(&canonical).to_hex().to_string(),
            })
        }
        Err(e) => {
            tracing::error!("USB package signature verification FAILED: {e}");
            Err(SyncError::UsbImport(
                "Package signature verification failed — rejecting import".to_string(),
            ))
        }
    }
}

#[cfg(test)]
mod tests {
    use base64::Engine;
    use chrono::TimeZone;
    use ed25519_dalek::{Signer, SigningKey};
    use serde_json::json;

    use super::*;

    fn minimal_package_json(extra: &str) -> String {
        format!(
            r#"{{
                "trust_domain":"usb:default",
                "sequence":1,
                "version":"1.0.0",
                "created_at":"2026-08-08T00:00:00Z",
                "expires_at":"2027-08-08T00:00:00Z",
                "signer_key_id":"ed25519:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                "next_signer_key_id":null,
                "recovery_signer_key_id":"ed25519:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
                "signing_cert":"informational-only",
                "signature":"AA==",
                "iaca_certificates":[],
                "csca_certificates":[],
                "dsc_certificates":[],
                "open_badge_verification_methods":[]
                {extra}
            }}"#
        )
    }

    fn signed_package_json(signing_key: &SigningKey, declared_signer: Option<&str>) -> String {
        let public_key = signing_key.verifying_key().to_bytes();
        let now = Utc::now();
        let mut package = json!({
            "trust_domain": "usb:default",
            "sequence": 1,
            "version": "1.0.0",
            "created_at": now.to_rfc3339(),
            "expires_at": (now + chrono::Duration::days(1)).to_rfc3339(),
            "signer_key_id": declared_signer
                .map(str::to_string)
                .unwrap_or_else(|| signer_key_id(&public_key)),
            "next_signer_key_id": Value::Null,
            "recovery_signer_key_id": signer_key_id(&[9_u8; 32]),
            "signing_cert": "informational-only",
            "signature": "",
            "iaca_certificates": [],
            "csca_certificates": [],
            "dsc_certificates": [],
            "open_badge_verification_methods": []
        });
        let canonical = canonical_signed_payload(&package).expect("canonical signed package");
        package["signature"] = json!(base64::engine::general_purpose::STANDARD
            .encode(signing_key.sign(&canonical).to_bytes()));
        serde_json::to_string(&package).expect("serialize signed package")
    }

    fn public_method() -> Value {
        json!({
            "id": "did:example:issuer#key-1",
            "type": "JsonWebKey2020",
            "controller": "did:example:issuer",
            "publicKeyJwk": {
                "kty": "OKP",
                "crv": "Ed25519",
                "x": "11qYAYdk9JwqPceJUchO3G0VQJq4aW8QjJwA8Yl5b4o"
            },
            "status": "active",
            "not_before": "2026-01-01T00:00:00Z",
            "not_after": "2027-01-01T00:00:00Z"
        })
    }

    #[test]
    fn strict_package_parser_rejects_duplicate_and_unknown_members() {
        let duplicate = minimal_package_json(",\"version\":\"2.0.0\"");
        let error = parse_strict_package(&duplicate).expect_err("duplicate member must fail");
        assert!(error.to_string().contains("duplicate JSON object member"));

        let unknown = minimal_package_json(",\"unexpected\":true");
        let error = parse_strict_package(&unknown).expect_err("unknown member must fail");
        assert!(error.to_string().contains("unknown field"));

        for required_policy_field in ["next_signer_key_id", "recovery_signer_key_id"] {
            let mut missing_transition_field: Value =
                serde_json::from_str(&minimal_package_json("")).unwrap();
            missing_transition_field
                .as_object_mut()
                .unwrap()
                .remove(required_policy_field);
            let error =
                parse_strict_package(&serde_json::to_string(&missing_transition_field).unwrap())
                    .expect_err("missing signed transition field must fail");
            assert!(error.to_string().contains(required_policy_field));
        }
    }

    #[test]
    fn signer_policy_requires_canonical_ed25519_key_ids() {
        let invalid_ids = [
            "missing-prefix",
            "ed25519:abc",
            "ed25519:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
            "ed25519:gggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggg",
        ];

        for field in ["next_signer_key_id", "recovery_signer_key_id"] {
            for invalid_id in invalid_ids {
                let mut value: Value =
                    serde_json::from_str(&minimal_package_json("")).expect("minimal package");
                value[field] = json!(invalid_id);
                let raw = serde_json::to_string(&value).expect("package JSON");
                let (package, _) = parse_strict_package(&raw).expect("strict package shape");
                let declared_signer = package.signer_key_id.clone();
                let declared_recovery = package.recovery_signer_key_id.clone();
                let error =
                    validate_package_metadata(&package, &declared_signer, &declared_recovery)
                        .expect_err("noncanonical signer policy id must fail");
                assert!(error.to_string().contains("ed25519:"));
            }
        }

        let (_, value) = parse_strict_package(&minimal_package_json(""))
            .expect("canonical signer ids must remain valid");
        let package: TrustAnchorPackage = serde_json::from_value(value).unwrap();
        let declared_signer = package.signer_key_id.clone();
        let declared_recovery = package.recovery_signer_key_id.clone();
        validate_package_metadata(&package, &declared_signer, &declared_recovery)
            .expect("canonical signer policy ids");

        let different_recovery = format!("ed25519:{}", "c".repeat(64));
        assert!(matches!(
            validate_package_metadata(&package, &declared_signer, &different_recovery),
            Err(SyncError::SignatureVerification)
        ));
    }

    #[test]
    fn future_package_time_is_rejected() {
        let now = Utc.with_ymd_and_hms(2026, 8, 8, 0, 0, 0).unwrap();
        assert!(validate_package_times(
            now + chrono::Duration::minutes(5),
            now + chrono::Duration::days(1),
            now
        )
        .is_ok());
        assert!(validate_package_times(
            now + chrono::Duration::minutes(5) + chrono::Duration::seconds(1),
            now + chrono::Duration::days(1),
            now
        )
        .is_err());
        assert!(validate_package_times(now, now, now).is_err());
        assert!(validate_package_times(
            now,
            now + chrono::Duration::hours(1),
            now + chrono::Duration::hours(2)
        )
        .is_err());
    }

    #[test]
    fn signature_binds_actual_pinned_key_identity_and_canonical_digest() {
        let signing_key = SigningKey::from_bytes(&[7_u8; 32]);
        let public_key = signing_key.verifying_key().to_bytes();
        let raw = signed_package_json(&signing_key, None);
        let (package, value) = parse_strict_package(&raw).expect("strict signed package");

        let verified = verify_package_signature(&value, &package, &public_key)
            .expect("signature from pinned key");
        validate_package_metadata(
            &package,
            &verified.signer_key_id,
            &package.recovery_signer_key_id,
        )
        .expect("declared signer matches pinned key");
        assert_eq!(verified.signer_key_id, signer_key_id(&public_key));
        assert_eq!(verified.package_digest.len(), 64);

        let wrong_id = format!("ed25519:{}", "b".repeat(64));
        let wrong_raw = signed_package_json(&signing_key, Some(&wrong_id));
        let (wrong_package, wrong_value) =
            parse_strict_package(&wrong_raw).expect("signed wrong-id package");
        let wrong_verified = verify_package_signature(&wrong_value, &wrong_package, &public_key)
            .expect("signature remains cryptographically valid");
        assert!(matches!(
            validate_package_metadata(
                &wrong_package,
                &wrong_verified.signer_key_id,
                &wrong_package.recovery_signer_key_id,
            ),
            Err(SyncError::SignatureVerification)
        ));

        let mut tampered: Value = serde_json::from_str(&raw).expect("signed JSON");
        tampered["version"] = json!("2.0.0");
        let tampered_raw = serde_json::to_string(&tampered).expect("tampered JSON");
        let (tampered_package, tampered_value) =
            parse_strict_package(&tampered_raw).expect("strict tampered package");
        assert!(verify_package_signature(&tampered_value, &tampered_package, &public_key).is_err());

        let mut tampered_transition: Value = serde_json::from_str(&raw).expect("signed JSON");
        tampered_transition["next_signer_key_id"] = json!(format!("ed25519:{}", "c".repeat(64)));
        let tampered_transition_raw =
            serde_json::to_string(&tampered_transition).expect("tampered transition JSON");
        let (tampered_transition_package, tampered_transition_value) =
            parse_strict_package(&tampered_transition_raw).expect("strict tampered package");
        assert!(verify_package_signature(
            &tampered_transition_value,
            &tampered_transition_package,
            &public_key
        )
        .is_err());
    }

    #[test]
    fn signed_payload_uses_rfc_8785_canonicalization() {
        let first: Value = serde_json::from_str(
            r#"{"signature":"ignored","z":1e0,"a":{"\u00e9":"\u00e9","b":2}}"#,
        )
        .unwrap();
        let second: Value =
            serde_json::from_str(r#"{"a":{"b":2,"é":"é"},"z":1,"signature":"different"}"#).unwrap();

        let first_payload = canonical_signed_payload(&first).unwrap();
        let second_payload = canonical_signed_payload(&second).unwrap();
        assert_eq!(first_payload, second_payload);
        assert_eq!(
            String::from_utf8(first_payload).unwrap(),
            r#"{"a":{"b":2,"é":"é"},"z":1}"#
        );
    }

    #[test]
    fn canonical_object_keys_use_utf16_sort_order() {
        let bmp = char::from_u32(0xe000).unwrap().to_string();
        let astral = char::from_u32(0x1f600).unwrap().to_string();
        let mut nested = serde_json::Map::new();
        nested.insert(bmp.clone(), json!("bmp"));
        nested.insert(astral.clone(), json!("astral"));
        let value = json!({ "signature": "ignored", "keys": nested });

        let canonical = String::from_utf8(canonical_signed_payload(&value).unwrap()).unwrap();
        assert!(canonical.find(&astral).unwrap() < canonical.find(&bmp).unwrap());
    }

    #[test]
    fn malformed_declared_method_fields_fail_instead_of_becoming_absent() {
        let created_at = Utc.with_ymd_and_hms(2026, 8, 8, 0, 0, 0).unwrap();
        let mut malformed_time = public_method();
        malformed_time["not_before"] = json!("not-a-time");
        assert!(parse_open_badge_method(&malformed_time, created_at).is_err());

        let mut null_time = public_method();
        null_time["not_after"] = Value::Null;
        assert!(parse_open_badge_method(&null_time, created_at).is_err());

        let mut aliases = public_method();
        aliases["notBefore"] = json!("2026-01-01T00:00:00Z");
        assert!(parse_open_badge_method(&aliases, created_at).is_err());

        for required in ["status", "not_before", "not_after"] {
            let mut missing = public_method();
            missing
                .as_object_mut()
                .expect("method object")
                .remove(required);
            assert!(parse_open_badge_method(&missing, created_at).is_err());
        }
    }

    #[test]
    fn private_method_material_is_rejected_and_signed_time_is_preserved() {
        let created_at = Utc.with_ymd_and_hms(2026, 8, 8, 0, 0, 0).unwrap();
        let method = parse_open_badge_method(&public_method(), created_at)
            .expect("public method should parse");
        assert_eq!(method.synced_at, created_at);

        let mut private = public_method();
        private["publicKeyJwk"]["d"] = json!("private");
        assert!(parse_open_badge_method(&private, created_at).is_err());
    }

    #[test]
    fn missing_unsupported_or_malformed_public_method_material_is_rejected() {
        let created_at = Utc.with_ymd_and_hms(2026, 8, 8, 0, 0, 0).unwrap();

        let mut missing = public_method();
        missing
            .as_object_mut()
            .expect("method object")
            .remove("publicKeyJwk");
        assert!(parse_open_badge_method(&missing, created_at).is_err());

        let mut unsupported = public_method();
        unsupported["type"] = json!("UnknownVerificationMethod");
        assert!(parse_open_badge_method(&unsupported, created_at).is_err());

        let mut malformed = public_method();
        malformed["publicKeyJwk"] = json!({ "kty": "OKP", "crv": "Ed25519" });
        assert!(parse_open_badge_method(&malformed, created_at).is_err());

        let mut conflicting = public_method();
        conflicting["publicKeyMultibase"] = json!("z6Mkh...");
        assert!(parse_open_badge_method(&conflicting, created_at).is_err());
    }

    #[test]
    fn malformed_certificate_and_timestamp_are_rejected() {
        let created_at = Utc.with_ymd_and_hms(2026, 8, 8, 0, 0, 0).unwrap();
        let entry = CertificateEntry {
            jurisdiction: "US-CO".to_string(),
            subject: None,
            issuer: None,
            serial: None,
            not_before: DeclaredValue::Present(json!("invalid")),
            not_after: DeclaredValue::Missing,
            certificate_der_b64: base64::engine::general_purpose::STANDARD.encode([0u8]),
        };
        assert!(parse_certificate_entry(
            &entry,
            marty_secure_storage::TrustAnchorType::Iaca,
            created_at
        )
        .is_err());

        let entry = CertificateEntry {
            not_before: DeclaredValue::Present(Value::Null),
            ..entry
        };
        assert!(parse_certificate_entry(
            &entry,
            marty_secure_storage::TrustAnchorType::Iaca,
            created_at
        )
        .is_err());

        let entry = CertificateEntry {
            not_before: DeclaredValue::Missing,
            ..entry
        };
        let error = parse_certificate_entry(
            &entry,
            marty_secure_storage::TrustAnchorType::Iaca,
            created_at,
        )
        .expect_err("malformed DER must fail");
        assert!(matches!(error, SyncError::Certificate(_)));
    }
}
