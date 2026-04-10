//! USB import for air-gapped deployments

use std::path::Path;

use serde::{Deserialize, Serialize};

use crate::error::SyncError;
use marty_secure_storage::{OpenBadgeKeySource, OpenBadgeVerificationMethod, TrustAnchor};

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
pub struct TrustAnchorPackage {
    /// Package version
    pub version: String,
    /// Package creation timestamp
    #[allow(dead_code)]
    pub created_at: String,
    /// Signing certificate (PEM)
    #[allow(dead_code)]
    pub signing_cert: String,
    /// Package signature (base64)
    #[allow(dead_code)]
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

/// Certificate entry in package
#[derive(Debug, Deserialize)]
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
    pub not_before: Option<String>,
    /// Not after date
    pub not_after: Option<String>,
    /// DER-encoded certificate (base64)
    pub certificate_der_b64: String,
}

/// Import trust anchors from USB package
pub async fn import_from_usb(
    path: &Path,
) -> Result<(Vec<TrustAnchor>, Vec<OpenBadgeVerificationMethod>, UsbImportResult), SyncError> {
    tracing::info!(path = ?path, "Importing trust anchors from USB");

    // Check path exists
    if !path.exists() {
        return Err(SyncError::UsbImport(format!(
            "Package not found: {:?}",
            path
        )));
    }

    // Read package file
    let package_json = std::fs::read_to_string(path)?;

    // Parse package
    let package: TrustAnchorPackage = serde_json::from_str(&package_json)
        .map_err(|e| SyncError::UsbImport(format!("Invalid package format: {}", e)))?;

    // Verify package signature
    let signature_valid = verify_package_signature(&package_json, &package)?;

    // Convert certificates to TrustAnchor format
    let mut anchors = Vec::new();
    let mut count = 0;

    // Process IACA certificates
    for cert in &package.iaca_certificates {
        if let Ok(anchor) =
            parse_certificate_entry(cert, marty_secure_storage::TrustAnchorType::Iaca)
        {
            anchors.push(anchor);
            count += 1;
        }
    }

    // Process CSCA certificates
    for cert in &package.csca_certificates {
        if let Ok(anchor) =
            parse_certificate_entry(cert, marty_secure_storage::TrustAnchorType::Csca)
        {
            anchors.push(anchor);
            count += 1;
        }
    }

    // Process DSC certificates
    for cert in &package.dsc_certificates {
        if let Ok(anchor) =
            parse_certificate_entry(cert, marty_secure_storage::TrustAnchorType::Dsc)
        {
            anchors.push(anchor);
            count += 1;
        }
    }

    // Convert Open Badge verification methods
    let mut open_badge_keys = Vec::new();
    let mut open_badge_count = 0;
    for method in &package.open_badge_verification_methods {
        if let Ok(entry) = parse_open_badge_method(method) {
            open_badge_keys.push(entry);
            open_badge_count += 1;
        }
    }

    tracing::info!(
        count,
        open_badge_count,
        version = %package.version,
        "Imported trust materials from USB package"
    );

    Ok((
        anchors,
        open_badge_keys,
        UsbImportResult {
            success: true,
            certificates_imported: count,
            open_badge_keys_imported: open_badge_count,
            signature_valid,
            package_version: Some(package.version),
            error: None,
        },
    ))
}

fn parse_certificate_entry(
    entry: &CertificateEntry,
    anchor_type: marty_secure_storage::TrustAnchorType,
) -> Result<TrustAnchor, SyncError> {
    use base64::Engine;
    use chrono::Utc;

    let certificate_der = base64::engine::general_purpose::STANDARD
        .decode(&entry.certificate_der_b64)
        .map_err(|e| SyncError::Parse(format!("Invalid base64: {}", e)))?;

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
        not_before: entry.not_before.as_ref().and_then(|s| {
            chrono::DateTime::parse_from_rfc3339(s)
                .ok()
                .map(|dt| dt.with_timezone(&Utc))
        }),
        not_after: entry.not_after.as_ref().and_then(|s| {
            chrono::DateTime::parse_from_rfc3339(s)
                .ok()
                .map(|dt| dt.with_timezone(&Utc))
        }),
        certificate_der,
        certificate_hash: hash.to_hex().to_string(),
        source: marty_secure_storage::TrustAnchorSource::UsbImport,
        synced_at: Utc::now(),
    })
}

fn parse_open_badge_method(
    value: &serde_json::Value,
) -> Result<OpenBadgeVerificationMethod, SyncError> {
    use chrono::Utc;

    let id = value
        .get("id")
        .and_then(|v| v.as_str())
        .ok_or_else(|| SyncError::Parse("Open Badge method missing id".to_string()))?;

    let controller = value.get("controller").and_then(|v| v.as_str()).map(|s| s.to_string());
    let issuer = value.get("issuer").and_then(|v| v.as_str()).map(|s| s.to_string());
    let kid = value.get("kid").and_then(|v| v.as_str()).map(|s| s.to_string());
    let status = value.get("status").and_then(|v| v.as_str()).map(|s| s.to_string());
    let not_before = value
        .get("not_before")
        .or_else(|| value.get("notBefore"))
        .and_then(|v| v.as_str())
        .and_then(|s| chrono::DateTime::parse_from_rfc3339(s).ok())
        .map(|dt| dt.with_timezone(&Utc));
    let not_after = value
        .get("not_after")
        .or_else(|| value.get("notAfter"))
        .and_then(|v| v.as_str())
        .and_then(|s| chrono::DateTime::parse_from_rfc3339(s).ok())
        .map(|dt| dt.with_timezone(&Utc));

    Ok(OpenBadgeVerificationMethod {
        id: id.to_string(),
        document: value.clone(),
        controller,
        issuer,
        kid,
        not_before,
        not_after,
        status,
        source: OpenBadgeKeySource::UsbImport,
        synced_at: Utc::now(),
    })
}

/// Verify the Ed25519 signature on a trust-anchor USB package.
///
/// The signature covers the canonical JSON of all fields *except* the
/// `signature` field itself.  The signing public key is loaded from
/// `USB_SIGNING_PUBLIC_KEY_PATH` (32-byte raw Ed25519 key, base64-encoded
/// file) or, when that is unset, from the embedded
/// `marty-verifier.key.pub` checked into the repository.
fn verify_package_signature(
    raw_json: &str,
    package: &TrustAnchorPackage,
) -> Result<bool, SyncError> {
    use base64::Engine;
    use ed25519_dalek::{Signature, VerifyingKey, Verifier};

    // ── Load the trusted public key ─────────────────────────────────
    let pub_key_path = std::env::var("USB_SIGNING_PUBLIC_KEY_PATH").ok();
    let pub_key_bytes: Vec<u8> = if let Some(ref p) = pub_key_path {
        let raw = std::fs::read_to_string(p)
            .map_err(|e| SyncError::UsbImport(format!("Cannot read public key {p}: {e}")))?;
        base64::engine::general_purpose::STANDARD
            .decode(raw.trim())
            .map_err(|e| SyncError::UsbImport(format!("Invalid base64 in public key: {e}")))?
    } else {
        // Fallback: built-in public key
        const EMBEDDED_PUBKEY: &str = env!("USB_SIGNING_PUBLIC_KEY", "Set USB_SIGNING_PUBLIC_KEY at compile time or use USB_SIGNING_PUBLIC_KEY_PATH at runtime");
        base64::engine::general_purpose::STANDARD
            .decode(EMBEDDED_PUBKEY)
            .map_err(|e| SyncError::UsbImport(format!(
                "Invalid embedded public key: {e}"
            )))?
    };

    let pub_key_array: [u8; 32] = pub_key_bytes
        .try_into()
        .map_err(|_| SyncError::UsbImport("Public key must be 32 bytes".to_string()))?;
    let verifying_key = VerifyingKey::from_bytes(&pub_key_array)
        .map_err(|e| SyncError::UsbImport(format!("Invalid Ed25519 public key: {e}")))?;

    // ── Decode the signature from the package ───────────────────────
    let sig_bytes = base64::engine::general_purpose::STANDARD
        .decode(&package.signature)
        .map_err(|e| SyncError::UsbImport(format!("Invalid signature base64: {e}")))?;
    let signature = Signature::from_slice(&sig_bytes)
        .map_err(|e| SyncError::UsbImport(format!("Invalid Ed25519 signature: {e}")))?;

    // ── Build the signed payload (JSON without the "signature" field)
    let mut doc: serde_json::Value = serde_json::from_str(raw_json)
        .map_err(|e| SyncError::UsbImport(format!("Re-parse failed: {e}")))?;
    if let Some(obj) = doc.as_object_mut() {
        obj.remove("signature");
    }
    let canonical = serde_json::to_string(&doc)
        .map_err(|e| SyncError::UsbImport(format!("Canonicalization failed: {e}")))?;

    // ── Verify ──────────────────────────────────────────────────────
    match verifying_key.verify(canonical.as_bytes(), &signature) {
        Ok(()) => {
            tracing::info!("USB package signature verified successfully");
            Ok(true)
        }
        Err(e) => {
            tracing::error!("USB package signature verification FAILED: {e}");
            Err(SyncError::UsbImport(
                "Package signature verification failed — rejecting import".to_string(),
            ))
        }
    }
}
