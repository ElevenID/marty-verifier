//! Public, signed vectors for native demo qualification.
//!
//! This module is excluded from normal builds. It never creates or loads a
//! credential or trust-package private key.

use std::{fs, path::Path};

use anyhow::{bail, Context, Result};
use base64::{engine::general_purpose::STANDARD, Engine};
use chrono::{DateTime, Utc};
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use marty_verification::dtc::verify_dtc_json;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::usb::{canonical_signed_payload, signer_key_id};

fn embedded_trust_package(kind: &str) -> Result<SignedTrustPackage> {
    let (package, signing, recovery) = match kind {
        "dtc" => (
            include_str!("fixtures/demo_dtc/trust-package.json"),
            include_str!("fixtures/demo_dtc/usb-signing-public-key.txt"),
            include_str!("fixtures/demo_dtc/usb-recovery-public-key.txt"),
        ),
        "emrtd" => (
            include_str!("fixtures/demo_emrtd/trust-package.json"),
            include_str!("fixtures/demo_emrtd/usb-signing-public-key.txt"),
            include_str!("fixtures/demo_emrtd/usb-recovery-public-key.txt"),
        ),
        _ => bail!("unknown public demo trust kind"),
    };
    public_signed_trust_package(package, signing, recovery)
}

fn require_fresh_trust(package: &Value, now: DateTime<Utc>) -> Result<()> {
    let created = DateTime::parse_from_rfc3339(
        package["created_at"]
            .as_str()
            .context("public trust package has no creation time")?,
    )?
    .with_timezone(&Utc);
    let maximum_age =
        chrono::Duration::hours(crate::SyncConfig::default().max_offline_hours as i64);
    if created > now || now - created >= maximum_age {
        bail!("public demo trust package is stale or future-dated; refresh through remote KMS custody");
    }
    Ok(())
}

/// Both generators consume only public, verified KMS signing outputs. An
/// explicitly configured input cannot silently fall back to an embedded vector.
pub(crate) fn demo_trust_package(kind: &str) -> Result<SignedTrustPackage> {
    let Some(root) = std::env::var_os("MARTY_DEMO_PUBLIC_TRUST_DIRECTORY") else {
        return embedded_trust_package(kind);
    };
    if !matches!(kind, "dtc" | "emrtd") {
        bail!("unknown public demo trust kind");
    }
    let directory = Path::new(&root).join(kind);
    let package = public_signed_trust_package(
        &fs::read_to_string(directory.join("trust-package.json"))?,
        &fs::read_to_string(directory.join("usb-signing-public-key.txt"))?,
        &fs::read_to_string(directory.join("usb-recovery-public-key.txt"))?,
    )?;
    require_fresh_trust(&package.trust_package, Utc::now())?;
    Ok(package)
}

/// Prepare the existing production canonical payload for an external KMS.
/// CSCA certificates and all signed document bytes remain unchanged.
pub fn prepare_public_trust_refresh(kind: &str, public_keys: &Path, output: &Path) -> Result<()> {
    let mut package = embedded_trust_package(kind)?.trust_package;
    let signing_text = fs::read_to_string(public_keys.join("usb-signing-public-key.txt"))?;
    let recovery_text = fs::read_to_string(public_keys.join("usb-recovery-public-key.txt"))?;
    let signing = public_key(&signing_text)?;
    let recovery = public_key(&recovery_text)?;
    if signing == recovery {
        bail!("demo trust signing and recovery custody must be distinct");
    }
    let now = Utc::now();
    package["created_at"] = json!(now.to_rfc3339());
    package["expires_at"] = json!((now
        + chrono::Duration::hours(crate::SyncConfig::default().max_offline_hours as i64))
    .to_rfc3339());
    package["sequence"] = json!(now.timestamp_millis());
    package["version"] = json!(format!("demo-{}", now.timestamp_millis()));
    package["signer_key_id"] = json!(signer_key_id(&signing));
    package["recovery_signer_key_id"] = json!(signer_key_id(&recovery));
    package["next_signer_key_id"] = Value::Null;
    package["signature"] = json!("");
    let payload = canonical_signed_payload(&package)?;
    fs::create_dir(output).context("create new public trust refresh directory")?;
    write_json(&output.join("trust-package.json"), &package)?;
    write_json(
        &output.join("kms-input.json"),
        &json!({"input":STANDARD.encode(payload)}),
    )?;
    fs::write(
        output.join("usb-signing-public-key.txt"),
        STANDARD.encode(signing),
    )?;
    fs::write(
        output.join("usb-recovery-public-key.txt"),
        STANDARD.encode(recovery),
    )?;
    Ok(())
}

/// Accept a public detached signature only after real verification. No private
/// key or KMS credential enters the generator or the resulting artifact.
pub fn complete_public_trust_refresh(directory: &Path, signature: &Path) -> Result<()> {
    let file = directory.join("trust-package.json");
    let mut package: Value = serde_json::from_str(&fs::read_to_string(&file)?)?;
    package["signature"] = json!(fs::read_to_string(signature)?.trim());
    let verified = public_signed_trust_package(
        &serde_json::to_string(&package)?,
        &fs::read_to_string(directory.join("usb-signing-public-key.txt"))?,
        &fs::read_to_string(directory.join("usb-recovery-public-key.txt"))?,
    )?;
    require_fresh_trust(&verified.trust_package, Utc::now())?;
    write_json(&file, &verified.trust_package)
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DemoFixtureManifest {
    pub trust_package_path: String,
    pub dtc_path: String,
    pub usb_signing_public_key_path: String,
    pub usb_recovery_public_key_path: String,
}

struct GeneratedFixtures {
    trust_package: Value,
    dtc: Value,
    #[cfg(test)]
    csca_pem: String,
    signing_public_key: [u8; 32],
    recovery_public_key: [u8; 32],
}

pub(crate) struct SignedTrustPackage {
    pub trust_package: Value,
    pub signing_public_key: [u8; 32],
    pub recovery_public_key: [u8; 32],
}

pub(crate) fn public_signed_trust_package(
    package_json: &str,
    signing_public_key_b64: &str,
    recovery_public_key_b64: &str,
) -> Result<SignedTrustPackage> {
    let trust_package: Value =
        serde_json::from_str(package_json).context("parse public trust package")?;
    let signing_public_key = public_key(signing_public_key_b64)?;
    let recovery_public_key = public_key(recovery_public_key_b64)?;
    let expires_at = trust_package["expires_at"]
        .as_str()
        .context("public trust package has no expiry")?;
    if DateTime::parse_from_rfc3339(expires_at).context("parse public trust expiry")? <= Utc::now()
    {
        bail!(
            "public demo trust package expired; refresh the signed vector through remote custody"
        );
    }
    if trust_package["signer_key_id"] != signer_key_id(&signing_public_key)
        || trust_package["recovery_signer_key_id"] != signer_key_id(&recovery_public_key)
    {
        bail!("public demo trust package signer binding is invalid");
    }
    let signature = STANDARD
        .decode(
            trust_package["signature"]
                .as_str()
                .context("public trust signature missing")?,
        )
        .context("decode public trust signature")?;
    let signature = Signature::from_slice(&signature).context("parse public trust signature")?;
    VerifyingKey::from_bytes(&signing_public_key)
        .context("parse public trust signer")?
        .verify(
            &canonical_signed_payload(&trust_package).context("canonicalize trust package")?,
            &signature,
        )
        .context("verify public trust package")?;
    Ok(SignedTrustPackage {
        trust_package,
        signing_public_key,
        recovery_public_key,
    })
}

fn public_key(encoded: &str) -> Result<[u8; 32]> {
    STANDARD
        .decode(encoded.trim())
        .context("decode public trust key")?
        .try_into()
        .map_err(|_| anyhow::anyhow!("public trust key must be Ed25519"))
}

/// Write a verified, time-bounded signed trust package and DTC in `output_dir`.
///
/// No private key material is serialized or returned.
pub fn generate_demo_fixtures(output_dir: &Path) -> Result<DemoFixtureManifest> {
    fs::create_dir_all(output_dir)
        .with_context(|| format!("create fixture directory {}", output_dir.display()))?;

    let generated = generate_values()?;
    let trust_package_path = output_dir.join("trust-package.json");
    let dtc_path = output_dir.join("dtc.json");
    let signing_key_path = output_dir.join("usb-signing-public-key.txt");
    let recovery_key_path = output_dir.join("usb-recovery-public-key.txt");

    write_json(&trust_package_path, &generated.trust_package)?;
    write_json(&dtc_path, &generated.dtc)?;
    fs::write(
        &signing_key_path,
        STANDARD.encode(generated.signing_public_key),
    )
    .with_context(|| format!("write {}", signing_key_path.display()))?;
    fs::write(
        &recovery_key_path,
        STANDARD.encode(generated.recovery_public_key),
    )
    .with_context(|| format!("write {}", recovery_key_path.display()))?;

    let manifest = DemoFixtureManifest {
        trust_package_path: absolute_display(&trust_package_path)?,
        dtc_path: absolute_display(&dtc_path)?,
        usb_signing_public_key_path: absolute_display(&signing_key_path)?,
        usb_recovery_public_key_path: absolute_display(&recovery_key_path)?,
    };
    write_json(&output_dir.join("manifest.json"), &manifest)?;
    Ok(manifest)
}

fn generate_values() -> Result<GeneratedFixtures> {
    let signed_trust = demo_trust_package("dtc")?;
    let dtc: Value = serde_json::from_str(include_str!("fixtures/demo_dtc/dtc.json"))
        .context("parse signed public DTC vector")?;
    let certificate_b64 = signed_trust.trust_package["csca_certificates"][0]["certificate_der_b64"]
        .as_str()
        .context("public DTC trust package has no CSCA")?;
    STANDARD
        .decode(certificate_b64)
        .context("decode public DTC CSCA")?;
    let certificate_lines = certificate_b64
        .as_bytes()
        .chunks(64)
        .map(std::str::from_utf8)
        .collect::<std::result::Result<Vec<_>, _>>()?
        .join("\n");
    let csca_pem =
        format!("-----BEGIN CERTIFICATE-----\n{certificate_lines}\n-----END CERTIFICATE-----\n");
    let mut verification_input = dtc.clone();
    verification_input["trust_anchors_pem"] = json!([&csca_pem]);
    let verified = verify_dtc_json(&verification_input.to_string()).map_err(anyhow::Error::msg)?;
    let verified: Value =
        serde_json::from_str(&verified).context("parse public DTC verification")?;
    if verified["is_valid"] != true {
        bail!("signed public DTC vector did not verify against its CSCA");
    }
    Ok(GeneratedFixtures {
        trust_package: signed_trust.trust_package,
        dtc,
        #[cfg(test)]
        csca_pem,
        signing_public_key: signed_trust.signing_public_key,
        recovery_public_key: signed_trust.recovery_public_key,
    })
}
pub(crate) fn write_json(path: &Path, value: &impl Serialize) -> Result<()> {
    let bytes = serde_json::to_vec_pretty(value)?;
    fs::write(path, bytes).with_context(|| format!("write {}", path.display()))
}

pub(crate) fn absolute_display(path: &Path) -> Result<String> {
    let absolute = path
        .canonicalize()
        .with_context(|| format!("resolve {}", path.display()))?
        .to_string_lossy()
        .into_owned();
    #[cfg(windows)]
    {
        if let Some(unc) = absolute.strip_prefix("\\\\?\\UNC\\") {
            return Ok(format!("\\\\{unc}"));
        }
        if let Some(drive_path) = absolute.strip_prefix("\\\\?\\") {
            return Ok(drive_path.to_string());
        }
    }
    Ok(absolute)
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signature, Verifier, VerifyingKey};
    use marty_verification::dtc::verify_dtc_json;

    #[test]
    fn refreshed_trust_rejects_old_future_and_missing_creation_times() {
        let now = Utc::now();
        for created in [
            now - chrono::Duration::hours(73),
            now + chrono::Duration::seconds(1),
        ] {
            assert!(require_fresh_trust(&json!({"created_at":created.to_rfc3339()}), now).is_err());
        }
        assert!(require_fresh_trust(&json!({}), now).is_err());
        assert!(require_fresh_trust(&json!({"created_at":now.to_rfc3339()}), now).is_ok());
    }

    #[test]
    fn refresh_preserves_public_anchors_and_uses_production_canonical_payload() {
        let root = tempfile::tempdir().unwrap();
        let original = embedded_trust_package("dtc").unwrap();
        fs::write(
            root.path().join("usb-signing-public-key.txt"),
            STANDARD.encode(original.signing_public_key),
        )
        .unwrap();
        fs::write(
            root.path().join("usb-recovery-public-key.txt"),
            STANDARD.encode(original.recovery_public_key),
        )
        .unwrap();
        let output = root.path().join("prepared");
        prepare_public_trust_refresh("dtc", root.path(), &output).unwrap();
        let package: Value =
            serde_json::from_str(&fs::read_to_string(output.join("trust-package.json")).unwrap())
                .unwrap();
        let request: Value =
            serde_json::from_str(&fs::read_to_string(output.join("kms-input.json")).unwrap())
                .unwrap();
        assert_eq!(
            package["csca_certificates"],
            original.trust_package["csca_certificates"]
        );
        assert_eq!(
            STANDARD.decode(request["input"].as_str().unwrap()).unwrap(),
            canonical_signed_payload(&package).unwrap()
        );
        require_fresh_trust(&package, Utc::now()).unwrap();
        // The old valid signature must never authorize the refreshed envelope.
        let signature = root.path().join("signature.txt");
        fs::write(
            &signature,
            original.trust_package["signature"].as_str().unwrap(),
        )
        .unwrap();
        let before = fs::read(output.join("trust-package.json")).unwrap();
        assert!(complete_public_trust_refresh(&output, &signature).is_err());
        assert_eq!(fs::read(output.join("trust-package.json")).unwrap(), before);
        assert!(prepare_public_trust_refresh("dtc", root.path(), &output).is_err());
    }

    #[test]
    fn fixtures_use_real_production_signing_and_never_serialize_private_keys() {
        let generated = generate_values().expect("generate demo fixtures");

        let payload = canonical_signed_payload(&generated.trust_package).unwrap();
        let signature = STANDARD
            .decode(generated.trust_package["signature"].as_str().unwrap())
            .unwrap();
        VerifyingKey::from_bytes(&generated.signing_public_key)
            .unwrap()
            .verify(&payload, &Signature::from_slice(&signature).unwrap())
            .expect("trust package signature");

        let mut dtc = generated.dtc;
        dtc.as_object_mut()
            .unwrap()
            .insert("trust_anchors_pem".to_string(), json!([generated.csca_pem]));
        let verified = verify_dtc_json(&dtc.to_string()).expect("verify generated DTC");
        let verified: Value = serde_json::from_str(&verified).unwrap();
        assert_eq!(verified["is_valid"], true, "{verified:#}");

        let serialized = serde_json::to_string(&dtc).unwrap();
        assert!(!serialized.contains("PRIVATE KEY"));
        assert!(!serialized.contains("signing_key_pem"));
    }

    #[test]
    fn fixture_writer_emits_only_declared_public_artifacts() {
        let output = tempfile::tempdir().unwrap();
        let manifest = generate_demo_fixtures(output.path()).unwrap();
        for path in [
            manifest.trust_package_path,
            manifest.dtc_path,
            manifest.usb_signing_public_key_path,
            manifest.usb_recovery_public_key_path,
        ] {
            assert!(!path.starts_with("\\\\?\\"));
            let contents = fs::read_to_string(path).unwrap();
            assert!(!contents.contains("PRIVATE KEY"));
            assert!(!contents.contains("signing_key_pem"));
        }
    }
}
