//! Ephemeral, cryptographically valid fixtures for native demo qualification.
//!
//! This module is excluded from normal builds. It deliberately writes only
//! public keys and signed artifacts; all private keys remain process-local.

use std::{fs, path::Path};

use anyhow::{bail, Context, Result};
use base64::{engine::general_purpose::STANDARD, Engine};
use chrono::{Duration, Utc};
use const_oid::ObjectIdentifier;
use der::Encode;
use ed25519_dalek::{Signer, SigningKey};
use marty_verification::dtc::{create_dtc_json, sign_dtc_json};
use rcgen::{BasicConstraints, CertificateParams, CustomExtension, DnType, IsCa, KeyPair};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use x509_cert::ext::pkix::ExtendedKeyUsage;

use crate::usb::{canonical_signed_payload, signer_key_id};

const DTC_SIGNER_EKU_OID: &str = "2.23.136.1.1.12.1";

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

/// Generate a fresh signed trust package and DTC chain in `output_dir`.
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
    let signing_key = random_ed25519_key()?;
    let recovery_key = random_ed25519_key()?;
    let signing_public_key = signing_key.verifying_key().to_bytes();
    let recovery_public_key = recovery_key.verifying_key().to_bytes();

    let mut ca_params = CertificateParams::default();
    ca_params
        .distinguished_name
        .push(DnType::CommonName, "Marty Demo CSCA");
    ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    let ca_key = KeyPair::generate().context("generate demo CSCA key")?;
    let ca_cert = ca_params
        .self_signed(&ca_key)
        .context("generate demo CSCA certificate")?;

    let signer_key = KeyPair::generate().context("generate demo DTC signer key")?;
    let mut signer_params = CertificateParams::default();
    signer_params
        .distinguished_name
        .push(DnType::CommonName, "Marty Demo DTC Signer");
    signer_params.is_ca = IsCa::NoCa;
    let eku = ExtendedKeyUsage(vec![ObjectIdentifier::new_unwrap(DTC_SIGNER_EKU_OID)]);
    let mut eku_extension = CustomExtension::from_oid_content(
        &[2, 5, 29, 37],
        eku.to_der().context("encode DTC signer EKU")?,
    );
    eku_extension.set_criticality(true);
    signer_params.custom_extensions.push(eku_extension);
    let ca_issuer = rcgen::Issuer::from_params(&ca_params, &ca_key);
    let signer_cert = signer_params
        .signed_by(&signer_key, &ca_issuer)
        .context("generate demo DTC signer certificate")?;

    let now = Utc::now();
    let mut trust_package = json!({
        "trust_domain": "usb:default",
        "sequence": now.timestamp_millis().unsigned_abs(),
        "version": "demo-1",
        "created_at": now.to_rfc3339(),
        "expires_at": (now + Duration::days(7)).to_rfc3339(),
        "signer_key_id": signer_key_id(&signing_public_key),
        "next_signer_key_id": Value::Null,
        "recovery_signer_key_id": signer_key_id(&recovery_public_key),
        "signing_cert": "ephemeral-demo-key",
        "signature": "",
        "iaca_certificates": [],
        "csca_certificates": [{
            "jurisdiction": "UTO",
            "subject": "Marty Demo CSCA",
            "issuer": "Marty Demo CSCA",
            "serial": Value::Null,
            "certificate_der_b64": STANDARD.encode(ca_cert.der().as_ref())
        }],
        "dsc_certificates": [],
        "open_badge_verification_methods": []
    });
    let payload = canonical_signed_payload(&trust_package).context("canonicalize trust package")?;
    trust_package["signature"] = STANDARD
        .encode(signing_key.sign(&payload).to_bytes())
        .into();

    let request = json!({
        "passport_number": "D09DEMO1",
        "issuing_authority": "UTO",
        "issue_date": (now - Duration::days(1)).format("%Y-%m-%d").to_string(),
        "expiry_date": (now + Duration::days(365)).format("%Y-%m-%d").to_string(),
        "personal_details": {
            "first_name": "MARTY",
            "last_name": "DEMO",
            "date_of_birth": "1990-01-01",
            "gender": "X",
            "nationality": "UTO"
        },
        "data_groups": [{"dg_number": 1, "data": "ZGVtby1kZzE=", "data_type": "MRZ"}],
        "dtc_type": 4,
        "type1_profile": {
            "mrz_line1": "P<UTODEMO<<MARTY<<<<<<<<<<<<<<<<<<<<<",
            "mrz_line2": "D09DEMO10UTO9001018X2708257<<<<<<<2",
            "sod_hash": "",
            "issuing_state": "UTO",
            "passive_auth_ok": true
        }
    });
    let created = create_dtc_json(&request.to_string()).map_err(anyhow::Error::msg)?;
    let mut signing_envelope: Value = serde_json::from_str(&created)?;
    let signing_object = signing_envelope
        .as_object_mut()
        .context("DTC creation returned a non-object")?;
    signing_object.insert(
        "signing_key_pem".to_string(),
        signer_key.serialize_pem().into(),
    );
    signing_object.insert("signer_id".to_string(), "marty-demo-dtc-signer".into());
    let signed = sign_dtc_json(&signing_envelope.to_string()).map_err(anyhow::Error::msg)?;
    let mut dtc: Value = serde_json::from_str(&signed)?;
    let dtc_object = dtc
        .as_object_mut()
        .context("DTC signing returned a non-object")?;
    dtc_object.insert(
        "signer_public_key_pem".to_string(),
        signer_key.public_key_pem().into(),
    );
    dtc_object.insert(
        "certificate_chain_pem".to_string(),
        json!([signer_cert.pem()]),
    );
    if dtc_object.contains_key("signing_key_pem") {
        bail!("DTC signing leaked private key material");
    }

    Ok(GeneratedFixtures {
        trust_package,
        dtc,
        #[cfg(test)]
        csca_pem: ca_cert.pem(),
        signing_public_key,
        recovery_public_key,
    })
}

fn random_ed25519_key() -> Result<SigningKey> {
    let mut seed = [0_u8; 32];
    getrandom::fill(&mut seed).map_err(|error| anyhow::anyhow!("generate Ed25519 key: {error}"))?;
    Ok(SigningKey::from_bytes(&seed))
}

fn write_json(path: &Path, value: &impl Serialize) -> Result<()> {
    let bytes = serde_json::to_vec_pretty(value)?;
    fs::write(path, bytes).with_context(|| format!("write {}", path.display()))
}

fn absolute_display(path: &Path) -> Result<String> {
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
