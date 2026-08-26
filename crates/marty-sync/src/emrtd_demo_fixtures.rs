//! Ephemeral ICAO 9303 fixtures for release-demo qualification.
//!
//! Only signed public artifacts are written. CSCA and DSC private keys remain
//! process-local and are dropped before the manifest is returned.

use std::{collections::HashMap, fs, path::Path};

use anyhow::{bail, Context, Result};
use base64::{engine::general_purpose::STANDARD, Engine};
use chrono::Utc;
use marty_crypto::{
    cert_builder::{create_csca_certificate, create_dsc_certificate},
    keygen::KeyType,
    sod_builder::build_emrtd_sod_der,
};
use marty_verification::{
    verification::emrtd::{verify_emrtd, SecurityObject},
    CscaRegistry,
};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use x509_cert::{der::Decode, Certificate};

use crate::demo_fixtures::{absolute_display, signed_trust_package, write_json};

const COUNTRY: &str = "UTO";
const DG1: &[u8] =
    b"P<UTODEMO<<MARTY<<<<<<<<<<<<<<<<<<<<<<<<<<D01DEMO10UTO9001018X2708257<<<<<<<<<<<<<<02";
const DG2: &[u8] = &[
    0xff, 0xd8, 0xff, 0xe0, 0x00, 0x10, b'J', b'F', b'I', b'F', 0x00, 0x01,
];

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EmrtdDemoFixtureManifest {
    pub trust_package_path: String,
    pub valid_passport_path: String,
    pub invalid_passport_path: String,
    pub usb_signing_public_key_path: String,
    pub usb_recovery_public_key_path: String,
}

/// Generate one trusted eMRTD and a DG-tampered counterpart in `output_dir`.
pub fn generate_emrtd_demo_fixtures(output_dir: &Path) -> Result<EmrtdDemoFixtureManifest> {
    fs::create_dir_all(output_dir)
        .with_context(|| format!("create fixture directory {}", output_dir.display()))?;

    let (csca_der, csca_key) =
        create_csca_certificate(COUNTRY, "Marty D-01 Demo CSCA", 3650, KeyType::EcdsaP256)
            .context("generate D-01 CSCA")?;
    let (dsc_der, dsc_key) = create_dsc_certificate(
        COUNTRY,
        "Marty D-01 Demo Document Signer",
        &csca_der,
        &csca_key,
        730,
        KeyType::EcdsaP256,
    )
    .context("generate D-01 document signer")?;
    let data_groups = vec![(1_u8, DG1.to_vec()), (2_u8, DG2.to_vec())];
    let sod_der = build_emrtd_sod_der(&data_groups, &dsc_der, &dsc_key)
        .context("build signed D-01 EF.SOD")?;

    let data_groups_json = json!({
        "DG1": STANDARD.encode(DG1),
        "DG2": STANDARD.encode(DG2),
    });
    let valid_passport = json!({
        "sod_base64": STANDARD.encode(&sod_der),
        "data_groups": data_groups_json,
        "country": COUNTRY,
    });
    let mut invalid_passport = valid_passport.clone();
    invalid_passport["data_groups"]["DG1"] = STANDARD.encode(b"tampered-passport-data").into();

    assert_cryptographic_outcomes(&valid_passport, &invalid_passport, &csca_der)?;

    let signed_trust = signed_trust_package(
        vec![json!({
            "jurisdiction": COUNTRY,
            "subject": "Marty D-01 Demo CSCA",
            "issuer": "Marty D-01 Demo CSCA",
            "serial": Value::Null,
            "certificate_der_b64": STANDARD.encode(&csca_der),
        })],
        Utc::now(),
        "d01-emrtd-demo-1",
    )?;

    let trust_package_path = output_dir.join("trust-package.json");
    let valid_passport_path = output_dir.join("valid-passport.json");
    let invalid_passport_path = output_dir.join("invalid-passport.json");
    let signing_key_path = output_dir.join("usb-signing-public-key.txt");
    let recovery_key_path = output_dir.join("usb-recovery-public-key.txt");
    write_json(&trust_package_path, &signed_trust.trust_package)?;
    write_json(&valid_passport_path, &valid_passport)?;
    write_json(&invalid_passport_path, &invalid_passport)?;
    fs::write(
        &signing_key_path,
        STANDARD.encode(signed_trust.signing_public_key),
    )
    .with_context(|| format!("write {}", signing_key_path.display()))?;
    fs::write(
        &recovery_key_path,
        STANDARD.encode(signed_trust.recovery_public_key),
    )
    .with_context(|| format!("write {}", recovery_key_path.display()))?;

    let manifest = EmrtdDemoFixtureManifest {
        trust_package_path: absolute_display(&trust_package_path)?,
        valid_passport_path: absolute_display(&valid_passport_path)?,
        invalid_passport_path: absolute_display(&invalid_passport_path)?,
        usb_signing_public_key_path: absolute_display(&signing_key_path)?,
        usb_recovery_public_key_path: absolute_display(&recovery_key_path)?,
    };
    write_json(&output_dir.join("manifest.json"), &manifest)?;
    Ok(manifest)
}

fn assert_cryptographic_outcomes(valid: &Value, invalid: &Value, csca_der: &[u8]) -> Result<()> {
    let csca = Certificate::from_der(csca_der).context("parse generated D-01 CSCA")?;
    let mut registry = CscaRegistry::new();
    registry
        .add_country_csca(COUNTRY, csca)
        .context("register generated D-01 CSCA")?;

    let verify = |payload: &Value| -> Result<bool> {
        let sod = STANDARD
            .decode(payload["sod_base64"].as_str().context("missing SOD")?)
            .context("decode generated SOD")?;
        let security_object = SecurityObject::from_sod_der(&sod, Some(COUNTRY.to_string()))
            .context("parse generated SOD")?;
        let groups = payload["data_groups"]
            .as_object()
            .context("missing generated data groups")?
            .iter()
            .map(|(name, encoded)| {
                let number = name
                    .strip_prefix("DG")
                    .context("invalid generated DG name")?
                    .parse::<u8>()
                    .context("invalid generated DG number")?;
                let bytes = STANDARD
                    .decode(encoded.as_str().context("invalid generated DG value")?)
                    .context("decode generated DG")?;
                Ok((number, bytes))
            })
            .collect::<Result<HashMap<_, _>>>()?;
        Ok(verify_emrtd(&security_object, &groups, &registry).verified)
    };

    if !verify(valid)? {
        bail!("generated trusted passport did not pass canonical eMRTD verification");
    }
    if verify(invalid)? {
        bail!("generated tampered passport unexpectedly passed canonical eMRTD verification");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fixture_writer_proves_trusted_and_tampered_paths_without_private_keys() {
        let output = tempfile::tempdir().unwrap();
        let manifest = generate_emrtd_demo_fixtures(output.path()).unwrap();
        let paths = [
            manifest.trust_package_path,
            manifest.valid_passport_path,
            manifest.invalid_passport_path,
            manifest.usb_signing_public_key_path,
            manifest.usb_recovery_public_key_path,
        ];
        for path in paths {
            assert!(!path.starts_with("\\\\?\\"));
            let contents = fs::read_to_string(path).unwrap();
            assert!(!contents.contains("PRIVATE KEY"));
            assert!(!contents.contains("signing_key_pem"));
        }
        let emitted = fs::read_dir(output.path()).unwrap().count();
        assert_eq!(emitted, 6, "five public artifacts plus manifest");
    }
}
