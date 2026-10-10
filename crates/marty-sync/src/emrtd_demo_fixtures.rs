//! Signed public ICAO 9303 vectors for release-demo qualification.
//!
//! No CSCA or DSC private key is created or loaded by this module.

use std::{collections::HashMap, fs, path::Path};

use anyhow::{bail, Context, Result};
use base64::{engine::general_purpose::STANDARD, Engine};
use marty_verification::{
    verification::emrtd::{verify_emrtd, SecurityObject},
    CscaRegistry,
};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use x509_cert::{der::Decode, Certificate};

use crate::demo_fixtures::{absolute_display, public_signed_trust_package, write_json};

const COUNTRY: &str = "UTO";
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

    let signed_trust = public_signed_trust_package(
        include_str!("fixtures/demo_emrtd/trust-package.json"),
        include_str!("fixtures/demo_emrtd/usb-signing-public-key.txt"),
        include_str!("fixtures/demo_emrtd/usb-recovery-public-key.txt"),
    )?;
    let valid_passport: Value =
        serde_json::from_str(include_str!("fixtures/demo_emrtd/valid-passport.json"))
            .context("parse signed public eMRTD vector")?;
    let invalid_passport: Value =
        serde_json::from_str(include_str!("fixtures/demo_emrtd/invalid-passport.json"))
            .context("parse tampered public eMRTD vector")?;
    let csca_der = STANDARD
        .decode(
            signed_trust.trust_package["csca_certificates"][0]["certificate_der_b64"]
                .as_str()
                .context("public eMRTD trust package has no CSCA")?,
        )
        .context("decode public eMRTD CSCA")?;
    assert_cryptographic_outcomes(&valid_passport, &invalid_passport, &csca_der)?;

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
