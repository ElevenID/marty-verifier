use crate::error::SyncError;

pub(crate) fn decode_signing_public_key(raw: &str) -> Result<Vec<u8>, SyncError> {
    for candidate in key_candidates(raw) {
        if let Some(key) = decode_candidate(candidate)? {
            return Ok(key);
        }
    }

    Err(SyncError::UsbImport(
        "Public key must be 32 raw Ed25519 bytes or a minisign Ed25519 public key".to_string(),
    ))
}

fn key_candidates(raw: &str) -> impl Iterator<Item = &str> {
    raw.lines()
        .map(str::trim)
        .filter(|line| !line.is_empty() && !line.starts_with("untrusted comment:"))
}

fn decode_candidate(candidate: &str) -> Result<Option<Vec<u8>>, SyncError> {
    use base64::Engine;

    let decoded = base64::engine::general_purpose::STANDARD
        .decode(candidate)
        .map_err(|e| SyncError::UsbImport(format!("Invalid base64 in public key: {e}")))?;

    match decoded.len() {
        32 => Ok(Some(decoded)),
        42 if decoded.starts_with(b"Ed") => Ok(Some(decoded[10..].to_vec())),
        _ => {
            if let Ok(nested) = std::str::from_utf8(&decoded) {
                for nested_candidate in key_candidates(nested) {
                    if let Some(key) = decode_candidate(nested_candidate)? {
                        return Ok(Some(key));
                    }
                }
            }
            Ok(None)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::decode_signing_public_key;
    use base64::Engine;

    #[test]
    fn decodes_raw_ed25519_public_key() {
        let key = [7_u8; 32];
        let encoded = base64::engine::general_purpose::STANDARD.encode(key);

        let decoded = decode_signing_public_key(&encoded).expect("decode raw key");

        assert_eq!(decoded, key.to_vec());
    }

    #[test]
    fn decodes_minisign_public_key() {
        let key = [7_u8; 32];
        let mut minisign = Vec::from(&b"Ed"[..]);
        minisign.extend_from_slice(&[1_u8; 8]);
        minisign.extend_from_slice(&key);
        let encoded = base64::engine::general_purpose::STANDARD.encode(minisign);
        let contents = format!("untrusted comment: minisign public key\n{encoded}\n");

        let decoded = decode_signing_public_key(&contents).expect("decode minisign key");

        assert_eq!(decoded, key.to_vec());
    }

    #[test]
    fn decodes_wrapped_minisign_public_key() {
        let key = [7_u8; 32];
        let mut minisign = Vec::from(&b"Ed"[..]);
        minisign.extend_from_slice(&[1_u8; 8]);
        minisign.extend_from_slice(&key);
        let encoded = base64::engine::general_purpose::STANDARD.encode(minisign);
        let contents = format!("untrusted comment: minisign public key\n{encoded}\n");
        let wrapped = base64::engine::general_purpose::STANDARD.encode(contents);

        let decoded = decode_signing_public_key(&wrapped).expect("decode wrapped minisign key");

        assert_eq!(decoded, key.to_vec());
    }
}
