//! Hardware fingerprinting for license binding

use sysinfo::System;

/// Generate a hardware fingerprint for license binding
pub fn generate_hardware_fingerprint() -> String {
    let mut components = Vec::new();

    // Get system info
    let sys = System::new_all();

    // CPU info
    if let Some(cpu) = sys.cpus().first() {
        components.push(format!("cpu:{}", cpu.brand()));
    }

    // Machine ID (platform-specific)
    #[cfg(target_os = "linux")]
    {
        if let Ok(machine_id) = std::fs::read_to_string("/etc/machine-id") {
            components.push(format!("machine:{}", machine_id.trim()));
        }
    }

    #[cfg(target_os = "macos")]
    {
        if let Ok(output) = std::process::Command::new("ioreg")
            .args(["-rd1", "-c", "IOPlatformExpertDevice"])
            .output()
        {
            let output_str = String::from_utf8_lossy(&output.stdout);
            for line in output_str.lines() {
                if line.contains("IOPlatformUUID") {
                    if let Some(uuid) = line.split('"').nth(3) {
                        components.push(format!("platform:{}", uuid));
                    }
                }
            }
        }
    }

    #[cfg(target_os = "windows")]
    {
        if let Ok(output) = std::process::Command::new("wmic")
            .args(["csproduct", "get", "UUID"])
            .output()
        {
            let output_str = String::from_utf8_lossy(&output.stdout);
            if let Some(uuid) = output_str.lines().nth(1) {
                components.push(format!("platform:{}", uuid.trim()));
            }
        }
    }

    // Hash all components
    let combined = components.join("|");
    let hash = blake3::hash(combined.as_bytes());

    // Return first 32 hex chars
    hash.to_hex()[..32].to_string()
}

/// Verify a hardware fingerprint matches current hardware
#[allow(dead_code)]
pub fn verify_hardware_fingerprint(expected: &str) -> bool {
    let current = generate_hardware_fingerprint();
    current == expected
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_fingerprint_consistency() {
        let fp1 = generate_hardware_fingerprint();
        let fp2 = generate_hardware_fingerprint();
        assert_eq!(fp1, fp2);
        assert_eq!(fp1.len(), 32);
    }
}
