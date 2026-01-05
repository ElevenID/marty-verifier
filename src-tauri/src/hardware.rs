//! Hardware detection and tier management

use serde::{Deserialize, Serialize};

/// Hardware tier classification
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum HardwareTier {
    /// Basic hardware: camera only
    Simple,
    /// Full sensor suite: NFC, BLE, biometrics
    Complex,
}

impl HardwareTier {
    /// Check if this tier supports a given feature
    pub fn supports_feature(&self, feature: &str) -> bool {
        match self {
            HardwareTier::Simple => matches!(
                feature,
                "mdl_qr" | "oid4vp" | "sd-jwt" | "basic_verification" | "dtc" | "open-badge"
            ),
            HardwareTier::Complex => true, // Complex tier supports all features
        }
    }
}

/// Hardware detection results
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HardwareCapabilities {
    /// Camera available for QR scanning
    pub has_camera: bool,

    /// NFC reader available (ISO 14443)
    pub has_nfc: bool,

    /// Bluetooth Low Energy available
    pub has_ble: bool,

    /// TPM 2.0 available for hardware binding
    pub has_tpm: bool,

    /// Biometric sensor available
    pub has_biometric_sensor: bool,

    /// USB HID scanner detected
    pub has_usb_scanner: bool,
}

impl Default for HardwareCapabilities {
    fn default() -> Self {
        Self {
            has_camera: true, // Assume camera is available
            has_nfc: false,
            has_ble: false,
            has_tpm: false,
            has_biometric_sensor: false,
            has_usb_scanner: false,
        }
    }
}

/// Hardware detector for runtime capability detection
pub struct HardwareDetector {
    capabilities: HardwareCapabilities,
}

impl HardwareDetector {
    /// Create new hardware detector
    pub fn new() -> Self {
        let capabilities = Self::detect_capabilities();
        Self { capabilities }
    }

    /// Detect available hardware capabilities
    fn detect_capabilities() -> HardwareCapabilities {
        let mut caps = HardwareCapabilities::default();

        // Detect NFC reader
        caps.has_nfc = Self::detect_nfc();

        // Detect BLE
        caps.has_ble = Self::detect_ble();

        // Detect TPM
        caps.has_tpm = Self::detect_tpm();

        // Detect biometric sensor
        caps.has_biometric_sensor = Self::detect_biometric();

        // Detect USB scanner
        caps.has_usb_scanner = Self::detect_usb_scanner();

        caps
    }

    /// Detect NFC reader (ISO 14443)
    fn detect_nfc() -> bool {
        // TODO: Use pcsc crate to enumerate smart card readers
        // For now, return false
        #[cfg(feature = "nfc")]
        {
            // pcsc::Context::establish(pcsc::Scope::User)
            //     .map(|ctx| ctx.list_readers_len().unwrap_or(0) > 0)
            //     .unwrap_or(false)
            false
        }

        #[cfg(not(feature = "nfc"))]
        false
    }

    /// Detect Bluetooth Low Energy
    fn detect_ble() -> bool {
        // TODO: Use btleplug or platform-specific APIs
        #[cfg(feature = "ble")]
        {
            false // Placeholder
        }

        #[cfg(not(feature = "ble"))]
        false
    }

    /// Detect TPM 2.0
    fn detect_tpm() -> bool {
        // Platform-specific TPM detection
        #[cfg(target_os = "windows")]
        {
            // Check for TPM via Windows APIs
            false // Placeholder
        }

        #[cfg(target_os = "macos")]
        {
            // macOS uses Secure Enclave instead
            // Check for T2/M1+ chip
            false // Placeholder
        }

        #[cfg(target_os = "linux")]
        {
            // Check for /dev/tpm0 or /dev/tpmrm0
            std::path::Path::new("/dev/tpm0").exists()
                || std::path::Path::new("/dev/tpmrm0").exists()
        }

        #[cfg(not(any(target_os = "windows", target_os = "macos", target_os = "linux")))]
        false
    }

    /// Detect biometric sensor
    fn detect_biometric() -> bool {
        // TODO: Platform-specific biometric detection
        false
    }

    /// Detect USB HID barcode scanner
    fn detect_usb_scanner() -> bool {
        // TODO: Use hidapi to enumerate HID devices
        false
    }

    /// Get detected hardware tier
    pub fn detect_tier(&self) -> HardwareTier {
        if self.capabilities.has_nfc
            || self.capabilities.has_ble
            || self.capabilities.has_biometric_sensor
        {
            HardwareTier::Complex
        } else {
            HardwareTier::Simple
        }
    }

    /// Get full hardware capabilities
    pub fn capabilities(&self) -> &HardwareCapabilities {
        &self.capabilities
    }

    /// Refresh hardware detection
    #[allow(dead_code)]
    pub fn refresh(&mut self) {
        self.capabilities = Self::detect_capabilities();
    }
}

impl Default for HardwareDetector {
    fn default() -> Self {
        Self::new()
    }
}
