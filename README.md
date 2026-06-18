# Marty Verifier

An on-site credential verification kiosk built with Tauri, designed for edge checkpoint deployments with offline-first operation.

## Features

- **Offline-First**: Operates without network for 72+ hours with local trust anchor cache
- **Multi-Credential Support**: mDL (ISO 18013-5), eMRTD (ICAO 9303), OID4VP, SD-JWT, DTC, Open Badges
- **Secure Storage**: SQLCipher encrypted database with platform keychain integration
- **Cryptographic Licensing**: JWT licenses with Ed25519 signatures and hardware binding
- **Trust Anchor Sync**: AAMVA DTS, ICAO PKD sources with USB import for air-gapped environments
- **Hardware Tiers**: Simple (camera only) and Complex (NFC, BLE, biometrics, TPM) kiosks
- **Optional Reporting**: Queue-and-forward reporting with local-only mode option

## Architecture

```
marty-verifier/
├── src-tauri/              # Rust backend
│   ├── src/
│   │   ├── main.rs         # Tauri app entry point
│   │   ├── commands/       # IPC command handlers
│   │   ├── config.rs       # Application configuration
│   │   ├── state.rs        # Application state management
│   │   └── hardware.rs     # Hardware detection
│   └── Cargo.toml
├── crates/
│   ├── marty-secure-storage/   # SQLCipher + keychain
│   ├── marty-license/          # JWT license validation
│   ├── marty-sync/             # Trust anchor synchronization
│   ├── marty-biometrics/       # Face verification (optional)
│   └── marty-reporting/        # Event reporting (optional)
└── ui/                     # React frontend
    ├── src/
    │   ├── components/     # Reusable UI components
    │   ├── pages/          # Page components
    │   ├── services/       # Tauri IPC bindings
    │   └── store/          # Zustand state management
    └── vite.config.ts
```

## Hardware Tiers

### Simple Kiosk
- Camera for QR code scanning
- Basic mDL/OID4VP/DTC/Open Badge verification
- No biometrics

### Complex Kiosk
- Camera + NFC + BLE
- Full mDL + eMRTD support
- Face matching biometrics
- TPM-bound licenses

## Building

### Prerequisites
- Rust 1.75+
- Node.js 20+
- pnpm 8+

### Development

```bash
# Install UI dependencies
cd ui
pnpm install

# Run development server
pnpm tauri dev
```

### Production Build

```bash
# Build for current platform
pnpm tauri build

# Build with specific features
cd src-tauri
cargo build --release --features "iaca,csca,oid4vp,sd-jwt,biometrics,reporting"
```

### Feature Flags

| Feature | Description |
|---------|-------------|
| `iaca` | AAMVA IACA certificate validation |
| `csca` | ICAO CSCA/DSC certificate validation |
| `oid4vp` | OpenID for Verifiable Presentations |
| `sd-jwt` | Selective Disclosure JWT credentials |
| `biometrics` | Face matching verification |
| `reporting` | Remote event reporting |
| `nfc` | NFC reader support |
| `ble` | Bluetooth Low Energy support |

### Minimal Build (Simple Kiosk)

```bash
cargo build --release --no-default-features --features "iaca,oid4vp"
```

### Full Build (Complex Kiosk)

```bash
cargo build --release --features "iaca,csca,oid4vp,sd-jwt,biometrics,reporting,nfc,ble"
```

## Configuration

Configuration is stored in the app data directory:
- macOS: `~/Library/Application Support/com.marty.verifier/config.json`
- Windows: `%APPDATA%\com.marty.verifier\config.json`
- Linux: `~/.config/com.marty.verifier/config.json`

### Example Configuration

```json
{
  "sync_config": {
    "aamva_dts_endpoint": "https://dts.aamva.org/api/v1",
    "icao_pkd_endpoint": "https://pkd.icao.int/api/v1",
    "sync_interval_hours": 24,
    "max_offline_hours": 72,
    "enable_usb_import": true
  },
  "reporting_config": {
    "enabled": true,
    "local_only": false,
    "batch_interval_minutes": 15
  },
  "ui_config": {
    "theme": "system",
    "kiosk_mode": true,
    "show_offline_banner": true
  },
  "retention": {
    "verification_events_days": 30,
    "audit_log_days": 90,
    "encrypt_pii": true
  }
}
```

## License Management

Licenses are cryptographic JWT tokens signed with Ed25519. License claims include:

- Organization ID
- Licensed features
- Expiration date
- Hardware binding (optional)
- Total verification limits
- Update channels
- Grace period

### Installing a License

1. Navigate to License page in the UI
2. Paste the JWT license token
3. Click "Validate & Install"

The license is validated against:
- Signature verification (Ed25519)
- Expiration date
- Hardware fingerprint (if hardware-bound)
- Total verification counts

## Updates

Updates are distributed via the Tauri updater plugin and gated by license update channels.
Configure the update base URL and public key in the app config, and ensure licenses include
the allowed `update_channels` (for example: `stable`, `beta`, `dev`).

## Trust Anchor Sync

### Online Sync

The application syncs trust anchors from:
- **AAMVA DTS**: IACA certificates for US driver's licenses
- **ICAO PKD**: CSCA/DSC certificates for passports

Sync runs automatically based on `sync_interval_hours` configuration.

### USB Import (Air-Gapped)

For environments without network access:

1. Export trust anchors on a connected system
2. Copy to USB drive as `trust_anchors.json`
3. Import via Sync page in the UI

### Trust Anchor Package Format

```json
{
  "version": "1.0.0",
  "created_at": "2024-01-15T12:00:00Z",
  "signature": "base64-encoded-ed25519-signature",
    "certificates": [
      {
        "type": "IACA",
        "jurisdiction": "US-CA",
        "subject": "...",
        "certificate_pem": "..."
      }
    ],
    "open_badge_verification_methods": [
      {
        "id": "did:example:issuer#key-1",
        "type": "JsonWebKey2020",
        "controller": "did:example:issuer",
        "publicKeyJwk": { "kty": "OKP", "crv": "Ed25519", "x": "..." },
        "status": "active",
        "not_before": "2025-01-01T00:00:00Z",
        "not_after": "2027-01-01T00:00:00Z"
      }
    ]
  }
```

## Security

### Data at Rest

- Database encrypted with SQLCipher (AES-256)
- Encryption key stored in platform keychain
- PII fields encrypted with separate key
- Searchable indexes use BLAKE3 hashes

### License Protection

- Ed25519 signatures prevent tampering
- Hardware binding prevents license transfer
- Grace period allows temporary offline operation

### Code Protection

Production builds use:
- Terser minification
- javascript-obfuscator for code protection
- Release builds strip debug symbols

## Development

### Running Tests

```bash
# Rust tests
cargo test --workspace

# UI tests
cd ui
pnpm test
```

### Code Quality

```bash
# Rust linting
cargo clippy --workspace

# UI linting
cd ui
pnpm lint
```

## Deployment

### Desktop App Releases

Marty Verifier uses an automated release pipeline with:

- **RC (Release Candidate) testing** before stable releases
- **Code signing** for macOS and Windows
- **Auto-updater** for seamless updates
- **Multi-platform builds** (macOS x86_64/arm64, Windows x64, Linux AppImage/deb)

See [docs/CODE_SIGNING.md](docs/CODE_SIGNING.md) for certificate setup instructions.

### Release Process

**Automated from marty-core:**

When marty-core releases a new version, this repository automatically:
1. Updates marty-core dependencies
2. Runs full test suite
3. Bumps patch version (e.g., 0.1.0 → 0.1.1)
4. Creates new release if tests pass
5. Creates GitHub Issue if tests fail

**Manual release:**

```bash
# Create RC tag
git tag v0.2.0-rc.1
git push origin v0.2.0-rc.1

# Test the RC build from GitHub Releases

# Promote to stable (creates v0.2.0 tag)
# Manually tag or wait for auto-promotion after marty-core update
git tag v0.2.0
git push origin v0.2.0
```

### Auto-Updater

The app automatically checks for updates on launch and periodically during operation:

- **Update channel:** Stable only (no beta/rc channel for end users)
- **Update manifest:** `https://github.com/ElevenID/marty-verifier/releases/latest/download/latest.json`
- **Signature verification:** Updates are cryptographically signed
- **Silent updates:** Downloads in background, prompts on next launch

Users can disable auto-updates in Settings.

### Distribution

**macOS:**
- DMG installer from GitHub Releases
- Code signed and notarized
- Supports macOS 10.15+

**Windows:**
- NSIS installer (.exe) from GitHub Releases
- Code signed with EV certificate
- Supports Windows 10+

**Linux:**
- AppImage (universal) from GitHub Releases
- .deb package for Debian/Ubuntu
- Tested on Ubuntu 20.04+

## License

This project is licensed under the [GNU Affero General Public License v3.0](LICENSE) (AGPL-3.0-only).
