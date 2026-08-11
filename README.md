# Marty Verifier

An on-site credential verification kiosk built with Tauri, designed for edge checkpoint deployments with offline-first operation.

## Features

- **Offline-First**: Operates without network for 72+ hours with local trust anchor cache
- **Multi-Credential Support**: mDL (ISO 18013-5), eMRTD (ICAO 9303), OID4VP, SD-JWT, DTC, Open Badges
- **Secure Storage**: SQLCipher encrypted database with platform keychain integration
- **Open-Source Capabilities**: Every capability compiled into the OSS build is available without a license key
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
│   ├── marty-entitlements/     # Provider-neutral capability extension
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
- Optional TPM-backed key storage

## Building

### Prerequisites
- Rust 1.87+
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

## Entitlement extension

The open-source distribution uses `AllowAllEntitlementProvider`: compiled
capabilities are available without registration or a license key. The
`marty-entitlements` interface is a provider-neutral integration point for
downstream distributions that need their own policy decisions.

## Updates

Updates are distributed via the Tauri updater plugin. Configure the update base
URL, signing public key, and default channel in the app configuration. Requested
channels are validated before they are incorporated into an update URL.

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
  "trust_domain": "usb:default",
  "sequence": 42,
  "version": "1.0.0",
  "created_at": "2026-08-08T12:00:00Z",
  "expires_at": "2026-09-08T12:00:00Z",
  "signer_key_id": "ed25519:<BLAKE3 digest of the pinned 32-byte public key>",
  "next_signer_key_id": null,
  "recovery_signer_key_id": "ed25519:<BLAKE3 digest of the offline recovery public key>",
  "signing_cert": "informational-only",
  "signature": "base64-encoded-ed25519-signature",
  "iaca_certificates": [{
    "jurisdiction": "US-CA",
    "subject": "...",
    "issuer": "...",
    "serial": "...",
    "not_before": "2026-01-01T00:00:00Z",
    "not_after": "2027-01-01T00:00:00Z",
    "certificate_der_b64": "..."
  }],
  "csca_certificates": [],
  "dsc_certificates": [],
  "open_badge_verification_methods": [{
    "id": "did:example:issuer#key-1",
    "type": "JsonWebKey2020",
    "controller": "did:example:issuer",
    "publicKeyJwk": { "kty": "OKP", "crv": "Ed25519", "x": "..." },
    "status": "active",
    "not_before": "2026-01-01T00:00:00Z",
    "not_after": "2027-01-01T00:00:00Z"
  }]
}
```

`trust_domain` must exactly match the verifier's out-of-band
`sync_config.usb_trust_domain` (default `usb:default`). The signature covers
RFC 8785 JSON Canonicalization Scheme bytes, excluding only `signature`.
The verifier derives `signer_key_id` from the actual configured or embedded
Ed25519 public key and rejects a signed mismatch. The stable recovery identity
is independently pinned by `USB_RECOVERY_PUBLIC_KEY_PATH` (or the compile-time
public value `USB_RECOVERY_PUBLIC_KEY`), and every package's signed
`recovery_signer_key_id` must match that key before any records are parsed or
stored. The complete package is then applied as one monotonic transaction. Every
package must include
`next_signer_key_id` (an exact key id or `null`) and a non-empty
`recovery_signer_key_id`; both fields are covered by the package signature.
`signing_cert` is never a source of trust.

To rotate an operational key, the current signer first signs a higher-sequence
package whose `next_signer_key_id` is the BLAKE3-derived id of the replacement
public key. The operator then installs that already-authorized public key through
`USB_SIGNING_PUBLIC_KEY_PATH`; a package signed by it activates the transition
and consumes the old authorization. Merely changing the configured key does not
authorize a transition. For recovery, install the stable offline recovery public
key and import a higher-sequence recovery-signed package that authorizes a
distinct next operational signer. The recovery key id cannot change after it is
first committed, and an unauthorized signer or recovery change leaves all trust
state untouched.

## Security

### Data at Rest

- Database encrypted with SQLCipher (AES-256)
- Encryption key stored in platform keychain
- PII fields encrypted with separate key
- Searchable indexes use BLAKE3 hashes

### Update protection

- Tauri update manifests and installers are verified with the configured public key
- Release artifacts include checksums, signatures, SBOMs, and build provenance

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
- **Unsigned macOS builds** with checksums and GitHub build provenance
- **Updater signing** for cryptographic update verification (independent of Apple signing)
- **Auto-updater** for seamless updates
- **Multi-platform builds** (macOS x86_64/arm64, Windows x64, Linux AppImage/deb)

See [docs/CODE_SIGNING.md](docs/CODE_SIGNING.md) for the release trust model and platform limitations.

### Release Process

**Marty Core dependency proposals:**

When Marty Core publishes a stable release, repository automation may open one
draft dependency PR. It resolves the published tag to an exact commit on Core's
protected `main`, updates all six Core `rev` pins and `Cargo.lock` together, and
runs locked, all-feature workspace tests before pushing the dedicated branch.
The PR then receives the normal Rust, UI, security, license, policy, and quality
checks. GitHub places workflow runs initiated by the repository's short-lived
`GITHUB_TOKEN` in an approval-required state; a maintainer must approve those
runs before review or merge. The automation never pushes `main`, bumps the
Verifier application version, creates or moves a tag, publishes a release,
force-pushes, approves, or merges its PR.

Application versioning is a separate reviewed release change. Cargo workspace,
Tauri, UI package, and npm lockfile versions must move together. A stable tag is
created only from the reviewed merge commit after that exact protected-`main`
commit's required checks pass; a failed immutable tag is never moved or reused.

**Manual release:**

```bash
# Create RC tag
git tag v0.2.0-rc.1
git push origin v0.2.0-rc.1

# Test the RC build from GitHub Releases

# After merging the complete 0.2.0 version change, capture exact origin/main
SOURCE_SHA=$(git rev-parse origin/main)

# Only the preparation workflow creates the previously unused annotated tag.
# It requires every configured exact-main gate and dispatches the tag-bound release.
gh workflow run prepare-stable-tag.yml --ref main \
  -f tag=v0.2.0 \
  -f source_sha="$SOURCE_SHA"
```

Do not create a stable tag manually. If preparation publishes a tag but release
publication fails, retain that immutable tag as quarantined and prepare a new
version; never move, delete, or reuse the failed tag.

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
- Unsigned and not Apple-notarized; macOS Gatekeeper may require explicit user approval
- SHA-256 checksums, SBOM, and GitHub build-provenance attestation are published with each release
- Supports macOS 10.15+

**Windows:**
- NSIS installer (.exe) from GitHub Releases
- SHA-256 checksums, SBOM, and GitHub build-provenance attestation are published with each release
- Supports Windows 10+

**Linux:**
- AppImage (universal) from GitHub Releases
- .deb package for Debian/Ubuntu
- Tested on Ubuntu 20.04+

## License

This project is licensed under the [GNU Affero General Public License v3.0](LICENSE) (AGPL-3.0-only).
