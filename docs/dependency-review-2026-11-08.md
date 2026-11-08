# Dependency boundary review — 2026-11-08

This review addresses [issue 70](https://github.com/ElevenID/marty-verifier/issues/70)
on top of Verifier `94c24fdf59fd03dcb008ab2053cf74d492165210`. The Core revision
remains `a11313be1fdb6035c11c87b42b4120e395d63aba`. The adapter/keyring cleanup in
[29af53ad](https://github.com/ElevenID/marty-verifier/commit/29af53ad110c1545dd93ee94026fe8a78ad0afa1)
preserves library versions; the compatible TLS patches in
[9884667b](https://github.com/ElevenID/marty-verifier/commit/9884667b9c0a6da8d4744fc65e7e0d8fe3d3e85d)
update five transitive libraries. The final updater migration below uses the
stable upstream owner to remove the affected ZIP family. Fork revisions,
credential profiles and custody configuration remain unchanged.

## Remove the obsolete keyring path

The locked graph before this change contains keyring **3.6.3** only because
`src-tauri` directly imports it as `keyring-legacy`. Its sole source consumer is
the packaged startup check's `LegacyMemoryBuilder`/`LegacyMemoryCredential` shim.
The workspace's keyring 4 declaration is unused. The earlier health record's
description of application keyring 4 plus Core keyring 3 no longer matches the
actual graph.

Both application and governed trust storage already share Core secure storage,
which uses **keyring-core 1.0.0** in this lockfile. Remove the unused keyring
workspace declaration, legacy direct dependency and compatibility shim. Keep
`AppState::from_config_with_process_local_keyring`, the process-only store identity
check, and the existing public startup-check contract. Normal GUI startup still
selects its configured platform store through the existing storage owner. The
process-local store is installed only for the explicit startup check.

The startup regression now initializes the real owned storage runtime even when
ordinary Rust tests use Tauri's development profile. Packaged startup still also
checks embedded assets and command registration. The retired keyring health row
is removed because its dependency path disappears, not because its deadline is
extended. The replacement `keyring-core` is an existing dependency, not a new
software signing fallback.

## Use the existing Marty crypto adapters

Verifier removes all direct `x509-cert`, `der` and `ed25519-dalek` dependencies:

| Consumer | Marty-owned operation | Preserved boundary |
| --- | --- | --- |
| DTC governed CSCA store | `marty_crypto::certificate::load_certificate_der` | DER parsing only; stored provenance, freshness and duplicate checks remain local policy inputs. |
| eMRTD CSCA registry and public demo fixtures | The same DER loader, followed by `CscaRegistry::add_country_csca` | Existing Core registry and RSA/certificate verification paths remain in use. |
| Signed USB certificate entries | The same DER loader | Signed subject, issuer, serial, validity and package creation metadata remain unchanged. PEM is not accepted as DER. |
| USB package signatures and public demo refresh completion | `marty_crypto::ed25519::verify` | Exact RFC 8785 payload bytes and pinned public-key identity remain unchanged. Core owns strict Ed25519 verification. |

The Core certificate loader still returns the parsed type accepted by its current
registry API; this change does not introduce a new opaque certificate contract.
It moves backend selection and decoding into the existing owner without adding a
parallel parser. The Ed25519 adapter rejects small-order keys through strict
verification. A public identity-point forgery regression makes that intentional
tightening explicit; valid signed vectors and tampering checks remain required.

## Current upstream release and dependency evidence

The following primary API responses were read on **2026-11-08**. “Newest” includes
prereleases; a release candidate is not treated as a stable migration target.

| Crate | Latest stable | Newest published | Source |
| --- | --- | --- | --- |
| CMS | 0.2.3 | 0.3.0-rc.1 | [crates.io CMS metadata](https://crates.io/api/v1/crates/cms) |
| RSA | 0.9.10 | 0.10.0-rc.22 | [crates.io RSA metadata](https://crates.io/api/v1/crates/rsa) |
| x509-cert | 0.3.0 | 0.3.0 | [crates.io X.509 metadata](https://crates.io/api/v1/crates/x509-cert) |
| der | 0.8.3 | 0.8.3 | [crates.io DER metadata](https://crates.io/api/v1/crates/der) |
| ed25519-dalek | 3.0.0 | 3.0.0 | [crates.io Ed25519 metadata](https://crates.io/api/v1/crates/ed25519-dalek) |
| rand | 0.10.3 | 0.10.3 | [crates.io rand metadata](https://crates.io/api/v1/crates/rand) |
| aes-gcm | 0.11.1 | 0.11.1 | [crates.io AES-GCM metadata](https://crates.io/api/v1/crates/aes-gcm) |

The compatibility edges establish why independent major bumps do not yield the
requested all-stable replacement:

- [CMS 0.2.3](https://crates.io/api/v1/crates/cms/0.2.3/dependencies)
  requires `der ^0.7.7`, `spki ^0.7` and `x509-cert ^0.2.3`.
  Its optional RSA and signature dependencies require `rsa ^0.9.6` and
  `signature ^2.1.0`.
- [CMS 0.3.0-rc.1](https://crates.io/api/v1/crates/cms/0.3.0-rc.1/dependencies)
  changes those requirements to `der ^0.8`, `spki ^0.8`, `x509-cert ^0.3`,
  optional `signature ^3` and optional `rsa ^0.10.0-rc.20`.
- [RSA 0.9.10](https://crates.io/api/v1/crates/rsa/0.9.10/dependencies)
  requires `signature >2.0, <2.3`, `spki ^0.7.3`, `pkcs8 ^0.10.2` and
  `rand_core ^0.6.4`. [RSA 0.10.0-rc.22](https://crates.io/api/v1/crates/rsa/0.10.0-rc.22/dependencies)
  selects signature 3 and the new key-codec/random-source family but remains a
  prerelease.
- [x509-cert 0.3.0](https://crates.io/api/v1/crates/x509-cert/0.3.0/dependencies)
  is stable and requires DER/SPKI 0.8. It cannot replace the 0.2 certificate type
  required by the retained stable CMS path without a coordinated consumer change.

The lockfile therefore retains CMS 0.2.3, x509-cert 0.2.5, DER 0.7.10,
SPKI 0.7.3, RSA 0.9.10 and signature 2.2.0, alongside already-present newer
DER/SPKI/signature generations. Core-owned consumers also retain Ed25519 2.2.0,
rand 0.8.7 and AES-GCM 0.10.3. The latter storage and crypto API migrations need
their owner's qualification; this review does not claim that each one is blocked
solely by CMS.

[RUSTSEC-2023-0071](https://rustsec.org/advisories/RUSTSEC-2023-0071.html)
remains applicable to RSA. The [current OSV record](https://api.osv.dev/v1/vulns/RUSTSEC-2023-0071)
contains no fixed-version event. Neither the latest stable nor the newest
prerelease is represented as a verified advisory fix. The advisory is now
explicit in this consumer's certificate-stack health record; the existing Core
watch remains authoritative for its public-verification-only use. No audit
ignore, deny rule, CI permission or release gate is relaxed.

The existing CI workflow runs `cargo audit` and `cargo deny` with
`continue-on-error: true`. A green Security job therefore does not establish that
those commands reported no findings. This review preserves that workflow and
keeps the unresolved advisory visible; the migration exit criteria below still
require an explicit security qualification.

The baseline scan used cargo-audit 0.22.2 and advisory database commit
`309392b18f6b17022f82c701f300433126901068` (2026-11-06). The original `94c24fdf`
lockfile and this adapter-cleanup lockfile both report the same **17 vulnerability
IDs and package versions**, plus 14 unmaintained and two yanked warnings. The
affected families are quinn-proto, RSA, rustls, rustls-webpki, the two webpki root
bundles and zip. This dependency ownership cleanup does not resolve those
pre-existing findings. Cargo-deny 0.20.2 also rejects the existing
`unmaintained = "warn"` configuration before it can scan the graph; the current
schema requires a dependency selection value. Those results are separate from
the successfully validated dependency-health review record.

## Compatible TLS and transport security patches

The next checkpoint updates only these five locked packages, using compatible
stable releases from their existing dependency families:

| Package | Previous | Patched | Existing parents | Resolved findings |
| --- | --- | --- | --- | --- |
| quinn-proto | 0.11.16 | [0.11.19](https://crates.io/api/v1/crates/quinn-proto/0.11.19) | quinn 0.11.11 | RUSTSEC-2026-0338, 0339, 0340, 0341, 0342 |
| rustls | 0.23.43 | [0.23.46](https://crates.io/api/v1/crates/rustls/0.23.46) | reqwest, hyper-rustls, ldap3, quinn, tokio-rustls, platform verifier, updater | RUSTSEC-2026-0285, 0346, 0348, 0349 |
| rustls-webpki | 0.103.13 | [0.103.16](https://crates.io/api/v1/crates/rustls-webpki/0.103.16) | rustls, rustls-platform-verifier | RUSTSEC-2026-0382 |
| webpki-roots | 1.0.9 | [1.0.11](https://crates.io/api/v1/crates/webpki-roots/1.0.11) | reqwest, hyper-rustls | RUSTSEC-2026-0381 |
| webpki-root-certs | 1.0.9 | [1.0.11](https://crates.io/api/v1/crates/webpki-root-certs/1.0.11) | ureq, rustls-platform-verifier | RUSTSEC-2026-0383 |

The advisory database's fixed-version ranges require quinn-proto at least
0.11.18, rustls at least 0.23.46, rustls-webpki at least 0.103.16 within its stable
family, and both root bundles at least 1.0.10. The selected releases satisfy all
those ranges without changing their parent versions or introducing a new crypto
backend. Existing aws-lc-rs 1.18.0 satisfies the new TLS requirements.

Scanning against the same advisory database reduces the vulnerability count from
**17 to 5**: RSA's unresolved advisory and four findings in zip 4.6.1 remain at
this checkpoint. The 14 unmaintained and two yanked warnings remain visible.
These numbers describe lockfile findings, not a claim that every vulnerable
function is reachable on every supported platform.

`deny.toml` is also migrated to the supported
[cargo-deny 0.20 advisory schema](https://github.com/EmbarkStudios/cargo-deny/blob/0.20.2/docs/src/checks/advisories/cfg.md)
and [license schema](https://github.com/EmbarkStudios/cargo-deny/blob/0.20.2/docs/src/checks/licenses/cfg.md).
Vulnerability and notice advisories are errors by default; unmaintained and
unsound selection explicitly covers the whole graph. The license allowlist and
two existing crate-specific exceptions are unchanged. Removing obsolete
`licenses.deny`/`copyleft` fields does not permit GPL/AGPL: unlisted licenses are
denied by the current schema. No advisory ignore is added, and all five platform
targets remain in the graph.

Cargo-deny now completes its scan instead of rejecting its configuration. It
still reports the unresolved advisories, unmaintained dependencies and existing
license-policy findings. The scan is not presented as a passing security gate.

## Migrate the updater through its stable owner

The four remaining ZIP advisories have fixed-version ranges beginning at ZIP 9:
[RUSTSEC-2026-0367](https://rustsec.org/advisories/RUSTSEC-2026-0367.html),
[0368](https://rustsec.org/advisories/RUSTSEC-2026-0368.html),
[0369](https://rustsec.org/advisories/RUSTSEC-2026-0369.html) and
[0429](https://rustsec.org/advisories/RUSTSEC-2026-0429.html). The locked updater
2.10.1 requires ZIP 4 on Windows. Its stable successor
[2.14.1](https://crates.io/api/v1/crates/tauri-plugin-updater/2.14.1/dependencies)
requires Tauri 2.12 and supports ZIP 9. The migration follows that supported owner
path rather than overriding the old updater's ZIP requirement.

| Component | Previous locked version | Qualified version |
| --- | --- | --- |
| Tauri runtime | 2.11.5 | [2.12.5](https://crates.io/api/v1/crates/tauri/2.12.5) |
| Tauri updater plugin | 2.10.1 | [2.14.1](https://crates.io/api/v1/crates/tauri-plugin-updater/2.14.1) |
| Windows updater ZIP dependency | 4.6.1 | [9.4.2](https://crates.io/api/v1/crates/zip/9.4.2) |
| JavaScript Tauri API | 2.11.1 | [2.12.4](https://registry.npmjs.org/@tauri-apps/api/2.12.4) |
| Tauri CLI and platform binaries | 2.11.4 | [2.12.4](https://registry.npmjs.org/@tauri-apps/cli/2.12.4) |

The Rust lock also updates the required Tauri build/codegen/runtime, Wry/Tao and
platform support family. The npm and pnpm locks update the Tauri API/CLI
records and existing shell plugin's API edge. The npm lock also reconciles its
root metadata with the already-declared `@emotion/cache` dependency; no unrelated
package version changes. The API and Rust runtime share major/minor 2.12,
satisfying the CLI's version compatibility check. Tauri and
updater declare Rust 1.90; ZIP declares 1.88, within this repository's pinned
Rust 1.97.1 toolchain. The frontend continues to use Node 24 and pnpm 9.

The updater explicitly selects `rustls-tls` and `zip` with default features
disabled. This preserves the previous resolved capabilities and Windows ZIP
support without adopting the new `system-proxy` default. Release targets,
`createUpdaterArtifacts = "v1Compatible"`, the pinned updater public key,
capability grants, and the existing signed-artifact/startup gates are unchanged.
Regenerated Tauri schemas add only the framework's explicit allow/deny definitions
for app exit and fullscreen-on-monitor; every previous permission, permission set
and default grant is preserved. Adding a schema definition does not grant it to
the application.

Review of the checksum-verified
[updater source at 12819068](https://github.com/tauri-apps/plugins-workspace/tree/128190689dbe59b59d344e01bf07b00862aa3791/plugins/updater)
confirms that downloaded bytes still require verification with the configured
public key before installation. `install()` additionally verifies bytes supplied
directly by its caller. The Windows path still extracts an authenticated archive
into a fresh temporary directory and selects the installer. The selected
[ZIP source at 0d7adbeb](https://github.com/zip-rs/zip2/tree/0d7adbeb0c86c1f367b0cc84237abb106948cb8e)
uses the default enclosed-path extraction checks, including Windows path and
reparse-point handling; no unrestricted extraction option is enabled. This does
not assert universal archive resource bounds. The updater's public-signature
verification does not introduce an application private signing key or software
credential-signing fallback.

The official updater crate SHA-256 is
`d957abbcb3f9f6c76d22a3a0f012f30880640d0bccb5634d2b12a9937e4c872b`;
ZIP 9.4.2 is
`df3845f734baabdd02de353a20580e30ceccd03897def44a4eb8e9654992e294`.
Both downloaded crates matched crates.io metadata before source review.

## Final security and custody results

Using the same cargo-audit version and advisory database throughout gives this
comparison:

| Locked graph | Vulnerability findings | Unmaintained warnings | Yanked warnings |
| --- | ---: | ---: | ---: |
| Original / adapter cleanup | 17 | 14 | 2 |
| Five compatible TLS patches | 5 | 14 | 2 |
| Stable updater/Tauri migration | 1 | 9 | 2 |

The remaining vulnerability is **RUSTSEC-2023-0071 in RSA 0.9.10**. The updater
migration also removes five obsolete `unic-*` dependencies. The nine remaining
unmaintained dependencies are `clear_on_drop`, `derivative`, `proc-macro-error`,
`serde_cbor`, `smallstr`, `unsafe-libyaml`, `zbus_names`, `zvariant` and
`zvariant_derive`. These remain visible for their owners' follow-up; no advisory
ignore is added.

The final cargo-deny 0.20.2 scan completes and exits unsuccessfully with **one
vulnerability, nine unmaintained-dependency errors and 32 license rejection
findings**. Its bans and sources checks pass, with the existing duplicate/source
warnings still reported. The license allowlist and its two existing exceptions
have not changed. These are real policy findings, not a configuration parse
failure or a clean security result.

Actual non-dev Cargo feature graphs were checked for both
`x86_64-unknown-linux-gnu` and `x86_64-pc-windows-msvc`, using the final lock and
`-p marty-verifier -e features,no-dev`. They retain `kms-only` on
`marty-crypto`, `marty-verification` and `marty-oid4vci` at the same Core revision.
Their `default`, `local-key-operations` and `test-fixtures` features are absent.
The resolved graph also excludes the ECDSA signing feature, combined EC signing
features, jsonwebtoken's software crypto backend, Ed448 signing/key-export
features and isomdl's local issuer-signing feature. Updater features are exactly
`rustls-tls,zip`; Windows resolves ZIP 9.4.2 and no ZIP 4. This qualifies the
credential/private-signing capability boundary; ordinary TLS transport and
existing symmetric local-storage protection are not credential signing.

These are resolved graph and source checks for Windows, not execution of a
Windows installer. Windows/macOS packaging, signing, installation and upgrade
runtime checks remain the responsibility of the existing platform release gates.

## Local qualification of the final graph

| Gate | Result |
| --- | --- |
| `cargo test --locked --workspace --all-features` | 237 passed, zero failed, one existing network-policy test ignored. Includes the signed USB, DTC/eMRTD, OID4VP and OpenBadge suites and real owned-storage startup regression. |
| `cargo clippy --locked --offline --workspace --all-targets --all-features -- -D warnings` | Passed. |
| pnpm 9 frozen install, type-check and ESLint | Passed with the updated frontend lock. |
| Frontend unit tests | 42 passed across five files. |
| Existing native-build, packaged-startup, stable-tag, Core-pin and private-fork Python contracts | 44 passed, plus 20 passing subtests. |
| `tauri build --debug --no-bundle --ci -- --locked --offline` | Passed the normal Rust/JavaScript version check, production frontend/obfuscation hook and Linux native application build. No mismatch bypass, installer generation or code signing was used. |
| Built application's `--self-check --report` | Passed all six checks: embedded frontend, safe defaults, application migrations, trust-storage initialization, runtime restore and command registration. |
| Formatting, diff check and the organization's dependency-health validator | Passed. |

The Linux native gates linked the official Microsoft ONNX Runtime 1.28.0 library
required by the unchanged `ort-sys` selection. The upstream CDN was unavailable,
so the matching official release archive was used after SHA-256 verification;
no native dependency was stubbed or feature disabled. These checks qualify the
Linux debug application and its startup contract, not signed release installers
or actual update installation on any platform.

## Retention decision and exit criteria

Retain the qualified transitive family, with a bounded review on **2026-11-15** or
earlier when stable CMS/RSA releases become available. Coordinate the actual
major-family migration through issue 70 and
[Core issue 361](https://github.com/ElevenID/marty-core/issues/361). A candidate must
preserve RSA, DTC/eMRTD, certificate, OpenBadge and OID4VP behavior and pass the
locked workspace tests, protocol vectors, `cargo audit` and `cargo deny` before
release. The current follow-up removes unnecessary dependency ownership; it does
not declare the retained upstream family migrated or the RSA advisory resolved.

Qualification for this change includes the signed USB and DTC/eMRTD public-vector
suites, real process-local storage initialization, and malformed signature,
small-order-key and PEM-as-DER negatives. These use public signed fixtures;
no issuer or trust-package private key is generated, loaded or exported.
