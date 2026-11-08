# Dependency boundary review — 2026-11-08

This review addresses [issue 70](https://github.com/ElevenID/marty-verifier/issues/70)
on top of Verifier `94c24fdf59fd03dcb008ab2053cf74d492165210`. The Core revision
remains `a11313be1fdb6035c11c87b42b4120e395d63aba`. The adapter/keyring cleanup in
`cd88a0bf4ab2bbea5bcf0569b09e7c707c0a3109` preserves library versions; the security
patches below update selected transitive libraries. Fork revisions, credential
profiles and custody configuration remain unchanged.

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
