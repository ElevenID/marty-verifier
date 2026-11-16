# Certificate dependency review — 2026-11-16

This review supersedes the release/advisory observations in the November 8
review; it does not qualify the coordinated migration in
[Core issue 361](https://github.com/ElevenID/marty-core/issues/361) or
[Verifier issue 70](https://github.com/ElevenID/marty-verifier/issues/70).

Primary crates.io release and normal-dependency metadata and the RustSec/OSV
record were read on November 16:

| Package | Latest stable | Newest published | Source |
| --- | --- | --- | --- |
| cms | 0.2.3 | 0.3.0-rc.2 | [metadata](https://crates.io/api/v1/crates/cms) |
| rsa | 0.10.0 | 0.10.0 | [metadata](https://crates.io/api/v1/crates/rsa) |
| x509-cert | 0.3.0 | 0.3.0 | [metadata](https://crates.io/api/v1/crates/x509-cert) |
| der | 0.8.3 | 0.8.3 | [metadata](https://crates.io/api/v1/crates/der) |
| ed25519-dalek | 3.0.0 | 3.0.0 | [metadata](https://crates.io/api/v1/crates/ed25519-dalek) |
| rand | 0.10.4 | 0.10.4 | [metadata](https://crates.io/api/v1/crates/rand) |
| aes-gcm | 0.11.1 | 0.11.1 | [metadata](https://crates.io/api/v1/crates/aes-gcm) |

**A fixed stable RSA release exists.** Both
[RustSec](https://rustsec.org/advisories/RUSTSEC-2023-0071.html) and
[OSV](https://api.osv.dev/v1/vulns/RUSTSEC-2023-0071) identify 0.10.0 as patched.
The retained 0.9.10 remains affected. The old claim that no fixed version exists
is superseded; the advisory remains explicit in the health record.

[Stable CMS 0.2.3](https://crates.io/api/v1/crates/cms/0.2.3/dependencies)
still requires DER/SPKI 0.7 and x509-cert 0.2; its optional RSA/signature edges
are RSA 0.9 and signature 2.
[CMS 0.3.0-rc.2](https://crates.io/api/v1/crates/cms/0.3.0-rc.2/dependencies)
uses DER/SPKI 0.8, x509-cert 0.3 and optional RSA 0.10/signature 3, but remains a
prerelease. [Stable RSA 0.10.0](https://crates.io/api/v1/crates/rsa/0.10.0/dependencies)
uses crypto-bigint 0.7, rand_core 0.10, signature 3 and optional PKCS8/SPKI 0.11/0.8.
These are distinct compatibility edges, not evidence that every RSA consumer
must wait for CMS. Any independent RSA migration still requires its owner's
API and public-signature/certificate qualification.

This prerequisite preserves the canonical Core-owned graph and moves all six
Core pins together. It adds no direct certificate/signature backend and keeps
the existing `kms-only`, verification roles and disabled defaults. Core's
published dependency-health decision already recognizes stable RSA 0.10.0 and
tracks coordinated JOSE, passport, mdoc, DIDComm, Python and wheel qualification
in issue 361. Preserve its public-verification-only RSA boundary and managed
private-key custody; do not introduce local RSA signing or remove supported
verification profiles to simplify resolution.

Decision: retain the current qualified Core-owned family for this dependency
checkpoint, keep RUSTSEC-2023-0071 visible and recheck by 2026-11-23, or earlier
when stable CMS or a qualified owner migration is available. The migration
owner remains Core issue 361, with consumer tracking in Verifier issue 70. This
review-date refresh is not migration qualification, advisory remediation or a
security-audit pass. Existing audit/deny configuration and workflow gates are
unchanged; no advisory ignore or CI waiver is introduced.

Actual local sync/storage tests and Clippy on the provisional Core graph are
recorded in PR 196. Those tests do not qualify the unperformed RustCrypto family
migration, an installed wallet or an existing database.
