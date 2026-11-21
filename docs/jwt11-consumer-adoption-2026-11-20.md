# Accepted Core JWT 11 consumer candidate — 2026-11-20

This bounded update carries the accepted Core JWT 11 continuation into Verifier
and its portable `marty-sync` policy/profile client. It follows the
[previous accepted consumer update](crypto-consumer-adoption-2026-11-20.md).

| Source | Previous accepted consumer | Selected accepted owner revision |
| --- | --- | --- |
| Marty Core | `64601c9513850e3eb60b00f6aa893cae8d9e4b0d` | `11152cfb83ec47174a21ad76fd4c9e811c93602f` ([Core #446](https://github.com/ElevenID/marty-core/pull/446)) |
| SD-JWT fork selected by Core | `ba5a9a154ae530ddcfcc5b52adf3da71e91b1929` | `9fc75ab0befe6b7f80987acd8b740baead40ee76` ([fork #43](https://github.com/ElevenID/sd-jwt-rust/pull/43)) |
| Shared JWT provider/types | `jsonwebtoken` 10.4.0 | `jsonwebtoken` 11.1.0 |

All six direct Core declarations and all eight locked Core package records use
the same accepted revision. Core and the SD-JWT fork share one locked JWT
package. The workspace's currently unused direct JWT declaration is aligned
with that package and disables default features; it does not install a second
provider. Existing Core feature selections and application version `0.1.4`
remain unchanged.

## Consumer boundaries

The owner change supplies the verification-only JWT provider and rejects
unknown/incomplete typed JWK fallbacks and raw private members. Verifier has no
direct `jsonwebtoken` public-type callers to rewrite. Its OID4VP entrypoint
continues to use Core's `VerificationEngine`, while the portable client returns
Core's `PresentationPolicy` directly. No serialization bridge or replacement
policy type is introduced.

The selected fork role remains `crypto-provider` plus `verifier`. Its optional
issuer-planning edges to rand 0.10/getrandom 0.4 and holder/completion edge to
curve25519-dalek 5 are not selected. The existing getrandom 0.2 WASM carrier and
public verification curve dependencies remain.
The native AWS-LC verification adapter enables its existing `ring-io` capability,
which adds `untrusted` 0.7.1 alongside the existing 0.9.0 package. This does not
enable a global JWT signing backend or local credential signing.

The complete lock candidate contains 906 package records, including 851
registry packages. It preserves 849 previous registry identities, versions and
checksums, replaces only JWT 10.4.0 with 11.1.0, and adds the required
`untrusted` 0.7.1 package. Normalizing dependency references shows only one new
edge among retained registry packages: `aws-lc-rs` 1.18.0 to `untrusted` 0.7.1.
The existing `untrusted` 0.9.0 references are disambiguated without changing
their targets. Tauri, UUID, the certificate family, and the existing SSI,
linked-data, isomdl and GTK compatibility revisions remain unchanged.

The certificate/RSA and GTK inventory decisions retain their recorded review
dates and scope. This dependency update does not claim advisory remediation,
enable mdoc status transport, expand SD-JWT digest admission, or qualify an
installed wallet.

## Local qualification and limits

The exact-pin/application-version validator and the four existing dependency,
stable-tag, native-build and private-fork Python suites pass all 35 tests.
Complete repository `cargo metadata --locked` and its `--all-features` variant
resolve the candidate without rewriting its lockfile, after restoring the exact
unchanged GTK fork and the existing registry inputs. The all-feature graph has
906 packages and all eight Core packages at the selected revision. The default
graph also resolves offline. These checks were recorded on 21 November UTC
(20 November in the user's development timezone).

The actual repository's portable `marty-sync` qualification passes:

| Command scope | Result |
| --- | --- |
| `cargo test --locked --offline -p marty-sync --no-default-features --lib` | 6 passed; the existing live-endpoint example remains ignored |
| `cargo check --locked --offline -p marty-sync --no-default-features --target wasm32-unknown-unknown --lib` | Passed |
| `cargo clippy --locked --offline -p marty-sync --no-default-features --lib --tests -- -D warnings` | Passed |

An external portable consumer probe uses the actual candidate `marty-sync`
source path, its inherited workspace dependencies, the exact selected Core
declarations, and the unchanged SSI/isomdl patches. Its native and WASM-filtered
metadata resolve offline. The 575-package probe confirms the candidate lock
records and dependency edges for Core OID4VCI, the SD-JWT fork, JWT 11, AWS-LC
and both `untrusted` versions. Core and the fork select the same JWT identity;
JWT enables only `use_pem`, with no default, `rust_crypto` or `aws_lc_rs` backend
feature. The probe also compiles the policy-return boundary directly against
the caller's selected Core type.

The native probe's one regression test passes public ES384 and Ed25519
signature vectors, rejects tampering and algorithm confusion, rejects
malformed/private JWK inputs, and confirms that the shared provider rejects
local signing. Its WASM library check and all-target Clippy with warnings denied
also pass. The WASM result is compilation, not browser runtime execution.
This probe is scoped consumer qualification, not complete Verifier GUI
qualification.

## Persisted consumer guard

Cargo unifies features in the final consumer graph, so upstream checks alone
cannot prevent a consumer dependency from enabling a second or built-in JWT
provider. `scripts/check_crypto_provider_boundary.py` checks fresh resolved
metadata for one JWT 11 identity shared by Core OID4VCI and the SD-JWT fork,
rejects JWT's `default`, `rust_crypto` and `aws_lc_rs` feature routes, and retains
the existing `kms-only` roles on Core crypto, verification and OID4VCI. Feature
lists must contain strings; malformed metadata cannot pass through string or
dictionary membership checks.

Nine mutation-test methods pass both an explicitly documented projection of
the real graph and the complete captured 906-package metadata. They cover
duplicate identities, other JWT major versions, divergent/missing/duplicate
JWT edges, forbidden provider features, malformed feature lists, missing nodes
and removed KMS-only roles. The existing dependency-automation job runs the
fixture tests. Each trusted Rust job resolves fresh locked all-feature metadata
after its existing private-fork fetch, then runs the guard and the mutation
tests on that actual graph before the existing tests or Clippy. Credential
scope, fetch policy and protected gates remain unchanged.

## Remaining qualification

The local machine lacks WebKitGTK/GTK/AppIndicator development libraries, so
full desktop builds and tests remain hosted qualification. No source URL,
committed patch, dependency version, private-fork guard or CI gate is relaxed
to avoid those requirements. The GTK restoration preserves its actual
`e60f1885a5168cb823914130e6bdd0e89ec1787c` commit and
`f9f72a50d6c3d27d33e34445c24330dd141d2b10` tree, including all 654 unique blobs;
no synthetic source identity or completion marker is used.

Before acceptance, the existing trusted hosted CI must confirm the complete
candidate graph and pass workspace nextest, documentation tests, all-target and
all-feature Clippy, signed-USB JSON feature compatibility, portable native/WASM
checks, and the protected multi-platform merge-group gates. Until then this
consumer candidate remains draft. Owner-level Core KMS qualification retains
its own revision and scope; public-vector consumer tests do not establish
installed-wallet or deployed-service signing qualification.

## Coordinated wallet adoption

Authenticator's currently qualified package graph still selects Core #445 and
Verifier #199. Keep those pins together until this Verifier candidate is
accepted. A later wallet batch must update its direct Core pins and its
`marty-sync` dependency to this PR's actual accepted commit together, preserving
`default-features = false` and its existing
`synced_policies_use_the_bridge_core_type_directly` regression. That batch needs
fresh package/device qualification; it cannot inherit acceptance from this
source update.
