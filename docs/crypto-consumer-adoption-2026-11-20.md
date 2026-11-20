# Accepted crypto consumer update — 2026-11-20

This update carries accepted Core changes into Verifier and the portable
`marty-sync` policy/profile client consumed by Authenticator. All six direct
Core dependencies and all eight Core package records in the lockfile select
one revision.

| Source | Previous checkpoint | Selected accepted checkpoint |
| --- | --- | --- |
| Marty Core | `8b553b472890cebbf4972cd0fdcb440141085d35` | `64601c9513850e3eb60b00f6aa893cae8d9e4b0d` ([Core #445](https://github.com/ElevenID/marty-core/pull/445)) |
| SD-JWT fork selected by Core | `fbe1e1b2c4bf0d62b0fdf0f47f265ffdaaae1ff2` | `ba5a9a154ae530ddcfcc5b52adf3da71e91b1929` ([fork #47](https://github.com/ElevenID/sd-jwt-rust/pull/47)) |

The Core delta includes provider-neutral evidence-policy enforcement in #444,
authenticated external-status verification in #443, and explicit SD-JWT
disclosure-digest selection/admission in #445. The fork also retains the
accepted strict-JSON consumer compatibility work. Existing Verifier feature
selections, application versions, KMS custody boundaries and other fork pins
remain unchanged. The new optional mdoc status-verification feature is not
enabled by this update. Existing wallet/product entrypoints retain SHA-256
admission; the wider digest capabilities require explicit Core selection.

## Dependency graph

The lock update preserves all 850 registry package identities, versions and
checksums and retains 905 package records. In addition to the two Git source
revisions, it carries Core's maintained-clock dependency edges: `marty-crypto`
and `marty-x509-verification` use `time` in place of `chrono`, `marty-oid4vci`
adds `time`, and the browser-enabled `time` path adds `js-sys`.

Source comparison found no Verifier calls to the changed fallible
`LivenessChallengeBuilder::build` or explicit chain-validation clock APIs.
The unchanged public signature and trust-policy callers still require native
and portable-target qualification. Registry inventory equality and a parsed
lockfile do not by themselves prove Cargo resolution or runtime compatibility.

## Coordinated Authenticator adoption

Authenticator's policy-sync bridge returns `marty-sync`'s Core
`PresentationPolicy` directly as its own Core type. Its existing
`synced_policies_use_the_bridge_core_type_directly` test enforces that boundary.
After this prerequisite is accepted, update Authenticator's direct Core pins
and its `marty-sync` pin together, using this PR's actual accepted Verifier
commit. Preserve `default-features = false` on the portable client. Do not use
serialization or duplicated policy types to conceal two Core source revisions.

## Qualification and scope

Before acceptance, validate exact manifest/lock identities with the existing
dependency contract, then complete locked native workspace tests,
documentation tests, all-target/all-feature Clippy, signed-USB JSON feature
compatibility and the portable `marty-sync` native/WASM checks. The existing
private-fork fetch boundary and protected multi-platform merge-group gates
remain required. Record actual outcomes on the PR; local source checks alone
are not native qualification.

The local exact-pin validator passed with application version `0.1.4`
unchanged. The existing Python dependency-update, stable-tag, native-build
and private-fork suites passed all 35 tests. A Rust 1.95.0
`cargo metadata --locked --format-version 1` attempt stopped before resolution:
the normal Git fetch of the unchanged private SSI revision
`8b546ef5dbcd6e806ec1c26a0c05296515798429` had no usable reader credentials.
This local result does not validate the proposed Cargo lock or any native
runtime. The existing authenticated internal-branch CI must qualify them.

This update does not change the certificate-family migration decision in
[the November 16 dependency review](dependency-review-2026-11-16.md), claim
advisory remediation, enable a new external-status transport, or qualify an
installed wallet. The coordinated JWT/RNG/curve migration remains separate.
