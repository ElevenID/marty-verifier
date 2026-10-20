# Verifier vector ownership

These public vectors belong to `tests/oid4vp_conformance.rs`, which exercises
the offline Tauri adapter's parsing and verification-result construction.
Keep the fixtures local so package tests remain hermetic. Core owns engine
verification and its own presentation definition; Authenticator owns wallet
protocol vectors. Update the relevant adapter case with each fixture change.

The trimmed VP token and parsed presentation definition/submission currently
match Core's vectors; formatting differs. Do not overwrite them from the retired Integration Python
generator. Future signed vectors should use the maintained Rust managed-signing
test facilities and retain public data only. These tests do not qualify Tauri
runtime state, licensing, storage or official OIDF conformance.
