# Release integrity and platform signing

Marty Verifier releases do not use Apple Developer certificates or Apple
notarization. The macOS artifacts are intentionally unsigned. The release
workflow must not reference `APPLE_*` secrets, import a macOS certificate, or
claim that a release is Apple-notarized.

## Release trust model

Every stable and release-candidate build is produced on a standard
GitHub-hosted runner. Releases include:

- `SHA256SUMS` covering the downloadable installers and archives;
- a CycloneDX SBOM;
- GitHub build-provenance attestations created through OIDC; and
- Tauri updater signatures for automatic updates.

Tauri updater signatures are not Apple code signatures. The updater private
key is stored in the protected release environment as
`TAURI_SIGNING_PRIVATE_KEY`; its public key is embedded in
`src-tauri/tauri.conf.json`. This key prevents an altered update from being
accepted by the application.

Verify an artifact with the GitHub CLI and its checksum before installing it:

```bash
sha256sum --check SHA256SUMS
gh attestation verify <artifact> --repo ElevenID/marty-verifier
```

## macOS limitation

Because the application is unsigned and not notarized, Gatekeeper will warn or
block it on first launch. Users must review the release provenance and checksum,
then explicitly approve the application in macOS Privacy & Security settings.
Do not suggest disabling Gatekeeper globally and do not publish instructions
that remove quarantine recursively.

The macOS jobs remain useful: they compile and test both Intel and Apple Silicon
targets and publish clearly disclosed unsigned artifacts. Obtaining Apple
release credentials is not a release prerequisite.

## Windows and Linux

Windows and Linux releases use the same checksum, SBOM, updater-signature, and
GitHub-attestation controls. No commercial Windows certificate is required by
the workflow. Windows SmartScreen may therefore also display a reputation
warning.

## Required release secrets

Only the updater key is secret-backed:

- `TAURI_SIGNING_PRIVATE_KEY`
- `TAURI_SIGNING_PRIVATE_KEY_PASSWORD` (only if the key is encrypted)

Publishing uses the job's short-lived `GITHUB_TOKEN`; no repository PAT or
Apple credential is required.
