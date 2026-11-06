# Native build access

Native builds use the complete `ElevenID/isomdl-elevenid`,
`ElevenID/ssi-elevenid`, and `ElevenID/sd-jwt-rust` repositories at their existing
pinned commits. Making those forks private does not change their upstream
history, licenses, notices, package APIs, or the public consumer's source license.

## Authenticated existing CI

`PRIVATE_FORKS_ENABLED` is a repository Actions variable. When it is unset or
`false`, the existing anonymous build and cache behavior remains available.
When it is exactly `true`, native jobs fetch their dependency graphs using the
repository's `PRIVATE_FORKS_READ_TOKEN` Actions secret, then run their existing
checks without that token. The reader needs only Contents read access to the
three forks; the credential helper answers only their exact GitHub HTTPS paths.

The reader is restricted to trusted internal work. Same-repository contributors
must already be authorized to read the forks. External fork PRs and Dependabot
PRs receive no reader and cannot pass required native checks through a skipped
job. Maintainers must review and move such changes to an authorized internal
branch before native validation. Merge-queue admission remains subject to the
existing required checks and review rules. Do not use `pull_request_target` to
run untrusted source with this reader.

Rust workspace tests, documentation tests, clippy, desktop RC/stable builds,
packaged startup checks, release provenance, and the existing CI Gate remain in
their original workflows. Dependency-update automation resolves its new exact
Core pins with the reader, then validates and tests without it. Frontend and
source-only checks continue normally. The public `marty-sync` source release
and optional registry publication retain their existing scope and gates.

Authentication applies to future release tags that include these workflows.
Rerunning an older tag uses that tag's older workflow, without the new helper.
The existing release provenance gate also rejects dispatching today's main
workflow against an older tag. Previously published artifacts remain unchanged.
To rebuild an older version, use an owner-authenticated local build or create
a new release version and tag with the current pipeline; never move old tags.

## Caches, outputs, and local development

Private-mode jobs do not restore or save Cargo Git sources or compiler caches.
The reader is available only to dependency resolution, never to compilation,
tests, package signing, or publication. Existing compiled products and metadata
artifacts remain public; ordinary compiler diagnostics and test logs also remain
public. This boundary prevents full private fork source from being placed in a
public cache or source artifact. It is not a guarantee that public diagnostics
will never show a source excerpt.

Keep the reader out of Git configuration files, command arguments, job-level
environment variables, artifacts, and logs. Enable the variable only after the
secret has read access to the private fork identities and authenticated native
checks pass. Removing the variable does not restore anonymous access to a
private fork.

Authorized local builds use the same pinned Git URLs with normal private-repo
read credentials. Continue merging upstream changes in the private forks, and
preserve required license notices when distributing Marty binaries or other
artifacts. Previously published source and its existing licenses are unaffected.
