# Native reporting acknowledgement contracts

Remote reporting has two explicit acknowledgement contracts. Existing generic
API and presigned object-store destinations keep the `http-status` policy: an
HTTP success acknowledges their submitted batch. This policy is not proof of
Organization audit ingestion and cannot qualify D09.

The Organization offline endpoint requires `offline-verification-ingest.v1`:

```json
{
  "enabled": true,
  "api_endpoint": "https://deployment.example/v1/organizations/28d552e4-4a94-4fd6-9b60-55e5e9ccb1a3/offline-verification-events",
  "api_acknowledgement": "offline-verification-ingest.v1",
  "api_key": "<scoped audit:write key supplied through private configuration>",
  "batch_endpoint": null,
  "local_only": false
}
```

This is a reporting configuration fragment; retain the other application
defaults. Missing `api_acknowledgement` in legacy configuration defaults to
`http-status`. The canonical Organization offline endpoint also selects durable
acknowledgement by route, so omitting the field cannot downgrade that endpoint.
An explicitly selected durable policy cannot fall back to a presigned PUT.

The durable policy requires a canonical deployed HTTPS URL, exact organization
path, no URL credentials/query/fragment, and an API key. Redirects are disabled.
Only this crate's unit tests permit owned loopback HTTP fixtures. Before the
POST, the reporter reads the same endpoint's capability with the same API key
and checks its contract, organization, producer, scope, batch bound, and storage
claim. Organization and producer identity come from that authenticated API,
never from nullable event device fields.

An API response must be HTTP 200 JSON, no larger than 128 KiB, and contain the
durable v1 acknowledgement. Counts must cover the exact submitted batch; there
must be one unique receipt for every expected event and no extras. Each receipt
must match the authenticated organization and producer, event and verification
UUIDs, full queued event, canonical SHA-256, and bounded receive time. Invalid,
missing, duplicate, mismatched, oversized, redirected, or unreadable evidence
does not acknowledge any event. Errors retain the batch and record only a
redacted failure category in the queue. A later retry can accept exact duplicate
receipts. Events queued after the submitted snapshot remain untouched.

`durable_ack.rs` reuses `VerificationEvent` for canonical serialization and
correlation. It does not copy the receiver's privacy or credential business
rules. The receiver remains responsible for validating and durably committing
the payload before returning a receipt. The frozen synthetic wire fixture and
digest match `marty-ui/contracts/offline-verification-ingest.json`; neither is
live verification evidence.

The recorder selects this policy and checks `get_config` before and after saving
it. A native binary that lacks the serialized policy field is refused before
D09 actions, so an older binary cannot silently ignore the requirement. D09
still performs independent authenticated receipt readback and exact replay after
the real native reconnect action.

## Focused checks

```sh
cargo test -j2 --locked -p marty-reporting --lib
cargo test -j2 --locked -p marty-reporting --lib --no-default-features
```

These tests exercise real isolated secure-storage queues and owned loopback
HTTP transports. They cover invalid success responses, authority binding,
response bounds, retention after a lost response, duplicate acknowledgement,
and a new event arriving during upload. Generic API/presigned status behavior
and feature-disabled failure remain covered by their existing tests. No Tauri
GUI, production service, deployed receiver, or released binary qualification is
implied by these crate tests.
