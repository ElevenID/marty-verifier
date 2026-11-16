# Sync consumers

Native consumers retain the default `native-sync`, `aamva` and `icao` features.
They include trust-anchor acquisition, encrypted storage and USB import. The
fixture feature also selects this native surface.

Consumers that need only authenticated policy/profile HTTP synchronization and
the `PolicyStorage` interface can disable defaults:

```toml
marty-sync = { version = "0.1.4", default-features = false }
```

This surface does not initialize a native database, keychain, LDAP client or
Tokio runtime. Its existing HTTP API and bearer authentication are unchanged.
The caller must supply an appropriate async executor and browser deployments
must use a trusted HTTPS owner endpoint with the required CORS policy.

`native-sync` is rejected on `wasm32`. Disabling it does not emulate native
storage, USB import or trust-list acquisition. It does not qualify the wallet's
other protocol transports, remote signing, full browser bridge or application
startup; those have separate security and acceptance boundaries.
