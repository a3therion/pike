# OIDC browser state across relays

OIDC can optionally keep pending sign-ins and opaque browser sessions in Redis. Relays with the same namespace and the same tunnel/policy revision can complete each other's callbacks, accept the same session cookie and observe logout. The default remains bounded relay memory. This does not implement public ingress routing between relays or change the `single-node` deployment-topology restriction.

Configure each participating relay:

```toml
[visitor_session_store]
redis_url = "rediss://pike:REPLACE_WITH_SECRET@redis.example.com:6379/0"
namespace = "production"
```

The namespace is required and accepts 1–64 ASCII letters, digits, underscores or hyphens. Separate deployments must use different namespaces. `rediss://` verifies the server certificate using trusted roots; insecure TLS fragments are rejected. For a protected loopback/private connection, `redis://` is also supported. Restrict Redis access to trusted relay operators and protect the TOML credentials. This store is independent of the optional telemetry `redis_url` and its in-memory fallback: **authentication never falls back to memory**.

## Admission and revocation

- Each authenticated request reads Redis. No successful local cache entry can authorize a request during a store outage. Operations, including waiting for a connection from the eight-connection pool, have a two-second deadline; failure returns 503.
- A relay polls its active sessions once per second in one bounded batch. Missing, expired or revoked records, or an unavailable store, cancel held HTTP bodies and WebSocket connections. The polling plus operation deadline gives a nominal three-second detection bound, subject to scheduler load; the local fixture checks actual closure within 4.5 seconds. This is not a production latency SLA.
- Logout closes matching local paths immediately and atomically removes the shared session. It returns success only after Redis acknowledges deletion. A failed logout returns 503 and must be retried; it does not claim other relays observed a revocation. Closed paths are never resumed after recovery. Unexpired sessions that were not revoked may authorize new requests after recovery.
- Sessions are bound to the tunnel identity, policy revision and fingerprint of the complete policy. Revision changes close active paths when each relay refreshes its control-plane lease (normally 25 seconds). Earlier sessions remain unusable with the new policy even if their Redis rows have not yet expired.
- Callback state is consumed atomically only for the matching browser cookie and policy scope. Wrong-browser attempts cannot burn a valid flow; racing valid callbacks produce at most one token exchange. The receiving relay performs certificate-verified discovery and checks that its authorization, token and JWKS endpoints match the discovery captured at login. A changed endpoint set requires a new login.

## Bounds and data

One namespace holds at most 1,024 pending flows, including at most 64 per policy scope, and 8,192 sessions. Capacity and expiry checks are atomic in Redis. Each relay also bounds locally active session references to 8,192 and concurrent sign-in/exchange handlers to 32. Pending flows expire within five minutes; session lifetime remains capped by the verified ID token and the configured maximum of 86,400 seconds. Redis expiry uses Redis time; synchronize the clocks of the identity provider, Redis and relays.

Browser state and session capabilities are stored only as SHA-256 lookup hashes. Pending records contain the browser hash, PKCE verifier, nonce, validated return URL and provider endpoint fingerprint; treat the store as sensitive authentication data. Provider access/ID tokens and OIDC client secrets are never stored. Session records contain only the policy scope and expiry. Expired entries are pruned on writes and lookup rejects expired records immediately. Namespace keys expire after inactivity; the store uses five keys under `pike:oidc:v1:{namespace}:…`.

Relay restart preserves shared state. Redis data loss forces fresh sign-in and cannot reconstruct sessions from a relay cache. Redis persistence, failover consistency, capacity and eviction policy remain operator responsibilities. Do not restore an old authentication snapshot into an active namespace: change the namespace after a rollback so previously revoked sessions cannot reappear. Redis Cluster routing is not implemented by this client.

## Executed local verification

`pike-cloud/workers/scripts/shared-oidc-e2e.mjs` starts a disposable password-protected Redis, real Worker/D1, two production relays, one QUIC connector, one forced WebSocket connector, an independent HTTPS identity provider and Chrome. Its HTTPS frontend deliberately selects each relay; this selection is fixture infrastructure, not a Pike public-ingress feature.

The fixture exercises browser login/callback on different relays; a concurrent callback race; actual held HTTP and WebSocket logout/expiry/outage cancellation; relay process restart with a pending PKCE flow and active cookie; a changed policy revision; and empty Redis restart. It runs the ignored `shared_redis_contract` against its disposable Redis to cover global/per-policy capacity, scope/browser isolation and atomic consumption. The default memory-backed OIDC fixture remains a separate two-transport regression.

Run with the bundled Node runtime or Node 22+, cached `redis:7-alpine`, built relay/CLI binaries, and Chrome:

```sh
cd pike-cloud/workers
PLAYWRIGHT_CHANNEL=chrome npm run test:shared-oidc
```

This is local proof. Public ingress/failover, production Redis HA/load/soak testing, external identity-provider compatibility and deployed behavior remain separate work.
