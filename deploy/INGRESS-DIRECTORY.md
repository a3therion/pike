# Live route directory

The management listener now exposes `GET /api/ingress/routes?nonce=<32 hexadecimal characters>` with the existing internal bearer token. It advertises routes admitted by the relay's actual connector sessions. Dashboard and connector credentials cannot read it. Keep the management listener private; it remains loopback by default. A future remote consumer must use an authenticated, verified TLS path rather than sending the token over an untrusted plaintext network.

This is the discovery part of public ingress. Forwarding across relays is implemented separately; see `PUBLIC-INGRESS.md`. Frontends fetch this same snapshot over the authenticated relay hop rather than this management endpoint, and the `cross-relay` topology is accepted only together with an `[ingress]` table. Without that table the `single-node` behaviour is unchanged.

## Response contract

The response includes protocol version 1, the caller's nonce, `max_age_ms: 2000` and a sorted route list. Responses use `Cache-Control: no-store`. A consumer must generate a new nonce for every poll, require an exact echo and supported version, bound the response to 2 MiB, and discard snapshots at most two seconds after the request began using its own monotonic clock. A request failure, timeout, nonce mismatch or malformed response must never extend an earlier snapshot's lifetime. The age is a discovery-cache limit, not a stronger control-plane revocation deadline.

Each route contains:

- `target`: `http`, `https` or `tls` with an exact hostname, or `tcp`/`udp` with the actual public port. HTTPS is advertised only when the relay has its native HTTPS listener configured. Custom hostnames require their current local domain grant.
- `authority`: an opaque SHA-256 digest of the target, owner, canonical profile identity, desired settings, full visitor policy and policy/domain revisions. Independent relays agree only when these inputs agree. Standalone identities use the operator-authorized primary hostname instead of a process-specific tunnel UUID.
- `members`: the number of locally admitted connectors with active authority and an open outbound channel, capped at eight.
- `origin_health`: the best current connector health (`healthy`, `unknown` or `unhealthy`). Missing, stale and unprobed observations remain unknown. TCP, TLS and UDP have no HTTP-origin observations and remain unknown.

The directory exposes no API keys, bearer tokens, private keys, visitor credentials, raw policy, origin addresses or caller-selected backend addresses. An authority digest is configuration identity; it is not an access token. Matching advertisements do not prove that an external socket is reachable, a TLS certificate is ready or a visitor is authorized. A forwarding consumer must independently connect and revalidate live route/visitor authority before application bytes, preserve the real visitor address, retain TLS and protocol semantics, and never replay traffic after bytes have reached a backend.

## Lifetime and bounds

Registration happens after normal endpoint, quota, policy and hostname admission and after the transport's forwarding route exists. Each session owns a separate registration. Connector cleanup removes it before tearing down forwarding. A closed transport channel or closed visitor gate hides it immediately from the next snapshot. Expired aliases disappear without withdrawing the primary hostname. A disconnected registration cannot remove a replacement because each has its own identifier.

The directory allows 16,384 connector registrations and 4,096 distinct advertised targets. Registration at capacity fails normal tunnel admission with cleanup; snapshots that exceed the target/serialization bound return 503 instead of a partial list. Conflicting authority for the same local target also returns 503. The directory does not refresh a Worker ownership lease or a DNS grant, retain authority after session cleanup, or restore advertisements from disk after relay restart.

## Verification

Rust tests cover independent membership and revocation, matching and conflicting identities across separate directories, expired aliases, all five target forms, resource guards, management authorization, nonce validation and no-store responses. The real connector fixtures include additional directory assertions alongside their actual Worker/D1, relay and CLI traffic:

```sh
cd pike
cargo test --offline -p pike-server ingress_directory -- --nocapture
cd ../pike-cloud/workers
PLAYWRIGHT_CHANNEL=chrome node scripts/connector-members-e2e.mjs
node scripts/same-relay-connectors-e2e.mjs
node scripts/shared-stream-connectors-e2e.mjs
node scripts/shared-udp-connectors-e2e.mjs
```

`Directory::verify` is the owner-side counterpart used by the hop: it requires the exact target and expected authority against current registrations and returns the endpoint's gate for dispatch binding. TCP/UDP routes are advertised only for ports reserved by the cloud profile; a standalone relay's ports are never advertised because a peer snapshot cannot establish global port ownership. The cross-relay fixture is `pike-cloud/workers/scripts/public-ingress-e2e.mjs`; private IP/subnet routing and deployed/external-network/soak proof remain separate work.
