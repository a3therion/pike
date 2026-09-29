# Pike

Pike is the open-source core of the Pike tunnel stack.

This repo is standalone and publishable on its own. It contains:
- `pike`: the CLI tunnel client
- `pike-server`: the relay server
- `pike-core`: shared protocol, transport, and type definitions

It does not include the hosted cloud control plane, dashboard UI, admin tooling, billing, email flows, or the marketing site. Those live in the private `pike-cloud` repo.

## Install

```bash
curl -fsSL https://pike.life/install | sh
```

The current public installer rollout supports Linux x86_64, Linux ARM64, and macOS x86_64/arm64. Windows x86_64 binaries are available from GitHub Releases. Termux artifacts are deferred, and the installer exits explicitly on unsupported systems instead of attempting a missing download.

## Quick Start

Building from source requires Rust 1.88 or later.

```bash
cargo build --workspace
cargo test --workspace
python3 scripts/local_tunnel_smoke.py
```

The smoke test boots local upstream services, a `pike-server` relay, and a `pike` client. It checks HTTP, upstream WebSockets, interactive TCP, half-closes, authentication, and reconnects over both QUIC and forced WebSocket fallback. Use `--transport quic` or `--transport websocket` to run one transport.

## Self-Hosted Relay

- Start from `deploy/server-vps.toml`.
- For a standalone relay, replace `local_api_keys` with your own key list.
- If you run your own remote control plane, set `control_plane_url`, `workers_api_url`, and `server_token`.
- Current public Linux release bundles support x86_64 and ARM64.
- The release workflow also publishes `ghcr.io/a3therion/pike-server:<tag>`.

## Client Configuration

Use `deploy/client-config.toml.template` as the starting point for `~/.pike/config.toml`.

For HTTP tunnels:
- `pike http 3000` now gets a unique URL by default on every run.
- Use `pike http 3000 --subdomain my-app` only when you want a fixed URL.
- The inspector prefers the configured port, but auto-selects the next free loopback port when that port is already in use.
- Shared `tunnel.subdomain_prefix` config is ignored for HTTP runtime routing and only kept for backward compatibility.

For TCP tunnels, `pike tcp 5432` allocates a relay port. Use `--remote-port 15432` to request an exact port; unavailable ports fail registration. Relay TCP ports must be reachable through your firewall (the supported allocation range is 10000–65000).

WebSocket fallback is enabled by `relay.ws_fallback`. After `relay.connect_timeout_ms` (default 5000) without a QUIC connection, the CLI connects to `wss://<relay host>/ws/tunnel`. Set `relay.ws_url` for a different HTTPS endpoint; plain `ws://` is accepted only for loopback development. The reverse proxy must forward WebSocket upgrades on `/ws/tunnel` to the relay HTTP listener. This transport requires compatible client and relay releases. Forwarding an application's WebSocket through a tunnel is supported on both transports.

## HTTP upload size and streaming

HTTP request bodies default to **200 MB (200,000,000 bytes)**. This is the complete request body, so multipart boundaries and form fields count toward the limit. Configure `max_request_body_bytes = 200000000` at the top level of the relay's TOML file. Exactly that many bytes are accepted; one byte more returns HTTP 413, including requests without Content-Length.

Uploads and downloads use bounded 32 KiB data frames and a 64 KiB per-stream flow-control window through QUIC and WebSocket fallback. Small frames also consume a minimum credit to bound queue metadata. Bytes reach the origin while the upload is still in progress. Closing a request cancels its origin exchange. Body I/O has a 30-second idle timeout; response headers have a 10-minute maximum to allow large active uploads.

This stream format requires **protocol 8 on both the relay and CLI**. Upgrade them together; older or unversioned clients are rejected at login. TCP, dedicated TLS and application WebSocket streams use explicit credit framing to backpressure slow peers; matching older builds cannot decode it. Both transports expire missing heartbeat acknowledgements after 20 seconds. The QUIC ALPN remains `pike/1`, with the application protocol version checked during login. Standalone installations can keep an isolated old relay for old clients during migration. Hosted quota enforcement requires draining older relays before the coordinated Worker/relay rollout described below.

A reverse proxy, CDN or origin can enforce a lower limit. Configure its request size, buffering and timeout settings as well. The local upload tests do not establish the configuration of a deployed service. Run `python3 scripts/local_tunnel_smoke.py --transport both` after building to verify real 200 MB bodies, SHA-256 integrity, exact overflow rejection, cancellation and resident-memory growth.

## Protect visitor access

Visitor authentication is separate from connector API keys. HTTP endpoints support
Basic passwords or signed JWT bearer tokens, including WebSocket upgrades and replay.
IP/CIDR policies also protect TCP, UDP and TLS. JWT policies pin RS256 or ES256, issuer,
audience, scopes and maximum lifetime; active requests close when their token expires.
Hosted users configure these in **Settings → Visitor access**. Standalone operators use
server TOML. Public authentication requires a trusted, correctly configured HTTPS
frontend. See [visitor policies, signing-key retrieval and rollout](deploy/VISITOR-POLICIES.md).
OpenID Connect browser sign-in uses PKCE, encrypted hosted client secrets and bounded HTTPS-only browser sessions. Logout, expiry and policy changes cancel active traffic. Sessions survive connector reconnect to one relay; relay restart requires sign-in again. Visitor mTLS verifies client certificates on native HTTPS and terminated raw TLS, including fingerprint restrictions and active-stream expiry. See [the operator contract](deploy/VISITOR-POLICIES.md#openid-connect-browser-sign-in).

## Edit and replay HTTP requests

The dashboard request detail and local inspector provide an **Edit and replay** action.
Use the complete **Inspector access** link printed by the CLI; captures and replay require
its per-run token. The `pike replay <saved-name-or-uuid> --file request.json` command sends
an explicit draft through the active owned tunnel. Replays use normal quotas, do not
follow redirects and never reconstruct missing or redacted credentials. Request and
response bodies are bounded to 64 KiB for this operation; ordinary uploads remain 200 MB.
See [replay authentication, draft format and limits](deploy/REPLAY.md).

## HTTP/2, gRPC and origin connections

The HTTP tunnel forwards native HTTP/2 request/response frames and trailers. Use HTTP/2 to the origin for gRPC unary, client-streaming, server-streaming and bidirectional RPCs:

```sh
# Cleartext HTTP/2 (h2c prior knowledge)
pike http 50051 --upstream-protocol http2

# Verified HTTPS; ALPN selects HTTP/2 or HTTP/1.1 automatically
pike http --upstream https://localhost:8443

# Add a private CA; an explicit certificate name remains verified
pike http --upstream https://127.0.0.1:8443 --origin-ca /absolute/path/ca.pem --origin-server-name service.internal

# Unix domain socket (HTTP/1.1 by default; --upstream-protocol http2 also selects h2c)
pike http --unix-socket /absolute/path/service.sock
```

A positional port, `--upstream` and `--unix-socket` are mutually exclusive. Origin URLs may contain a hostname and port, but no credentials, path, query or fragment. `--upstream-protocol http1` forces HTTP/1.1; `http2` requires HTTP/2 ALPN for HTTPS and uses prior knowledge for cleartext. Public Host/authority and paths are preserved, while TLS SNI and certificate verification use the configured origin hostname. Origin certificates are always verified; relay development TLS settings do not disable origin verification. Application WebSocket upgrades use HTTP/1.1 to the same HTTP, HTTPS or Unix origin.

The relay listener accepts h2c directly. A public TLS reverse proxy must accept HTTP/2 and forward HTTP/2 to that listener for native gRPC; merely enabling HTTP/2 on its public side is insufficient. HTTP/2 `:authority` participates in the same routing/admission path as HTTP/1.1 Host. Conflicting authority/Host values and duplicate Host headers are rejected. gRPC status trailers, binary payloads, timeout metadata and cancellation pass through; the configured 200 MB aggregate request-body limit also applies to a streaming RPC, and 30 seconds without body progress ends an idle stream. No public TLS listener or certificate automation is added by these origin options.

After `cargo build --workspace`, run `cargo test -p pike --test origin_e2e -- --nocapture`. The fixture launches real CLI/relay processes over QUIC and forced WebSocket fallback, uses tonic and Hyper as independent clients/origins, checks all four RPC shapes, request/response trailers, deadline propagation, cancellation cleanup, HTTPS trust/hostname failures, and HTTP/HTTPS/Unix SSE and WebSocket forwarding. It requires loopback/Unix socket access and OpenSSL for an ephemeral origin certificate. It does not establish deployed proxy configuration or external-network behavior.


## Origin pools and health checks

Repeat `--upstream` to balance one HTTP tunnel across up to 16 origins:

```sh
pike http --upstream http://127.0.0.1:3000 --upstream http://127.0.0.1:3001 --health-path /ready
```

Healthy members receive requests in round-robin order. Pools probe every 5 seconds by default; `--health-interval` accepts 1–300 seconds and `--health-timeout-ms` accepts 100–5000 milliseconds (default 2000). With `--health-path`, a HEAD request must return 2xx. Without a path, checks establish TCP/TLS connectivity only. Health requests use the origin's configured authority; application requests preserve the public authority. Recovery occurs on the next successful probe. A single origin retains its existing behavior unless a health path is explicitly enabled.

Each incoming request has a 5-second total connection budget. Failed connections try another member within that budget. Once application bytes have been sent, Pike never retries the request automatically: a POST, RPC or other operation may already have taken effect. Existing streaming responses and WebSockets stay on their selected origin. When no healthy member can be reached within the budget, new HTTP requests and WebSocket upgrades receive 503 with `Retry-After: 1`. Health changes do not forcibly move established streams.

Pool origins share the selected HTTP protocol and origin CA/certificate-name settings. TLS verification is mandatory. Repeated URLs cannot be combined with a positional port or Unix socket. URL credentials and duplicate origins are rejected. The local inspector exposes `/api/origins`, caps its live view at the newest 1,000 requests, and displays health state; expired checks are labeled rather than presented as current. Saved dashboard pool configuration is available; distributed connector failover and cloud origin-health reporting remain separate work.

`cargo test -p pike --test origin_e2e -- --nocapture` includes controlled health failure/recovery, 10/10 request distribution, all-down HTTP/WebSocket behavior, an origin that consumes a POST then fails (exactly one delivery), sustained concurrent streamed uploads with sampled CLI/relay RSS, and verified HTTPS/gRPC pool interoperability over both transports. `node scripts/inspector_ui_check.cjs` executes the shipped inspector renderer with hostile captured values using a DOM stub; it is not browser visual QA.

## License

Apache-2.0. See `LICENSE`.

## Public UDP endpoints

`pike udp 5353 --remote-port 15353` forwards a public IPv4 UDP port to the configured local bind address and port. Omitting `--remote-port` allocates an available port from 10000–65000. Open that UDP port in the relay firewall; TCP and UDP port allocations are independent. A normal HTTP reverse proxy cannot carry the public UDP endpoint.

Each public source IP/port receives a distinct connected origin socket, so replies cannot cross clients or arrive from an unrelated origin. Packet boundaries, binary and zero-length datagrams are preserved over QUIC and forced WebSocket fallback. The framing accepts at most 65,507 payload bytes per packet; the host OS and network path can impose a lower UDP limit. This is UDP forwarding, not private subnet routing.

The relay permits 32 active peers per endpoint and 64 across one CLI connection. Each public peer has a four-packet queue; overload drops whole packets. An inactive session expires after 60 seconds; `--idle-timeout` accepts 1–300 seconds. A stalled tunnel write expires after two seconds. Disconnect closes all origin sockets; reconnect creates fresh sessions and never replays old datagrams. QUIC streams and WebSocket are reliable carriers, so UDP traffic can experience head-of-line delay within a peer or WebSocket connection.

Use matching protocol-8 CLI and relay builds. Standalone forwarding and saved HTTP/TCP/UDP/TLS profiles are implemented. The dashboard displays the actual leased endpoint, public port and transport. Run `python3 scripts/udp_e2e.py --transport both` after `cargo build --workspace --locked --offline` for real-process packet, isolation, overload, expiry and reconnect checks.


## Saved tunnel profiles

Create or edit a tunnel in the dashboard, then run `pike start <name>` on the origin machine. The CLI fetches the profile from the configured `relay.api_url` using its API key. Managed start needs `tunnels:read` and `tunnels:write`; raw CLI registration/reconnect continues to work with a write-only key. API credentials use HTTPS, except loopback development.

Profiles support HTTP local ports, up to 16 HTTP(S) origins, verified custom origin CA/name, HTTP/1.1 or HTTP/2, Unix sockets and health checks; TCP/UDP local and requested public ports; and UDP idle expiry. File paths refer to the connector's machine. For an older profile containing only `port` or no settings, edit and save its configuration once in the new dashboard. Saving a profile does not start a process on that machine. Editing its settings requires restarting the command so it fetches the new configuration.

Enabled and connected are separate states. A trusted relay publishes the actual endpoint and renews a 90-second lease every 25 seconds. Disabling a profile or editing its configuration rejects the old connector's next renewal, which normally stops forwarding within 30 seconds. A failed relay can leave its last endpoint visible as connected until its lease expires; the dashboard checks expiry. Graceful connector shutdown releases its lease without disabling the saved profile. Lease ownership prevents a competing relay or delayed teardown from replacing or clearing a live endpoint.

Apply Worker migrations through `0018_quota_reservations.sql` with the matching API before the dashboard and protocol-8 CLI/relay. Hosted relays additionally require quota protocol 1 on authentication and endpoint leases; older relays cannot claim or renew endpoints. Drain older hosted relays before enabling the coordinated quota rollout. The relay `server_token` must match Workers `SERVER_TOKEN`, and lease publishing requires the owner's tunnel-write API key. Local standalone relays retain their existing operation without Workers. These changes are local source, not a deployment.

Hosted monthly bandwidth and daily-request quotas use the account's stored custom limits and a persistent ledger shared by relays. HTTP, WebSocket, TCP, TLS and UDP consume durable credit before forwarding. Credit is bounded to 4 MiB and 16 requests, expires within 60 seconds, and cannot cross UTC quota windows. Limit changes reach existing grants within that interval. The dashboard separates reported usage from reserved allowance. See [quota and usage recovery](deploy/USAGE-RECOVERY.md) for failure behavior, crash recovery and journal migration.

Local runtime checks live in `pike-cloud/workers/scripts/{tunnel-runtime-tests,managed-tunnel-e2e,dashboard-runtime-e2e}.mjs`. They use isolated workerd/D1/KV; the managed fixture forwards actual traffic through a production-mode relay on both transports. The dashboard fixture uses a production build, real API/database and a controlled endpoint lease; real traffic is checked by the managed fixture separately. The relay applies the account's custom active-tunnel cap returned by authentication, including zero; an absent cap uses the plan default. Custom bandwidth/daily-request overrides remain outstanding. TCP, UDP, TLS and upgraded WebSocket observations now use the durable usage journal; see [usage recovery](deploy/USAGE-RECOVERY.md) for byte directions, counting rules and the commit boundary.

TCP port allocation rejects ports already occupied by another listener, including a loopback-specific listener when Pike binds all interfaces. On non-Linux systems, address reuse is disabled for these public listeners; an explicitly requested port may remain unavailable while the OS retires earlier connections. The CLI's normal registration retry applies. Busy requested ports are checked before consuming the tunnel-creation allowance, and the final bind still validates availability. Other applications on the relay host remain under the operator's control.

## SNI-routed TLS endpoints

`pike tls 8443 --subdomain service --mode passthrough` exposes a TLS origin on the relay's shared TLS listener. Clients connect with SNI `service.<relay-domain>` and validate the origin's certificate. TLS bytes and ALPN pass unchanged through the tunnel. `--mode terminate` instead presents an operator-configured relay certificate and forwards decrypted bytes to the local TCP service. This mode does not currently negotiate an application ALPN protocol or re-encrypt to the local service. Use passthrough when origin TLS/ALPN or origin mTLS must remain intact; STARTTLS belongs on a TCP endpoint.

Configure the relay explicitly (the listener is disabled by default):

```toml
[public_tls]
bind_addr = "0.0.0.0:443"

[[public_tls.certificates]]
hostname = "service.pike.example"
owner_user_id = "canonical-account-uuid"
cert_path = "/etc/pike/tls/service-chain.pem"
key_path = "/etc/pike/tls/service-key.pem"
```

The public hostname must resolve to this relay, and the TCP listener must be reachable. Port 443 may require service privileges/capabilities and cannot already be occupied by an HTTP frontend on the same address; use a dedicated IP, an alternate port, or a frontend that passes the TLS connection through. The returned `tls://hostname:port` is authoritative. Both CLI modes require SNI; unknown names, plaintext and missing SNI fail closed.

Certificates are configured only by the relay operator. A hostname with a configured certificate is reserved to `owner_user_id` in both modes. For a self-hosted local API key, the owner ID is `local-` followed by that key's SHA-256 hexadecimal digest; keep the key private. Keys must be readable by the relay service. New handshakes load the configured files and verify the key matches the chain. Replace a renewed certificate atomically; when changing keys, use a safely switched directory/symlink pair. A transient mismatch rejects new handshakes. Existing connections retain their negotiated TLS session.

The listener caps accepted connections at 256 (including handshakes and active streams), limits ClientHello input to 64 KiB, and closes incomplete handshakes after five seconds. Each route has a four-connection queue; the common TCP/TLS bridge permits 128 active connections per connector. Stream bytes update live directional counters and are committed to the durable usage journal before forwarding each bounded chunk. A TCP/TLS connection counts once; chunks do not inflate the request count. The 200 MB HTTP request limit does not impose a total byte limit on raw TCP/TLS connections.

Saved TLS profiles and the dashboard store `local_host`, `local_port` and `tls_mode`; certificate keys never enter the profile. `pike start <name>` registers the saved mode and publishes the actual SNI endpoint. Disabling or editing the profile invalidates the connector lease as with the other managed modes. Run `python3 scripts/tls_e2e.py --transport both` for independent OpenSSL/Python TLS validation against real CLI/relay/origin processes.

Custom-domain ownership, exact aliases and optional [ACME HTTP-01 certificates](deploy/ACME.md) are implemented. Public CA interoperability and deployed TLS proof remain unverified.

### Local application interoperability

`python3 scripts/services_e2e.py --output ../reports/feature-delivery-2026-09-20/services.json`
checks actual PostgreSQL/libpq, Redis/redis-cli, OpenSSH and SFTP clients through
QUIC and forced WebSocket fallback. It needs macOS OpenSSH and already-cached
`postgres:16.14` and `redis:7` Docker images; it never pulls images. It creates
fresh temporary databases, disposable keys and a command-restricted loopback SSH
server, then removes the fixture resources. It verifies binary transfers,
transactions, pinned host keys and rejected credentials. These local checks do
not establish production capacity or external-network behavior.

### Custom hostnames

Hosted DNS ownership, exact HTTP/TLS aliases and dashboard onboarding now have local proof on both transports. Standalone operators can bind aliases to an explicit local-key owner. See [custom-domain setup](deploy/CUSTOM-DOMAINS.md) for migration 0020 and domain protocol 1. HTTPS supports manual certificates or [automatic ACME certificates](deploy/ACME.md), including durable recovery and renewal. Hosted readiness requires migration 0021.

Cloud origin checks are now visible in the dashboard, with unknown, healthy, unhealthy and stale states tied to the current lease. Apply migration 0022 and matching protocol-8 builds; see [origin health](deploy/ORIGIN-HEALTH.md). Distributed connectors/failover remain separate work.
