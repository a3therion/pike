# Public ingress across relays

Relays can now forward public traffic to the relay that owns a tunnel over an
authenticated relay-to-relay hop. A **frontend** relay accepts public HTTP/1,
h2c, WebSocket, native HTTPS, raw TCP, SNI TLS and UDP traffic for hostnames and
ports it does not serve itself, and the **owning** relay runs exactly the checks
it runs for a direct visitor. This document covers configuration, the trust
model, what each protocol preserves and what remains unverified.

**Status.** The implementation and its two-relay fixture exist in source. No
build, unit test or fixture run has been executed for this change at the time
of writing; see "Verification" for the commands. Private IP/subnet networking
is separate, pending work.

## Configuration

Both roles are opted into explicitly. The `deployment_topology` guard now accepts
`"cross-relay"` only together with an `[ingress]` table, and rejects either one
alone. Defaults are unchanged: without `[ingress]` a relay behaves exactly as
before.

```toml
deployment_topology = "cross-relay"

# Interface for public TCP/UDP tunnel ports and frontend forwarders. Defaults
# to 0.0.0.0; give each relay on a shared host its own address.
public_bind_ip = "0.0.0.0"

[ingress]
# Dedicated operator CA for relay identities. Never reuse a visitor mTLS CA or
# a public certificate chain here.
ca_path = "/etc/pike/ingress/ca.pem"
cert_path = "/etc/pike/ingress/relay-a.pem"
key_path = "/etc/pike/ingress/relay-a.key"
# Owner role: accept hops from frontends. Omit on a pure frontend.
hop_bind_addr = "10.0.0.1:7443"
# Frontend role: forward to these peers. Omit on a pure owner.
[[ingress.peers]]
name = "relay-b.internal"   # must match the peer's certificate exactly
addr = "10.0.0.2:7443"
```

A relay may hold both roles. A relay never lists its own hop listener as a
peer, and traffic that arrived over a hop is never forwarded again, so two
frontends cannot loop. Relay certificates need `serverAuth` and `clientAuth`
key usage and a DNS name equal to the configured peer name.

## Trust and the accepted-visitor boundary

- The hop is one mutually authenticated TLS connection per visitor stream.
  Frontends verify the configured peer name; owners require a client
  certificate from the dedicated CA. Network position, forwarding headers and
  the bearer-token management listener play no part.
- The hop header is a fixed binary shape (protocol, exact hostname or port,
  64-hex authority, visitor address, TLS flag) bounded to 1 KiB. Unknown
  versions, extra bytes or an unspecified visitor address are refused.
- The owner calls `Directory::verify` against its **current** registrations:
  the target must be live, every registration for it must carry the expected
  authority and share one visitor gate; conflict or absence fails closed. It
  then binds dispatch to that same endpoint or route by gate pointer equality
  and only then writes one accept byte.
- Before the accept byte the frontend has forwarded nothing. An explicit
  rejection permits one re-resolve from a fresh snapshot; a connect or TLS
  failure moves to the next candidate. After the header is written, a timeout
  or EOF is never retried, including for server-first TCP origins. For HTTP the
  frontend never resends once request headers left, and an owner-side 421
  (authority changed between binding and routing) passes through unchanged.
- Accepted streams enter the existing handlers with the original visitor
  address: `run_listener` for TCP, the SNI listener for TLS, the native HTTPS
  listener for HTTPS (the visitor's own ClientHello and certificate proof are
  forwarded intact and terminated on the owner), the same axum application for
  plain HTTP behind a middleware that rebinds the request to the hop-verified
  visitor and expected gate, and the UDP listener for datagrams. IP rules,
  admission, quota, metering, policy revocation, domain revision and channel
  closure keep their existing enforcement. The frontend meters nothing.

## Discovery and ports

Frontends poll each peer's directory over the hop every second with a fresh
nonce, require exact version and nonce echo, cap the response at 2 MiB and 4,096
routes, and expire each snapshot two seconds after the poll began on their own
monotonic clock. A failed, slow or malformed poll withdraws that peer's routes
immediately. A target advertised with different authorities by different peers
is not forwarded.

TCP and UDP ports are opened by a frontend only for conflict-free targets that
the frontend does not serve itself, and close within one poll when the target
disappears or conflicts.

**Port identity is the Worker reservation, not a peer snapshot.** Before a
hosted relay binds a TCP or UDP port it calls
`POST /api/v1/tunnels/<id>/reserve-port` (relay credential plus the owner's API
key). The Worker keeps one `public_ports` row per profile and protocol
(migration 0024): the configured `remote_port`, or a number it chooses once for
a profile without one. Every relay and every reconnect of that profile receives
the same number, an explicit request that disagrees is refused, and a number
reserved by another profile is refused with `Public port is reserved by another
tunnel`. Each connector lease must then carry exactly the reserved number.
Deleting or disabling the profile, or changing its `remote_port`, releases the
number; lease expiry alone does not. A relay that bound before reserving (an
older build) is admitted only if its number can still become the reservation.
Every reservation read and write is fenced inside the statement against the
exact enabled profile it was derived from, so a request computed from an older
configuration that resumes after the profile moved is refused with `Tunnel
changed; reserve again from the current profile` and cannot delete or replace
the newer number. A TCP/UDP lease renews only while its number is still the
profile's reservation, and the profile's runtime projects such a lease as
connected only under the same condition; migration 0024 invalidates any lease
that lost a contested number.

Only after the reservation succeeds does the relay withdraw the port from its
own frontend forwarder (accepted TCP streams stay pinned; UDP associations end
with the socket they reply through). The withdrawal is scoped to that
registration attempt and releases on every failure path, so a rejected
registration cannot leave a peer's port withdrawn. Only cloud-reserved ports
are advertised to peers.

The stable public identity of a port is `relay.<domain>:<port>`. Every owner
in one cluster must share `domain`; two physical relay hosts do not masquerade
as two identities, and a lease naming a different host is refused.

**Standalone relays have no global port authority.** A standalone relay
(`dev_mode`, or no `workers_api_url`) cannot prove that another relay is not
serving the same number for a different profile, so in the `cross-relay`
topology it refuses TCP and UDP profiles outright with `public TCP/UDP ports in
the cross-relay topology require the cloud port reservation`. Ordinary
single-node standalone behaviour (explicit or relay-chosen ports served on that
relay only) is unchanged; those ports are never advertised to peers.

## Protocol notes

- Plain HTTP routes per request, including different `Host` values on one
  keep-alive connection. Ordinary requests use HTTP/2 prior knowledge over the
  hop (trailers, cancellation, backpressure and binary bodies preserved via
  hyper); WebSocket upgrades use HTTP/1.1 and pin to their upgraded connection.
  The frontend's body limit still rejects a 200,000,001-byte upload before any
  hop is opened. The request keeps the visitor's full authority, including a
  port in `Host` such as `demo.pike.test:8080`; the normalized hostname is used
  only for route lookup, so the owner's `Host`/`:authority` agreement check
  passes for HTTP/1.1 and HTTP/2 alike.
- ACME HTTP-01 challenges for a forwarded HTTP hostname reach the owner because
  the router miss is forwarded before local challenge handling. A TLS-terminate
  profile advertises no HTTP target, so its challenge travels as a separate
  bounded hop request (`KIND_CHALLENGE`): exact hostname, authority and a
  base64url token of at most 256 bytes, `GET` without a query only. The owner
  runs the same `Directory::verify` as for a stream and answers only from the
  certificate entry bound to that verified gate; nothing else is reachable
  through this path, and no HTTP origin route is created for the profile.
  Owners with separate local ACME stores hold different challenges for one
  hostname, so an owner's explicit refusal moves the lookup to the next owner
  that advertised the same authority (a lookup carries no visitor bytes and has
  no origin side effect). A malformed, oversize, truncated or off-token answer
  ends the lookup, and peers that disagree about the authority are never asked.
  The frontend also requires the proof to be a key authorization for exactly
  the requested token.
- Frontend shutdown ends forwarded HTTP responses. The forwarded response body
  is the only handle that keeps an HTTP/2 hop open once the request has been
  dispatched: a visitor that goes away resets the stream and hyper closes the
  hop; on SIGTERM the frontend drops the body itself, closes the hop and cuts
  the visitor's response with an error rather than a clean end of stream. The
  owner sees the hop close and cancels the hop-served request like any lost
  visitor, so an endless remote stream cannot hold the frontend's graceful HTTP
  shutdown open. TCP, UDP, TLS and WebSocket forwarding already observed
  shutdown.
- Injected UDP associations pass the owner's active gate and IP rules for the
  original visitor address before any association is allocated, exactly like a
  directly received datagram.
- Basic and JWT visitor authentication over a plaintext frontend hop is
  rejected as insecure; use native HTTPS on the frontend.
- UDP pins one visitor address to one hop association; packets travel with the
  existing four-byte framing, so zero-length and 65,507-byte datagrams and
  packet boundaries survive. Replies return only through that association. Peer
  caps, queue bounds, member selection and idle expiry apply on the owner.

## Verification

Nothing below has been run for the current repair; the Worker typecheck and the
earlier three port-lease unit tests passed before the reservation was added.

```sh
cd pike
cargo test --offline -p pike-server ingress
cargo test --offline -p pike-server
cd ../pike-cloud/workers
bun test tests/public-port-leases.test.ts
node scripts/public-port-leases-runtime-tests.mjs
node scripts/public-ingress-e2e.mjs      # needs 127.0.0.2 to 127.0.0.5 (Linux)
node scripts/public-ingress-acme-e2e.mjs # 127.0.0.1 only; needs Docker (Pebble)
```

The Rust `ingress` tests include a real hyper HTTP/2 owner over a duplex that
streams forever: dropping the forwarded response closes the hop, and frontend
shutdown cuts the response with an error and closes the hop. They also cover
the challenge lookup order with scripted owners: refusal moves on, a
malformed answer or an authority conflict fails closed, and the exact request
reaches every owner asked.

The fixture starts three relays (a frontend and two live owners), sixteen CLI
connectors (QUIC to one owner, forced WebSocket to the other), a controlled
fourth peer that serves silent, conflicting, oversize and wrong-nonce
snapshots, and independent clients for every protocol from a visitor address
distinct from the hop address. It covers wrong hop identity, forged and stale
authority, snapshot freshness and bounds, HTTP and UDP IP denial that provably
sees the original visitor address, mTLS over HTTP/1.1 and h2, `Host` with a
port and per-request routing on one keep-alive socket, bidirectional gRPC
streaming with trailers both ways, WebSocket, binary TCP/TLS, a Worker-reserved
auto port shared by both owners, empty and maximum UDP packets, the exact upload
boundary, connector loss, owner loss with failover to the survivor and no replay
of a side-effecting request, pinned sessions, recovery, SIGTERM of the frontend
while a visitor reads a remote endless HTTP stream (bounded exit, the origin
sees the stream close, both owners and every connector stay up), single
metering, and cleanup with every port bindable again. It kills only processes
it started, and its hard timeout runs the same bounded cleanup. HTTP-01 over
the hop for a TLS-terminate hostname is exercised there for refusal paths only,
because that fixture runs no ACME issuer.

`public-ingress-acme-e2e.mjs` is the positive proof and runs on a Mac with
Docker: a production frontend relay and two production owner relays on
127.0.0.1 with distinct ports, each owner with its own local ACME store, real
CLI connectors (QUIC and forced WebSocket) for one TLS-terminate profile, and
an independent containerized Pebble CA that validates HTTP-01 through the
frontend's public HTTP listener and the hop. It requires every validation the
CA made to have been answered with the key authorization for exactly the
requested token (two owners, two distinct tokens and account thumbprints, so
the lookup had to move past the owner without that token), verifies the issued
chains with an independent Node TLS client against the CA roots through the
frontend and directly on each owner, echoes origin bytes exactly through
termination, refuses missing, invalid, wrong-authority, wrong-protocol and
rogue-identity challenges without an origin connection, and keeps serving from
the surviving owner after one connector is stopped. Fresh temporary state,
generated identities, handles for every process and container, bounded
cleanup and a machine-readable JSON result. No public CA, real DNS, Worker or
deployment is involved. Neither fixture has been run for this repair.
