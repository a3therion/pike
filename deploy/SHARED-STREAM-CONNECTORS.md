# TCP and dedicated TLS connector sharing

Saved TCP and TLS profiles can attach up to eight matching connectors to one
relay. The profile owns its listener, visitor policy, exact domain grants and
certificate authority. Each connector retains its own transport, cloud lease,
stream bridge and quota reservation. All members use the same canonical account
and profile for limits and durable usage accounting.

For each new accepted TCP or TLS stream, the relay rotates among member queues.
It skips closed or full queues before forwarding any application bytes. If every live
queue is full, one dispatcher-held stream waits at most two seconds for capacity,
backpressuring the listener. Membership is rechecked before delivery. If no member
remains or the wait expires, the stream closes. Once selected, the stream stays
on that connector; it is never migrated or replayed after an error. TCP server-
first data and half-closes still pass through the existing byte bridge. Dedicated
TLS supports both passthrough and termination. SNI ownership and visitor admission
are checked before the accepted stream enters member selection.

One connector departing removes only its queue and streams. The surviving
members keep the listener, aliases, visitor gate and server certificate
authorization. A replacement must match owner, canonical identity, protocol,
desired configuration and policy/domain revisions. The last ordinary departure
closes the listener and releases authority. Registry maintenance moves listener
metadata to a live representative when its previous owner leaves.

## Policy-driven TCP listener handoff

Policy/configuration changes can reset all connector leases. Closing and
immediately rebinding a used fixed TCP port is not portable: macOS can reject the
bind while old connections retire. On a lease-driven reset, the relay instead
parks the listener for at most 60 seconds. Its dispatcher is cleared and new
connections are closed without reaching an origin. Old connector streams still
end, and their policy authority is released.

Only an authenticated admission for the same runtime can reuse the parked
listener. A different runtime cannot claim its port. A matching replacement
keeps the same socket and port; a changed requested port uses a new listener.
Without a replacement, the parked listener expires and releases the port. A
disabled profile cannot forward or regain admission, although its port may stay
reserved for the bounded handoff period. Relay shutdown closes parked listeners.
Ordinary user disconnects do not park them.

## Bounds and operating scope

- Eight members per saved profile across all relays; one account tunnel slot.
- Four pending accepted streams per member, one dispatcher-held stream with a
  two-second deadline, plus the existing listener queue.
- Existing limit of 128 active byte streams per connector. Adding members grows
  the profile's aggregate stream capacity.
- Dedicated TLS retains its global 256-connection/handshake limit, five-second
  handshake deadline and 64 KiB ClientHello bound.
- Member selection checks queue availability. HTTP origin-health preference is
  a separate HTTP feature; raw TCP/TLS have no origin-health ranking here.
- UDP sharing and pinned-peer dispatch are described in
  `SHARED-UDP-CONNECTORS.md`. Cross-relay public
  ingress/failover, distributed OIDC/ACME coordination and private networking
  remain separate work. No deployment or external-network proof is implied.

## Verification

Build matching protocol-8 CLI/relay binaries. From `pike-cloud/workers`, use
Node 24 to run `node scripts/shared-stream-connectors-e2e.mjs`.

The fixture uses actual Worker/D1, a production relay and real QUIC and forced-
WebSocket CLIs. Independent Node clients exercise TCP and both TLS modes with
OpenSSL-issued certificates and DNS-proven aliases. Eight held streams reveal
four/four connector assignment when one member stops; the other four continue.
Tests cover replacement, delayed release, abrupt loss, binary traffic, half-
closes, policy reconnect, mTLS revocation, exact canonical accounting and profile
disable. Each account retains its one-profile Free limit and four deliberate
creation allowances; policy reconnects must use their scoped tickets.

TCP unit tests separately prove handoff cannot move to another runtime, parked
connections do not forward, and an unused reservation expires. The normal
listener replacement/shutdown regressions remain required.

This change keeps protocol 8. Deploy the matching relay with Worker migration
0023 and its matching API; follow the existing coordinated schema rollout and
preserve usage journals. This local work has not deployed anything.
