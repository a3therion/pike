# UDP connectors sharing one relay

A saved UDP profile can attach up to eight matching connectors across relays.
On one relay, those members share one bound public UDP socket, visitor policy
and peer table. Each member retains its own transport, cloud lease, quota
reservation, response routes and per-connection peer budget. Members must match
the profile owner, canonical identity, protocol, configuration and current
policy/domain revisions before traffic becomes available.

## Association and departure

The first packet from a public source address and port selects an open member
with available peer capacity, rotating among eligible members. Further packets
from that client and all replies stay with the same member and origin socket.
The relay does not select a new connector for each packet. Selection does not
use HTTP origin-health reports.

Removing a member cancels only its associations. Surviving members keep the
public socket and their existing origin sockets. Retired response routes cannot
recreate an association or deliver through a replacement route: tunnel, public
peer, connection ID and transport stream identity remain checked. After an old
association ends, a later public packet can create a new association on a live
member. Origin application state is not migrated, and queued old packets are
not replayed.

The final departure stops the listener and joins its peer tasks before releasing
the socket. This also applies to profile disable and lease-driven policy changes.
A replacement may bind the same port after shutdown; UDP needs no TCP-style
parked-port period. Delayed release of an old cloud lease does not remove a new
member. IP policy revisions use the existing lease refresh and reconnect flow. API
inactive state is immediate; actual traffic cessation is checked separately
within the relay lease-refresh window. The local fixture observed 23.838 seconds,
under its 35-second ceiling; this is not a production latency guarantee.

## Bounds and accounting

- 32 public peer associations per profile on one relay, shared across members.
- 64 UDP associations per connector session, shared with its other UDP profiles.
- At most eight members per saved profile across all relays, enforced by cloud
  admission; members of one profile consume one account tunnel slot.
- Four queued complete packets per peer; overload drops whole datagrams.
- Maximum packet payload is 65,507 bytes, including support for empty packets.
- The existing bounded transport codec, byte credit and configured idle expiry
  remain in effect. Source filtering accepts replies only from the chosen origin.
- Each accepted public packet counts once before origin forwarding. Reply
  packets add outbound bytes without incrementing the request count. All members
  retain the same canonical owner and profile identity.

UDP remains connectionless: packet loss, duplication and ordering depend on the
network and application. This implementation does not promise seamless recovery
of an origin's state or real-time latency across reliable tunnel transports.

## Verification and rollout

With matching CLI and relay binaries, run from `pike-cloud/workers` using Node 24:

```sh
node scripts/shared-udp-connectors-e2e.mjs
```

The fixture uses actual local Worker/D1, one production-mode relay, QUIC and
forced-WebSocket CLIs, independent Node UDP clients and a real UDP origin. It
checks one Free-plan profile and public port, maximum/empty/binary packets,
pinned client isolation, four/four membership revealed by origin-initiated
replies after member loss, replacement, delayed release, the shared 32-peer cap,
idle recovery, source filtering, policy reconnect, exact canonical request
accounting and profile disable. Origin-only keepalives preserve associations
without creating replacement associations during departure checks.

The existing `python3 scripts/udp_e2e.py --transport both` fixture remains a
required regression for standalone UDP, port ownership and relay restart.
Focused Rust tests cover member budgets, cancellation, route identity, shared
socket lifetime and immediate rebinding after final cleanup.

No wire protocol change is required: protocol 8 and the existing matching Worker
migration 0023 remain the rollout contract. Follow the coordinated schema/Worker
switch in the cloud membership documentation. Cross-relay public ingress and
failover and private networking remain
separate work. This implementation and its local tests do not deploy services or
prove external-network or production-soak behavior.
