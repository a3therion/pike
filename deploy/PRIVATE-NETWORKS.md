# Private IPv4 networks over native WireGuard

`pike network` connects an owner's devices and LAN subnets privately. The
Worker is the only source of truth for membership, owned routes and access
grants. An owner-run Linux **hub** enforces them with native WireGuard and
nftables; owner-run Linux **site** gateways expose LAN subnets; clients are
ordinary WireGuard configurations. Pike never carries the packets.

## Scope

- IPv4 only. No IPv6 addresses, routes or pools.
- Exactly one active hub per network. No multi-hub high availability.
- UDP transport only (WireGuard). Networks that block UDP are not supported;
  there is no QUIC or WebSocket fallback for private traffic.
- Hub and site gateways run on Linux with a WireGuard-capable kernel (5.6 or
  later, or the out-of-tree module), `wireguard-tools`, `nftables` (1.0 or
  later; concatenated interval sets with timeouts need kernel 5.6 or later),
  `iproute2` and `CAP_NET_ADMIN`. The operator enables `net.ipv4.ip_forward=1`;
  the gateway refuses to start otherwise and never changes it.
- Clients on macOS, Windows, iOS, Android or Linux import the printed file by
  hand into the official WireGuard app or use `wg-quick`. There is no automatic
  client setup on any OS.
- The hub sees plaintext for traffic it forwards. It is acceptable only because
  the owner runs it.
- Nothing here is deployed or proven outside the local container fixture.

## Trust and enforcement model

- **Keys stay on devices.** `pike network join` runs `wg genkey` locally, stores
  the private key at `<config dir>/networks/<network id>/<member>.key` with
  mode 0600 in a 0700 directory, and sends only the public key. A device may
  instead enroll with `--public-key` from a key generated in the WireGuard app;
  Pike then never holds its private key. The Worker, its status API and gateway
  logs contain public keys, addresses, handshake times and counters only.
- **The only private key is never deleted on a guess.** `join` writes the key
  and a *pending* record (no member id) before it enrolls. If the answer is
  lost (timeout, unreadable body, server failure) the files stay: rerunning
  the same `join` looks the public key up in the network, verifies name and
  role, reuses the original key and only completes the record, so a committed
  enrollment is finished rather than duplicated. Only a definitive 4xx refusal
  of a brand-new key removes it. Record replacement writes a private temporary
  file and renames it, so a crash leaves the old or the new record, never
  neither. Pending records block `config`, `hub` and `site` with the two ways
  out: finish with `join`, or discard with `leave --forget-local`.
  `leave` deletes the local key only when the owner's control plane confirms
  the member revoked. A 404 also answers a deleted network or a key of
  another account, so it keeps the key and explains. For a pending record,
  `leave` looks the key up first and revokes the member it finds; a lookup
  that does not find the key proves nothing, because the enrollment whose
  answer was lost may still be in flight and commit after the check, so the
  key and record stay with the same two ways out. `--forget-local` discards
  the local files deliberately and never revokes anything.
- **Ownership.** Every API statement is scoped to the authenticated owner.
  Another account sees 404. Addresses are allocated and routes are claimed by
  single atomic statements, so concurrent overlapping claims leave exactly one
  winner. Route CIDRs must be canonical private IPv4 subnets (RFC 1918 or
  100.64.0.0/10, /8 to /32); they can never overlap each other, the client pool
  or be the default route. The client pool is explicit at creation (/20 to /29).
- **Grants** are `client member -> owned route`, all IP protocols. There are no
  per-port rules and no wildcard grants.
- **Hub WireGuard.** Each client peer's AllowedIPs is exactly its /32; each
  site's is its /32 plus the routes it owns. Packets with any other source are
  dropped by WireGuard's cryptokey routing before reaching netfilter.
- **Hub nftables** (`table inet pike_<id>`): forwarding between peers requires
  the exact `(client, route)` pair to be a live element of the timed `grants`
  set in the request direction, and the same pair plus conntrack
  `established,related` in the reply direction. There is no unconditional
  established accept, so removing a grant also stops flows already in
  progress. Sites cannot open connections toward clients and clients cannot
  reach each other. Only packets entering or leaving the Pike interface are
  ever dropped; the table has no effect on other host traffic. The input hook
  accepts ICMP echo to the hub's own address and drops everything else from
  the Pike interface.
- **Site nftables** forwards only client-pool sources toward the site's live
  owned routes (masqueraded onto the LAN) and LAN replies for established
  flows back into the tunnel.
- **Kernel-enforced lease.** Every poll (10 s) the gateway fetches its desired
  state with a `networks:run` key and, in one atomic `nft -f` transaction,
  recreates every grant (hub) or route (site) element with a timeout of
  30 s minus the time since that fetch began minus a fixed install budget
  (3 s for the whole `nft` run including its stdin, plus 1 s slack). The
  `nft` process is killed when its budget ends, so no element can ever be
  committed with an expiry later than fetch start + 30 s, even if `nft`
  stalls. Every child the gateway spawns also arms a parent-death SIGKILL in
  itself before it execs (Linux `PR_SET_PDEATHSIG`, verified against the
  parent pid recorded before the fork so it can never be armed against a
  parent that is already gone), so an `nft` that is running, stalled or
  stopped when the gateway itself is SIGKILLed dies with it instead of
  resuming later and committing a stale transaction. A fresh apply therefore
  arms 26 s, comfortably more than one poll.
  Incoming traffic never refreshes the timeout. If the agent is SIGKILLed,
  hangs, loses the control plane, or its key is revoked, the elements expire
  on their own and forwarding stops within 30 s of the last successful fetch.
  Static WireGuard handshakes still complete with a dead agent (the interface
  and peers remain), but no data is forwarded. A 401, 403, 404 or 410 from the
  control plane, or an invalid desired state, makes the gateway drop
  authorization immediately and exit.
- **Closed at every instant.** On start the gateway installs its default-deny
  table (with empty sets) *before* it creates or adopts the interface, loads
  peers, assigns the address or brings the link up; a crash between any two
  steps leaves either nothing or a filtered interface, never an unfiltered
  one. When peers or kernel routes change, every authorization element is
  removed first, then peers and routes are reconciled, and only then is the
  full, validated new authorization installed. Nothing is carried across an
  identity change: a `(client, route)` pair or a route element is a number
  pair that cannot distinguish a revoked key from its successor on the same
  /32 or CIDR, so even a successor that receives the same grant on the same
  address (or a site that inherits a CIDR and its grants) starts from an
  empty set, and an element that expired during an outage is never refreshed
  under the old key. The cost is a short forwarding gap on every peer or route
  change; an unchanged identity set (the normal poll) only refreshes the
  timeouts. Teardown flushes authorization, brings the interface down
  and deletes it, and removes the table last; unless the interface is
  confirmed gone (removed, or absent in a readable inventory) the table stays
  so the interface remains filtered.
- **Owned resources only.** The gateway creates interface `pike<8 hex>` and
  table `pike_<8 hex>`, both derived from the network id, and installs site
  routes on that interface with rtproto 250. The table carries a counter
  object named `owner_<member id>`; on start the gateway adopts (atomically
  replaces) an existing table only if it carries this member's exact marker,
  and adopts an existing interface only if `wg show` proves it holds this
  member's key. Anything else with those names is refused and left exactly as
  found, and a refused start removes only what this run itself created.
  Existence is read only from the complete machine-readable inventories
  (`ip -j link show`, `nft -j list tables`); a command that fails or answers
  something unreadable is treated as unknown, never as absence, so the start
  is refused before anything is installed and teardown leaves the table.
  Kernel
  routes are reconciled from an inventory of the main table: only routes on
  the Pike interface with rtproto 250 are ever deleted, missing routes are
  added with `ip route add` (never `replace`), and a desired prefix that is
  already routed by anything else is a conflict that the hub refuses and logs
  until the Pike route is withdrawn or the other route removed. It never
  flushes global rules, replaces default routes, or deletes unowned
  interfaces, routes or tables. A table left by an older build without the
  marker is not adopted; delete it by hand once.
- **Control plane access** uses HTTPS with no redirects, bounded timeouts and a
  256 KiB response bound. Plain HTTP is allowed only to loopback (the same rule
  as `pike start`). Every value is validated before it reaches `wg`, `nft` or
  `ip`, which are invoked with argument vectors, never a shell.

## API keys and scopes

Create API keys in the Dashboard with exactly the scopes a device needs:

1. Sign in to the Dashboard and open **Account → API Keys** (`/api-keys`).
2. Click **Create API Key**.
3. Enter a **Name** (for example `laptop enrollment` or `hub gateway`).
4. Under **Scopes**, untick the preselected `tunnels:read` and `tunnels:write`
   unless this key also runs tunnels, and tick:
   - `networks:read` **and** `networks:write` for a key that creates
     networks, enrolls devices (`join`), prints configurations, manages
     routes and grants, revokes and leaves;
   - `networks:run` only, for a key a hub or site gateway runs with.
5. Choose **Expiration** and **Rate Limit**, then click **Create Key**.
6. Copy the key from the **Secret key** box. It is shown once (the box hides
   it after five seconds; **Show** reveals it again until the dialog closes).

| Scope | Allows |
|---|---|
| `networks:read` | `GET /api/v1/networks…` (list, status, client config) |
| `networks:write` | create, delete, enroll, revoke, routes, grants |
| `networks:run` | only `GET …/members/:id/desired` and `POST …/members/:id/status` |

Tunnel-scoped keys (`tunnels:read`, `tunnels:write`) are unchanged and have
no network authority; `pike start`, `tcp`, `tls` and `udp` keep using them.

Store a key in a profile with `pike login`:

```sh
pike login <key>                                   # ~/.pike/config.toml
pike --config ~/.pike/run.toml login <key>          # a separate profile
```

`login` validates the key against the API (or saves it unverified when
offline) and writes it to the profile's `[auth] api_key`. Every `pike network`
command reads the key from the profile given by `--config` (default
`~/.pike/config.toml`). Two common layouts:

- **One profile.** `pike login <read+write key>` on an admin machine or a
  laptop; every `pike network` command uses it.
- **Enrollment profile plus run-only gateway profile** on a hub or site host:
  `pike login <read+write key>` for `join`, and
  `pike --config ~/.pike/run.toml login <networks:run key>` for the
  long-running `pike --config ~/.pike/run.toml network hub …` or `… site …`.
  The read+write key can then be revoked in the Dashboard; the gateway keeps
  running with `networks:run` alone. Both profiles must live in the **same
  directory**: enrollment records are stored under
  `<directory of the config file>/networks/`, and the gateway resolves its
  member from there without any control-plane call.

A standard client needs no API key after enrollment.

## Commands

```sh
pike network create lab --client-cidr 100.96.0.0/24
pike network join lab --as hub --role hub --endpoint hub.example.test:51820   # on the hub host
pike network hub lab --as hub                                                # long-running, Linux
pike network join lab --as office --role site                                # on the site host
pike network site lab --as office --lan-if eth1                              # long-running, Linux
pike network route add lab 10.10.0.0/24 --via office
pike network join lab --as laptop                 # prints a wg-quick file on stdout
pike network join lab --as phone --public-key <key from the WireGuard app>
pike network config lab --as laptop               # reprint after routes change
pike network grant lab --client laptop --to 10.10.0.0/24
pike network status lab [--json]
pike network ungrant lab --client laptop --to 10.10.0.0/24
pike network route withdraw lab 10.10.0.0/24      # also removes its grants
pike network revoke lab laptop                    # a revoked key can never re-enroll
pike network leave lab --as laptop                # self-revoke; deletes the local key only on confirmation
pike network leave lab --as laptop --forget-local # also discard the local key after a deleted network or wrong-account 404
pike network delete lab
```

A `join` that fails after the answer was lost prints how to continue; rerun
the same `join` (with the same `--public-key`, if one was used) to finish it.

Client files route the client pool and every network route into the tunnel;
the hub enforces grants, so a client sees only the subnets it was granted.
Reprint and re-import a client file after adding routes. The hub's UDP port
must be reachable from clients and sites; open it in the host firewall.
Bounds: 8 networks per account, 64 active members, 32 routes and 256 grants
per network.

## Rollout

Apply Workers migration `0025_private_networks.sql`, deploy the Worker, then
ship a CLI build that has the `network` subcommand. No relay (`pike-server`)
change is involved.

## Verification

Focused checks (run from `pike-cloud/workers`):

```sh
bun test tests/private-network.test.ts        # SQL contracts on real SQLite
node scripts/private-network-runtime-tests.mjs # actual local Worker/D1 API
cargo test -p pike network                     # renderers, validation, plans, apply ordering,
                                               # local record atomicity, mocked-API join/leave recovery
```

The Rust tests include a mocked control plane (wiremock) that commits an
enrollment but answers with an unreadable body or a 5xx, then proves the
retried `join` reuses the pending key byte for byte and completes the record
without a second enrollment; that a wrong-account or deleted-network 404 on
`leave`, or a pending key the lookup does not find yet, keeps the key until
`--forget-local`; that an unreadable link or table inventory is never taken
for absence and the table is deleted only after the interface is confirmed
gone; on Linux, that a child whose parent is not the pid recorded before the
fork refuses to exec; and that an apply whose peer set changes always empties
authorization before `wg syncconf`, even when the `(client, route)` tuple is
unchanged.

Container end-to-end (Docker on this machine, no host networking, NET_ADMIN
only, native kernel WireGuard):

```sh
PIKE_LINUX_BINARY=/path/to/linux-amd64/pike node scripts/private-network-e2e.mjs
```

The fixture builds a small Debian image (or uses `PIKE_NET_IMAGE`, which must
carry `python3`), runs a hub, two sites on disjoint internal LANs, independent
socat TCP echo, Python stdlib UDP echo and ICMP origins, three standard
`wg-quick` clients (one with a key Pike never saw) and an unknown-key
stranger, and provisions everything through the real CLI and API. It proves
allowed TCP (hash-compared), UDP datagrams (one per size, byte-compared under
an explicit socket timeout; a failure reports sizes, timeouts, client and
origin errors, gateway counters and handshake ages, never a key) and ICMP
through *each* site to its own LAN, with the other site's counters unchanged;
denial of
ungranted clients and routes, client-to-client and site-initiated traffic;
spoofed client and site sources; unknown keys; concurrent pairwise-overlapping
route claims with exactly one winner; grant removal and revocation cutting an
established TCP stream while the client keeps writing; a member enrolled into
a revoked client's /32 within one poll inheriting none of its grants (the hub
agent is frozen with SIGSTOP so the race is deterministic); a foreign route
for the same prefix in the hub's main table surviving a refused claim;
withdrawal while traffic is live; SIGTERM cleanup and restart; control-plane
outage expiry; SIGKILL lease expiry proven from nft JSON with the interface,
peers and table still present and no Pike process left in the container; an
`nft` transaction held (stopped by a test-only stand-in that execs the real
`nft` in place) before commit while the captured hub pid is SIGKILLed, dying
with the hub so that after the lease nothing can be resumed to install stale
grants; refusal of a same-named foreign table and of a same-named interface
holding
another key, both left untouched; `leave` with another account's key (404)
leaving the key bytes and record untouched until `--forget-local`, the same
for the hub's own key after the network is deleted, and a committed
enrollment whose answer was lost being finished by a retried `join` with the
original private key and no duplicate member; and name reuse after deletion.
SIGINT or
SIGTERM to the fixture removes only its own containers, networks and image and
then exits with the signal's status. Results, timings and source hashes are
written to `reports/private-network-2026-09-27/private-network-e2e.json` only
when the fixture actually runs. Build the Linux binary against a glibc no newer
than the fixture base image, or as a static musl binary.

References: WireGuard project documentation (https://www.wireguard.com/),
`wg(8)`, `wg-quick(8)`, and the nftables wiki and `nft(8)` manual on set
element timeouts and atomic `nft -f` transactions.
