# HTTP connectors sharing a relay

Multiple `pike start <saved-name>` processes can now join one HTTP profile on the
same relay. Each connector must match the owner, canonical profile/runtime ID,
desired settings, visitor-policy revision and exact custom-domain assignments.
Up to eight connectors share one account tunnel slot and one request-rate window.
The cloud's eight-member limit also covers connectors on other relays.

New HTTP exchanges prefer open connector channels whose latest validated report
contains a fresh healthy origin. Equal-ranked members use round-robin selection.
If none are healthy, unknown/unprobed/stale members rank ahead of members whose
origins are all freshly unhealthy. If every member is unhealthy, the chosen CLI
returns its normal all-down response. Health is an observation, not a guarantee
that a later request will succeed. Once selected, the exchange stays pinned; no application bytes are replayed to another
connector. HTTP/2 requests and application WebSocket upgrades cross the same
selection point. Existing streams on a surviving connector continue when another
disconnects. A stream on the lost connector ends and its client must decide
whether retrying is appropriate.

The saved endpoint owns the immutable visitor gate, custom-domain grants and
certificate authorization. Connectors own forwarding channels, health reports and
cloud leases. Removing one member cannot revoke the remaining members' server
certificate or visitor gate. The last member closes the authority. Policy/domain
revisions still invalidate old leases; reconnecting members must match the new
authority before spending their scoped reconnect allowances.

All members share the canonical quota and usage identity. The relay counts the
profile once for its active-tunnel limit, and finalizes usage only after its last
member leaves. Graceful and delayed cleanup remove only the matching connection.
Dead-connection maintenance selects a surviving registry owner. Authenticated
replay retains the specific connector selected during authorization.

## Verification and scope

`pike-cloud/workers/scripts/same-relay-connectors-e2e.mjs` starts one production
relay, actual Worker/D1 and two real CLIs, one using QUIC and one forced to
WebSocket. Independent inspector captures prove eight requests split four/four.
Independent HTTP/2, HTTPS and binary WSS clients verify primary and DNS-proven
alias traffic. Graceful stop, abrupt connector loss, replacement, replay,
policy-driven reconnects, active mTLS revocation, exact combined accounting and
profile disable are exercised. The account retains its one-profile Free limit.
Health tests first fail the shared origin and observe both real CLI probes and
HTTP 503 responses. One CLI is then paused while the origin recovers; all six new
requests use the other connector's fresh healthy report. Resuming the paused CLI
restores four/four balancing. This is a controlled local observation divergence,
not a multi-machine or external-network experiment. Unit checks cover stale probe
age, publication expiry, unprobed members, channel loss and replay pinning.
The fixture allows exactly four deliberate starts; policy reconnects use scoped
allowances. Certificate material comes from an independent OpenSSL fixture CA.

This implementation covers HTTP profiles, including HTTP/2 and application
WebSockets. TCP and dedicated TLS now share connectors too; see
`SHARED-STREAM-CONNECTORS.md`. UDP shares one socket with pinned peers; see `SHARED-UDP-CONNECTORS.md`. Each CLI still handles its own origin-pool
selection. Managed connector observations expire locally after 15 seconds or the
remaining probe-age allowance (maximum of 20 seconds and twice the configured
interval plus timeout), whichever comes first. Poll transit counts toward age;
missing reports become unknown. Cloud publication failure cannot refresh or
block local selection. Standalone connectors without these hosted observations
remain unknown and retain channel-based round-robin. Per-connector forwarding limits remain bounded;
adding connectors increases a profile's aggregate concurrency.

The public address in this fixture belongs to one relay. Cross-relay ingress and
failure of that relay still require a distributed routing design. OIDC sessions
remain relay-local; distributed ACME challenge coordination and private IP/subnet
networking remain separate work. No production deployment or external-network
claim is made.

Protocol remains 8; no wire change is introduced. Use the current relay build with
Worker migration 0023 and its matching API. The old profile-only Worker conflict
target cannot serve the composite lease schema. Preserve relay usage journals
and follow the existing coordinated rollout contracts.
