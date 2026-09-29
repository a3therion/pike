# Durable usage observations

When both `workers_api_url` and `server_token` are configured, the relay opens
`usage_journal_path` before accepting traffic. The default is
`$STATE_DIRECTORY/usage.sqlite3`, or `data/usage.sqlite3` without that variable.
The systemd service supplies `/var/lib/pike`; containers must retain that
directory in a persistent volume. The journal is local to one relay process or
its replacement, not a shared network filesystem or a cluster-wide queue.

The journal records canonical tunnel and owner UUIDs and observed traffic. HTTP
uses streamed body bytes. Hosted HTTP, TCP/TLS and upgraded WebSocket streams record bytes in
each direction before forwarding each bounded chunk. UDP records whole packet
payloads, including empty packets. Protocol framing used inside the Pike tunnel
is excluded. TLS passthrough counts the encrypted stream, while relay-terminated
TLS counts plaintext application bytes. Minute buckets preserve the observation period during an outage.
SQLite WAL transactions use `synchronous=FULL`. Freezing a batch assigns stable
report IDs and moves its counters into an outbox in the same transaction. Only
a complete Worker acknowledgement removes those rows. A restarted relay sends
the same IDs; the Worker deduplicates them in D1. New observations never get
merged into a batch whose acknowledgement is uncertain.

## Exact guarantee

An observation that has committed locally survives a relay process restart and
an acknowledgement lost after the Worker commits it. This does not guarantee
accounting for bytes not yet observed when the process is killed, lost disks, or
a storage device that violates its synchronization contract. Hosted forwarding
waits for an atomic quota debit and usage observation before admitting each
bounded chunk, packet or opening. Bytes accepted from a socket can be committed even if a later
network write fails; observations are not acknowledgements from the final app.
Request inspection/log ingestion remains a bounded in-memory queue and may
lose recent diagnostic records on an abrupt exit. It is separate from billing.
Each HTTP request, TCP/TLS connection or WebSocket upgrade counts once; each
public UDP datagram counts once. Reply packets and stream chunks do not add
requests. Empty public UDP packets still count.

The legacy HTTP accounting path (without hosted quota enforcement) awaits its
completion observation at EOF and schedules a best-effort commit on cancellation.
Hosted HTTP now commits each bounded body chunk before forwarding; cancellation
cannot discard already committed observations. Trailers remain intact.

## Shared quota recovery

Hosted relays require Worker quota protocol 1. Each account uses finite shared
credits: at most 4 MiB and 16 requests per grant, expiring within 60 seconds or at
the UTC day/month boundary. Quota failures stop forwarding; an unavailable quota
API permits only remaining, unexpired credit. Daily exhaustion rejects new
requests/connections/public UDP packets while existing streams can still consume
bandwidth. Zero bandwidth denies even a new empty admission. An exhausted HTTP
admission returns 429; an unavailable quota service returns 503. A stream that has
already sent headers is terminated when its byte allowance runs out.

Journal schema 2 stores a stable relay identity and pending, active or sealed
grants. Consumption and usage observations commit in one transaction. After a
restart, the relay seals recovered balances and returns only their persisted
unused credit before obtaining a fresh grant. It never restores a full balance
or extends a grant's expiry. Pending reservation/refund IDs survive ambiguous
responses. Idle grants are sealed after ten seconds without consumption and
returned on the five-second maintenance cycle; active grants use conservative
monotonic deadlines derived from the Worker clock and the request round trip.

Schema migration preserves old counters and outbox IDs as unaccounted usage.
New `quota_accounted` observations stay in separate minute buckets and cannot be
merged with old observations. The Worker counts late legacy usage while avoiding
a second debit for already reserved observations. Preserve the database and WAL;
deleting them can lose billing records and leave unused credits conservatively
charged until reset. See the [control-plane contract](../../pike-cloud/workers/docs/QUOTA-CONTRACT.md).

## Backpressure and recovery

The journal bounds pending aggregates and reports to 20,000 rows. Each outbound
batch contains at most 500 rows and each flush attempts at most 40 batches. A
failed disk write or full backlog marks accounting unhealthy and subsequent
ordinary HTTP forwarding returns 503 until a successful journal operation.
Hosted traffic and non-HTTP traffic stop at a failed observation, before that chunk or packet is
forwarded. Journal concurrency is bounded and quota API calls have five-second
deadlines. Standalone relays
without a configured cloud sink retain their existing operation.
Rows remain queued on network errors or incomplete acknowledgements. Existing
minute aggregates can still be updated at the row limit. Review logs for
`usage remains durably queued for retry` and `usage observation could not be
committed`; restore the destination or disk capacity before restarting traffic.

Do not delete the database or its WAL to clear an error: that discards unreported
usage. Keep the same path and exact destination URL across restarts. A journal
opened for a different destination or a newer schema fails closed. Restore the
original configuration or reconcile pending reports before intentionally moving
to a new destination. Use SQLite's backup API for a live backup, or stop the
relay cleanly before copying the database and its associated files. A deployment
must preserve both the database and any uncheckpointed WAL.

## Repeatable local evidence

From the Rust repository:

```sh
cargo test -p pike-server --test usage_journal --test usage_reporter --test usage_identity
cargo run --release -p pike-server --example usage_journal_benchmark
```

For the coupled local stack, keep `pike` and `pike-cloud` beside each other, build
the current Rust release binaries, install the cloud workspace dependencies and
Playwright Chromium, then run from `pike-cloud`:

```sh
node scripts/stack-integration.mjs
```

`PLAYWRIGHT_CHANNEL=chrome` selects an installed Chrome instead. The script uses
isolated temporary D1/KV databases, production frontend bundles on localhost
5173/5174, the repository's development TLS certificate and loopback listeners.
No deployed services are involved. Its recovery test forwards a chunked upload,
kills the relay after the local commit, loses an actual Worker acknowledgement,
kills the relay again, and verifies identical replay with exactly one D1 charge.
The local certificate bypass belongs only to that fixture.

The managed fixture also tests HTTP, WebSocket, TCP, TLS and UDP observations
during a usage-sink outage, kills the relay, restarts it against the same journal,
and compares exact committed totals with real Worker/D1 results. It retries frozen
report IDs to verify no duplicate charge:

```sh
# From pike-cloud/workers, after building the Rust debug binaries:
node scripts/managed-tunnel-e2e.mjs
```
