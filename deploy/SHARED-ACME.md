# Shared ACME coordination

Automatic HTTP-01 certificates can use Redis to coordinate issuance, renewal, challenge responses and account state across relays. Each relay keeps its own private, exclusively locked local cache directory and independently verifies shared certificate material. Manual certificates continue to take precedence. The default ACME backend remains local files and memory.

```toml
[acme]
directory_url = "https://acme-staging-v02.api.letsencrypt.org/directory"
contact_email = "operator@example.com"
terms_of_service_agreed = true
storage_dir = "/var/lib/pike/acme-this-relay"
renew_before_secs = 2592000
retry_secs = 60

[acme.shared]
redis_url = "rediss://pike:REPLACE_WITH_SECRET@redis.example.com:6379/0"
namespace = "production"
```

Use the same namespace, CA directory, contact and trust settings on participating relays. The namespace allows 1–64 ASCII letters, digits, underscores or hyphens. Keys are additionally scoped to the complete CA directory URL, so separate staging and production directories do not share account or certificate state. `rediss://` verifies server certificates; insecure TLS fragments are rejected. `redis://` is supported for a protected local/private connection.

## Authority and routing

Each relay must already have a current, owner-bound route for the requested hostname. Its visitor gate and any DNS ownership grant must be active. Redis records do not create routes, prove DNS ownership or authorize a different owner. An eligible relay can answer the same exact HTTP-01 challenge as the issuer, even though it did not create the order. Unknown hosts/tokens, expired issuance leases, unsupported methods and queries fail closed without forwarding to the application.

Public port 80 must reach these authorized relays with the original Host and challenge path. This is shared certificate coordination, **not automatic public ingress routing or failover**. A frontend must select reachable relays that have the hostname's active route. The deployment-topology restriction remains `single-node`; the local fixture deliberately addresses two processes. Private routing and multi-node public ingress require their own implementation and proof.

Only a current per-host issuance lease can publish a proof or commit a certificate. The lease lasts 15 seconds and renews every five seconds. Redis operations have a two-second deadline; a failed renewal cancels the local issuance job. Lua atomically checks the random lease token, owner and record version. A successor cannot be overwritten by an expired job, and delayed cleanup cannot delete its lease or challenge. A process crash leaves at most the remaining lease lifetime before takeover, plus scheduling/issuance time. An already in-flight CA request may finish after a crash or partition; fencing prevents that stale job from publishing its result. It is not an exactly-once guarantee for external CA operations.

## Shared state and bounds

The account key is inserted atomically **before** the first account-creation request. Competing initializers read the winning key; promotion to account credentials uses compare-and-set and cannot replace a different account generation. Each issuance reloads the shared account record; there is no local account fallback during Redis failure. Corrupt shared account data is rejected.

Certificate records include the exact hostname and owner. Every importing relay checks the chain, hostname, validity, server purpose and matching private key against its configured roots before installation. Healthy relays check for changed certificates every five seconds; a coordination error can delay the next check by up to 30 seconds. An existing TLS connection retains its original handshake. Current local authority is checked before import, persistence, challenge response and use.

At most 16,384 hostname records are indexed per namespace/CA directory. Records have bounded 128 KiB serialization; certificate parsing retains its separate 64 KiB chain and 16 KiB key limits. Records normally remain until one day after certificate expiry, with a 400-day retention ceiling; unfinished jobs/backoff records retain a one-day recovery window. The account record does not expire. Each relay runs at most four certificate jobs, uses an eight-connection Redis pool and admits at most four simultaneous public challenge lookups, leaving pool capacity for coordination. The existing CA HTTP and 150-second job deadlines still apply.

Shared records contain **account and certificate private keys**. Keep Redis private, use authenticated verified TLS where needed, restrict its ACLs to trusted relay operators and encrypt durable storage/backups. Redis durability, eviction policy, replication/failover consistency and capacity are operator responsibilities; a successful Redis write is not a guarantee that an asynchronous replica or disk has persisted it. Do not restore stale authentication/issuance snapshots into a live deployment. Account-state loss can require deliberate account recovery and may otherwise create a new CA account. Redis Cluster routing is not implemented by this client. Synchronize the clocks of relays, Redis and the CA.

## Outages and ownership changes

A coordination failure prevents new issuance, shared challenge responses and unverified cache imports. An already validated, unexpired local certificate can continue serving while Redis or the CA is unavailable, but only with current local route/owner authority. TLS material is refused at expiry even if the visitor disables certificate verification. Shared renewal failures keep the previous certificate and persist exponentially increasing per-host retry time, capped at an hour, so restarting or changing the issuing relay does not bypass CA backoff. A relay imports an existing valid shared certificate before considering that backoff.

Hostname withdrawal and DNS expiry cancel the local job and hide local challenge access. Cleanup is fenced; if the issuer cannot reach Redis, the challenge and lease expire. Control-plane ownership/policy changes retain the existing lease-refresh observation window. The shared store does not provide a stronger instantaneous control-plane revocation guarantee.

## Local evidence

`pike-cloud/workers/scripts/shared-acme-e2e.mjs` uses real password-protected Redis, digest-pinned Pebble with actual HTTP-01 validation, two production relays, real QUIC and forced WebSocket CLIs, native HTTPS, raw TLS and independent visitor mTLS. Its frontend requests each proof from both relays and checks matching responses before returning a valid response to Pebble. Validation bypass is never enabled.

The fixture also exercises renewal convergence, Redis outage, issuer SIGKILL and lease takeover, fresh-cache rejection of wrong-owner/mismatched-key shared records, offline cache recovery, shared CA backoff, certificate expiry and recovery. The separately executed `shared_acme_redis_contract` tests atomic account initialization, per-host exclusion, stale-write/cleanup fencing, challenge isolation and the index capacity guard. Existing standalone and hosted suites cover the default storage path and Worker/dashboard ownership/readiness behavior.

```sh
cd pike
cargo build --offline -p pike-server -p pike
cd ../pike-cloud/workers
node scripts/shared-acme-e2e.mjs
```

These are local, short-lifetime tests. Public CA interoperability, external port/DNS reachability, production Redis failover/load/soak behavior and deployment remain unverified.
