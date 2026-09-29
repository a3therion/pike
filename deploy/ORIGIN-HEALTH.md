# Cloud origin health

Matching **protocol-8** relay/CLI builds can publish HTTP origin health to the hosted dashboard. Apply Worker migrations through `0022_origin_health.sql`, update Workers and the dashboard, and roll out matching relay/CLI builds together. Older and unversioned connectors are rejected at login. ALPN remains `pike/1`; quota protocol 1, visitor-policy protocol 4 and domain protocol 1 are unchanged. No deployment is performed by these source changes.

Every five seconds the authenticated relay polls the current connector. A report contains at most 16 observations, ordered exactly like the saved configuration: a nullable success result and its monotonic age. It contains no origin address, path, credentials or provider error. A single local-port or Unix origin is one member even though canonical `origins` is empty. Single origins without an explicit health path remain **Not checked**; forwarding success is not substituted for a health probe.

Responses must match a pending, session-local nonce and arrive within three seconds. The relay conservatively adds the entire poll round trip to observation age, including transport queuing. Duplicate, late and unrelated responses cannot satisfy the poll. Invalid member counts or inconsistent observations end the offending connection. Missing responses clear cloud observations. Both transports bound source maps and control queues; snapshot reads neither perform network I/O nor wait for probes.

The relay posts `/api/v1/tunnels/:id/health` with health protocol 1, its current lease ID, send time and report. It uses the owner's tunnel-write API key and the relay server token. Workers conditionally update only an unexpired, enabled lease whose owner, configuration, policy revision and domain revision still match. This endpoint **does not extend the lease or change its heartbeat**. Replacing a lease clears prior health. Health is hidden on disconnected or edited profiles.

Freshness uses Worker time and the relay's send time, reserves five seconds for clock skew, and includes all probe and transport age. Keep relay clocks synchronized; timestamps over five seconds ahead are rejected, and clocks behind produce conservative expiry. Reports expire at most 15 seconds after their conservative publication anchor. Probe results additionally expire after the larger of 20 seconds or twice the configured probe interval plus timeout. Delayed or repeated publication cannot make an old check current. These are observation freshness rules, not an availability guarantee. The dashboard polls connected HTTP details every five seconds and expires displayed results locally every second, including while a tab cannot fetch.

Each CLI's origin pool still selects its own origin. Managed HTTP connectors sharing one relay additionally use the validated, transit-aged reports to prefer members with at least one fresh healthy origin, then unknown/unprobed/stale members, then members whose origins are all freshly unhealthy. Equal-ranked open channels rotate; an all-down CLI returns the existing HTTP 503 or gRPC unavailable response. Local snapshots expire after 15 seconds or the probe-age allowance, whichever comes first, using monotonic time. Missing replies clear local observations; cloud publication failure cannot refresh or block local selection. Replay and existing streams remain pinned. No exchange is retried after application bytes are sent. See `SHARED-HTTP-CONNECTORS.md`; cross-relay forwarding and distributed failover remain pending.

## Local verification

From `pike`, build matching binaries and run the workspace suite and strict Clippy. From `pike-cloud`, run Workers unit tests/typecheck and dashboard lint/build. Then, using Node 24 and Chrome:

```
node workers/scripts/origin-health-runtime-tests.mjs
PLAYWRIGHT_CHANNEL=chrome node workers/scripts/origin-health-e2e.mjs
```

The API fixture uses actual local Worker/D1. The end-to-end fixture uses actual production relay/CLI, independent HTTP origins, both QUIC and forced WebSocket, and the production dashboard build in Chrome. It controls origin failure/recovery, publication outages and delayed publication; verifies disconnect/replacement fencing and unprobed origins; and captures desktop/mobile screenshots. Its relay creation allowance is raised to ten for six deliberate connector starts. It changes no hosted account, DNS record or deployed service. Distributed routing, external-network behavior, hosted D1 cost/capacity and production soak remain unverified.
