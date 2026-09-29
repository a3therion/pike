# Custom hostnames

HTTP and TLS tunnels can serve exact custom hostnames. Every alias uses the same connector, visitor policy, canonical usage identity and quota as its saved profile. HTTP routing no longer falls back to the first DNS label.

Hosted ownership, alias forwarding and the dashboard have local end-to-end evidence. Native HTTPS and terminated raw TLS support operator-provisioned certificates or optional [ACME HTTP-01 issuance and renewal](ACME.md). TLS passthrough uses the origin's certificate.

## Hosted setup

1. Apply Workers migrations through `0021_certificate_status.sql` after the preceding migrations. Deploy the compatible Workers API and dashboard before the new relay. This is a rollout instruction; no deployment is implied by the repository tests.
2. Set Workers `TUNNEL_BASE_DOMAIN` to the relay's `domain` when it differs from `pike.life`. The platform zone and all its descendants cannot be claimed as custom domains. Workers defaults to the verified-HTTPS resolver `https://cloudflare-dns.com/dns-query`; `DOMAIN_DOH_URL` may select an operator-owned DNS JSON resolver. Redirects, malformed answers and failed lookups never prove ownership. Plain HTTP resolvers are accepted only on loopback in the explicit test environment.
3. Open a tunnel's **Settings → Custom domains**, add its hostname, and publish the displayed `_pike-verification.<hostname>` TXT record. Keep the record in DNS. Click **Verify DNS** after propagation. Point the hostname to the primary endpoint with a CNAME, or the relay's A/AAAA addresses when CNAME is unavailable. DNS proof does not establish public routing or HTTPS readiness.
4. Configure [automatic certificates](ACME.md), or for native HTTPS add an exact hostname and the tunnel owner's user ID under `public_https.certificates`. For terminated raw TLS, use `public_tls.certificates`. The certificate must cover the custom hostname and the relay must be able to read its private key. Never place private keys in a tunnel profile or the ownership API. Existing operator certificate replacement on new handshakes remains supported.
5. Start the profile with `pike start <name>`. A verified assignment is loaded on a new endpoint claim. Changes invalidate its previous endpoint lease; the existing connector checks every 25 seconds, closes captured work and reconnects. A removed hostname cannot be routed by the new connection. Other profiles remain independent.

An unverified claim does not reserve a name across tenants. Only one verified assignment can own a hostname. Up to 16 names are allowed per profile. Only HTTP and TLS profiles accept aliases; arbitrary TCP and UDP ports are unchanged. Claims are owner-scoped and require the ordinary tunnel read/write key scopes.

Verification lasts at most 24 hours. Scheduled verification runs every five minutes, considers records last checked over an hour ago, and refreshes at most 100 candidates with four concurrent lookups per invocation. Oldest records go first, including after failed lookups. Resolver failures never extend a grant. The relay cancels active alias HTTP, WebSocket and raw TLS streams at their ownership deadline even between heartbeat checks; a later snapshot that removes a hostname also ends the old lease. Reverify an expired assignment to activate it again. This bounded refresh budget has not been production-load tested and must be sized for the deployed domain count.

Browser OIDC sign-in uses one configured callback origin per profile. Its `redirect_uri` can use a verified custom hostname. Configure the identity provider for that exact HTTPS callback. Host-only cookies and sessions are not shared across aliases; requests on another origin fail closed. Basic, JWT, IP and mTLS policies continue to use the profile's common visitor gate.

## Standalone setup

A relay operator can authorize names without Workers or DNS API storage:

```toml
[custom_domains."preview.pike.example.com"]
owner_user_id = "local-<sha256-of-the-allowed-api-key>"
hostnames = ["preview.customer.example.com"]

[[public_https.certificates]]
hostname = "preview.customer.example.com"
owner_user_id = "local-<sha256-of-the-allowed-api-key>"
cert_path = "/etc/pike/customer/fullchain.pem"
key_path = "/etc/pike/customer/key.pem"
```

Use the same owner identity as operator certificate configuration: `local-` followed by the lowercase SHA-256 hex digest of the local API key. The configured primary must be in the relay's platform zone. Duplicate assignments, malformed names, platform-zone aliases, missing owners and more than 16 names per profile are rejected. Another valid local key cannot claim this assignment. Standalone configuration is not accepted as an override for hosted ownership. Restart the relay after changing an assignment; active connections are closed during shutdown.

The operator controls both public DNS and TLS material. Operator-authorized names last for that running configuration; hosted DNS leases are a separate authorization source. QUIC and forced WebSocket both support standalone aliases.

## Version and evidence boundaries

The connector wire protocol is **8**, quota protocol **1**, visitor-policy protocol **4**. Domain assignment protocol **1** is now required by this relay for hosted claims and renewals. The updated Worker accepts older domain-unaware relays only on profiles with no verified custom names. Apply the migration and Worker update before rolling out the new relay; an old Worker cannot acknowledge its domain protocol.

Local fixtures exercise real workerd/D1, an independent DNS JSON server, the production relay/CLI, verified HTTPS, HTTP/2, WSS, raw TLS and TLS passthrough. They test ownership competition, stale replies, assignment revisions, expiry, renewal, canonical usage and desktop/mobile dashboard setup. Separate independent Pebble fixtures exercise automatic issuance, renewal, restart, CA outage, invalid cache rejection and authenticated dashboard readiness. Public DNS, external CA interoperability/reachability, production renewal soak and deployment remain unverified.
