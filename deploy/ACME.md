# Automatic server certificates

Native HTTPS and terminated raw TLS share an optional ACME HTTP-01 certificate manager. An optional [shared Redis coordinator](SHARED-ACME.md) supports account state, issuance leases, challenges, renewal and certificate distribution across relays. Exact manual certificates remain supported and take precedence. TLS passthrough continues to use the origin's certificate. Visitor mTLS trust and client certificates are separate from this server-certificate lifecycle.

## Configure the relay

Use a CA directory you have selected and reviewed. Start with its staging service, then use a separate private state directory for production. Enabling `terms_of_service_agreed` is the operator's explicit agreement to that CA's terms; tests do not create a production account.

```toml
[public_https]
bind_addr = "0.0.0.0:443"

[acme]
directory_url = "https://acme-staging-v02.api.letsencrypt.org/directory"
contact_email = "operator@example.com"
terms_of_service_agreed = true
storage_dir = "/var/lib/pike/acme-staging"
renew_before_secs = 2592000
retry_secs = 60
```

The relay's existing plaintext `http_bind_addr` must be publicly reachable on **port 80** for HTTP-01. Forwarding port 80 through a load balancer must preserve the exact Host and challenge path. With default local state it must reach the issuing relay; with shared ACME it may reach any participating relay with a current authorized route for that hostname. A private test CA can use its own challenge port. Public DNS A/AAAA/CNAME records must reach this listener. Native HTTPS and raw TLS may use separate ports; this does not change HTTP-01's public validation port.

A hosted custom hostname must first pass the dashboard's independent DNS TXT ownership check. Keep that TXT record in DNS. A standalone operator authorizes exact aliases in `custom_domains` with the local API-key owner's identity. Primary platform names and admitted aliases are eligible only while their connector and visitor gate are active. The manager does not issue wildcard certificates or perform DNS-01. It does not provision public DNS records or issue visitor client certificates.

Only `GET /.well-known/acme-challenge/<exact-token>` on the exact admitted hostname can return the temporary proof without visitor credentials. Unknown tokens, other hostnames, queries and unsupported methods return 404. These paths do not reach the application or its inspection/replay stream. Application Basic/JWT/OIDC/IP/mTLS rules remain in force on ordinary requests.

## Private state and trust

Run the relay as the owner of `storage_dir`. The manager creates a directory with mode **0700** and files with mode **0600** and rejects permissive existing paths and symbolic-link state files. This implementation requires Unix filesystem permissions. Keep state on a local filesystem with working exclusive file locks, atomic rename and fsync. One relay process exclusively locks each local directory. Shared ACME still requires a separate private cache directory per relay; Redis carries coordination state. Do not share the directory between machines, copy live local-only state into concurrent relays, or place it in a publicly served directory.

In local-only mode, account private keys are durably written before the first account-creation request. Shared mode atomically stores the key in Redis first; durability depends on the Redis configuration described in the shared contract. Restart after an ambiguous response reuses the same key. Each certificate and matching private key is stored in one atomically replaced file, scoped to both hostname and owner. Keep encrypted backups of the entire private directory. Corrupt account state is an error; it never silently creates a replacement account. Restoring or switching a CA directory requires deliberate operator action and a separate state directory.

Both CA HTTP connections and issued server certificate chains are verified. The certificate hostname, validity dates, server purpose and matching private key are checked before installation; an expired certificate is refused on new handshakes. Optional `directory_ca_path` and `certificate_ca_path` can add an operator-owned PEM trust bundle for a private CA. Each bundle must contain 1–16 certificates and be at most 64 KiB. Do not configure these to accept an untrusted CA.

ACME directory and resource URLs must use HTTPS and the **same origin**. Redirects and environment proxies are disabled. CA responses are limited to 1 MiB and ten seconds; an issuance job has a 150-second deadline and at most four jobs run concurrently. CAs requiring External Account Binding or resources on a different origin are not supported by this configuration.

## Renewal and failure

Renewal starts at the configured lead time, capped at one third of the certificate's lifetime. Short-lived test certificates therefore do not trigger an immediate renewal loop. A failed attempt keeps the previous still-valid certificate, reports a renewal warning and retries with exponentially increasing delays, capped at one hour. Local-only backoff is process-local; keep the state directory intact and avoid repeated restarts during CA outages or rate limiting. Shared mode persists backoff across issuing relays and restarts. Provider rate limits still apply; this implementation does not automatically switch CAs or solve challenges by another method.

A valid cached certificate can serve after relay restart while the CA is unavailable. Invalid, expired, mismatched-key, wrong-host and wrong-owner cache entries are never served. Active DNS ownership expiry or connector withdrawal hides pending challenges and prevents certificate access/installation. Files may remain for recovery but do not authorize a disconnected or reassigned hostname. A successful renewal affects subsequent TLS handshakes; established encrypted connections retain their existing session until ordinary stream, policy, ownership or connection lifetime ends.

Manual certificates are reloaded for new handshakes and must have an exact owner assignment. Invalid manual files fail closed; ACME does not silently replace a manually configured hostname. The same hostname on native HTTPS and raw TLS must use the same manual owner and material paths.

## Dashboard and rollout

Apply migrations through **0021_certificate_status.sql** and update Workers before the relay. Domain protocol remains 1, visitor-policy protocol 4, quota protocol 1 and connector wire protocol 8. The authenticated relay sends bounded certificate observations with its existing 25-second lease heartbeat. Only its live, owner-scoped lease may update these observations. A relay-triggered lease reset grants one 90-second reconnect allowance per existing owner/hostname/tunnel identity, so policy/domain edits do not consume another creation allowance. Normal authentication, bans, ownership checks and concurrent-tunnel limits still apply; new identities cannot use that allowance. A new connector clears old readiness; expired or changed leases and expired DNS ownership do not advertise usable alias certificates.

Settings → Custom domains shows pending, ready (automatic or operator managed), unconfigured, error, expiry and renewal warning. DNS verified is separate from certificate ready. Reports are observations, not synthetic HTTPS probes: the UI shows the last report time and withdraws readiness at certificate expiry or after the 90-second lease horizon. Public routing, firewall and frontend health still need operational checks.

## Reproduce local proof

From `pike`, build with `cargo build --offline -p pike-server -p pike`. From `pike-cloud/workers`, run:

```sh
node scripts/acme-e2e.mjs
PLAYWRIGHT_CHANNEL=chrome node scripts/acme-hosted-e2e.mjs
node scripts/certificate-status-runtime-tests.mjs
```

The fixture uses digest-pinned Pebble and challenge-server images, real HTTP-01 validation, production relay/CLI binaries, a private test CA and disposable state. It never enables Pebble's validation bypass. The standalone suite covers both transports, renewal, restart, CA outage, expiry, recovery and invalid cache rejection. Hosted tests add actual Worker/D1, DNS proof, lease-authenticated status and the production dashboard. These are local short-lifetime tests; public CA interoperability, public DNS/port reachability, deployment and a production renewal soak remain unverified.
