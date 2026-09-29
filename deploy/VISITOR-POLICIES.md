# Visitor access: Basic, JWT, OIDC, mTLS and IP rules

These controls are separate from connector API keys and dashboard sessions. Basic and JWT authentication protect HTTP (including WebSockets and replay) and IP/CIDR restrictions for HTTP, TCP, UDP and both TLS modes. OpenID Connect browser sign-in protects HTTPS application traffic. Visitor mTLS protects native HTTPS and terminated raw TLS, and can be combined with one HTTP sign-in method. A TLS origin certificate is separate from visitor authentication.

## Hosted setup and rollout

Apply Worker migration `0019_visitor_policies.sql`, deploy the Worker API, then install the matching relay and dashboard. The connector wire version is 8. New relays require visitor-policy protocol 4 acknowledgements from Workers. The Worker accepts protocols 1–4 for Basic/IP policies, 2–4 for JWT and 3–4 for OIDC. mTLS requires protocol 4 for both claim and renewal. Old relays cannot claim a profile with a saved policy, and their existing lease fails renewal when a policy is saved. This is a coordinated rollout; no deployment is performed by the local checks.

Open a tunnel's **Settings → Visitor access**. Enter allowed/denied IPs and, for HTTP, Basic users. Denied addresses take precedence. Disabled allow-list filtering means unrestricted IPs; an enabled but empty allow list denies everyone. Each list accepts at most 64 CIDRs; IPv4-mapped IPv6 peers match IPv4 rules. IPv6 `::/0` does not include IPv4 peers. Basic accepts up to eight unique users with 12–1024-byte passwords. A blank password preserves that existing username's hash. Removing all Basic users disables the Basic challenge.

Owner API: `GET` and `PUT /api/v1/tunnels/{id}/visitor-policy`, requiring `tunnels:read` and `tunnels:write` respectively for API keys. PUT supplies the current `revision` and the complete `policy`; a concurrent edit returns 409. GET/PUT responses expose usernames but never passwords or hashes. Origin configuration and CLI profile downloads contain no visitor secrets. The trusted relay receives salted PBKDF2 hashes in its owner-and-server-authorized endpoint lease. Requests are bounded to 64 KiB before parsing; password verification has a relay-wide limit of eight concurrent blocking jobs.

```json
{
  "revision": 0,
  "policy": {
    "allow_cidrs": ["203.0.113.0/24", "2001:db8::/32"],
    "deny_cidrs": ["203.0.113.7/32"],
    "basic": [{ "username": "reviewer", "password": "replace-with-a-long-random-password" }]
  }
}
```

A relay gate remains closed until its authoritative lease and policy validate. Every 25 seconds, renewal checks the exact policy revision. Changes close the old gate, directly cancel active HTTP bodies and stream/datagram tasks, and cause the connector session to disconnect and reconnect with fresh policy. Renewal requests time out after five seconds; failures close admission. This is bounded polling, not instantaneous revocation. The report records observed established-session cleanup under local tests; it is not a production latency SLA.

## HTTPS and trusted reverse proxies

Basic credentials and JWT bearer tokens require HTTPS, provided by the native listener below or an authenticated HTTPS frontend. By default it ignores caller-supplied forwarding identity headers and refuses visitor authentication over plaintext, including loopback.

If nginx terminates TLS locally, put this setting at the top level of relay TOML and configure the frontend to **overwrite**, never append, these headers:

```toml
trusted_http_proxies = ["127.0.0.1/32", "::1/128"]
```

```nginx
location / {
    proxy_pass http://127.0.0.1:8080;
    proxy_set_header Host $http_host;
    proxy_set_header X-Real-IP $remote_addr;
    proxy_set_header X-Forwarded-Proto $scheme;
    proxy_request_buffering off;
}
```

Integrate those identity settings with the deployment's existing HTTP/2/WebSocket forwarding configuration. Keep port 8080 private. Trust only the immediate frontend network, and ensure any upstream CDN's real-client-IP configuration is independently correct. Missing, duplicate or malformed identity headers from a configured trusted proxy return 400. Never copy a client-supplied `X-Real-IP`, `X-Forwarded-For` or `Forwarded` value into these authoritative fields.

The relay strips consumed Basic credentials and JWT bearer tokens, removes spoofed `X-Pike-Visitor-*` and `Forwarded` fields, and replaces IP/protocol headers with its resolved identity before HTTP or WebSocket forwarding. Without an authentication policy, ordinary application Authorization is preserved. Replay must supply visitor credentials in its explicit draft and must pass the caller's IP rules; management authorization grants no visitor bypass.

Only local fixtures may opt into plaintext visitor authentication with `allow_insecure_loopback_visitors = true`. This works only when the direct socket peer is loopback and is not a configured trusted proxy. It does not mark the request HTTPS. Do not enable it behind a production loopback proxy.

TCP/UDP/TLS IP admission uses the actual socket peer; HTTP proxy headers are irrelevant. TLS denial happens before origin forwarding (the public TLS handshake may already complete). Policies do not inspect datagram contents or implement private subnet routing.

## Standalone relay configuration

Self-hosted relays without Workers can configure policies by exact public hostname in TOML. Edits require a relay restart, which disconnects old sessions. Protect the file like other server secrets; password hashes are sensitive. For TCP/UDP give the connector an explicit name so the policy can target that hostname. Unsupported Basic policies on raw protocols fail registration.

```toml
[visitor_policies."preview.example.com"]
allow_cidrs = ["203.0.113.0/24"]
deny_cidrs = []
# Omit allow_cidrs for unrestricted source IPs; [] denies everyone.
[[visitor_policies."preview.example.com".basic]]
username = "reviewer"
password_hash = "pbkdf2_sha256$100000$BASE64_32_BYTE_SALT$BASE64_32_BYTE_SHA256_KEY"
```

Generate a compatible hash locally without putting the password in command history:

```sh
python3 - <<'PY'
import base64, getpass, hashlib, secrets
password = getpass.getpass('Visitor password: ').encode()
salt = secrets.token_bytes(32)
key = hashlib.pbkdf2_hmac('sha256', password, salt, 100000, 32)
print('pbkdf2_sha256$100000$' + base64.b64encode(salt).decode() + '$' + base64.b64encode(key).decode())
PY
```

The Basic format follows [RFC 7617](https://www.rfc-editor.org/rfc/rfc7617.html). Local fixtures prove behavior through the current binaries and actual Worker/D1; external frontends and deployed networks still need their own verification.


## JWT bearer tokens

In **Settings → Visitor access**, select **JWT bearer token**. Choose exactly one signing algorithm (`RS256` or `ES256`), the exact issuer and audience, and an HTTPS JWKS URL. Basic and JWT cannot be combined; IP rules still apply. Optional token type matching distinguishes access tokens (for example `at+jwt`) from other JWTs. The relay requires nonempty `sub`, exact `iss`, matching string/array `aud`, integer `iat` and `exp`, a currently valid `nbf` when supplied, and a lifetime no greater than the configured maximum (60–86,400 seconds, default 3,600). There is no clock-skew allowance. Keep relay and issuer clocks synchronized.

Required scopes must all occur in a space-separated `scope` claim or string-array `scp`. Up to 64 explicitly revoked `jti` values may be configured. A saved policy change uses the existing revision/reconnect path. Omitted `jwt` in an older API client's edit preserves the existing JWT policy; explicit `jwt: null` removes it. Example API policy:

```json
{
  "allow_cidrs": null,
  "deny_cidrs": [],
  "basic": [],
  "jwt": {
    "issuer": "https://identity.example.com/",
    "audience": "my-preview",
    "jwks_url": "https://identity.example.com/.well-known/jwks.json",
    "algorithm": "RS256",
    "token_type": "at+jwt",
    "required_scopes": ["preview:read"],
    "revoked_jti": [],
    "max_lifetime_secs": 3600
  }
}
```

JWT signatures use `jsonwebtoken` 11.1 with AWS-LC. Rust 1.88 or later is required. Tokens are limited to 16 KiB and must identify a signing key with `kid`. Header algorithms cannot override the policy; symmetric keys, `none`, token-supplied JWKS/JWK URLs, critical extensions and unencoded payloads are rejected. The relay consumes and removes the bearer token before origin forwarding and capture. Replay drafts must supply a separate visitor token. Active HTTP bodies, gRPC streams and application WebSockets share the request's authorization deadline and are interrupted at token expiry. Expiring one token does not revoke other visitors.

### Key retrieval and private identity providers

Key retrieval uses certificate-verified HTTPS, no redirects and no environment proxy. Requests have a two-second connect and three-second total deadline. Documents are bounded to 64 KiB/64 keys. RSA verification keys require 2048–8192-bit byte-aligned moduli; EC keys require P-256. Duplicate supported signing-key IDs are rejected. Thirty-two JWT validations and eight key fetches may run concurrently per relay; there are at most 256 active key sources. Excess work returns 503.

By default, both literal addresses and the actual DNS addresses passed to the connector must be public. The conservative filter denies private, loopback, link-local, multicast, documentation and special-use ranges; IPv6 allows global unicast with special-range exclusions. Tenant policy cannot disable this check. To permit a private identity provider, an **operator** can pin one exact canonical URL, optionally with an additional CA certificate, at the top level of server TOML:

```toml
[[visitor_jwks_sources]]
url = "https://identity.internal.example/keys"
allow_private_network = true
ca_path = "/etc/pike/private-identity-ca.pem"
```

The override applies only to that URL and never disables hostname or certificate verification. A CA override without `allow_private_network = true` still enforces public addresses. Standalone tunnels use the same JWT fields in `[visitor_policies."preview.example.com".jwt]`; hosted JWT settings come from the authoritative Worker lease.

Successfully retrieved keys are cached for at most 60 seconds, shortened by `Cache-Control: max-age`, `no-cache` or `no-store`. A missing key ID or signature mismatch can trigger a refresh at most once per five seconds; failed fetches back off for five seconds. A failed early refresh preserves still-unexpired keys; it does not extend their lifetime. Expired keys are never used during an outage. Shorter issuer cache lifetimes shorten key-removal detection, at the cost of more requests. Removed keys are checked on new requests; established streams retain their already-verified token until expiry or a local policy revision. Issuer-side per-token revocation is **not** discovered by offline signature verification: use short-lived tokens, local `jti` revocation, or remove the signing key. No token introspection is performed by JWT authentication. OIDC browser sign-in is a separate policy mode described below.

Validation follows [JWT best current practices (RFC 8725)](https://www.rfc-editor.org/rfc/rfc8725.html), using [JWT claims (RFC 7519)](https://www.rfc-editor.org/rfc/rfc7519.html) and [JWK sets (RFC 7517)](https://www.rfc-editor.org/rfc/rfc7517.html).


## OpenID Connect browser sign-in

Select **OpenID Connect browser sign-in** in **Settings → Visitor access**. Configure the exact issuer, client ID, HTTPS callback `https://<public-host>/.pike/auth/callback`, signing algorithm and client authentication method. Register that exact callback with the provider, including any nonstandard port. The trusted frontend must preserve the public Host and port. OIDC cannot be combined with Basic or JWT; IP rules still apply. This implements OIDC authorization-code flow, not arbitrary OAuth-only services.

The relay discovers the provider over verified HTTPS, requires code flow, uses PKCE S256, and checks signed ID tokens for exact issuer, client audience, subject, nonce, issued-at and expiry. An `azp` claim must match the client ID; additional untrusted audiences are rejected. `at_hash` and `c_hash` are checked when present. RS256 and ES256 are supported. ID tokens and the provider's supported signing keys must include matching `kid` values. Tokens have no clock-skew allowance and may span at most 24 hours. Public PKCE clients, `client_secret_basic`, and `client_secret_post` are supported. No refresh token, userinfo request, provider logout or background token introspection is used.

A subject allowlist and a verified-email allowlist may each contain up to 64 exact values. `null` permits any value; an empty list denies everyone. When both are configured, both must match. Email filtering requires `email_verified: true`. Matching is case sensitive, including email addresses. API example:

```json
{
  "revision": 0,
  "policy": {
    "allow_cidrs": null,
    "deny_cidrs": [],
    "basic": [],
    "jwt": null,
    "oidc": {
      "issuer": "https://identity.example.com",
      "client_id": "pike-preview",
      "client_secret": "supply-through-your-secret-management-workflow",
      "redirect_uri": "https://preview.example.com/.pike/auth/callback",
      "algorithm": "RS256",
      "token_endpoint_auth_method": "client_secret_basic",
      "session_ttl_secs": 3600,
      "allowed_subjects": null,
      "allowed_emails": ["reviewer@example.com"]
    }
  }
}
```

Owner responses contain `client_secret_set` only. A blank or omitted secret retains and reencrypts the existing secret, but changing issuer or client ID requires a new secret. Omitting `oidc` preserves the existing policy; explicit `oidc: null` removes it. The dashboard sends explicit null for modes that are disabled. Public clients use `token_endpoint_auth_method: "none"` and omit the secret.

### Encrypted hosted secrets and rollout

Configure the Worker secret binding **VISITOR_POLICY_KEYS** before saving confidential clients. Its JSON shape is `{"active":"key-2026-09","keys":{"key-2026-09":"BASE64_32_RANDOM_BYTES"}}`. Supply it through the existing deployment secret workflow, never a checked-in Wrangler variable. The keyring supports up to four 32-byte AES keys. D1 stores AES-256-GCM envelopes authenticated to the tunnel ID, issuer and client ID. Only a server-and-owner-authorized protocol-3 relay lease receives the decrypted secret. Missing, retired or mismatched keys fail closed with 503 before leasing an endpoint.

For rotation, install both old and new keys and make the new ID active. Resave each confidential-client policy with its secret blank; this decrypts with the old key and writes a fresh envelope using the active key. Verify all stored envelope key IDs have moved before retiring the old key. Retain required decryption keys in the operator's backup and recovery policy. Rotating the keyring alone does not rewrite existing rows. No database migration beyond 0019 is required for the new JSON policy field; deploy the matching Worker before the protocol-3 relay and dashboard.

### Browser and session boundaries

A top-level HTML GET redirects to the provider; an unauthenticated API request returns 401 with a sign-in link. Reserved routes are `/.pike/auth/login`, `/.pike/auth/callback`, and `/.pike/auth/logout`. Return paths must remain on the configured origin. Authorization state is random, browser-bound, single-use and expires in five minutes. Callback handling and its authorization code are never forwarded to origins or captured as tunnel traffic. Relay HTTP tracing records the path without query strings. Configure external frontend access logs to avoid logging callback queries too.

The relay creates an opaque random session, with a lifetime capped by both the configured 60–86,400 seconds and the ID token's remaining life. `__Host-Pike-Visitor` and the browser-correlation cookie `__Host-Pike-OIDC` are host-only, Secure, HttpOnly, SameSite=Lax and Path=/. These cookies are removed before origin forwarding while application cookies are retained. OIDC always requires trusted HTTPS; the loopback plaintext testing option does not bypass it.

Unsafe HTTP methods and WebSocket upgrades require the exact origin. Cross-origin subresources are rejected, including sibling sites; top-level safe navigation is allowed. GET to logout shows a form. POST requires the exact Origin, clears cookies and revokes that session immediately, including active HTTP and WebSocket work. Expiry does the same. Other sessions remain valid. A saved policy revision cancels the gate at the existing 25-second lease check and invalidates all sessions from the previous revision. Signing-key changes alone do not revoke already-created sessions: use short ID-token lifetimes or a local policy revision. Replay does not inherit the browser's visitor cookies, and management authorization gives no bypass.

By default, sessions live in relay memory, scoped to the profile, revision and complete policy. They survive connector reconnect to that relay; a relay restart, different relay or policy revision requires sign-in again. The optional [shared OIDC store](SHARED-OIDC.md) keeps pending flows and sessions in Redis so callbacks, cookies and logout can cross relays. Its authentication path fails closed during store outages and has separate operational bounds. There are at most 8,192 sessions, 1,024 pending flows (64 per policy) and 32 concurrent login/exchange handlers per relay. Saturation returns 503. Provider discovery caches for five minutes; failures back off for five seconds. Discovery and JWKS GETs have three-second total deadlines, token exchanges ten seconds; HTTPS connections have two-second deadlines. All response bodies are capped at 64 KiB, with eight concurrent identity HTTP requests and no redirects or environment proxy.

The existing safe-address/DNS and certificate checks apply to discovery, token exchange and keys. For a private identity provider, add exact URL entries using `[[visitor_identity_sources]]` for discovery, authorization, token and JWKS endpoints; this is an alias for `visitor_jwks_sources`. Use one array name consistently. `allow_private_network = true` never disables certificate or hostname verification. The authorization URL is a browser redirect but still requires an explicit private-source override. Standalone OIDC uses the same fields under `[visitor_policies."preview.example.com".oidc]`, with a protected plaintext `client_secret` in the operator-owned TOML; the Worker encryption keyring is not used in standalone mode.

Protocol references: [OIDC Core](https://openid.net/specs/openid-connect-core-1_0.html), [OIDC Discovery](https://openid.net/specs/openid-connect-discovery-1_0.html), [PKCE RFC 7636](https://www.rfc-editor.org/rfc/rfc7636.html), and [OAuth security BCP RFC 9700](https://www.rfc-editor.org/rfc/rfc9700.html). Independent local fixtures verify both transports, a real HTTPS frontend/provider, and the production dashboard in Chrome. External provider compatibility and deployed behavior require separate proof.

## Visitor mutual TLS

Enable **Require visitor client certificates** in Settings → Visitor access. Supply the public CA bundle that issues visitor certificates. This is independent of Basic/JWT/OIDC; when a sign-in method is enabled, both proofs are required. Raw TCP, UDP and TLS passthrough reject an mTLS policy. TLS passthrough can still carry the origin's own mTLS exchange without Pike authenticating it.

The relay must terminate the visitor TLS connection itself. Configure an exact application hostname, its owner account ID, and its server certificate/private key:

```toml
[public_https]
bind_addr = "0.0.0.0:443"
[[public_https.certificates]]
hostname = "preview.example.com"
owner_user_id = "owner-account-id"
cert_path = "/etc/pike/preview-chain.pem"
key_path = "/etc/pike/preview-key.pem"
```

This application listener negotiates HTTP/2 or HTTP/1.1 and supports HTTP, gRPC, SSE and application WebSockets. It does not serve dashboard management or connector WebSocket endpoints. Keep those on the existing frontend. HTTP authority must match TLS SNI, the active route must belong to the configured certificate owner, and a connection's proof cannot migrate to a replacement route. Native HTTPS uses the actual socket source IP; trusted-proxy headers do not override it. A TCP-pass-through frontend therefore supplies its own source IP unless a future supported transport carries the real peer identity. Do not configure IP allowlists as though native HTTPS consumes a proxy's HTTP headers.

For raw TLS use the existing `[public_tls]` listener/certificate entries and `tls_mode = "terminate"`. It forwards decrypted bytes to a TCP origin; it does not re-encrypt the origin hop. Server certificate renewal is manual and requires operator action; this feature does not implement custom-domain onboarding or ACME.

The policy object is:

```json
{
  "mtls": {
    "ca_pem": "-----BEGIN CERTIFICATE-----\n...\n-----END CERTIFICATE-----\n",
    "allowed_fingerprints": null,
    "revoked_fingerprints": []
  }
}
```

Combine that object with the other policy fields and the current revision. CA bundles allow 1–8 certificates, at most 16 KiB. The Worker validates PEM syntax and bounds; the relay validates X.509 CA semantics before opening the route. Fingerprint lists allow at most 64 SHA-256 leaf-certificate fingerprints each. API fingerprints use 64 hexadecimal characters; the dashboard also accepts colon-separated fingerprints. `null` allows any client issued by the trusted CA; `[]` denies everyone. Revocation takes precedence over an allowlist. Omission preserves existing mTLS in older clients' edits; explicit `mtls: null` removes it.

Rustls validates the client chain, client-auth usage, validity and private-key possession during TLS negotiation. The relay then checks the fingerprint and caps active HTTP, WebSocket and raw TLS streams at the earliest presented certificate expiry. A saved policy revision cancels the previous gate at the 25-second lease check. Some fingerprint denials close a successfully negotiated TLS connection before any origin connection is opened. TLS resumption and early data are disabled on these listeners, so a resumed session cannot retain an older certificate policy. HTTP certificate headers are never accepted as proof, including from a configured trusted HTTP proxy. Authenticated replay cannot synthesize a visitor TLS connection and is denied on an mTLS-protected endpoint.

No CRL, OCSP or issuer-side revocation lookup is performed. Use the explicit fingerprint revocation list, short-lived client certificates or an operator-managed CA change. Trust anchors are operator/owner supplied; ordinary PKIX trust-anchor handling is not an automatic CA lifecycle service.

Standalone relays use `[visitor_policies."preview.example.com".mtls]` with the same fields (`ca_pem` can be a TOML multiline string; omit `allowed_fingerprints` for any trusted certificate). The certificate owner ID for a local API key is `local-` followed by the lowercase SHA-256 hash of that key. Treat that value as deployment metadata and keep the key private. Changes require a relay restart.

The native HTTPS listener limits concurrent connections to 256, queued accepted connections to 16, ClientHello input to 64 KiB and handshakes to five seconds. Server bundles allow at most eight certificates/64 KiB and keys at most 16 KiB. Client certificate chains allow at most eight certificates/64 KiB. These bounds are per relay, not a distributed admission budget.

Reproduce the mTLS checks from `pike-cloud/workers` with `node scripts/mtls-policy-runtime-tests.mjs`, `PLAYWRIGHT_CHANNEL=chrome node scripts/mtls-policy-e2e.mjs`, and `node scripts/mtls-standalone-e2e.mjs`. The completed browser fixtures used Node 24 and installed Chrome. Build matching Rust binaries first; the fixtures create temporary local services, fresh OpenSSL certificates and local database state, then tear them down. They do not contact a production control plane or publish the report.
