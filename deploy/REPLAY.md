# HTTP inspection, modification and replay

Replay sends an explicit HTTP request through an owned, active tunnel. The relay
uses the same forwarding, origin-pool selection, abuse checks and shared quota
accounting as ordinary public traffic. It does not accept a destination URL or
caller-selected Host. Admission captures the tunnel connection once; a hostname
reassignment cannot redirect the authorized request to another connector.

## Dashboard

Open the tunnel's Traffic tab, inspect a request, then choose **Edit and replay**.
Edit the method, relative path/query, headers and body. The body editor accepts
UTF-8 or base64 for binary data. Captured credentials remain redacted; replace or
remove those headers and supply any missing, binary or truncated body before
sending. The form requires an explicit acknowledgement that the body is complete.

Sending can change application data. Each click sends once; the UI disables the
button during the exchange, and neither the relay nor CLI follows redirects or
retries an operation after application bytes have been sent. A failed response or
timeout does not establish whether the origin processed the request. Check the
application before manually repeating a write.

The result includes the origin status, response headers/trailers, duration and
up to 64 KiB of response bytes. It is available only to the authenticated caller
and is not stored as an unredacted inspection record. Normal request history
continues using the configured redaction and bounded previews. Response cookies
are JSON data, not Set-Cookie headers on the dashboard response.

## Local inspector

`pike http` and saved HTTP profiles print an **Inspector access** link containing
a fresh random capability in its URL fragment. Open that complete link. The page
removes the fragment immediately and keeps the token only in memory. Refreshing
requires opening the access link again; it is not saved in cookies or local
storage. Treat the complete link as a credential for that running inspector.

Capture lists, origin status, the event stream, clearing history and replay all
require the capability as a bearer header. The listener binds to loopback and
rejects foreign Host/Origin values. Responses are not cached or frameable. The
page uses local assets only. Closing the CLI invalidates its inspector access.
The inspector retains the connector's API key internally and uses the same
owned-tunnel replay endpoint as the dashboard.

Open a captured request, select **Edit and replay**, then edit its JSON draft.
Routing/framing headers are removed when creating the draft. Redaction markers
are rejected by the relay instead of being sent as application credentials.

## CLI

```sh
pike replay my-saved-profile --file request.json
# A runtime/cloud UUID also works. Override the HTTP listener for custom setups:
pike replay 00000000-0000-0000-0000-000000000001 \
  --file request.json --relay-url https://relay.example
```

`request.json` contains a complete explicit body; an empty string means zero bytes:

```json
{
  "method": "POST",
  "path": "/items?mode=preview",
  "headers": [{"name": "content-type", "value": "application/json"}],
  "body_base64": "eyJuYW1lIjoiZWRpdGVkIn0="
}
```

The CLI resolves saved profile names through the configured Worker API. The
relay HTTP origin defaults to `relay.ws_url` with an HTTP(S) scheme, or
`https://<relay.addr>` when no WebSocket URL is configured. It verifies HTTPS
certificates, refuses embedded URL credentials and refuses plaintext credential
transport except explicit loopback development. It does not inherit the QUIC
certificate-verification development override. The configured API key must have
`tunnels:write`; standalone relays use their configured local keys.

## Relay interface and limits

`POST /api/v1/tunnels/<cloud-or-runtime-uuid>/replay` accepts the JSON draft and a
bearer credential. Hosted credentials are freshly validated by Workers for every
operation, including session/key revocation and the `tunnels:write` scope. The
live registry must still identify the same owner. In development mode the replay
credential must match the connector's key; the read-only dashboard dev bypass
does not grant replay access. Missing, disconnected or foreign-owned HTTP tunnels
are rejected. TCP/UDP/TLS endpoints cannot be replayed as HTTP.

- Standard HTTP methods GET, POST, PUT, PATCH, DELETE, HEAD and OPTIONS.
- Relative path/query only, at most 8 KiB; no scheme, alternate authority or fragment.
- At most 100 supplied headers totaling 16 KiB. Host, Content-Length, hop-by-hop,
  forwarding, proxy-authentication and WebSocket-upgrade headers are rejected.
- Explicit base64 request body, at most 64 KiB; JSON draft at most 128 KiB.
- Eight concurrent relay replays; two per local inspector. Request-draft read
  timeout five seconds; total forwarding/response deadline 30 seconds.
- Response capture stops at 64 KiB and cancels the remaining stream, with
  `truncated: true`. Exactly 64 KiB is accepted without a truncation claim.
- An HTTP 200 interface response contains the actual forwarded status in `status`,
  including quota 429 or origin errors. Authentication/validation failures use
  the interface HTTP status with an error message. Responses use `Cache-Control: no-store`.

The ordinary HTTP upload ceiling remains **200,000,000 bytes**. Replay is a
bounded inspection operation; it does not capture or silently reconstruct large
uploads, missing secrets, continuous WebSocket sessions or arbitrary TCP/UDP
protocol conversations. Raw responses and explicit drafts can contain secrets;
normal redacted history is not a source for recovering removed credentials.

## Verification

`node scripts/replay-e2e.mjs` in `pike-cloud/workers` runs local workerd/D1/KV,
production-mode relay/CLI processes, an independent HTTP origin, Chrome against
the shipped inspector and a production dashboard build. The fixture exercises
QUIC and forced WebSocket fallback; its results live in the workspace's
`reports/feature-delivery-2026-09-20/replay-e2e.json` after a passing run.
Standalone local-key replay is part of the Rust origin-pool fixture. These checks
are local evidence, not a production deployment or external-network claim.
