# Telephony Media Harness

`telephony_media_harness.mjs` is a dependency-free Node.js harness for sending
20 ms audio-style WebSocket frames to a media endpoint and reporting RTT,
jitter, dropped frames, and reconnect behavior.

It expects Node.js 22 or newer for the built-in WebSocket client.

Run a local echo self-test:

```bash
node scripts/telephony_media_harness.mjs --local-echo --duration 5s
node scripts/telephony_media_harness.mjs --local-echo --duration 5s --mode binary
```

Run against a relay or provider WebSocket endpoint:

```bash
node scripts/telephony_media_harness.mjs \
  --url wss://relay.example.com \
  --path /media \
  --duration 2m \
  --interval 20ms \
  --payload-size 160 \
  --mode text
```

Useful options:

- `--mode text` sends JSON frames with a base64 media payload. `--mode binary`
  sends raw binary frames of exactly `--payload-size` bytes.
- `--payload-size 160` approximates a 20 ms G.711 frame. Use `320` for 20 ms
  of 8 kHz 16-bit PCM.
- `--drop-after 2s` controls how long a sent frame can remain unacknowledged
  before it is counted as dropped. RTT requires the endpoint to echo the frame.
- `--no-reconnect` disables reconnect attempts. By default, reconnect attempts
  continue until the bounded `--duration` elapses.
- `--json` prints a machine-readable final report.
- `--local-echo --echo-tls --cert cert.pem --key key.pem --insecure-tls` can be
  used for local `wss://` testing with a self-signed certificate.
