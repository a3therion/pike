# Pike Server VPS Bundle

This bundle targets Linux VPS deployments.

Current public bundle rollout: Linux x86_64 and Linux ARM64.

Included files:
- `pike-server`: relay binary
- `server-vps.toml`: production config template
- `setup.sh`: VPS installation/update helper (preserves existing configuration)
- `pike-server.service`: systemd unit
- `journald.conf`: journald size cap drop-in (see "Logging" below)
- `start.sh`: generic container entrypoint for Docker-based installs

Logging:
- `pike-server` writes to the systemd journal (`StandardOutput=journal`).
  There is no flat `/var/log/pike/server.log` file to rotate.
- View logs with `journalctl -u pike-server -f`.
- Install `journald.conf` to cap on-disk log size (default cap: 500M):
  `sudo install -m 0644 journald.conf /etc/systemd/journald.conf.d/pike.conf`
  then `sudo systemctl restart systemd-journald`.

Important requirements:
- Set a unique `internal_token`.
- Replace the default `local_api_keys` list or point the relay at your own remote control plane.
- Set `server_token` only if you are using a remote control plane.
- Update `redis_url` before first start.

TLS (automated, no manual renewal):
- The relay serves arbitrary subdomains, so it needs a **wildcard** cert (`*.pike.life`),
  which requires a DNS-01 challenge. `setup.sh` provisions and auto-renews it with Certbot's
  Cloudflare DNS plugin (`certbot-dns-cloudflare`) — no more hand-run manual DNS challenges.
- You must provision a Cloudflare API token first:
  1. In the Cloudflare dashboard create an API token with **Zone → DNS → Edit** on the zone.
  2. `sudo install -m 600 -o root -g root /dev/null /etc/pike/cloudflare.ini`
  3. Add one line: `dns_cloudflare_api_token = <YOUR_CLOUDFLARE_API_TOKEN>`
  4. Ensure it stays mode `600` (root-only): `sudo chmod 600 /etc/pike/cloudflare.ini`
- On first run `setup.sh` issues the cert, copies it to `/etc/pike/tls/{cert,key}.pem`
  (root:pike, mode 640), and enables `certbot.timer`. Renewal is unattended: certbot's timer
  renews and a deploy hook (`/etc/letsencrypt/renewal-hooks/deploy/pike.sh`) re-copies the
  certs and reloads `pike-server`.
- Override the domain with `DOMAIN=example.com sudo ./setup.sh` (defaults to `pike.life`).
- Error monitoring (optional): set `SENTRY_DSN` in the service environment (or `sentry_dsn`
  in `server.toml`) to enable Sentry. Unset = disabled (no-op).

Typical systemd install flow:
1. Provision `/etc/pike/cloudflare.ini` (Cloudflare API token, mode 600) — see TLS above.
   Skip this to install your own certificates with the permissions described below.
2. Run `setup.sh` as root on the VPS (installs the bundled binary and issues the wildcard cert when the token file exists).
3. Review and edit `/etc/pike/server.toml`.
4. Start the service with `systemctl start pike-server`.

The installer resolves bundle files beside `setup.sh`, so invocation from another working directory is supported. It installs the binary atomically and preserves an existing `/etc/pike/server.toml`, including tokens and other custom settings. It does not automatically restart the service after an update. The shipped template only generates an internal token on first installation; review remote `server_token`, keys, domain and Redis settings separately.

`/etc/pike/tls` must be owned by `root:pike` with mode `750`; `cert.pem`, `key.pem`, and `/etc/pike/server.toml` use `root:pike` and mode `640`. Renewed certificates must retain these permissions (the certbot deploy hook installed by `setup.sh` does). A symlink to a private ACME directory also requires traversable parent directories; copying certificates into the dedicated TLS directory avoids weakening unrelated directories. The service runs as `pike`, and systemd creates its state and log directories.

For local fixture checks only, set `PIKE_INSTALL_ROOT` to an existing temporary directory. All filesystem writes are prefixed with that directory; user creation, ownership changes, certbot provisioning, and systemd commands are skipped. A prefix of `/` is rejected. This validates bundle layout, modes and preservation without installing a service on the developer machine.

## Protocol 5 streaming and saved-profile rollout

Use matching protocol-5 relay and CLI builds for HTTP streaming. This version rejects protocol-1, protocol-2, protocol-3, protocol-4 or unversioned clients; a rolling rollout needs a separate compatible endpoint for older clients. The relay default is `max_request_body_bytes = 200000000` (decimal bytes, the whole HTTP body including multipart overhead).

Keep reverse-proxy request buffering disabled and ensure any CDN, reverse proxy and origin permit this size. For nginx, use `client_max_body_size 200000000;` and `proxy_request_buffering off;`, with upstream request/response timeouts suited to the link. These are operator instructions, not changes to a live deployment. Local application body I/O expires after 30 seconds without progress; the response-header deadline is 600 seconds.


For hosted profiles, first apply Workers migration `0017_tunnel_runtime_leases.sql`, then deploy the updated Workers API and dashboard before the matching CLI/relay pair. The relay requires a nonempty `server_token` matching Workers `SERVER_TOKEN`; an owner API key alone cannot publish endpoint leases. Profiles are enabled independently of their expiring runtime status. See the main README for renewal, restart and failure timing. No production deployment is implied by the local E2E fixtures.

Visitor authentication and IP restrictions: see [VISITOR-POLICIES.md](VISITOR-POLICIES.md) for trusted HTTPS frontend configuration, hosted migration, standalone policy hashes and revocation behavior. Basic/JWT/IP are implemented; OIDC sign-in and visitor mTLS remain separate pending work. JWT requires visitor-policy protocol 2 and Rust 1.88+; see the linked rollout and signing-key source contract.
