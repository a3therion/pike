# Pike Server VPS Bundle

This bundle targets Linux VPS deployments.

Current public bundle rollout: Linux x86_64 and Linux ARM64.

Included files:
- `pike-server`: relay binary
- `server-vps.toml`: production config template
- `setup.sh`: first-time VPS setup helper
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
2. Run `setup.sh` as root on the VPS (issues the wildcard cert automatically).
3. Review and edit `/etc/pike/server.toml`.
4. Copy the `pike-server` binary to `/opt/pike/pike-server`.
5. Start the service with `systemctl start pike-server`.
