# Pike Server VPS Bundle

This bundle targets Linux VPS deployments.

Included files:
- `pike-server`: relay binary
- `server-vps.toml`: production config template
- `setup.sh`: first-time VPS setup helper
- `pike-server.service`: systemd unit
- `start.sh`: generic container entrypoint for Docker-based installs

Important requirements:
- Set a unique `internal_token`.
- Replace the default `local_api_keys` list or point the relay at your own remote control plane.
- Set `server_token` only if you are using a remote control plane.
- Install valid TLS certs at `/etc/pike/tls/cert.pem` and `/etc/pike/tls/key.pem`.
- Update `redis_url` before first start.

Typical systemd install flow:
1. Run `setup.sh` as root on the VPS.
2. Review and edit `/etc/pike/server.toml`.
3. Copy the `pike-server` binary to `/opt/pike/pike-server`.
4. Start the service with `systemctl start pike-server`.
