# Pike

Pike is the open-source core of the Pike tunnel stack.

This repo is standalone and publishable on its own. It contains:
- `pike`: the CLI tunnel client
- `pike-server`: the relay server
- `pike-core`: shared protocol, transport, and type definitions

It does not include the hosted cloud control plane, dashboard UI, admin tooling, billing, email flows, or the marketing site. Those live in the private `pike-cloud` repo.

## Install

```bash
curl -fsSL https://pike.life/install | sh
```

The current public installer rollout supports Linux x86_64 and macOS x86_64/arm64. Windows x86_64 binaries are available from GitHub Releases. Linux ARM64 and Termux artifacts are deferred, and the installer exits explicitly on those systems instead of attempting a missing download.

## Quick Start

```bash
cargo build --workspace
cargo test --workspace
python3 scripts/local_tunnel_smoke.py
```

The smoke test boots a local upstream service, a local `pike-server` relay in `--dev-mode`, and a local `pike` client, then verifies HTTP and WebSocket forwarding end to end.

## Self-Hosted Relay

- Start from `deploy/server-vps.toml`.
- For a standalone relay, replace `local_api_keys` with your own key list.
- If you run your own remote control plane, set `control_plane_url`, `workers_api_url`, and `server_token`.
- Current public Linux release bundles are x86_64 only.
- The release workflow also publishes `ghcr.io/a3therion/pike-server:<tag>`.

## Client Configuration

Use `deploy/client-config.toml.template` as the starting point for `~/.pike/config.toml`.

For HTTP tunnels:
- `pike http 3000` now gets a unique URL by default on every run.
- Use `pike http 3000 --subdomain my-app` only when you want a fixed URL.
- The inspector prefers the configured port, but auto-selects the next free loopback port when that port is already in use.
- Shared `tunnel.subdomain_prefix` config is ignored for HTTP runtime routing and only kept for backward compatibility.

## License

Apache-2.0. See `LICENSE`.
