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

The installer downloads the latest GitHub release for Linux or macOS, verifies its SHA-256 checksum when the release publishes one, and installs `pike` into a writable bin directory.

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
- Linux release bundles are published with GitHub releases.
- The release workflow also publishes `ghcr.io/a3therion/pike-server:<tag>`.

## Client Configuration

Use `deploy/client-config.toml.template` as the starting point for `~/.pike/config.toml`.

## License

Apache-2.0. See `LICENSE`.
