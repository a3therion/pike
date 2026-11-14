# Agent guidance

Public open-source core of Pike:

- `crates/pike`: the CLI tunnel client
- `crates/pike-server`: the relay
- `crates/pike-core`: shared protocol, QUIC/WebSocket transport and types

The private hosted control plane lives in the sibling `pike-cloud` repo, which deploys pinned releases of this one.

Verify with `cargo clippy --workspace --all-targets -- -D warnings` and `cargo test --workspace`. For transport changes, also run `python3 scripts/local_tunnel_smoke.py` after `cargo build --workspace`.

- The CLI and relay must speak the same protocol version (`PROTOCOL_VERSION` in `crates/pike-core/src/proto/mod.rs`); change and release them together.
- `scripts/install.sh` on `main` is live: `pike.life/install` redirects to it, and it installs the latest GitHub release.
- Pushing a `v*` tag publishes binaries and the `ghcr.io/a3therion/pike-server` image, and new installs pick it up. Don't tag until production runs a matching relay (see the rollout state in `pike-cloud/DEPLOY.md`).
