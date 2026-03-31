# Pike development task runner

# Build entire workspace
build:
    cargo build --workspace

# Run all tests
test:
    cargo test --workspace

# Start pike-server in dev mode
dev-server:
    cargo run -p pike-server -- --config dev.toml

# Start pike
dev-cli:
    cargo run -p pike -- http 3000

# Format all code
fmt:
    cargo fmt --all

# Lint with clippy
lint:
    cargo clippy --workspace -- -D warnings

# Check everything (fast)
check:
    cargo check --workspace

# Clean build artifacts
clean:
    cargo clean
