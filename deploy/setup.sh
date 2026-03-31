#!/bin/bash
# Pike Server Deployment Script for a Linux VPS

set -e

echo "=== Pike Server Deployment Script ==="
echo ""

# Configuration
PIKE_USER="pike"
PIKE_DIR="/opt/pike"
CONFIG_DIR="/etc/pike"
LOG_DIR="/var/log/pike"
TLS_DIR="/etc/pike/tls"

# Check if running as root
if [ "$EUID" -ne 0 ]; then 
  echo "Please run as root (use sudo)"
  exit 1
fi

echo "Step 1: Creating pike user and directories..."
if ! id "$PIKE_USER" &>/dev/null; then
  useradd --system --no-create-home --shell /bin/false "$PIKE_USER"
fi

mkdir -p "$PIKE_DIR" "$CONFIG_DIR" "$LOG_DIR" "$TLS_DIR"
chown -R "$PIKE_USER:$PIKE_USER" "$PIKE_DIR" "$LOG_DIR"
chown root:root "$CONFIG_DIR" "$TLS_DIR"
chmod 755 "$CONFIG_DIR"
chmod 700 "$TLS_DIR"

echo "Step 2: Installing binary..."
if [ ! -f "./pike-server" ]; then
  echo "Error: pike-server binary not found in current directory"
  echo "Please copy the binary to this directory first"
  exit 1
fi

cp ./pike-server "$PIKE_DIR/"
chown root:root "$PIKE_DIR/pike-server"
chmod 755 "$PIKE_DIR/pike-server"

echo "Step 3: Setting up configuration..."
if [ ! -f "./server-vps.toml" ]; then
  echo "Error: server-vps.toml not found"
  exit 1
fi

cp ./server-vps.toml "$CONFIG_DIR/server.toml"
chown root:root "$CONFIG_DIR/server.toml"
chmod 644 "$CONFIG_DIR/server.toml"

echo "Step 4: Generating internal token..."
TOKEN=$(openssl rand -hex 32)
sed -i "s|^internal_token = \"CHANGE_ME.*\"|internal_token = \"$TOKEN\"|" "$CONFIG_DIR/server.toml"
echo "Generated secure internal token"

echo "Step 5: Review auth configuration..."
echo "Update local_api_keys in $CONFIG_DIR/server.toml before first start."
echo "If you are using a remote control plane, also set server_token to match that service."

echo "Step 6: Redis installation..."
echo "The production config requires Redis for persistent state (rate limits, abuse logs)."
echo "Install Redis and update redis_url in $CONFIG_DIR/server.toml before first start."
echo "Example commands:"
echo ""
echo "apt-get update"
echo "apt-get install -y redis-server"
echo "systemctl enable redis-server"
echo "systemctl start redis-server"
echo ""
echo "For remote Redis, replace redis_url in $CONFIG_DIR/server.toml with the correct endpoint."
echo ""

echo "Step 7: Checking TLS certificate installation..."
if [ -f "$TLS_DIR/cert.pem" ] && [ -f "$TLS_DIR/key.pem" ]; then
  echo "TLS certificates already installed"
else
  echo "TLS certificates not found in $TLS_DIR"
  echo "Install production certificates before starting pike-server:"
  echo "  - $TLS_DIR/cert.pem"
  echo "  - $TLS_DIR/key.pem"
fi

echo "Step 8: Installing systemd service..."
if [ ! -f "./pike-server.service" ]; then
  echo "Error: pike-server.service not found"
  exit 1
fi

cp ./pike-server.service /etc/systemd/system/
chmod 644 /etc/systemd/system/pike-server.service

systemctl daemon-reload
systemctl enable pike-server

echo ""
echo "=== Deployment Complete ==="
echo ""
echo "To start the server:"
echo "  sudo systemctl start pike-server"
echo ""
echo "To check status:"
echo "  sudo systemctl status pike-server"
echo ""
echo "To view logs:"
echo "  sudo journalctl -u pike-server -f"
echo ""
echo "Health check:"
echo "  curl http://YOUR_SERVER_IP:8080/health"
echo ""
echo "IMPORTANT: This deployment only supports a single relay instance."
echo "Do not place multiple pike-server nodes behind a load balancer until"
echo "distributed tunnel routing and shared state are implemented."
echo ""
echo "Install production TLS certificates in $TLS_DIR before starting the service."
