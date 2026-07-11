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
DATA_DIR="/var/lib/pike"
TLS_DIR="/etc/pike/tls"
# Base domain served by the relay. The relay needs a WILDCARD cert (`*.DOMAIN`) plus the
# apex, so tunnels get `<sub>.DOMAIN`. Override with `DOMAIN=example.com sudo ./setup.sh`.
DOMAIN="${DOMAIN:-pike.life}"
# Cloudflare API token file the operator provisions (mode 600). Used by certbot's Cloudflare
# DNS plugin for the unattended DNS-01 challenge. The token needs Zone:DNS:Edit on the zone.
CF_INI="$CONFIG_DIR/cloudflare.ini"
# Fixed certbot lineage name so the deploy hook can find the certs at a stable path.
CERT_NAME="pike"

# Check if running as root
if [ "$EUID" -ne 0 ]; then 
  echo "Please run as root (use sudo)"
  exit 1
fi

echo "Step 1: Creating pike user and directories..."
if ! id "$PIKE_USER" &>/dev/null; then
  useradd --system --no-create-home --shell /bin/false "$PIKE_USER"
fi

mkdir -p "$PIKE_DIR" "$CONFIG_DIR" "$LOG_DIR" "$DATA_DIR" "$TLS_DIR"
chown -R "$PIKE_USER:$PIKE_USER" "$PIKE_DIR" "$LOG_DIR" "$DATA_DIR"
chown root:root "$CONFIG_DIR" "$TLS_DIR"
chgrp "$PIKE_USER" "$TLS_DIR"
chmod 755 "$CONFIG_DIR"
chmod 750 "$TLS_DIR"

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
# server.toml holds secrets (server_token / internal_token). Keep it out of
# world-readable range: owned by root, readable only by the pike service group.
chown "root:$PIKE_USER" "$CONFIG_DIR/server.toml"
chmod 640 "$CONFIG_DIR/server.toml"

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

echo "Step 7: Provisioning TLS certificate (automated Cloudflare DNS-01)..."
# The relay serves arbitrary subdomains, so it needs a wildcard cert. Wildcards require a
# DNS-01 challenge. Instead of Certbot's MANUAL DNS challenge (which must be renewed by hand
# every ~90 days -> scheduled outage), we use Certbot's Cloudflare DNS plugin for a fully
# UNATTENDED issuance + renewal driven by certbot's systemd timer.

# A deploy hook copies renewed certs into $TLS_DIR (readable by the pike group) and reloads
# the service. It runs on both first issuance and every automatic renewal, so renewal is
# hands-off. Written idempotently (overwritten each run).
RENEWAL_HOOK_DIR="/etc/letsencrypt/renewal-hooks/deploy"
RENEWAL_HOOK="$RENEWAL_HOOK_DIR/pike.sh"
mkdir -p "$RENEWAL_HOOK_DIR"
cat > "$RENEWAL_HOOK" <<HOOK
#!/bin/bash
# Installed by pike deploy/setup.sh. Copies the pike lineage certs into the relay's TLS dir
# with pike-group-readable perms, then reloads the service. Runs after every renewal.
set -e
LIVE="/etc/letsencrypt/live/$CERT_NAME"
# Only act for our lineage (deploy hooks run for every renewed lineage on the host).
if [ -n "\$RENEWED_LINEAGE" ] && [ "\$RENEWED_LINEAGE" != "\$LIVE" ]; then
  exit 0
fi
install -o root -g "$PIKE_USER" -m 640 "\$LIVE/fullchain.pem" "$TLS_DIR/cert.pem"
install -o root -g "$PIKE_USER" -m 640 "\$LIVE/privkey.pem" "$TLS_DIR/key.pem"
# Restart (not reload): the relay reads its TLS material at startup, so a full restart is
# what actually picks up the rotated certificate.
if systemctl is-active --quiet pike-server; then
  systemctl restart pike-server
fi
HOOK
chmod 755 "$RENEWAL_HOOK"

if [ ! -f "$CF_INI" ]; then
  echo "WARNING: Cloudflare API token file not found at $CF_INI"
  echo "Automated TLS provisioning is SKIPPED until you create it:"
  echo "  sudo install -m 600 -o root -g root /dev/null $CF_INI"
  echo "  # then add ONE line (token needs Zone:DNS:Edit on the $DOMAIN zone):"
  echo "  #   dns_cloudflare_api_token = <YOUR_CLOUDFLARE_API_TOKEN>"
  echo "  sudo chmod 600 $CF_INI"
  echo "Then re-run this script (or run the certbot command printed below) to issue the cert."
  echo ""
  echo "certbot certonly --non-interactive --agree-tos \\"
  echo "  --dns-cloudflare --dns-cloudflare-credentials $CF_INI \\"
  echo "  --dns-cloudflare-propagation-seconds 30 \\"
  echo "  --cert-name $CERT_NAME -d '*.$DOMAIN' -d '$DOMAIN'"
elif [ -f "$TLS_DIR/cert.pem" ] && [ -f "$TLS_DIR/key.pem" ] && [ -d "/etc/letsencrypt/live/$CERT_NAME" ]; then
  echo "TLS certificate already provisioned; certbot's timer handles renewal."
else
  # Enforce the required 600 perms on the token file before using it.
  chmod 600 "$CF_INI"
  chown root:root "$CF_INI"

  echo "Installing certbot + Cloudflare DNS plugin..."
  if command -v apt-get >/dev/null 2>&1; then
    apt-get update
    apt-get install -y certbot python3-certbot-dns-cloudflare
  elif command -v dnf >/dev/null 2>&1; then
    dnf install -y certbot python3-certbot-dns-cloudflare
  else
    echo "Error: no supported package manager (apt-get/dnf) found to install certbot."
    echo "Install 'certbot' and the 'certbot-dns-cloudflare' plugin manually, then re-run."
    exit 1
  fi

  echo "Requesting wildcard certificate for *.$DOMAIN via DNS-01..."
  certbot certonly --non-interactive --agree-tos \
    --dns-cloudflare --dns-cloudflare-credentials "$CF_INI" \
    --dns-cloudflare-propagation-seconds 30 \
    --cert-name "$CERT_NAME" -d "*.$DOMAIN" -d "$DOMAIN"

  # Run the deploy hook now to place the freshly issued certs.
  RENEWED_LINEAGE="/etc/letsencrypt/live/$CERT_NAME" "$RENEWAL_HOOK"

  # certbot ships a systemd timer (certbot.timer) that renews twice daily and runs deploy
  # hooks automatically. Make sure it is enabled so renewal is unattended.
  if systemctl list-unit-files | grep -q '^certbot.timer'; then
    systemctl enable --now certbot.timer
    echo "Enabled certbot.timer for unattended renewal."
  else
    echo "NOTE: certbot.timer not found; add a daily cron entry running 'certbot renew' instead."
  fi
  echo "TLS certificate provisioned and automatic renewal configured."
fi

echo "Step 8: Installing systemd service..."
if [ ! -f "./pike-server.service" ]; then
  echo "Error: pike-server.service not found"
  exit 1
fi

cp ./pike-server.service /etc/systemd/system/
chmod 644 /etc/systemd/system/pike-server.service

# Install the journald size cap so logs (which go to the journal, not a flat
# file) cannot fill the disk. See deploy/journald.conf for details.
if [ -f "./journald.conf" ]; then
  echo "Installing journald size cap..."
  mkdir -p /etc/systemd/journald.conf.d
  cp ./journald.conf /etc/systemd/journald.conf.d/pike.conf
  chmod 644 /etc/systemd/journald.conf.d/pike.conf
  systemctl restart systemd-journald
fi

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
echo "TLS: certificates are provisioned + auto-renewed via Certbot's Cloudflare DNS plugin."
echo "If you saw the Cloudflare token warning above, create $CF_INI (mode 600) and re-run."
