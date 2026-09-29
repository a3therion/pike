#!/bin/bash
# Pike relay installation. Existing configuration/secrets are preserved on rerun.
set -euo pipefail
umask 027

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
PIKE_USER="pike"
INSTALL_ROOT="${PIKE_INSTALL_ROOT:-}"
FIXTURE=0
if [ -n "$INSTALL_ROOT" ]; then
  # A nonempty existing prefix is an explicit filesystem-only test installation.
  INSTALL_ROOT=$(cd -- "$INSTALL_ROOT" && pwd -P)
  if [ "$INSTALL_ROOT" = / ]; then
    echo 'PIKE_INSTALL_ROOT must be a dedicated fixture directory, not /' >&2
    exit 1
  fi
  FIXTURE=1
elif [ "$EUID" -ne 0 ]; then
  echo 'Please run as root (use sudo)' >&2
  exit 1
fi

PIKE_DIR="$INSTALL_ROOT/opt/pike"
CONFIG_DIR="$INSTALL_ROOT/etc/pike"
LOG_DIR="$INSTALL_ROOT/var/log/pike"
STATE_DIR="$INSTALL_ROOT/var/lib/pike"
TLS_DIR="$CONFIG_DIR/tls"
SYSTEMD_DIR="$INSTALL_ROOT/etc/systemd/system"
JOURNALD_DIR="$INSTALL_ROOT/etc/systemd/journald.conf.d"
# Base domain served by the relay. The relay needs a WILDCARD cert (`*.DOMAIN`) plus the
# apex, so tunnels get `<sub>.DOMAIN`. Override with `DOMAIN=example.com sudo ./setup.sh`.
DOMAIN="${DOMAIN:-pike.life}"
# Cloudflare API token file the operator provisions (mode 600). Used by certbot's Cloudflare
# DNS plugin for the unattended DNS-01 challenge. The token needs Zone:DNS:Edit on the zone.
CF_INI="$CONFIG_DIR/cloudflare.ini"
# Fixed certbot lineage name so the deploy hook can find the certs at a stable path.
CERT_NAME="pike"

# Reject incomplete bundles before modifying the host.
for file in pike-server server-vps.toml pike-server.service; do
  if [ ! -f "$SCRIPT_DIR/$file" ]; then
    echo "Missing bundle file: $SCRIPT_DIR/$file" >&2
    exit 1
  fi
done

if [ "$FIXTURE" -eq 0 ]; then
  if ! getent group "$PIKE_USER" >/dev/null; then groupadd --system "$PIKE_USER"; fi
  if ! id "$PIKE_USER" &>/dev/null; then
    useradd --system --gid "$PIKE_USER" --no-create-home --shell /bin/false "$PIKE_USER"
  fi
fi
mkdir -p "$PIKE_DIR" "$CONFIG_DIR" "$LOG_DIR" "$STATE_DIR" "$TLS_DIR" "$SYSTEMD_DIR"
chmod 755 "$PIKE_DIR" "$CONFIG_DIR"
chmod 750 "$LOG_DIR" "$STATE_DIR" "$TLS_DIR"
if [ "$FIXTURE" -eq 0 ]; then
  chown root:root "$PIKE_DIR" "$CONFIG_DIR"
  chown "$PIKE_USER:$PIKE_USER" "$LOG_DIR" "$STATE_DIR"
  chown "root:$PIKE_USER" "$TLS_DIR"
fi

# Atomic replacement also works while the previous executable is running.
install -m 755 "$SCRIPT_DIR/pike-server" "$PIKE_DIR/pike-server.new"
mv -f "$PIKE_DIR/pike-server.new" "$PIKE_DIR/pike-server"
if [ ! -f "$CONFIG_DIR/server.toml" ]; then
  install -m 640 "$SCRIPT_DIR/server-vps.toml" "$CONFIG_DIR/server.toml"
  TOKEN=$(openssl rand -hex 32)
  sed "s|^internal_token = \"CHANGE_ME.*\"|internal_token = \"$TOKEN\"|" \
    "$CONFIG_DIR/server.toml" > "$CONFIG_DIR/server.toml.new"
  mv "$CONFIG_DIR/server.toml.new" "$CONFIG_DIR/server.toml"
  unset TOKEN
  echo "Created $CONFIG_DIR/server.toml; review local_api_keys, Redis, domain and control-plane settings."
else
  echo "Preserved existing $CONFIG_DIR/server.toml and its secrets."
fi
chmod 640 "$CONFIG_DIR/server.toml"
if [ "$FIXTURE" -eq 0 ]; then
  chown root:root "$PIKE_DIR/pike-server"
  chown "root:$PIKE_USER" "$CONFIG_DIR/server.toml"
fi

# Private keys remain readable by the service group, not by other users.
for cert in "$TLS_DIR/cert.pem" "$TLS_DIR/key.pem"; do
  if [ -f "$cert" ]; then
    chmod 640 "$cert"
    if [ "$FIXTURE" -eq 0 ]; then chown "root:$PIKE_USER" "$cert"; fi
  fi
done

# TLS provisioning (automated Cloudflare DNS-01). The relay serves arbitrary subdomains,
# so it needs a wildcard cert, which requires a DNS-01 challenge. Certbot's Cloudflare
# plugin gives unattended issuance and renewal driven by certbot's systemd timer; the
# deploy hook below re-copies renewed certs with the group-readable permissions above
# and restarts the relay (it reads TLS material at startup). Skipped in fixture mode and
# when no token file exists, so operators may still install their own certificates.
if [ "$FIXTURE" -eq 0 ]; then
  RENEWAL_HOOK_DIR="/etc/letsencrypt/renewal-hooks/deploy"
  RENEWAL_HOOK="$RENEWAL_HOOK_DIR/pike.sh"
  if [ ! -f "$CF_INI" ]; then
    if [ -f "$TLS_DIR/cert.pem" ] && [ -f "$TLS_DIR/key.pem" ]; then
      echo "Using the existing certificates in $TLS_DIR."
    else
      echo "No Cloudflare API token at $CF_INI; automated TLS provisioning skipped."
      echo "Either install cert.pem/key.pem into $TLS_DIR (root:$PIKE_USER, mode 640) or create the token file:"
      echo "  sudo install -m 600 -o root -g root /dev/null $CF_INI"
      echo "  # add ONE line (token needs Zone:DNS:Edit on the $DOMAIN zone):"
      echo "  #   dns_cloudflare_api_token = <YOUR_CLOUDFLARE_API_TOKEN>"
      echo "then re-run this script."
    fi
  elif [ -f "$TLS_DIR/cert.pem" ] && [ -f "$TLS_DIR/key.pem" ] && [ -d "/etc/letsencrypt/live/$CERT_NAME" ]; then
    echo "TLS certificate already provisioned; certbot's timer handles renewal."
  else
    chmod 600 "$CF_INI"
    chown root:root "$CF_INI"
    mkdir -p "$RENEWAL_HOOK_DIR"
    cat > "$RENEWAL_HOOK" <<HOOK
#!/bin/bash
# Installed by pike deploy/setup.sh. Copies the pike lineage certs into the relay's TLS dir
# with pike-group-readable perms, then restarts the service. Runs after every renewal.
set -e
LIVE="/etc/letsencrypt/live/$CERT_NAME"
# Only act for our lineage (deploy hooks run for every renewed lineage on the host).
if [ -n "\$RENEWED_LINEAGE" ] && [ "\$RENEWED_LINEAGE" != "\$LIVE" ]; then
  exit 0
fi
install -o root -g "$PIKE_USER" -m 640 "\$LIVE/fullchain.pem" "$TLS_DIR/cert.pem"
install -o root -g "$PIKE_USER" -m 640 "\$LIVE/privkey.pem" "$TLS_DIR/key.pem"
if systemctl is-active --quiet pike-server; then
  systemctl restart pike-server
fi
HOOK
    chmod 755 "$RENEWAL_HOOK"
    echo "Installing certbot + Cloudflare DNS plugin..."
    if command -v apt-get >/dev/null 2>&1; then
      apt-get update
      apt-get install -y certbot python3-certbot-dns-cloudflare
    elif command -v dnf >/dev/null 2>&1; then
      dnf install -y certbot python3-certbot-dns-cloudflare
    else
      echo "Error: no supported package manager (apt-get/dnf) found to install certbot." >&2
      echo "Install 'certbot' and the 'certbot-dns-cloudflare' plugin manually, then re-run." >&2
      exit 1
    fi
    echo "Requesting wildcard certificate for *.$DOMAIN via DNS-01..."
    certbot certonly --non-interactive --agree-tos \
      --dns-cloudflare --dns-cloudflare-credentials "$CF_INI" \
      --dns-cloudflare-propagation-seconds 30 \
      --cert-name "$CERT_NAME" -d "*.$DOMAIN" -d "$DOMAIN"
    # Place the freshly issued certs now; renewals run the same hook automatically.
    RENEWED_LINEAGE="/etc/letsencrypt/live/$CERT_NAME" "$RENEWAL_HOOK"
    if systemctl list-unit-files | grep -q '^certbot.timer'; then
      systemctl enable --now certbot.timer
      echo "Enabled certbot.timer for unattended renewal."
    else
      echo "NOTE: certbot.timer not found; add a daily cron entry running 'certbot renew' instead."
    fi
    echo "TLS certificate provisioned and automatic renewal configured."
  fi
fi

install -m 644 "$SCRIPT_DIR/pike-server.service" "$SYSTEMD_DIR/pike-server.service"
# Logs go to the journal, not a flat file; cap its size so it cannot fill the disk.
if [ -f "$SCRIPT_DIR/journald.conf" ]; then
  mkdir -p "$JOURNALD_DIR"
  install -m 644 "$SCRIPT_DIR/journald.conf" "$JOURNALD_DIR/pike.conf"
fi
if [ "$FIXTURE" -eq 0 ]; then
  if [ -f "$JOURNALD_DIR/pike.conf" ]; then systemctl restart systemd-journald; fi
  systemctl daemon-reload
  systemctl enable pike-server
  echo 'Installation complete. Review configuration and TLS certificates, then run: sudo systemctl start pike-server'
  echo 'Logs: journalctl -u pike-server -f'
else
  echo "Fixture installation complete under $INSTALL_ROOT; no users, ownership, certificates, or services were changed."
fi
