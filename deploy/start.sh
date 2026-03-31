#!/bin/sh
set -e

CONFIG_PATH="/etc/pike/server.toml"

replace_or_append_setting() {
  key="$1"
  value="$2"
  escaped_value=$(printf '%s' "$value" | sed 's/[&|]/\\&/g')
  if grep -q "^${key} = " "$CONFIG_PATH"; then
    sed -i "s|^${key} = .*|${key} = \"${escaped_value}\"|" "$CONFIG_PATH"
  else
    printf '\n%s = "%s"\n' "$key" "$value" >> "$CONFIG_PATH"
  fi
}

if [ -n "${BIND_ADDR:-}" ]; then
  replace_or_append_setting "bind_addr" "${BIND_ADDR}"
fi

if [ -n "${INTERNAL_TOKEN:-}" ]; then
  replace_or_append_setting "internal_token" "${INTERNAL_TOKEN}"
fi

if [ -n "${SERVER_TOKEN:-}" ]; then
  replace_or_append_setting "server_token" "${SERVER_TOKEN}"
fi

if [ -n "${REDIS_URL:-}" ]; then
  replace_or_append_setting "redis_url" "${REDIS_URL}"
fi

if [ -n "${CONTROL_PLANE_URL:-}" ]; then
  replace_or_append_setting "control_plane_url" "${CONTROL_PLANE_URL}"
  replace_or_append_setting "workers_api_url" "${CONTROL_PLANE_URL}"
fi

if grep -q '^internal_token = "CHANGE_ME_' "$CONFIG_PATH"; then
  echo "Missing required INTERNAL_TOKEN; update ${CONFIG_PATH} or provide INTERNAL_TOKEN" >&2
  exit 1
fi

if ! grep -q '^local_api_keys = \[' "$CONFIG_PATH" && grep -q '^server_token = "CHANGE_ME_' "$CONFIG_PATH"; then
  echo "Missing required SERVER_TOKEN; update ${CONFIG_PATH} or provide SERVER_TOKEN" >&2
  exit 1
fi

# Decode TLS certs from base64 environment variables if provided
if [ -n "${TLS_CERT:-}" ] && [ -n "${TLS_KEY:-}" ]; then
  mkdir -p /etc/pike/tls
  echo "${TLS_CERT}" | base64 -d > /etc/pike/tls/cert.pem
  echo "${TLS_KEY}" | base64 -d > /etc/pike/tls/key.pem
  echo "TLS certificates decoded from secrets"
fi

if [ ! -f /etc/pike/tls/cert.pem ] || [ ! -f /etc/pike/tls/key.pem ]; then
  echo "Missing TLS certificate or key at /etc/pike/tls; mount production certificates before starting pike-server" >&2
  exit 1
fi

echo "Starting pike-server with config ${CONFIG_PATH}"

exec pike-server --config "$CONFIG_PATH"
