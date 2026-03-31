#!/bin/sh
# Pike CLI install script
# Usage: curl -fsSL https://pike.life/install | sh

set -eu

REPO="${PIKE_INSTALL_REPO:-a3therion/pike}"
BINARY_NAME="pike"
RELEASES_URL="https://github.com/${REPO}/releases"
SYSTEM_INSTALL_DIR="/usr/local/bin"
USER_INSTALL_DIR_DEFAULT=".local/bin"
REQUESTED_INSTALL_DIR="${PIKE_INSTALL_DIR:-${INSTALL_DIR:-}}"
REQUESTED_VERSION="${PIKE_INSTALL_VERSION:-}"

info() {
    printf '%s\n' "$*"
}

warn() {
    printf '%s\n' "$*" >&2
}

die() {
    warn "Error: $*"
    exit 1
}

need_cmd() {
    command -v "$1" >/dev/null 2>&1 || die "Missing required command: $1"
}

expand_path() {
    case "$1" in
        "~")
            [ -n "${HOME:-}" ] || die "HOME is not set"
            printf '%s\n' "$HOME"
            ;;
        "~/"*)
            [ -n "${HOME:-}" ] || die "HOME is not set"
            printf '%s/%s\n' "$HOME" "${1#~/}"
            ;;
        *)
            printf '%s\n' "$1"
            ;;
    esac
}

detect_platform() {
    os_name=$(uname -s)
    arch_name=$(uname -m)

    case "$os_name" in
        Linux)
            os="linux"
            ;;
        Darwin)
            os="macos"
            ;;
        MINGW*|MSYS*|CYGWIN*)
            die "Windows shell installs are not supported. Download the release asset from ${RELEASES_URL}"
            ;;
        *)
            die "Unsupported operating system: ${os_name}"
            ;;
    esac

    case "$arch_name" in
        x86_64|amd64)
            arch="amd64"
            ;;
        aarch64|arm64)
            arch="arm64"
            ;;
        *)
            die "Unsupported architecture: ${arch_name}"
            ;;
    esac

    asset_name="${BINARY_NAME}-${os}-${arch}"
}

resolve_install_dir() {
    if [ -n "$REQUESTED_INSTALL_DIR" ]; then
        install_dir=$(expand_path "$REQUESTED_INSTALL_DIR")
        return
    fi

    if [ "$(id -u)" -eq 0 ]; then
        install_dir="$SYSTEM_INSTALL_DIR"
        return
    fi

    if [ -d "$SYSTEM_INSTALL_DIR" ] && [ -w "$SYSTEM_INSTALL_DIR" ]; then
        install_dir="$SYSTEM_INSTALL_DIR"
        return
    fi

    [ -n "${HOME:-}" ] || die "HOME is not set and ${SYSTEM_INSTALL_DIR} is not writable. Set PIKE_INSTALL_DIR."
    install_dir="${HOME}/${USER_INSTALL_DIR_DEFAULT}"
}

build_download_urls() {
    if [ -n "$REQUESTED_VERSION" ]; then
        version_label="$REQUESTED_VERSION"
        asset_url="${RELEASES_URL}/download/${REQUESTED_VERSION}/${asset_name}"
        checksum_url="${RELEASES_URL}/download/${REQUESTED_VERSION}/checksums.txt"
        return
    fi

    version_label="latest"
    asset_url="${RELEASES_URL}/latest/download/${asset_name}"
    checksum_url="${RELEASES_URL}/latest/download/checksums.txt"
}

download_file() {
    url="$1"
    destination="$2"
    curl -fsSL "$url" -o "$destination"
}

sha256_file() {
    file_path="$1"

    if command -v sha256sum >/dev/null 2>&1; then
        sha256sum "$file_path" | awk '{print $1}'
        return
    fi

    if command -v shasum >/dev/null 2>&1; then
        shasum -a 256 "$file_path" | awk '{print $1}'
        return
    fi

    if command -v openssl >/dev/null 2>&1; then
        openssl dgst -sha256 "$file_path" | awk '{print $NF}'
        return
    fi

    die "No SHA-256 tool found (sha256sum, shasum, or openssl)"
}

verify_checksum() {
    checksum_file="$1"
    binary_file="$2"

    if ! download_file "$checksum_url" "$checksum_file"; then
        warn "Checksum file not found at ${checksum_url}; continuing without verification"
        return
    fi

    expected_checksum=$(awk -v file="$asset_name" '$2 == file { print $1 }' "$checksum_file")
    [ -n "$expected_checksum" ] || die "Missing checksum entry for ${asset_name}"

    actual_checksum=$(sha256_file "$binary_file")

    [ "$expected_checksum" = "$actual_checksum" ] || die "Checksum verification failed for ${asset_name}"
}

install_binary() {
    tmp_dir=$(mktemp -d 2>/dev/null || mktemp -d -t pike-install)
    trap 'rm -rf "$tmp_dir"' EXIT INT TERM

    binary_path="${tmp_dir}/${asset_name}"
    checksum_path="${tmp_dir}/checksums.txt"
    destination_path="${install_dir}/${BINARY_NAME}"

    info "Installing ${BINARY_NAME} (${version_label}) for ${asset_name}"
    info "Downloading ${asset_url}"
    download_file "$asset_url" "$binary_path"
    verify_checksum "$checksum_path" "$binary_path"

    mkdir -p "$install_dir"
    chmod +x "$binary_path"
    mv "$binary_path" "$destination_path"
    chmod 755 "$destination_path"

    installed_version=$("$destination_path" --version 2>/dev/null || true)

    info ""
    if [ -n "$installed_version" ]; then
        info "Installed ${installed_version} to ${destination_path}"
    else
        info "Installed ${BINARY_NAME} to ${destination_path}"
    fi

    case ":${PATH:-}:" in
        *:"${install_dir}":*)
            ;;
        *)
            warn "Add ${install_dir} to your PATH to run ${BINARY_NAME} from any shell:"
            warn "  export PATH=\"${install_dir}:\$PATH\""
            ;;
    esac

    info "Run '${BINARY_NAME} --help' to get started"
}

main() {
    need_cmd curl
    need_cmd uname
    need_cmd mktemp
    need_cmd awk
    need_cmd id
    need_cmd mv
    need_cmd chmod
    need_cmd mkdir

    detect_platform
    resolve_install_dir
    build_download_urls
    install_binary
}

main "$@"
