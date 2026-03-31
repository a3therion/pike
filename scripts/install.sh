#!/bin/sh
# Pike CLI Install Script
# Usage: curl -sSL https://pike.dev/install.sh | sh

set -e

REPO="pike/pike"
BINARY="pike"
INSTALL_DIR="${INSTALL_DIR:-/usr/local/bin}"

# Detect OS and architecture
detect_platform() {
    OS=$(uname -s | tr '[:upper:]' '[:lower:]')
    ARCH=$(uname -m)
    
    case "$OS" in
        linux)
            case "$ARCH" in
                x86_64) ASSET_NAME="pike-linux-amd64" ;;
                aarch64|arm64) ASSET_NAME="pike-linux-arm64" ;;
                *) echo "Unsupported architecture: $ARCH"; exit 1 ;;
            esac
            ;;
        darwin)
            case "$ARCH" in
                x86_64) ASSET_NAME="pike-macos-amd64" ;;
                aarch64|arm64) ASSET_NAME="pike-macos-arm64" ;;
                *) echo "Unsupported architecture: $ARCH"; exit 1 ;;
            esac
            ;;
        *)
            echo "Unsupported OS: $OS"
            exit 1
            ;;
    esac
}

# Get latest release version
get_latest_version() {
    curl -s "https://api.github.com/repos/$REPO/releases/latest" | grep '"tag_name":' | sed -E 's/.*"([^"]+)".*/\1/'
}

# Download and install
download_and_install() {
    VERSION=$(get_latest_version)
    if [ -z "$VERSION" ]; then
        echo "Error: Could not determine latest version"
        exit 1
    fi
    
    echo "Installing $BINARY $VERSION from $ASSET_NAME..."

    URL="https://github.com/$REPO/releases/download/$VERSION/${ASSET_NAME}"
    TMP_DIR=$(mktemp -d)

    echo "Downloading from $URL..."
    curl -sSL "$URL" -o "$TMP_DIR/$BINARY"
    
    echo "Installing to $INSTALL_DIR..."
    if [ -w "$INSTALL_DIR" ]; then
        mv "$TMP_DIR/$BINARY" "$INSTALL_DIR/"
    else
        echo "Need sudo access to install to $INSTALL_DIR"
        sudo mv "$TMP_DIR/$BINARY" "$INSTALL_DIR/"
    fi
    
    chmod +x "$INSTALL_DIR/$BINARY"
    rm -rf "$TMP_DIR"
    
    echo ""
    echo "✓ $BINARY $VERSION installed successfully!"
    echo "Run '$BINARY --help' to get started"
}

# Main
main() {
    detect_platform
    download_and_install
}

main
