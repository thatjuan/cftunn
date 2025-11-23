#!/bin/bash
set -e

OWNER="thatjuan"
REPO="cftunn"
BINARY="cftunn"
INSTALL_DIR="/usr/local/bin"

# Detect OS
OS="$(uname -s)"
if [ "$OS" = "Darwin" ]; then
    OS_TYPE="Darwin"
elif [ "$OS" = "Linux" ]; then
    OS_TYPE="Linux"
else
    echo "Unsupported OS: $OS"
    exit 1
fi

# Detect Arch
ARCH="$(uname -m)"
if [ "$ARCH" = "x86_64" ]; then
    ARCH_TYPE="x86_64"
elif [ "$ARCH" = "arm64" ] || [ "$ARCH" = "aarch64" ]; then
    ARCH_TYPE="arm64"
else
    echo "Unsupported Architecture: $ARCH"
    exit 1
fi

ASSET_NAME="${BINARY}_${OS_TYPE}_${ARCH_TYPE}.tar.gz"
DOWNLOAD_URL="https://github.com/${OWNER}/${REPO}/releases/latest/download/${ASSET_NAME}"

echo "Downloading $ASSET_NAME..."
TMP_DIR=$(mktemp -d)
curl -fsSL "$DOWNLOAD_URL" -o "$TMP_DIR/$ASSET_NAME"

echo "Extracting..."
tar -xzf "$TMP_DIR/$ASSET_NAME" -C "$TMP_DIR"

echo "Installing to $INSTALL_DIR..."
if [ -w "$INSTALL_DIR" ]; then
    mv "$TMP_DIR/$BINARY" "$INSTALL_DIR/$BINARY"
else
    echo "Sudo required to install to $INSTALL_DIR"
    sudo mv "$TMP_DIR/$BINARY" "$INSTALL_DIR/$BINARY"
fi

chmod +x "$INSTALL_DIR/$BINARY"
rm -rf "$TMP_DIR"

echo "$BINARY installed successfully to $INSTALL_DIR/$BINARY"
