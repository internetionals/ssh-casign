#!/bin/sh
# Build the Azure Functions package: a static x86-64 Linux binary plus the
# Functions host files, zipped for zip deployment.
#   usage: deploy/azure-functions/build.sh [extra cargo features]
#   output: deploy/azure-functions/dist/ssh-casign-azure-functions.zip
# Set CONFIG to a config.toml to include it in the package (otherwise use the
# SSH_CASIGN_CONFIG_TOML app setting).
set -eu
HERE="$(cd "$(dirname "$0")" && pwd)"
BINARY="$("$HERE/../build-static.sh" x86_64 "ca-azure-keyvault${1:+,$1}")"

DIST="$HERE/dist"
rm -rf "$DIST/package"
mkdir -p "$DIST/package/ssh-casign"
cp "$BINARY" "$DIST/package/ssh-casign-service"
cp "$HERE/host.json" "$DIST/package/"
cp "$HERE/ssh-casign/function.json" "$DIST/package/ssh-casign/"
if [ -n "${CONFIG:-}" ]; then cp "$CONFIG" "$DIST/package/config.toml"; fi
rm -f "$DIST/ssh-casign-azure-functions.zip"
(cd "$DIST/package" && zip -qr "../ssh-casign-azure-functions.zip" .)
echo "$DIST/ssh-casign-azure-functions.zip"
