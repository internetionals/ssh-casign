#!/bin/sh
# Build the Azure Functions package: a static x86-64 Linux binary (musl,
# rustls) plus the Functions host files, zipped for zip deployment.
#   usage: deploy/azure-functions/build.sh [extra cargo features]
#   output: deploy/azure-functions/dist/ssh-casign-azure-functions.zip
# Needs docker or podman. Set CONFIG to a config.toml to include it in the
# package (otherwise use the SSH_CASIGN_CONFIG_TOML app setting).
set -eu
HERE="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(cd "$HERE/../.." && pwd)"
FEATURES="ca-azure-keyvault,tls-rustls${1:+,$1}"
RUNTIME="${CONTAINER_RUNTIME:-$(command -v docker >/dev/null && docker info >/dev/null 2>&1 && echo docker || echo podman)}"
TARGET_DIR="$HERE/target"
mkdir -p "$TARGET_DIR/cargo-home"

# Cross-compile natively (no emulation) with cargo-zigbuild: Zig serves as
# C compiler and linker for the musl target, on x86-64 and ARM hosts alike.
ZIG_VERSION=0.13.0
case "$(uname -m)" in
  arm64|aarch64) PLATFORM=linux/arm64 ;;
  *) PLATFORM=linux/amd64 ;;
esac
"$RUNTIME" run --rm --platform "$PLATFORM" \
  -v "$ROOT:/src:ro" -v "$TARGET_DIR:/target" -v "$TARGET_DIR/cargo-home:/cargo-home" \
  -w /src -e CARGO_TARGET_DIR=/target -e CARGO_HOME=/cargo-home \
  docker.io/library/rust:1-bookworm sh -ec "
    export PATH=/cargo-home/bin:\$PATH
    if [ ! -x /cargo-home/zig/zig ]; then
      arch=\$(uname -m)
      curl -sSfL https://ziglang.org/download/$ZIG_VERSION/zig-linux-\$arch-$ZIG_VERSION.tar.xz | tar -xJ -C /cargo-home
      mv /cargo-home/zig-linux-\$arch-$ZIG_VERSION /cargo-home/zig
    fi
    export PATH=/cargo-home/zig:\$PATH
    command -v cargo-zigbuild >/dev/null || cargo install --locked --quiet cargo-zigbuild@^0.19
    rustup target add x86_64-unknown-linux-musl >/dev/null
    cargo zigbuild --release --locked --target x86_64-unknown-linux-musl \
      -p ssh-casign-service --no-default-features --features $FEATURES"

DIST="$HERE/dist"
rm -rf "$DIST/package"
mkdir -p "$DIST/package/ssh-casign"
cp "$TARGET_DIR/x86_64-unknown-linux-musl/release/ssh-casign-service" "$DIST/package/"
cp "$HERE/host.json" "$DIST/package/"
cp "$HERE/ssh-casign/function.json" "$DIST/package/ssh-casign/"
if [ -n "${CONFIG:-}" ]; then cp "$CONFIG" "$DIST/package/config.toml"; fi
rm -f "$DIST/ssh-casign-azure-functions.zip"
(cd "$DIST/package" && zip -qr "../ssh-casign-azure-functions.zip" .)
echo "$DIST/ssh-casign-azure-functions.zip (features: $FEATURES)"
