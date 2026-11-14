#!/bin/sh
# Build a static Linux ssh-casign-service binary (musl, rustls) for serverless
# platforms, cross-compiled in a rust container with cargo-zigbuild: Zig is the
# C compiler and linker for the musl target, so no emulation is needed and it
# works on x86-64 and ARM hosts alike.
#   usage: deploy/build-static.sh <x86_64|arm64> <cargo features>
#   prints the path of the binary
# Needs docker or podman.
set -eu
DEPLOY="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(dirname "$DEPLOY")"
case "$1" in
  x86_64|amd64) TARGET=x86_64-unknown-linux-musl ;;
  arm64|aarch64) TARGET=aarch64-unknown-linux-musl ;;
  *) echo "unknown architecture $1 (x86_64 or arm64)" >&2; exit 1 ;;
esac
FEATURES="$2,tls-rustls"
RUNTIME="${CONTAINER_RUNTIME:-$(command -v docker >/dev/null && docker info >/dev/null 2>&1 && echo docker || echo podman)}"
TARGET_DIR="$DEPLOY/target"
mkdir -p "$TARGET_DIR/cargo-home"
case "$(uname -m)" in
  arm64|aarch64) PLATFORM=linux/arm64 ;;
  *) PLATFORM=linux/amd64 ;;
esac
# Zig 0.14+ is needed for aarch64: it accepts the linker flag Rust passes for
# that target (--fix-cortex-a53-843419).
ZIG_VERSION=0.14.1
ZIGBUILD_VERSION=0.24.1
"$RUNTIME" run --rm --platform "$PLATFORM" \
  -v "$ROOT:/src:ro" -v "$TARGET_DIR:/target" -v "$TARGET_DIR/cargo-home:/cargo-home" \
  -w /src -e CARGO_TARGET_DIR=/target -e CARGO_HOME=/cargo-home \
  docker.io/library/rust:1-bookworm sh -ec "
    export PATH=/cargo-home/bin:\$PATH
    ZIG=/cargo-home/zig-$ZIG_VERSION
    if [ ! -x \$ZIG/zig ]; then
      arch=\$(uname -m)
      curl -sSfL https://ziglang.org/download/$ZIG_VERSION/zig-\$arch-linux-$ZIG_VERSION.tar.xz | tar -xJ -C /cargo-home
      mv /cargo-home/zig-\$arch-linux-$ZIG_VERSION \$ZIG
    fi
    export PATH=\$ZIG:\$PATH
    ZIGBUILD=/cargo-home/cargo-zigbuild-$ZIGBUILD_VERSION
    [ -x \$ZIGBUILD/bin/cargo-zigbuild ] || cargo install --locked --quiet --root \$ZIGBUILD cargo-zigbuild@$ZIGBUILD_VERSION
    export PATH=\$ZIGBUILD/bin:\$PATH
    rustup target add $TARGET >/dev/null
    cargo zigbuild --release --locked --target $TARGET \
      -p ssh-casign-service --no-default-features --features $FEATURES" >&2
echo "$TARGET_DIR/$TARGET/release/ssh-casign-service"
