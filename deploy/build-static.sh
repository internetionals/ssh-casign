#!/bin/sh
# Build a static Linux ssh-casign-service binary (musl, rustls) for serverless
# platforms, in a rust container.
#   usage: deploy/build-static.sh <x86_64|arm64> <cargo features>
#   prints the path of the binary
#   env:   BUILD_METHOD=native|zig to override the automatic choice
# Needs docker or podman.
#
# When the target architecture is the build machine's own, it builds natively
# with Debian's musl-gcc. Otherwise it cross-compiles with cargo-zigbuild:
# Zig provides the C compiler (for ring's C code) and the linker for the musl
# target. Zig is downloaded once, checked against the SHA-256 published in
# https://ziglang.org/download/index.json, and cached in deploy/target.
set -eu
DEPLOY="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(dirname "$DEPLOY")"
case "$1" in
  x86_64|amd64) TARGET=x86_64-unknown-linux-musl; TARGET_ARCH=x86_64 ;;
  arm64|aarch64) TARGET=aarch64-unknown-linux-musl; TARGET_ARCH=aarch64 ;;
  *) echo "unknown architecture $1 (x86_64 or arm64)" >&2; exit 1 ;;
esac
FEATURES="$2,tls-rustls"
RUNTIME="${CONTAINER_RUNTIME:-$(command -v docker >/dev/null && docker info >/dev/null 2>&1 && echo docker || echo podman)}"
case "$(uname -m)" in
  arm64|aarch64) HOST_ARCH=aarch64; PLATFORM=linux/arm64 ;;
  *) HOST_ARCH=x86_64; PLATFORM=linux/amd64 ;;
esac
if [ "$TARGET_ARCH" = "$HOST_ARCH" ]; then DEFAULT_METHOD=native; else DEFAULT_METHOD=zig; fi
METHOD="${BUILD_METHOD:-$DEFAULT_METHOD}"

TARGET_DIR="$DEPLOY/target"
mkdir -p "$TARGET_DIR/cargo-home"
CARGO_BUILD="cargo build --release --locked --target $TARGET -p ssh-casign-service --no-default-features --features $FEATURES"

case "$METHOD" in
native)
  if [ "$TARGET_ARCH" != "$HOST_ARCH" ]; then
    echo "a native build needs a $TARGET_ARCH build machine; use BUILD_METHOD=zig" >&2
    exit 1
  fi
  SCRIPT="
    apt-get update -qq >/dev/null && apt-get install -y -qq musl-tools >/dev/null
    rustup target add $TARGET >/dev/null
    export CC_$(echo "$TARGET" | tr - _)=musl-gcc
    $CARGO_BUILD"
  ;;
zig)
  # Pinned tools; the checksums are Zig's own, from its download index.
  ZIG_VERSION=0.14.1
  ZIG_SHA256_x86_64=24aeeec8af16c381934a6cd7d95c807a8cb2cf7df9fa40d359aa884195c4716c
  ZIG_SHA256_aarch64=f7a654acc967864f7a050ddacfaa778c7504a0eca8d2b678839c21eea47c992b
  ZIGBUILD_VERSION=0.24.1
  eval "ZIG_SHA256=\$ZIG_SHA256_$HOST_ARCH"
  ZIG_TARBALL="zig-$HOST_ARCH-linux-$ZIG_VERSION.tar.xz"
  SCRIPT="
    ZIG=/cargo-home/zig-$ZIG_VERSION
    if [ ! -x \$ZIG/zig ]; then
      curl -sSfL -o /tmp/$ZIG_TARBALL https://ziglang.org/download/$ZIG_VERSION/$ZIG_TARBALL
      echo '$ZIG_SHA256  /tmp/$ZIG_TARBALL' | sha256sum -c --quiet
      tar -xJf /tmp/$ZIG_TARBALL -C /cargo-home
      mv /cargo-home/zig-$HOST_ARCH-linux-$ZIG_VERSION \$ZIG
    fi
    ZIGBUILD=/cargo-home/cargo-zigbuild-$ZIGBUILD_VERSION
    [ -x \$ZIGBUILD/bin/cargo-zigbuild ] || cargo install --locked --quiet --root \$ZIGBUILD cargo-zigbuild@$ZIGBUILD_VERSION
    export PATH=\$ZIG:\$ZIGBUILD/bin:\$PATH
    rustup target add $TARGET >/dev/null
    $(echo "$CARGO_BUILD" | sed 's/^cargo build/cargo zigbuild/')"
  ;;
*) echo "unknown BUILD_METHOD $METHOD (native or zig)" >&2; exit 1 ;;
esac

echo "building $TARGET ($METHOD)" >&2
"$RUNTIME" run --rm --platform "$PLATFORM" \
  -v "$ROOT:/src:ro" -v "$TARGET_DIR:/target" -v "$TARGET_DIR/cargo-home:/cargo-home" \
  -w /src -e CARGO_TARGET_DIR=/target -e CARGO_HOME=/cargo-home \
  docker.io/library/rust:1-bookworm sh -ec "$SCRIPT" >&2
echo "$TARGET_DIR/$TARGET/release/ssh-casign-service"
