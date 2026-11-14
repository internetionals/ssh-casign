#!/bin/sh
# Build the AWS Lambda container image: a static Linux binary plus the Lambda
# Web Adapter, on the provided.al2023 base image.
#   usage: deploy/aws-lambda/build.sh [extra cargo features]
#   env:   ARCH=arm64 (default, Graviton) or x86_64; IMAGE=name:tag
#          CONFIG=path/to/config.toml to include it (else SSH_CASIGN_CONFIG_TOML)
set -eu
HERE="$(cd "$(dirname "$0")" && pwd)"
ARCH="${ARCH:-arm64}"
IMAGE="${IMAGE:-ssh-casign-lambda:latest}"
BINARY="$("$HERE/../build-static.sh" "$ARCH" "ca-aws-kms${1:+,$1}")"

CONTEXT="$HERE/dist/context"
rm -rf "$CONTEXT"
mkdir -p "$CONTEXT/config"
cp "$HERE/Dockerfile" "$BINARY" "$CONTEXT/"
if [ -n "${CONFIG:-}" ]; then cp "$CONFIG" "$CONTEXT/config/config.toml"; fi
case "$ARCH" in x86_64|amd64) PLATFORM=linux/amd64 ;; *) PLATFORM=linux/arm64 ;; esac
RUNTIME="${CONTAINER_RUNTIME:-$(command -v docker >/dev/null && docker info >/dev/null 2>&1 && echo docker || echo podman)}"
"$RUNTIME" build -q --platform "$PLATFORM" -t "$IMAGE" "$CONTEXT" >&2
echo "$IMAGE ($PLATFORM)"
