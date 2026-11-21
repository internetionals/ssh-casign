#!/bin/sh
# Static checks and unit tests, as CI runs them (and as you can before
# pushing): formatting, clippy for the workspace and for every service
# feature combination a deployment uses, the unit tests, and the client's
# Windows build.
#   usage: ci/check.sh
set -eu
cd "$(dirname "$0")/.."

echo "== fmt"
cargo fmt --all --check

echo "== clippy (workspace, all features)"
cargo clippy --locked --workspace --all-targets --all-features -q -- -D warnings

echo "== clippy (service feature combinations)"
for features in \
  ca-file,tls-native \
  ca-pkcs11,tls-native \
  ca-vault,tls-rustls \
  ca-azure-keyvault,store-azure-blob,tls-rustls \
  ca-aws-kms,store-s3,tls-rustls \
  ca-gcp-kms,store-gcs,tls-rustls \
  ca-barbican,tls-rustls; do
  echo "   $features"
  cargo clippy --locked -q -p ssh-casign-service --no-default-features --features "$features" -- -D warnings
done

echo "== unit tests"
cargo test --locked --workspace -q

echo "== client for Windows (cargo check)"
rustup target add x86_64-pc-windows-msvc >/dev/null 2>&1
cargo check --locked -q -p ssh-casign-client --target x86_64-pc-windows-msvc
echo "== all checks passed"
