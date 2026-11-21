#!/bin/bash
# Run end-to-end scenarios against dependencies that are already running
# (started by run.sh, or CI services), and summarize.
#   usage: tests/e2e/suite.sh [--tier core|backends]... [--no-build] [SCENARIO...]
#   env:   E2E_KEEP=1 keeps the scratch directory of failed scenarios
set -u
DIR="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(cd "$DIR/../.." && pwd)"
TIERS=()
NAMES=()
BUILD=1
while [ $# -gt 0 ]; do
  case "$1" in
    --tier) TIERS+=("$2"); shift 2 ;;
    --no-build) BUILD=0; shift ;;
    -h|--help) sed -n 2,6p "$0"; exit 0 ;;
    *) NAMES+=("$1"); shift ;;
  esac
done
[ ${#TIERS[@]} -gt 0 ] || TIERS=(core backends)

# Every backend and store, so one build serves all scenarios.
FEATURES="ca-file,ca-pkcs11,ca-vault,ca-azure-keyvault,ca-aws-kms,ca-gcp-kms,ca-barbican,store-s3,store-gcs,store-azure-blob,tls-native"
if [ $BUILD = 1 ]; then
  echo "== building"
  (cd "$ROOT" && cargo build --locked -q -p ssh-casign-client \
    && cargo build --locked -q -p ssh-casign-service --no-default-features --features "$FEATURES") || exit 1
fi

scenarios=()
for tier in "${TIERS[@]}"; do
  for file in "$DIR/scenarios/$tier"/*.sh; do
    name="$(basename "$file" .sh)"
    if [ ${#NAMES[@]} -gt 0 ]; then
      printf '%s\n' "${NAMES[@]}" | grep -qx "$name" || continue
    fi
    scenarios+=("$file")
  done
done
[ ${#scenarios[@]} -gt 0 ] || { echo "no scenarios selected"; exit 1; }

failed=()
for file in "${scenarios[@]}"; do
  bash "$file" || failed+=("$(basename "$(dirname "$file")")/$(basename "$file" .sh)")
done

echo
echo "== ${#scenarios[@]} scenario(s), ${#failed[@]} failed"
for name in "${failed[@]}"; do echo "   $name"; done
[ ${#failed[@]} = 0 ]
