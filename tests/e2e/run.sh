#!/bin/bash
# Run the end-to-end suite locally with podman (or docker): start the
# dependencies the selected scenarios need on a container network, under the
# names the scenarios use, and run the suite in the runner image.
#   usage: tests/e2e/run.sh [--tier core|backends|packages]... [SCENARIO...]
#   env:   CONTAINER_RUNTIME=podman|docker, E2E_KEEP=1 (keep failed scratch dirs)
# The packages tier (container images, podman secrets) runs on the host, since
# it starts containers itself.
set -u
DIR="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(cd "$DIR/../.." && pwd)"
RUNTIME="${CONTAINER_RUNTIME:-$(command -v podman >/dev/null && echo podman || echo docker)}"
NET=ssh-casign-e2e
IMAGE=localhost/ssh-casign-e2e-runner:latest

TIERS=()
NAMES=()
while [ $# -gt 0 ]; do
  case "$1" in
    --tier) TIERS+=("$2"); shift 2 ;;
    -h|--help) sed -n 2,8p "$0"; exit 0 ;;
    *) NAMES+=("$1"); shift ;;
  esac
done
[ ${#TIERS[@]} -gt 0 ] || TIERS=(core backends)

# Dependencies by name: image and arguments. Keep in step with .woodpecker/e2e.yaml.
dep_run() {
  local name="$1"
  local base=(--detach --rm --name "ssh-casign-e2e-$name" --network "$NET" --network-alias "$name")
  case "$name" in
    oidc) "$RUNTIME" run "${base[@]}" -v "$DIR:/e2e:ro" \
            -e JSON_CONFIG_PATH=/e2e/fixtures/mock-oidc.json ghcr.io/navikt/mock-oauth2-server:2.1.10 ;;
    dex) "$RUNTIME" run "${base[@]}" -v "$DIR:/e2e:ro" \
            ghcr.io/dexidp/dex:v2.41.1 dex serve /e2e/fixtures/dex.yaml ;;
    openbao) "$RUNTIME" run "${base[@]}" -e BAO_DEV_ROOT_TOKEN_ID=root \
            docker.io/openbao/openbao:2.1.0 server -dev -dev-listen-address=0.0.0.0:8200 ;;
    tokenreview) "$RUNTIME" run "${base[@]}" -v "$DIR:/e2e:ro" docker.io/library/python:3.12.8-slim-bookworm \
            python3 -I -B /e2e/mocks/tokenreview.py 8443 /e2e/fixtures/k8s-token ;;
    localstack) "$RUNTIME" run "${base[@]}" -e SERVICES=kms,s3 docker.io/localstack/localstack:4.0.3 ;;
    azurite) "$RUNTIME" run "${base[@]}" mcr.microsoft.com/azure-storage/azurite:3.35.0 \
            azurite-blob --blobHost 0.0.0.0 --skipApiVersionCheck --location /tmp/azurite ;;
    gcs) "$RUNTIME" run "${base[@]}" docker.io/fsouza/fake-gcs-server:1.54.0 \
            -scheme http -port 4443 -public-host gcs:4443 ;;
    lowkey) "$RUNTIME" run "${base[@]}" docker.io/nagyesta/lowkey-vault:2.7.1 ;;
    *) echo "unknown dependency $name" >&2; return 1 ;;
  esac
}

selected() {
  local tier file name
  for tier in "$@"; do
    for file in "$DIR/scenarios/$tier"/*.sh; do
      name="$(basename "$file" .sh)"
      if [ ${#NAMES[@]} -gt 0 ]; then
        printf '%s\n' ${NAMES[@]+"${NAMES[@]}"} | grep -qx "$name" || continue
      fi
      echo "$file"
    done
  done
}

container_tiers=()
host_tiers=()
for tier in "${TIERS[@]}"; do
  if [ "$tier" = packages ]; then host_tiers+=("$tier"); else container_tiers+=("$tier"); fi
done

status=0
if [ ${#container_tiers[@]} -gt 0 ] && [ -n "$(selected ${container_tiers[@]+"${container_tiers[@]}"})" ]; then
  deps="$(selected "${container_tiers[@]}" | xargs sed -n 's/^# needs: //p' | tr ' ' '\n' | sort -u | grep -v '^$')"
  cleanup() {
    for dep in $deps; do "$RUNTIME" rm -f "ssh-casign-e2e-$dep" >/dev/null 2>&1; done
    "$RUNTIME" rm -f ssh-casign-e2e-suite >/dev/null 2>&1
    "$RUNTIME" network rm "$NET" >/dev/null 2>&1
  }
  trap cleanup EXIT
  cleanup
  echo "== runner image"
  "$RUNTIME" build -q -t "$IMAGE" "$DIR" >/dev/null || exit 1
  "$RUNTIME" network create "$NET" >/dev/null
  for dep in $deps; do
    echo "== starting $dep"
    dep_run "$dep" >/dev/null || exit 1
  done
  args=()
  for tier in "${container_tiers[@]}"; do args+=(--tier "$tier"); done
  # (bash 3.2 on macOS: an empty array is "unbound" under set -u)
  "$RUNTIME" run --rm --name ssh-casign-e2e-suite --network "$NET" \
    -v "$ROOT:/src:ro" -v ssh-casign-e2e-cargo:/usr/local/cargo/registry \
    -v ssh-casign-e2e-target:/target -e CARGO_TARGET_DIR=/target -e E2E_KEEP="${E2E_KEEP:-}" \
    -w /src "$IMAGE" tests/e2e/suite.sh "${args[@]}" ${NAMES[@]+"${NAMES[@]}"} || status=1
fi

for tier in ${host_tiers[@]+"${host_tiers[@]}"}; do
  for file in $(selected "$tier"); do
    bash "$file" || status=1
  done
done
exit $status
