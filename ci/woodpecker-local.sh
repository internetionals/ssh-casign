#!/bin/sh
# Run the Woodpecker workflows (.woodpecker/) locally with woodpecker-cli
# exec, using podman's Docker-compatible API as the backend: the same
# pipeline Woodpecker runs, without a Woodpecker server.
#   usage: ci/woodpecker-local.sh [workflow directory or file, default .woodpecker]
#   env:   PODMAN_SOCKET (default: the socket podman reports; inside the
#          podman machine on macOS)
# The CLI runs in a container next to the pipeline's containers, with the
# repository at the same path, so the workspace it mounts is found. Exits
# with the pipeline's status. The services and the build together need more
# than 4 GiB: on macOS, give the podman machine 8 GiB.
set -eu
cd "$(dirname "$0")/.."
PIPELINE="${1:-.woodpecker}"
SOCKET="${PODMAN_SOCKET:-$(podman info --format '{{.Host.RemoteSocket.Path}}' | sed 's|^unix://||')}"

# woodpecker-cli exec leaves its workspace volumes and, when it's
# interrupted, its containers and networks: remove the ones this run made.
leftovers() {
  podman ps -aq --filter name=wp_ | sed 's/^/container /'
  podman network ls -q --filter name=wp_ | sed 's/^/network /'
  podman volume ls -q --filter name=wp_ | sed 's/^/volume /'
}
BEFORE="$(leftovers)"
cleanup() {
  leftovers | while read -r kind id; do
    printf '%s\n' "$BEFORE" | grep -qx "$kind $id" && continue
    case "$kind" in
      container) podman rm -f "$id" ;;
      network) podman network rm -f "$id" ;;
      volume) podman volume rm -f "$id" ;;
    esac >/dev/null 2>&1 || true
  done
}
trap cleanup EXIT
trap 'exit 130' INT TERM

# The "no such container" errors at the end of each workflow are harmless:
# the teardown removes the services before it waits for them, and podman
# answers that with a 404 Woodpecker doesn't recognise.
# https://github.com/woodpecker-ci/woodpecker/issues/7472 (fix: PR #7535).
# Drop this comment once a woodpecker-cli release with the fix is pinned below.
podman run --rm --user 0 --security-opt label=disable \
  -v "$SOCKET:/var/run/docker.sock" -v "$PWD:$PWD" -w "$PWD" \
  docker.io/woodpeckerci/woodpecker-cli:v3.18.1 \
  exec --backend-engine docker --local --repo-path "$PWD" "$PIPELINE"
