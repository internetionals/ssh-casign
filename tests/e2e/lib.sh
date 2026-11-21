# Shared helpers for the end-to-end scenarios. Sourced by every scenario:
#
#   source "$(dirname "$0")/../../lib.sh"
#   scenario "what it tests"
#   check "name" command ...
#   finish
#
# Dependencies are reached by name (oidc, dex, openbao, ...): run.sh starts
# them on a podman network with those names, and CI runs them as services
# with the same names. Override with E2E_<NAME> (base URLs) if needed.

set -u

E2E_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
E2E_ROOT="$(cd "$E2E_DIR/../.." && pwd)"
E2E_BIN="${E2E_BIN:-${CARGO_TARGET_DIR:-$E2E_ROOT/target}/debug}"
SERVICE="$E2E_BIN/ssh-casign-service"
CLIENT="$E2E_BIN/ssh-casign-client"

OIDC="${E2E_OIDC:-http://oidc:8080}"
DEX="${E2E_DEX:-http://dex:5556}"
OPENBAO="${E2E_OPENBAO:-http://openbao:8200}"
LOCALSTACK="${E2E_LOCALSTACK:-http://localstack:4566}"
AZURITE="${E2E_AZURITE:-http://azurite:10000}"
GCS="${E2E_GCS:-http://gcs:4443}"
LOWKEY="${E2E_LOWKEY:-https://lowkey:8443}"
TOKENREVIEW="${E2E_TOKENREVIEW:-http://tokenreview:8443}"

# A short scratch directory: Unix socket paths are limited to ~104 bytes.
T="$(mktemp -d /tmp/e2e.XXXXXX)"
E2E_PASSED=0
E2E_FAILED=0
E2E_PIDS=()
E2E_NAME="$(basename "$0" .sh)"

cleanup() {
  local pid
  for pid in ${E2E_PIDS[@]+"${E2E_PIDS[@]}"}; do kill "$pid" 2>/dev/null; done
  wait 2>/dev/null
  [ -n "${POD:-}" ] && "$RUNTIME" pod rm -f "$POD" >/dev/null 2>&1
  if [ "$E2E_FAILED" -gt 0 ] && [ -n "${E2E_KEEP:-}" ]; then
    echo "   (kept $T)"
  else
    rm -rf "$T"
  fi
}
trap cleanup EXIT

scenario() {
  echo "== $E2E_NAME: $*"
}

# Run a command in the background for the rest of the scenario; its output
# goes to $T/background.log.
background() {
  "$@" >> "$T/background.log" 2>&1 &
  E2E_PIDS+=($!)
}

_report() {
  local name="$1" ok="$2" detail="$3"
  if [ "$ok" = 0 ]; then
    E2E_PASSED=$((E2E_PASSED + 1))
    echo "   ok    $name"
  else
    E2E_FAILED=$((E2E_FAILED + 1))
    echo "   FAIL  $name"
    printf '%s\n' "$detail" | sed 's/^/         /' | head -15
  fi
}

# check NAME COMMAND...: passes when the command succeeds.
check() {
  local name="$1"; shift
  local out
  out="$("$@" 2>&1)"
  _report "$name" $? "$out"
}

# check_out NAME PATTERN COMMAND...: succeeds and prints PATTERN (grep -E).
check_out() {
  local name="$1" pattern="$2"; shift 2
  local out status
  out="$("$@" 2>&1)"; status=$?
  if [ $status = 0 ] && grep -qE -- "$pattern" <<<"$out"; then
    _report "$name" 0 ""
  else
    _report "$name" 1 "exit $status, expected /$pattern/ in:
$out"
  fi
}

# check_has NAME TEXT COMMAND...: succeeds and prints TEXT (a fixed string,
# e.g. a fingerprint, whose + and / aren't regex-safe).
check_has() {
  local name="$1" text="$2"; shift 2
  local out status
  out="$("$@" 2>&1)"; status=$?
  if [ $status = 0 ] && grep -qF -- "$text" <<<"$out"; then
    _report "$name" 0 ""
  else
    _report "$name" 1 "exit $status, expected '$text' in:
$out"
  fi
}

# check_says NAME PATTERN COMMAND...: prints PATTERN, whatever its exit status
# (ssh-keygen -Q exits 1 when it finds a revoked key).
check_says() {
  local name="$1" pattern="$2"; shift 2
  local out
  out="$("$@" 2>&1)"
  if grep -qE -- "$pattern" <<<"$out"; then
    _report "$name" 0 ""
  else
    _report "$name" 1 "expected /$pattern/ in:
$out"
  fi
}

# check_fail NAME PATTERN COMMAND...: fails and prints PATTERN.
check_fail() {
  local name="$1" pattern="$2"; shift 2
  local out status
  out="$("$@" 2>&1)"; status=$?
  if [ $status != 0 ] && grep -qE -- "$pattern" <<<"$out"; then
    _report "$name" 0 ""
  else
    _report "$name" 1 "exit $status, expected a failure with /$pattern/ in:
$out"
  fi
}

# check_eq NAME EXPECTED ACTUAL
check_eq() {
  if [ "$2" = "$3" ]; then _report "$1" 0 ""; else _report "$1" 1 "expected '$2', got '$3'"; fi
}

finish() {
  echo "   $E2E_PASSED passed, $E2E_FAILED failed"
  [ "$E2E_FAILED" = 0 ]
  exit $?
}

# skip REASON: the scenario can't run here (not a failure).
skip() {
  echo "   skipped: $*"
  exit 0
}

# wait_for URL [SECONDS]: until URL answers (any HTTP status).
wait_for() {
  local url="$1" seconds="${2:-60}" i
  for i in $(seq $((seconds * 4))); do
    curl -sk -o /dev/null --max-time 2 "$url" && return 0
    sleep 0.25
  done
  echo "timed out waiting for $url" >&2
  return 1
}

# require NAME URL: skip the scenario when a dependency isn't there.
require() {
  wait_for "$2" "${E2E_WAIT:-60}" 2>/dev/null || skip "$1 is not reachable at $2"
}

# The mock IdP's token for a test user (user1, admin1) from its config.
mock_token() {
  curl -sf -d grant_type=client_credentials -d "code=$1" -d client_id=ssh-casign \
    -d client_secret=x "$OIDC/ssh-casign/token" | jq -r .access_token
}

# service_start CONFIG [LISTEN]: start the service and wait for discovery.
# Sets SERVICE_URL; the log is $T/service.log.
service_start() {
  local config="$1" listen="${2:-127.0.0.1:3000}"
  SSH_CASIGN_CONFIG="$config" SSH_CASIGN_LISTEN="$listen" "$SERVICE" >> "$T/service.log" 2>&1 &
  SERVICE_PID=$!
  E2E_PIDS+=($SERVICE_PID)
  SERVICE_URL="http://$listen"
  local i
  for i in $(seq 120); do
    curl -sf -o /dev/null "$SERVICE_URL/.well-known/ssh-casign" && return 0
    kill -0 $SERVICE_PID 2>/dev/null || { echo "service exited:"; tail -5 "$T/service.log"; return 1; }
    sleep 0.25
  done
  echo "service didn't come up"; tail -5 "$T/service.log"; return 1
}

service_stop() {
  [ -n "${SERVICE_PID:-}" ] || return 0
  kill "$SERVICE_PID" 2>/dev/null
  wait "$SERVICE_PID" 2>/dev/null
  SERVICE_PID=
}

# The service must refuse to start with CONFIG; prints its error.
service_refuses() {
  local config="$1"
  SSH_CASIGN_CONFIG="$config" SSH_CASIGN_LISTEN=127.0.0.1:3999 timeout 30 "$SERVICE" 2>&1 \
    | sed 's/\x1b\[[0-9;]*m//g' | grep -E "ERROR" && return 1
  return 0
}

# A service config with the mock IdP and a file CA; extra TOML appended.
# Generates $T/ca (user CA) unless it exists.
mock_config() {
  [ -f "$T/ca" ] || ssh-keygen -q -t ed25519 -N '' -C e2e-user-ca -f "$T/ca"
  cat <<EOF
server_id = "e2e"
listen = "127.0.0.1:3000"

[oidc_provider]
issuer = "$OIDC/ssh-casign"
client_id = "ssh-casign"
id_claim = "upn"

[profiles.default]
ssh_ca = "users"
validity = 300
max_validity = 86400

[authorities.users]
provider = "file"
private_key_file = "$T/ca"
cert_types = ["user"]

$*
EOF
}

# The client with a config of its own (no token cache).
client() {
  "$CLIENT" -f "$T/client.toml" "$@"
}

client_config() {
  cat > "$T/client.toml" <<EOF
token_store = "none"
[profiles.default]
url = "${1:-$SERVICE_URL}/"
EOF
}

# sshd_start CA_PUB PRINCIPAL [EXTRA_CONFIG]: a throwaway sshd on 127.0.0.1:2222
# for the current user, trusting CA_PUB and accepting PRINCIPAL.
sshd_start() {
  local ca="$1" principal="$2" extra="${3:-}"
  mkdir -p "$T/sshd"
  [ -f "$T/sshd/host_key" ] || ssh-keygen -q -t ed25519 -N '' -f "$T/sshd/host_key"
  cp "$ca" "$T/sshd/ca.pub"
  echo "$principal" > "$T/sshd/principals"
  mkdir -p /run/sshd 2>/dev/null
  cat > "$T/sshd/config" <<EOF
Port 2222
ListenAddress 127.0.0.1
HostKey $T/sshd/host_key
PidFile $T/sshd/pid
TrustedUserCAKeys $T/sshd/ca.pub
AuthorizedPrincipalsFile $T/sshd/principals
AuthorizedKeysFile none
PasswordAuthentication no
KbdInteractiveAuthentication no
PermitRootLogin prohibit-password
UsePAM no
StrictModes no
LogLevel VERBOSE
$extra
EOF
  # PerSourcePenalties (OpenSSH 9.8+) would lock out the repeated test logins.
  if "$(command -v sshd || echo /usr/sbin/sshd)" -T -f "$T/sshd/config" 2>/dev/null | grep -qi persourcepenalties; then
    echo "PerSourcePenalties no" >> "$T/sshd/config"
  fi
  "$(command -v sshd || echo /usr/sbin/sshd)" -D -e -f "$T/sshd/config" > "$T/sshd/log" 2>&1 &
  E2E_PIDS+=($!)
  local i
  for i in $(seq 40); do
    (exec 3<>/dev/tcp/127.0.0.1/2222) 2>/dev/null && return 0
    sleep 0.25
  done
  echo "sshd didn't come up"; cat "$T/sshd/log"; return 1
}

sshd_stop() {
  [ -f "$T/sshd/pid" ] && kill "$(cat "$T/sshd/pid")" 2>/dev/null
  local i
  for i in $(seq 40); do
    (exec 3<>/dev/tcp/127.0.0.1/2222) 2>/dev/null || return 0
    sleep 0.25
  done
}

# ssh_login KEY [extra ssh options]: log in to the throwaway sshd with KEY
# (and KEY-cert.pub), print the remote user.
ssh_login() {
  local key="$1"; shift
  ssh -F /dev/null -p 2222 -i "$key" -o IdentitiesOnly=yes -o IdentityAgent=none \
    -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o BatchMode=yes \
    -o LogLevel=ERROR -o ConnectTimeout=5 "$@" 127.0.0.1 'echo "logged in as $(id -un)"'
}

# ssh_agent_login: log in with whatever is in $SSH_AUTH_SOCK.
ssh_agent_login() {
  ssh -F /dev/null -p 2222 -o IdentityFile=none -o IdentityAgent=SSH_AUTH_SOCK \
    -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o BatchMode=yes \
    -o LogLevel=ERROR -o ConnectTimeout=5 "$@" 127.0.0.1 'echo "logged in as $(id -un)"'
}

# The signing CA of a certificate file, as ssh-keygen shows it.
signing_ca() {
  ssh-keygen -L -f "$1" | sed -n 's/.*Signing CA: //p'
}

fingerprint() {
  ssh-keygen -l -f "$1" | awk '{print $2}'
}

# A CEF field from the audit log's records, one value per line.
cef_field() {
  local field="$1" file="$2"
  grep -oE "(^| )$field=[^=]*( [a-zA-Z0-9]+=|$)" "$file" \
    | sed -E "s/^ ?$field=//; s/ [a-zA-Z0-9]+=$//"
}

# sign_with ALGORITHM: a certificate for $T/user.pub signed with ALGORITHM
# ("" for the default); prints "<CA type> <algorithm>", e.g. "RSA rsa-sha2-512".
sign_with() {
  rm -f "$T/user-cert.pub"
  client cert ${1:+--ca-signature-algorithm "$1"} -o "$T/user-cert.pub" "$T/user.pub" >/dev/null 2>"$T/sign.err" \
    || { cat "$T/sign.err"; return 1; }
  signing_ca "$T/user-cert.pub" | sed -E 's/^([A-Z0-9]+) SHA256:[^ ]+ \(using ([^)]+)\)$/\1 \2/'
}

# The CA public keys in the discovery document, one per line.
discovery_ca_keys() {
  curl -sf "$SERVICE_URL/.well-known/ssh-casign" | jq -r '.authorities[].public_key' | sort -u
}

# --- the packages tier (on the host, starting containers itself) ---

RUNTIME="${CONTAINER_RUNTIME:-$(command -v podman >/dev/null && echo podman || echo docker)}"

# host_build: the client for the host (packages run outside the runner image).
host_build() {
  (cd "$E2E_ROOT" && cargo build --locked -q -p ssh-casign-client) || return 1
}

# pod_start NAME PORT...: a pod publishing host PORT:PORT, with the mock IdP
# at localhost:8090 inside it and on the host (8080 is the Lambda emulator's).
pod_start() {
  local name="$1"; shift
  local ports=(-p 8090:8090) port
  for port in "$@"; do ports+=(-p "$port"); done
  "$RUNTIME" pod rm -f "$name" >/dev/null 2>&1
  "$RUNTIME" pod create --name "$name" "${ports[@]}" >/dev/null || return 1
  POD="$name"
  "$RUNTIME" run -d --pod "$name" --name "$name-oidc" -v "$E2E_DIR:/e2e:ro" -e SERVER_PORT=8090 \
    -e JSON_CONFIG_PATH=/e2e/fixtures/mock-oidc.json ghcr.io/navikt/mock-oauth2-server:2.1.10 >/dev/null || return 1
  OIDC=http://localhost:8090
  wait_for "$OIDC/ssh-casign/.well-known/openid-configuration" 90
}

pod_stop() {
  [ -n "${POD:-}" ] && "$RUNTIME" pod rm -f "$POD" >/dev/null 2>&1
}
