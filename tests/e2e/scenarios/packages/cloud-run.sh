#!/bin/bash
# The Google Cloud Run image (static binary on distroless) with the CA key
# and the configuration as podman secrets: mounted files (0400, owned by the
# image's nonroot user) and an environment secret.
source "$(dirname "$0")/../../lib.sh"
scenario "Cloud Run image and podman secrets"
command -v "$RUNTIME" >/dev/null || skip "needs podman or docker"
host_build || exit 1
ARCH="$(case "$(uname -m)" in arm64|aarch64) echo arm64 ;; *) echo x86_64 ;; esac)"
check_out "build the image (static, $ARCH)" 'ssh-casign-e2e-cloud-run' \
  env ARCH="$ARCH" IMAGE=ssh-casign-e2e-cloud-run:latest "$E2E_ROOT/deploy/gcp-cloud-run/build.sh" ca-file
ssh-keygen -q -t ed25519 -N '' -C e2e-user-ca -f "$T/ca"
cat > "$T/config.toml" <<CONF
server_id = "cloud-run-e2e"
[oidc_provider]
issuer = "http://localhost:8090/ssh-casign"
client_id = "ssh-casign"
id_claim = "upn"
[profiles.default]
ssh_ca = "users"
validity = 300
[authorities.users]
provider = "file"
private_key_file = "/run/secrets/ca-key"
cert_types = ["user"]
[audit]
client_address_header = "x-forwarded-for"
trusted_proxies = ["0.0.0.0/0", "::/0"]
[[audit.sink]]
type = "stdout"
CONF
"$RUNTIME" secret rm ssh-casign-e2e-ca ssh-casign-e2e-config >/dev/null 2>&1
"$RUNTIME" secret create ssh-casign-e2e-ca "$T/ca" >/dev/null
"$RUNTIME" secret create ssh-casign-e2e-config "$T/config.toml" >/dev/null
pod_start ssh-casign-e2e-cloud-run 7074:8000 || exit 1
cat > "$T/client.toml" <<CONF
token_store = "none"
[profiles.default]
url = "http://127.0.0.1:7074/"
CONF
ssh-keygen -q -t ed25519 -N '' -f "$T/user"
run_service() {
  "$RUNTIME" rm -f ssh-casign-e2e-cloud-run-svc >/dev/null 2>&1
  "$RUNTIME" run -d --pod "$POD" --name ssh-casign-e2e-cloud-run-svc -e PORT=8000 \
    --secret ssh-casign-e2e-ca,target=/run/secrets/ca-key,mode=0400,uid=65532 "$@" \
    ssh-casign-e2e-cloud-run:latest >/dev/null
  wait_for http://127.0.0.1:7074/.well-known/ssh-casign 60
}
issue() { SSH_CASIGN_TOKEN="$(mock_token user1)" "$CLIENT" -f "$T/client.toml" cert -o - "$T/user.pub" | ssh-keygen -L -f -; }
run_service --secret ssh-casign-e2e-config,target=/etc/ssh-casign/config.toml,mode=0400,uid=65532
check_has "mounted secrets: signed with the secret CA key" "$(fingerprint "$T/ca.pub")" issue
check_out "runs as the nonroot user" '65532|nonroot' "$RUNTIME" inspect ssh-casign-e2e-cloud-run-svc --format '{{.Config.User}}'
check_out "audit records on stdout" 'CEF:0\|' "$RUNTIME" logs ssh-casign-e2e-cloud-run-svc
check_eq "the key isn't in the container's inspect output" 0 \
  "$("$RUNTIME" inspect ssh-casign-e2e-cloud-run-svc | grep -c 'PRIVATE KEY')"
run_service --secret ssh-casign-e2e-config,type=env,target=SSH_CASIGN_CONFIG_TOML
check_has "environment secret for the configuration" "$(fingerprint "$T/ca.pub")" issue
"$RUNTIME" secret rm ssh-casign-e2e-ca ssh-casign-e2e-config >/dev/null 2>&1
finish
