#!/bin/bash
# The Azure Functions package (custom handler) in the Functions host image,
# signing with Lowkey Vault (Key Vault).
source "$(dirname "$0")/../../lib.sh"
scenario "Azure Functions package"
command -v "$RUNTIME" >/dev/null || skip "needs podman or docker"
host_build || exit 1
check "build the package (static, x86-64)" "$E2E_ROOT/deploy/azure-functions/build.sh"
pod_start ssh-casign-e2e-functions 7071:80 8443:8443 || exit 1
"$RUNTIME" run -d --pod "$POD" --name "$POD-kv" docker.io/nagyesta/lowkey-vault:2.7.1 >/dev/null
wait_for https://localhost:8443/ping 120 || exit 1
key() {
  curl -sk -X POST "https://localhost:8443/keys/$1/create?api-version=7.4" -H 'Authorization: Bearer x' \
    -H 'Content-Type: application/json' -d "$2" >/dev/null
}
key e2e-ec '{"kty":"EC","crv":"P-256","key_ops":["sign","verify"]}'
key e2e-rsa '{"kty":"RSA","key_size":3072,"key_ops":["sign","verify"]}'
# Mounted into the container: podman on macOS only shares the home
# directory, so not $T under /tmp.
EXTRA="$(mktemp -d "$E2E_ROOT/target/e2e-functions.XXXXXX")"
trap 'rm -rf "$EXTRA"; cleanup' EXIT
echo | openssl s_client -connect localhost:8443 -servername localhost 2>/dev/null | openssl x509 > "$EXTRA/lowkey.pem"
# The App Service managed identity endpoint (Lowkey Vault accepts any token).
"$RUNTIME" run -d --pod "$POD" --name "$POD-identity" -v "$E2E_DIR:/e2e:ro" \
  docker.io/library/python:3.12.8-slim-bookworm python3 -I -B /e2e/mocks/azure_identity.py 8181 >/dev/null
CONFIG="server_id = \"functions-e2e\"
[oidc_provider]
issuer = \"$OIDC/ssh-casign\"
client_id = \"ssh-casign\"
id_claim = \"upn\"
[profiles.default]
ssh_ca = [\"kv-ec\", \"kv-rsa\"]
validity = 300
[authorities.kv-ec]
provider = \"azure_keyvault\"
vault_url = \"https://localhost:8443\"
key = \"e2e-ec\"
ca_cert_file = \"/extra/lowkey.pem\"
cert_types = [\"user\"]
[authorities.kv-rsa]
provider = \"azure_keyvault\"
vault_url = \"https://localhost:8443\"
key = \"e2e-rsa\"
ca_cert_file = \"/extra/lowkey.pem\"
cert_types = [\"user\"]
[audit]
client_address_header = \"x-forwarded-for\"
trusted_proxies = [\"127.0.0.1/32\", \"::1/128\"]
[[audit.sink]]
type = \"stdout\""
"$RUNTIME" run -d --pod "$POD" --name "$POD-func" \
  -v "$E2E_ROOT/deploy/azure-functions/dist/package:/home/site/wwwroot:ro" -v "$EXTRA:/extra:ro" \
  -e AzureWebJobsScriptRoot=/home/site/wwwroot -e FUNCTIONS_WORKER_RUNTIME=custom \
  -e AzureWebJobsSecretStorageType=files -e AzureFunctionsJobHost__Logging__Console__IsEnabled=true \
  -e IDENTITY_ENDPOINT=http://127.0.0.1:8181/msi/token -e IDENTITY_HEADER=e2e \
  -e SSH_CASIGN_CONFIG_TOML="$CONFIG" mcr.microsoft.com/azure-functions/base:4 >/dev/null
wait_for http://127.0.0.1:7071/.well-known/ssh-casign 180 || { "$RUNTIME" logs "$POD-func" 2>&1 | tail -30; exit 1; }
cat > "$T/client.toml" <<CONF
token_store = "none"
[profiles.default]
url = "http://127.0.0.1:7071/"
CONF
ssh-keygen -q -t ed25519 -N '' -f "$T/user"
export SSH_CASIGN_TOKEN="$(mock_token user1)"
check_out "discovery through the Functions host" '"kv-rsa"' curl -sf http://127.0.0.1:7071/.well-known/ssh-casign
check_out "a certificate signed in Key Vault (P-256)" '^ECDSA ecdsa-sha2-nistp256$' sign_with ""
check_out "a certificate signed in Key Vault (RSA)" '^RSA rsa-sha2-256$' sign_with rsa-sha2-256
check_out "audit records in the host log" 'CEF:0\|' "$RUNTIME" logs "$POD-func"
finish
