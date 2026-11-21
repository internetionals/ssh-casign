#!/bin/bash
# needs: oidc lowkey azurite
# Azure Key Vault (Lowkey Vault) with a managed identity, and the Azure Blob
# store (Azurite, Shared Key).
source "$(dirname "$0")/../../lib.sh"
scenario "Azure Key Vault backend and Blob store"
require oidc "$OIDC/ssh-casign/.well-known/openid-configuration"
require lowkey "$LOWKEY/ping"
require azurite "$AZURITE/devstoreaccount1?comp=list"

# Lowkey Vault's certificate names localhost: forward localhost:8443 to it.
host="${LOWKEY#https://}"
background python3 -I -B "$E2E_DIR/mocks/forward.py" 8443 "${host%%:*}" "${host##*:}"
background python3 -I -B "$E2E_DIR/mocks/azure_identity.py" 8181
wait_for https://localhost:8443/ping 20 || exit 1
echo | openssl s_client -connect localhost:8443 -servername localhost 2>/dev/null | openssl x509 > "$T/lowkey.pem"
key() {
  curl -sk -X POST "https://localhost:8443/keys/$1/create?api-version=7.4" -H 'Authorization: Bearer x' \
    -H 'Content-Type: application/json' -d "$2" >/dev/null
}
key e2e-ec '{"kty":"EC","crv":"P-256","key_ops":["sign","verify"]}'
key e2e-ec384 '{"kty":"EC","crv":"P-384","key_ops":["sign","verify"]}'
key e2e-rsa '{"kty":"RSA","key_size":3072,"key_ops":["sign","verify"]}'
export IDENTITY_ENDPOINT=http://127.0.0.1:8181/msi/token IDENTITY_HEADER=e2e
authority() {
  printf '[authorities.%s]\nprovider = "azure_keyvault"\nvault_url = "https://localhost:8443"\nkey = "%s"\nca_cert_file = "%s/lowkey.pem"\ncert_types = ["user"]\n%s\n' \
    "$1" "$2" "$T" "${3:-}"
}
mock_config "$(authority kv-rsa e2e-rsa 'signature_algorithms = ["ssh-rsa"]')" \
  | sed 's/^ssh_ca = "users"$/ssh_ca = ["kv-rsa"]/' > "$T/bad.toml"
check_fail "ssh-rsa on Key Vault is refused at startup" "can't sign with ssh-rsa" service_refuses "$T/bad.toml"
mock_config "
$(authority kv-ec e2e-ec)
$(authority kv-ec384 e2e-ec384)
$(authority kv-rsa e2e-rsa)
" | sed 's/^ssh_ca = "users"$/ssh_ca = ["kv-ec", "kv-ec384", "kv-rsa"]/' > "$T/service.toml"
service_start "$T/service.toml" || exit 1
client_config
ssh-keygen -q -t ed25519 -N '' -f "$T/user"
export SSH_CASIGN_TOKEN="$(mock_token user1)"
check_out "managed identity used" 'managed identity' cat "$T/service.log"
check_out "P-256 in Key Vault" '^ECDSA ecdsa-sha2-nistp256$' sign_with ""
check_out "P-384 in Key Vault" '^ECDSA ecdsa-sha2-nistp384$' sign_with ecdsa-sha2-nistp384
check_out "RSA in Key Vault" '^RSA rsa-sha2-512$' sign_with rsa-sha2-512
discovery_ca_keys > "$T/kv-cas.pub"
sign_with "" >/dev/null
sshd_start "$T/kv-cas.pub" user1 || exit 1
check_out "sshd accepts it" 'logged in as' ssh_login "$T/user"
check_out "the Blob store's own tests (Azurite)" 'test result: ok. 1 passed' \
  env SSH_CASIGN_TEST_AZURITE="$AZURITE/devstoreaccount1" \
  cargo test --locked -q --manifest-path "$E2E_ROOT/Cargo.toml" -p ssh-casign-ca-azure azurite -- --ignored
finish
