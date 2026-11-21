#!/bin/bash
# needs: oidc
# PKCS#11 with SoftHSM: Ed25519, P-256 and RSA keys on a token, the service
# signing through it, sshd accepting the certificate.
source "$(dirname "$0")/../../lib.sh"
scenario "PKCS#11 backend (SoftHSM)"
require oidc "$OIDC/ssh-casign/.well-known/openid-configuration"
MODULE="$(ls /usr/lib/softhsm/libsofthsm2.so /usr/lib/*/softhsm/libsofthsm2.so /opt/homebrew/lib/softhsm/libsofthsm2.so 2>/dev/null | head -1)"
[ -n "$MODULE" ] && command -v pkcs11-tool >/dev/null || skip "needs SoftHSM and pkcs11-tool (OpenSC)"

mkdir -p "$T/tokens"
printf 'directories.tokendir = %s\nobjectstore.backend = file\n' "$T/tokens" > "$T/softhsm2.conf"
export SOFTHSM2_CONF="$T/softhsm2.conf"
softhsm2-util --init-token --free --label e2e --pin 1234 --so-pin 5678 >/dev/null
p11() { pkcs11-tool --module "$MODULE" --token-label e2e --login --pin 1234 "$@" >/dev/null 2>&1; }
p11 --keypairgen --key-type EC:edwards25519 --label test-ed25519 --id 01
p11 --keypairgen --key-type EC:prime256v1 --label test-p256 --id 02
p11 --keypairgen --key-type rsa:3072 --label test-rsa --id 03
echo 1234 > "$T/pin"
check_out "the backend's own test against the token" 'test result: ok. 1 passed' \
  env PKCS11_TEST_MODULE="$MODULE" PKCS11_TEST_TOKEN=e2e SSH_CASIGN_PKCS11_PIN=1234 \
  cargo test --locked -q --manifest-path "$E2E_ROOT/Cargo.toml" -p ssh-casign-ca-pkcs11 issues_with_a_real_token -- --ignored

authority() {
  printf '[authorities.%s]\nprovider = "pkcs11"\nmodule = "%s"\ntoken_label = "e2e"\nkey_label = "%s"\npin_file = "%s/pin"\ncert_types = ["user"]\n%s\n' \
    "$1" "$MODULE" "$2" "$T" "${3:-}"
}
mock_config "
$(authority hsm-ed test-ed25519)
$(authority hsm-ec test-p256)
$(authority hsm-rsa test-rsa)
$(authority hsm-rsa-legacy test-rsa 'signature_algorithms = ["ssh-rsa"]')
" | sed 's/^ssh_ca = "users"$/ssh_ca = ["hsm-ed", "hsm-ec", "hsm-rsa", "hsm-rsa-legacy"]/' > "$T/service.toml"
service_start "$T/service.toml" || exit 1
client_config
ssh-keygen -q -t ed25519 -N '' -f "$T/user"
export SSH_CASIGN_TOKEN="$(mock_token user1)"
check_out "Ed25519 on the token" '^ED25519 ssh-ed25519$' sign_with ""
check_out "P-256 on the token" '^ECDSA ecdsa-sha2-nistp256$' sign_with ecdsa-sha2-nistp256
check_out "RSA on the token" '^RSA rsa-sha2-512$' sign_with rsa-sha2-512
check_out "ssh-rsa on the token" '^RSA ssh-rsa$' sign_with ssh-rsa
sign_with "" >/dev/null
discovery_ca_keys > "$T/hsm-cas.pub"
sshd_start "$T/hsm-cas.pub" user1 || exit 1
check_out "sshd accepts it" 'logged in as' ssh_login "$T/user"
finish
