#!/bin/bash
# needs: oidc openbao tokenreview
# OpenBao/Vault transit: signing with every key type and algorithm, sshd,
# and the kubernetes, jwt and approle logins with renewal and revocation.
source "$(dirname "$0")/../../lib.sh"
scenario "OpenBao transit backend and logins"
require oidc "$OIDC/ssh-casign/.well-known/openid-configuration"
require openbao "$OPENBAO/v1/sys/health"
require tokenreview "$TOKENREVIEW/"

B="$OPENBAO/v1"
api() {
  if [ -n "${3:-}" ]; then curl -sf -H "X-Vault-Token: root" -X "$1" "$B/$2" -d "$3"
  else curl -sf -H "X-Vault-Token: root" -X "$1" "$B/$2"; fi
}
api POST sys/mounts/transit '{"type":"transit"}' >/dev/null
for k in ed:ed25519 ec:ecdsa-p256 ec384:ecdsa-p384 rsa:rsa-3072; do
  api POST "transit/keys/${k%%:*}" "{\"type\":\"${k#*:}\"}" >/dev/null
done
echo root > "$T/token"
authority() {
  printf '[authorities.%s]\nprovider = "vault"\naddress = "%s"\nkey = "%s"\ntoken_file = "%s/token"\ncert_types = ["user"]\n%s\n' \
    "$1" "$OPENBAO" "$2" "$T" "${3:-}"
}
{ mock_config "
$(authority vault-ed ed)
$(authority vault-ec ec)
$(authority vault-ec384 ec384)
$(authority vault-rsa rsa)
$(authority vault-rsa-legacy rsa 'signature_algorithms = ["ssh-rsa"]')
" | sed 's/^ssh_ca = "users"$/ssh_ca = ["vault-ed", "vault-ec", "vault-ec384", "vault-rsa", "vault-rsa-legacy"]/'; } > "$T/service.toml"
service_start "$T/service.toml" || exit 1
client_config
ssh-keygen -q -t ed25519 -N '' -f "$T/user"
export SSH_CASIGN_TOKEN="$(mock_token user1)"
check_out "default: Ed25519" '^ED25519 ssh-ed25519$' sign_with ""
check_out "ecdsa-sha2-nistp256" '^ECDSA ecdsa-sha2-nistp256$' sign_with ecdsa-sha2-nistp256
check_out "ecdsa-sha2-nistp384" '^ECDSA ecdsa-sha2-nistp384$' sign_with ecdsa-sha2-nistp384
check_out "rsa-sha2-512" '^RSA rsa-sha2-512$' sign_with rsa-sha2-512
check_out "rsa-sha2-256" '^RSA rsa-sha2-256$' sign_with rsa-sha2-256
check_out "ssh-rsa (SHA-1, legacy authority)" '^RSA ssh-rsa$' sign_with ssh-rsa
sign_with "" >/dev/null
discovery_ca_keys > "$T/vault-cas.pub"
sshd_start "$T/vault-cas.pub" user1 || exit 1
check_out "sshd accepts a certificate signed in Vault" 'logged in as' ssh_login "$T/user"
service_stop

# Logins: a policy for the transit key, 6 s tokens, then the backend's test.
api PUT sys/policies/acl/ssh-casign '{"policy":"path \"transit/keys/ssh-ca\" { capabilities = [\"read\"] }\npath \"transit/sign/ssh-ca*\" { capabilities = [\"update\"] }"}' >/dev/null
api POST transit/keys/ssh-ca '{"type":"ed25519"}' >/dev/null
api POST sys/auth/approle '{"type":"approle"}' >/dev/null
api POST auth/approle/role/ssh-casign '{"token_policies":["ssh-casign"],"token_ttl":"6s","token_max_ttl":"60s"}' >/dev/null
api GET auth/approle/role/ssh-casign/role-id | jq -r .data.role_id > "$T/role-id"
api POST auth/approle/role/ssh-casign/secret-id | jq -r .data.secret_id > "$T/secret-id"
openssl genrsa -out "$T/jwt-key.pem" 2048 2>/dev/null
openssl rsa -in "$T/jwt-key.pem" -pubout -out "$T/jwt-pub.pem" 2>/dev/null
api POST sys/auth/jwt '{"type":"jwt"}' >/dev/null
api POST auth/jwt/config "$(jq -n --rawfile k "$T/jwt-pub.pem" '{jwt_validation_pubkeys: [$k], bound_issuer: "https://issuer.example"}')" >/dev/null
api POST auth/jwt/role/ssh-casign '{"role_type":"jwt","bound_audiences":["vault"],"user_claim":"sub","token_policies":["ssh-casign"],"token_ttl":"6s","token_max_ttl":"60s"}' >/dev/null
b64url() { openssl base64 -A | tr '+/' '-_' | tr -d '='; }
now=$(date +%s)
h=$(printf '{"alg":"RS256","typ":"JWT"}' | b64url)
p=$(printf '{"iss":"https://issuer.example","sub":"ssh-casign","aud":"vault","iat":%s,"exp":%s}' $now $((now + 3600)) | b64url)
printf '%s.%s.%s' "$h" "$p" "$(printf '%s.%s' "$h" "$p" | openssl dgst -sha256 -sign "$T/jwt-key.pem" | b64url)" > "$T/jwt-token"
cp "$E2E_DIR/fixtures/k8s-token" "$T/k8s-token"
openssl req -x509 -newkey rsa:2048 -nodes -keyout "$T/k8s-ca.key" -out "$T/k8s-ca.pem" -days 1 -subj /CN=k8s-e2e 2>/dev/null
api POST sys/auth/kubernetes '{"type":"kubernetes"}' >/dev/null
api POST auth/kubernetes/config "$(jq -n --rawfile ca "$T/k8s-ca.pem" --arg host "$TOKENREVIEW" '{kubernetes_host: $host, disable_local_ca_jwt: true, kubernetes_ca_cert: $ca}')" >/dev/null
api POST auth/kubernetes/role/ssh-casign '{"bound_service_account_names":["ssh-casign"],"bound_service_account_namespaces":["prod"],"token_policies":["ssh-casign"],"token_ttl":"6s","token_max_ttl":"60s"}' >/dev/null
check_out "logins: approle, kubernetes, jwt with renewal and re-login" 'test result: ok. 1 passed' \
  env SSH_CASIGN_TEST_VAULT="$OPENBAO" SSH_CASIGN_TEST_VAULT_DIR="$T" \
  cargo test --locked -q --manifest-path "$E2E_ROOT/Cargo.toml" -p ssh-casign-ca-vault login_methods -- --ignored
finish
