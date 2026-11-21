#!/bin/bash
# The AWS Lambda image (Lambda Web Adapter) behind the runtime interface
# emulator and a Function URL proxy, signing with KMS on LocalStack.
source "$(dirname "$0")/../../lib.sh"
scenario "AWS Lambda image"
command -v "$RUNTIME" >/dev/null || skip "needs podman or docker"
host_build || exit 1
ARCH="$(case "$(uname -m)" in arm64|aarch64) echo arm64 ;; *) echo x86_64 ;; esac)"
check_out "build the image (static, $ARCH)" 'ssh-casign-e2e-lambda' \
  env ARCH="$ARCH" IMAGE=ssh-casign-e2e-lambda:latest "$E2E_ROOT/deploy/aws-lambda/build.sh"
pod_start ssh-casign-e2e-lambda 4566:4566 9100:8080 || exit 1
"$RUNTIME" run -d --pod "$POD" --name "$POD-kms" -e SERVICES=kms docker.io/localstack/localstack:4.0.3 >/dev/null
wait_for http://localhost:4566/_localstack/health 120 || exit 1
kms() {
  curl -sf -X POST http://localhost:4566/ -H "X-Amz-Target: TrentService.$1" \
    -H 'Content-Type: application/x-amz-json-1.1' \
    -H 'Authorization: AWS4-HMAC-SHA256 Credential=test/20260101/eu-west-1/kms/aws4_request, SignedHeaders=host, Signature=0' \
    -d "$2"
}
for spec in ec:ECC_NIST_P256 rsa:RSA_3072; do
  id="$(kms CreateKey "{\"KeySpec\":\"${spec#*:}\",\"KeyUsage\":\"SIGN_VERIFY\"}" | jq -r .KeyMetadata.KeyId)"
  kms CreateAlias "{\"AliasName\":\"alias/e2e-${spec%%:*}\",\"TargetKeyId\":\"$id\"}" >/dev/null
done
CONFIG="server_id = \"lambda-e2e\"
[oidc_provider]
issuer = \"$OIDC/ssh-casign\"
client_id = \"ssh-casign\"
id_claim = \"upn\"
[profiles.default]
ssh_ca = [\"kms-ec\", \"kms-rsa\"]
validity = 300
[authorities.kms-ec]
provider = \"aws_kms\"
key_id = \"alias/e2e-ec\"
endpoint_url = \"http://localhost:4566\"
cert_types = [\"user\"]
[authorities.kms-rsa]
provider = \"aws_kms\"
key_id = \"alias/e2e-rsa\"
endpoint_url = \"http://localhost:4566\"
cert_types = [\"user\"]
[audit]
client_address_header = \"x-forwarded-for\"
trusted_proxies = [\"127.0.0.1/32\", \"::1/128\"]
[[audit.sink]]
type = \"stdout\""
"$RUNTIME" run -d --pod "$POD" --name "$POD-fn" -e AWS_ACCESS_KEY_ID=test -e AWS_SECRET_ACCESS_KEY=test \
  -e AWS_REGION=eu-west-1 -e SSH_CASIGN_CONFIG_TOML="$CONFIG" ssh-casign-e2e-lambda:latest >/dev/null
background python3 -I -B "$E2E_DIR/mocks/function_url.py" 7073 http://localhost:9100/2015-03-31/functions/function/invocations
wait_for http://127.0.0.1:7073/.well-known/ssh-casign 90 || exit 1
cat > "$T/client.toml" <<CONF
token_store = "none"
[profiles.default]
url = "http://127.0.0.1:7073/"
CONF
ssh-keygen -q -t ed25519 -N '' -f "$T/user"
export SSH_CASIGN_TOKEN="$(mock_token user1)"
check_out "discovery through the Function URL, RIE and the adapter" '"kms-rsa"' \
  curl -sf http://127.0.0.1:7073/.well-known/ssh-casign
check_out "a certificate signed with KMS (P-256)" '^ECDSA ecdsa-sha2-nistp256$' sign_with ""
check_out "a certificate signed with KMS (RSA)" '^RSA rsa-sha2-256$' sign_with rsa-sha2-256
check_fail "a denied request" 'not in allowed_principals|403' client cert -n root -o - "$T/user.pub"
check_out "audit records in the function log" 'CEF:0\|' "$RUNTIME" logs "$POD-fn"
check_out "with the Function URL's client address" 'src=203.0.113.5' "$RUNTIME" logs "$POD-fn"
finish
