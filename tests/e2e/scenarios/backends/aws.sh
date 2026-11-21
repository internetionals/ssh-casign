#!/bin/bash
# needs: oidc localstack
# AWS KMS (LocalStack): P-256, P-384 and RSA keys by alias, ssh-rsa refused;
# the S3 store; the revocation API on S3.
source "$(dirname "$0")/../../lib.sh"
scenario "AWS KMS backend and S3 store (LocalStack)"
require oidc "$OIDC/ssh-casign/.well-known/openid-configuration"
require localstack "$LOCALSTACK/_localstack/health"
export AWS_ACCESS_KEY_ID=test AWS_SECRET_ACCESS_KEY=test AWS_REGION=eu-west-1
# LocalStack doesn't check signatures, so plain JSON calls set up the keys.
kms() {
  curl -sf -X POST "$LOCALSTACK/" -H "X-Amz-Target: TrentService.$1" \
    -H 'Content-Type: application/x-amz-json-1.1' \
    -H 'Authorization: AWS4-HMAC-SHA256 Credential=test/20260101/eu-west-1/kms/aws4_request, SignedHeaders=host, Signature=0' \
    -d "$2"
}
for spec in ec:ECC_NIST_P256 ec384:ECC_NIST_P384 rsa:RSA_3072; do
  id="$(kms CreateKey "{\"KeySpec\":\"${spec#*:}\",\"KeyUsage\":\"SIGN_VERIFY\"}" | jq -r .KeyMetadata.KeyId)"
  kms CreateAlias "{\"AliasName\":\"alias/e2e-${spec%%:*}-$$\",\"TargetKeyId\":\"$id\"}" >/dev/null
done
authority() {
  printf '[authorities.%s]\nprovider = "aws_kms"\nkey_id = "alias/e2e-%s-%s"\nendpoint_url = "%s"\ncert_types = ["user"]\n%s\n' \
    "$1" "$2" "$$" "$LOCALSTACK" "${3:-}"
}
mock_config "$(authority kms-rsa rsa 'signature_algorithms = ["ssh-rsa"]')" \
  | sed 's/^ssh_ca = "users"$/ssh_ca = ["kms-rsa"]/' > "$T/bad.toml"
check_fail "ssh-rsa on KMS is refused at startup" "can't sign with ssh-rsa" service_refuses "$T/bad.toml"

curl -sf -X PUT "$LOCALSTACK/ssh-casign-e2e-$$" >/dev/null
mkdir -p "$T"
mock_config "
$(authority kms-ec ec)
$(authority kms-ec384 ec384)
$(authority kms-rsa rsa)
[store]
type = \"s3\"
bucket = \"ssh-casign-e2e-$$\"
prefix = \"prod/\"
region = \"eu-west-1\"
endpoint_url = \"$LOCALSTACK\"
[revocation]
reload_interval = 1
" | sed 's/^ssh_ca = "users"$/ssh_ca = ["kms-ec", "kms-ec384", "kms-rsa"]/' > "$T/service.toml"
service_start "$T/service.toml" || exit 1
client_config
ssh-keygen -q -t ed25519 -N '' -f "$T/user"
export SSH_CASIGN_TOKEN="$(mock_token user1)"
check_out "P-256 in KMS" '^ECDSA ecdsa-sha2-nistp256$' sign_with ""
check_out "P-384 in KMS" '^ECDSA ecdsa-sha2-nistp384$' sign_with ecdsa-sha2-nistp384
check_out "RSA in KMS, SHA-256" '^RSA rsa-sha2-256$' sign_with rsa-sha2-256
check_out "RSA in KMS, SHA-512" '^RSA rsa-sha2-512$' sign_with rsa-sha2-512
discovery_ca_keys > "$T/kms-cas.pub"
sign_with "" >/dev/null
sshd_start "$T/kms-cas.pub" user1 || exit 1
check_out "sshd accepts it" 'logged in as' ssh_login "$T/user"
check_out "the issuance index is in S3" '<Key>prod/issued/' curl -sf "$LOCALSTACK/ssh-casign-e2e-$$?list-type=2&prefix=prod/"
check_out "revoke by possession, stored in S3" 'revoked key' client revoke --key "$T/user"
check_out "revocations.json in the bucket" '"key holder"' curl -sf "$LOCALSTACK/ssh-casign-e2e-$$/prod/revocations.json"
check_fail "and in force" 'This key is revoked' client cert -o - "$T/user.pub"
curl -sf -X PUT "$LOCALSTACK/ssh-casign-test" >/dev/null
check_out "the S3 store's own tests" 'test result: ok. 1 passed' \
  env SSH_CASIGN_TEST_S3="$LOCALSTACK" \
  cargo test --locked -q --manifest-path "$E2E_ROOT/Cargo.toml" -p ssh-casign-ca-aws localstack -- --ignored
finish
