#!/bin/bash
# needs: oidc gcs
# Google Cloud KMS (a mock of the REST API): every algorithm including
# ssh-rsa with a raw PKCS#1 key, service account JWTs, the metadata server,
# workload identity federation; the GCS store (fake-gcs-server).
source "$(dirname "$0")/../../lib.sh"
scenario "Google Cloud KMS backend and GCS store"
require oidc "$OIDC/ssh-casign/.well-known/openid-configuration"
require gcs "$GCS/storage/v1/b"
python3 -I -c 'import cryptography' 2>/dev/null || skip "the GCP mock needs python3-cryptography"

cp "$E2E_DIR/fixtures/k8s-token" "$T/k8s-token"
background python3 -I -B "$E2E_DIR/mocks/gcp.py" 8085 "$T/sa.json" "$(cat "$T/k8s-token")"
wait_for http://127.0.0.1:8085/ 20 || exit 1
export GCE_METADATA_HOST=127.0.0.1:8085
V=projects/p/locations/europe-west1/keyRings/ssh/cryptoKeys
authority() {
  printf '[authorities.%s]\nprovider = "gcp_kms"\nkey_version = "%s/%s/cryptoKeyVersions/1"\nendpoint_url = "http://127.0.0.1:8085"\ncert_types = ["user"]\n%s\n' \
    "$1" "$V" "$2" "${3:-}"
}
mock_config "
$(authority gcp-ed ed)
$(authority gcp-ec ec "credentials_file = \"$T/sa.json\"")
$(authority gcp-ec384 ec384)
$(authority gcp-rsa rsa)
$(authority gcp-rsa-raw rsa-raw)
$(authority gcp-legacy rsa-raw 'signature_algorithms = ["ssh-rsa"]')
" | sed 's/^ssh_ca = "users"$/ssh_ca = ["gcp-ed", "gcp-ec", "gcp-ec384", "gcp-rsa", "gcp-rsa-raw", "gcp-legacy"]/' > "$T/service.toml"
service_start "$T/service.toml" || exit 1
client_config
ssh-keygen -q -t ed25519 -N '' -f "$T/user"
export SSH_CASIGN_TOKEN="$(mock_token user1)"
check_out "credentials: metadata server and a service account key" 'service account' cat "$T/service.log"
check_out "Ed25519" '^ED25519 ssh-ed25519$' sign_with ""
check_out "P-256 (service account JWT)" '^ECDSA ecdsa-sha2-nistp256$' sign_with ecdsa-sha2-nistp256
check_out "P-384" '^ECDSA ecdsa-sha2-nistp384$' sign_with ecdsa-sha2-nistp384
check_out "RSA PKCS#1 SHA-256" '^RSA rsa-sha2-256$' sign_with rsa-sha2-256
check_out "raw PKCS#1: rsa-sha2-512" '^RSA rsa-sha2-512$' sign_with rsa-sha2-512
check_out "raw PKCS#1: ssh-rsa" '^RSA ssh-rsa$' sign_with ssh-rsa
discovery_ca_keys > "$T/gcp-cas.pub"
sign_with "" >/dev/null
sshd_start "$T/gcp-cas.pub" user1 || exit 1
check_out "sshd accepts it" 'logged in as' ssh_login "$T/user"

AUD="//iam.googleapis.com/projects/1/locations/global/workloadIdentityPools/k8s/providers/cluster"
jq -n --arg aud "$AUD" --arg f "$T/k8s-token" '{type: "external_account", audience: $aud, subject_token_type: "urn:ietf:params:oauth:token-type:jwt", token_url: "http://127.0.0.1:8085/sts", service_account_impersonation_url: "http://127.0.0.1:8085/v1/projects/-/serviceAccounts/ssh-ca@p.iam.gserviceaccount.com:generateAccessToken", credential_source: {file: $f}}' > "$T/file-impersonate.json"
jq -n --arg aud "$AUD" '{type: "external_account", audience: $aud, subject_token_type: "urn:ietf:params:oauth:token-type:jwt", token_url: "http://127.0.0.1:8085/sts", credential_source: {url: "http://127.0.0.1:8085/subject", headers: {"X-Test-Header": "yes"}, format: {type: "json", subject_token_field_name: "id_token"}}}' > "$T/url-direct.json"
check_out "workload identity federation (file + impersonation, URL + direct)" 'test result: ok. 1 passed' \
  env SSH_CASIGN_TEST_GCP_WIF="$T" SSH_CASIGN_TEST_GCP_ENDPOINT=http://127.0.0.1:8085 \
  cargo test --locked -q --manifest-path "$E2E_ROOT/Cargo.toml" -p ssh-casign-ca-gcp workload_identity -- --ignored

curl -sf -X POST "$GCS/storage/v1/b" -H 'Content-Type: application/json' -d '{"name":"ssh-casign-test"}' >/dev/null
check_out "the GCS store's own tests (fake-gcs-server)" 'test result: ok. 1 passed' \
  env STORAGE_EMULATOR_HOST="${GCS#http://}" \
  cargo test --locked -q --manifest-path "$E2E_ROOT/Cargo.toml" -p ssh-casign-ca-gcp emulator -- --ignored
finish
