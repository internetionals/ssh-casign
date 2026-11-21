#!/bin/bash
# needs: oidc
# OpenStack Barbican with Keystone (a mock of both APIs): the CA key fetched
# with an application credential or a password, signing in memory.
source "$(dirname "$0")/../../lib.sh"
scenario "Barbican backend with Keystone"
require oidc "$OIDC/ssh-casign/.well-known/openid-configuration"

ssh-keygen -q -t ed25519 -N '' -C barbican-ca -f "$T/barbican-ca"
echo app-credential-secret > "$T/app-secret"
echo os-password > "$T/password"
background python3 -I -B "$E2E_DIR/mocks/openstack.py" 9311 "$T/barbican-ca" "$T"
wait_for http://127.0.0.1:9311/ 20 || exit 1
SECRET=5f6a2c1e-0000-4000-8000-ssh-casign-ca
check_out "the backend's own test (both credential types)" 'test result: ok. 1 passed' \
  env SSH_CASIGN_TEST_KEYSTONE=http://127.0.0.1:9311/v3 SSH_CASIGN_TEST_BARBICAN_SECRET=$SECRET SSH_CASIGN_TEST_BARBICAN_DIR="$T" \
  cargo test --locked -q --manifest-path "$E2E_ROOT/Cargo.toml" -p ssh-casign-ca-barbican mock_openstack -- --ignored
mock_config "
[authorities.openstack]
provider = \"barbican\"
secret = \"$SECRET\"
auth_url = \"http://127.0.0.1:9311/v3\"
region = \"RegionOne\"
application_credential_id = \"ac1\"
application_credential_secret_file = \"$T/app-secret\"
cert_types = [\"user\"]
" | sed 's/^ssh_ca = "users"$/ssh_ca = "openstack"/' > "$T/service.toml"
service_start "$T/service.toml" || exit 1
client_config
ssh-keygen -q -t ed25519 -N '' -f "$T/user"
export SSH_CASIGN_TOKEN="$(mock_token user1)"
check_has "signed with the key from Barbican" "$(fingerprint "$T/barbican-ca.pub")" \
  sh -c "'$CLIENT' -f '$T/client.toml' cert -o - '$T/user.pub' | ssh-keygen -L -f -"
echo wrong > "$T/app-secret"
service_stop
check_fail "a wrong application credential stops the service" '401' service_refuses "$T/service.toml"
finish
