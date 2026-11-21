#!/bin/bash
# needs: oidc
# Host certificates: a host signing its own keys (client credentials at a
# second issuer), an administrator, an orchestrator; ssh trusting them.
source "$(dirname "$0")/../../lib.sh"
scenario "host certificates"
require oidc "$OIDC/machines/.well-known/openid-configuration"

ssh-keygen -q -t ed25519 -N '' -C e2e-host-ca -f "$T/host-ca"
mock_config "
[issuers.machines]
issuer = \"$OIDC/machines\"
audience = [\"ssh-casign-hosts\"]

[[profiles.map]]
name = \"admin-hosts\"
claim = \"roles\"
value = \"ssh-admin\"
settings = { ssh_ca = [\"users\", \"hosts\"], cert_types = [\"host\"], validity = 86400, matching_principals = '[a-z0-9-]+\.example\.com' }

[[profiles.map]]
name = \"self-enroll\"
issuer = \"machines\"
claim = \"kind\"
value = \"host\"
settings = { ssh_ca = \"hosts\", cert_types = [\"host\"], validity = 2592000, principals = [\"{{claim:hostname}}\", \"{{claim:google.compute_engine.instance_name}}.internal\"] }

[[profiles.map]]
name = \"cmdb\"
issuer = \"machines\"
claim = \"kind\"
value = \"orchestrator\"
settings = { ssh_ca = \"hosts\", cert_types = [\"host\"], validity = 604800, matching_principals = '[a-z0-9-]+\.prod\.example\.com' }

[authorities.hosts]
provider = \"file\"
private_key_file = \"$T/host-ca\"
cert_types = [\"host\"]
known_hosts_pattern = \"*.prod.example.com\"
" > "$T/service.toml"
service_start "$T/service.toml" || exit 1
echo secret > "$T/secret"
cat > "$T/client.toml" <<CONF
token_store = "none"
[profiles.default]
url = "$SERVICE_URL/"
[profiles.self]
url = "$SERVICE_URL/"
sign_in = "client-credentials"
issuer = "$OIDC/machines"
client_id = "web-1"
client_secret_file = "$T/secret"
scopes = ["host-web-1"]
[profiles.cmdb]
url = "$SERVICE_URL/"
sign_in = "client-credentials"
issuer = "$OIDC/machines"
client_id = "cmdb"
client_secret_file = "$T/secret"
scopes = ["orchestrator"]
CONF
mkdir -p "$T/hostkeys"
ssh-keygen -q -t ed25519 -N '' -f "$T/hostkeys/ssh_host_ed25519_key"
ssh-keygen -q -t rsa -b 3072 -N '' -f "$T/hostkeys/ssh_host_rsa_key"
KEYS=("$T/hostkeys/ssh_host_ed25519_key.pub" "$T/hostkeys/ssh_host_rsa_key.pub")

check_out "host: signs both host keys" 'wrote .*ssh_host_rsa_key-cert.pub' \
  client -p self host --on-change "touch $T/changed" "${KEYS[@]}"
check "host: --on-change ran" test -f "$T/changed"
rm -f "$T/changed"
check_out "names from claims, lowercased; nested claim" 'web-1.internal' ssh-keygen -L -f "$T/hostkeys/ssh_host_ed25519_key-cert.pub"
check_out "... and the hostname claim" 'web-1.prod.example.com' ssh-keygen -L -f "$T/hostkeys/ssh_host_ed25519_key-cert.pub"
check_out "a host certificate" 'host certificate' ssh-keygen -L -f "$T/hostkeys/ssh_host_ed25519_key-cert.pub"
check_out "30 days (the machine token's max_validity is not policy)" 'Valid: from' \
  sh -c "ssh-keygen -L -f '$T/hostkeys/ssh_host_ed25519_key-cert.pub' | grep Valid"
check_out "a second run keeps them" 'kept .*ssh_host_ed25519_key-cert.pub' \
  client -p self host --on-change "touch $T/changed" "${KEYS[@]}"
check "and doesn't run --on-change" test ! -f "$T/changed"
check_fail "other names without limits are refused" 'requesting principals requires' \
  client -p self host -n other.example.com "${KEYS[0]}"
check_fail "a machine token gets no user certificate" 'No profile issues user certificates' \
  client -p self cert -o - "${KEYS[0]}"

ssh-keygen -q -t ecdsa -N '' -f "$T/switch"
A="$(mock_token admin1)"
check_out "admin: signs a switch key, lowercased" 'switch-1.example.com' \
  sh -c "SSH_CASIGN_TOKEN='$A' '$CLIENT' -f '$T/client.toml' cert -t host -n Switch-1.example.com -o - '$T/switch.pub' | ssh-keygen -L -f -"
check_has "admin: signed by the host CA, not the user CA" "$(fingerprint "$T/host-ca.pub")" \
  sh -c "SSH_CASIGN_TOKEN='$A' '$CLIENT' -f '$T/client.toml' cert -t host -n switch-1.example.com -o - '$T/switch.pub' | ssh-keygen -L -f -"
check_fail "admin: outside matching_principals" 'does not match matching_principals' \
  env SSH_CASIGN_TOKEN="$A" "$CLIENT" -f "$T/client.toml" cert -t host -n evil.other.org -o - "$T/switch.pub"
check_fail "admin: no wildcards" "contains '\*'" \
  env SSH_CASIGN_TOKEN="$A" "$CLIENT" -f "$T/client.toml" cert -t host -n '*.example.com' -o - "$T/switch.pub"
check_fail "admin: no extensions on host certificates" 'host certificates have no extensions' \
  env SSH_CASIGN_TOKEN="$A" "$CLIENT" -f "$T/client.toml" cert -t host -n switch-1.example.com --extension permit-pty -o - "$T/switch.pub"
check_fail "a user without the role gets no host certificate" 'No profile issues host certificates' \
  env SSH_CASIGN_TOKEN="$(mock_token user1)" "$CLIENT" -f "$T/client.toml" cert -t host -n switch-1.example.com -o - "$T/switch.pub"
check_out "orchestrator: inside its domain" 'db-7.prod.example.com' \
  sh -c "'$CLIENT' -f '$T/client.toml' -p cmdb cert -t host -n db-7.prod.example.com -o - '$T/switch.pub' | ssh-keygen -L -f -"
check_fail "orchestrator: outside it" 'does not match matching_principals' \
  client -p cmdb cert -t host -n web-1.example.com -o - "$T/switch.pub"

# ssh trusting the host CA through ca-keys
check_out "ca-keys writes the file" 'updated' client ca-keys --type host -o "$T/known_hosts"
check_out "@cert-authority with the published pattern" '^@cert-authority \*\.prod\.example\.com ssh-ed25519 ' \
  cat "$T/known_hosts"
# sshd presents the certified host key; the user logs in with a certificate.
mkdir -p "$T/sshd"
cp "$T/hostkeys/ssh_host_ed25519_key" "$T/sshd/host_key"
cp "$T/hostkeys/ssh_host_ed25519_key.pub" "$T/sshd/host_key.pub"
ssh-keygen -q -t ed25519 -N '' -f "$T/user"
SSH_CASIGN_TOKEN="$(mock_token user1)" "$CLIENT" -f "$T/client.toml" cert "$T/user.pub" >/dev/null
sshd_start "$T/ca.pub" user1 "HostCertificate $T/hostkeys/ssh_host_ed25519_key-cert.pub" || exit 1
host_ssh() {
  ssh -F /dev/null -p 2222 -i "$T/user" -o IdentitiesOnly=yes -o IdentityAgent=none \
    -o UserKnownHostsFile="$T/known_hosts" -o GlobalKnownHostsFile=/dev/null \
    -o StrictHostKeyChecking=yes -o BatchMode=yes -o HostKeyAlias="$1" 127.0.0.1 true
}
check "ssh accepts the host by its certificate" host_ssh web-1.prod.example.com
check_fail "and refuses a name not in it" 'Host key verification failed' host_ssh web-2.prod.example.com
finish
