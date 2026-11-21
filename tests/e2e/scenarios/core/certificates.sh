#!/bin/bash
# needs: oidc
# A user certificate from a mock IdP token, accepted by sshd; refusals.
source "$(dirname "$0")/../../lib.sh"
scenario "issue a user certificate and log in with it"
require oidc "$OIDC/ssh-casign/.well-known/openid-configuration"

mock_config > "$T/service.toml"
service_start "$T/service.toml" || exit 1
client_config
ssh-keygen -q -t ed25519 -N '' -f "$T/user"
U="$(mock_token user1)"

check_out "discovery lists the CA" '"users"' curl -sf "$SERVICE_URL/.well-known/ssh-casign"
check "cert writes user-cert.pub" env SSH_CASIGN_TOKEN="$U" "$CLIENT" -f "$T/client.toml" cert "$T/user.pub"
check_eq "signed by the user CA" "$(fingerprint "$T/ca.pub")" "$(signing_ca "$T/user-cert.pub" | awk '{print $2}')"
check_out "principals from the token" 'user1' ssh-keygen -L -f "$T/user-cert.pub"
check_out "key ID server:profile:id:app" 'e2e:default:user1@example.com:ssh-casign-client' ssh-keygen -L -f "$T/user-cert.pub"

sshd_start "$T/ca.pub" user1 || exit 1
check_out "sshd accepts the certificate" 'logged in as' ssh_login "$T/user"
check_fail "sshd refuses the key without certificate" 'Permission denied' \
  ssh -F /dev/null -p 2222 -i "$T/user" -o IdentitiesOnly=yes -o CertificateFile=none \
  -o IdentityAgent=none -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null \
  -o BatchMode=yes 127.0.0.1 true

check_fail "requesting a principal outside the limits" 'not in allowed_principals|403' \
  env SSH_CASIGN_TOKEN="$U" "$CLIENT" -f "$T/client.toml" cert -n root -o - "$T/user.pub"
check_fail "validity above the token's max" 'exceeds max_validity|403' \
  env SSH_CASIGN_TOKEN="$U" "$CLIENT" -f "$T/client.toml" cert -V 30d -o - "$T/user.pub"
check_fail "no host profile: host certificates refused" 'No profile issues host' \
  env SSH_CASIGN_TOKEN="$U" "$CLIENT" -f "$T/client.toml" cert -t host -n h.example.com -o - "$T/user.pub"
check_fail "a bad token gets 401" '401' \
  env SSH_CASIGN_TOKEN=not-a-jwt "$CLIENT" -f "$T/client.toml" cert -o - "$T/user.pub"
ssh-keygen -q -t rsa -b 1024 -N '' -f "$T/small" 2>/dev/null
check_fail "RSA client key below 2048 bits" 'below the default minimum' \
  env SSH_CASIGN_TOKEN="$U" "$CLIENT" -f "$T/client.toml" cert -o - "$T/small.pub"
check_out "responses are not cached" 'no-store' \
  curl -s -D - -o /dev/null -X POST "$SERVICE_URL/sign"
finish
