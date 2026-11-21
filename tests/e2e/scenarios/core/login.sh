#!/bin/bash
# needs: dex
# Interactive sign-in against Dex (device flow and authorization code flow),
# login into ssh-agent, reuse, refresh tokens, logout.
source "$(dirname "$0")/../../lib.sh"
scenario "sign in with Dex, login into ssh-agent"
require dex "$DEX/dex/.well-known/openid-configuration"

ssh-keygen -q -t ed25519 -N '' -C e2e-user-ca -f "$T/ca"
cat > "$T/service.toml" <<CONF
server_id = "e2e"
[oidc_provider]
issuer = "$DEX/dex"
client_id = "ssh-casign"
scopes = ["openid", "email", "profile", "offline_access"]
id_claim = "email"
[profiles.default]
ssh_ca = "users"
validity = 300
max_validity = 28800
principals = ["{{claim:name}}"]
allowed_principals = ["{{claim:name}}", "{{claim:name}}-admin"]
[authorities.users]
provider = "file"
private_key_file = "$T/ca"
cert_types = ["user"]
CONF
service_start "$T/service.toml" || exit 1
export DEX_URL="$DEX" BROWSER="$E2E_DIR/fixtures/dex-browser.sh" DEX_BROWSER_LOG="$T/browser.log"
export SSH_CASIGN_URL="$SERVICE_URL" SSH_CASIGN_CACHE_DIR="$T/cache"
unset SSH_CASIGN_TOKEN
touch "$T/browser.log"
issued() { grep -c 'issued certificate' "$T/service.log"; }
browsers() { grep -c 'login form' "$T/browser.log"; }
ssh-keygen -q -t ed25519 -N '' -f "$T/user"

# Device flow: read the code the client prints, approve it like a user would.
"$CLIENT" --token-store none --sign-in device cert -o "$T/device-cert.pub" "$T/user.pub" 2> "$T/device.err" &
DEVICE_PID=$!
for i in $(seq 80); do grep -q 'enter the code' "$T/device.err" && break; sleep 0.25; done
CODE="$(sed -n 's/.*enter the code: //p' "$T/device.err")"
check_out "device flow: approve the code" 'approved' "$E2E_DIR/fixtures/dex-approve.sh" "$CODE"
wait $DEVICE_PID
check_out "device flow: certificate for user1" 'user1' ssh-keygen -L -f "$T/device-cert.pub"

check "authorization code flow: certificate" \
  "$CLIENT" --token-store none --sign-in browser cert -o "$T/browser-cert.pub" "$T/user.pub"
check_out "authorization code flow: principal" 'user1' ssh-keygen -L -f "$T/browser-cert.pub"

# login into an agent, then ssh
sshd_start "$T/ca.pub" user1 || exit 1
eval "$(ssh-agent -a "$T/agent.sock")" >/dev/null
E2E_PIDS+=($SSH_AGENT_PID)
check_fail "no certificate: ssh refused" 'Permission denied' ssh_agent_login
check_out "login adds a key" 'Added certificate' \
  "$CLIENT" --token-store none --sign-in browser login -I e2e -V 8
check_out "ssh with the agent's certificate" 'logged in as' ssh_agent_login
before=$(issued)
check_out "a second login reuses the certificate" 'Reusing certificate' \
  "$CLIENT" --token-store none --sign-in browser login -I e2e
check_eq "no new certificate for the reuse" "$before" "$(issued)"
check_out "another app name gets its own certificate" 'Added certificate' \
  "$CLIENT" --token-store none --sign-in browser login -I other
sleep 9
check_out "the expired key is gone from the agent" 'other' ssh-add -l
ssh-add -D >/dev/null 2>&1
check_out "user2 gets a certificate" 'Added certificate' \
  env DEX_LOGIN=user2@example.com "$CLIENT" --token-store none --sign-in browser login -I user2 --new
check_fail "user2's principal isn't accepted by sshd" 'Permission denied' ssh_agent_login

# Refresh tokens in the file store
b=$(browsers)
check_out "file store: first login signs in" 'Added certificate' \
  "$CLIENT" --token-store file --sign-in browser login -I cache --new
check_eq "one browser sign-in" "$((b + 1))" "$(browsers)"
first="$(jq -r '.[]' "$T/cache/refresh-tokens.json" 2>/dev/null | sha256sum)"
check_eq "token file is private" 600 "$(stat -c %a "$T/cache/refresh-tokens.json" 2>/dev/null || stat -f %Lp "$T/cache/refresh-tokens.json")"
check_out "next login uses the refresh token" 'Added certificate' \
  "$CLIENT" --token-store file --sign-in browser login -I cache --new
check_eq "no browser sign-in" "$((b + 1))" "$(browsers)"
check "the refresh token was rotated" test "$first" != "$(jq -r '.[]' "$T/cache/refresh-tokens.json" | sha256sum)"
jq 'map_values("garbage")' "$T/cache/refresh-tokens.json" > "$T/garbage.json" && mv "$T/garbage.json" "$T/cache/refresh-tokens.json"
check_out "a garbage refresh token falls back to sign-in" 'Added certificate' \
  "$CLIENT" --token-store file --sign-in browser login -I cache --new
check_eq "browser sign-in after the garbage token" "$((b + 2))" "$(browsers)"
check_out "logout forgets the token and the keys" 'Forgot' "$CLIENT" --token-store file logout
check_fail "nothing left in the agent" 'no identities|The agent has no' ssh-add -l
finish
