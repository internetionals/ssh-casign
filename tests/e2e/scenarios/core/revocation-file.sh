#!/bin/bash
# needs: oidc
# Revocation from the revocation file: the KRL, ssh-keygen -Q, sshd's
# RevokedKeys, the krl command, reloading, a broken file.
source "$(dirname "$0")/../../lib.sh"
scenario "revocation file and KRL"
require oidc "$OIDC/ssh-casign/.well-known/openid-configuration"

: > "$T/revocations.toml"
mock_config "
[revocation]
file = \"$T/revocations.toml\"
reload_interval = 1
" > "$T/service.toml"
service_start "$T/service.toml" || exit 1
client_config
export SSH_CASIGN_TOKEN="$(mock_token user1)"
for k in a b c; do ssh-keygen -q -t ed25519 -N '' -f "$T/id_$k"; done
client cert "$T/id_a.pub" >/dev/null
client cert "$T/id_b.pub" >/dev/null
# Its own app name, so its key ID (server:profile:id:app) is its own.
client cert -I laptop-c "$T/id_c.pub" >/dev/null

check_out "krl: an empty list" 'updated' client krl -o "$T/revoked.krl"
check_out "nothing revoked yet" ': ok$' ssh-keygen -Q -f "$T/revoked.krl" "$T/id_a-cert.pub"
serial="$(ssh-keygen -L -f "$T/id_a-cert.pub" | awk '/Serial:/{print $2}')"
key_id="$(ssh-keygen -L -f "$T/id_c-cert.pub" | awk -F'"' '/Key ID/{print $2}')"
cat > "$T/revocations.toml" <<EOT
[[revoked]]
serial = "$serial"
authority = "users"
reason = "laptop stolen"
[[revoked]]
fingerprint = "$(fingerprint "$T/id_b.pub")"
[[revoked]]
key_id = "$key_id"
authority = "users"
EOT
sleep 2.5
check_out "krl: the file changed" 'updated' client krl -o "$T/revoked.krl"
check_says "a revoked serial" 'id_a-cert.pub.*REVOKED' ssh-keygen -Q -f "$T/revoked.krl" "$T/id_a-cert.pub"
check_says "a revoked key: its certificate" 'id_b-cert.pub.*REVOKED' ssh-keygen -Q -f "$T/revoked.krl" "$T/id_b-cert.pub"
check_says "a revoked key: the key itself" 'id_b.pub.*REVOKED' ssh-keygen -Q -f "$T/revoked.krl" "$T/id_b.pub"
check_says "a revoked key ID" 'id_c-cert.pub.*REVOKED' ssh-keygen -Q -f "$T/revoked.krl" "$T/id_c-cert.pub"
check_eq "krl: unchanged, nothing written" "" "$(client krl -o "$T/revoked.krl" 2>/dev/null)"
etag="$(curl -sI "$SERVICE_URL/revoked.krl" | tr -d '\r' | sed -n 's/^[Ee][Tt]ag: //p')"
check_eq "If-None-Match with the ETag gets a 304" 304 \
  "$(curl -s -o /dev/null -w '%{http_code}' -H "If-None-Match: $etag" "$SERVICE_URL/revoked.krl")"
check_fail "the service refuses to sign the revoked key" 'This key is revoked' client cert -o - "$T/id_b.pub"
check_fail "and a revoked key ID" 'is revoked' client cert -I laptop-c -o - "$T/id_c.pub"

ssh-keygen -q -t ed25519 -N '' -f "$T/id_d"
client cert "$T/id_d.pub" >/dev/null
sshd_start "$T/ca.pub" user1 "RevokedKeys $T/revoked.krl" || exit 1
check_out "sshd accepts a certificate that isn't revoked" 'logged in as' ssh_login "$T/id_d"
check_fail "and refuses a revoked one" 'Permission denied' ssh_login "$T/id_a"
check_out "sshd logs why" 'revoked by file' cat "$T/sshd/log"

printf '[[revoked]]\nserail = 1\n' > "$T/revocations.toml"
sleep 3
check_eq "a broken file is reported once" 1 "$(grep -c 'not reloaded' "$T/service.log")"
check_fail "and the previous list stays in force" 'This key is revoked' client cert -o - "$T/id_b.pub"
printf '[[revoked]]\nserial = 16361417745147627987\nauthority = "users"\n' > "$T/revocations.toml"
sleep 2.5
check_out "an unquoted large serial explains itself" 'must be quoted' cat "$T/service.log"
finish
