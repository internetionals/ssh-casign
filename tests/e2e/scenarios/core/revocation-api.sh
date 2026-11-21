#!/bin/bash
# needs: oidc
# The revocation API with a shared store: two service instances, users
# revoking their own certificates, key holders, administrators' searches.
source "$(dirname "$0")/../../lib.sh"
scenario "revocation API and issuance index"
require oidc "$OIDC/ssh-casign/.well-known/openid-configuration"

mkdir -p "$T/store"
mock_config "
[store]
type = \"file\"
path = \"$T/store\"
[revocation]
reload_interval = 1
admins = [{ claim = \"roles\", value = \"ssh-admin\" }]
[audit]
[[audit.sink]]
type = \"file\"
path = \"$T/audit.cef\"
" > "$T/service.toml"
service_start "$T/service.toml" 127.0.0.1:3000 || exit 1
service_start "$T/service.toml" 127.0.0.1:3001 || exit 1
cat > "$T/client.toml" <<CONF
token_store = "none"
[profiles.default]
url = "http://127.0.0.1:3000/"
[profiles.second]
url = "http://127.0.0.1:3001/"
CONF
for k in a b c d; do ssh-keygen -q -t ed25519 -N '' -C "$k" -f "$T/id_$k"; done
U="$(mock_token user1)"
A="$(mock_token admin1)"
as_user() { SSH_CASIGN_TOKEN="$U" "$CLIENT" -f "$T/client.toml" "$@"; }
as_admin() { SSH_CASIGN_TOKEN="$A" "$CLIENT" -f "$T/client.toml" "$@"; }
serial() { ssh-keygen -L -f "$1" | awk '/Serial:/{print $2}'; }

check_out "discovery offers the revoke API" '"revoke_endpoint"' curl -sf http://127.0.0.1:3000/.well-known/ssh-casign
as_user cert "$T/id_a.pub" >/dev/null; as_user cert "$T/id_b.pub" >/dev/null; as_admin cert "$T/id_d.pub" >/dev/null
check_eq "the index has user1's two certificates" 2 "$(as_user certificates --json | jq length)"
check_out "user1 revokes one of them" 'revoked serial' \
  as_user revoke --serial "$(serial "$T/id_a-cert.pub")" --authority users --reason "laptop lost"
check_fail "but not the admin's" 'not one of your unexpired certificates' as_user revoke --certificate "$T/id_d-cert.pub"
check_fail "users can't revoke by fingerprint" 'only administrators' as_user revoke --fingerprint "$(fingerprint "$T/id_b.pub")"
check_fail "or search" 'only administrators can search' as_user certificates --where principal=user1
check_out "a key holder revokes a key without signing in" 'revoked key' "$CLIENT" -f "$T/client.toml" revoke --key "$T/id_c" --reason "key leaked"
check_fail "the service refuses to sign it" 'This key is revoked' as_user cert -o - "$T/id_c.pub"
check_out "admin: search by principal" 'REVOKED' as_admin certificates --where principal=user1
check_out "admin: revoke everything from an address" 'revoked serial' \
  as_admin revoke --where client_address=127.0.0.1 --reason "abuse"
check_out "user1: revoke --all finds nothing left" 'already revoked' as_user revoke --all
sleep 2
check_out "instance two serves the revocations" 'updated' "$CLIENT" -f "$T/client.toml" -p second krl -o "$T/revoked.krl"
for k in a b d; do
  check_says "id_$k's certificate is in instance two's KRL" 'REVOKED' ssh-keygen -Q -f "$T/revoked.krl" "$T/id_$k-cert.pub"
done
check_says "and key c" 'REVOKED' ssh-keygen -Q -f "$T/revoked.krl" "$T/id_c.pub"
check_eq "four revocation records in the audit log" 4 "$(grep -c 'certificate-revoked' "$T/audit.cef")"
check_out "with who revoked" 'duser=admin oidc_provider admin1@example.com' cat "$T/audit.cef"
check_eq "the store's document has them" 4 "$(jq '.revoked | length' "$T/store/revocations.json")"
finish
