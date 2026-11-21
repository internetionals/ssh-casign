#!/bin/bash
# needs: oidc
# Behind a proxy or CDN: the client address from X-Forwarded-For only from
# trusted proxies, skipping trusted hops; the proxy's correlation ID.
source "$(dirname "$0")/../../lib.sh"
scenario "client addresses behind proxies"
require oidc "$OIDC/ssh-casign/.well-known/openid-configuration"

audit() {
  cat <<CONF
[audit]
client_address_header = "x-forwarded-for"
trusted_proxies = [$1]
correlation_id_header = "cf-ray"
[[audit.sink]]
type = "file"
path = "$T/audit.cef"
CONF
}
mock_config "$(audit '"127.0.0.1/32", "198.51.100.0/24"')" > "$T/service.toml"
service_start "$T/service.toml" || exit 1
ssh-keygen -q -t ed25519 -N '' -f "$T/user"
TOKEN="$(mock_token user1)"
BODY="$(jq -n --arg k "$(cat "$T/user.pub")" '{public_key: $k, cert_type: "user"}')"
sign() {
  curl -sf -o /dev/null -w '%{http_code}' -H "Authorization: Bearer $TOKEN" \
    -H 'Content-Type: application/json' "$@" -d "$BODY" "$SERVICE_URL/sign"
}
last() { tail -1 "$T/audit.cef" | tr ' ' '\n' | sed -n "s/^$1=//p"; }

check_eq "a request through two trusted hops" 200 \
  "$(sign -H 'X-Forwarded-For: 6.6.6.6, 203.0.113.9, 198.51.100.2' -H 'CF-Ray: 8f1c2a3b4c5d6e7f-AMS')"
check_eq "the client is the first untrusted address" 203.0.113.9 "$(last src)"
check_eq "the proxy is recorded" 127.0.0.1 "$(last proxyAddress)"
check_eq "the correlation ID is recorded" 8f1c2a3b4c5d6e7f-AMS "$(last flexString2)"
check_eq "no client port behind a proxy" "" "$(last spt)"
check_eq "RFC 7239 isn't this header" 200 "$(sign -H 'Forwarded: for=192.0.2.60')"
check_eq "without the header: the peer" 127.0.0.1 "$(last src)"
service_stop

mock_config "$(audit '"198.51.100.0/24"')" > "$T/service.toml"
service_start "$T/service.toml" || exit 1
check_eq "an untrusted peer" 200 "$(sign -H 'X-Forwarded-For: 6.6.6.6' -H 'CF-Ray: spoofed')"
check_eq "its headers are ignored" 127.0.0.1 "$(last src)"
check_eq "and so is its correlation ID" "" "$(last flexString2)"
check "with its port" test -n "$(last spt)"
check_out "discovery may be cached briefly" 'max-age=300' curl -s -D - -o /dev/null "$SERVICE_URL/.well-known/ssh-casign"
finish
