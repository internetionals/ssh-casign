#!/bin/bash
# needs: oidc
# The CEF audit log: file, stdout and syslog (Unix socket, UDP, TCP) sinks,
# denials, and failing closed when a required sink is down.
source "$(dirname "$0")/../../lib.sh"
scenario "audit log sinks and failing closed"
require oidc "$OIDC/ssh-casign/.well-known/openid-configuration"

background python3 -I -B "$E2E_DIR/mocks/syslog_receiver.py" "$T" 5514
RECEIVER_PID=$!
for i in $(seq 40); do [ -S "$T/log.sock" ] && break; sleep 0.25; done
mock_config "
[audit]
[[audit.sink]]
type = \"file\"
path = \"$T/audit.cef\"
[[audit.sink]]
type = \"stdout\"
[[audit.sink]]
type = \"syslog\"
path = \"$T/log.sock\"
[[audit.sink]]
type = \"syslog\"
transport = \"udp\"
address = \"127.0.0.1:5514\"
[[audit.sink]]
type = \"syslog\"
transport = \"tcp\"
address = \"127.0.0.1:5514\"
facility = \"local4\"
" > "$T/service.toml"
service_start "$T/service.toml" || exit 1
client_config
ssh-keygen -q -t ed25519 -N '' -f "$T/user"
export SSH_CASIGN_TOKEN="$(mock_token user1)"
check "a certificate is issued" client cert -o "$T/user-cert.pub" "$T/user.pub"
sleep 0.5
check_out "file sink: issued record" '^CEF:0\|ssh-casign\|ssh-casign-service\|.*\|certificate-issued\|' cat "$T/audit.cef"
check_out "stdout sink" 'CEF:0\|.*certificate-issued' cat "$T/service.log"
check_out "syslog, Unix socket" 'ssh-casign.*CEF:0' cat "$T/rx-unix"
check_out "syslog, UDP (RFC 5424)" '^<[0-9]+>1 .*CEF:0' cat "$T/rx-udp"
check_out "syslog, TCP, facility local4 (<165>: local4.notice)" '^<165>1 ' cat "$T/rx-tcp"
serial="$(ssh-keygen -L -f "$T/user-cert.pub" | awk '/Serial:/{print $2}')"
check_out "the record has the serial" "flexString1=$serial" cat "$T/audit.cef"
check_out "and the certificate" 'sshCertificate=ssh-ed25519-cert-v01@openssh.com ' cat "$T/audit.cef"
check_fail "a refused request" 'not in allowed_principals|403' client cert -n root -o - "$T/user.pub"
check_out "is recorded as a denial" 'certificate-denied.*act=denied' cat "$T/audit.cef"

kill $RECEIVER_PID; wait $RECEIVER_PID 2>/dev/null
sleep 0.5
check_fail "TCP syslog down: the certificate is withheld" 'Audit log unavailable' client cert -o - "$T/user.pub"
service_stop
sed -i 's/^type = "syslog"$/type = "syslog"\nrequired = false/' "$T/service.toml"
service_start "$T/service.toml" || exit 1
check "optional sinks that are down don't block issuing" client cert -o - "$T/user.pub"
finish
