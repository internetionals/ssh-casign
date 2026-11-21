#!/bin/bash
# needs: oidc
# Weak keys: ROCA, Fermat, a small factor, a low-order Ed25519 point,
# blocklists (Debian format), shared keys, and a blocklisted CA key.
source "$(dirname "$0")/../../lib.sh"
scenario "weak key checks"
require oidc "$OIDC/ssh-casign/.well-known/openid-configuration"

python3 -I -B "$E2E_DIR/mocks/weak_keys.py" "$T"
for k in good blocked dup; do ssh-keygen -q -t ed25519 -N '' -C "$k" -f "$T/id_$k"; done
python3 -I - "$T" <<'PY'
import base64, hashlib, sys
t = sys.argv[1]
blob = base64.b64decode(open(f"{t}/id_blocked.pub").read().split()[1])
open(f"{t}/blocklist.txt", "w").write("# Debian openssh-blacklist format\n" + hashlib.md5(blob).hexdigest()[12:] + "\n")
PY
mkdir -p "$T/store"
config() {
  mock_config "
[store]
type = \"file\"
path = \"$T/store\"
[key_checks]
blocklists = [$1]
duplicates = \"$2\"
[audit]
[[audit.sink]]
type = \"file\"
path = \"$T/audit.cef\"
" | sed 's/^ssh_ca = "users"$/ssh_ca = "users"\nallowed_key_types = ["ssh-ed25519", "ssh-rsa"]/'
}
config "\"$T/blocklist.txt\"" warn > "$T/service.toml"
service_start "$T/service.toml" || exit 1
client_config
U="$(mock_token user1)"
A="$(mock_token admin1)"
sign() { SSH_CASIGN_TOKEN="$1" "$CLIENT" -f "$T/client.toml" cert -o - "$2"; }
check_fail "Fermat" 'primes are too close together' sign "$U" "$T/fermat.pub"
check_fail "ROCA" 'ROCA' sign "$U" "$T/roca.pub"
check_fail "a small factor" 'small factor 3' sign "$U" "$T/smallfactor.pub"
check_fail "a low-order Ed25519 key" 'low order' sign "$U" "$T/lowed.pub"
check_fail "a blocklisted key (by file name only)" 'on the blocklist blocklist.txt$|on the blocklist blocklist.txt ' sign "$U" "$T/id_blocked.pub"
check "a good key" sign "$U" "$T/id_good.pub"
ssh-keygen -q -t rsa -b 4096 -N '' -f "$T/rsa4096"
check "a 4096-bit RSA key" sign "$U" "$T/rsa4096.pub"
check_out "ssh-keygen itself accepts the weak keys" 'RSA' ssh-keygen -l -f "$T/roca.pub"
check "same key for user1" sign "$U" "$T/id_dup.pub"
check "and admin1 (warn)" sign "$A" "$T/id_dup.pub"
check_out "logged" 'also certified for' cat "$T/service.log"
check_out "in the audit record" 'sshKeySharedWith=' cat "$T/audit.cef"
service_stop
config "\"$T/blocklist.txt\"" deny > "$T/service.toml"
service_start "$T/service.toml" || exit 1
check_fail "duplicates = deny" 'already certified for another identity' sign "$A" "$T/id_dup.pub"
service_stop
fingerprint "$T/ca.pub" > "$T/ca-blocklist.txt"
config "\"$T/ca-blocklist.txt\"" warn > "$T/service.toml"
check_fail "a blocklisted CA key stops the service" 'authority users: key is on the blocklist' service_refuses "$T/service.toml"
finish
