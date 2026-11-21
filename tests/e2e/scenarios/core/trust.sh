#!/bin/bash
# needs: oidc
# The signed trust statement: pinning, forgeries refused, CA rotation in
# automatic mode, offline trust keys (2 of 3), an attacker in the config.
source "$(dirname "$0")/../../lib.sh"
scenario "trust statement and pinning"
require oidc "$OIDC/ssh-casign/.well-known/openid-configuration"

for k in ca users2-ca host-ca; do ssh-keygen -q -t ed25519 -N '' -C "$k" -f "$T/$k"; done
for k in trust1 trust2 trust3 attacker; do ssh-keygen -q -t ed25519 -N '' -C "$k" -f "$T/$k"; done
pub() { cut -d' ' -f1,2 "$1"; }

# stage: auto VERSION, rotate VERSION, retire VERSION, offline, evil-auto
config() {
  local stage="$1" version="${2:-1}" users2=false retired=false
  case "$stage" in rotate|retire|offline|evil-*) users2=true ;; esac
  case "$stage" in retire|offline|evil-*) retired=true ;; esac
  cat <<CONF
server_id = "e2e"
listen = "127.0.0.1:3000"
[oidc_provider]
issuer = "$OIDC/ssh-casign"
client_id = "ssh-casign"
id_claim = "upn"
[profiles.default]
ssh_ca = $($users2 && echo '["users2", "users"]' || echo '"users"')
validity = 300
[[profiles.map]]
name = "admin-hosts"
claim = "roles"
value = "ssh-admin"
settings = { ssh_ca = "hosts", cert_types = ["host"], validity = 86400, matching_principals = '[a-z0-9-]+\.example\.com' }
[authorities.users]
provider = "file"
private_key_file = "$T/ca"
cert_types = ["user"]
retired = $retired
[authorities.hosts]
provider = "file"
private_key_file = "$T/host-ca"
cert_types = ["host"]
known_hosts_pattern = "*.prod.example.com"
CONF
  $users2 && printf '[authorities.users2]\nprovider = "file"\nprivate_key_file = "%s"\ncert_types = ["user"]\n' "$T/users2-ca"
  case "$stage" in
    offline) printf '[trust]\nstatement = "%s"\nsignatures = ["%s", "%s"]\n' "$T/trust.toml" "$T/trust1.sig" "$T/trust2.sig" ;;
    evil-auto) printf '[authorities.evil]\nprovider = "file"\nprivate_key_file = "%s"\ncert_types = ["user"]\n[trust]\nid = "example"\nversion = 5\n' "$T/attacker" ;;
    *) printf '[trust]\nid = "example"\nversion = %s\n' "$version" ;;
  esac
}
run_stage() { service_stop 2>/dev/null; config "$@" > "$T/service.toml"; service_start "$T/service.toml"; }
cat > "$T/client.toml" <<CONF
token_store = "none"
[profiles.default]
url = "http://127.0.0.1:3000/"
trust_store = "$T/pin.json"
[profiles.fake]
url = "http://127.0.0.1:3100/"
trust_store = "$T/pin.json"
CONF

# 1. automatic mode
run_stage auto 1 || exit 1
check_fail "pin: wrong expected signers refused" 'not the expected keys' \
  client trust pin --expect "$(fingerprint "$T/trust1.pub")"
check_out "pin: the CA fingerprints" 'pinned in' \
  client trust pin --expect "$(fingerprint "$T/ca.pub")" --expect "$(fingerprint "$T/host-ca.pub")"
check_out "ca-keys: host pattern from the statement" '^@cert-authority \*\.prod\.example\.com ' client ca-keys --type host
check_out "ca-keys -o writes the file" 'updated' client ca-keys -o "$T/trusted-user-ca-keys" --on-change "touch $T/changed"
check_eq "and runs --on-change" yes "$(test -f "$T/changed" && echo yes)"
rm -f "$T/changed"
check_eq "a second run changes nothing" "" "$(client ca-keys -o "$T/trusted-user-ca-keys" --on-change "touch $T/changed")"
check "krl: signatures checked" client krl -o "$T/revoked.krl"
curl -sf "$SERVICE_URL/.well-known/ssh-casign" > "$T/discovery.json"
jq -j .trust.statement "$T/discovery.json" > "$T/statement.json"
jq -r '.trust.signatures[0]' "$T/discovery.json" > "$T/ca0.sig"
{ echo "ca $(pub "$T/ca.pub")"; echo "ca $(pub "$T/host-ca.pub")"; } > "$T/allowed_ca"
check_out "ssh-keygen -Y verify accepts the service's signature" 'Good "ssh-casign-trust" signature' \
  sh -c "ssh-keygen -Y verify -f '$T/allowed_ca' -I ca -n ssh-casign-trust -s '$T/ca0.sig' < '$T/statement.json'"

# 2. forgeries from a fake server
mkdir -p "$T/fake/.well-known"
python3 -I - "$T" <<'PY'
import json, subprocess, sys
t = sys.argv[1]
d = json.load(open(f"{t}/discovery.json"))
st = json.loads(d["trust"]["statement"])
evil = " ".join(open(f"{t}/attacker.pub").read().split()[:2])
st["authorities"].append({"name": "zz-evil", "public_key": evil, "cert_types": ["user"]})
st["version"] += 1
st["signers"] = {"keys": [evil], "threshold": 1}
canonical = json.dumps(st, separators=(",", ":"))
sig = subprocess.run(["ssh-keygen", "-q", "-Y", "sign", "-n", "ssh-casign-trust", "-f", f"{t}/attacker"],
                     input=canonical.encode(), capture_output=True).stdout.decode()
forged = dict(d, trust={"statement": canonical, "signatures": [sig]},
              revocation_list="revoked.krl", revocation_list_signatures="revoked.krl.sig")
json.dump(forged, open(f"{t}/fake/.well-known/ssh-casign", "w"))
emptied = dict(d, revocation_list="revoked.krl", revocation_list_signatures="revoked.krl.sig")
json.dump(emptied, open(f"{t}/fake/emptied.json", "w"))
open(f"{t}/fake/.well-known/revoked.krl", "wb").write(b"SSHKRL\n\0" + b"\0\0\0\1" + b"\0" * 24 + b"\0" * 8)
open(f"{t}/fake/.well-known/revoked.krl.sig", "w").write("")
PY
background python3 -I -B -m http.server 3100 --bind 127.0.0.1 --directory "$T/fake"
wait_for http://127.0.0.1:3100/ 10
check_fail "fake server: an extra CA signed by an attacker" '0 of the pinned signers' client -p fake ca-keys
cp "$T/fake/emptied.json" "$T/fake/.well-known/ssh-casign"
check_fail "fake server: an emptied KRL" 'not signed by authorities' client -p fake krl -o "$T/revoked.krl"

# 3. CA rotation in automatic mode
run_stage rotate 1 || exit 1
check_fail "a new CA without a new version" 'a change needs a higher version' client ca-keys
run_stage rotate 2 || exit 1
check_out "version 2 with users2" 'users2' client ca-keys
run_stage retire 3 || exit 1
check_out "version 3: users retired, still trusted" 'retired' client trust show
check_out "the retired CA's certificates stay trusted" ' users$' client ca-keys

# 4. offline trust keys, 2 of 3
cat > "$T/trust.toml" <<TOML
id = "example"
version = 4
expires = 2099-01-01
[signers]
threshold = 2
keys = ["$(pub "$T/trust1.pub")", "$(pub "$T/trust2.pub")", "$(pub "$T/trust3.pub")"]
[[authorities]]
name = "users"
public_key = "$(pub "$T/ca.pub")"
cert_types = ["user"]
retired = true
[[authorities]]
name = "users2"
public_key = "$(pub "$T/users2-ca.pub")"
cert_types = ["user"]
[[authorities]]
name = "hosts"
public_key = "$(pub "$T/host-ca.pub")"
cert_types = ["host"]
known_hosts_pattern = "*.prod.example.com"
TOML
"$CLIENT" trust statement "$T/trust.toml" | ssh-keygen -q -Y sign -n ssh-casign-trust -f "$T/trust1" > "$T/trust1.sig"
check "trust sign (with ssh-keygen)" "$CLIENT" trust sign -k "$T/trust2" -o "$T/trust2.sig" "$T/trust.toml"
check_fail "trust verify: one signature is not enough" '1 of its own signers' "$CLIENT" trust verify "$T/trust.toml" "$T/trust1.sig"
check_out "trust verify: two are" '^valid' "$CLIENT" trust verify "$T/trust.toml" "$T/trust1.sig" "$T/trust2.sig"
for i in 1 2 3; do echo "trust$i $(pub "$T/trust$i.pub")"; done > "$T/allowed_trust"
check_out "ssh-keygen -Y verify accepts trust sign's signature" 'Good' \
  sh -c "'$CLIENT' trust statement '$T/trust.toml' | ssh-keygen -Y verify -f '$T/allowed_trust' -I trust2 -n ssh-casign-trust -s '$T/trust2.sig'"
run_stage offline || exit 1
check_out "automatic version 3 to offline version 4" 'users2' client ca-keys
check_out "the pin is version 4, 2 of 3" 'version 4.*' client trust show
check "krl still verifies" client krl -o "$T/revoked.krl"

# 5. an attacker who controls the service's configuration
sed -i 's/^version = 4$/version = 6/' "$T/trust.toml"
service_stop
config offline > "$T/service.toml"
check_fail "a tampered statement stops the service" "isn't validly signed" service_refuses "$T/service.toml"
sed -i 's/^version = 6$/version = 4/' "$T/trust.toml"
run_stage evil-auto || exit 1
check_fail "back to automatic mode with an extra CA" '0 of the pinned signers' client ca-keys
check_eq "the pin stays at version 4" 4 "$(jq -r .statement "$T/pin.json" | jq .version)"
finish
