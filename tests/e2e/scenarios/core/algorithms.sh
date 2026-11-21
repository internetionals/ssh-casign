#!/bin/bash
# needs: oidc
# Several CAs per profile, chosen by the client's accepted CA signature
# algorithms; ssh-rsa (SHA-1) only where configured; client key types.
source "$(dirname "$0")/../../lib.sh"
scenario "CA signature algorithms and client key types"
require oidc "$OIDC/ssh-casign/.well-known/openid-configuration"

ssh-keygen -q -t ecdsa -b 384 -N '' -f "$T/ca-ecdsa"
ssh-keygen -q -t rsa -b 3072 -N '' -f "$T/ca-rsa"
mock_config '
[authorities.ecdsa]
provider = "file"
private_key_file = "'"$T"'/ca-ecdsa"
cert_types = ["user"]
[authorities.rsa]
provider = "file"
private_key_file = "'"$T"'/ca-rsa"
cert_types = ["user"]
[authorities.rsa-legacy]
provider = "file"
private_key_file = "'"$T"'/ca-rsa"
cert_types = ["user"]
signature_algorithms = ["ssh-rsa"]
' | sed 's/^ssh_ca = "users"$/ssh_ca = ["users", "ecdsa", "rsa", "rsa-legacy"]\nallowed_key_types = ["ssh-ed25519", "ssh-rsa"]/' > "$T/service.toml"
service_start "$T/service.toml" || exit 1
client_config
ssh-keygen -q -t ed25519 -N '' -f "$T/user"
export SSH_CASIGN_TOKEN="$(mock_token user1)"
sign() { client cert -o "$T/user-cert.pub" "$@" "$T/user.pub" >/dev/null 2>&1 && signing_ca "$T/user-cert.pub"; }

check_out "default: the first authority (Ed25519)" '^ED25519 .*using ssh-ed25519' sign
check_out "ecdsa-sha2-nistp384" 'ECDSA .*using ecdsa-sha2-nistp384' sign --ca-signature-algorithm ecdsa-sha2-nistp384
check_out "rsa-sha2-256" 'RSA .*using rsa-sha2-256' sign --ca-signature-algorithm rsa-sha2-256
check_out "the authority's preference within the accepted set" 'using rsa-sha2-512' \
  sign --ca-signature-algorithm rsa-sha2-256,rsa-sha2-512
check_out "ssh-rsa from the legacy authority" 'RSA .*using ssh-rsa' sign --ca-signature-algorithm ssh-rsa
check_fail "nothing offers ecdsa-sha2-nistp521" 'no authority of this profile signs' \
  client cert -o - --ca-signature-algorithm ecdsa-sha2-nistp521 "$T/user.pub"
check_fail "unknown algorithms only" 'no known CA signature algorithm' \
  client cert -o - --ca-signature-algorithm made-up "$T/user.pub"
check_out "discovery lists ssh-rsa only for the legacy authority" '"rsa-legacy".*ssh-rsa' \
  sh -c "curl -sf '$SERVICE_URL/.well-known/ssh-casign' | jq -c '.authorities | to_entries[] | [.key, .value.signature_algorithms]' | tr '\n' ' '"

# sshd: SHA-1 CA signatures need CASignatureAlgorithms
sign --ca-signature-algorithm ssh-rsa >/dev/null
sshd_start "$T/ca-rsa.pub" user1 || exit 1
check_fail "sshd refuses an ssh-rsa signed certificate by default" 'Permission denied' ssh_login "$T/user"
sshd_stop
sshd_start "$T/ca-rsa.pub" user1 'CASignatureAlgorithms +ssh-rsa' || exit 1
check_out "with +ssh-rsa it accepts it" 'logged in as' ssh_login "$T/user"
sign --ca-signature-algorithm rsa-sha2-512 >/dev/null
check_out "rsa-sha2-512 is accepted too" 'logged in as' ssh_login "$T/user"

ssh-keygen -q -t ecdsa -N '' -f "$T/user-ecdsa"
check_fail "client key type outside allowed_key_types" 'not in allowed_key_types' \
  client cert -o - "$T/user-ecdsa.pub"
finish
