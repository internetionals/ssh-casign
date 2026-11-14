CA key backends
===============

Each authority keeps its CA key in a backend. The service encodes the certificate
itself and only asks the backend to sign it. It then verifies the signature against the
authority's public key before handing the certificate out, so a misconfigured backend
(or the wrong key) fails the request instead of producing a bad certificate.

Backends are Cargo features of `ssh-casign-service`, so a build only contains what its
platform needs. A configuration that names a backend the build lacks fails at startup
with the feature to enable.

| `provider`       | Feature             | Status  | Keys                                                  |
|------------------|---------------------|---------|-------------------------------------------------------|
| `file`           | `ca-file`           | done    | OpenSSH private key file (default feature)            |
| `pkcs11`         | `ca-pkcs11`         | done    | YubiKey (ykcs11), smart cards (OpenSC), SoftHSM, HSMs |
| `vault`          | `ca-vault`          | done    | OpenBao / HashiCorp Vault transit engine              |
| `aws_kms`        | `ca-aws-kms`        | planned | AWS KMS                                               |
| `azure_keyvault` | `ca-azure-keyvault` | planned | Azure Key Vault / Managed HSM                         |
| `gcp_kms`        | `ca-gcp-kms`        | planned | Google Cloud KMS                                      |

```sh
# standalone server with a YubiKey or HSM
cargo build --release -p ssh-casign-service --no-default-features --features ca-pkcs11

# with OpenBao / Vault, keeping file-based CAs available
cargo build --release -p ssh-casign-service --features ca-vault
```

Signature algorithms per backend
--------------------------------

An authority offers the algorithms that both its key and its backend support (see
`signature_algorithms` in the README):

| Backend | Ed25519                                                   | ECDSA P-256/384/521 | `rsa-sha2-512/256`   | `ssh-rsa` (SHA-1)    |
|---------|-----------------------------------------------------------|---------------------|----------------------|----------------------|
| file    | yes                                                       | yes                 | yes                  | yes                  |
| pkcs11  | if the token has `CKM_EDDSA` (YubiKey 5.7+, SoftHSM 2.6+) | yes (`CKM_ECDSA`)   | yes (`CKM_RSA_PKCS`) | yes                  |
| vault   | yes                                                       | yes                 | yes                  | yes                  |
| AWS KMS | to check                                                  | yes                 | yes                  | no                   |
| Azure   | no                                                        | yes                 | yes                  | no                   |
| GCP KMS | yes                                                       | P-256/384           | yes                  | only raw-PKCS#1 keys |

On platforms without SHA-1 support, profiles that need `ssh-rsa` must use an authority
on another backend.

`file`
------

```toml
[authorities.ed25519]
provider = "file"
private_key_file = "/etc/ssh-casign/ca"   # unencrypted OpenSSH private key
cert_types = ["user"]
```

`pkcs11`
--------

```toml
[authorities.yubikey]
provider = "pkcs11"
module = "/usr/lib/x86_64-linux-gnu/libykcs11.so"   # or opensc-pkcs11.so, libsofthsm2.so
token_label = "YubiKey PIV #12345678"   # optional if only one token is present
key_label = "SIGN key"                  # and/or key_id = "02" (hex)
pin_file = "/run/secrets/ca-pin"        # or SSH_CASIGN_PKCS11_PIN; neither: no login
cert_types = ["user"]
```

- The private key and a public key object with the same label/ID must be on the token.
- The algorithms offered follow the token's mechanism list. RSA uses `CKM_RSA_PKCS`
  over a `DigestInfo` the service builds, so every hash works.
- Calls run on a blocking thread, one at a time per key. If signing fails (token
  replugged, session reset), the service opens a new session and tries once more.

Testing with SoftHSM:

```sh
softhsm2-util --init-token --free --label ca --pin 1234 --so-pin 0000
M=/usr/lib/softhsm/libsofthsm2.so
pkcs11-tool --module $M --token-label ca --login --pin 1234 \
  --keypairgen --key-type EC:edwards25519 --label test-ed25519 --id 01
pkcs11-tool --module $M --token-label ca --login --pin 1234 \
  --keypairgen --key-type EC:prime256v1 --label test-p256 --id 02
pkcs11-tool --module $M --token-label ca --login --pin 1234 \
  --keypairgen --key-type rsa:2048 --label test-rsa --id 03
PKCS11_TEST_MODULE=$M PKCS11_TEST_TOKEN=ca SSH_CASIGN_PKCS11_PIN=1234 \
  cargo test -p ssh-casign-service --features ca-pkcs11 -- --ignored issues_with_a_real_token
```

`vault`
-------

```toml
[authorities.vault-ecdsa]
provider = "vault"
address = "https://vault.example.com:8200"
mount = "transit"                        # default
key = "ssh-ca"                           # transit key: ed25519, ecdsa-p256/384/521, rsa-2048/3072/4096
# key_version = 3                        # default: latest at startup
token_file = "/run/secrets/vault-token"  # or VAULT_TOKEN
# namespace = "admin/ssh"
# ca_cert_file = "/etc/ssl/vault-ca.pem"
cert_types = ["user"]
```

- The key version is fixed at startup, so the advertised public key always matches the
  signatures. After rotating the key in Vault, restart the service. Add the new key to
  servers' `TrustedUserCAKeys` before doing so.
- The token needs `read` on `transit/keys/<key>` and `update` on `transit/sign/<key>`
  (or a longer path for `hash_algorithm`).
- Only token authentication so far; AppRole, Kubernetes and cloud IAM logins are not
  implemented yet.
