CA key backends
===============

Each authority keeps its CA key in a backend. The service encodes the certificate
itself and only asks the backend to sign it. It then verifies the signature against the
authority's public key before handing the certificate out, so a misconfigured backend
(or the wrong key) fails the request instead of producing a bad certificate.

Each backend is its own crate (`ssh-casign-ca-*`), depending only on the backend API in
`ssh-casign-ca`. The `ssh-casign-service` binary includes them through Cargo features, so
a build only contains what its platform needs. A configuration that names a backend the
build lacks fails at startup with the feature to enable.

| `provider`       | Feature             | Status  | Keys                                                  |
|------------------|---------------------|---------|-------------------------------------------------------|
| `file`           | `ca-file`           | done    | OpenSSH private key file (default feature)            |
| `pkcs11`         | `ca-pkcs11`         | done    | YubiKey (ykcs11), smart cards (OpenSC), SoftHSM, HSMs |
| `vault`          | `ca-vault`          | done    | OpenBao / HashiCorp Vault transit engine              |
| `aws_kms`        | `ca-aws-kms`        | planned | AWS KMS                                               |
| `azure_keyvault` | `ca-azure-keyvault` | done    | Azure Key Vault / Managed HSM                         |
| `gcp_kms`        | `ca-gcp-kms`        | planned | Google Cloud KMS                                      |

```sh
# standalone server with a YubiKey or HSM
cargo build --release -p ssh-casign-service --no-default-features --features ca-pkcs11

# with OpenBao / Vault, keeping file-based CAs available
cargo build --release -p ssh-casign-service --features ca-vault

# Azure Functions: static binary, see deploy/azure-functions
deploy/azure-functions/build.sh
```

TLS for outgoing connections (IdP, Vault, Key Vault) is a feature too: `tls-native`
(default; the platform's TLS stack and certificate store) or `tls-rustls` (rustls with
the OS certificate store plus built-in Mozilla roots, for static builds). One of them
is required.

Signature algorithms per backend
--------------------------------

An authority offers the algorithms that both its key and its backend support (see
`signature_algorithms` in the README):

| Backend        | Ed25519                                                   | ECDSA P-256/384/521 | `rsa-sha2-512/256`   | `ssh-rsa` (SHA-1)    |
|----------------|-----------------------------------------------------------|---------------------|----------------------|----------------------|
| file           | yes                                                       | yes                 | yes                  | yes                  |
| pkcs11         | if the token has `CKM_EDDSA` (YubiKey 5.7+, SoftHSM 2.6+) | yes (`CKM_ECDSA`)   | yes (`CKM_RSA_PKCS`) | yes                  |
| vault          | yes                                                       | yes                 | yes                  | yes                  |
| AWS KMS        | to check                                                  | yes                 | yes                  | no                   |
| azure_keyvault | no                                                        | yes                 | yes                  | no                   |
| GCP KMS        | yes                                                       | P-256/384           | yes                  | only raw-PKCS#1 keys |

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
  cargo test -p ssh-casign-ca-pkcs11 -- --ignored
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

`azure_keyvault`
----------------

```toml
[authorities.kv-ec]
provider = "azure_keyvault"
vault_url = "https://my-vault.vault.azure.net"   # or https://my-hsm.managedhsm.azure.net
key = "ssh-ca-ec"                                # EC P-256/384/521 or RSA, also -HSM
# key_version = "…"                              # default: current version at startup
# credential = "auto"                            # managed_identity, client_secret, workload_identity
# client_id = "…"                                # user-assigned identity or app registration
# tenant_id = "…"; client_secret_file = "…"      # for client_secret
cert_types = ["user"]
```

- The service hashes the certificate and Key Vault signs the hash (`ES256/384/512`,
  `RS256`, `RS512`). Key Vault has no Ed25519 and no SHA-1, so `ssh-rsa` needs another
  backend.
- Credentials (`auto` tries them in this order): workload identity
  (`AZURE_FEDERATED_TOKEN_FILE`, AKS), a client secret (`client_secret_file` or
  `AZURE_CLIENT_SECRET`), managed identity through `IDENTITY_ENDPOINT` (App Service,
  Functions), managed identity through the instance metadata service (VMs). Tenant and
  client ID default to `AZURE_TENANT_ID` and `AZURE_CLIENT_ID`. Tokens are cached until
  shortly before they expire.
- The identity needs `get` and `sign` on the key (role "Key Vault Crypto User", or a
  narrower custom role).
- The key version is fixed at startup, as for Vault.
- `ca_cert_file` adds a CA to trust, e.g. for an emulator. Tested with
  [Lowkey Vault](https://github.com/nagyesta/lowkey-vault). Its self-signed certificate
  is valid for longer than macOS accepts, so on macOS use a `tls-rustls` build for that.

Deployment on Azure Functions: [deploy/azure-functions](../deploy/azure-functions/README.md).

Writing a backend
-----------------

A backend crate depends on `ssh-casign-ca` and provides:

- a type implementing `ssh_casign_ca::Backend`: `public_key()`, the `algorithms()` it
  can sign with, and `sign(algorithm, data)` returning the signature in SSH encoding
  (`encoding` has helpers for ECDSA conversion, digests and RSA `DigestInfo`);
- `pub const PROVIDER: &str`, the name used as `provider` in the configuration;
- `pub fn load(config: toml::Table) -> BoxFuture<Result<Box<dyn Backend>, String>>`,
  which gets the authority's table without the common keys (`provider`, `cert_types`,
  `signature_algorithms`); `ssh_casign_ca::parse_config` deserializes it.

Certificates are encoded and verified by `ssh_casign_ca::signing::issue`, so a backend
can't produce an invalid certificate. `ssh_casign_ca::testing::issue_with_every_algorithm`
checks a backend end to end in its own tests.

To include it in the service: add an optional dependency and a `ca-…` feature to
`ssh-casign-service/Cargo.toml`, and a `registry.register(PROVIDER, load)` line (plus
`unavailable` for builds without it) in `ssh-casign-service/src/main.rs`. HTTP-based
backends should take their TLS stack from the service: give them `native-tls` (default)
and `rustls` features that the service's `tls-native`/`tls-rustls` forward to.

