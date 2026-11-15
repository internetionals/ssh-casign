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

| `provider`       | Feature             | Status | Keys                                                  |
|------------------|---------------------|--------|-------------------------------------------------------|
| `file`           | `ca-file`           | done   | OpenSSH private key file (default feature)            |
| `pkcs11`         | `ca-pkcs11`         | done   | YubiKey (ykcs11), smart cards (OpenSC), SoftHSM, HSMs |
| `vault`          | `ca-vault`          | done   | OpenBao / HashiCorp Vault transit engine              |
| `aws_kms`        | `ca-aws-kms`        | done   | AWS KMS                                               |
| `azure_keyvault` | `ca-azure-keyvault` | done   | Azure Key Vault / Managed HSM                         |
| `gcp_kms`        | `ca-gcp-kms`        | done   | Google Cloud KMS                                      |
| `barbican`       | `ca-barbican`       | done   | OpenStack Barbican (Keystone), signed in memory       |

```sh
# standalone server with a YubiKey or HSM
cargo build --release -p ssh-casign-service --no-default-features --features ca-pkcs11

# with OpenBao / Vault, keeping file-based CAs available
cargo build --release -p ssh-casign-service --features ca-vault

# Azure Functions, AWS Lambda, Google Cloud Run: static binaries, see deploy/
deploy/azure-functions/build.sh
deploy/aws-lambda/build.sh
deploy/gcp-cloud-run/build.sh
```

TLS for outgoing connections (IdP, Vault, Key Vault) is a feature too: `tls-native`
(default; the platform's TLS stack and certificate store) or `tls-rustls` (rustls with
the OS certificate store plus built-in Mozilla roots, for static builds). One of them
is required.

Signature algorithms per backend
--------------------------------

An authority offers the algorithms that both its key and its backend support (see
`signature_algorithms` in the README):

| Backend        | Ed25519                                                   | ECDSA P-256/384/521 | `rsa-sha2-512/256`   | `ssh-rsa` (SHA-1)                |
|----------------|-----------------------------------------------------------|---------------------|----------------------|----------------------------------|
| file           | yes                                                       | yes                 | yes                  | yes                              |
| pkcs11         | if the token has `CKM_EDDSA` (YubiKey 5.7+, SoftHSM 2.6+) | yes (`CKM_ECDSA`)   | yes (`CKM_RSA_PKCS`) | yes                              |
| vault          | yes                                                       | yes                 | yes                  | yes                              |
| aws_kms        | yes (`ECC_NIST_EDWARDS25519`)                             | yes                 | yes                  | no                               |
| azure_keyvault | no                                                        | yes                 | yes                  | no                               |
| gcp_kms        | yes (`EC_SIGN_ED25519`)                                   | P-256/384           | yes                  | with `RSA_SIGN_RAW_PKCS1_*` keys |
| barbican       | yes                                                       | yes                 | yes                  | yes                              |

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
token_file = "/run/secrets/vault-token"  # or VAULT_TOKEN, or an auth table (below)
# namespace = "admin/ssh"
# ca_cert_file = "/etc/ssl/vault-ca.pem"
cert_types = ["user"]
```

- The key version is fixed at startup, so the advertised public key always matches the
  signatures. After rotating the key in Vault, restart the service. Add the new key to
  servers' `TrustedUserCAKeys` before doing so.
- The token needs `read` on `transit/keys/<key>` and `update` on `transit/sign/<key>`
  (or a longer path for `hash_algorithm`).
- Authentication: `token_file` (re-read on every request, so a Vault Agent sidecar can
  rotate it) or `VAULT_TOKEN`, or a login method:

  ```toml
  [authorities.vault-ecdsa.auth]
  method = "kubernetes"                  # the pod's service account token
  role = "ssh-casign"
  # mount = "kubernetes"
  # token_file = "/var/run/secrets/kubernetes.io/serviceaccount/token"

  # method = "jwt"; role = "ssh-casign"; token_file = "/run/secrets/oidc-token"
  # method = "approle"; role_id_file = "/run/secrets/role-id"; secret_id_file = "/run/secrets/secret-id"
  ```

  Login tokens are renewed (`renew-self`) after two thirds of their lease. When renewal
  fails, or Vault answers 403 (a revoked token), the service logs in again. Tested
  against OpenBao 2.1.0 with all three methods, 6-second tokens and revocation in
  between. Kubernetes auth was tested with a stand-in for the TokenReview API.

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

`aws_kms`
---------

```toml
[authorities.kms]
provider = "aws_kms"
key_id = "alias/ssh-ca"        # key ID, key ARN, alias name or alias ARN
# region = "eu-west-1"         # default: from an ARN, else AWS_REGION / AWS_DEFAULT_REGION
# endpoint_url = "…"           # VPC/FIPS endpoint, LocalStack; default AWS_ENDPOINT_URL_KMS
# profile = "ssh-ca"           # default: AWS_PROFILE, else the credential chain
cert_types = ["user"]
```

- Key specs: `ECC_NIST_EDWARDS25519` (Ed25519; KMS signs the certificate itself, which
  must be at most 4096 bytes), `ECC_NIST_P256/P384/P521` and `RSA_2048/3072/4096` (the
  service hashes, KMS signs the digest). KMS has no SHA-1, so no `ssh-rsa`.
- Aliases are resolved at startup and the service signs with that key ARN, so moving
  the alias doesn't change the advertised key until a restart. KMS asymmetric keys have
  no versions; rotate with a new key.
- Requests are signed with AWS Signature Version 4 (checked against botocore's output
  in the tests). Credentials, in this order: a named profile (`profile` or
  `AWS_PROFILE`, static keys only), environment variables (Lambda), web identity
  (`AWS_WEB_IDENTITY_TOKEN_FILE` + `AWS_ROLE_ARN`, EKS), the `default` profile,
  container credentials (ECS, EKS Pod Identity), IMDSv2 (EC2). SSO and role-chaining
  profiles aren't supported. Temporary credentials are refreshed before they expire.
- The identity needs `kms:GetPublicKey` and `kms:Sign` on the key.
- Tested with LocalStack 4.0.3 (P-256, P-384, RSA) and `sshd`; that LocalStack version
  predates KMS Ed25519, so Ed25519 is covered by unit tests only.

Deployment on AWS Lambda: [deploy/aws-lambda](../deploy/aws-lambda/README.md).

`gcp_kms`
---------

```toml
[authorities.gcp]
provider = "gcp_kms"
key_version = "projects/p/locations/europe-west1/keyRings/ssh/cryptoKeys/ca/cryptoKeyVersions/1"
# credentials_file = "…"     # default: GOOGLE_APPLICATION_CREDENTIALS, gcloud, metadata server
# endpoint_url = "…"         # default https://cloudkms.googleapis.com
cert_types = ["user"]
```

- A Cloud KMS key version has a single algorithm, which decides what it offers:
  `EC_SIGN_ED25519` → `ssh-ed25519` (the certificate is signed as is),
  `EC_SIGN_P256_SHA256` / `EC_SIGN_P384_SHA384` → ECDSA, `RSA_SIGN_PKCS1_*_SHA256` →
  `rsa-sha2-256`, `RSA_SIGN_PKCS1_4096_SHA512` → `rsa-sha2-512`. The raw keys
  `RSA_SIGN_RAW_PKCS1_2048/3072/4096` sign a `DigestInfo` the service builds, so they
  offer `rsa-sha2-512`, `rsa-sha2-256` and (when listed) `ssh-rsa`: the only cloud KMS
  here that can serve SHA-1-only systems.
- The key version is named explicitly (asymmetric keys have no primary version).
- Credentials, in this order: `credentials_file` or `GOOGLE_APPLICATION_CREDENTIALS`
  (a service account key, from which the service signs a JWT, or `authorized_user`
  credentials), the gcloud credentials from `gcloud auth application-default login`,
  the metadata server (Cloud Run, GCE, GKE; `GCE_METADATA_HOST` overrides).
  Workload identity federation: an `external_account` file (as `gcloud iam
  workload-identity-pools create-cred-config` writes it) exchanges a token from a file
  or URL at Google's STS, for example a Kubernetes service account token on EKS, AKS or
  on-prem clusters. It then optionally impersonates a service account
  (`service_account_impersonation_url`). Text and JSON token formats work; the AWS and
  executable sources don't. Tested against a mock of STS and IAM credentials.
- The identity needs `cloudkms.cryptoKeyVersions.useToSign` and `viewPublicKey` (role
  `roles/cloudkms.signerVerifier`).
- Google has no Cloud KMS emulator: tested against a mock of the documented REST API
  (including raw PKCS#1 and service account JWTs) and with `sshd`, not yet against
  Cloud KMS itself.

Deployment on Google Cloud Run: [deploy/gcp-cloud-run](../deploy/gcp-cloud-run/README.md).

`barbican`
----------

OpenStack's Barbican stores secrets but doesn't sign with them. This backend fetches
the CA private key from Barbican when the service starts (with a Keystone token) and
signs in memory, like `file`. Barbican keeps the key encrypted at rest and controls who
may read it; the service host must be trusted with the key.

```toml
[authorities.openstack]
provider = "barbican"
secret = "5f6a2c1e-..."                  # the secret's UUID or its full URL
auth_url = "https://keystone.example.com:5000/v3"      # default OS_AUTH_URL
application_credential_id = "..."        # default OS_APPLICATION_CREDENTIAL_ID
application_credential_secret_file = "/run/secrets/app-credential"
# or a user: username, password_file, project_name, user_domain_name,
# project_domain_name (OS_USERNAME, OS_PASSWORD, OS_PROJECT_NAME)
# region = "RegionOne"                   # OS_REGION_NAME; interface = "public"
# endpoint_url = "https://barbican.example.com:9311"   # instead of the catalog
cert_types = ["user"]
```

Store the key as an unencrypted OpenSSH private key:

```sh
ssh-keygen -t ed25519 -N '' -f ca
openstack secret store --name ssh-ca --secret-type private \
  --payload-content-type application/octet-stream --file ca
shred -u ca
```

- Application credentials are the better choice for a service: scoped to one
  project, revocable, no user password.
- The Barbican endpoint comes from the Keystone catalog (`key-manager`, by interface
  and region) unless `endpoint_url` is set.
- The key is read once; after rotating it in Barbican, restart the service.
- Tested against a mock of Keystone v3 and Barbican (both authentication methods,
  the catalog, content types), not against a real OpenStack.

Secrets in containers
---------------------

Every secret the service needs can come from a file or an environment variable, so
podman and Docker secrets, Kubernetes secrets and Vault Agent work as they are:

| Part                           | Secrets from                                                    |
|--------------------------------|-----------------------------------------------------------------|
| `file`                         | `private_key_file`                                              |
| `pkcs11`                       | `pin_file`                                                      |
| `vault`                        | `token_file`, `VAULT_TOKEN`, the `auth` files                   |
| `aws_kms`, `s3`                | `AWS_SHARED_CREDENTIALS_FILE`, `AWS_*`, token files             |
| `azure_keyvault`, `azure_blob` | `client_secret_file`, `AZURE_CLIENT_SECRET`, `account_key_file` |
| `gcp_kms`, `gcs`               | `credentials_file`, `GOOGLE_APPLICATION_CREDENTIALS`            |
| `barbican`                     | `application_credential_secret_file`, `password_file`, `OS_*`   |
| the configuration              | `SSH_CASIGN_CONFIG` (a file) or `SSH_CASIGN_CONFIG_TOML`        |

With podman:

```sh
podman secret create ssh-casign-ca ./ca
podman secret create ssh-casign-config ./config.toml
podman run \
  --secret ssh-casign-ca,target=/run/secrets/ca-key,mode=0400,uid=65532 \
  --secret ssh-casign-config,target=/etc/ssh-casign/config.toml,mode=0400,uid=65532 \
  ssh-casign-cloud-run:latest
# or the configuration as a variable:
#   --secret ssh-casign-config,type=env,target=SSH_CASIGN_CONFIG_TOML
```

`uid=65532` is the distroless image's `nonroot` user. The service doesn't check file
modes, so `0400` owned by that user, or the default `0444`, both work. Tested with the
static image in a podman pod: the CA key and the configuration as mounted secrets, and
the configuration as an environment secret. The secrets don't show in `podman
inspect`.

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

