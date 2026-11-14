ssh-casign on Google Cloud Run
==============================

The service runs as a Cloud Run service: a container with the static binary on
distroless, listening on the `PORT` Cloud Run sets. Cloud Run *functions* are
source-based (buildpacks for a fixed set of languages, no Rust), so a container image on
a Cloud Run service is the way to run a Rust binary on that platform.

CA keys live in Cloud KMS; the service's service account signs with them through the
metadata server, so the configuration contains no secrets.

Build
-----

```sh
CONFIG=path/to/config.toml deploy/gcp-cloud-run/build.sh
# -> container image ssh-casign-cloud-run:latest (linux/amd64)
```

- `ARCH=x86_64` (default) or `ARCH=arm64` (for local testing); `IMAGE=name:tag`.
- The binary is static (musl, rustls, built-in CA roots), built by
  `deploy/build-static.sh`. Features: `ca-gcp-kms,tls-rustls`; extra features can be
  passed as the first argument.
- The image is `gcr.io/distroless/static-debian12:nonroot` with the binary and
  `/etc/ssh-casign/config.toml` (`CONFIG`), running as a non-root user. Without
  `CONFIG`, set `SSH_CASIGN_CONFIG_TOML`.

Google Cloud resources
----------------------

```sh
PROJECT=my-project; REGION=europe-west1
REPO=$REGION-docker.pkg.dev/$PROJECT/ssh-casign

# CA keys: one algorithm per key version
gcloud kms keyrings create ssh --location $REGION
gcloud kms keys create ca-ed25519 --keyring ssh --location $REGION \
  --purpose asymmetric-signing --default-algorithm ec-sign-ed25519
# for old systems that need ssh-rsa (SHA-1): a raw PKCS#1 key, see docs/backends.md
gcloud kms keys create ca-rsa-raw --keyring ssh --location $REGION \
  --purpose asymmetric-signing --default-algorithm rsa-sign-raw-pkcs1-3072

# Service account with only signing rights on these keys
gcloud iam service-accounts create ssh-casign
for key in ca-ed25519 ca-rsa-raw; do
  gcloud kms keys add-iam-policy-binding $key --keyring ssh --location $REGION \
    --member serviceAccount:ssh-casign@$PROJECT.iam.gserviceaccount.com \
    --role roles/cloudkms.signerVerifier
done

# Image and service (public: the service does its own OIDC authentication)
gcloud artifacts repositories create ssh-casign --repository-format docker --location $REGION
docker tag ssh-casign-cloud-run:latest $REPO/ssh-casign:1 && docker push $REPO/ssh-casign:1
gcloud run deploy ssh-casign --image $REPO/ssh-casign:1 --region $REGION \
  --service-account ssh-casign@$PROJECT.iam.gserviceaccount.com --allow-unauthenticated
```

`roles/cloudkms.signerVerifier` covers signing and reading the public key; a custom role
with `cloudkms.cryptoKeyVersions.useToSign` and `cloudkms.cryptoKeyVersions.viewPublicKey`
is narrower.

Configuration
-------------

```toml
server_id = "gcp-euw1"     # set it: instances are anonymous

[oidc_provider]
issuer = "https://idp.example.com"
client_id = "ssh-casign"
scopes = ["openid", "profile", "offline_access"]

[profiles.default]
ssh_ca = ["gcp-ed25519"]
validity = 3600
principals = ["{{claim:preferred_username}}"]
allowed_principals = ["{{claim:preferred_username}}"]

[authorities.gcp-ed25519]
provider = "gcp_kms"
key_version = "projects/my-project/locations/europe-west1/keyRings/ssh/cryptoKeys/ca-ed25519/cryptoKeyVersions/1"
cert_types = ["user"]

[audit]
client_address_header = "x-forwarded-for"
trusted_proxies = ["0.0.0.0/0", "::/0"]  # Google's front end; only it reaches the service
# client_address_skip = 1   # behind an external Application Load Balancer

[[audit.sink]]
type = "stdout"
```

- **Credentials**: the service account through the metadata server; elsewhere a key
  file (`credentials_file` or `GOOGLE_APPLICATION_CREDENTIALS`) or `gcloud auth
  application-default login`.
- **Key versions** are named explicitly; Cloud KMS asymmetric keys have no primary
  version. To rotate, add a version, trust its public key on servers, then switch
  `key_version` (or list both as authorities, the new one first).
- **Client address**: Cloud Run adds the caller's address at the end of
  `X-Forwarded-For` (as observed; Google doesn't document Cloud Run's format
  explicitly). Behind an external Application Load Balancer the header ends with
  `<client>,<load balancer>`, so set `client_address_skip = 1` there.

Audit log
---------

Cloud Run sends each line on stdout and stderr to Cloud Logging. The `stdout` sink's CEF
lines are audit records; route them with a log sink filtered on
`textPayload =~ "^CEF:0\\|"` (to BigQuery, Cloud Storage with a retention lock, or
Pub/Sub for a SIEM).

Local test
----------

```sh
ARCH=arm64 deploy/gcp-cloud-run/build.sh       # native on an ARM machine
docker run --rm -p 8080:8080 -e PORT=8080 \
  -e GOOGLE_APPLICATION_CREDENTIALS=/key.json -v "$PWD/key.json:/key.json:ro" \
  -e SSH_CASIGN_CONFIG_TOML="$(cat config.toml)" ssh-casign-cloud-run:latest
```

Google has no Cloud KMS emulator. The backend was tested against a mock of the Cloud KMS
REST API, the metadata server and the token endpoint, written from Google's
documentation (`publicKey`, `asymmetricSign` with `digest` and `data`, raw PKCS#1
padding, service account JWTs), and with `sshd`. Not yet against Google's own service.
