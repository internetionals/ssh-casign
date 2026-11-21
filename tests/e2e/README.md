End-to-end tests
================

The real service and client, against real or emulated identity providers, key stores
and storage, and a real `sshd`. Every scenario asserts its results; the suite reports
passed and failed checks per scenario.

Running
-------

```sh
tests/e2e/run.sh                      # the core and backends tiers
tests/e2e/run.sh login trust          # some scenarios (by name)
tests/e2e/run.sh --tier core          # one tier
tests/e2e/run.sh --tier packages      # container images and podman secrets
E2E_KEEP=1 tests/e2e/run.sh hosts     # keep the scratch directory of a failed scenario
```

`run.sh` needs podman (or docker, with `CONTAINER_RUNTIME=docker`). It creates a
network `ssh-casign-e2e`, starts the dependencies the selected scenarios need under
their names, and runs the suite in a runner image (Rust, OpenSSH, SoftHSM, Python with
`cryptography`), built from `Containerfile`. The cargo registry and build output are
kept in the volumes `ssh-casign-e2e-cargo` and `ssh-casign-e2e-target`, so later runs
only build what changed.

The `packages` tier runs on the host, because it builds images and starts containers
itself: it needs podman and a host Rust toolchain.

Tiers and scenarios
-------------------

| Tier       | Scenario          | What                                                             |
|------------|-------------------|------------------------------------------------------------------|
| `core`     | `certificates`    | issue, `sshd` login, refusals, caching headers                   |
|            | `login`           | Dex: both sign-in flows, `login`, reuse, refresh tokens          |
|            | `algorithms`      | several CAs per profile, `ssh-rsa` with `sshd`, client key types |
|            | `audit`           | file, stdout and syslog (Unix, UDP, TCP) sinks; failing closed   |
|            | `proxy`           | `trusted_proxies`, `X-Forwarded-For`, CF-Ray                     |
|            | `hosts`           | host certificates for machines, admins, orchestrators            |
|            | `revocation-file` | revocation file, KRL, `ssh-keygen -Q`, `RevokedKeys`             |
|            | `revocation-api`  | the revoke API, issuance index, two instances on one store       |
|            | `trust`           | pinning, forgeries, CA rotation, 2-of-3 trust keys               |
|            | `weak-keys`       | ROCA, Fermat, low-order points, blocklists, shared keys, CA keys |
| `backends` | `vault`           | OpenBao transit; Kubernetes, JWT and AppRole logins              |
|            | `pkcs11`          | SoftHSM: Ed25519, P-256, RSA on a token                          |
|            | `aws`             | KMS (LocalStack) and the S3 store                                |
|            | `azure`           | Key Vault (Lowkey Vault) and Blob storage (Azurite)              |
|            | `gcp`             | Cloud KMS (mock), workload identity federation, the GCS store    |
|            | `barbican`        | Barbican and Keystone (mock)                                     |
| `packages` | `cloud-run`       | the Cloud Run image with podman secrets                          |
|            | `aws-lambda`      | the Lambda image, runtime emulator, Function URL                 |
|            | `azure-functions` | the Functions package in the Functions host image                |

Dependencies
------------

| Name          | Image                                                 | For                       |
|---------------|-------------------------------------------------------|---------------------------|
| `oidc`        | `ghcr.io/navikt/mock-oauth2-server:2.1.10`            | tokens with custom claims |
| `dex`         | `ghcr.io/dexidp/dex:v2.41.1`                          | real sign-in flows        |
| `openbao`     | `docker.io/openbao/openbao:2.1.0`                     | the vault backend         |
| `tokenreview` | `python:3.12.8-slim-bookworm`, `mocks/tokenreview.py` | OpenBao's Kubernetes auth |
| `localstack`  | `docker.io/localstack/localstack:4.0.3`               | KMS, S3                   |
| `azurite`     | `mcr.microsoft.com/azure-storage/azurite:3.35.0`      | Blob storage              |
| `gcs`         | `docker.io/fsouza/fake-gcs-server:1.54.0`             | Cloud Storage             |
| `lowkey`      | `docker.io/nagyesta/lowkey-vault:2.7.1`               | Key Vault                 |

Each scenario declares what it needs in a `# needs:` line; `run.sh` starts exactly
those. Scenarios reach dependencies by name (`http://oidc:8080`, ...); `E2E_OIDC`,
`E2E_DEX`, `E2E_OPENBAO` and the like override the addresses. A scenario whose
dependency doesn't answer is skipped, not failed.

Mocks
-----

Some services have no emulator. The mocks in `mocks/` are written from the providers'
documentation and are test tools only: passing against them is not the same as
passing against the real service.

| Mock                                               | Stands in for                                        |
|----------------------------------------------------|------------------------------------------------------|
| `gcp.py`                                           | Cloud KMS, metadata server, token endpoint, STS, IAM |
| `openstack.py`                                     | Keystone v3 and Barbican                             |
| `tokenreview.py`                                   | the Kubernetes TokenReview API                       |
| `azure_identity.py`                                | the App Service managed identity endpoint            |
| `function_url.py`                                  | a Lambda Function URL (HTTP to payload 2.0 events)   |
| `syslog_receiver.py`, `forward.py`, `weak_keys.py` | helpers                                              |

CI
--

`.woodpecker/` has two workflows: `check.yaml` runs `ci/check.sh` (fmt, clippy for
every feature combination, unit tests, the client's Windows build), then `e2e.yaml`
runs the `core` and `backends` tiers, with the dependencies as Woodpecker services
under the same names. They work on Woodpecker's Docker, podman and Kubernetes
backends. When you change a dependency's image or arguments, change it in both
`run.sh` and `.woodpecker/e2e.yaml`.

`ci/woodpecker-local.sh` runs the workflows with `woodpecker-cli exec` against the
local podman (its Docker-compatible API), without a Woodpecker server, and exits with
the pipeline's status. (`e2e.yaml` depends on `check`, so it doesn't run on its own;
`tests/e2e/run.sh` is the quicker way to run only the suite.) The services and the build together need more than
4 GiB: on macOS, give the podman machine 8 GiB (`podman machine set --memory 8192`).

Any other CI can do the same: start the dependencies by name, run
`tests/e2e/setup-runner.sh` on a `rust:1-bookworm` image, then `tests/e2e/suite.sh`.

Writing a scenario
------------------

```bash
#!/bin/bash
# needs: oidc
# One line on what it covers.
source "$(dirname "$0")/../../lib.sh"
scenario "what it tests"
require oidc "$OIDC/ssh-casign/.well-known/openid-configuration"

mock_config > "$T/service.toml"           # the mock IdP and a file CA in $T/ca
service_start "$T/service.toml" || exit 1
client_config
export SSH_CASIGN_TOKEN="$(mock_token user1)"
ssh-keygen -q -t ed25519 -N '' -f "$T/user"

check      "a step succeeds"       client cert "$T/user.pub"
check_out  "output matches"        'user1' ssh-keygen -L -f "$T/user-cert.pub"
check_has  "contains a fixed text" "$(fingerprint "$T/ca.pub")" ssh-keygen -L -f "$T/user-cert.pub"
check_fail "fails with a message"  'not in allowed_principals' client cert -n root -o - "$T/user.pub"
check_eq   "values are equal"      expected "$(some command)"
sshd_start "$T/ca.pub" user1 || exit 1
check_out  "sshd accepts it"       'logged in as' ssh_login "$T/user"
finish
```

`$T` is a scratch directory, removed at the end. Background processes started with
`background`, services and `sshd` are stopped automatically. `lib.sh` has the
helpers; keep keys generated per run, never committed.
