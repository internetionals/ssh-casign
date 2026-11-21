Project status
==============

Snapshot of 2026-11-15 (commit `9c6e7d0`).

Status per area
---------------

Legend: ✅ done · 🟡 partial · ❌ not started.

### Signing service

| Area                                   | State | Notes                                                  |
|----------------------------------------|:-----:|--------------------------------------------------------|
| HTTP API                               |  ✅   | `/sign`, `/revoke`, `/certificates`, KRL; JSON errors  |
| Discovery endpoint                     |  ✅   | issuer, endpoints, CA keys, signed trust statement     |
| Token validation                       |  ✅   | JWKS signature, `exp`, `nbf`; `iss` and `aud` required |
| Several issuers                        |  ✅   | `[issuers.<name>]` for machines; routed by `iss`       |
| Claims → profile selection             |  🟡   | issuer, cert type, one `claim == value`; first match   |
| Certificate policy (defaults + limits) |  ✅   | request → token → profile; both limit (policy.md)      |
| User certificates                      |  ✅   | ssh-keygen's default extensions                        |
| Host certificates                      |  ✅   | machine, admin and orchestrator routes (hosts.md)      |
| Key ID template, serial numbers        |  ✅   | server:profile:oidc id:app name; random 64-bit         |
| CA key backends                        |  ✅   | file, pkcs11, vault, Azure, AWS, GCP, Barbican         |
| Backend authentication                 |  ✅   | Vault k8s/JWT/AppRole; AWS, Azure, GCP chains          |
| Several CAs per profile, algorithms    |  ✅   | selected by accepted algorithms; ssh-rsa opt-in        |
| Client key limits, weak keys           |  ✅   | types, RSA size, ROCA, Fermat, blocklists              |
| Audit log                              |  ✅   | CEF to file/stdout/syslog; fail closed (audit.md)      |
| Behind proxies and CDNs                |  ✅   | `trusted_proxies`, XFF/RFC 7239/CF headers, `CF-Ray`   |
| Revocation                             |  ✅   | file and API → signed KRL (revocation.md)              |
| Shared storage, issuance index         |  ✅   | optional; file, S3, GCS, Azure Blob                    |
| Signed trust statement, pinning        |  ✅   | automatic or offline trust keys, k of n (trust.md)     |
| Serverless packages                    |  ✅   | Azure Functions, AWS Lambda, Google Cloud Run          |
| Config and secrets                     |  ✅   | file or `SSH_CASIGN_CONFIG_TOML`; secrets from files   |
| TLS termination in the service         |  ❌   | run behind a TLS-terminating proxy for now             |
| Health endpoint                        |  ❌   | no `/healthz` (discovery works as a probe)             |
| Automated tests                        |  ✅   | unit tests; tests/e2e suite; Woodpecker CI             |

### Client

| Area                                | State | Notes                                                 |
|-------------------------------------|:-----:|-------------------------------------------------------|
| `cert`, config file, named profiles |  ✅   | service URL is enough; everything else discovered     |
| Interactive sign-in                 |  ✅   | device flow and authorization code + PKCE (Dex)       |
| Machine sign-in                     |  🟡   | client credentials, token file tested; others not run |
| Refresh token caching, `logout`     |  ✅   | keyring, file or none                                 |
| `login` with `ssh-agent`            |  ✅   | in-memory Ed25519 key or existing key; reuse          |
| `host` (host certificate renewal)   |  ✅   | renews when due; `--on-change`                        |
| `ca-keys`, `krl`, `trust`           |  ✅   | pinned trust statement; files updated on change       |
| `revoke`, `certificates`            |  ✅   | possession, own certificates, admin search            |
| Platforms                           |  🟡   | Linux, macOS; Windows compiles but hasn't run         |

Outstanding
-----------

Ordered by impact. "Tested" in the docs means against emulators, mocks or local servers
unless it says otherwise.

### 1. Nothing has run against the real services

Every cloud and OpenStack integration was built from the providers' documentation and
tested against emulators or mocks of my own:

| Integration                             | Tested against                                      |
|-----------------------------------------|-----------------------------------------------------|
| AWS KMS, S3 store, Lambda               | LocalStack 4.0.3, the Lambda RIE; SigV4 vs botocore |
| Azure Key Vault, Functions              | Lowkey Vault, the Functions host image              |
| Azure Blob store                        | Azurite 3.35.0, Shared Key only (no Entra ID)       |
| Google Cloud KMS, Cloud Run, federation | a mock of the REST APIs, STS and IAM credentials    |
| GCS store                               | fake-gcs-server 1.54.0                              |
| OpenStack Barbican, Keystone            | a mock of both APIs                                 |
| Vault/OpenBao Kubernetes auth           | OpenBao 2.1.0 with a stand-in TokenReview API       |
| Machine sign-in on GCP, Azure, GitHub   | not run at all                                      |
| EKS Pod Identity                        | a stand-in agent in a unit test                     |

A round of tests on the real platforms (one per cloud is enough to start) is the most
valuable next step: emulators accept things the real services may not (LocalStack
doesn't check SigV4 signatures, for example).

### 2. CI hasn't run on a Woodpecker server yet

The end-to-end suite is in the repository ([tests/e2e](../tests/e2e/README.md)): 19
scenarios in three tiers, against Dex, a mock IdP, OpenBao, LocalStack, Azurite,
fake-gcs-server, Lowkey Vault, SoftHSM, the mocks and `sshd`, run with one command
(`tests/e2e/run.sh`). `ci/check.sh` runs the static checks and unit tests.

- The workflows in `.woodpecker/` (`check`, then `e2e`) pass in full with
  `ci/woodpecker-local.sh` (`woodpecker-cli exec` on podman): all checks, 16
  scenarios, 213 checks. They haven't run on a Woodpecker server and agent yet, nor
  on the Kubernetes backend (services as Kubernetes Services).
- On podman, Woodpecker reports the services as failed at teardown ("no such
  container", [woodpecker#7472](https://github.com/woodpecker-ci/woodpecker/issues/7472),
  fix in PR #7535). That is harmless as long as service failures are ignored, which
  is the default; Woodpecker 4.0 wants to remove that option, and then every run on
  podman would fail. Before upgrading, pin a release that has the fix.
- The `packages` tier (container images, podman secrets) runs locally only; CI would
  need a runner that may start containers.
- The client's Windows build is only checked (`cargo check`), not tested on Windows.

### 3. Service operations

- **TLS in the service.** It speaks plain HTTP and must run behind a TLS proxy, a tunnel,
  or a platform front end. TLS for syslog over TCP is missing too.
- **No `/healthz`.** The discovery endpoint works as a liveness probe, but there is no
  readiness check of the IdP, the backends and the store.
- **Rate limiting** on `/sign` and `/revoke` is left to a proxy or CDN.
- **Clock skew.** `valid_after` is the current time; a server whose clock is a little
  behind rejects a fresh certificate. Back-dating by about 60 seconds is common.

### 4. Policy and identity

- **One claim per profile selector.** Several claims at once (GitHub's `repository`
  and `ref`, say) would make machine profiles tighter.
- **Audience.** When an IdP puts the `client_id` in `aud` of every token it issues to that
  client, the service can't tell a token meant for it from one meant for something else
  of the same client. Use a dedicated client or a dedicated `audience`.
- **Default RSA minimum** is 2048 bits; 3072 is the more future-proof default.
- **Claim templates** only cover principals; comments and `matching_*` patterns built from
  claims would be the same mechanism.

### 5. Backends and credentials

- **Vault/OpenBao:** cloud IAM logins (the `aws`, `gcp` and `azure` auth methods) are not
  implemented; Kubernetes, JWT, AppRole and tokens are.
- **AWS:** SSO and role-chaining profiles aren't supported.
- **GCP federation:** the AWS and executable credential sources aren't supported; token
  files and URLs are.
- **Barbican:** no `clouds.yaml`; configuration and `OS_*` variables only. The key is in
  memory while the service runs (inherent to Barbican, which doesn't sign).
- **Key rotation** in Vault, Barbican and the KMS backends needs a service restart (the
  key or version is fixed at startup, so the advertised key matches the signatures).

### 6. Revocation, trust and key checks

- **Revocation API:** Entra ID authentication for the Azure Blob store is untested.
  Administrator searches read every unexpired index entry, which is fine for
  investigations but not for routine use at scale.
- **`ca-keys`** writes whole files; it can't manage a marked block inside an existing
  `known_hosts`, and it takes one service URL (servers trusting several independent
  services need one run per service).
- **`login`** could keep the `@cert-authority` lines in the user's own `known_hosts` up to
  date (opt-in).
- **Weak keys:** not tested with real ROCA keys or Debian's actual blocklist files; there
  is no import tool for the badkeys project's data.
- **Host certificates** refuse wildcard principals; whether to allow them (OpenSSH
  supports them) is undecided.

### 7. Client

- **Windows** support (named-pipe agent, browser launch) compiles but hasn't run on
  Windows.
- **Linux keyring:** the kernel keyring doesn't survive a reboot; a Secret Service
  backend (GNOME Keyring, KWallet) would, but needs D-Bus.
- **Shared agents:** `login` reuses a certificate from the agent without checking whose
  it is; on a shared agent a second user could get the first user's certificate.
- **`login` keys** are Ed25519 only; an RSA option would help with old servers (an RSA
  key generated in memory).
- **Loopback redirect** uses `localhost`, not the `127.0.0.1` RFC 8252 prefers (Dex and
  Azure need `localhost`); a profile option could switch it.
- **The client enables ssh-key's `dsa` feature,** which it doesn't need.
- **Discovery** could hint which sign-in methods the IdP client allows.

### 8. Code

- `CertificateOptions` has public fields and also getters and setters. Choose one style.

History
-------

Fixed or built since the first analysis, in order: audience and issuer checks, policy
defaults and limits, the discovery endpoint, both interactive sign-in flows,
`ssh-agent` integration and `login`, serials and claim templates, refresh tokens, the
audit log, several CAs per profile and CA signature algorithms, the CA backends and
serverless packages, the crate split, proxy support, host certificates, revocation (file,
then API with shared storage), the signed trust statement, weak key checks, Vault and
GCP federation logins, and Barbican.

Two upstream problems are worked around: ssh-key 0.6.7 converts RSA keys for the `rsa`
crate with the prime `p` twice (the service uses its own conversion,
`ssh-casign-ca/src/encoding.rs`), and ssh-key can't represent `ssh-rsa` (SHA-1)
signatures (those certificates are encoded by hand, and the client keeps certificates
as the bytes it received).
