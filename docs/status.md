Project status
==============

Snapshot of 2026-11-14 (commit `1d40eaa` plus uncommitted work).

Status per area
---------------

Legend: ✅ done · 🟡 partial · ❌ not started.

### Signing service

| Area                                   | State | Notes                                                    |
|----------------------------------------|:-----:|----------------------------------------------------------|
| HTTP endpoint `POST /sign`             |  ✅   | axum, JSON in/out, JSON error bodies                     |
| Discovery endpoint                     |  ✅   | issuer, client ID, scopes, sign endpoint, CA public keys |
| Bearer token extraction                |  ✅   | `Claims<T>` extractor, 401 + `WWW-Authenticate`          |
| JWT validation                         |  ✅   | signature (JWKS), `exp`, `nbf`; `iss` and `aud` required |
| Claims → profile selection             |  🟡   | one `claim == value` per selector; first match wins      |
| Certificate policy (defaults + limits) |  ✅   | request → token → profile; both limit; docs/policy.md    |
| Default user extensions                |  ✅   | ssh-keygen's defaults when no extensions are configured  |
| CA key backends                        |  🟡   | file, pkcs11, vault, Azure, AWS; GCP planned             |
| Several CAs per profile                |  ✅   | ordered; selected by the client's accepted algorithms    |
| CA signature algorithms                |  ✅   | Ed25519, ECDSA, rsa-sha2-512/256, ssh-rsa (opt-in)       |
| Client key type and size limits        |  ✅   | `allowed_key_types`, `min_rsa_bits`, `max_rsa_bits`      |
| File-based CA provider                 |  ✅   | OpenSSH private key, restricts allowed cert types        |
| GCP KMS                                |  ❌   | planned; see docs/backends.md                            |
| Azure Functions                        |  ✅   | custom handler package in deploy/azure-functions         |
| AWS Lambda                             |  ✅   | image with Lambda Web Adapter in deploy/aws-lambda       |
| User certificates                      |  ✅   |                                                          |
| Host certificates                      |  ❌   | refused with 501 until a trust model is designed         |
| Key ID template                        |  ✅   | server:profile:oidc id:app name by default               |
| Audit log                              |  ✅   | CEF to file/stdout/syslog; fail closed (docs/audit.md)   |
| Serial numbers                         |  ✅   | random non-zero 64-bit; `{{serial}}` in key ID templates |
| Config path, listen address            |  ✅   | argument or `SSH_CASIGN_CONFIG`; `listen` in config      |
| Strict config parsing                  |  ✅   | unknown keys are an error                                |
| TLS                                    |  ❌   | run behind a TLS-terminating proxy for now               |
| Tests                                  |  🟡   | unit tests for profile parsing/lookup and the policy     |

### Client

| Area                                   | State | Notes                                                    |
|----------------------------------------|:-----:|----------------------------------------------------------|
| CLI, `cert` subcommand                 |  ✅   | `-t`, `-o`, key from file or stdin, `<key>-cert.pub`     |
| Config file + named profiles           |  ✅   | profile = service URL (+ optional overrides)             |
| `--url` without a config file          |  ✅   |                                                          |
| Service discovery                      |  ✅   | resolves the relative sign endpoint                      |
| Sign-in method selection               |  ✅   | CLI/env > profile > config > `device`                    |
| IdP discovery                          |  ✅   | issuer checked; endpoint for the chosen method required  |
| Device authorization flow              |  ✅   | RFC 8628; tested against Dex                             |
| Authorization code flow + PKCE         |  ✅   | loopback redirect on `localhost`; tested against Dex     |
| Token from environment                 |  ✅   | `SSH_CASIGN_TOKEN`, for testing and automation           |
| Token caching / refresh                |  ✅   | refresh tokens in keyring/file; `logout` forgets them    |
| Platforms                              |  ✅   | Linux (tests in a container), macOS, Windows (compiles)  |
| Sign request with bearer token         |  ✅   | error details from body or `WWW-Authenticate`            |
| Request certificate values             |  ✅   | validity, principals, extensions, app name, ...          |
| Add key + certificate to `ssh-agent`   |  ✅   | `login`: in-memory key, or existing key via `ssh-add`    |
| Reuse still-valid certificates         |  ✅   | same CA, app name, enough validity left; `--new`         |
| Generate a key pair                    |  ✅   | ephemeral Ed25519 for `login`, never written to disk     |
| Tests                                  |  🟡   | option precedence, certificate file naming               |

### PoC

| Area                                   | State | Notes                                                    |
|----------------------------------------|:-----:|----------------------------------------------------------|
| Mock IdP with SSH claims               |  ✅   | mock-oauth2-server, `client_credentials` + `code` hack   |
| curl-based end-to-end script           |  ✅   |                                                          |
| Client end to end                      |  ✅   | device flow with Dex; mock tokens via `SSH_CASIGN_TOKEN` |
| IdP with device flow for testing       |  ✅   | `poc/dex/`, with `approve.sh` for browserless approval   |
| End to end through `sshd`              |  ✅   | `poc/e2e-login.sh`: login, ssh, expiry, wrong principal  |

Known issues
------------

Fixed on 2026-11-14: unchecked `aud`/`iss` (including tokens *without* those claims),
host request panic, missing default extensions, client `.pub` parsing, client argument
order, unauthenticated client requests, PoC config, silently ignored config keys,
malformed `WWW-Authenticate`, missing-principals 401 instead of 403, client error output.

Policy defaults and limits were added on 2026-11-14 (see [policy.md](policy.md)).

The workspace is split into a service binary, `ssh-casign-core` (service logic),
`ssh-casign-ca` (certificates and the backend API) and one crate per backend; see the
README.

Certificates are now encoded by the service itself (byte-identical to ssh-key, which a
test checks); backends only sign bytes, and every certificate is verified before it is
handed out.

Fixed with the signature algorithm work: RSA CAs didn't work at all. ssh-key 0.6.7
converts RSA keys for the `rsa` crate with the prime `p` twice instead of `p` and `q`,
which `rsa` 0.9.10 rejects. All RSA signing now uses our own conversion
(`rsa_private_key` in `ssh-casign-ca/src/encoding.rs`). ssh-key also can't represent
`ssh-rsa` (SHA-1) signatures, so those certificates are encoded by hand, and the client
keeps certificates as the bytes it received (`ssh-casign-client/src/certificate.rs`).

Still open, ordered by impact:

1. **No revocation yet.** The audit log has every certificate (and its serial), which is
   what a KRL (key revocation list) generator needs; generating and distributing one is
   still to do.
2. **No proof that the token was meant for this service** when the IdP puts the
   `client_id` in `aud` for every token issued to that client. Use a dedicated client
   for ssh-casign, or configure a dedicated `audience`.

Suggestions
-----------

### Discovery (done)

The service publishes the issuer, client ID, scopes, sign endpoint and CA public keys at
`/.well-known/ssh-casign`, so client configuration reduces to the service URL. A later
addition could be a hint about which sign-in methods the IdP client allows, so the
client can pick a working default.

### Client authentication

- Both flows are done: [auth/device.rs](../ssh-casign-client/src/auth/device.rs) and
  [auth/authorization_code.rs](../ssh-casign-client/src/auth/authorization_code.rs). The
  browser flow redirects to `localhost` rather than the `127.0.0.1` that RFC 8252
  prefers, because Dex (and Azure's registration) need that form. If an IdP requires the
  IP literal, that could become a client profile option.
- The client sends the ID token when the IdP returns one, else the access token. Many
  IdPs issue opaque access tokens, or access tokens without custom claims; the ID token
  (with `aud = client_id`) is the most portable choice. A JWT access token with a
  dedicated audience is the cleaner choice where the IdP supports it. Either way, the
  service checks the audience.
- Refresh tokens are cached (done; `token_store` in the client config).
- Non-interactive use (CI, host enrollment) could get a separate `client_credentials`
  mode with its own config. For now, `SSH_CASIGN_TOKEN` covers testing.

### Claim mapping (done for principals)

Profiles can derive principals from standard claims with templates (see
[policy.md](policy.md#principal-templates)). The same mechanism could be extended to other
values, for example a `comment` template, or `matching_*` patterns built from claims.

### Certificate hygiene

- Random 64-bit serial numbers, also available in the key ID template.
- Set `valid_after` about 60 seconds in the past to tolerate clock skew.
- Reject weak keys: DSA (the service enables the `dsa` feature) and RSA keys under 3072
  bits. Allow-list the algorithms you accept.
- Write an audit log entry for every issuance: subject, principals, serial, key
  fingerprint, validity, profile.

### Client UX

- `login` is done: in-memory key or existing key, lifetime equal to the certificate, and
  reuse of a still-valid certificate from the same service and application name.
- Refresh tokens are cached (keyring, file or none), so a new certificate needs no
  browser or device code while the IdP session lasts.
- Reuse doesn't look at *who* the certificate is for: on a shared agent, a second user
  running `login` would get the first user's certificate. An agent is normally personal,
  but `login` could check the principals or key ID once it knows the identity.
- Windows support (named-pipe agent, URL handler for the browser) compiles but hasn't
  been run on Windows yet. On Linux, the `keyring` store uses the kernel keyring, which
  doesn't survive a reboot; a Secret Service backend (GNOME Keyring, KWallet) would, but
  needs D-Bus.

### Service operations

- CLI/env for the config path and listen address. Return startup errors instead of
  calling `expect()`.
- Terminate TLS in the service (`axum-server` + rustls), or document that it must run
  behind a TLS proxy.
- `GET /healthz`, request IDs in tracing spans, and rate limiting on `/sign`.
- Host certificates need a different trust model than user OIDC logins: for example
  machine identity, the client credentials grant with a per-host client, or an
  administrator approving the request. Design this separately before building it.

### Code

- `CertificateOptions` has public fields and also getters/setters, and the `impl<'a>`
  lifetime is unnecessary. Choose one style.
- The `Signer` trait uses `async fn` in a trait without a `Send` bound. That works with
  the current enum dispatch. If you later want `dyn` providers, add
  `#[trait_variant::make(Send)]` or return boxed futures.
- Tests: unit tests for `Profiles::lookup` and `CertificateSettings::apply` exist. Next:
  an integration test that runs the service against an in-process JWKS or the mock IdP
  container.

Suggested order of work
-----------------------

1. ~~Small bugs that block end-to-end testing.~~ Done.
2. ~~Audience/issuer validation, policy defaults and limits.~~ Done.
3. ~~Shared proto crate + discovery endpoint.~~ Done.
4. ~~Client: the device flow, then authorization code + PKCE.~~ Done.
5. ~~`ssh-agent` integration and the `login` command.~~ Done.
6. ~~Serials, claim templates for principals, durable audit log~~ (done), TLS,
   integration tests.
7. Host certificates; ~~CA backends file, PKCS#11, Vault, Azure Key Vault, AWS KMS~~
   (done), then GCP KMS (with item 8).
8. Serverless deployment per platform, each with its cloud KMS: ~~Azure Functions with
   Key Vault, AWS Lambda with AWS KMS~~ (done), then Google Cloud Run functions with
   Cloud KMS.
