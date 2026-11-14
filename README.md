ssh-casign
==========

An SSH certificate authority that issues short-lived SSH certificates to users who have
authenticated with an OpenID Connect (OIDC) identity provider.

The user runs a client. The client authenticates the user against the IdP (the device
flow, or the authorization code flow in a browser) and sends the user's SSH public key
together with the token to the signing service. The service validates the token, maps
the token's claims to a certificate profile and returns a signed certificate. The client
writes the certificate to disk or loads it into `ssh-agent`.

> Status: experimental. Sign-in (device flow and browser), certificate issuance,
> `ssh-agent` loading and `sshd` login work end to end against Dex. See
> [docs/status.md](docs/status.md).

Workspace layout
----------------

| Path                  | Contents                                                      |
|-----------------------|---------------------------------------------------------------|
| `ssh-casign-service/` | HTTP signing service (axum): token validation, profiles, CAs  |
| `ssh-casign-client/`  | CLI client (clap): discovery, sign-in selection, sign request |
| `ssh-casign-proto/`   | Wire types shared by service and client                       |
| `poc/`                | Mock IdP, test CA key, sample config and a curl test script   |

Flow
----

```text
 ssh-casign-client                 OIDC IdP                  ssh-casign-service
 -----------------                 --------                  ------------------
 0. GET /.well-known/ssh-casign  ------------------------------------------>
    <---------------------------  issuer, client_id, scopes, sign endpoint, CAs
 1. device flow, or
    authorization code + PKCE  -->
                               <-- 2. token (JWT)
 3. POST /sign  { public_key, cert_type }
    Authorization: Bearer <token>  ---------------------------------------->
                                                             4. validate JWT (JWKS,
                                                                exp, nbf, iss, aud)
                                                             5. pick profile from claims
                                                             6. build options, sign
    <------------------------------------------------------ 7. { "certificate": ... }
 8. write <key>-cert.pub (later: add to ssh-agent)
```

Service
-------

### HTTP API

`GET /.well-known/ssh-casign` returns the discovery document. With it, a client needs
only the service URL:

```json
{
  "issuer": "https://idp.example.com/realms/ssh",
  "client_id": "ssh-casign",
  "scopes": ["openid", "profile"],
  "sign_endpoint": "../sign",
  "authorities": {
    "default": { "public_key": "ssh-ed25519 AAAA...", "cert_types": ["user"] }
  }
}
```

`sign_endpoint` is relative to the discovery document's URL. It therefore still resolves
correctly when the service is published under a path prefix. `authorities` lists the CA
public keys, for `TrustedUserCAKeys` on servers or `@cert-authority` lines in
`known_hosts`.

`POST /sign`, with header `Authorization: Bearer <JWT>`:

```json
{ "cert_type": "user", "public_key": "ssh-ed25519 AAAA... comment" }
```

Optional requested values: `validity` (seconds), `principals` (list), `extensions` and
`critical_options` (maps of name → value), `app_name`, `comment`.

Response on success (`200`):

```json
{ "certificate": "ssh-ed25519-cert-v01@openssh.com AAAA..." }
```

| Status | Meaning                                                                 |
|-------:|-------------------------------------------------------------------------|
|    400 | Request body is not a valid OpenSSH public key                          |
|    401 | Token missing or invalid (`WWW-Authenticate: Bearer error=...`)         |
|    403 | No profile matched, request outside the policy limits, or no principals |
|    500 | CA from the profile is not configured, or signing failed                |
|    501 | Host certificate requested (not supported yet)                          |

Error bodies are `{ "error": "<message>" }`. A 401 has no body; the reason is in the
`WWW-Authenticate` header.

### Token validation

The token must be a JWT signed by a key in the IdP's JWKS. It must contain `exp`, `iss`
and `aud`. `iss` must equal `oidc_provider.issuer`, and `aud` must contain one of
`oidc_provider.audience` (default: the `client_id`, which is what ID tokens carry).
`nbf` is checked when present.

### Certificate policy

Each value (validity, principals, extensions, critical options, comment) is
taken from the client's request, else the token's claims, else the profile. The token
and the profile can both set limits (`min_*`/`max_*`, `required_*`/`allowed_*`,
`matching_*`), and both always apply. A request that breaks a limit is rejected; defaults
are fitted to the limits. See [docs/policy.md](docs/policy.md) for the full rules.

### Key ID

The service builds the key ID from the profile's `key_id` template. The default is
`{{server_id}}:{{profile}}:{{oidc_id}}:{{app_name}}`, for example
`ca1:ops:alice@example.com:ansible`. It records which service instance issued the
certificate, under which profile, for which IdP identity, and for which client workload.
See [docs/policy.md](docs/policy.md#key-id).

### Audit log

Every issued certificate and every denied request of an authenticated client is
recorded in Common Event Format (CEF), to a file, stdout (for AWS Lambda, Azure
Functions, GCP), and/or syslog (local socket, TCP or UDP). A certificate is only
returned once its record has been written. See [docs/audit.md](docs/audit.md).

### Configuration

The service reads the file named by its first argument, or by `SSH_CASIGN_CONFIG`, or
`./config.toml`. Unknown keys are an error. Set log verbosity with `RUST_LOG` (default
`info`).

```toml
server_id = "ca1"                            # in key IDs; default: hostname
listen = "0.0.0.0:3000"                      # default

[oidc_provider]
issuer = "https://idp.example.com/realms/ssh" # must equal the tokens' `iss`
client_id = "ssh-casign"                      # public client the CLI signs in as
scopes = ["openid", "profile"]                # default ["openid"]
# audience = ["ssh-casign"]                   # accepted `aud`; default [client_id]
id_claim = "sub"                              # unique, traceable ID for the key ID

# Profile selectors: the first match wins. A selector matches when the claim is
# a string equal to `value` or an array that contains `value`.
[[profiles.map]]
name = "ops"                   # used in the key ID; default "roles=ops"
claim = "roles"
value = "ops"
settings = { ssh_ca = "default", validity = 3600, max_validity = 86400 }

# Used when no selector matches. Without it, unmatched users get a 403.
# Any key from docs/policy.md can be used here (defaults and limits).
[profiles.default]
ssh_ca = "default"
# key_id = "{{server_id}}:{{profile}}:{{oidc_id}}:{{app_name}}"   # default
validity = 300                 # default, unless the client or token says otherwise
max_validity = 28800
comment = "default profile"
matching_principals = "[a-z][a-z0-9_-]*"
required_extensions = ["permit-pty"]

# Named signing authorities, referenced by `ssh_ca` in a profile.
[authorities.default]
provider = "file"              # only provider so far: OpenSSH private key on disk
private_key_file = "ssh-ca"
cert_types = ["user"]          # "user" and/or "host"

# Audit log (CEF), see docs/audit.md.
[audit]
[[audit.sink]]
type = "file"
path = "/var/log/ssh-casign/audit.cef"
```

The service logs to stderr; stdout is reserved for the audit log's `stdout` sink.

Client
------

```text
ssh-casign-client [OPTIONS] login [-k KEY] [--new] [--min-remaining DURATION] [REQUEST OPTIONS]
ssh-casign-client [OPTIONS] logout [--keep-agent]
ssh-casign-client [OPTIONS] cert [-t user|host] [-o FILE] [REQUEST OPTIONS] [PUBLIC_KEY_FILE]
```

`login` signs in and loads a certificate into `ssh-agent` (`$SSH_AUTH_SOCK`). The
agent forgets the key when the certificate expires, so there is nothing to clean up:

- Without `-k`, a new Ed25519 key is generated in memory and added to the agent with its
  certificate. The private key never touches the disk.
- With `-k ~/.ssh/id_ed25519`, the existing key is used: `id_ed25519.pub` is signed,
  the certificate is written to `id_ed25519-cert.pub`, and `ssh-add -t <lifetime>` loads
  both (and asks for the passphrase if the key has one).

```sh
$ ssh-casign-client login -I laptop
Added certificate to ssh-agent
  key ID:     ca1:default:alice@example.com:laptop
  principals: alice
  expires in: 1h00m

$ ssh-casign-client login -I laptop        # again: no sign-in needed
Reusing certificate in ssh-agent
  ...
```

`login` reuses a still-valid certificate instead of signing in again when:

- it was signed by one of the service's authorities (from the discovery document);
- it has at least `--min-remaining` left (default: 5 minutes, or half the certificate's
  validity if that is shorter);
- the request is plain: no `-V`, `-n`, `--extension`, `--critical-option` or `-C`
  (those always get a new certificate);
- without `-k`: it was added by `login` for the same application name (`-I`). The agent
  comment records it: `ssh-casign:<app_name> <key_id>`.
- with `-k KEY`: `KEY-cert.pub` is used. If the agent no longer holds it, it is loaded
  again with `ssh-add`, still without signing in.

`--new` always signs in. When `login` adds a new in-memory key, it removes the keys it
added earlier for the same application name, so the agent doesn't collect keys (servers
give up after `MaxAuthTries` attempts).

`logout` forgets the cached sign-in (see below) and removes the keys `login` added to
the agent for this service; `--keep-agent` only forgets the sign-in.

`cert` only requests a certificate for a public key and writes it out.

### Staying signed in

When the IdP returns a refresh token, the client stores it, and the next `cert` or
`login` that needs a new certificate uses it instead of the browser or device flow.
Rotated refresh tokens replace the stored one. If the IdP rejects the refresh token, or
the service rejects the refreshed token, the client forgets it and signs in normally.

Most IdPs only issue refresh tokens for the `offline_access` scope; add it to
`oidc_provider.scopes` in the service config (or `scopes` in a client profile).

| `token_store` | Where                                                                                                          |
|---------------|----------------------------------------------------------------------------------------------------------------|
| `keyring`     | OS credential store: macOS Keychain, Windows Credential Manager, Linux kernel keyring (until logout or reboot) |
| `file`        | `refresh-tokens.json` in the cache directory, readable only by the user                                        |
| `none`        | not stored; every new certificate needs a sign-in                                                              |

Tokens are stored per IdP issuer and client ID, so profiles on the same IdP share the
sign-in. Set `token_store` at the top of the client config or per profile.

### Platforms

The client runs on Linux, macOS and Windows. On Windows, `login` talks to the OpenSSH
agent's named pipe (`\\.\pipe\openssh-ssh-agent`, or the pipe in `SSH_AUTH_SOCK`), and the
browser is opened through the shell's URL handler. TLS uses each platform's own TLS
stack and certificate store, so internal CAs that the OS trusts work.

Request options; anything not requested falls back to the token's and then the
profile's defaults:

| Option                         | Requests                                        |
|--------------------------------|-------------------------------------------------|
| `-V, --validity DURATION`      | validity: `300`, `30m`, `8h`, `1d`, `1h30m`     |
| `-n, --principal NAME[,NAME]`  | principals (repeatable)                         |
| `--extension NAME[=VALUE]`     | extensions, replacing the defaults (repeatable) |
| `--no-extensions`              | no extensions (required ones are still added)   |
| `--critical-option NAME=VALUE` | critical options, replacing the defaults        |
| `--no-critical-options`        | no critical options (except required ones)      |
| `-I, --app-name NAME`          | workload name for the key ID (see below)        |
| `-C, --comment TEXT`           | comment                                         |

Global options:

| Option              | Environment              | Meaning                                       |
|---------------------|--------------------------|-----------------------------------------------|
| `-f, --config-file` | `SSH_CASIGN_CONFIG`      | Config file                                   |
| `-p, --profile`     | `SSH_CASIGN_PROFILE`     | Profile from the config file                  |
| `-u, --url`         | `SSH_CASIGN_URL`         | Service base URL; overrides the profile's URL |
| `--sign-in`         | `SSH_CASIGN_SIGN_IN`     | `device` or `authorization-code` (`browser`)  |
| `--token-store`     | `SSH_CASIGN_TOKEN_STORE` | `keyring` (default), `file` or `none`         |
|                     | `SSH_CASIGN_CACHE_DIR`   | Directory for the `file` token store          |
|                     | `SSH_CASIGN_TOKEN`       | Use this bearer token, skip sign-in (testing) |
|                     | `RUST_LOG`               | Log verbosity (default `warn`)                |

`cert` reads the public key from `PUBLIC_KEY_FILE`, or from stdin when that is omitted or
`-`. It writes the certificate to `-o FILE`. Without `-o`, it follows OpenSSH's naming
convention (`id_ed25519.pub` → `id_ed25519-cert.pub`), or writes to stdout when the key
came from stdin.

### Configuration

The default config file is `<config dir>/ssh-casign-client/config.toml`. On macOS that is
`~/Library/Application Support/ssh-casign-client/config.toml`. The file is optional when
`--url` is given.

```toml
default_profile = "default"    # default
sign_in = "device"             # default for all profiles; "device" if omitted
app_name = "laptop"            # default for all profiles; "ssh-casign-client" if omitted
token_store = "keyring"        # where refresh tokens are kept: keyring, file or none

[profiles.default]
url = "https://ssh-ca.example.com/"

[profiles.workstation]
url = "https://ssh-ca.example.com/"
sign_in = "authorization-code"   # this profile prefers the browser
app_name = "workstation"
# client_id = "..."              # override what the service publishes
# scopes = ["openid", "groups"]
```

The application name (`-I`) goes into the certificate's key ID, so concurrent workloads
(ssh, ansible, terraform, vs code, ...) can be told apart. It is chosen in this order:
`--app-name` / `SSH_CASIGN_APP_NAME`, then the profile's `app_name`, then the top-level
`app_name`, then `ssh-casign-client`.

- **`device`**: the client prints a URL and a code on stderr. Open the URL on any device,
  enter the code and sign in; the client continues once the sign-in is approved.
- **`authorization-code`** (`browser`): the client opens the IdP's sign-in page in a
  browser on this machine (`$BROWSER`, else `open`/`xdg-open`) and also prints the URL.
  It uses PKCE and receives the code on `http://localhost:<random port>/callback`,
  listening on both `127.0.0.1` and `[::1]`. Register the client at the IdP as a public
  client that allows loopback redirects. The client waits up to five minutes.

Both send the ID token to the service when the IdP returns one, otherwise the access
token.

The sign-in method is chosen in this order: `--sign-in` / `SSH_CASIGN_SIGN_IN`, then the
profile's `sign_in`, then the top-level `sign_in`, then `device`. The client checks that
the IdP advertises the endpoint for the chosen method, and otherwise suggests the other
one.

Local testing with the PoC
--------------------------

The PoC has two test IdPs:

| IdP                                                                | Use for                         | Service config        |
|--------------------------------------------------------------------|---------------------------------|-----------------------|
| [Dex](https://dexidp.io/)                                          | the device flow, real sign-in   | `poc/config-dex.toml` |
| [mock-oauth2-server](https://github.com/navikt/mock-oauth2-server) | tokens with custom (SSH) claims | `poc/config.toml`     |

### Sign-in with Dex

Dex runs on port 5557 with the test users `user1@example.com` and `user2@example.com`,
both with password `password`. The profile in `config-dex.toml` gives each user their
own username as principal through a claim template.

```sh
# all at once: Dex, service, login into a separate ssh-agent, and an ssh login
# into a throwaway sshd on 127.0.0.1:2222 (needs cargo build --workspace first)
poc/e2e-login.sh

# or by hand; terminal 1: Dex on :5557 (docker or podman)
poc/dex/run.sh

# terminal 2: signing service on 127.0.0.1:3000
cd poc && cargo run -p ssh-casign-service -- config-dex.toml

# terminal 3: sign in with the device flow and get a certificate
cargo run -p ssh-casign-client -- -u http://127.0.0.1:3000 cert ~/.ssh/id_ed25519.pub
#   follow the printed link and log in, or approve without a browser:
#   poc/dex/approve.sh <CODE>
ssh-keygen -L -f ~/.ssh/id_ed25519-cert.pub

# or with the browser flow (drop BROWSER=... to use your real browser)
BROWSER=poc/dex/browser.sh DEX_LOGIN=user2@example.com \
  cargo run -p ssh-casign-client -- -u http://127.0.0.1:3000 --sign-in browser \
  cert -n user2-admin ~/.ssh/id_ed25519.pub
```

### Custom claims with mock-oauth2-server

The mock issues tokens with SSH claims (principals, limits, `upn`) for the fake user
`user1`. It has no device flow, so pass its token with `SSH_CASIGN_TOKEN`.

```sh
# terminal 1: mock IdP on :8080 (run.sh uses docker; podman works the same)
poc/mock-oidc-server/run.sh

# terminal 2: signing service on 127.0.0.1:3000
cd poc && cargo run -p ssh-casign-service

# terminal 3: request a certificate with a token from the mock IdP (skips sign-in)
cd poc
SSH_CASIGN_TOKEN="$(mock-oidc-server/get_token.sh)" \
  cargo run -p ssh-casign-client -- -u http://127.0.0.1:3000 cert ~/.ssh/id_ed25519.pub
ssh-keygen -L -f ~/.ssh/id_ed25519-cert.pub

# or without the client
./test_client_flow.sh "$(cat ~/.ssh/id_ed25519.pub)" > cert && ssh-keygen -L -f cert
```
