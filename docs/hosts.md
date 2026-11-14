Host certificates
=================

A host certificate lets `ssh` trust a server's host key because a CA signed it for the
server's names, instead of because someone accepted the key on first connect. Clients
need one `@cert-authority` line in `known_hosts` instead of a key per host.

Who may get one
---------------

A user's sign-in says nothing about which host a public key belongs to, so host
certificates come from profiles that explicitly issue them (`cert_types = ["host"]`),
selected by claims like every profile. Three ways fit this model:

| Route         | Authenticates                        | Host names from                                     |
|---------------|--------------------------------------|-----------------------------------------------------|
| Machine       | the host itself, with its own token  | the token's claims (profile `principals` templates) |
| Administrator | a person, through the user IdP       | the request, limited by `matching_principals`       |
| Orchestrator  | a CMDB or orchestrator, as a machine | the request, limited by `matching_principals`       |

- **Machine**: the host signs in without a person, for example with an OAuth client
  credentials grant (one client per host or host group), its cloud workload identity
  (the GCE metadata server's identity token, an Azure managed identity), a Kubernetes
  service account token or a GitHub Actions token. Its names come from claims the IdP
  vouches for (`hostname`, `google.compute_engine.instance_name`, ...).
- **Administrator**: someone with, say, the `ssh-admin` role signs keys they supply,
  e.g. read with `ssh-keyscan`. Good for switches and appliances that can't run a
  client.
- **Orchestrator**: a provisioning system that already knows which host has which key
  and name signs for the hosts it manages, as one machine identity.

Machine tokens usually come from another issuer than the user IdP. Such issuers are
configured as `[issuers.<name>]`, and only profile selectors that name them match their
tokens. A token from another issuer never falls through to the default profile.

Service configuration
---------------------

```toml
[oidc_provider]                     # people (published in the discovery document)
issuer = "https://idp.example.com"
client_id = "ssh-casign"

[issuers.machines]                  # client credentials at the same or another IdP
issuer = "https://idp.example.com"
audience = ["ssh-casign-hosts"]     # required for every extra issuer
id_claim = "sub"                    # default
# token_policy = false              # default: claims are not read as policy

[issuers.gce]                       # Google Compute Engine identity tokens
issuer = "https://accounts.google.com"
audience = ["https://ssh-ca.example.com"]
id_claim = "google.compute_engine.instance_id"

[authorities.hosts]                 # a separate CA key for hosts
provider = "file"
private_key_file = "/etc/ssh-casign/host-ca"
cert_types = ["host"]

[[profiles.map]]                    # administrators
name = "admin-hosts"
claim = "roles"
value = "ssh-admin"
settings = { ssh_ca = "hosts", cert_types = ["host"], validity = 2592000, matching_principals = "[a-z0-9-]+\\.example\\.com" }

[[profiles.map]]                    # hosts signing their own keys
name = "gce-prod"
issuer = "gce"
claim = "google.compute_engine.project_id"
value = "prod-project"
settings = { ssh_ca = "hosts", cert_types = ["host"], validity = 2592000, principals = ["{{claim:google.compute_engine.instance_name}}.c.prod-project.internal"] }

[[profiles.map]]                    # the CMDB
name = "cmdb"
issuer = "machines"
claim = "sub"
value = "cmdb-service-account-id"
settings = { ssh_ca = "hosts", cert_types = ["host"], validity = 604800, matching_principals = "[a-z0-9-]+\\.prod\\.example\\.com" }
```

- **Issuers**: a token is matched to the issuer configurations with its `iss`, and
  accepted by the first whose signature, `exp`, `nbf` and `aud` checks pass. Several
  configurations may share an issuer URL with different audiences (people and machines
  at the same IdP). The service fetches each issuer's
  `/.well-known/openid-configuration` at startup.
- **`token_policy`**: `[oidc_provider]` reads defaults and limits from token claims
  (`max_validity`, `allowed_principals`, ...); extra issuers don't unless
  `token_policy = true`. Third parties such as GitHub or Google set claims for their own
  purposes, so they must not define certificate policy here.
- **Profiles**: `cert_types` defaults to `["user"]`. A lookup takes the first profile
  that matches the token's issuer and claims *and* issues the requested type, so one role
  can have one profile for user certificates and another for host certificates.
  Selectors without `issuer` only match `[oidc_provider]` tokens.
- **Authorities**: each profile's authorities are filtered by `cert_types`, so a profile
  can't sign a host key with the user CA. The service refuses to start when a profile
  issues a type that none of its authorities signs.
- **Claims**: templates and selectors accept paths into nested claims
  (`google.compute_engine.instance_name`). A top-level claim with exactly that name
  (`https://example.com/roles`) takes precedence.

### What a host certificate may contain

- **Principals** are host names or IP addresses: lowercase `a-z`, digits, `.`, `-`, `_`,
  `:`, at most 253 characters, no wildcards. Names from claims and requests are
  lowercased first, because `ssh` compares host names in lowercase. Write
  `matching_principals` for lowercase names.
- **Requesting names** needs `allowed_principals` or `matching_principals`, as for user
  certificates. Without them, only the profile's `principals` (from claims) are used.
- **No extensions or critical options**: OpenSSH defines none for host certificates.
  Requesting any is refused; `required_extensions` and `required_critical_options` only
  apply to user certificates.
- **Validity**: set `validity` in host profiles. Host certificates are usually
  long-lived (weeks) and renewed by a timer.

Each issued certificate gets an audit record with `sshCertType=host`, the profile and the
principals, like user certificates.

Client
------

### `host`: renew this machine's certificates

```text
ssh-casign-client [-p PROFILE] host [-n NAME[,NAME]] [-V DURATION] [--renew-before DURATION]
                                    [--force] [--on-change COMMAND] [KEY.pub ...]
```

- Without key files, it signs the `ssh_host_{ed25519,ecdsa,rsa}_key.pub` files in
  `/etc/ssh` (`%ProgramData%\ssh` on Windows) that exist. Each certificate goes next to
  its key (`ssh_host_ed25519_key-cert.pub`), written atomically, mode 0644.
- It only signs when a certificate is missing, expires within a third of its lifetime
  (or `--renew-before`), was signed by an authority the service no longer has, or
  doesn't have the names given with `-n`. `--force` always signs. All keys that need it
  are signed with one sign-in.
- `--on-change` runs a command (with `sh -c`, or `cmd /C` on Windows) only when a
  certificate was written. `sshd` reads host certificates at startup and on reload.

A client profile for a host:

```toml
token_store = "none"

[profiles.default]
url = "https://ssh-ca.example.com/"
sign_in = "client-credentials"
issuer = "https://idp.example.com"          # where the machine client lives
client_id = "host-web-1"
client_secret_file = "/etc/ssh-casign/client-secret"
scopes = ["ssh-host"]                       # optional
# audience = "ssh-casign-hosts"             # some IdPs select the API this way
```

Non-interactive sign-in methods (`sign_in`, or `--sign-in`):

| Method                   | Token                               | Profile settings                   |
|--------------------------|-------------------------------------|------------------------------------|
| `client-credentials`     | OAuth 2.0 client credentials grant  | `client_id`, `client_secret_file`  |
| `token-file`             | a file, read on each run            | `token_file`                       |
| `gcp-metadata`           | the GCE/GKE metadata identity token | `audience`                         |
| `azure-managed-identity` | the Azure managed identity's token  | `audience`, `client_id` (optional) |
| `github-actions`         | the GitHub Actions OIDC token       | `audience`                         |

- `client-credentials` authenticates with HTTP Basic at the token endpoint of `issuer`
  (default: the issuer the service publishes), with the profile's `scopes`, and
  `audience` if set (some IdPs select the API that way).
- `token-file` suits Kubernetes projected service account tokens, or any token another
  agent keeps fresh.
- `gcp-metadata` asks for `format=full`, so the token has the `google.compute_engine`
  claims (project, zone, instance).
- `azure-managed-identity` uses IMDS on VMs, or `IDENTITY_ENDPOINT` on App Service,
  Functions and Container Apps; `client_id` picks a user-assigned identity.
- `github-actions` needs `permissions: id-token: write` in the workflow.

`SSH_CASIGN_CLIENT_SECRET` overrides `client_secret_file`. Nothing is cached for these
methods: each run gets a fresh token.

### Administrators and orchestrators

`cert -t host` signs a given key for the requested names:

```sh
ssh-keyscan -t ed25519 switch-1.example.com | cut -d' ' -f2- > switch-1.pub
ssh-casign-client cert -t host -n switch-1.example.com -o switch-1-cert.pub switch-1.pub
```

An orchestrator does the same with a machine profile (`-p cmdb`, `sign_in =
"client-credentials"`) for each host it provisions.

### `ca-keys`: trust the authorities

```sh
# on clients: known_hosts
ssh-casign-client ca-keys --type host --hosts '*.example.com' >> ~/.ssh/known_hosts
# on servers: TrustedUserCAKeys
ssh-casign-client ca-keys --type user > /etc/ssh/trusted-user-ca-keys
```

`--hosts` is a `known_hosts` pattern list (`*.example.com,10.0.0.*`). Keep it as narrow
as the names the host profiles allow.

To withdraw a host certificate before it expires (a decommissioned or compromised
host), revoke it and let clients fetch the KRL for `RevokedHostKeys`; see
[revocation.md](revocation.md).

Setting up a host
-----------------

`/etc/ssh/sshd_config`:

```text
HostCertificate /etc/ssh/ssh_host_ed25519_key-cert.pub
HostCertificate /etc/ssh/ssh_host_rsa_key-cert.pub
```

A systemd timer that checks twice a day:

```ini
# /etc/systemd/system/ssh-casign-host.service
[Unit]
Description=Renew SSH host certificates
After=network-online.target
Wants=network-online.target

[Service]
Type=oneshot
ExecStart=/usr/local/bin/ssh-casign-client -f /etc/ssh-casign/client.toml host --on-change "systemctl reload ssh"

# /etc/systemd/system/ssh-casign-host.timer
[Timer]
OnBootSec=2min
OnUnitActiveSec=12h
RandomizedDelaySec=1h

[Install]
WantedBy=timers.target
```

The service is called `sshd` on some distributions. On a first run the client prints
the `HostCertificate` lines `sshd_config` needs.

Tested
------

End to end with a mock IdP with two issuers and `sshd`:

- a host with a client credentials token at a second issuer, its names from a claim and a
  nested claim (an uppercase name lowercased); a second run kept the certificates and
  didn't run `--on-change`;
- an administrator signing an ECDSA switch key; a CMDB client for `*.prod.example.com`;
- refusals: other names without limits, names outside `matching_principals`, wildcards,
  extensions, a plain user asking for a host certificate, a machine token asking for a
  user certificate;
- `ssh` with `@cert-authority` from `ca-keys` accepted the host and refused a name not in
  the certificate.

The machine sign-in methods `gcp-metadata`, `azure-managed-identity` and
`github-actions` follow the platforms' documentation but haven't run on those platforms
yet.
