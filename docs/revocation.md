Revocation
==========

A certificate is valid until it expires. To withdraw one sooner (a stolen laptop, a
leaked key, a decommissioned host), it goes on the revocation list. The service turns
that list into an OpenSSH KRL (key revocation list), which `sshd` and `ssh` check on
every connection:

| Who checks | Setting                        | Refuses                                  |
|------------|--------------------------------|------------------------------------------|
| `sshd`     | `RevokedKeys` (sshd_config)    | revoked user certificates and keys       |
| `ssh`      | `RevokedHostKeys` (ssh_config) | revoked host certificates and host keys  |
| service    | (always)                       | signing revoked keys and revoked key IDs |

Short-lived user certificates (the default is an hour or less) rarely need revoking:
disabling the account at the IdP stops new ones. Revocation matters for long-lived
certificates, host certificates, and keys that must never be signed again.

What can be revoked
-------------------

| Entry                         | Revokes                                                        |
|-------------------------------|----------------------------------------------------------------|
| `serial` + `authority`        | one certificate (serials are per CA)                           |
| `key_id` (+ `authority`)      | every certificate with that key ID; all authorities by default |
| `fingerprint` or `public_key` | a key: every certificate for it, and the plain key             |

The audit log has what you need for each certificate: `flexString1` (serial), `cs2`
(key ID), `cs4` (authority), `cs6` (the key's fingerprint) and the certificate itself.
`ssh-keygen -L -f cert.pub` shows the serial and key ID of a certificate file, and
`ssh-keygen -l -f key.pub` the fingerprint of a key.

Revoking a key is the strongest: the service refuses to sign it again, and `sshd`
refuses its certificates from every authority. Revoking a key ID stops future
certificates with the same ID as well (the service refuses to issue them). Key IDs
include the profile, the IdP's ID and the application name (`ca1:default:alice:laptop`),
so this withdraws one workload of one user.

The revocation file
-------------------

```toml
[[revoked]]
serial = "16361417745147627987"     # quoted: TOML integers stop at 9223372036854775807
authority = "users"
reason = "laptop stolen"            # reason, revoked_at, revoked_by: for people only
revoked_at = 2026-11-14
revoked_by = "alice@example.com"

[[revoked]]
key_id = "ca1:self-enroll:web-1:ssh-casign-host"
authority = "hosts"
reason = "web-1 decommissioned"

[[revoked]]
fingerprint = "SHA256:fQSj6HaatnBaVv0loaHzLTwGicxkVS55273L8BHQyvI"
reason = "key leaked"
```

Each entry has exactly one of `serial`, `key_id`, `fingerprint` and `public_key`.
Unknown keys and unknown authority names are errors. Keep the file in version control:
changes are reviewed like the rest of the configuration, and the history shows who
revoked what.

Service configuration:

```toml
[revocation]
file = "/etc/ssh-casign/revocations.toml"
reload_interval = 60                # seconds between checks for changes; 0: never

# Entries can also be inline, e.g. with SSH_CASIGN_CONFIG_TOML on serverless platforms:
# [[revocation.revoked]]
# fingerprint = "SHA256:..."
```

- At startup, an invalid list stops the service.
- Afterwards the file is checked for changes every `reload_interval`. An invalid new
  version is logged once as an error, and the previous list stays in force until the
  file is fixed. Watch for that error: new revocations don't apply until then.
- On serverless platforms the file is part of the image or the configuration, so a
  revocation is a deploy; new instances start with it.
- Without `[revocation]`, the KRL is empty. Servers can point `RevokedKeys` at it from
  the start.

The KRL
-------

`GET /revoked.krl` serves the KRL (`application/octet-stream`). It has an `ETag`;
`If-None-Match` gets a 304 when nothing changed. It may be cached for five minutes. The
discovery document links to it (`revocation_list`). The KRL is not secret.

The KRL has one certificate section per authority with revocations (serials and key
IDs) and a SHA-256 fingerprint section for revoked keys (OpenSSH 7.9 and newer). Its
version and date are the revocation file's modification time, and the lists are
sorted, so instances with the same file serve the same bytes.

Distributing it
---------------

```sh
ssh-casign-client krl -o /etc/ssh/revoked.krl
```

The file is replaced atomically and only when the list changed; a failed download
leaves the old file. `--on-change` runs a command after a change. With a pinned trust
statement ([trust.md](trust.md)), the KRL must be signed by every authority that isn't
retired (`/revoked.krl.sig`), so an emptied or replaced list is refused. `sshd` and `ssh` read
the file on each connection, so they need no reload.

On servers, in `sshd_config`:

```text
RevokedKeys /etc/ssh/revoked.krl
```

On clients that use host certificates, in `ssh_config`:

```text
RevokedHostKeys /etc/ssh/revoked.krl
```

A systemd timer, for example every 15 minutes:

```ini
# /etc/systemd/system/ssh-casign-krl.service
[Service]
Type=oneshot
ExecStart=/usr/local/bin/ssh-casign-client -u https://ssh-ca.example.com/ krl -o /etc/ssh/revoked.krl

# /etc/systemd/system/ssh-casign-krl.timer
[Timer]
OnBootSec=1min
OnUnitActiveSec=15min

[Install]
WantedBy=timers.target
```

Check a certificate against a KRL with OpenSSH itself:

```sh
ssh-keygen -Q -f /etc/ssh/revoked.krl ~/.ssh/id_ed25519-cert.pub
ssh-keygen -Q -l -f /etc/ssh/revoked.krl     # list the KRL's contents
```

How quickly a revocation takes effect is the sum of the reload interval, the KRL's cache
time (5 minutes) and the timer's interval.

`sshd` and the missing file
---------------------------

If `RevokedKeys` names a file that doesn't exist or can't be read, `sshd` refuses all
public key authentication. That fails closed, but it also locks everyone out. Fetch the
KRL once before adding `RevokedKeys`, and keep the timer from deleting it: the client
only ever replaces the file with a valid KRL.

The revocation API (optional)
----------------------------

With shared storage (`[store]`), revocations can go through the service, so revoking
doesn't need a file change or a deploy. Without `[store]` everything above works as
before, and the API isn't offered.

### Storage

```toml
[store]
type = "file"                     # a directory: standalone servers
path = "/var/lib/ssh-casign"

# type = "s3"                     # feature store-s3 (AWS Lambda)
# bucket = "ssh-casign-state"
# prefix = "prod/"

# type = "gcs"                    # feature store-gcs (Cloud Run)
# bucket = "ssh-casign-state"

# type = "azure_blob"             # feature store-azure-blob (Azure Functions)
# account_url = "https://sshcasign.blob.core.windows.net"
# container = "ssh-casign"
```

| Store        | Credentials                     | Permissions                                    |
|--------------|---------------------------------|------------------------------------------------|
| `file`       | the service's user              | read and write the directory                   |
| `s3`         | AWS chain (as `aws_kms`)        | `s3:Get/Put/DeleteObject`, `s3:ListBucket`     |
| `gcs`        | Google (as `gcp_kms`)           | `roles/storage.objectUser` on the bucket       |
| `azure_blob` | Entra ID, or `account_key_file` | Storage Blob Data Contributor on the container |

The store holds `revocations.json` (the API's revocations, next to the revocation file
and the inline entries) and the issuance index under `issued/`. All writes to the
revocations document are conditional (S3 `If-Match`, GCS `ifGenerationMatch`, Azure
`If-Match`, a lock file for `file`): concurrent revocations on several instances retry
instead of overwriting each other. Every instance reloads the store every
`reload_interval`; the one that took a revocation applies it at once.

### Who may revoke what

```toml
[revocation]
admins = [{ claim = "roles", value = "ssh-admin" }]   # issuer: default oidc_provider
# index = true                    # default with a store; see below
```

| Caller                   | Proves                        | May revoke                              |
|--------------------------|-------------------------------|-----------------------------------------|
| holder of a key          | an SSHSIG made with the key   | that key, with all its certificates     |
| signed-in user           | a token from a trusted issuer | their own certificates (from the index) |
| administrator (`admins`) | a token matching a selector   | anything, or all a search matches       |

```sh
# a key you still hold (a leaked key, a laptop you still have); no sign-in:
ssh-casign-client revoke --key ~/.ssh/id_ed25519 --reason "key leaked"
# your own certificates, from any device (a lost laptop):
ssh-casign-client certificates
ssh-casign-client revoke --all --reason "laptop lost"
ssh-casign-client revoke --serial 16361417745147627987 --authority users
ssh-casign-client revoke --certificate ~/.ssh/id_ed25519-cert.pub
# administrators:
ssh-casign-client revoke --fingerprint SHA256:... --reason "compromised"
ssh-casign-client revoke --key-id ca1:default:alice@example.com:laptop
ssh-casign-client certificates --where client_address=203.0.113.9
ssh-casign-client revoke --where client_address=203.0.113.9 --reason "abuse from this address"
```

`--where FIELD=VALUE` (repeatable; all must match) searches the issuance index:
`owner_issuer`, `owner_id`, `principal`, `fingerprint`, `key_id`, `profile`,
`authority`, `app_name`, `client_address`. Searches across owners read every unexpired
entry, which is fine for an investigation but not for routine use.

A proof of possession is an SSHSIG (namespace `ssh-casign-revoke`) over the key, the
service's trust domain (`trust.id`) and the time; it must be within ten minutes of the
service's clock. The client signs with `ssh-keygen -Y sign`, so keys in files, on
FIDO tokens and in `ssh-agent` (pass the `.pub` file) work.

Each revocation is an audit record `certificate-revoked` with who revoked it (`duser`),
what (serial, key ID or fingerprint) and the reason.

### The issuance index

With a store, every issued certificate is recorded under
`issued/<owner>/<expiry>.<authority>.<serial>.json`: serial, authority, key ID, type,
principals, validity, the key's fingerprint, profile, application name, client address
and owner (token issuer and IdP-determined ID). That is what lets users revoke their own
certificates and administrators find everything related to an incident.

- **Fail closed**, like the audit log: if the entry can't be written, the certificate
  is withheld (`Issuance index unavailable`).
- **Only unexpired certificates are listed.** Entries are deleted when a listing passes
  them a week after expiry. For S3, GCS and Azure, a lifecycle rule on `issued/` (delete
  after the longest `max_validity` plus a week) keeps the store small without that.
- `index = false` turns it off: revoking by possession and by administrators still
  works, users can't list or revoke their own certificates.

Tested
------

End to end with `sshd`, `ssh` and `ssh-keygen -Q`:

- a user certificate revoked by serial, a key by fingerprint and a host certificate by
  key ID;
- `ssh-keygen -Q` reported the three as revoked and an unrelated certificate as ok;
- `sshd` with `RevokedKeys` refused the revoked user certificates and accepted the
  other;
- `ssh` with `RevokedHostKeys` refused the revoked host certificate;
- the service refused to sign the revoked key;
- `krl` replaced the file only on change, and `If-None-Match` got a 304;
- a broken revocation file was reported once and the previous list kept.

The API, end to end with two service instances on one store (file, and S3 on
LocalStack), the mock IdP and `ssh-keygen -Q`:

- a user listed and revoked their own certificate by serial; revoking another user's
  certificate, revoking by fingerprint and searching were refused;
- a key holder revoked a key that was never signed in, and the service then refused to
  sign it;
- an administrator found the user's certificates by principal and revoked every
  certificate requested from one address;
- the other instance's KRL had all four revocations within a second;
- the audit log recorded each revocation, with who and why.

The stores passed the same tests (conditional writes, list, delete) against LocalStack
4.0.3 (S3), fake-gcs-server 1.54.0 (GCS) and Azurite 3.35.0 (Azure Blob, Shared Key), and
eight concurrent writers lost no update on the file store. S3 request signing matches
botocore's. Entra ID authentication for Azure Blob and the real cloud services are not
tested yet.
