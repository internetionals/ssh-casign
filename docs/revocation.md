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

Later: a revocation API
-----------------------

The list is read through an internal `Source` interface (version check and load). A
storage-backed source (file, S3, GCS, Azure Blob) with a `revoke` endpoint for
administrators, and for users revoking their own certificates, can implement the same
interface without changing the KRL or the checks.

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
