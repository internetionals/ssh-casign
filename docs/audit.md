Audit log
=========

The service records every issued certificate, and every denied request of an
authenticated client, as one line in Common Event Format (CEF). A certificate is only
returned once all required sinks have accepted its record; if one fails, the request
gets a 500 (`Audit log unavailable`) and the certificate is discarded.

Requests with a missing or invalid token (401) are not recorded, so the log can't be
filled without valid credentials. The regular service log on stderr still has them.

Every request gets a request ID. It is in the record (`externalId`), in the
`X-Request-Id` response header, and in the client's error messages, so a user's error
can be found in the audit log.

Configuration
-------------

```toml
[audit]
record_denials = true                   # default
# client_address_header = "x-forwarded-for"   # behind a proxy or API gateway
# device_vendor = "ssh-casign"          # CEF header fields
# device_product = "ssh-casign-service"

[[audit.sink]]
type = "file"
path = "/var/log/ssh-casign/audit.cef"  # directory must exist

[[audit.sink]]
type = "syslog"                         # default transport: the local Unix socket
facility = "authpriv"                   # default

[[audit.sink]]
type = "syslog"
transport = "tcp"                       # or "udp"
address = "siem.example.com:514"
required = false                        # don't fail requests when the SIEM is down
```

Without an `[audit]` section the service starts with a warning and only logs issuances
to its regular log. Unknown keys are an error.

### Sinks

| Sink                       | Format                                   | Durability                                  |
|----------------------------|------------------------------------------|---------------------------------------------|
| `file`                     | one CEF line per record                  | appended and fsynced per record             |
| `stdout`                   | one CEF line per record                  | flushed per record; the platform keeps it   |
| `syslog`, `unix` (default) | `<PRI>ssh-casign[pid]: CEF:…`            | handed to the local syslog daemon           |
| `syslog`, `tcp`            | RFC 5424, newline framed, CEF as message | written to the connection (reconnects once) |
| `syslog`, `udp`            | RFC 5424, one datagram, CEF as message   | none: UDP can lose records silently         |

- **`file`** opens the file for every record (mode `640`), so rotation by renaming
  (`logrotate` without `copytruncate`) needs no signal.
- **`stdout`** is meant for AWS Lambda, Azure Functions, Google Cloud Run functions and
  containers: the platform's log collection (CloudWatch Logs, Azure Monitor, Cloud
  Logging) keeps the lines. The service's own log goes to stderr, so stdout holds only
  audit records; route lines starting with `CEF:0|` to the SIEM.
- **`syslog`** over the local socket uses `/dev/log` (Linux) or `/var/run/syslog`
  (macOS), or `path`. The traditional local format is used, because local daemons
  (rsyslog, syslog-ng, journald) expect it and add timestamp and hostname themselves.
  Datagram sockets are tried first, stream sockets as fallback. Over the network, the
  RFC 5424 hostname is the `server_id`. Severity is `notice` for issuances and `warning`
  for denials.
- **`required`** (default `true`): a required sink must work at startup (file writable,
  TCP receiver reachable, Unix socket present) and for every record. Failures of an
  optional sink are only logged.

### Client address

`src`/`spt` are the TCP peer. Behind a load balancer or API gateway, set
`client_address_header` (e.g. `x-forwarded-for`): the **rightmost** address in it is
used, which is the one the proxy that talks to the service added; anything to its left
can be set by the client. Only use this when the service is reachable through that proxy
alone.

CEF fields
----------

Header: `CEF:0|<device_vendor>|<device_product>|<version>|<class>|<name>|<severity>|`

| Event  | Class ID             | Name                           | Severity |
|--------|----------------------|--------------------------------|---------:|
| Issued | `certificate-issued` | SSH certificate issued         |        3 |
| Denied | `certificate-denied` | SSH certificate request denied |        6 |

Extension fields:

| Key                            | Event  | Content                                                          |
|--------------------------------|--------|------------------------------------------------------------------|
| `rt`                           | both   | time of the record (milliseconds since the epoch)                |
| `dvchost`                      | both   | `server_id`                                                      |
| `externalId`                   | both   | request ID                                                       |
| `src`, `spt`                   | both   | client IP address and port (no port with a proxy header)         |
| `suser`                        | both   | the IdP-determined ID (`oidc_provider.id_claim`)                 |
| `suid`                         | both   | the token's `sub`                                                |
| `requestClientApplication`     | both   | the client's application name                                    |
| `cs5` (`issuer`)               | both   | IdP issuer                                                       |
| `cs1` (`profile`)              | both   | matched profile, if any                                          |
| `act`, `outcome`               | both   | `issued`/`success` or `denied`/`failure`                         |
| `flexString1` (`serial`)       | issued | certificate serial (decimal; doesn't fit `cn1`'s signed 64 bits) |
| `cs2` (`keyId`)                | issued | certificate key ID                                               |
| `cs3` (`principals`)           | issued | principals, comma separated                                      |
| `cs4` (`authority`)            | issued | signing authority                                                |
| `cs6` (`publicKeyFingerprint`) | issued | SHA-256 fingerprint of the client's public key                   |
| `start`, `end`                 | issued | validity (milliseconds since the epoch)                          |
| `sshCertType`                  | issued | `user`                                                           |
| `sshExtensions`                | issued | extensions, comma separated, `name` or `name=value`              |
| `sshCriticalOptions`           | issued | critical options, same format                                    |
| `sshCertificate`               | issued | the certificate (OpenSSH format), e.g. for revocation            |
| `reason`                       | denied | the error message the client got                                 |
| `cn1` (`httpStatus`)           | denied | HTTP status                                                      |

The `ssh*` keys are custom extensions. SIEMs that only map the CEF dictionary keep them
as additional fields (Microsoft Sentinel: `AdditionalExtensions`).

Values are escaped as CEF requires: `\` and `=` with a backslash, line breaks as `\n` /
`\r`; header fields escape `\` and `|`.

Example (shortened):

```text
CEF:0|ssh-casign|ssh-casign-service|0.1.0|certificate-issued|SSH certificate issued|3|rt=1794671871641 dvchost=poc-ca1 externalId=c8d8b567… src=127.0.0.1 spt=52811 suser=user1@example.com suid=CiQw… requestClientApplication=audit-test cs5Label=issuer cs5=http://127.0.0.1:5557/dex cs1Label=profile cs1=default act=issued outcome=success flexString1Label=serial flexString1=8162701812246731047 cs2Label=keyId cs2=poc-ca1:default:user1@example.com:audit-test …
```
