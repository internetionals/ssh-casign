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
# client_address_header = "x-forwarded-for"   # behind a proxy, CDN or API gateway
# trusted_proxies = ["10.0.0.0/8"]      # only believe headers from these peers
# correlation_id_header = "cf-ray"      # the proxy's request ID
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

### Behind a reverse proxy or CDN

`src`/`spt` are the TCP peer. Behind a reverse proxy, load balancer, CDN or API gateway
that is the proxy, so the client's address has to come from a header the proxy sets:

| Setting                 | Meaning                                                                       |
|-------------------------|-------------------------------------------------------------------------------|
| `client_address_header` | the header with the client address (see below)                                |
| `trusted_proxies`       | address ranges (`192.0.2.0/24`, `2001:db8::/32`, single addresses) of proxies |
| `client_address_skip`   | trailing entries added by proxies whose addresses aren't known (default 0)    |
| `correlation_id_header` | a request ID the proxy sets, recorded next to our own                         |

Supported headers:

| Header             | Set by                                                    |
|--------------------|-----------------------------------------------------------|
| `x-forwarded-for`  | most proxies and load balancers, Lambda, Cloud Run, Azure |
| `forwarded`        | RFC 7239 (`for=`): HAProxy, Envoy, some CDNs              |
| `cf-connecting-ip` | Cloudflare (one address)                                  |
| `true-client-ip`   | Akamai, Cloudflare Enterprise (one address)               |
| `x-real-ip`        | nginx (`proxy_set_header X-Real-IP $remote_addr`)         |

Entries may be `IP`, `IP:port`, `[IPv6]` or `[IPv6]:port`.

How the client address is found:

1. If `trusted_proxies` is set and the TCP peer isn't in it, the request didn't come
   through a trusted proxy: forwarding headers are ignored and the peer is recorded.
2. The header is read from the right: the first `client_address_skip` entries are
   passed over, then every entry inside `trusted_proxies`. The next address is the
   client. Everything further left was sent by the client and can be anything.
3. If the header is missing, or has fewer entries than `client_address_skip` (the
   proxy was bypassed), the peer is recorded. An entry that isn't an address
   (`unknown`, an obfuscated RFC 7239 name) stops the walk at the last trusted hop.
   If every entry is trusted, the leftmost is recorded.

When the address comes from the header, the record also has the proxy (`proxyAddress`,
`proxyPort`). Several header lines count as one list.

**Without `trusted_proxies`, the header is believed from every peer**, and the service
logs a warning at startup. That is only right when clients can't reach the service
except through the proxy: Lambda, Cloud Run and Azure Functions, or a server that
listens on loopback or a private network. A standalone server that is reachable
directly must set `trusted_proxies`; otherwise anyone can put any address in the log.
Where the proxy's address isn't known but it can't be bypassed (Cloud Run), say so with
`trusted_proxies = ["0.0.0.0/0", "::/0"]`, which also silences the warning.

The correlation ID (e.g. Cloudflare's `CF-Ray`) is recorded as `flexString2`, and it is
in the service's own log line, so an audit record can be matched to the CDN's logs. Like
the address header, it is only taken from trusted proxies. It is cut to 128 printable
characters. The service's own request ID stays the primary one (`externalId`, response
header `X-Request-Id`), since a client could choose a forwarded one.

#### Cloudflare

Behind Cloudflare's proxy, trust Cloudflare's address ranges:

```toml
[audit]
client_address_header = "cf-connecting-ip"
correlation_id_header = "cf-ray"
trusted_proxies = [
  # https://www.cloudflare.com/ips-v4 and https://www.cloudflare.com/ips-v6
  "173.245.48.0/20", "103.21.244.0/22", "...",
  "2400:cb00::/32", "...",
]
```

The service doesn't have Cloudflare's ranges built in, because they change from time to
time. Take the current lists from those two URLs when you deploy, and check them now and
then.

Simpler and safer is a **Cloudflare Tunnel** (`cloudflared`): the service listens on
loopback only (`listen = "127.0.0.1:3000"`) and has no open port, so nothing bypasses
Cloudflare. Use `trusted_proxies = ["127.0.0.1/32", "::1/128"]`.

Other things to set up at Cloudflare:

- **Bot protection** (Bot Fight Mode, managed challenges, "Under Attack" mode) answers
  with an HTML challenge that a CLI client can't solve. Add a WAF custom rule that
  skips these for `/.well-known/ssh-casign` and `/sign`.
- **Rate limiting** isn't built into the service. A rate limiting rule on `/sign` (e.g.
  per IP) belongs here.
- **TLS to the origin**: the service speaks plain HTTP. Use a tunnel, or keep the
  traffic between Cloudflare and the service on a private network. "Full (strict)"
  mode needs TLS on the service itself, which isn't supported yet.

#### nginx

```nginx
location / {
    proxy_pass http://127.0.0.1:3000;
    proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
}
```

```toml
[audit]
client_address_header = "x-forwarded-for"
trusted_proxies = ["127.0.0.1/32", "::1/128"]
```

If nginx itself is behind a CDN or load balancer, add those ranges to
`trusted_proxies` too: the walk then passes over them to the real client.

#### Caching

Responses from `/sign` (certificates and errors) carry `Cache-Control: no-store`. The
discovery document carries `max-age=300`, so configuration changes reach clients and
caches within five minutes. A path prefix (`https://proxy.example/casign/`) needs no
setting: the discovery document gives the sign endpoint as a relative URL.

CEF fields
----------

Header: `CEF:0|<device_vendor>|<device_product>|<version>|<class>|<name>|<severity>|`

| Event  | Class ID             | Name                           | Severity |
|--------|----------------------|--------------------------------|---------:|
| Issued | `certificate-issued` | SSH certificate issued         |        3 |
| Denied | `certificate-denied` | SSH certificate request denied |        6 |

Extension fields:

| Key                             | Event  | Content                                                          |
|---------------------------------|--------|------------------------------------------------------------------|
| `rt`                            | both   | time of the record (milliseconds since the epoch)                |
| `dvchost`                       | both   | `server_id`                                                      |
| `externalId`                    | both   | request ID                                                       |
| `src`, `spt`                    | both   | client IP address and port (no port with a proxy header)         |
| `proxyAddress`, `proxyPort`     | both   | the proxy that delivered the request, with a proxy header        |
| `flexString2` (`correlationId`) | both   | the proxy's request ID (`correlation_id_header`)                 |
| `suser`                         | both   | the IdP-determined ID (`oidc_provider.id_claim`)                 |
| `suid`                          | both   | the token's `sub`                                                |
| `requestClientApplication`      | both   | the client's application name                                    |
| `cs5` (`issuer`)                | both   | IdP issuer                                                       |
| `cs1` (`profile`)               | both   | matched profile, if any                                          |
| `act`, `outcome`                | both   | `issued`/`success` or `denied`/`failure`                         |
| `flexString1` (`serial`)        | issued | certificate serial (decimal; doesn't fit `cn1`'s signed 64 bits) |
| `cs2` (`keyId`)                 | issued | certificate key ID                                               |
| `cs3` (`principals`)            | issued | principals, comma separated                                      |
| `cs4` (`authority`)             | issued | signing authority                                                |
| `cs6` (`publicKeyFingerprint`)  | issued | SHA-256 fingerprint of the client's public key                   |
| `start`, `end`                  | issued | validity (milliseconds since the epoch)                          |
| `sshCertType`                   | issued | `user`                                                           |
| `sshExtensions`                 | issued | extensions, comma separated, `name` or `name=value`              |
| `sshCriticalOptions`            | issued | critical options, same format                                    |
| `sshCertificate`                | issued | the certificate (OpenSSH format), e.g. for revocation            |
| `reason`                        | denied | the error message the client got                                 |
| `cn1` (`httpStatus`)            | denied | HTTP status                                                      |

The `ssh*` keys are custom extensions. SIEMs that only map the CEF dictionary keep them
as additional fields (Microsoft Sentinel: `AdditionalExtensions`).

Values are escaped as CEF requires: `\` and `=` with a backslash, line breaks as `\n` /
`\r`; header fields escape `\` and `|`.

Example (shortened):

```text
CEF:0|ssh-casign|ssh-casign-service|0.1.0|certificate-issued|SSH certificate issued|3|rt=1794671871641 dvchost=poc-ca1 externalId=c8d8b567… src=127.0.0.1 spt=52811 suser=user1@example.com suid=CiQw… requestClientApplication=audit-test cs5Label=issuer cs5=http://127.0.0.1:5557/dex cs1Label=profile cs1=default act=issued outcome=success flexString1Label=serial flexString1=8162701812246731047 cs2Label=keyId cs2=poc-ca1:default:user1@example.com:audit-test …
```
