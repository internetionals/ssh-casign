Trusting the authorities
========================

Servers need the user CA keys (`TrustedUserCAKeys`), clients the host CA keys
(`@cert-authority` in `known_hosts`), and both the KRL. They get them from the
service's discovery document. Without more, whoever controls that document (DNS, a
TLS interception proxy, a CDN, the service itself) decides which CAs servers trust,
and one extra line in `TrustedUserCAKeys` lets someone log in as anyone.

So the discovery document carries a signed **trust statement**, and servers and
clients **pin** it: they accept a changed set of authorities only when the keys they
already trust have signed it.

The trust statement
-------------------

```json
{
  "id": "example",
  "version": 4,
  "expires": 1826150400,
  "authorities": [
    { "name": "hosts", "public_key": "ssh-ed25519 AAAA...", "cert_types": ["host"],
      "known_hosts_pattern": "*.prod.example.com" },
    { "name": "users", "public_key": "ssh-ed25519 AAAA...", "cert_types": ["user"],
      "retired": true },
    { "name": "users2", "public_key": "ssh-ed25519 AAAA...", "cert_types": ["user"] }
  ],
  "signers": { "keys": ["ssh-ed25519 AAAA...", "...", "..."], "threshold": 2 }
}
```

It is published as a string (`trust.statement`) with SSHSIG signatures
(`trust.signatures`, namespace `ssh-casign-trust`, the format of `ssh-keygen -Y
sign`). The signatures cover exactly that string, which must be the statement's
canonical form (compact JSON, authorities sorted by name, keys without comments).

A pinned client accepts a new statement only if all of these hold:

| Check           | Rule                                                                            |
|-----------------|---------------------------------------------------------------------------------|
| trust domain    | `id` equals the pinned `id`                                                     |
| freshness       | `expires` is in the future                                                      |
| authorised      | `threshold` of the **pinned** signers signed it                                 |
| self-consistent | `threshold` of its **own** signers signed it                                    |
| no replay       | `version` is higher, or equal with the same content (only `expires` may change) |

Then the new statement becomes the pin. A client follows changes step by step; a client
that was offline for a while still accepts the newest statement as long as its pinned
signers signed it.

Two modes
---------

### Automatic (default)

The service builds the statement from its authorities and signs it with all of them.
The signers are the authorities that aren't retired, and all of them must sign.

```toml
[trust]
id = "example"          # the same on every instance; default "ssh-casign"
version = 1             # increase it whenever the authorities change
validity = 7776000      # seconds (90 days, the default); re-signed at half of it
```

This protects against forgery on the way to the service: DNS, TLS interception, a
CDN. It does **not** protect against someone who controls the service or its
configuration: the service signs whatever authorities it is configured with, with keys
it holds. An attacker who adds a CA to the configuration gets it signed by the old
ones.

### Offline trust keys (recommended)

A few keys the service never has (say, YubiKeys of three administrators) sign the
statement, 2 of 3. The statement is a TOML file, kept in version control:

```toml
# trust.toml
id = "example"
version = 4
expires = 2027-11-14                 # a date, a date-time, or Unix seconds

[signers]
threshold = 2
keys = [
  "sk-ssh-ed25519@openssh.com AAAA... alice",
  "sk-ssh-ed25519@openssh.com AAAA... bob",
  "sk-ssh-ed25519@openssh.com AAAA... carol",
]

[[authorities]]
name = "users2"
public_key = "ssh-ed25519 AAAA..."
cert_types = ["user"]

[[authorities]]
name = "users"
public_key = "ssh-ed25519 AAAA..."
cert_types = ["user"]
retired = true

[[authorities]]
name = "hosts"
public_key = "ssh-ed25519 AAAA..."
cert_types = ["host"]
known_hosts_pattern = "*.prod.example.com"
```

Two of the three sign it:

```sh
ssh-casign-client trust sign -k ~/.ssh/id_ed25519_sk -o alice.sig trust.toml
# or with ssh-keygen directly (same bytes):
ssh-casign-client trust statement trust.toml | ssh-keygen -Y sign -n ssh-casign-trust -f ~/.ssh/id_ed25519_sk > bob.sig
# check before deploying:
ssh-casign-client trust verify trust.toml alice.sig bob.sig
```

The service serves it:

```toml
[trust]
statement = "/etc/ssh-casign/trust.toml"
signatures = ["/etc/ssh-casign/alice.sig", "/etc/ssh-casign/bob.sig"]
```

At startup the service refuses to run if:

- the signatures don't reach the threshold;
- an authority it signs with is missing from the statement or has another key there;
- the statement lists an authority that isn't retired but isn't configured.

It warns 30 days before the statement expires.

A change of the authorities now needs two of the three key holders. Someone who
controls the service or its configuration can't add a CA: a statement without their
signatures doesn't pass the pin, and switching the service back to automatic mode
gives a statement the pinned trust keys didn't sign.

In both modes the service adds its own authorities' signatures. Clients that pinned an
automatic statement need those to move to the offline one: the step from automatic to
offline is signed by the old signers (the CAs, through the service) and by the new
ones (the trust keys).

Pinning
-------

```sh
# the expected signers, distributed by config management:
ssh-casign-client trust pin --expect SHA256:aaa... --expect SHA256:bbb... --expect SHA256:ccc...
# or trust on first use, deliberately:
ssh-casign-client trust pin --tofu
ssh-casign-client trust show
```

- `--expect` must name exactly the statement's signers. In automatic mode those are the
  CA keys (`ssh-keygen -l -f ca.pub`); in offline mode the trust keys.
- The pin is a file per service: `trust_store` in the client profile, else
  `<data dir>/ssh-casign-client/trust/<service>.json`. On servers, point it somewhere
  stable, e.g. `/var/lib/ssh-casign/trust.json`.
- Once pinned, `ca-keys` and `krl` check the statement on every run and update the pin
  when a newer one passes. A statement that doesn't pass is an error, and the output
  files stay as they were.
- `trust pin --force` replaces the pin: the way back when signer keys are lost.

`ca-keys` without a pin uses the unsigned list and warns.

### What a pin protects

| Part                              | With a pin                                           |
|-----------------------------------|------------------------------------------------------|
| `TrustedUserCAKeys` (`ca-keys`)   | only authorities from an accepted statement          |
| `known_hosts` (`ca-keys -t host`) | the same, with each host CA's `known_hosts_pattern`  |
| KRL (`krl`)                       | must be signed by every authority that isn't retired |
| IdP settings, sign endpoint       | not covered (they don't decide what servers trust)   |

The KRL signatures (`/revoked.krl.sig`, namespace `ssh-casign-krl`) are made by the
service online, since the list changes often. They stop an emptied or replaced KRL
on the way, which would quietly un-revoke certificates.

Rotating
--------

### A CA key

1. Add the new authority to the configuration (and the statement file in offline
   mode), increase the version, deploy. Servers fetch the statement with both keys.
2. Point the profiles at the new authority first (`ssh_ca = ["users2", "users"]`).
3. Mark the old one `retired = true` (and in the statement file), new version. It no
   longer signs certificates but stays trusted and in the KRL until its certificates
   have expired.
4. Remove it, new version.

In automatic mode each step is signed by the authorities of the previous one,
because retired authorities keep signing statements.

### A trust key

Write a statement with the new signer set and a higher version. It needs `threshold`
signatures from the old signers (to be accepted) and from the new signers (to be
self-consistent); a key in both sets counts for both.

If more than `threshold - 1` trust keys are lost, no new statement can be accepted:
servers have to be re-pinned with `trust pin --force`. With 2 of 3, losing one key is
fine.

### Expiry

A statement expires (offline: when its `expires` says; automatic: after `validity`,
re-signed at half). Expiry bounds how long a stale statement can be served to a server
that is cut off from the real service. Sign a new offline statement well before it
expires; it is a ceremony like any other change.

Tested
------

End to end with the service, `ssh-keygen` and a fake server:

- pinning: a wrong `--expect` was refused, the CA fingerprints (automatic) worked;
- `ssh-keygen -Y verify` accepted the service's signatures and the trust keys'
  signatures over the canonical statement;
- a fake server with an extra CA signed by an attacker key was refused (0 of the pinned
  signers), and an emptied KRL was refused (not signed by the authorities);
- automatic rotation: adding a CA without a new version was refused; versions 2
  (`users2` added) and 3 (`users` retired) were followed;
- automatic version 3 to offline version 4 (2 of 3 trust keys plus the CAs) was
  accepted; one trust key signature alone was refused by `trust verify`;
- with the offline pin, a tampered statement file stopped the service at startup, and
  switching the service back to automatic mode with an extra CA was refused by the
  client (0 of the pinned signers). The pin stayed at version 4.
