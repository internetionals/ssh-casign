Weak key checks
===============

A certificate is only as good as the key it certifies. Some keys look fine but have a
private key that is known, or can be computed from the public key: keys from flawed
chips or random number generators, keys with badly chosen primes, and keys that were
published (in documentation, test suites, firmware images). The service refuses to
certify them, and refuses to run with such a CA key.

What is checked
---------------

| Check          | Catches                                                                           |
|----------------|-----------------------------------------------------------------------------------|
| ROCA           | RSA keys from Infineon chips (CVE-2017-15361): older YubiKey 4, TPMs, smart cards |
| Fermat         | RSA keys whose primes are too close together (CVE-2022-26320)                     |
| RSA sanity     | even modulus, a prime factor below 2000, exponent 1 or even                       |
| Ed25519 points | invalid points, low order, a torsion component, non-canonical encodings           |
| ECDSA points   | points not on the curve, the identity                                             |
| blocklists     | keys listed in files you configure (see below)                                    |
| shared keys    | one key certified for several owners (needs the issuance index)                   |

The built-in checks cost microseconds to milliseconds per key (a 4096-bit RSA key takes
well under the time of the request itself), and apply to `sk-` keys as well.

- **ROCA** is the fingerprint test of the paper's authors: a ROCA modulus is, modulo
  each of 38 small primes, a power of 65537. Ordinary moduli practically never are.
- **Fermat** tries 100 steps from √N, like the badkeys project: enough for primes that
  share their top half, the pattern of the affected implementations.

Configuration
-------------

```toml
[key_checks]
builtin = true                                   # default
blocklists = ["/etc/ssh-casign/blocklist.txt", "/usr/share/ssh/blacklist.RSA-2048"]
duplicates = "warn"                              # allow, warn (default) or deny
```

Without `[key_checks]`, the built-in checks run and nothing else. A refused key gets
`403 Weak key: <reason>`, and the denial is in the audit log.

### Blocklists

One key per line, `#` starts a comment:

| Line                           | Meaning                                   |
|--------------------------------|-------------------------------------------|
| `SHA256:<base64>`              | a fingerprint as `ssh-keygen -l` shows it |
| 64 hex digits                  | the SHA-256 of the key blob               |
| 32 hex digits (colons allowed) | an MD5 fingerprint                        |
| 20 hex digits                  | Debian's `openssh-blacklist` format       |
| `ssh-ed25519 AAAA...`          | a public key                              |

The 20-digit form is the last 80 bits of the MD5 fingerprint, as in Debian's
`blacklist.RSA-2048` and similar files. Those files list the keys of the Debian OpenSSL
flaw (CVE-2008-0166), which made only about 32,000 keys possible per type and size. Old
packages of `openssh-blacklist` still have them.

Good sources for further entries: the badkeys project (badkeys.info) collects the
Debian keys, keys from firmware, documentation and test suites, and keys with shared
primes. Check its formats and licence before converting its lists.

The blocklists also apply to the CA keys at startup. Put the keys of test and
proof-of-concept CAs on a list in production, and a forgotten test CA stops the
service instead of signing certificates.

### Shared keys

With the issuance index, the service records which owners each key was certified for.
A key certified for a second owner (a key copied between people, or a test key
deployed on many machines) is:

| `duplicates` | Then                                                                       |
|--------------|----------------------------------------------------------------------------|
| `allow`      | nothing                                                                    |
| `warn`       | issued; logged, and the audit record lists the others (`sshKeySharedWith`) |
| `deny`       | refused: `This key is already certified for another identity`              |

`deny` needs the issuance index (`[store]`); `warn` does nothing without it.
Administrators can find the other certificates with `certificates --where
fingerprint=SHA256:...`.

Tested
------

Unit tests with constructed keys: ROCA-structured moduli are detected and ten ordinary
ones are not; adjacent primes are found by Fermat; small factors, bad exponents, the
identity point, a point of order 8, a key with a torsion component and a non-canonical
encoding are refused; every blocklist line format matches.

End to end with the service, the mock IdP and keys that `ssh-keygen` itself accepts: a
Fermat key, a 2048-bit ROCA key, a modulus with factor 3, a low-order Ed25519 key and a
key on a Debian-format blocklist were refused with their reason; a normal key and a
4096-bit RSA key were issued; one key for two users was issued with a warning and the
audit field, and refused with `duplicates = "deny"`; a blocklisted CA key stopped the
service at startup.

Not tested: real ROCA keys (the test keys have ROCA's structure, built the way the
paper describes), and Debian's actual blocklist files.
