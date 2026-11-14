Certificate policy
==================

Every value in a certificate is resolved from three sources:

| Source      | Where it comes from                                    | Provides          |
|-------------|--------------------------------------------------------|-------------------|
| **request** | the client's sign request (`ssh-casign-client cert …`) | requested values  |
| **token**   | claims in the OIDC token                               | defaults + limits |
| **profile** | the matching profile in the service config             | defaults + limits |

Defaults
--------

A value is taken from the first source that has it: request → token → profile.

User certificates get `ssh-keygen`'s default extensions when no source specifies
extensions: `permit-X11-forwarding`, `permit-agent-forwarding`, `permit-port-forwarding`,
`permit-pty` and `permit-user-rc`.

Limits
------

The token and the profile can both set limits, and both always apply. The allowed values
are those that both allow.

| Value              | Default key        | Limit keys                                                                           |
|--------------------|--------------------|--------------------------------------------------------------------------------------|
| validity (seconds) | `validity`         | `min_validity`, `max_validity`                                                       |
| principals         | `principals`       | `required_principals`, `allowed_principals`, `matching_principals`                   |
| extensions         | `extensions`       | `required_extensions`, `allowed_extensions`, `matching_extensions`                   |
| critical options   | `critical_options` | `required_critical_options`, `allowed_critical_options`, `matching_critical_options` |
| application name   | (request only)     | `matching_app_name`, at most 64 characters                                           |
| comment            | `comment`          | `matching_comment`                                                                   |

- `min_*` / `max_*`: inclusive range. The effective range is the higher minimum and the
  lower maximum of the two sources.
- `allowed_*`: list; every value must be in it.
- `required_*`: always added to the result. For critical options it is a map, and the
  option is forced to that value.
- `matching_*`: a regular expression (Rust `regex` syntax) that is **anchored**: the
  whole value must match, so `"[a-z]+"` means `^(?:[a-z]+)$`. It is applied to each
  principal, each extension name, the application name and the comment.
  `matching_critical_options` maps an option name to a pattern for its value.
- `extensions` and `critical_options` are maps of name → value. Extensions normally have
  an empty value. `allowed_*` and `required_extensions` take names.

How violations are handled
--------------------------

| Situation                                                             | Result                     |
|-----------------------------------------------------------------------|----------------------------|
| A **requested** value breaks a limit                                  | 403, request rejected      |
| A **default** range value is out of range                             | clamped into the range     |
| A **default** set member is not allowed                               | dropped                    |
| A **default** text value doesn't match                                | 403 (text can't be fitted) |
| A required value is itself not allowed (by either source)             | 403, conflict              |
| A requested critical option has a different value than a required one | 403, request rejected      |
| A default critical option has a different value than a required one   | required value wins        |
| `min_validity` above `max_validity`                                   | 403, conflict              |
| No principals left                                                    | 403                        |
| No validity in any source                                             | 403                        |

The 403 message names the limit and its source, for example
`requested validity 10800s exceeds max_validity 7200s of the token`. Conflicts are also
logged as warnings, because they point at contradictory configuration rather than at a
bad request.

> **Principals fail closed.** A client may only request principals when the token or the
> profile sets `allowed_principals` or `matching_principals`. Without such a limit, the
> default principals would be the only thing keeping a client from requesting `root`.

### Principal templates

In the **profile**, `principals`, `required_principals` and `allowed_principals` may be
templates over the token's claims. That way IdPs that can't emit custom claims (Dex,
most corporate IdPs) can still give each user their own principals:

```toml
[profiles.default]
ssh_ca = "default"
validity = 3600
principals = ["{{claim:preferred_username}}", "grp-{{claim:groups}}"]
allowed_principals = ["{{claim:preferred_username}}", "{{claim:preferred_username}}-admin", "grp-{{claim:groups}}"]
```

- Placeholders: `{{claim:NAME}}`, `{{oidc_id}}`, `{{profile}}` and `{{server_id}}`. The
  client-chosen `{{app_name}}` and `{{serial}}` are rejected when the config loads.
- A **list claim fans out**: with `groups = ["dev", "ops"]`, `grp-{{claim:groups}}`
  gives `grp-dev` and `grp-ops`. Several list placeholders in one template give every
  combination.
- A **missing claim gives no principal** from that template, rather than an error. Fewer
  defaults is safe, and an expanded `allowed_principals` that comes out empty allows
  nothing.
- Values are used as is (no escaping, unlike the key ID). Results that are empty or
  contain whitespace or control characters are dropped. All other limits still apply.
- Templates are only expanded in the profile. Values from the token's claims are always
  literal.

Requested sets **replace** the defaults; required values are still added. For example,
`--extension permit-pty` gives a certificate with only `permit-pty` plus any
`required_extensions`. `--no-extensions` requests an empty set.

Examples
--------

Profile in the service config:

```toml
[profiles.default]
ssh_ca = "default"
validity = 3600                         # 1 hour unless asked otherwise
max_validity = 28800                    # never more than 8 hours
matching_principals = "[a-z][a-z0-9_-]*"
required_extensions = ["permit-pty"]
allowed_critical_options = ["source-address", "force-command"]
matching_critical_options = { "source-address" = '10\.[0-9./,]+' }
matching_app_name = '[a-z][a-z0-9-]*'
```

Claims in the token (configured at the IdP):

```json
{
  "principals": ["alice"],
  "allowed_principals": ["alice", "deploy"],
  "max_validity": 7200
}
```

`valid_principals` is accepted as an alias of `principals` in both places.

Client requests (`-I` sets the application name, see [Key ID](#key-id)):

```sh
ssh-casign-client cert ~/.ssh/id_ed25519.pub                   # 1h, alice
ssh-casign-client cert -V 2h -n deploy ~/.ssh/id_ed25519.pub   # 2h, deploy
ssh-casign-client cert -V 4h ~/.ssh/id_ed25519.pub             # 403: max_validity of the token
ssh-casign-client cert -n root ~/.ssh/id_ed25519.pub           # 403: allowed_principals
```

Key ID
------

The key ID shows up in `sshd`'s logs, so it is not a free value: the service builds it
from the profile's `key_id` template. The default records where the certificate came
from:

```text
{{server_id}}:{{profile}}:{{oidc_id}}:{{app_name}}
```

for example `ca1:ops:alice@example.com:ansible`.

| Placeholder      | Value                                                 | Why                                           |
|------------------|-------------------------------------------------------|-----------------------------------------------|
| `{{server_id}}`  | `server_id` in the service config (default: hostname) | several instances can run side by side        |
| `{{profile}}`    | name of the matched profile                           | the profile determines the limits             |
| `{{oidc_id}}`    | token claim named by `oidc_provider.id_claim`         | who was authorized                            |
| `{{app_name}}`   | application name from the client, or `-`              | which workload (ssh, ansible, terraform, ...) |
| `{{serial}}`     | the certificate's serial number (decimal)             | tells certificates of one workload apart      |
| `{{claim:NAME}}` | any string, number or boolean claim of the token      | custom templates                              |

- **`oidc_id`** must identify the user or client uniquely, and the IdP maintainer must
  be able to trace it back. Options include `sub` (the default; stable and unique per
  issuer), a UPN, a UUID, or a pseudonymous ID that only the IdP can resolve. A token
  without the claim, or with an empty one, gets a 403.
- **`app_name`** is chosen by the client, like PostgreSQL's `application_name`. It is
  limited to 64 characters and by `matching_app_name` from the token and the profile.
- **Profile names**: `name` on a `[[profiles.map]]` entry, defaulting to
  `<claim>=<value>`. The fallback profile is called `default`. Names must be unique.
- **Escaping**: substituted values are percent-encoded for `%`, `:`, whitespace, control
  characters and non-ASCII (`vs code:remote` → `vs%20code%3Aremote`). A value can
  therefore never shift the fields of the template. Literal template text is used as is.
- **Serial numbers** are random, non-zero 64-bit values, so instances need no
  coordination. They are not in the default template because `sshd` already logs the
  serial next to the key ID; use `{{serial}}` to make the key ID unique on its own.
- **Audit log**: every issued certificate is logged at `info` with its serial, key ID,
  profile, authority, principals, validity and the public key's fingerprint.

Custom template:

```toml
[profiles.default]
ssh_ca = "default"
key_id = "{{server_id}}/{{profile}}/{{claim:email}}/{{app_name}}"
```
