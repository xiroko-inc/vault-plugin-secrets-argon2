# vault-plugin-secrets-argon2

A HashiCorp Vault secrets engine that provides Argon2id password
hashing as a service. Applications POST plaintext passwords on signup
and login; Vault stores the hash and returns an opaque `hash_id`. The
hash material never leaves Vault — verification happens server-side.
Compromise of the application database reveals only IDs, not hashes.

This plugin is the missing "Transit-for-passwords": Vault's `transit`
engine handles symmetric and asymmetric crypto with stable keys, but
Vault has no first-party primitive for one-way password hashing. Apps
that want "passwords never leave Vault" semantics today roll their
own; this plugin standardizes the pattern.

**Status:** pre-1.0. The API surface is stable in design but not yet
tagged for production use.

## Why this plugin

The canonical password-hashing pattern is:

1. App authenticates a user, receives a plaintext password.
2. App calls `argon2id(password, salt, params) → hash`.
3. App stores the hash in its own database.

A leaked database file with hashed passwords lets an attacker take it
home and grind against it indefinitely with no rate-limiting. This
plugin moves the hash inside Vault. The app's database stores only an
opaque `hash_id`. The plugin holds the actual hash material, and
`verify` is the only operation against it.

What you get:

- **Audit log integration for free.** Every `hash` and `verify`
  operation flows through Vault's audit devices. Failed-login
  attribution is built-in.
- **Centralized parameter rotation.** When today's `m=64MiB t=3 p=2`
  is no longer enough, one Vault config change propagates to every
  consumer.
- **Hash isolation.** Consumer database compromises don't reveal hash
  material.

## API surface

Mount-relative paths. Defaults to `argon2/`.

| Verb     | Path                       | Purpose                                |
|----------|----------------------------|----------------------------------------|
| `PUT`    | `policy/<name>`            | Create or update a hashing policy      |
| `GET`    | `policy/<name>`            | Read a policy                          |
| `DELETE` | `policy/<name>`            | Delete a policy (404s if hashes exist) |
| `LIST`   | `policy`                   | List all policies                      |
| `POST`   | `hash/<policy>`            | Hash a password under the named policy |
| `DELETE` | `hash/<hash_id>`           | Delete a stored hash                   |
| `LIST`   | `hash`                     | List hash IDs                          |
| `POST`   | `verify/<hash_id>`         | Verify a password                      |

Policy defaults match RFC 9106 §4 "second recommended option":

```
algorithm    argon2id
memory_kib   65536       (64 MiB)
iterations   3
parallelism  2
salt_len     16
key_len      32
```

Hard bounds:

```
memory_kib   [8192, 1048576]   (1 MiB to 1 GiB)
iterations   [1, 100]
parallelism  [1, 16]
salt_len     [16, 64]
key_len      [32, 64]
```

See [`docs/api.md`](docs/api.md) for full request/response shapes.

## Installing

### Download

Download a release binary from the [GitHub Releases page][releases]
matching your Vault server's OS and architecture. Verify the SHA-256
checksum.

[releases]: https://github.com/xiroko-inc/vault-plugin-secrets-argon2/releases

### Register

```sh
# 1. Place the binary in Vault's plugin directory and chmod 0755.
mv vault-plugin-secrets-argon2 /etc/vault/plugins/

# 2. Compute its SHA-256 and register with Vault.
SHA=$(sha256sum /etc/vault/plugins/vault-plugin-secrets-argon2 | awk '{print $1}')
vault plugin register \
  -sha256="$SHA" \
  -command=vault-plugin-secrets-argon2 \
  secret vault-plugin-secrets-argon2

# 3. Mount it.
vault secrets enable -path=argon2 vault-plugin-secrets-argon2
```

### Configure a policy

```sh
vault write argon2/policy/users \
  memory_kib=65536 \
  iterations=3 \
  parallelism=2
```

## Quick example

```sh
# Hash a password — caller supplies subject_id matching their app's user UUID.
vault write argon2/hash/users \
  password="hunter2" \
  subject_id="2c1f-..."
# => hash_id=2c1f-...  policy=users  created_at=...

# Verify on login.
vault write argon2/verify/2c1f-... password="hunter2"
# => valid=true policy_drift=false

# Wrong password.
vault write argon2/verify/2c1f-... password="wrong"
# => valid=false policy_drift=false  (status 200 — bool in body)

# Account deletion.
vault delete argon2/hash/2c1f-...
```

See [`docs/integration.md`](docs/integration.md) for a Go HTTP client
example and the recommended Vault policy for application servers.

## Audit logging

The `password` field is annotated `Sensitive: true` and is redacted
in audit logs by Vault's framework. The stored PHC string is never
returned in any API response, so it cannot leak via response-body
audit. `hash_id`, `subject_id`, `policy`, and timestamps are NOT
redacted — they are the legitimate audit trail.

## Threat model

The full threat model is documented in
[`docs/threat-model.md`](docs/threat-model.md). Summary:

- **Defends against:** stolen application database (yields `hash_id`s
  with no hash material), stolen Vault audit logs (passwords are
  redacted).
- **Does not defend against:** compromised Vault server, compromised
  application server (which sees plaintext passwords on the wire).
- **Out of scope:** server-side rate limiting (use Vault's own
  rate-limit subsystem), failed-login lockout (track in your app),
  HSM/sealed-pepper layering (v1.x roadmap).

## Building from source

```sh
git clone https://github.com/xiroko-inc/vault-plugin-secrets-argon2
cd vault-plugin-secrets-argon2
make build      # → ./vault-plugin-secrets-argon2
make test       # unit tests
make acceptance # acceptance tests against an in-process Vault TestCluster
```

## License

[MPL 2.0](LICENSE) — matches Vault upstream.
