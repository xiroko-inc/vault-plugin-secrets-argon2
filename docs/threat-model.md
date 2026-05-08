# Threat model

Formalizes §7 of the requirements spec. Covers what this plugin
defends against, what it explicitly does not, and the assumptions that
must hold for the defenses to work.

---

## Trust boundaries

### Trusted

- **Vault operators.** They configure policies, mount the plugin,
  hold root tokens. The plugin gives them control; they can read raw
  hash material via the storage backend if they go around the plugin.
  This is not the plugin's threat to mitigate — by Vault's own design,
  operators are inside the trust boundary.
- **The plugin code itself.** Standard "supply-chain assumes our deps
  and binaries aren't malicious" assumption. The release pipeline
  produces SHA-256 checksums and SLSA provenance attestations to make
  this assumption auditable.

### Semi-trusted

- **Vault token holders with `argon2/hash/*` and `argon2/verify/*`
  capabilities.** They can hash arbitrary passwords (creating new
  entries) and verify any hash they have an ID for. They cannot
  directly read hash material — Vault enforces capability-scoped
  access.
- **Application servers.** Hold a Vault token (Kubernetes auth,
  AppRole, etc.); call `hash` on signup and `verify` on login. They
  send the plaintext password to Vault each time. **The plaintext
  password is in the request body**, so transport security (TLS) and
  audit-log redaction are critical.

### Untrusted

- **Attackers without a Vault token.** They cannot reach the plugin's
  API — Vault's auth methods stand in front. Their attack surface
  through this plugin is zero unless they first compromise an auth
  method.
- **Attackers with stolen application database content.** They have
  `hash_id` strings but no hash material. Useless without a Vault
  token.
- **Attackers with stolen Vault audit logs.** They see `hash_id`,
  `subject_id`, `policy`, timestamps, and operation type — but NOT
  passwords (redacted via `Sensitive: true`) and NOT hash material
  (Vault never writes storage values to audit). Failed-login
  attribution by subject is exposed; that's the point.

---

## Defenses

### Hash isolation

The application database stores opaque `hash_id` strings, never PHC
strings or parameter tuples. A leaked database file is useless against
the user's password unless the attacker also obtains a Vault token
authorized for `argon2/verify/+`.

### Audit trail

Every `hash`, `verify`, `delete`, and `policy/*` operation flows
through Vault's audit devices automatically. Failed-login attribution
by `subject_id` is built-in. Audit redaction:

- `password` request body field — `Sensitive: true`, redacted by
  Vault's framework.
- Stored PHC strings — never returned in any response, so they cannot
  leak via response-body audit.

### Defense against tampered storage

If an attacker (or operator error) writes a corrupt or out-of-bounds
PHC string into the storage backend, `Verify` rejects it with
`ErrInvalidPHC` rather than attempting to derive a key with
absurd parameters. Without these bounds, a tampered entry with
`m=4 GiB, t=1000` could DoS the verify path. The bounds are enforced
in the parser (`ParsePHC` returns the parsed values, then `Verify`
checks them) so even if the named policy is updated to widen the
bounds, the stored entry is still rejected against the original
hard-coded ceilings.

### Constant-time comparison

`Verify` uses `crypto/subtle.ConstantTimeCompare` for the final
key comparison. Argon2id itself is a constant-cost (in input length)
function — the per-call cost is determined solely by the parameter
tuple, not by the password content.

### Per-call salt freshness

Every `Hash` call draws a fresh salt from `crypto/rand`. Two hashes
of the same password under the same policy produce different PHC
strings, defeating cross-database rainbow-table attacks.

---

## What this plugin does NOT defend against

### A compromised Vault server

If the attacker controls Vault's storage, they have everything: every
PHC string, every plaintext password as it flows through the verify
path. The plugin assumes Vault itself is operationally secure.

Mitigations are layered outside the plugin:

- Vault audit devices write to append-only / WORM storage.
- Vault HSM auto-unseal so a stolen storage backend cannot be opened
  offline.
- Strict operator controls on root token usage.

### A compromised application server

The application sends plaintext passwords on every login. An attacker
with the application's runtime can intercept them at the source. The
plugin is no worse than in-process hashing in this scenario, but no
better either.

Mitigations:

- mTLS between application and Vault.
- Short-TTL Vault tokens, revocable independent of application
  credentials.
- Application-layer rate limiting and lockout (per-user, not just
  per-IP).

### Side-channel attacks

`golang.org/x/crypto/argon2` and `crypto/subtle` provide the standard
mitigations for timing and cache side channels. Beyond that — power
analysis, microarchitectural side channels, etc. — is outside the
plugin's scope.

### Brute-force attacks via the verify path

Vault has its own rate-limit subsystem
(`sys/quotas/rate-limit/...`). The application also has a token TTL
cap. The plugin does not implement its own rate limiting because
duplicating the existing layer is more error-prone than relying on it.
Operators must configure rate limits explicitly — the plugin will
not stop a million-rps `verify` flood on its own.

---

## Required preconditions for the defenses to hold

1. **TLS between application and Vault.** Otherwise the plaintext
   password is on the wire.
2. **Audit devices configured.** Otherwise the failed-login
   attribution and audit redaction guarantees are vacuous.
3. **Vault rate limits configured** for `argon2/verify/+`. The plugin
   intentionally does not provide its own.
4. **`Sensitive: true` annotation respected by the audit backend.**
   The plugin sets the annotation; verify your audit configuration
   honors it.
5. **Application-layer lockout.** The plugin reports `valid: false` on
   wrong passwords but does not track attempts. The application is the
   right layer for "lock this user after N failures."

---

## Roadmap

These items are explicitly v1.x, not v1.0:

- **HSM-sealed pepper.** Layering a constant secret into the KDF so a
  stolen database is useless even with hash material. Argon2id has no
  `secret` parameter — this would require a separate KDF wrapper.
- **Server-side lockout.** Track failed `verify` attempts per
  `subject_id`, lock after N within a window. Useful pattern but adds
  significant scope and persistence requirements.
- **Bulk operations.** Batch hash/verify for migrations.
- **Other algorithms.** bcrypt, scrypt, PBKDF2 as alternative
  algorithm options once the API surface is stable.
