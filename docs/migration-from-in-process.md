# Migrating from in-process Argon2id to this plugin

This guide is for an existing service that already uses
`golang.org/x/crypto/argon2` directly and wants to move the hash
material into Vault behind this plugin. It pairs with
[`integration.md`](integration.md) (which covers the green-field
integration shape) by adding the migration-specific concerns:
schema change, dual-read / cutover strategy, and how to handle
users whose hashes were created before the move.

This guide was written with the
[`doro-wallet`](https://github.com/xiroko-inc/doro-wallet) refactor
in mind — its `internal/auth/pin.go` is the canonical "before"
example. Adapt the names and field shapes as your service
requires.

---

## Before: in-process Argon2id

The "before" pattern looks like this (paraphrasing
`doro-wallet/internal/auth/pin.go`):

```go
package auth

import (
    "crypto/rand"
    "crypto/subtle"
    "encoding/base64"
    "fmt"

    "golang.org/x/crypto/argon2"
)

const (
    pinSaltLen     = 16
    pinKeyLen      = 32
    pinIterations  = 3
    pinMemoryKiB   = 64 * 1024
    pinParallelism = 2
)

// HashPIN derives a PHC string in-process and returns it for storage.
func HashPIN(pin string) (string, error) {
    salt := make([]byte, pinSaltLen)
    if _, err := rand.Read(salt); err != nil {
        return "", err
    }
    key := argon2.IDKey([]byte(pin), salt,
        pinIterations, pinMemoryKiB, pinParallelism, pinKeyLen)
    return fmt.Sprintf("$argon2id$v=%d$m=%d,t=%d,p=%d$%s$%s",
        argon2.Version, pinMemoryKiB, pinIterations, pinParallelism,
        base64.RawStdEncoding.EncodeToString(salt),
        base64.RawStdEncoding.EncodeToString(key)), nil
}

// VerifyPIN re-derives and constant-time-compares.
func VerifyPIN(pin, phc string) (bool, error) {
    // ... parse phc, re-derive, subtle.ConstantTimeCompare ...
}
```

The PHC string is stored in the application database (in
`doro-wallet`, in the `claimed_wallets.claimed_pin_hash` column).
A leaked database file gives an attacker every PHC string, and
they can grind against them offline with no rate-limiting.

---

## After: plugin-backed

The "after" pattern moves the hash material into Vault. The app
stores only an opaque `hash_id`; the plugin holds the PHC.
`Verify` is the only operation against it, and every call is
audit-logged.

```go
package auth

import (
    "context"
    "errors"
    "fmt"

    vault "github.com/hashicorp/vault/api"
)

// PINAuthenticator wraps the argon2id Vault plugin behind a
// signature that matches the previous in-process functions.
// Keep the interface narrow so the wallet code can mock it in
// tests without standing up a real Vault.
type PINAuthenticator interface {
    Hash(ctx context.Context, pin, subjectID string) (hashID string, err error)
    Verify(ctx context.Context, hashID, pin string) (valid, drift bool, err error)
    Delete(ctx context.Context, hashID string) error
}

type vaultPINAuth struct {
    client *vault.Client
    policy string // e.g. "users" — must match an existing argon2/policy/<name>
}

func NewPINAuthenticator(client *vault.Client, policy string) PINAuthenticator {
    return &vaultPINAuth{client: client, policy: policy}
}

func (a *vaultPINAuth) Hash(ctx context.Context, pin, subjectID string) (string, error) {
    secret, err := a.client.Logical().WriteWithContext(ctx,
        fmt.Sprintf("argon2/hash/%s", a.policy),
        map[string]interface{}{"password": pin, "subject_id": subjectID})
    if err != nil {
        return "", fmt.Errorf("argon2 hash: %w", err)
    }
    id, _ := secret.Data["hash_id"].(string)
    if id == "" {
        return "", errors.New("argon2 hash: response missing hash_id")
    }
    return id, nil
}

// ErrHashIDNotFound is returned when the plugin reports the
// hash_id doesn't exist. The caller's response depends on where
// in the migration timeline they are:
//
//   - During the dual-read window (Strategy B, while
//     claimed_pin_hash still exists for at least some users):
//     a 404 means "this user hasn't been migrated yet" — fall
//     back to the in-process VerifyPIN against
//     claimed_pin_hash, then migrate-and-retry.
//   - After migration completion (claimed_pin_hash dropped):
//     a 404 means the credential is gone for good — surface
//     it to the caller as "no such user" / re-signup required.
//
// The caller — not this wrapper — decides which response is
// correct. Strategy B's authenticateLogin example below shows
// the dual-read branching.
var ErrHashIDNotFound = errors.New("argon2: hash_id not found")

func (a *vaultPINAuth) Verify(ctx context.Context, hashID, pin string) (bool, bool, error) {
    secret, err := a.client.Logical().WriteWithContext(ctx,
        fmt.Sprintf("argon2/verify/%s", hashID),
        map[string]interface{}{"password": pin})
    if err != nil {
        // The Vault API client surfaces a 404 as a non-nil error,
        // not as `secret == nil`. Detect it via *vault.ResponseError
        // so the caller can distinguish "hash_id gone" from other
        // failure modes.
        var respErr *vault.ResponseError
        if errors.As(err, &respErr) && respErr.StatusCode == 404 {
            return false, false, ErrHashIDNotFound
        }
        return false, false, fmt.Errorf("argon2 verify: %w", err)
    }
    valid, _ := secret.Data["valid"].(bool)
    drift, _ := secret.Data["policy_drift"].(bool)
    return valid, drift, nil
}

func (a *vaultPINAuth) Delete(ctx context.Context, hashID string) error {
    _, err := a.client.Logical().DeleteWithContext(ctx,
        fmt.Sprintf("argon2/hash/%s", hashID))
    return err
}
```

The `subjectID` parameter is optional in the plugin API but
strongly recommended for migration: pass your existing stable
user identifier (the wallet UUID, user ID, etc.). The plugin
returns that exact string as the `hash_id`, which makes the
schema migration below much simpler — the `hash_id` column
ends up equal to the existing user identifier column.

---

## Database schema migration

Two shapes work; pick the one that matches your existing schema.

### Shape A: `hash_id` equals the existing user identifier

This is the **end-state** when your existing user identifier
is already URL-safe (UUID, ULID, etc.): pass it as `subject_id`
on every `Hash` call, the plugin returns that identifier
verbatim as `hash_id`, and the `claimed_pin_hash` column drops
out entirely.

```sql
-- Before:
CREATE TABLE claimed_wallets (
    id              UUID PRIMARY KEY,
    -- ... other columns ...
    claimed_pin_hash TEXT NOT NULL  -- the PHC string
);

-- End state (after migration completes for ALL users):
ALTER TABLE claimed_wallets DROP COLUMN claimed_pin_hash;
-- The wallet's `id` column IS the hash_id; no new column needed.
```

**Don't drop the column at the start of the migration.** Until
every existing user has either authenticated (and triggered the
lazy migrate-on-login in Strategy B) or been force-reset
(Strategy A), `claimed_pin_hash` is the only verifier for
un-migrated users. The dropped-column SQL above is the end
state, not the day-one schema change. Keep `claimed_pin_hash`
populated and add the dual-read logic (or force-reset prompt)
described in the Rollout strategies section below.

A simple migration marker for Shape A: "this user has been
migrated iff `argon2/verify/<user.id>` does not return 404."
Strategy B's `authenticateLogin` example uses exactly this
test on the dual-read branch.

### Shape B: separate `hash_id` column

If you'd rather decouple the hash identifier from your primary
key (e.g., to allow re-hashing under a fresh ID without
touching the user record):

```sql
ALTER TABLE claimed_wallets
    ADD COLUMN pin_hash_id TEXT NULL;

-- Backfill happens as users next authenticate (see "Dual-read
-- rollout" below). Once every active user has authenticated:
ALTER TABLE claimed_wallets
    ALTER COLUMN pin_hash_id SET NOT NULL,
    DROP COLUMN claimed_pin_hash;
```

The plugin's `subject_id` and `hash_id` namespaces are flat —
they share a single keyspace under `argon2/hash/`. The plugin
accepts only `[A-Za-z0-9]` plus underscore (`_`), hyphen (`-`),
and period (`.`) — verified against `validHashID` in
`path_hash.go`. UUIDs, ULIDs, and Vault-style alphanumeric IDs
all pass; identifiers containing `/`, `:`, whitespace, or
multi-byte runes are rejected at the API boundary (see
[`api.md`](api.md)).

---

## Vault prerequisites

The plugin must be mounted before any code change ships. From
the operator's perspective:

```sh
# 1. Mount the plugin at argon2/ (see README.md for the catalog
# registration step that runs once per Vault cluster).
vault secrets enable -path=argon2 vault-plugin-secrets-argon2

# 2. Create the policy your service will use. Match the
# parameters from your prior in-process constants exactly so
# the cost is unchanged for users.
vault write argon2/policy/users \
    memory_kib=65536 \
    iterations=3 \
    parallelism=2 \
    salt_len=16 \
    key_len=32

# 3. Grant the application's Vault role the capabilities
# integration.md §"Recommended Vault policy" enumerates.
```

For in-cluster Kubernetes services, use the Kubernetes auth
method bound to the service account that runs the wallet pods.
For VMs or non-cluster workloads, AppRole is the standard
choice. Either way, the service should renew its Vault token
before TTL expiry — `github.com/hashicorp/vault/api` provides a
LifetimeWatcher helper for this.

---

## Rollout strategies

Pick one of these. None of them requires re-hashing every user
on day one.

### Strategy A: Cutover (greenfield-ish)

Use this if your service is pre-launch, or if you can afford to
require every existing user to re-set their PIN at the next
login (sending a "PIN change required" notification ahead of
the cutover).

1. Replace the in-process `HashPIN` / `VerifyPIN` call sites with
   `PINAuthenticator` from the example above for new signups and
   for the reset path described below. Keep the in-process
   `VerifyPIN` function available for the legacy column read
   below — do NOT delete it yet.
2. Schema change: if using Shape B, add the `pin_hash_id` column
   nullable. **Leave `claimed_pin_hash` populated** for now —
   dropping it strands every un-reset user.
3. On every login, branch on whether the user has been migrated:
    - **Migrated** (`pin_hash_id IS NOT NULL`, or Shape A:
      `argon2/verify/<user.id>` does not 404): call
      `pinAuth.Verify` and authenticate as normal.
    - **Not migrated** (`pin_hash_id IS NULL` or 404): prompt
      for PIN reset *instead of* verifying. On reset, call
      `pinAuth.Hash`, store the returned `hash_id`, and on the
      same transaction either set `claimed_pin_hash` to a
      tombstone marker or — when the schema allows nullability
      — `NULL` it. The user is now migrated.
4. Announce the cutover deadline. Send "PIN change required" to
   un-migrated users before the deadline.
5. After 100% of active users have reset (or the deadline has
   passed and you accept losing the long-tail of inactive
   accounts), drop the `claimed_pin_hash` column and remove
   the in-process `VerifyPIN` from the codebase.

The downside is the forced PIN reset for everyone. Acceptable
for a new service; not great for an established one.

### Strategy B: Dual-read with lazy migration

Use this if you have existing users with in-process PHC strings
and want a zero-friction migration.

1. Add a `pin_hash_id TEXT NULL` column alongside the existing
   `claimed_pin_hash TEXT NOT NULL` column.
2. Keep the in-process `VerifyPIN` function available but only
   call it on the fallback path below.
3. Replace the **login** flow with:

   ```go
   func authenticateLogin(ctx context.Context, user *User, pin string) error {
       if user.PINHashID != "" {
           // New plugin-backed user.
           valid, drift, err := pinAuth.Verify(ctx, user.PINHashID, pin)
           if err != nil {
               return err
           }
           if !valid {
               return ErrWrongPIN
           }
           if drift {
               // Opportunistic re-hash under the current policy.
               // Failure is non-fatal; queue and move on. The
               // pinPostLoginQueue carries (op, hashID, pin)
               // tuples to a bounded worker pool — see "Queue
               // for post-login background work" below for why
               // we don't `go rehash(...)` directly here.
               pinPostLoginQueue.Submit(rehashJob{
                   HashID: user.PINHashID, PIN: pin,
               })
           }
           return nil
       }
       // Legacy in-process user.
       valid, err := auth.VerifyPIN(pin, user.ClaimedPINHash)
       if err != nil {
           return err
       }
       if !valid {
           return ErrWrongPIN
       }
       // Successful legacy verify → migrate this user via the
       // same bounded background queue.
       pinPostLoginQueue.Submit(migrateJob{
           User: user, PIN: pin,
       })
       return nil
   }
   ```

4. The `migrateUserToPlugin` background function calls `Hash`
   with the user's PIN and stores the returned `hash_id` in
   `pin_hash_id`. **Do not clear `claimed_pin_hash` in the same
   transaction** — the column is `NOT NULL`, so clearing it
   would require either making it nullable first or using a
   sentinel string. Easier: leave the legacy column populated
   until the global drop in step 6. The migration marker is
   `pin_hash_id IS NOT NULL`, not the absence of the legacy
   column. If `Hash` fails, leave the legacy column intact and
   the user simply migrates on their next login.
5. The `rehash` helper (called from the drift path above)
   handles the subject_id-collision rule explicitly:

   ```go
   func rehash(ctx context.Context, auth PINAuthenticator,
       hashID, pin string) {
       // The plugin rejects POST hash/<policy> when subject_id
       // already exists (per docs/api.md §"Hash"). DELETE first
       // so the re-create with the same subject_id succeeds.
       if err := auth.Delete(ctx, hashID); err != nil {
           // Log and stop — re-doing later is fine.
           return
       }
       if _, err := auth.Hash(ctx, pin, hashID); err != nil {
           // The user is now mid-migration: old hash gone,
           // new one failed to write. Surface a metric so
           // operators can repair from the in-process column
           // (which we deliberately preserved in step 4).
           return
       }
   }
   ```

   This is the canonical price of using `subject_id` as a stable
   `hash_id`: rehash is two API calls (DELETE + POST) instead
   of one. The alternative — generating a fresh `hash_id` per
   rehash and updating the `pin_hash_id` column — is one API
   call but adds a DB write per rehash and complicates audit
   trails (the same user gets multiple `hash_id`s over time).

6. **Queue for post-login background work** — don't naively
   `go rehash(...)` or `go migrate(...)` from the request
   goroutine. Two reasons:

   - The plaintext PIN stays in memory for the lifetime of the
     background goroutine. A naive `go` per login keeps it
     resident until the Argon2id derivation completes (~50–
     100 ms each). Under load that's a meaningful sensitive-
     data lifetime extension. A bounded worker pool with an
     explicit short-lived `context.WithTimeout` derived from
     the request bounds it.
   - `go func(){}()` per login provides no backpressure. A
     traffic spike or a slow Vault produces unbounded goroutine
     growth. A bounded queue with a fixed worker count (10–50
     is typical for this workload) caps the in-flight count
     and surfaces lag as queue depth, which is observable.

   Shape of the queue:

   ```go
   type pinJob interface{ Run(context.Context, deps) error }

   type pinPostLoginPool struct {
       jobs chan pinJob
   }

   func newPinPostLoginPool(workers, queueDepth int, deps deps) *pinPostLoginPool {
       p := &pinPostLoginPool{jobs: make(chan pinJob, queueDepth)}
       for i := 0; i < workers; i++ {
           go func() {
               for j := range p.jobs {
                   ctx, cancel := context.WithTimeout(
                       context.Background(), 10*time.Second)
                   _ = j.Run(ctx, deps) // log on err
                   cancel()
               }
           }()
       }
       return p
   }

   func (p *pinPostLoginPool) Submit(j pinJob) {
       select {
       case p.jobs <- j:
       default:
           // Queue full: drop and metric. The user's drift
           // flag remains true; next login retries. For
           // unmigrated users, the legacy column is still
           // intact so a dropped migrate job is also safe.
           metrics.PINQueueDrops.Inc()
       }
   }
   ```

   `migrateJob.Run` and `rehashJob.Run` should treat the PIN
   field as ephemeral — zero it (`for i := range j.PIN { j.PIN[i] = 0 }`)
   after the derivation completes if you've moved the PIN
   into a `[]byte`. If you keep it as a `string`, Go strings
   are immutable and you can't zero them, but the lifetime is
   still bounded by the worker's iteration.

7. **Replace** the signup flow to call only `Hash` and store
   only `pin_hash_id` from day one.
8. After the migration tail flattens (typically two PIN
   lifecycles for the long-tail of inactive users), force-reset
   any remaining users where `pin_hash_id IS NULL` and drop the
   `claimed_pin_hash` column.

The dual-read window means the in-process Argon2id
implementation stays in your binary until the column is
dropped. That's fine — your CI keeps testing it; the only risk
is dependency drift on `golang.org/x/crypto/argon2` over a long
window. v1.x of the plugin will continue to accept and verify
PHC strings produced by `golang.org/x/crypto/argon2`, so
nothing breaks if the migration takes longer than expected.

### Strategy C: Bulk import (operator-driven)

Use this if you can afford an outage window and don't want a
long dual-read tail. Standard pattern:

1. Take the service offline.
2. Run a script that for each user:
   a. Reads `claimed_pin_hash` from the DB.
   b. POSTs the PHC string directly to the plugin via a
      one-off operator endpoint... **except this plugin
      doesn't have one.** It only accepts plaintext passwords
      on `Hash`, by design — the threat model assumes the
      operator never sees the plaintext. So this strategy
      requires either (a) forcing PIN reset on every user
      after import (no different from Strategy A), or
      (b) using your own Vault tooling to `vault kv put`
      stored hashes directly into the plugin's storage path,
      which violates the audit-log integrity guarantee.

We do **not** recommend Strategy C. The plugin's design
explicitly does not provide a "trust this PHC string"
ingestion path; supporting one would create an operator-
visible bypass that defeats the audit trail. Choose A or B.

A v1.x roadmap item is a bulk-import API gated behind a Vault
policy capability so the operator path is at least
audit-logged. Until that lands, prefer Strategy B.

---

## Operational considerations

- **Vault is now on the login path.** Every login does one
  network round-trip to Vault and one server-side Argon2id
  derivation (~50–100 ms of Vault CPU at the default
  parameters). Plan Vault's CPU and memory budget accordingly:
  64 MiB per concurrent verify means a server handling 100
  concurrent logins reserves ~6.4 GiB for Argon2id work
  buffers.
- **Vault availability dictates login availability.** Add Vault
  health to your service's readiness probe with care — failing
  readiness on a brief Vault hiccup may take more of your fleet
  out than warranted. A more nuanced pattern: serve a degraded
  401 from logins during a Vault outage but keep already-
  authenticated sessions running.
- **Audit log volume.** Every `verify` writes one audit entry.
  At sustained login rates, the audit device must keep up; the
  `file` device on local SSD handles tens of thousands of
  entries per second, but a syslog or network audit device may
  bottleneck earlier.
- **Token renewal.** Make sure the service's Vault token
  renewal interval is shorter than the token's TTL. The
  `vault/api` `LifetimeWatcher` handles this; verify it's wired
  in before the migration ships.
- **Rate limiting.** This plugin does NOT implement its own
  rate limiting (see `docs/threat-model.md` §"What this plugin
  does NOT defend against"). Use Vault's quota system
  (`sys/quotas/rate-limit/`) on `argon2/verify/+` to cap a
  compromised application server's brute-force throughput.

---

## Verification checklist

Before declaring the migration complete:

- [ ] `pinAuth.Hash` returns a non-empty `hash_id` for a new
      user signup.
- [ ] `pinAuth.Verify` returns `(true, false, nil)` for the
      correct PIN immediately after signup.
- [ ] `pinAuth.Verify` returns `(false, false, nil)` for a
      wrong PIN (and **not** a 4xx error — see
      [`api.md`](api.md) §"Verify").
- [ ] `pinAuth.Delete` followed by `pinAuth.Verify` returns
      a not-found error.
- [ ] Vault audit log contains the `subject_id` and
      `argon2/hash/<policy>` path, and the `password` field is
      hashed (`hmac-sha256(...)`) rather than plaintext.
- [ ] Failed-login rate is unchanged or lower vs the
      in-process baseline (no surprises in the Vault round-
      trip behavior).
- [ ] If using Strategy B: the dual-read fallback fires on
      legacy users, and `migrateUserToPlugin` writes a fresh
      `pin_hash_id` on success.

---

## References

- [`integration.md`](integration.md) — green-field integration
  shape, full Vault policy template, Go client example.
- [`api.md`](api.md) — wire protocol and capability
  requirements.
- [`threat-model.md`](threat-model.md) — what the plugin
  defends against and what it doesn't, including required
  preconditions.
- [doro-wallet `internal/auth/pin.go`](https://github.com/xiroko-inc/doro-wallet/blob/main/internal/auth/pin.go) — the reference "before" implementation this guide migrates from.
