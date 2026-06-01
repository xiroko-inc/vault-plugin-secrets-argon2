## Decision: Add an `overwrite` parameter to the `hash/<policy>` path so an existing subject's hash can be REPLACED in a single atomic storage write, rather than forcing consumers to delete-then-rehash.

## Context: xiroko-inc/doro#176 (self-service participant PIN change)

The wallet-service needs a participant-facing "change PIN" flow. The PIN is
stored as an Argon2id hash in this plugin, keyed by `subject_id` =
`wallet_uuid`. Changing the PIN means replacing the stored hash for an
existing subject.

The plugin's `hash` create deliberately REJECTS an existing `subject_id`
("already exists; DELETE before re-hashing") — a create-only contract that
protects the first-hash (claim) path from an accidental clobber. So the only
way to change a PIN with the original API was, consumer-side:
`Verify(current) → Delete(slot) → Hash(new)`. That delete-then-rehash has a
window: if `Hash(new)` fails (a transient Vault blip) after the `Delete`,
the subject is left with NO usable hash — exactly the "stranded
claimed-but-PIN-less wallet" class that doro#164 (atomic claim) was filed to
eliminate. Carrying a compensating-rollback (re-hash the old PIN on failure)
in every consumer is fragile and replicates the anti-pattern #164 warned
against.

## Alternatives Considered

- **A — `overwrite` param on the existing `hash` path (chosen).** A
  backward-compatible boolean: when `overwrite=true` and the subject exists,
  skip the collision check and let the existing single `Storage.Put` replace
  the entry. Vault's `Storage.Put` is an atomic upsert — the slot goes
  old-hash → new-hash in one write, never empty.
- **B — A dedicated `change`/`rehash` path** that verifies the old password
  AND stores the new one in one server-side call. Most encapsulated, but a
  larger new API surface (a second password field, its own path + tests +
  policy grant) for marginal benefit over A.
- **C — Consumer-side delete-then-rehash with compensating restore.** No
  plugin change, but fragile (residual stranding window during a Vault
  outage striking between the delete and both hash attempts) and pushes the
  atomicity burden onto every consumer.

## Reasoning: A won

- **Atomic by construction.** The replace is a single `Storage.Put` — there
  is no intermediate empty state, so the #164 stranding class is eliminated
  at the source rather than mitigated per-consumer.
- **Backward-compatible.** `overwrite` defaults `false`, so the create-only
  collision-reject contract is unchanged for first-hash callers (claim). Only
  a deliberate credential-change opts in.
- **No new policy grant.** Same path (`hash/<policy>`), same verb
  (`UpdateOperation`) — just an extra body field. Consumers already holding
  `update` on `argon2/hash/*` (the wallet-service does) need no policy edit.
- **Simplest correct consumer.** Change-PIN collapses to
  `Verify(current) → Hash(new, overwrite=true)` — no delete, no restore dance.
- **Reusable.** Any future credential rotation gets atomic replace for free.

## Trade-offs Accepted

- The verify-then-overwrite is still two client calls, so there's a benign
  read-modify window between them (the same authenticated subject racing
  itself) — not a correctness hazard, since the destructive step (the
  overwrite) is itself atomic and idempotent.
- `overwrite=true` removes the audit-noticeable "DELETE before re-hash" speed
  bump for the opt-in path; acceptable because a deliberate change-credential
  caller IS the audited actor, and the default path keeps the guard.
- Shipping requires a plugin release → rebuild of the `xiroko-vault` image →
  re-register (new SHA256/version) + reload in Vault. The established
  `bootstrap-exercise-argon2.sh` re-register-on-SHA-drift flow handles it.

## Supersedes: None (complements doro#164 — same atomicity principle, applied at the plugin layer).
