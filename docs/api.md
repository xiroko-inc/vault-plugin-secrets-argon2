# API reference

All paths are mount-relative. Examples assume the plugin is mounted at
`argon2/`. Replace the mount path if you mount it elsewhere.

Every path requires a Vault token with the appropriate capability.
There are no unauthenticated paths.

---

## Policies

A policy is a named tuple of Argon2id cost parameters. Hashes carry a
copy of their parameters in the PHC string itself, so a stored hash
remains verifiable even after the policy is updated or deleted — the
named policy only affects new hashes and is the basis for the
`policy_drift` flag returned by `verify`.

### Create / update — `PUT argon2/policy/<name>`

Request body — all fields optional, defaults applied for any field
omitted on first create:

```json
{
  "memory_kib":  65536,
  "iterations":  3,
  "parallelism": 2,
  "salt_len":    16,
  "key_len":     32
}
```

Response:

```json
{
  "name":        "users",
  "algorithm":   "argon2id",
  "memory_kib":  65536,
  "iterations":  3,
  "parallelism": 2,
  "salt_len":    16,
  "key_len":     32,
  "created_at":  "2026-05-07T12:34:56.789Z",
  "updated_at":  "2026-05-07T12:34:56.789Z"
}
```

Hard bounds — values outside these ranges are rejected with a 4xx:

| Field         | Min   | Max     |
|---------------|-------|---------|
| `memory_kib`  | 8192  | 1048576 |
| `iterations`  | 1     | 100     |
| `parallelism` | 1     | 16      |
| `salt_len`    | 16    | 64      |
| `key_len`     | 32    | 64      |

Capability required: `update` (or `create` if the policy doesn't
already exist).

### Read — `GET argon2/policy/<name>`

Returns the same shape as create. 404 if the policy doesn't exist.

Capability required: `read`.

### Delete — `DELETE argon2/policy/<name>`

Rejects with a 4xx if any stored hash still references the policy. The
caller must delete or rehash dependent records first.

Capability required: `delete`.

### List — `LIST argon2/policy`

```json
{ "keys": ["service-accounts", "users"] }
```

Capability required: `list`.

---

## Hashes

### Create — `POST argon2/hash/<policy>`

Request body:

```json
{
  "password":   "<plaintext>",
  "subject_id": "<optional caller-supplied stable id>"
}
```

- If `subject_id` is omitted, the server returns a 32-byte hex
  `hash_id`.
- If `subject_id` is supplied and a hash already uses it, the request
  is rejected with a 4xx (the caller must `DELETE` and re-`POST` to
  replace).

Response:

```json
{
  "hash_id":    "2c1f-...",
  "policy":     "users",
  "created_at": "2026-05-07T12:34:56.789Z"
}
```

Capability required: `update`.

The `password` field is marked `Sensitive` and is redacted in Vault's
audit log. The stored PHC string is never returned in any response.

### Delete — `DELETE argon2/hash/<hash_id>`

Idempotent. Returns 204 whether the hash existed or not.

Capability required: `delete`.

### List — `LIST argon2/hash`

```json
{ "keys": ["2c1f-...", "8a3b-..."] }
```

Page size is capped at 1000 ids. The response **never** includes hash
material, parameters, or password content — only ids.

Capability required: `list`.

---

## Verify

### Verify — `POST argon2/verify/<hash_id>`

Request body:

```json
{ "password": "<plaintext>" }
```

Response:

```json
{
  "valid":        true,
  "policy_drift": false
}
```

- `valid` is the boolean result of the constant-time compare. Returns
  status `200` regardless of correctness — wrong passwords are not
  4xx, because middleware that translates 4xx into "abort processing"
  treats wrong-password as a server error rather than a counted
  failed-login attempt.
- `policy_drift` is `true` when the stored hash's parameters differ
  from the named policy's *current* parameters. Lets callers detect
  rehash-on-next-login opportunities.
- Returns `404` if the `hash_id` doesn't exist. This is an error: the
  caller has a stale ID.
- Returns `5xx` (with detail) if the stored PHC is malformed or out
  of bounds — operational failure, not wrong password.

Capability required: `update`.

The `password` field is redacted in audit logs.

---

## Errors

All error responses follow Vault's standard error envelope:

```json
{ "errors": ["...one or more strings..."] }
```

Common cases:

| Status | When                                                      |
|--------|-----------------------------------------------------------|
| 400    | Missing required field, parameter out of bounds           |
| 403    | Vault policy denies the capability for the path           |
| 404    | Policy or hash_id does not exist                          |
| 409    | `subject_id` collision on create                          |
| 500    | Stored PHC is corrupt or out of bounds                    |
