# Integration patterns

This plugin is HTTP-shaped on the wire — your application doesn't need
to import a Go-specific SDK or an Argon2id library. Any language that
can make HTTP requests to Vault can use it.

---

## Recommended Vault policy

Grant the application:

- `update` on `argon2/hash/<policy>` for the policies it owns
- `update` on `argon2/verify/+` to verify any hash by id
- `delete` on `argon2/hash/+` for account deletion

```hcl
# Path scoped to one named policy — the app cannot create hashes
# under a different policy by accident.
path "argon2/hash/users" {
  capabilities = ["update"]
}

path "argon2/verify/+" {
  capabilities = ["update"]
}

path "argon2/hash/+" {
  capabilities = ["delete"]
}
```

The `+` wildcard matches one path segment. Refine to a path-prefix
match if your application's hash IDs share a known prefix (e.g.,
caller-supplied UUIDs).

---

## Authentication

Pick whichever Vault auth method matches your runtime:

- **Kubernetes (`auth/kubernetes`)** — recommended for in-cluster
  workloads. The pod's service account token is exchanged for a Vault
  token with the policy above.
- **AppRole (`auth/approle`)** — for VMs and stand-alone services.
- **AWS / GCP / Azure IAM** — for the corresponding cloud workloads.

Token renewal follows Vault's standard refresh pattern. The plugin
itself stores no client state.

---

## Web app login flow

```
Signup:
  app:  POST $VAULT_ADDR/v1/argon2/hash/users
        body:    {"password": "<user-supplied>", "subject_id": "<our-uuid>"}
        header:  X-Vault-Token: <kubernetes-auth-token>
  Vault → {"hash_id": "<our-uuid>", "policy": "users", "created_at": "..."}
  app:  store user with id=<our-uuid>; no password material in app DB.

Login:
  app:  POST $VAULT_ADDR/v1/argon2/verify/<our-uuid>
        body: {"password": "<user-supplied>"}
  Vault → {"valid": true|false, "policy_drift": false}
  app:  on valid=true, issue session; on valid=false, increment own
        lockout counter.

Account deletion:
  app:  DELETE $VAULT_ADDR/v1/argon2/hash/<our-uuid>
  app:  delete app row.
```

The application never imports `golang.org/x/crypto/argon2` (or its
Python / Java / Rust equivalent). It makes HTTP calls to Vault.

---

## Go client example

Using the official `github.com/hashicorp/vault/api` package:

```go
package authflow

import (
    "context"
    "fmt"

    vault "github.com/hashicorp/vault/api"
)

type PasswordAuthenticator struct {
    client *vault.Client
    policy string // e.g. "users"
}

func NewPasswordAuthenticator(client *vault.Client, policy string) *PasswordAuthenticator {
    return &PasswordAuthenticator{client: client, policy: policy}
}

// Hash creates a new hash entry under p.policy. subjectID may be empty
// to let Vault generate one; the chosen id is returned either way.
func (p *PasswordAuthenticator) Hash(ctx context.Context, password, subjectID string) (string, error) {
    secret, err := p.client.Logical().WriteWithContext(ctx,
        fmt.Sprintf("argon2/hash/%s", p.policy),
        map[string]interface{}{
            "password":   password,
            "subject_id": subjectID,
        })
    if err != nil {
        return "", fmt.Errorf("argon2 hash: %w", err)
    }
    id, _ := secret.Data["hash_id"].(string)
    return id, nil
}

// Verify returns (valid, drift, error). drift is true when the stored
// hash was produced under prior policy parameters; the caller can
// rehash on the same login to migrate the user to the current policy.
func (p *PasswordAuthenticator) Verify(ctx context.Context, hashID, password string) (bool, bool, error) {
    secret, err := p.client.Logical().WriteWithContext(ctx,
        fmt.Sprintf("argon2/verify/%s", hashID),
        map[string]interface{}{"password": password})
    if err != nil {
        return false, false, fmt.Errorf("argon2 verify: %w", err)
    }
    valid, _ := secret.Data["valid"].(bool)
    drift, _ := secret.Data["policy_drift"].(bool)
    return valid, drift, nil
}

func (p *PasswordAuthenticator) Delete(ctx context.Context, hashID string) error {
    _, err := p.client.Logical().DeleteWithContext(ctx,
        fmt.Sprintf("argon2/hash/%s", hashID))
    return err
}
```

---

## Handling `policy_drift`

When `verify` returns `policy_drift: true`, the stored hash was
produced under prior policy parameters. To migrate that user to the
current parameters in a single login, call `hash` with their
`subject_id` after deleting the prior record:

```go
ok, drift, err := auth.Verify(ctx, userID, password)
if err != nil || !ok {
    return err // password wrong or hash gone
}
if drift {
    if err := auth.Delete(ctx, userID); err != nil {
        return err
    }
    if _, err := auth.Hash(ctx, password, userID); err != nil {
        return err
    }
}
// session = mintSession(userID)
```

This pays the cost of an extra Argon2id derivation only on logins
where the policy has been bumped — typically rare.

---

## Failed-login attribution

The `subject_id` is preserved through to Vault's audit log. Audit a
trail of `verify/<subject_id>` calls returning `valid=false` and you
have failed-login attribution by user, free.

The `password` field is redacted; the `subject_id`, `hash_id`,
`policy`, and timestamps are NOT — they are the audit trail.
