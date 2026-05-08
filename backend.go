// Vault secrets-engine backend wiring. The backend struct embeds
// *framework.Backend; its only responsibility is composing the
// path tables defined in path_policy.go, path_hash.go, and
// path_verify.go. All cryptographic logic lives in argon2id.go.
package argon2id

import (
	"context"
	"strings"

	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
)

// Storage path prefixes inside logical.Storage.
const (
	policyStoragePrefix = "policy/"
	hashStoragePrefix   = "hash/"
)

// backend is the Vault secrets engine. It carries no per-request state
// — every handler reads from and writes to the request-scoped
// logical.Storage.
type backend struct {
	*framework.Backend
}

// Factory satisfies the logical.Factory signature consumed by the
// Vault plugin host.
func Factory(ctx context.Context, conf *logical.BackendConfig) (logical.Backend, error) {
	b, err := newBackend()
	if err != nil {
		return nil, err
	}
	if err := b.Setup(ctx, conf); err != nil {
		return nil, err
	}
	return b, nil
}

func newBackend() (*backend, error) {
	b := &backend{}
	b.Backend = &framework.Backend{
		Help:         strings.TrimSpace(backendHelp),
		BackendType:  logical.TypeLogical,
		PathsSpecial: &logical.Paths{
			// Every path requires a Vault token. No unauthenticated
			// access — the whole point of this plugin is that
			// password material lives behind the Vault auth boundary.
		},
		Paths: framework.PathAppend(
			b.policyPaths(),
			b.hashPaths(),
			b.verifyPaths(),
		),
	}
	return b, nil
}

const backendHelp = `
The argon2id secrets engine provides Argon2id password hashing as a
service. Applications POST plaintext passwords on signup and login;
Vault stores the hash and returns an opaque hash_id. The hash material
never leaves Vault — verification happens server-side. Compromise of
the application database reveals only IDs, not hashes.

See https://github.com/xiroko-inc/vault-plugin-secrets-argon2 for
full documentation.
`
