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

// PluginVersion is the running plugin version reported to Vault via
// framework.Backend.RunningVersion (visible in `vault plugin info`).
// The cmd/vault-plugin-secrets-argon2 entry point sets it from the
// `version` ldflag stamped by goreleaser at release-build time
// (-X main.version=<tag>).
//
// Defaults to "" because Vault validates RunningVersion as semver
// and rejects unstamped sentinel strings ("dev", "snapshot", etc.).
// An empty string disables the version field — operators see no
// version in `vault plugin info`, which is the right signal for an
// un-tagged local build.
//
// Set this BEFORE the plugin host calls Factory — assignment after
// Factory has been called won't propagate to a backend that's
// already been constructed.
var PluginVersion = ""

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
		Help:           strings.TrimSpace(backendHelp),
		BackendType:    logical.TypeLogical,
		RunningVersion: PluginVersion,
		PathsSpecial:   &logical.Paths{
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
