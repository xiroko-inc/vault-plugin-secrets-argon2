// Path handler for /verify/<hash_id>. Verify is the read-mostly hot
// path: the application calls it on every login. Returns
// {valid, policy_drift} regardless of password correctness — wrong
// passwords are NOT 4xx errors because middlewares often translate
// 4xx into "stop processing" which is the wrong semantic for a
// failed-login increment.
//
// 404 is returned only when the hash_id doesn't exist. That IS an
// error: the caller has a stale ID and should remove it from their
// own database.
package argon2id

import (
	"context"

	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
)

func (b *backend) verifyPaths() []*framework.Path {
	return []*framework.Path{
		{
			Pattern: "verify/" + framework.GenericNameRegex("hash_id"),
			Fields: map[string]*framework.FieldSchema{
				"hash_id": {
					Type:        framework.TypeString,
					Description: "Hash identifier to verify against.",
				},
				"password": {
					Type:        framework.TypeString,
					Description: "Plaintext password to verify. NEVER logged.",
					DisplayAttrs: &framework.DisplayAttributes{
						Sensitive: true,
					},
				},
			},
			Operations: map[logical.Operation]framework.OperationHandler{
				logical.UpdateOperation: &framework.PathOperation{Callback: b.handleVerify},
			},
			HelpSynopsis: "Verify a password against a stored hash.",
		},
	}
}

func (b *backend) handleVerify(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	hashID := d.Get("hash_id").(string)
	password := d.Get("password").(string)

	if password == "" {
		return logical.ErrorResponse("password is required"), nil
	}

	stored, err := readHash(ctx, req.Storage, hashID)
	if err != nil {
		return nil, err
	}
	if stored == nil {
		// 404-equivalent: a nil response with nil error on a non-LIST
		// path is the framework's "not found" signal.
		return nil, nil
	}

	// Look up the named policy as it stands today. If the policy was
	// deleted (or never existed for hashes created before strict
	// reference-checking), drift is still computed against the
	// stored PHC's own embedded params via Verify; we just pass
	// Params{} to suppress drift comparison in that edge case.
	current := Params{}
	policy, err := readPolicy(ctx, req.Storage, stored.Policy)
	if err != nil {
		return nil, err
	}
	if policy != nil {
		current = policy.toParams()
	}

	valid, drift, err := Verify([]byte(password), stored.PHC, current)
	if err != nil {
		// Stored PHC is corrupt or out-of-bounds — operational error,
		// surface to caller so they can take action (typically: rehash
		// from a known-good source). Distinct from valid=false.
		return nil, err
	}
	return &logical.Response{
		Data: map[string]interface{}{
			"valid":        valid,
			"policy_drift": drift,
		},
	}, nil
}
