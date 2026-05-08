// Path handlers for /hash/<policy> (POST), /hash/<hash_id> (DELETE),
// and /hash (LIST). Hash IDs are either server-generated 32-character
// hex strings (16 random bytes encoded) or caller-supplied
// subject_ids — both flow through the same storage path. The two namespaces are NOT distinguished at
// rest: a caller-supplied subject_id "u-1" and a generated hex are
// indistinguishable to the storage layer, by design.
//
// POST /hash/<policy> and DELETE /hash/<hash_id> share one
// framework.Path pattern ("hash/<name>") and are dispatched by HTTP
// verb in the Operations map: UpdateOperation → handleHashCreate
// reads `name` as a policy and stores under the generated/supplied
// hash_id; DeleteOperation → handleHashDelete reads `name` as a
// hash_id and removes that record. Splitting them into two patterns
// collides on the framework router (same regex shape), so we keep
// one path entry and dispatch by Operation. The same trade-off is
// repeated in hashPaths() with an inline comment.
package argon2id

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
)

const maxListPageSize = 1000

// storedHash is the shape persisted under hash/<id>. The PHC string
// fully encodes parameters, salt, and key — Verify can re-derive even
// if the named policy is later updated or deleted.
type storedHash struct {
	Policy    string    `json:"policy"`
	PHC       string    `json:"phc"`
	CreatedAt time.Time `json:"created_at"`
}

func (b *backend) hashPaths() []*framework.Path {
	return []*framework.Path{
		{
			// One pattern serves two semantics distinguished by HTTP
			// verb: POST treats `name` as a policy name and creates a
			// fresh hash; DELETE treats `name` as a hash_id and
			// removes that record. The URL shape is identical because
			// in practice consumers pick one or the other and the path
			// is just an opaque string to them. Splitting them into
			// two framework.Path entries collides on routing, so we
			// keep one entry and dispatch by Operation.
			Pattern: "hash/" + framework.GenericNameRegex("name"),
			Fields: map[string]*framework.FieldSchema{
				"name": {
					Type:        framework.TypeString,
					Description: "On POST: policy name. On DELETE: hash_id.",
				},
				"password": {
					Type:        framework.TypeString,
					Description: "Plaintext password to hash. NEVER logged.",
					DisplayAttrs: &framework.DisplayAttributes{
						Sensitive: true,
					},
				},
				"subject_id": {
					Type: framework.TypeString,
					Description: "Optional caller-supplied stable identifier (e.g. user UUID). " +
						"If omitted, a server-generated 32-character hex ID (16 random bytes) is returned. " +
						"If supplied and an existing hash already uses it, the request is rejected.",
				},
			},
			Operations: map[logical.Operation]framework.OperationHandler{
				logical.UpdateOperation: &framework.PathOperation{Callback: b.handleHashCreate},
				logical.DeleteOperation: &framework.PathOperation{Callback: b.handleHashDelete},
			},
			HelpSynopsis: "POST a password to hash under a policy, or DELETE a stored hash by ID.",
		},
		{
			Pattern: "hash/?$",
			Operations: map[logical.Operation]framework.OperationHandler{
				logical.ListOperation: &framework.PathOperation{Callback: b.handleHashList},
			},
			HelpSynopsis: "List stored hash IDs (no hash material returned).",
		},
	}
}

func (b *backend) handleHashCreate(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	policyName := d.Get("name").(string)
	password := d.Get("password").(string)
	subjectID := d.Get("subject_id").(string)

	if policyName == "" {
		return logical.ErrorResponse("policy name is required"), nil
	}
	if password == "" {
		return logical.ErrorResponse("password is required"), nil
	}

	policy, err := readPolicy(ctx, req.Storage, policyName)
	if err != nil {
		return nil, err
	}
	if policy == nil {
		return logical.ErrorResponse("policy %q does not exist", policyName), nil
	}

	hashID := subjectID
	if hashID == "" {
		generated, err := newHashID()
		if err != nil {
			return nil, fmt.Errorf("generating hash id: %w", err)
		}
		hashID = generated
	} else {
		// Reject subject_ids that the framework's path regex
		// (GenericNameRegex) wouldn't match. Storing one would
		// produce an entry unreachable via verify/<id> and the
		// DELETE-on-hash/<id> route, since both match a single path
		// segment of safe characters.
		if !validHashID(hashID) {
			return logical.ErrorResponse(
				"subject_id %q contains characters not allowed in a path segment", hashID), nil
		}
		// Caller-supplied subject_id collision: hard 409-equivalent.
		// Forces explicit DELETE before re-Hash so the operator
		// notices and audit-logs the replacement.
		existing, err := req.Storage.Get(ctx, hashStoragePrefix+hashID)
		if err != nil {
			return nil, err
		}
		if existing != nil {
			return logical.ErrorResponse(
				"hash with subject_id %q already exists; DELETE before re-hashing", hashID), nil
		}
	}

	phc, err := Hash([]byte(password), policy.toParams())
	if err != nil {
		return nil, fmt.Errorf("argon2id hash: %w", err)
	}

	now := time.Now().UTC()
	stored := storedHash{
		Policy:    policyName,
		PHC:       phc,
		CreatedAt: now,
	}
	entry, err := logical.StorageEntryJSON(hashStoragePrefix+hashID, &stored)
	if err != nil {
		return nil, err
	}
	if err := req.Storage.Put(ctx, entry); err != nil {
		return nil, err
	}
	return &logical.Response{
		Data: map[string]interface{}{
			"hash_id":    hashID,
			"policy":     policyName,
			"created_at": now.Format(time.RFC3339Nano),
		},
	}, nil
}

func (b *backend) handleHashDelete(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	hashID := d.Get("name").(string)
	// Idempotent: silently succeed whether the entry existed or not.
	if err := req.Storage.Delete(ctx, hashStoragePrefix+hashID); err != nil {
		return nil, err
	}
	return nil, nil
}

func (b *backend) handleHashList(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	keys, err := req.Storage.List(ctx, hashStoragePrefix)
	if err != nil {
		return nil, err
	}
	if len(keys) > maxListPageSize {
		keys = keys[:maxListPageSize]
	}
	// Critically: only IDs. No PHC, no parameters, no policy names.
	return logical.ListResponse(keys), nil
}

// newHashID returns 32 hex chars (16 random bytes). Long enough to
// avoid collision in any practical deployment; short enough to fit
// comfortably in a logger or audit field.
func newHashID() (string, error) {
	buf := make([]byte, 16)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	return hex.EncodeToString(buf), nil
}

// validHashID accepts only the character set allowed by the
// framework's GenericNameRegex routing: word chars (letters, digits,
// underscore) plus hyphen and period. A subject_id that fails this
// check would be unreachable via the verify/<id> and delete/<id>
// path patterns. Reject at the boundary rather than create an
// orphan record.
func validHashID(s string) bool {
	if s == "" {
		return false
	}
	for _, r := range s {
		switch {
		case r >= 'a' && r <= 'z':
		case r >= 'A' && r <= 'Z':
		case r >= '0' && r <= '9':
		case r == '_' || r == '-' || r == '.':
		default:
			return false
		}
	}
	return true
}

func readHash(ctx context.Context, s logical.Storage, hashID string) (*storedHash, error) {
	if strings.ContainsAny(hashID, "/ ") {
		return nil, fmt.Errorf("invalid hash id %q", hashID)
	}
	entry, err := s.Get(ctx, hashStoragePrefix+hashID)
	if err != nil {
		return nil, err
	}
	if entry == nil {
		return nil, nil
	}
	var stored storedHash
	if err := json.Unmarshal(entry.Value, &stored); err != nil {
		return nil, fmt.Errorf("decoding stored hash %q: %w", hashID, err)
	}
	return &stored, nil
}
