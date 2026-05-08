// Path handlers for /policy/<name>: CRUD on Argon2id parameter
// policies. Each policy is a named tuple of (memory, iterations,
// parallelism, salt_len, key_len) — the §4.2 cost knobs.
//
// The PHC string stored alongside every hash carries its own
// parameters, so policy updates do NOT invalidate existing hashes;
// they only affect new Hash calls and surface as `policy_drift: true`
// in Verify responses for hashes created under the prior parameters.
package argon2id

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
)

// storedPolicy is the shape persisted under policy/<name>.
type storedPolicy struct {
	Algorithm   string    `json:"algorithm"`
	MemoryKiB   uint32    `json:"memory_kib"`
	Iterations  uint32    `json:"iterations"`
	Parallelism uint8     `json:"parallelism"`
	SaltLen     uint32    `json:"salt_len"`
	KeyLen      uint32    `json:"key_len"`
	CreatedAt   time.Time `json:"created_at"`
	UpdatedAt   time.Time `json:"updated_at"`
}

func (sp storedPolicy) toParams() Params {
	return Params{
		MemoryKiB:   sp.MemoryKiB,
		Iterations:  sp.Iterations,
		Parallelism: sp.Parallelism,
		SaltLen:     sp.SaltLen,
		KeyLen:      sp.KeyLen,
	}
}

func (b *backend) policyPaths() []*framework.Path {
	return []*framework.Path{
		{
			Pattern: "policy/" + framework.GenericNameRegex("name"),
			Fields: map[string]*framework.FieldSchema{
				"name": {
					Type:        framework.TypeString,
					Description: "Name of the hashing policy.",
				},
				"memory_kib": {
					Type:        framework.TypeInt,
					Description: "Argon2id memory cost in KiB. Bounds: [8192, 1048576] (1 MiB to 1 GiB).",
				},
				"iterations": {
					Type:        framework.TypeInt,
					Description: "Argon2id iteration count. Bounds: [1, 100].",
				},
				"parallelism": {
					Type:        framework.TypeInt,
					Description: "Argon2id parallelism factor. Bounds: [1, 16].",
				},
				"salt_len": {
					Type:        framework.TypeInt,
					Description: "Salt length in bytes. Bounds: [16, 64].",
				},
				"key_len": {
					Type:        framework.TypeInt,
					Description: "Derived-key length in bytes. Bounds: [32, 64].",
				},
			},
			Operations: map[logical.Operation]framework.OperationHandler{
				logical.UpdateOperation: &framework.PathOperation{Callback: b.handlePolicyWrite},
				logical.CreateOperation: &framework.PathOperation{Callback: b.handlePolicyWrite},
				logical.ReadOperation:   &framework.PathOperation{Callback: b.handlePolicyRead},
				logical.DeleteOperation: &framework.PathOperation{Callback: b.handlePolicyDelete},
			},
			ExistenceCheck: b.handlePolicyExists,
			HelpSynopsis:   "Create, read, update, or delete an Argon2id parameter policy.",
		},
		{
			Pattern: "policy/?$",
			Operations: map[logical.Operation]framework.OperationHandler{
				logical.ListOperation: &framework.PathOperation{Callback: b.handlePolicyList},
			},
			HelpSynopsis: "List all Argon2id policies.",
		},
	}
}

func (b *backend) handlePolicyExists(ctx context.Context, req *logical.Request, d *framework.FieldData) (bool, error) {
	name := d.Get("name").(string)
	entry, err := req.Storage.Get(ctx, policyStoragePrefix+name)
	return err == nil && entry != nil, nil
}

func (b *backend) handlePolicyWrite(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	name := d.Get("name").(string)
	if name == "" {
		return logical.ErrorResponse("policy name is required"), nil
	}

	now := time.Now().UTC()
	existing, err := readPolicy(ctx, req.Storage, name)
	if err != nil {
		return nil, err
	}

	sp := storedPolicy{
		Algorithm:   "argon2id",
		MemoryKiB:   DefaultMemoryKiB,
		Iterations:  DefaultIterations,
		Parallelism: DefaultParallelism,
		SaltLen:     DefaultSaltLen,
		KeyLen:      DefaultKeyLen,
		CreatedAt:   now,
		UpdatedAt:   now,
	}
	if existing != nil {
		sp = *existing
		sp.UpdatedAt = now
	}

	if v, ok := d.GetOk("memory_kib"); ok {
		sp.MemoryKiB = uint32(v.(int))
	}
	if v, ok := d.GetOk("iterations"); ok {
		sp.Iterations = uint32(v.(int))
	}
	if v, ok := d.GetOk("parallelism"); ok {
		sp.Parallelism = uint8(v.(int))
	}
	if v, ok := d.GetOk("salt_len"); ok {
		sp.SaltLen = uint32(v.(int))
	}
	if v, ok := d.GetOk("key_len"); ok {
		sp.KeyLen = uint32(v.(int))
	}

	if err := sp.toParams().Validate(); err != nil {
		return logical.ErrorResponse(err.Error()), nil
	}

	if err := writePolicy(ctx, req.Storage, name, &sp); err != nil {
		return nil, err
	}
	return policyResponse(name, &sp), nil
}

func (b *backend) handlePolicyRead(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	name := d.Get("name").(string)
	sp, err := readPolicy(ctx, req.Storage, name)
	if err != nil {
		return nil, err
	}
	if sp == nil {
		return nil, nil
	}
	return policyResponse(name, sp), nil
}

func (b *backend) handlePolicyDelete(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	name := d.Get("name").(string)

	// Reject delete if any hash still references this policy. This is
	// an O(N) storage scan over hash IDs — acceptable for the
	// policy-mutation path which is rare; not used on the hot
	// hash/verify paths.
	hashIDs, err := req.Storage.List(ctx, hashStoragePrefix)
	if err != nil {
		return nil, fmt.Errorf("listing hashes for policy reference check: %w", err)
	}
	for _, id := range hashIDs {
		entry, err := req.Storage.Get(ctx, hashStoragePrefix+id)
		if err != nil {
			return nil, fmt.Errorf("reading hash %s: %w", id, err)
		}
		if entry == nil {
			continue
		}
		var stored storedHash
		if err := json.Unmarshal(entry.Value, &stored); err != nil {
			continue
		}
		if stored.Policy == name {
			return logical.ErrorResponse(
				"cannot delete policy %q: hash %s still references it; delete dependent hashes first",
				name, id), nil
		}
	}

	if err := req.Storage.Delete(ctx, policyStoragePrefix+name); err != nil {
		return nil, err
	}
	return nil, nil
}

func (b *backend) handlePolicyList(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	keys, err := req.Storage.List(ctx, policyStoragePrefix)
	if err != nil {
		return nil, err
	}
	return logical.ListResponse(keys), nil
}

func readPolicy(ctx context.Context, s logical.Storage, name string) (*storedPolicy, error) {
	if name == "" {
		return nil, nil
	}
	entry, err := s.Get(ctx, policyStoragePrefix+name)
	if err != nil {
		return nil, err
	}
	if entry == nil {
		return nil, nil
	}
	var sp storedPolicy
	if err := json.Unmarshal(entry.Value, &sp); err != nil {
		return nil, fmt.Errorf("decoding stored policy %q: %w", name, err)
	}
	return &sp, nil
}

func writePolicy(ctx context.Context, s logical.Storage, name string, sp *storedPolicy) error {
	if strings.ContainsAny(name, "/ ") {
		return fmt.Errorf("invalid policy name %q", name)
	}
	entry, err := logical.StorageEntryJSON(policyStoragePrefix+name, sp)
	if err != nil {
		return err
	}
	return s.Put(ctx, entry)
}

func policyResponse(name string, sp *storedPolicy) *logical.Response {
	return &logical.Response{
		Data: map[string]interface{}{
			"name":        name,
			"algorithm":   sp.Algorithm,
			"memory_kib":  sp.MemoryKiB,
			"iterations":  sp.Iterations,
			"parallelism": sp.Parallelism,
			"salt_len":    sp.SaltLen,
			"key_len":     sp.KeyLen,
			"created_at":  sp.CreatedAt.Format(time.RFC3339Nano),
			"updated_at":  sp.UpdatedAt.Format(time.RFC3339Nano),
		},
	}
}
