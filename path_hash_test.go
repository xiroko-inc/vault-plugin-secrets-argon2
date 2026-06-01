package argon2id

import (
	"context"
	"testing"

	"github.com/hashicorp/vault/sdk/logical"
)

func mustCreatePolicy(t *testing.T, b *backend, store logical.Storage, name string) {
	t.Helper()
	resp, err := b.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      "policy/" + name,
		Storage:   store,
	})
	if err != nil {
		t.Fatalf("create policy %s: %v", name, err)
	}
	if resp != nil && resp.IsError() {
		t.Fatalf("create policy %s: %v", name, resp.Error())
	}
}

func TestHash_generatesIDWhenSubjectIDOmitted(t *testing.T) {
	b, store := newTestBackend(t)
	mustCreatePolicy(t, b, store, "users")

	resp, err := b.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      "hash/users",
		Data:      map[string]interface{}{"password": "letmein"},
		Storage:   store,
	})
	if err != nil {
		t.Fatalf("hash: %v", err)
	}
	if resp == nil || resp.IsError() {
		t.Fatalf("hash error: %+v", resp)
	}
	id, _ := resp.Data["hash_id"].(string)
	if len(id) != 32 {
		t.Errorf("hash_id length: got %d, want 32 hex chars", len(id))
	}
}

func TestHash_usesSuppliedSubjectID(t *testing.T) {
	b, store := newTestBackend(t)
	mustCreatePolicy(t, b, store, "users")

	resp, err := b.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      "hash/users",
		Data:      map[string]interface{}{"password": "p", "subject_id": "wallet-uuid-1"},
		Storage:   store,
	})
	if err != nil || resp == nil || resp.IsError() {
		t.Fatalf("hash: err=%v resp=%+v", err, resp)
	}
	if id, _ := resp.Data["hash_id"].(string); id != "wallet-uuid-1" {
		t.Errorf("hash_id: got %q, want wallet-uuid-1", id)
	}
}

func TestHash_subjectIDCollisionRejected(t *testing.T) {
	b, store := newTestBackend(t)
	mustCreatePolicy(t, b, store, "users")
	ctx := context.Background()

	_, err := b.HandleRequest(ctx, &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      "hash/users",
		Data:      map[string]interface{}{"password": "p", "subject_id": "u-1"},
		Storage:   store,
	})
	if err != nil {
		t.Fatalf("first hash: %v", err)
	}

	resp, err := b.HandleRequest(ctx, &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      "hash/users",
		Data:      map[string]interface{}{"password": "different", "subject_id": "u-1"},
		Storage:   store,
	})
	if err != nil {
		t.Fatalf("second hash: %v", err)
	}
	if resp == nil || !resp.IsError() {
		t.Errorf("expected error response on collision, got %+v", resp)
	}
}

// overwrite=true atomically REPLACES an existing subject's hash (the
// atomic-credential-change primitive #176 needs). Asserted via the
// verify path against known passwords — the new PIN verifies and the
// old one no longer does, proving the slot went old→new.
func TestHash_overwriteReplacesExisting(t *testing.T) {
	b, store := newTestBackend(t)
	mustCreatePolicy(t, b, store, "users")
	ctx := context.Background()

	hash := func(pw string, overwrite bool) *logical.Response {
		data := map[string]interface{}{"password": pw, "subject_id": "u-1"}
		if overwrite {
			data["overwrite"] = true
		}
		resp, err := b.HandleRequest(ctx, &logical.Request{
			Operation: logical.UpdateOperation, Path: "hash/users", Data: data, Storage: store,
		})
		if err != nil {
			t.Fatalf("hash(%q, overwrite=%v): %v", pw, overwrite, err)
		}
		return resp
	}
	verify := func(pw string) bool {
		resp, err := b.HandleRequest(ctx, &logical.Request{
			Operation: logical.UpdateOperation, Path: "verify/u-1",
			Data: map[string]interface{}{"password": pw}, Storage: store,
		})
		if err != nil || resp == nil || resp.IsError() {
			t.Fatalf("verify(%q): err=%v resp=%+v", pw, err, resp)
		}
		v, _ := resp.Data["valid"].(bool)
		return v
	}

	if resp := hash("old-pin", false); resp.IsError() {
		t.Fatalf("initial hash errored: %+v", resp)
	}
	if !verify("old-pin") {
		t.Fatal("old-pin should verify after the initial hash")
	}

	if resp := hash("new-pin", true); resp.IsError() {
		t.Fatalf("overwrite hash should succeed (not collide), got: %+v", resp)
	}
	if !verify("new-pin") {
		t.Error("new-pin should verify after overwrite")
	}
	if verify("old-pin") {
		t.Error("old-pin should NOT verify after overwrite — the slot was replaced")
	}
}

// overwrite=true on a subject that doesn't exist yet behaves like a
// normal create (no collision to skip) — so a change-pin caller need
// not special-case "first hash vs replace".
func TestHash_overwriteOnFreshSubjectCreates(t *testing.T) {
	b, store := newTestBackend(t)
	mustCreatePolicy(t, b, store, "users")

	resp, err := b.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      "hash/users",
		Data:      map[string]interface{}{"password": "p", "subject_id": "fresh-1", "overwrite": true},
		Storage:   store,
	})
	if err != nil || resp == nil || resp.IsError() {
		t.Fatalf("overwrite-on-fresh: err=%v resp=%+v", err, resp)
	}
	if id, _ := resp.Data["hash_id"].(string); id != "fresh-1" {
		t.Errorf("hash_id: got %q, want fresh-1", id)
	}
}

func TestHash_unknownPolicyRejected(t *testing.T) {
	b, store := newTestBackend(t)
	resp, err := b.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      "hash/nonexistent",
		Data:      map[string]interface{}{"password": "p"},
		Storage:   store,
	})
	if err != nil {
		t.Fatalf("hash: %v", err)
	}
	if resp == nil || !resp.IsError() {
		t.Errorf("expected error, got %+v", resp)
	}
}

func TestHash_emptyPasswordRejected(t *testing.T) {
	b, store := newTestBackend(t)
	mustCreatePolicy(t, b, store, "users")
	resp, err := b.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      "hash/users",
		Data:      map[string]interface{}{"password": ""},
		Storage:   store,
	})
	if err != nil {
		t.Fatalf("hash: %v", err)
	}
	if resp == nil || !resp.IsError() {
		t.Errorf("expected error response on empty password, got %+v", resp)
	}
}

func TestHash_listReturnsIDsOnly(t *testing.T) {
	b, store := newTestBackend(t)
	mustCreatePolicy(t, b, store, "users")
	ctx := context.Background()

	for _, sid := range []string{"u-1", "u-2", "u-3"} {
		_, err := b.HandleRequest(ctx, &logical.Request{
			Operation: logical.UpdateOperation,
			Path:      "hash/users",
			Data:      map[string]interface{}{"password": "p", "subject_id": sid},
			Storage:   store,
		})
		if err != nil {
			t.Fatalf("hash %s: %v", sid, err)
		}
	}

	resp, err := b.HandleRequest(ctx, &logical.Request{
		Operation: logical.ListOperation,
		Path:      "hash/",
		Storage:   store,
	})
	if err != nil {
		t.Fatalf("LIST: %v", err)
	}
	keys, _ := resp.Data["keys"].([]string)
	if len(keys) != 3 {
		t.Errorf("LIST keys: got %d, want 3", len(keys))
	}
	// Critical: response must NOT include any field that exposes
	// hash material.
	for k := range resp.Data {
		switch k {
		case "keys", "key_info":
			// allowed
		default:
			t.Errorf("LIST response contains forbidden field %q", k)
		}
	}
}

func TestHash_deleteIsIdempotent(t *testing.T) {
	b, store := newTestBackend(t)
	ctx := context.Background()

	// Delete a hash that doesn't exist — should succeed silently.
	_, err := b.HandleRequest(ctx, &logical.Request{
		Operation: logical.DeleteOperation,
		Path:      "hash/nonexistent-id",
		Storage:   store,
	})
	if err != nil {
		t.Errorf("delete nonexistent: err = %v, want nil", err)
	}
}
