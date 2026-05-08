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
