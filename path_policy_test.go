// Path-handler tests use logical.InmemStorage and exercise
// b.HandleRequest directly — full Vault TestCluster coverage lives in
// backend_test.go. This is the inner-loop unit-test layer.
package argon2id

import (
	"context"
	"testing"
	"time"

	"github.com/hashicorp/vault/sdk/logical"
)

func newTestBackend(t *testing.T) (*backend, logical.Storage) {
	t.Helper()
	b, err := newBackend()
	if err != nil {
		t.Fatalf("newBackend: %v", err)
	}
	cfg := &logical.BackendConfig{
		StorageView: &logical.InmemStorage{},
		Logger:      nil,
		System:      &logical.StaticSystemView{DefaultLeaseTTLVal: time.Hour, MaxLeaseTTLVal: time.Hour * 24},
	}
	if err := b.Setup(context.Background(), cfg); err != nil {
		t.Fatalf("Setup: %v", err)
	}
	return b, cfg.StorageView
}

func TestPolicy_createWithDefaults(t *testing.T) {
	b, store := newTestBackend(t)
	ctx := context.Background()

	resp, err := b.HandleRequest(ctx, &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      "policy/users",
		Data:      map[string]interface{}{},
		Storage:   store,
	})
	if err != nil {
		t.Fatalf("PUT policy/users: %v", err)
	}
	if resp != nil && resp.IsError() {
		t.Fatalf("PUT policy/users: %v", resp.Error())
	}

	resp, err = b.HandleRequest(ctx, &logical.Request{
		Operation: logical.ReadOperation,
		Path:      "policy/users",
		Storage:   store,
	})
	if err != nil {
		t.Fatalf("GET policy/users: %v", err)
	}
	if resp == nil || resp.Data == nil {
		t.Fatal("GET policy/users: nil response")
	}
	wants := map[string]uint32{
		"memory_kib": DefaultMemoryKiB,
		"iterations": DefaultIterations,
		"salt_len":   DefaultSaltLen,
		"key_len":    DefaultKeyLen,
	}
	for k, want := range wants {
		got, ok := resp.Data[k].(uint32)
		if !ok {
			t.Errorf("field %s: not a uint32 in response (%T)", k, resp.Data[k])
			continue
		}
		if got != want {
			t.Errorf("field %s: got %d, want %d", k, got, want)
		}
	}
	if got, ok := resp.Data["parallelism"].(uint8); !ok || got != DefaultParallelism {
		t.Errorf("parallelism: got %v, want %d", resp.Data["parallelism"], DefaultParallelism)
	}
	if got, ok := resp.Data["algorithm"].(string); !ok || got != "argon2id" {
		t.Errorf("algorithm: got %v, want argon2id", resp.Data["algorithm"])
	}
}

func TestPolicy_createWithExplicitParams(t *testing.T) {
	b, store := newTestBackend(t)
	ctx := context.Background()

	resp, err := b.HandleRequest(ctx, &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      "policy/strict",
		Data: map[string]interface{}{
			"memory_kib":  131072,
			"iterations":  4,
			"parallelism": 4,
			"salt_len":    32,
			"key_len":     48,
		},
		Storage: store,
	})
	if err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("PUT policy/strict: err=%v resp=%v", err, resp)
	}

	resp, err = b.HandleRequest(ctx, &logical.Request{
		Operation: logical.ReadOperation,
		Path:      "policy/strict",
		Storage:   store,
	})
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	if got, _ := resp.Data["memory_kib"].(uint32); got != 131072 {
		t.Errorf("memory_kib: got %v, want 131072", resp.Data["memory_kib"])
	}
	if got, _ := resp.Data["iterations"].(uint32); got != 4 {
		t.Errorf("iterations: got %v, want 4", resp.Data["iterations"])
	}
}

func TestPolicy_createRejectsOutOfBounds(t *testing.T) {
	b, store := newTestBackend(t)
	ctx := context.Background()

	tests := []struct {
		name string
		data map[string]interface{}
	}{
		{"memory below floor", map[string]interface{}{"memory_kib": 1024}},
		{"memory above ceiling", map[string]interface{}{"memory_kib": 2 * 1024 * 1024}},
		{"iterations zero", map[string]interface{}{"iterations": 0}},
		{"parallelism above ceiling", map[string]interface{}{"parallelism": 32}},
		{"salt_len above ceiling", map[string]interface{}{"salt_len": 128}},
		{"key_len below floor", map[string]interface{}{"key_len": 16}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			resp, err := b.HandleRequest(ctx, &logical.Request{
				Operation: logical.UpdateOperation,
				Path:      "policy/bad",
				Data:      tt.data,
				Storage:   store,
			})
			if err != nil {
				// Some out-of-range integers fail the framework's type
				// coercion before reaching our handler — that's fine,
				// they're still rejected.
				return
			}
			if resp == nil || !resp.IsError() {
				t.Errorf("expected error response for %s, got: %+v", tt.name, resp)
			}
		})
	}
}

func TestPolicy_listAndDelete(t *testing.T) {
	b, store := newTestBackend(t)
	ctx := context.Background()

	for _, name := range []string{"alpha", "beta", "gamma"} {
		_, err := b.HandleRequest(ctx, &logical.Request{
			Operation: logical.UpdateOperation,
			Path:      "policy/" + name,
			Storage:   store,
		})
		if err != nil {
			t.Fatalf("create %s: %v", name, err)
		}
	}

	resp, err := b.HandleRequest(ctx, &logical.Request{
		Operation: logical.ListOperation,
		Path:      "policy/",
		Storage:   store,
	})
	if err != nil {
		t.Fatalf("LIST: %v", err)
	}
	keys, ok := resp.Data["keys"].([]string)
	if !ok || len(keys) != 3 {
		t.Errorf("keys: got %v, want 3 entries", resp.Data["keys"])
	}

	_, err = b.HandleRequest(ctx, &logical.Request{
		Operation: logical.DeleteOperation,
		Path:      "policy/beta",
		Storage:   store,
	})
	if err != nil {
		t.Fatalf("DELETE beta: %v", err)
	}

	resp, err = b.HandleRequest(ctx, &logical.Request{
		Operation: logical.ReadOperation,
		Path:      "policy/beta",
		Storage:   store,
	})
	if err != nil {
		t.Fatalf("GET deleted: %v", err)
	}
	if resp != nil {
		t.Errorf("GET deleted policy: expected nil response, got %+v", resp)
	}
}

func TestPolicy_deleteRejectsWhenHashesReference(t *testing.T) {
	b, store := newTestBackend(t)
	ctx := context.Background()

	// Create policy.
	_, err := b.HandleRequest(ctx, &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      "policy/users",
		Storage:   store,
	})
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	// Create a hash referencing it.
	_, err = b.HandleRequest(ctx, &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      "hash/users",
		Data:      map[string]interface{}{"password": "p", "subject_id": "u-1"},
		Storage:   store,
	})
	if err != nil {
		t.Fatalf("hash: %v", err)
	}

	resp, err := b.HandleRequest(ctx, &logical.Request{
		Operation: logical.DeleteOperation,
		Path:      "policy/users",
		Storage:   store,
	})
	if err != nil {
		t.Fatalf("DELETE policy: %v", err)
	}
	if resp == nil || !resp.IsError() {
		t.Errorf("DELETE policy with referencing hash: expected error response, got %+v", resp)
	}
}
