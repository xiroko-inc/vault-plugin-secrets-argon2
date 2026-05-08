package argon2id

import (
	"context"
	"testing"

	"github.com/hashicorp/vault/sdk/logical"
)

func TestVerify_correctPassword(t *testing.T) {
	b, store := newTestBackend(t)
	mustCreatePolicy(t, b, store, "users")
	ctx := context.Background()

	resp, err := b.HandleRequest(ctx, &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      "hash/users",
		Data:      map[string]interface{}{"password": "letmein", "subject_id": "u-1"},
		Storage:   store,
	})
	if err != nil || resp.IsError() {
		t.Fatalf("hash: %v %v", err, resp)
	}

	resp, err = b.HandleRequest(ctx, &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      "verify/u-1",
		Data:      map[string]interface{}{"password": "letmein"},
		Storage:   store,
	})
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if got, _ := resp.Data["valid"].(bool); !got {
		t.Errorf("valid: got false, want true")
	}
	if got, _ := resp.Data["policy_drift"].(bool); got {
		t.Errorf("policy_drift: got true, want false (params unchanged)")
	}
}

func TestVerify_wrongPasswordReturns200False(t *testing.T) {
	b, store := newTestBackend(t)
	mustCreatePolicy(t, b, store, "users")
	ctx := context.Background()

	_, err := b.HandleRequest(ctx, &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      "hash/users",
		Data:      map[string]interface{}{"password": "correct", "subject_id": "u-1"},
		Storage:   store,
	})
	if err != nil {
		t.Fatalf("hash: %v", err)
	}

	resp, err := b.HandleRequest(ctx, &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      "verify/u-1",
		Data:      map[string]interface{}{"password": "wrong"},
		Storage:   store,
	})
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if resp == nil || resp.IsError() {
		t.Fatalf("verify on wrong password should NOT be an error response: %+v", resp)
	}
	if got, _ := resp.Data["valid"].(bool); got {
		t.Errorf("valid: got true on wrong password")
	}
}

func TestVerify_unknownIDReturns404(t *testing.T) {
	b, store := newTestBackend(t)
	resp, err := b.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      "verify/no-such-id",
		Data:      map[string]interface{}{"password": "anything"},
		Storage:   store,
	})
	// logical.ErrInvalidRequest is the framework signal for "not
	// found / bad request"; the framework translates this to 4xx.
	if err == nil && resp != nil && !resp.IsError() {
		t.Errorf("expected error or error response for unknown id, got %+v", resp)
	}
}

func TestVerify_reportsPolicyDriftAfterPolicyUpdate(t *testing.T) {
	b, store := newTestBackend(t)
	ctx := context.Background()

	// Create policy with non-default params, hash under it.
	_, err := b.HandleRequest(ctx, &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      "policy/users",
		Data: map[string]interface{}{
			"memory_kib":  32768,
			"iterations":  2,
			"parallelism": 1,
		},
		Storage: store,
	})
	if err != nil {
		t.Fatalf("create policy: %v", err)
	}
	_, err = b.HandleRequest(ctx, &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      "hash/users",
		Data:      map[string]interface{}{"password": "p", "subject_id": "u-1"},
		Storage:   store,
	})
	if err != nil {
		t.Fatalf("hash: %v", err)
	}

	// Bump the policy parameters.
	_, err = b.HandleRequest(ctx, &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      "policy/users",
		Data: map[string]interface{}{
			"memory_kib":  131072,
			"iterations":  4,
			"parallelism": 4,
		},
		Storage: store,
	})
	if err != nil {
		t.Fatalf("update policy: %v", err)
	}

	// Verify against the original hash — should be valid + drift.
	resp, err := b.HandleRequest(ctx, &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      "verify/u-1",
		Data:      map[string]interface{}{"password": "p"},
		Storage:   store,
	})
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if got, _ := resp.Data["valid"].(bool); !got {
		t.Errorf("valid: got false, want true")
	}
	if got, _ := resp.Data["policy_drift"].(bool); !got {
		t.Errorf("policy_drift: got false, want true after policy update")
	}
}

func TestVerify_afterDelete404s(t *testing.T) {
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
		t.Fatalf("hash: %v", err)
	}

	_, err = b.HandleRequest(ctx, &logical.Request{
		Operation: logical.DeleteOperation,
		Path:      "hash/u-1",
		Storage:   store,
	})
	if err != nil {
		t.Fatalf("delete: %v", err)
	}

	resp, err := b.HandleRequest(ctx, &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      "verify/u-1",
		Data:      map[string]interface{}{"password": "p"},
		Storage:   store,
	})
	if err == nil && resp != nil && !resp.IsError() {
		t.Errorf("verify after delete: expected not-found, got %+v", resp)
	}
}
