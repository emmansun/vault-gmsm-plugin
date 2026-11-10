package gmsm

import (
	"context"
	"testing"

	"github.com/hashicorp/vault/sdk/logical"
)

func TestConfigKeysDisableUpsert(t *testing.T) {
	b, storage := createBackendWithSysView(t)

	mustRun := func(req *logical.Request) *logical.Response {
		t.Helper()
		resp, err := b.HandleRequest(context.Background(), req)
		if err != nil {
			t.Fatalf("unexpected error %v for %#v", err, *req)
		}
		if resp != nil && resp.IsError() {
			t.Fatalf("unexpected error response %v for %#v", resp.Error(), *req)
		}
		return resp
	}
	mustReject := func(req *logical.Request) {
		t.Helper()
		resp, err := b.HandleRequest(context.Background(), req)
		if err != nil {
			return
		}
		if resp == nil || !resp.IsError() {
			t.Fatalf("expected a rejection for %#v", *req)
		}
	}

	req := &logical.Request{
		Storage:   storage,
		Operation: logical.ReadOperation,
		Path:      "config/keys",
	}

	// Nothing has been configured yet, so upserting is allowed.
	if got := mustRun(req).Data["disable_upsert"].(bool); got {
		t.Fatalf("expected disable_upsert to default to false, got %v", got)
	}

	// An unknown key name is created on the fly while upserting is allowed.
	req.Operation = logical.CreateOperation
	req.Path = "encrypt/upsert-allowed"
	req.Data = map[string]interface{}{"plaintext": "aGVsbG8K"}
	mustRun(req)

	// Turn implicit key creation off.
	req.Operation = logical.UpdateOperation
	req.Path = "config/keys"
	req.Data = map[string]interface{}{"disable_upsert": true}
	mustRun(req)

	// A second unknown key name must now be refused.
	req.Operation = logical.CreateOperation
	req.Path = "encrypt/upsert-denied"
	req.Data = map[string]interface{}{"plaintext": "aGVsbG8K"}
	mustReject(req)

	// Keys that already exist keep working.
	req.Path = "encrypt/upsert-allowed"
	mustRun(req)
}
