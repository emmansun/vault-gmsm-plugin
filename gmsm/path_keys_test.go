package gmsm

import (
	"strings"
	"testing"

	"github.com/hashicorp/vault/sdk/logical"
)

// TestKeyTypeNames covers the SM2 type under its current name and under the
// older "ecdsa-sm2" spelling, which shipped before the key was documented as an
// encryption key as well as a signing one.
func TestKeyTypeNames(t *testing.T) {
	b, s := createBackendWithStorage(t)

	_, pkcs8PEM, _ := newImportTestKey(t)

	cases := []struct {
		name string
		path string
		data map[string]interface{}
	}{
		{
			name: "create with the current name",
			path: "keys/current-name",
			data: map[string]interface{}{"type": "sm2"},
		},
		{
			name: "create with the older name",
			path: "keys/older-name",
			data: map[string]interface{}{"type": "ecdsa-sm2"},
		},
		{
			name: "import with the older name",
			path: importPath("older-import"),
			data: map[string]interface{}{"type": "ecdsa-sm2", "private_key": pkcs8PEM},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			resp := requestOK(t, b, s, logical.UpdateOperation, tc.path, tc.data)
			if got := resp.Data["type"]; got != "sm2" {
				t.Fatalf("expected the key to report itself as sm2, got %v", got)
			}
		})
	}

	// An alias is not a wildcard: a name that was never a type stays a bad
	// request.
	resp, _ := importRequest(b, s, logical.UpdateOperation, "keys/unknown-name",
		map[string]interface{}{"type": "aes256-gcm96"})
	if resp == nil || !resp.IsError() {
		t.Fatalf("expected an unknown key type to be refused, got %v", resp)
	}
	if msg := resp.Error().Error(); !strings.Contains(msg, "unknown key type") {
		t.Fatalf("expected the refusal to name the unknown type, got %q", msg)
	}
}
