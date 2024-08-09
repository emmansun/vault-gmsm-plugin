package gmsm

import (
	"context"
	"testing"

	"github.com/hashicorp/vault/sdk/logical"
)

func TestTransit_Hash(t *testing.T) {
	b, storage := createBackendWithSysView(t)

	req := &logical.Request{
		Storage:   storage,
		Operation: logical.UpdateOperation,
		Path:      "hash",
		Data: map[string]interface{}{
			"input": "dGhlIHF1aWNrIGJyb3duIGZveA==",
		},
	}

	doRequest := func(req *logical.Request, errExpected bool, expected string) {
		resp, err := b.HandleRequest(context.Background(), req)
		if err != nil && !errExpected {
			t.Fatal(err)
		}
		if resp == nil {
			t.Fatal("expected non-nil response")
		}
		if errExpected {
			if !resp.IsError() {
				t.Fatalf("bad: got error response: %#v", *resp)
			}
			return
		}
		if resp.IsError() {
			t.Fatalf("bad: got error response: %#v", *resp)
		}
		sum, ok := resp.Data["sum"]
		if !ok {
			t.Fatal("no sum key found in returned data")
		}
		if sum.(string) != expected {
			t.Fatalf("mismatched hashes, got %s, expected %s", sum, expected)
		}
	}

	// Test defaults -- sm3
	doRequest(req, false, "e2e9e396c4e75860bd806ec6f548c77b26f54a63f5f268fdc2daf17152aa0767")

	// Test algorithm selection in the path
	req.Path = "hash/sm3"
	doRequest(req, false, "e2e9e396c4e75860bd806ec6f548c77b26f54a63f5f268fdc2daf17152aa0767")

	// Reset and test algorithm selection in the data
	req.Path = "hash"
	req.Data["algorithm"] = "sm3"
	doRequest(req, false, "e2e9e396c4e75860bd806ec6f548c77b26f54a63f5f268fdc2daf17152aa0767")

	// Test returning as base64
	req.Data["format"] = "base64"
	doRequest(req, false, "4unjlsTnWGC9gG7G9UjHeyb1SmP18mj9wtrxcVKqB2c=")

	// Test bad input/format/algorithm
	req.Data["format"] = "base92"
	doRequest(req, true, "")

	req.Data["format"] = "hex"
	req.Data["algorithm"] = "foobar"
	doRequest(req, true, "")

	req.Data["algorithm"] = "sm3"
	req.Data["input"] = "foobar"
	doRequest(req, true, "")
}
