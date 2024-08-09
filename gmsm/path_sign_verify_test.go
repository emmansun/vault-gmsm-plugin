package gmsm

import (
	"context"
	"strconv"
	"testing"

	"github.com/hashicorp/vault/sdk/logical"
)

// The outcome of processing a request includes
// the possibility that the request is incomplete or incorrect,
// or that the request is well-formed but the signature (for verification)
// is invalid, or that the signature is valid, but the key is not.
type signOutcome struct {
	requestOk bool
	valid     bool
	keyValid  bool
	reference string
}

func TestTransit_SignVerify(t *testing.T) {
	b, storage := createBackendWithSysView(t)

	// First create a key
	req := &logical.Request{
		Storage:   storage,
		Operation: logical.UpdateOperation,
		Path:      "keys/foo",
		Data: map[string]interface{}{
			"type": "ecdsa-sm2",
		},
	}
	_, err := b.HandleRequest(context.Background(), req)
	if err != nil {
		t.Fatal(err)
	}

	// Now, change the key value to something we control
	p, _, err := b.GetPolicy(context.Background(), PolicyRequest{
		Storage: storage,
		Name:    "foo",
	}, b.GetRandomReader())
	if err != nil {
		t.Fatal(err)
	}

	keyEntry := p.Keys[strconv.Itoa(p.LatestVersion)]
	_, ok := keyEntry.EC_X.SetString("8356e642a40ebd18d29ba3532fbd9f3bbee8f027c3f6f39a5ba2f870369f9988", 16)
	if !ok {
		t.Fatal("could not set X")
	}
	_, ok = keyEntry.EC_Y.SetString("981f5efe55d1c5cdf6c0ef2b070847a14f7fdf4272a8df09c442f3058af94ba1", 16)
	if !ok {
		t.Fatal("could not set Y")
	}
	_, ok = keyEntry.EC_D.SetString("6c5a0a0b2eed3cbec3e4f1252bfe0e28c504a1c6bf1999eebb0af9ef0f8e6c85", 16)
	if !ok {
		t.Fatal("could not set D")
	}
	p.Keys[strconv.Itoa(p.LatestVersion)] = keyEntry
	if err = p.Persist(context.Background(), storage); err != nil {
		t.Fatal(err)
	}

	req.Data = map[string]interface{}{
		"input": "dGhlIHF1aWNrIGJyb3duIGZveA==",
	}

	signRequest := func(req *logical.Request, errExpected bool, postpath string) string {
		t.Helper()
		req.Path = "sign/foo" + postpath
		resp, err := b.HandleRequest(context.Background(), req)
		if err != nil && !errExpected {
			t.Fatal(err)
		}
		if resp == nil {
			t.Fatal("expected non-nil response")
		}
		if errExpected {
			if !resp.IsError() {
				t.Fatalf("bad: should have gotten error response: %#v", *resp)
			}
			return ""
		}
		if resp.IsError() {
			t.Fatalf("bad: got error response: %#v", *resp)
		}
		value, ok := resp.Data["signature"]
		if !ok {
			t.Fatalf("no signature key found in returned data, got resp data %#v", resp.Data)
		}
		return value.(string)
	}

	verifyRequest := func(req *logical.Request, errExpected bool, postpath, sig string) {
		t.Helper()
		req.Path = "verify/foo" + postpath
		req.Data["signature"] = sig
		resp, err := b.HandleRequest(context.Background(), req)
		if err != nil {
			if errExpected {
				return
			}
			t.Fatalf("got error: %v, sig was %v", err, sig)
		}
		if resp == nil {
			t.Fatal("expected non-nil response")
		}
		if resp.IsError() {
			if errExpected {
				return
			}
			t.Fatalf("bad: got error response: %#v", *resp)
		}
		value, ok := resp.Data["valid"]
		if !ok {
			t.Fatalf("no valid key found in returned data, got resp data %#v", resp.Data)
		}
		if !value.(bool) && !errExpected {
			t.Fatalf("verification failed; req was %#v, resp is %#v", *req, *resp)
		} else if value.(bool) && errExpected {
			t.Fatalf("expected error and didn't get one; req was %#v, resp is %#v", *req, *resp)
		}
	}

	// Comparisons are against values generated via openssl

	// Test defaults
	sig := signRequest(req, false, "")
	verifyRequest(req, false, "", sig)

	// Test a bad signature
	verifyRequest(req, true, "", sig[0:len(sig)-2])

	req.Data["prehashed"] = true
	sig = signRequest(req, false, "")
	verifyRequest(req, false, "", sig)
	delete(req.Data, "prehashed")

	// Test marshaling selection
	// Bad value
	req.Data["marshaling_algorithm"] = "asn2"
	sig = signRequest(req, true, "")
	// Use the default, verify we can't validate with jws
	req.Data["marshaling_algorithm"] = "asn1"
	sig = signRequest(req, false, "")
	req.Data["marshaling_algorithm"] = "jws"
	verifyRequest(req, true, "", sig)
	// Sign with jws, verify we can validate
	sig = signRequest(req, false, "")
	verifyRequest(req, false, "", sig)
	// If we change marshaling back to asn1 we shouldn't be able to verify
	delete(req.Data, "marshaling_algorithm")
	verifyRequest(req, true, "", sig)
}
