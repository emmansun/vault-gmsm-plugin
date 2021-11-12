package gmsm

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"strings"
	"testing"

	"github.com/hashicorp/vault/sdk/logical"
	"github.com/mitchellh/mapstructure"
)

// The outcome of processing a request includes
// the possibility that the request is incomplete or incorrect,
// or that the request is well-formed but the signature (for verification)
// is invalid, or that the signature is valid, but the key is not.
type signOutcome struct {
	requestOk bool
	valid     bool
	keyValid  bool
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

func validatePublicKey(t *testing.T, in string, sig string, pubKeyRaw []byte, expectValid bool, postpath string, b *backend) {
	t.Helper()
	input, _ := base64.StdEncoding.DecodeString(in)
	splitSig := strings.Split(sig, ":")
	signature, _ := base64.StdEncoding.DecodeString(splitSig[2])
	valid := ed25519.Verify(ed25519.PublicKey(pubKeyRaw), input, signature)
	if valid != expectValid {
		t.Fatalf("status of signature: expected %v. Got %v", valid, expectValid)
	}
	if !valid {
		return
	}

	keyReadReq := &logical.Request{
		Operation: logical.ReadOperation,
		Path:      "keys/" + postpath,
	}
	keyReadResp, err := b.HandleRequest(context.Background(), keyReadReq)
	if err != nil {
		t.Fatal(err)
	}
	val := keyReadResp.Data["keys"].(map[string]map[string]interface{})[strings.TrimPrefix(splitSig[1], "v")]
	var ak asymKey
	if err := mapstructure.Decode(val, &ak); err != nil {
		t.Fatal(err)
	}
	if ak.PublicKey != "" {
		t.Fatal("got non-empty public key")
	}
	keyReadReq.Data = map[string]interface{}{
		"context": "abcd",
	}
	keyReadResp, err = b.HandleRequest(context.Background(), keyReadReq)
	if err != nil {
		t.Fatal(err)
	}
	val = keyReadResp.Data["keys"].(map[string]map[string]interface{})[strings.TrimPrefix(splitSig[1], "v")]
	if err := mapstructure.Decode(val, &ak); err != nil {
		t.Fatal(err)
	}
	if ak.PublicKey != base64.StdEncoding.EncodeToString(pubKeyRaw) {
		t.Fatalf("got incorrect public key; got %q, expected %q\nasymKey struct is\n%#v", ak.PublicKey, pubKeyRaw, ak)
	}
}
