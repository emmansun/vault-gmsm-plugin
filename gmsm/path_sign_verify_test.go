package gmsm

import (
	"context"
	"encoding/base64"
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

// signVerifyUIDHelper wraps the sign and verify endpoints of a fresh SM2 key so
// the identifier tests stay readable.
type signVerifyUIDHelper struct {
	t       *testing.T
	b       *backend
	storage logical.Storage
	key     string
	input   string
}

func newSignVerifyUIDHelper(t *testing.T) *signVerifyUIDHelper {
	t.Helper()

	b, storage := createBackendWithSysView(t)
	h := &signVerifyUIDHelper{
		t:       t,
		b:       b,
		storage: storage,
		key:     "uid",
		input:   base64.StdEncoding.EncodeToString([]byte("the quick brown fox")),
	}

	if _, err := b.HandleRequest(context.Background(), &logical.Request{
		Storage:   storage,
		Operation: logical.UpdateOperation,
		Path:      "keys/" + h.key,
		Data:      map[string]interface{}{"type": "ecdsa-sm2"},
	}); err != nil {
		t.Fatal(err)
	}

	return h
}

func (h *signVerifyUIDHelper) request(path string, data map[string]interface{}) *logical.Response {
	h.t.Helper()

	resp, err := h.b.HandleRequest(context.Background(), &logical.Request{
		Storage:   h.storage,
		Operation: logical.UpdateOperation,
		Path:      path,
		Data:      data,
	})
	if err != nil {
		h.t.Fatalf("%s: %v", path, err)
	}
	if resp != nil && resp.IsError() {
		h.t.Fatalf("%s: %#v", path, *resp)
	}

	return resp
}

func (h *signVerifyUIDHelper) sign(data map[string]interface{}) string {
	h.t.Helper()

	if data == nil {
		data = map[string]interface{}{}
	}
	if _, ok := data["input"]; !ok {
		data["input"] = h.input
	}

	sig, ok := h.request("sign/"+h.key, data).Data["signature"].(string)
	if !ok {
		h.t.Fatal("no signature in response")
	}

	return sig
}

func (h *signVerifyUIDHelper) verify(sig string, data map[string]interface{}) bool {
	h.t.Helper()

	if data == nil {
		data = map[string]interface{}{}
	}
	if _, ok := data["input"]; !ok {
		data["input"] = h.input
	}
	data["signature"] = sig

	valid, ok := h.request("verify/"+h.key, data).Data["valid"].(bool)
	if !ok {
		h.t.Fatal("no valid flag in response")
	}

	return valid
}

func TestTransit_SignVerifyUID(t *testing.T) {
	h := newSignVerifyUIDHelper(t)

	sig := h.sign(nil)
	if !h.verify(sig, nil) {
		t.Fatal("signature made with the default identifier did not verify")
	}

	uidSig := h.sign(map[string]interface{}{"uid": "alice@example.com"})
	if !h.verify(uidSig, map[string]interface{}{"uid": "alice@example.com"}) {
		t.Fatal("signature made with a custom identifier did not verify")
	}
	if h.verify(uidSig, nil) {
		t.Fatal("signature verified without the identifier it was created with")
	}
	if h.verify(uidSig, map[string]interface{}{"uid": "bob@example.com"}) {
		t.Fatal("signature verified with a different identifier")
	}

	// A prehashed input is signed as-is, so the identifier plays no part and a
	// mismatch must not make an otherwise good signature fail.
	prehashedSig := h.sign(map[string]interface{}{"prehashed": true, "uid": "alice@example.com"})
	if !h.verify(prehashedSig, map[string]interface{}{"prehashed": true, "uid": "bob@example.com"}) {
		t.Fatal("prehashed signature was bound to the identifier")
	}
}

func TestTransit_SignVerifyUIDBatch(t *testing.T) {
	h := newSignVerifyUIDHelper(t)

	resp := h.request("sign/"+h.key, map[string]interface{}{
		"uid": "carol@example.com",
		"batch_input": []interface{}{
			map[string]interface{}{"input": h.input, "uid": "alice@example.com"},
			map[string]interface{}{"input": h.input},
			map[string]interface{}{"input": h.input, "uid": "bob@example.com"},
		},
	})

	results, ok := resp.Data["batch_results"].([]batchResponseSignItem)
	if !ok || len(results) != 3 {
		t.Fatalf("unexpected batch results: %#v", resp.Data)
	}

	// A per item identifier wins over the request level one, which is the
	// fallback for items that do not name their own.
	wanted := []string{"alice@example.com", "carol@example.com", "bob@example.com"}
	for i, uid := range wanted {
		if !h.verify(results[i].Signature, map[string]interface{}{"uid": uid}) {
			t.Fatalf("batch result %d did not verify with identifier %q", i, uid)
		}
	}

	if h.verify(results[2].Signature, map[string]interface{}{"uid": "carol@example.com"}) {
		t.Fatal("batch item ignored the identifier it was signed with")
	}

	verifyResp := h.request("verify/"+h.key, map[string]interface{}{
		"batch_input": []interface{}{
			map[string]interface{}{"input": h.input, "signature": results[0].Signature, "uid": "alice@example.com"},
			map[string]interface{}{"input": h.input, "signature": results[0].Signature, "uid": "bob@example.com"},
		},
	})

	verifyResults, ok := verifyResp.Data["batch_results"].([]batchResponseVerifyItem)
	if !ok || len(verifyResults) != 2 {
		t.Fatalf("unexpected batch results: %#v", verifyResp.Data)
	}
	if !verifyResults[0].Valid {
		t.Fatal("batch verification ignored the item level identifier")
	}
	if verifyResults[1].Valid {
		t.Fatal("batch verification accepted a different identifier")
	}
}
