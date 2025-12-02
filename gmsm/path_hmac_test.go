package gmsm

import (
	"context"
	"fmt"
	"strconv"
	"strings"
	"testing"

	"github.com/hashicorp/vault/sdk/logical"
)

func TestTransit_HMAC(t *testing.T) {
	b, storage := createBackendWithSysView(t)

	cases := []struct {
		name string
		typ  string
	}{
		{
			name: "foo",
			typ:  "",
		},
		{
			name: "dedicated",
			typ:  "hmac",
		},
	}

	for _, c := range cases {
		req := &logical.Request{
			Storage:   storage,
			Operation: logical.UpdateOperation,
			Path:      "keys/" + c.name,
		}
		_, err := b.HandleRequest(context.Background(), req)
		if err != nil {
			t.Fatal(err)
		}

		// Now, change the key value to something we control
		p, _, err := b.GetPolicy(context.Background(), PolicyRequest{
			Storage: storage,
			Name:    c.name,
		}, b.GetRandomReader())
		if err != nil {
			t.Fatal(err)
		}
		// We don't care as we're the only one using this
		latestVersion := strconv.Itoa(p.LatestVersion)
		keyEntry := p.Keys[latestVersion]
		keyEntry.HMACKey = []byte("01234567890123456789012345678901")
		keyEntry.Key = []byte("01234567890123456789012345678901")
		p.Keys[latestVersion] = keyEntry
		if err = p.Persist(context.Background(), storage); err != nil {
			t.Fatal(err)
		}

		req.Path = "hmac/" + c.name
		req.Data = map[string]interface{}{
			"input": "dGhlIHF1aWNrIGJyb3duIGZveA==",
		}

		doRequest := func(req *logical.Request, errExpected bool, expected string) {
			t.Helper()
			path := req.Path
			defer func() { req.Path = path }()

			resp, err := b.HandleRequest(context.Background(), req)
			if err != nil && !errExpected {
				panic(fmt.Sprintf("%v", err))
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
			value, ok := resp.Data["hmac"]
			if !ok {
				t.Fatalf("no hmac key found in returned data, got resp data %#v", resp.Data)
			}
			if value.(string) != expected {
				panic(fmt.Sprintf("mismatched hashes; expected %s, got resp data %#v", expected, resp.Data))
			}

			// Now verify
			verify := func() {
				t.Helper()

				resp, err = b.HandleRequest(context.Background(), req)
				if err != nil {
					t.Fatalf("%v: %v", err, resp)
				}
				if resp == nil {
					t.Fatal("expected non-nil response")
				}
				if errStr, ok := resp.Data["error"]; ok {
					t.Fatalf("error validating hmac: %s", errStr)
				}
				if resp.Data["valid"].(bool) == false {
					t.Fatalf("error validating hmac;\nreq:\n%#v\nresp:\n%#v", *req, *resp)
				}
			}
			req.Path = strings.ReplaceAll(req.Path, "hmac", "verify")
			req.Data["hmac"] = value.(string)
			verify()

			// If `algorithm` parameter is used, try with `hash_algorithm` as well
			if algorithm, ok := req.Data["algorithm"]; ok {
				// Note that `hash_algorithm` takes precedence over `algorithm`, since the
				// latter is deprecated.
				req.Data["hash_algorithm"] = algorithm
				req.Data["algorithm"] = "xxx"
				defer func() {
					// Restore the req fields, since it is re-used by the tests below
					delete(req.Data, "hash_algorithm")
					req.Data["algorithm"] = algorithm
				}()

				verify()
			}
		}

		// Comparisons are against values generated via openssl

		// Test defaults -- sm3
		doRequest(req, false, "vault:v1:wRjXXumBBHpDsKXQiCIvKCoCKIMcK5goYtcx0YtbZiM=")

		// Test algorithm selection in the path
		req.Path = "hmac/" + c.name + "/sm3"
		doRequest(req, false, "vault:v1:wRjXXumBBHpDsKXQiCIvKCoCKIMcK5goYtcx0YtbZiM=")

		// Reset and test algorithm selection in the data
		req.Path = "hmac/" + c.name
		req.Data["algorithm"] = "sm3"
		doRequest(req, false, "vault:v1:wRjXXumBBHpDsKXQiCIvKCoCKIMcK5goYtcx0YtbZiM=")

		// Test returning as base64
		req.Data["format"] = "base64"
		doRequest(req, false, "vault:v1:wRjXXumBBHpDsKXQiCIvKCoCKIMcK5goYtcx0YtbZiM=")

		// Rotate
		err = p.Rotate(context.Background(), storage, b.GetRandomReader())
		if err != nil {
			t.Fatal(err)
		}
		keyEntry = p.Keys["2"]
		// Set to another value we control
		keyEntry.HMACKey = []byte("12345678901234567890123456789012")
		p.Keys["2"] = keyEntry
		if err = p.Persist(context.Background(), storage); err != nil {
			t.Fatal(err)
		}

		doRequest(req, false, "vault:v2:3ZLn1Ltm1zGfUeec5bpFqrBm56l7iz2xgUAqvmhUc10=")

		// Verify a previous version
		req.Path = "verify/" + c.name

		req.Data["hmac"] = "vault:v1:wRjXXumBBHpDsKXQiCIvKCoCKIMcK5goYtcx0YtbZiM="
		resp, err := b.HandleRequest(context.Background(), req)
		if err != nil {
			t.Fatalf("%v: %v", err, resp)
		}
		if resp == nil {
			t.Fatal("expected non-nil response")
		}
		if resp.Data["valid"].(bool) == false {
			t.Fatalf("error validating hmac\nreq\n%#v\nresp\n%#v", *req, *resp)
		}

		// Try a bad value
		req.Data["hmac"] = "vault:v1:UcBvm4VskkukzZHlPgm3p5P/Yr/PV6xpuOGZISya3A4="
		resp, err = b.HandleRequest(context.Background(), req)
		if err != nil {
			t.Fatalf("%v: %v", err, resp)
		}
		if resp == nil {
			t.Fatal("expected non-nil response")
		}
		if resp.Data["valid"].(bool) {
			t.Fatalf("expected error validating hmac")
		}

		// Set min decryption version, attempt to verify
		p.MinDecryptionVersion = 2
		if err = p.Persist(context.Background(), storage); err != nil {
			t.Fatal(err)
		}

		req.Data["hmac"] = "vault:v1:UcBvm5VskkukzZHlPgm3p5P/Yr/PV6xpuOGZISya3A4="
		resp, err = b.HandleRequest(context.Background(), req)
		if err == nil {
			t.Fatalf("expected an error, got response %#v", resp)
		}
		if err != logical.ErrInvalidRequest {
			t.Fatalf("expected invalid request error, got %v", err)
		}
	}
}

func TestTransit_batchHMAC(t *testing.T) {
	b, storage := createBackendWithSysView(t)

	// First create a key
	req := &logical.Request{
		Storage:   storage,
		Operation: logical.UpdateOperation,
		Path:      "keys/foo",
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
	// We don't care as we're the only one using this
	latestVersion := strconv.Itoa(p.LatestVersion)
	keyEntry := p.Keys[latestVersion]
	keyEntry.HMACKey = []byte("01234567890123456789012345678901")
	p.Keys[latestVersion] = keyEntry
	if err = p.Persist(context.Background(), storage); err != nil {
		t.Fatal(err)
	}

	req.Path = "hmac/foo"
	batchInput := []batchRequestHMACItem{
		{"input": "dGhlIHF1aWNrIGJyb3duIGZveA==", "reference": "one"},
		{"input": "dGhlIHF1aWNrIGJyb3duIGZveA==", "reference": "two"},
		{"input": "", "reference": "three"},
		{"input": ":;.?", "reference": "four"},
		{},
	}

	expected := []batchResponseHMACItem{
		{HMAC: "vault:v1:wRjXXumBBHpDsKXQiCIvKCoCKIMcK5goYtcx0YtbZiM=", Reference: "one"},
		{HMAC: "vault:v1:wRjXXumBBHpDsKXQiCIvKCoCKIMcK5goYtcx0YtbZiM=", Reference: "two"},
		{HMAC: "vault:v1:2jzZ1oTSE2WdBg53msoEO1v+jndTKST9jgwNZIhHWX0=", Reference: "three"},
		{Error: "unable to decode input as base64: illegal base64 data at input byte 0", Reference: "four"},
		{Error: "missing input for HMAC"},
	}

	req.Data = map[string]interface{}{
		"batch_input": batchInput,
	}

	resp, err := b.HandleRequest(context.Background(), req)

	if err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("err:%v resp:%#v", err, resp)
	}

	batchResponseItems := resp.Data["batch_results"].([]batchResponseHMACItem)

	if len(batchResponseItems) != len(batchInput) {
		t.Fatalf("Expected %d items in response. Got %d", len(batchInput), len(batchResponseItems))
	}

	for i, m := range batchResponseItems {
		if expected[i].Error == "" && expected[i].HMAC != m.HMAC {
			t.Fatalf("Expected HMAC %s got %s in result %d", expected[i].HMAC, m.HMAC, i)
		}
		if expected[i].Error != "" && expected[i].Error != m.Error {
			t.Fatalf("Expected Error %q got %q in result %d", expected[i].Error, m.Error, i)
		}
		if expected[i].Reference != m.Reference {
			t.Fatalf("Expected references to match, Got %s, Expected %s", m.Reference, expected[i].Reference)
		}
	}

	// Verify a previous version
	req.Path = "verify/foo"
	good_hmac := "vault:v1:wRjXXumBBHpDsKXQiCIvKCoCKIMcK5goYtcx0YtbZiM="
	bad_hmac := "vault:v1:UcBvm4VskkukzZHlPgm3p5P/Yr/PV6xpuOGZISya3A4="
	verifyBatch := []batchRequestHMACItem{
		{"input": "dGhlIHF1aWNrIGJyb3duIGZveA==", "hmac": good_hmac},
	}

	req.Data = map[string]interface{}{
		"batch_input": verifyBatch,
	}

	resp, err = b.HandleRequest(context.Background(), req)
	if err != nil {
		t.Fatalf("%v: %v", err, resp)
	}
	if resp == nil {
		t.Fatal("expected non-nil response")
	}

	batchHMACVerifyResponseItems := resp.Data["batch_results"].([]batchResponseHMACItem)

	if !batchHMACVerifyResponseItems[0].Valid {
		t.Fatalf("error validating hmac\nreq\n%#v\nresp\n%#v", *req, *resp)
	}

	// Try a bad value
	verifyBatch[0]["hmac"] = bad_hmac
	resp, err = b.HandleRequest(context.Background(), req)
	if err != nil {
		t.Fatalf("%v: %v", err, resp)
	}
	if resp == nil {
		t.Fatal("expected non-nil response")
	}

	batchHMACVerifyResponseItems = resp.Data["batch_results"].([]batchResponseHMACItem)

	if batchHMACVerifyResponseItems[0].Valid {
		t.Fatalf("expected error validating hmac\nreq\n%#v\nresp\n%#v", *req, *resp)
	}

	// Rotate
	err = p.Rotate(context.Background(), storage, b.GetRandomReader())
	if err != nil {
		t.Fatal(err)
	}
	keyEntry = p.Keys["2"]
	// Set to another value we control
	keyEntry.HMACKey = []byte("12345678901234567890123456789012")
	p.Keys["2"] = keyEntry
	if err = p.Persist(context.Background(), storage); err != nil {
		t.Fatal(err)
	}

	// Set min decryption version, attempt to verify
	p.MinDecryptionVersion = 2
	if err = p.Persist(context.Background(), storage); err != nil {
		t.Fatal(err)
	}

	// supply a good hmac, but with expired key version
	verifyBatch[0]["hmac"] = good_hmac

	resp, err = b.HandleRequest(context.Background(), req)
	if err != nil {
		t.Fatalf("%v: %v", err, resp)
	}
	if resp == nil {
		t.Fatal("expected non-nil response")
	}

	batchHMACVerifyResponseItems = resp.Data["batch_results"].([]batchResponseHMACItem)

	if batchHMACVerifyResponseItems[0].Valid {
		t.Fatalf("expected error validating hmac\nreq\n%#v\nresp\n%#v", *req, *resp)
	}
}
