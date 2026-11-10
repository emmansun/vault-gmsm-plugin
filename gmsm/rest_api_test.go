package gmsm

import (
	"bytes"
	"crypto/ecdsa"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"net/http"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/emmansun/gmsm/smx509"
	"github.com/emmansun/vault-gmsm-plugin/internal/testca"
)

// restClient talks to a Vault server that already has the plugin mounted. The
// REST test exists because the CLI hides the parts a REST client depends on:
// HTTP status codes, the JSON key names and the shape of error responses.
type restClient struct {
	t     *testing.T
	addr  string
	token string
	mount string
}

func newRESTClient(t *testing.T) *restClient {
	t.Helper()

	addr := os.Getenv("VAULT_ADDR")
	token := os.Getenv("VAULT_TOKEN")
	if addr == "" || token == "" {
		t.Skip("set VAULT_ADDR and VAULT_TOKEN to run the REST API integration test against a mounted plugin")
	}

	mount := os.Getenv("GMSM_MOUNT")
	if mount == "" {
		mount = "gmsm"
	}

	return &restClient{
		t:     t,
		addr:  strings.TrimSuffix(addr, "/"),
		token: token,
		mount: strings.Trim(mount, "/"),
	}
}

// call sends a request to a path below the plugin mount and returns the status
// code together with the decoded body.
func (c *restClient) call(method, path string, body any) (int, map[string]any) {
	c.t.Helper()

	return c.do(method, fmt.Sprintf("%s/v1/%s/%s", c.addr, c.mount, strings.TrimPrefix(path, "/")), body)
}

// callRoot sends a request to a path outside the mount, such as sys/health.
func (c *restClient) callRoot(method, path string, body any) (int, map[string]any) {
	c.t.Helper()

	return c.do(method, fmt.Sprintf("%s/v1/%s", c.addr, strings.TrimPrefix(path, "/")), body)
}

func (c *restClient) do(method, url string, body any) (int, map[string]any) {
	c.t.Helper()

	var payload io.Reader
	if body != nil {
		encoded, err := json.Marshal(body)
		if err != nil {
			c.t.Fatalf("could not encode the body for %s %s: %v", method, url, err)
		}
		payload = bytes.NewReader(encoded)
	}

	req, err := http.NewRequest(method, url, payload)
	if err != nil {
		c.t.Fatalf("could not build %s %s: %v", method, url, err)
	}
	req.Header.Set("X-Vault-Token", c.token)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		c.t.Fatalf("%s %s: %v", method, url, err)
	}
	defer resp.Body.Close()

	raw, err := io.ReadAll(resp.Body)
	if err != nil {
		c.t.Fatalf("%s %s: could not read the response: %v", method, url, err)
	}

	decoded := map[string]any{}
	if len(bytes.TrimSpace(raw)) > 0 {
		if err := json.Unmarshal(raw, &decoded); err != nil {
			c.t.Fatalf("%s %s: status %d with a body that is not a JSON object: %s", method, url, resp.StatusCode, raw)
		}
	}

	if resp.StatusCode >= 400 {
		c.t.Logf("%s %s -> %d %s", method, url, resp.StatusCode, bytes.TrimSpace(raw))
	}

	return resp.StatusCode, decoded
}

// TestRESTAPI walks the documented endpoints over the HTTP API. It needs a Vault
// server with the plugin mounted and is skipped otherwise, so the unit test run
// stays self contained.
func TestRESTAPI(t *testing.T) {
	c := newRESTClient(t)

	// Names carry a timestamp so repeated runs against the same server do not
	// inherit the key versions of an earlier run.
	suffix := strconv.FormatInt(time.Now().UnixNano(), 10)
	keyName := "rest-sm2-" + suffix
	sm4Name := "rest-sm4-" + suffix
	missingName := "rest-missing-" + suffix

	input := base64.StdEncoding.EncodeToString([]byte("the quick brown fox"))
	otherInput := base64.StdEncoding.EncodeToString([]byte("a different input"))

	status, body := c.call(http.MethodPost, "keys/"+keyName, map[string]any{"type": "ecdsa-sm2"})
	wantStatus(t, status, http.StatusOK, "create a signing key")
	wantString(t, body, "ecdsa-sm2", "data", "type")
	wantNumber(t, body, 1, "data", "latest_version")

	// Both signatures are taken once and reused by the verification subtests.
	signatures := map[string]string{}
	for _, uid := range []string{"alice@example.com", "bob@example.com"} {
		status, body = c.call(http.MethodPost, "sign/"+keyName, map[string]any{"input": input, "uid": uid})
		wantStatus(t, status, http.StatusOK, "sign with the identifier "+uid)

		signed, ok := dig(t, body, "data", "signature").(string)
		if !ok || !strings.HasPrefix(signed, "vault:v1:") {
			t.Fatalf("signing with %q returned no versioned signature: %v", uid, body)
		}
		signatures[uid] = signed
	}

	t.Run("health", func(t *testing.T) {
		status, _ := c.callRoot(http.MethodGet, "sys/health", nil)
		wantStatus(t, status, http.StatusOK, "read the health endpoint")
	})

	t.Run("read key", func(t *testing.T) {
		status, body := c.call(http.MethodGet, "keys/"+keyName, nil)
		wantStatus(t, status, http.StatusOK, "read the key")
		wantString(t, body, keyName, "data", "name")
		wantString(t, body, "ecdsa-sm2", "data", "type")
		if !strings.Contains(digString(t, body, "data", "keys", "1", "public_key"), "BEGIN PUBLIC KEY") {
			t.Fatal("the key metadata does not carry the public key in PEM form")
		}
	})

	t.Run("encrypt and decrypt", func(t *testing.T) {
		status, body := c.call(http.MethodPost, "encrypt/"+keyName, map[string]any{"plaintext": input})
		wantStatus(t, status, http.StatusOK, "encrypt")

		ciphertext, ok := dig(t, body, "data", "ciphertext").(string)
		if !ok || !strings.HasPrefix(ciphertext, "vault:v1:") {
			t.Fatalf("encrypting returned no versioned ciphertext: %v", body)
		}

		status, body = c.call(http.MethodPost, "decrypt/"+keyName, map[string]any{"ciphertext": ciphertext})
		wantStatus(t, status, http.StatusOK, "decrypt")
		wantString(t, body, input, "data", "plaintext")
	})

	t.Run("verify needs the identifier the signature was made with", func(t *testing.T) {
		status, body := c.call(http.MethodPost, "verify/"+keyName, map[string]any{
			"input": input, "signature": signatures["alice@example.com"], "uid": "alice@example.com",
		})
		wantStatus(t, status, http.StatusOK, "verify with the matching identifier")
		wantBool(t, body, true, "data", "valid")

		// A mismatch is an answer, not an error: HTTP 200 with valid=false.
		for name, uid := range map[string]string{"without an identifier": "", "with a different identifier": "bob@example.com"} {
			request := map[string]any{"input": input, "signature": signatures["alice@example.com"]}
			if uid != "" {
				request["uid"] = uid
			}

			status, body = c.call(http.MethodPost, "verify/"+keyName, request)
			wantStatus(t, status, http.StatusOK, "verify "+name)
			wantBool(t, body, false, "data", "valid")
		}
	})

	t.Run("batch verification honours the per item identifier", func(t *testing.T) {
		status, body := c.call(http.MethodPost, "verify/"+keyName, map[string]any{
			"batch_input": []any{
				map[string]any{"input": input, "signature": signatures["alice@example.com"], "uid": "alice@example.com", "reference": "alice"},
				map[string]any{"input": input, "signature": signatures["bob@example.com"], "uid": "bob@example.com", "reference": "bob"},
				map[string]any{"input": input, "signature": signatures["alice@example.com"], "uid": "bob@example.com", "reference": "mismatched"},
			},
		})
		wantStatus(t, status, http.StatusOK, "verify a batch of signatures")

		wantBool(t, batchItem(t, body, 0), true, "valid")
		wantString(t, batchItem(t, body, 1), "bob", "reference")
		wantBool(t, batchItem(t, body, 1), true, "valid")
		wantBool(t, batchItem(t, body, 2), false, "valid")
	})

	t.Run("rejected hmac still reports valid", func(t *testing.T) {
		status, body := c.call(http.MethodPost, "hmac/"+keyName, map[string]any{"input": input})
		wantStatus(t, status, http.StatusOK, "generate an hmac")
		mac, ok := dig(t, body, "data", "hmac").(string)
		if !ok {
			t.Fatalf("generating an hmac returned none: %v", body)
		}

		status, body = c.call(http.MethodPost, "verify/"+keyName, map[string]any{"input": otherInput, "hmac": mac})
		wantStatus(t, status, http.StatusOK, "verify the hmac against a different input")
		wantBool(t, body, false, "data", "valid")

		// The batch form must carry the field too instead of omitting it.
		status, body = c.call(http.MethodPost, "verify/"+keyName, map[string]any{
			"batch_input": []any{map[string]any{"input": otherInput, "hmac": mac, "reference": "one"}},
		})
		wantStatus(t, status, http.StatusOK, "verify the hmac in a batch")
		wantBool(t, batchItem(t, body, 0), false, "valid")

		status, body = c.call(http.MethodPost, "verify/"+keyName, map[string]any{"input": input, "hmac": mac})
		wantStatus(t, status, http.StatusOK, "verify the hmac against the input it covers")
		wantBool(t, body, true, "data", "valid")
	})

	t.Run("certificate chain round trip", func(t *testing.T) {
		status, body := c.call(http.MethodPost, "keys/"+keyName+"/csr", map[string]any{
			"version": 1,
			"csr":     newTestCsrTemplate(t, "svc.internal"),
		})
		wantStatus(t, status, http.StatusOK, "generate a certificate request")
		wantString(t, body, keyName, "data", "name")
		wantString(t, body, "ecdsa-sm2", "data", "type")
		wantNumber(t, body, 1, "data", "key_version")

		csrPEM := digString(t, body, "data", "csr")
		csr := restParseCSR(t, csrPEM)
		if err := csr.CheckSignature(); err != nil {
			t.Fatalf("the generated request is not signed correctly: %v", err)
		}
		if csr.Subject.CommonName != "svc.internal" {
			t.Fatalf("the template subject was not carried over: %q", csr.Subject.CommonName)
		}
		if len(csr.DNSNames) != 1 || csr.DNSNames[0] != "svc.internal" {
			t.Fatalf("the template names were not carried over: %v", csr.DNSNames)
		}

		// The request has to hold the key of the version, not the throwaway key
		// that signed the template.
		status, body = c.call(http.MethodGet, "keys/"+keyName, nil)
		wantStatus(t, status, http.StatusOK, "read the key behind the request")
		storedKey := restParsePublicKey(t, digString(t, body, "data", "keys", "1", "public_key"))
		requestKey, ok := csr.PublicKey.(*ecdsa.PublicKey)
		if !ok || !storedKey.Equal(requestKey) {
			t.Fatal("the request does not carry the public key of the key version")
		}

		chainPEM, summary, err := testca.IssueChain([]byte(csrPEM), time.Hour, "rest api test ca")
		if err != nil {
			t.Fatalf("could not issue a chain for the request: %v", err)
		}
		t.Logf("certificate authority: %s", summary)

		status, body = c.call(http.MethodPost, "keys/"+keyName+"/set-certificate", map[string]any{
			"version":           1,
			"certificate_chain": string(chainPEM),
		})
		wantStatus(t, status, http.StatusOK, "store the certificate chain")
		wantNumber(t, body, 1, "data", "key_version")
		wantString(t, body, string(chainPEM), "data", "certificate_chain")

		status, body = c.call(http.MethodGet, "export/certificate-chain/"+keyName, nil)
		wantStatus(t, status, http.StatusOK, "export the certificate chain")
		if exported := digString(t, body, "data", "keys", "1"); strings.Count(exported, "BEGIN CERTIFICATE") != 2 {
			t.Fatalf("the exported chain does not hold both certificates: %q", exported)
		}

		status, body = c.call(http.MethodGet, "keys/"+keyName, nil)
		wantStatus(t, status, http.StatusOK, "read the key after storing the chain")
		if digString(t, body, "data", "keys", "1", "certificate_chain") == "" {
			t.Fatal("the key metadata does not expose the stored chain")
		}
	})

	t.Run("certificate chain must belong to the key", func(t *testing.T) {
		// A valid request signed by a real SM2 key, just not the stored one.
		foreignPEM := newTestCsrTemplate(t, "other.internal")
		chainPEM, _, err := testca.IssueChain([]byte(foreignPEM), time.Hour, "rest api test ca")
		if err != nil {
			t.Fatalf("could not issue a chain for the foreign request: %v", err)
		}

		status, body := c.call(http.MethodPost, "keys/"+keyName+"/set-certificate", map[string]any{
			"certificate_chain": string(chainPEM),
		})
		wantStatus(t, status, http.StatusBadRequest, "store a chain that belongs to another key")
		wantError(t, body, "does not match the key version selected")
	})

	t.Run("keys that cannot sign are rejected", func(t *testing.T) {
		status, body := c.call(http.MethodPost, "keys/"+sm4Name, map[string]any{})
		wantStatus(t, status, http.StatusOK, "create a symmetric key")
		wantString(t, body, "sm4-gcm96", "data", "type")

		status, body = c.call(http.MethodPost, "keys/"+sm4Name+"/csr", map[string]any{})
		wantStatus(t, status, http.StatusBadRequest, "generate a request for a symmetric key")
		wantError(t, body, "does not support certificates")

		status, body = c.call(http.MethodPost, "keys/"+sm4Name+"/set-certificate", map[string]any{
			"certificate_chain": "irrelevant",
		})
		wantStatus(t, status, http.StatusBadRequest, "store a chain on a symmetric key")
		wantError(t, body, "does not support certificates")
	})

	t.Run("user errors and missing keys", func(t *testing.T) {
		status, body := c.call(http.MethodPost, "keys/"+missingName+"/csr", map[string]any{})
		wantStatus(t, status, http.StatusBadRequest, "generate a request for an unknown key")
		wantError(t, body, "not found")

		// The handler answers a missing key with an empty response rather than
		// an error, so Vault turns it into a bare 404: the errors array is
		// empty and there is no message to read. A client can only go by the
		// status code here, which is the contract this asserts.
		status, body = c.call(http.MethodGet, "keys/"+missingName, nil)
		wantStatus(t, status, http.StatusNotFound, "read an unknown key")
		if errors, ok := body["errors"].([]any); !ok || len(errors) != 0 {
			t.Fatalf("reading an unknown key answered with more than an empty error list: %v", body)
		}

		status, body = c.call(http.MethodPost, "keys/"+keyName+"/set-certificate", map[string]any{
			"certificate_chain": "not a pem block",
		})
		wantStatus(t, status, http.StatusBadRequest, "store a chain that is not PEM")
		wantError(t, body, "could not decode PEM")

		status, body = c.call(http.MethodPost, "keys/"+keyName+"/set-certificate", map[string]any{
			"certificate_chain": "-----BEGIN PRIVATE KEY-----\nAAAA\n-----END PRIVATE KEY-----\n",
		})
		wantStatus(t, status, http.StatusBadRequest, "store a bundle without a certificate")
		wantError(t, body, "did not contain a PEM certificate")
	})
}

// dig returns the value at the end of path, failing the test when a step is
// missing. A missing field is exactly the kind of REST contract break the test
// has to catch.
func dig(t *testing.T, body map[string]any, path ...string) any {
	t.Helper()

	var current any = body
	for _, key := range path {
		object, ok := current.(map[string]any)
		if !ok {
			t.Fatalf("cannot read %q from %#v", key, current)
		}
		if current, ok = object[key]; !ok {
			t.Fatalf("the response has no %q field: %#v", key, object)
		}
	}

	return current
}

func digString(t *testing.T, body map[string]any, path ...string) string {
	t.Helper()

	value, ok := dig(t, body, path...).(string)
	if !ok {
		t.Fatalf("%v is not a string: %#v", path, dig(t, body, path...))
	}

	return value
}

func wantStatus(t *testing.T, got, want int, what string) {
	t.Helper()

	if got != want {
		t.Fatalf("%s: got HTTP %d, want %d", what, got, want)
	}
}

func wantString(t *testing.T, body map[string]any, want string, path ...string) {
	t.Helper()

	if got := dig(t, body, path...); got != want {
		t.Fatalf("%v: got %#v, want %q", path, got, want)
	}
}

func wantNumber(t *testing.T, body map[string]any, want float64, path ...string) {
	t.Helper()

	got, ok := dig(t, body, path...).(float64)
	if !ok || got != want {
		t.Fatalf("%v: got %#v, want %v", path, dig(t, body, path...), want)
	}
}

func wantBool(t *testing.T, body map[string]any, want bool, path ...string) {
	t.Helper()

	got, ok := dig(t, body, path...).(bool)
	if !ok {
		t.Fatalf("%v is not a bool: %#v", path, dig(t, body, path...))
	}
	if got != want {
		t.Fatalf("%v: got %v, want %v", path, got, want)
	}
}

// wantError checks the error list Vault returns for a rejected request.
func wantError(t *testing.T, body map[string]any, want string) {
	t.Helper()

	messages, ok := body["errors"].([]any)
	if !ok || len(messages) == 0 {
		t.Fatalf("the response carries no error list: %#v", body)
	}

	for _, message := range messages {
		if text, ok := message.(string); ok && strings.Contains(text, want) {
			return
		}
	}

	t.Fatalf("no error mentions %q: %v", want, messages)
}

func batchItem(t *testing.T, body map[string]any, index int) map[string]any {
	t.Helper()

	results, ok := dig(t, body, "data", "batch_results").([]any)
	if !ok || len(results) <= index {
		t.Fatalf("batch_results has no entry %d: %#v", index, body)
	}

	item, ok := results[index].(map[string]any)
	if !ok {
		t.Fatalf("batch_results[%d] is not an object: %#v", index, results[index])
	}

	return item
}

func restParseCSR(t *testing.T, csrPEM string) *smx509.CertificateRequest {
	t.Helper()

	block, _ := pem.Decode([]byte(csrPEM))
	if block == nil {
		t.Fatalf("the endpoint did not return a PEM block: %q", csrPEM)
	}

	csr, err := smx509.ParseCertificateRequest(block.Bytes)
	if err != nil {
		t.Fatalf("could not parse the returned request: %v", err)
	}

	return csr
}

func restParsePublicKey(t *testing.T, keyPEM string) *ecdsa.PublicKey {
	t.Helper()

	block, _ := pem.Decode([]byte(keyPEM))
	if block == nil {
		t.Fatalf("the key metadata does not hold a PEM block: %q", keyPEM)
	}

	key, err := smx509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		t.Fatalf("could not parse the stored public key: %v", err)
	}

	ecKey, ok := key.(*ecdsa.PublicKey)
	if !ok {
		t.Fatalf("the stored public key is a %T, not an ECDSA/SM2 key", key)
	}

	return ecKey
}
