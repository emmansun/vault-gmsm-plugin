package gmsm

import (
	"context"
	"encoding/base64"
	"strings"
	"testing"
	"time"

	"github.com/emmansun/vault-gmsm-plugin/internal/testca"
	"github.com/hashicorp/vault/sdk/logical"
)

// TestCertificateWalkthrough mirrors the flow the CI walkthrough drives with the
// CLI: ask for a certificate without a template, let an external CA issue the
// chain, store it back and export it. The endpoint tests each start from a
// template; this one starts from the request a caller that only has a key gets,
// which is an empty subject, and follows it all the way to the export.
func TestCertificateWalkthrough(t *testing.T) {
	b, s := createBackendWithStorage(t)
	const key = "walkthrough"

	mustWriteCertificate(t, b, s, "keys/"+key, map[string]interface{}{"type": "sm2"})

	csrResp := mustWriteCertificate(t, b, s, "keys/"+key+"/csr", map[string]interface{}{"version": 1})
	csrPEM, _ := csrResp.Data["csr"].(string)
	if !strings.Contains(csrPEM, "BEGIN CERTIFICATE REQUEST") {
		t.Fatalf("the endpoint did not return a PEM request: %q", csrPEM)
	}

	chain, summary, err := testca.IssueChain([]byte(csrPEM), time.Hour, "walkthrough ca")
	if err != nil {
		t.Fatalf("the test CA could not sign the request: %v", err)
	}
	t.Logf("certificate authority: %s", summary)

	mustWriteCertificate(t, b, s, "keys/"+key+"/set-certificate", map[string]interface{}{
		"version":           1,
		"certificate_chain": string(chain),
	})

	resp, err := b.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.ReadOperation,
		Path:      "export/certificate-chain/" + key,
		Storage:   s,
	})
	if err != nil {
		t.Fatalf("exporting the chain failed: %v", err)
	}
	if resp == nil || resp.IsError() {
		t.Fatalf("exporting the chain returned no chain: %#v", resp)
	}

	keys, ok := resp.Data["keys"].(map[string]string)
	if !ok {
		t.Fatalf("the export does not hold a version to chain map: %#v", resp.Data)
	}
	if got := strings.Count(keys["1"], "BEGIN CERTIFICATE"); got != 2 {
		t.Fatalf("the exported chain holds %d certificates, want the leaf and the CA", got)
	}

	// Storing the chain must not disturb the key: the identifier still drives the
	// Z value afterwards, in the order the CI walkthrough uses it.
	input := base64.StdEncoding.EncodeToString([]byte("my secret data"))

	write := func(path string, data map[string]interface{}) *logical.Response {
		return mustWriteCertificate(t, b, s, path, data)
	}

	sign := func(uid string) string {
		data := map[string]interface{}{"input": input}
		if uid != "" {
			data["uid"] = uid
		}
		signature, _ := write("sign/"+key, data).Data["signature"].(string)

		return signature
	}

	verify := func(signature, uid string) bool {
		data := map[string]interface{}{"input": input, "signature": signature}
		if uid != "" {
			data["uid"] = uid
		}
		valid, _ := write("verify/"+key, data).Data["valid"].(bool)

		return valid
	}

	identified := sign("alice@example.com")
	if !strings.HasPrefix(identified, "vault:v1:") {
		t.Fatalf("signing returned %q, want a vault:v1 signature", identified)
	}
	if !verify(identified, "alice@example.com") {
		t.Fatal("the signature does not verify with the identifier it was signed with")
	}
	if verify(identified, "") {
		t.Fatal("the signature verified without an identifier")
	}
	if verify(identified, "bob@example.com") {
		t.Fatal("the signature verified with another identifier")
	}
}
