package pki

import (
	"bytes"
	"encoding/asn1"
	"encoding/base64"
	"math/big"
	"net/http"
	"net/url"
	"testing"
	"time"

	"github.com/emmansun/gmsm/smx509"
	"github.com/emmansun/vault-gmsm-plugin/internal/ocspclient"
	"github.com/hashicorp/vault/sdk/logical"
)

// askOCSP asks about one serial and reads the answer, which is checked against
// the authority that should have signed it.
func askOCSP(t *testing.T, b *backend, s logical.Storage, serial *big.Int, issuer *smx509.Certificate) (*ocspclient.Response, int) {
	t.Helper()

	der, err := ocspclient.Request(serial, issuer)
	if err != nil {
		t.Fatalf("could not build the request: %v", err)
	}

	return sendOCSP(t, b, s, logical.UpdateOperation, "ocsp", map[string]interface{}{
		"request": base64.StdEncoding.EncodeToString(der),
	}, issuer)
}

// sendOCSP sends whatever encoding it is given and reads the answer. A refusal
// carries no signature, so only an answer that claims success is verified.
func sendOCSP(t *testing.T, b *backend, s logical.Storage, op logical.Operation, path string, data map[string]interface{}, issuer *smx509.Certificate) (*ocspclient.Response, int) {
	t.Helper()

	resp, err := request(t, b, s, op, path, data)
	if err != nil {
		t.Fatalf("%s failed: %v", path, err)
	}
	if resp == nil {
		t.Fatalf("%s answered with nothing", path)
	}
	if resp.IsError() {
		// A request that cannot be answered is answered in the protocol, not
		// with an error of the API.
		t.Fatalf("%s answered with an API error: %v", path, resp.Error())
	}

	body, ok := resp.Data[logical.HTTPRawBody].([]byte)
	if !ok {
		t.Fatalf("%s answered with %v, not a raw body", path, resp.Data)
	}
	code, ok := resp.Data[logical.HTTPStatusCode].(int)
	if !ok {
		t.Fatalf("%s answered without a status code", path)
	}
	if contentType := resp.Data[logical.HTTPContentType]; contentType != ocspContentType {
		t.Fatalf("%s answered with content type %v, want %s", path, contentType, ocspContentType)
	}

	answer, err := ocspclient.Verify(body, issuer)
	if err != nil {
		t.Fatalf("the answer of %s does not verify: %v", path, err)
	}

	return answer, code
}

// askAboutIssues issues one certificate and asks the responder about it.
func askAboutIssues(t *testing.T, b *backend, s logical.Storage, commonName string) (*smx509.Certificate, *logical.Response) {
	t.Helper()

	issued := mustWrite(t, b, s, "issue/web", map[string]interface{}{
		"common_name": commonName,
	})

	return parseCert(t, pemData(t, issued.Data, "certificate")), issued
}

func TestOCSPAnswersGoodThenRevoked(t *testing.T) {
	b, storage := newTestBackend(t)
	root := generateRoot(t, b, storage)
	writeWebRole(t, b, storage)

	leaf, issued := askAboutIssues(t, b, storage, "web.example.com")

	answer, code := askOCSP(t, b, storage, leaf.SerialNumber, root)
	if code != http.StatusOK || answer.Status != ocspclient.Successful {
		t.Fatalf("the responder answered with status %d and HTTP %d", answer.Status, code)
	}
	if answer.CertStatus != ocspclient.CertGood {
		t.Fatalf("an issued certificate is reported as %v", answer.CertStatus)
	}
	if answer.Serial.Cmp(leaf.SerialNumber) != 0 {
		t.Fatalf("the answer is about serial %x, want %x", answer.Serial, leaf.SerialNumber)
	}

	// An answer that does not say how long it holds leaves a client nothing to
	// refresh; the two times are what it is good between.
	if answer.NextUpdate.Sub(answer.ThisUpdate) != ocspValidity {
		t.Fatalf("the answer is good for %v, want %v", answer.NextUpdate.Sub(answer.ThisUpdate), ocspValidity)
	}
	if time.Since(answer.ThisUpdate) > time.Minute || time.Until(answer.ThisUpdate) > time.Minute {
		t.Fatalf("the answer says it was made at %s", answer.ThisUpdate)
	}

	revoked := mustWrite(t, b, storage, "revoke", map[string]interface{}{
		"serial_number": pemData(t, issued.Data, "serial_number"),
	})
	revokedAt := time.Unix(revoked.Data["revocation_time"].(int64), 0).UTC()

	answer, code = askOCSP(t, b, storage, leaf.SerialNumber, root)
	if code != http.StatusOK || answer.Status != ocspclient.Successful {
		t.Fatalf("the responder answered with status %d and HTTP %d", answer.Status, code)
	}
	if answer.CertStatus != ocspclient.CertRevoked {
		t.Fatalf("a revoked certificate is reported as %v", answer.CertStatus)
	}
	if !answer.RevokedAt.Equal(revokedAt) {
		t.Fatalf("the revocation is reported at %s, want %s", answer.RevokedAt, revokedAt)
	}
}

func TestOCSPAnswersUnknownForASerialItNeverIssued(t *testing.T) {
	b, storage := newTestBackend(t)
	root := generateRoot(t, b, storage)

	answer, code := askOCSP(t, b, storage, big.NewInt(0x5eed), root)
	if code != http.StatusOK || answer.Status != ocspclient.Successful {
		t.Fatalf("the responder answered with status %d and HTTP %d", answer.Status, code)
	}
	if answer.CertStatus != ocspclient.CertUnknown {
		t.Fatalf("a serial the mount never issued is reported as %v", answer.CertStatus)
	}
}

func TestOCSPRefusesARequestAboutAnotherAuthority(t *testing.T) {
	b, storage := newTestBackend(t)
	generateRoot(t, b, storage)

	// An authority of another mount, which this one has never seen. It cannot
	// answer for it, and saying unknown would leave the client with a lie.
	other, otherStorage := newTestBackend(t)
	otherRoot := generateRoot(t, other, otherStorage)

	answer, code := askOCSP(t, b, storage, big.NewInt(1), otherRoot)
	if code != http.StatusUnauthorized {
		t.Fatalf("a request about another authority answered with HTTP %d, want %d", code, http.StatusUnauthorized)
	}
	if answer.Status != ocspclient.Unauthorized {
		t.Fatalf("the refusal carries status %d, want %d", answer.Status, ocspclient.Unauthorized)
	}
}

func TestOCSPReadsTheRequestFromThePath(t *testing.T) {
	b, storage := newTestBackend(t)
	root := generateRoot(t, b, storage)
	writeWebRole(t, b, storage)

	leaf, _ := askAboutIssues(t, b, storage, "web.example.com")

	der, err := ocspclient.Request(leaf.SerialNumber, root)
	if err != nil {
		t.Fatalf("could not build the request: %v", err)
	}

	// The base64 alphabet holds characters that a client puts into a URL
	// escaped, which is why the path is unescaped before it is decoded.
	encoded := url.QueryEscape(base64.StdEncoding.EncodeToString(der))

	answer, code := sendOCSP(t, b, storage, logical.ReadOperation, "ocsp/"+encoded, nil, root)
	if code != http.StatusOK || answer.Status != ocspclient.Successful {
		t.Fatalf("the responder answered with status %d and HTTP %d", answer.Status, code)
	}
	if answer.CertStatus != ocspclient.CertGood {
		t.Fatalf("the answer read from the path reports %v", answer.CertStatus)
	}
	if answer.Serial.Cmp(leaf.SerialNumber) != 0 {
		t.Fatalf("the answer is about serial %x, want %x", answer.Serial, leaf.SerialNumber)
	}
}

func TestOCSPRefusesWhatItCannotRead(t *testing.T) {
	b, storage := newTestBackend(t)
	root := generateRoot(t, b, storage)
	writeWebRole(t, b, storage)

	leaf, _ := askAboutIssues(t, b, storage, "web.example.com")

	request, err := ocspclient.Request(leaf.SerialNumber, root)
	if err != nil {
		t.Fatalf("could not build the request: %v", err)
	}

	// A digest this responder does not compute is refused before the two
	// identifiers are compared, so the hashes in the request do not matter.
	sm3, err := asn1.Marshal(asn1.ObjectIdentifier{1, 2, 156, 10197, 1, 401})
	if err != nil {
		t.Fatalf("could not encode the digest: %v", err)
	}
	other, err := asn1.Marshal(asn1.ObjectIdentifier{1, 2, 156, 10197, 1, 502})
	if err != nil {
		t.Fatalf("could not encode the digest: %v", err)
	}
	unknownDigest := bytes.Replace(request, sm3, other, 1)
	if bytes.Equal(unknownDigest, request) {
		t.Fatal("the request does not name the digest it should")
	}

	cases := []struct {
		name    string
		encoded string
	}{
		{"nothing", ""},
		{"not base64", "this is not base64"},
		{"not an OCSP request", base64.StdEncoding.EncodeToString([]byte("this is not an OCSP request"))},
		{"a digest the responder does not compute", base64.StdEncoding.EncodeToString(unknownDigest)},
		{"a request over the bound", base64.StdEncoding.EncodeToString(make([]byte, ocspMaxRequest+1))},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			answer, code := sendOCSP(t, b, storage, logical.UpdateOperation, "ocsp", map[string]interface{}{
				"request": tc.encoded,
			}, root)

			if code != http.StatusBadRequest {
				t.Fatalf("the refusal answered with HTTP %d, want %d", code, http.StatusBadRequest)
			}
			if answer.Status != ocspclient.MalformedRequest {
				t.Fatalf("the refusal carries status %d, want %d", answer.Status, ocspclient.MalformedRequest)
			}
		})
	}
}

func TestOCSPAnswersWithTheAuthorityOfTheCertificate(t *testing.T) {
	b, storage := newTestBackend(t)
	oldRoot := generateRoot(t, b, storage)
	writeWebRole(t, b, storage)

	before, issued := askAboutIssues(t, b, storage, "before.example.com")

	rotated := mustWrite(t, b, storage, "root/rotate/internal", map[string]interface{}{
		"common_name": "Rotated Root CA",
	})
	newRoot := parseCert(t, pemData(t, rotated.Data, "certificate"))

	// The mount holds both authorities, and only one of them issued this
	// certificate. The other one knows nothing about it.
	answer, _ := askOCSP(t, b, storage, before.SerialNumber, oldRoot)
	if answer.CertStatus != ocspclient.CertGood {
		t.Fatalf("the certificate is reported as %v under the authority that signed it", answer.CertStatus)
	}

	answer, code := askOCSP(t, b, storage, before.SerialNumber, newRoot)
	if code != http.StatusOK || answer.Status != ocspclient.Successful {
		t.Fatalf("the answer of the new authority carries status %d and HTTP %d", answer.Status, code)
	}
	if answer.CertStatus != ocspclient.CertUnknown {
		t.Fatalf("the certificate is reported as %v under the authority that did not sign it", answer.CertStatus)
	}

	// A revocation is recorded against the authority as well, so it does not
	// travel to the other one with the serial.
	mustWrite(t, b, storage, "revoke", map[string]interface{}{
		"serial_number": pemData(t, issued.Data, "serial_number"),
	})

	answer, _ = askOCSP(t, b, storage, before.SerialNumber, oldRoot)
	if answer.CertStatus != ocspclient.CertRevoked {
		t.Fatalf("the revoked certificate is reported as %v", answer.CertStatus)
	}

	answer, _ = askOCSP(t, b, storage, before.SerialNumber, newRoot)
	if answer.CertStatus != ocspclient.CertUnknown {
		t.Fatalf("the revocation of another authority leaked: the certificate is %v under the new one", answer.CertStatus)
	}
}
