package testca_test

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/x509/pkix"
	"encoding/pem"
	"strings"
	"testing"
	"time"

	"github.com/emmansun/gmsm/sm2"
	"github.com/emmansun/gmsm/smx509"
	"github.com/emmansun/vault-gmsm-plugin/internal/testca"
)

func newRequest(t *testing.T) ([]byte, *sm2.PrivateKey) {
	t.Helper()

	key, err := sm2.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("could not generate the request key: %v", err)
	}

	der, err := smx509.CreateCertificateRequest(rand.Reader, &smx509.CertificateRequest{
		Subject:        pkix.Name{CommonName: "svc.internal", Organization: []string{"test"}},
		DNSNames:       []string{"svc.internal", "svc.internal.default.svc"},
		EmailAddresses: []string{"svc@example.com"},
	}, key)
	if err != nil {
		t.Fatalf("could not create the request: %v", err)
	}

	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der}), key
}

func parseChain(t *testing.T, chainPEM []byte) (*smx509.Certificate, *smx509.Certificate) {
	t.Helper()

	var certificates []*smx509.Certificate
	remaining := chainPEM
	for len(remaining) > 0 {
		var block *pem.Block
		block, remaining = pem.Decode(remaining)
		if block == nil {
			break
		}
		cert, err := smx509.ParseCertificate(block.Bytes)
		if err != nil {
			t.Fatalf("could not parse a certificate of the chain: %v", err)
		}
		certificates = append(certificates, cert)
	}

	if len(certificates) != 2 {
		t.Fatalf("expected a leaf and a CA certificate, got %d", len(certificates))
	}

	return certificates[0], certificates[1]
}

func TestIssueChain(t *testing.T) {
	requestPEM, requestKey := newRequest(t)

	chainPEM, summary, err := testca.IssueChain(requestPEM, time.Hour, "unit test ca")
	if err != nil {
		t.Fatalf("issuing the chain failed: %v", err)
	}

	leaf, ca := parseChain(t, chainPEM)

	if leaf.IsCA {
		t.Fatal("the first certificate of the chain is a CA, so set-certificate would reject it")
	}
	if !ca.IsCA || ca.KeyUsage&smx509.KeyUsageCertSign == 0 {
		t.Fatal("the second certificate of the chain is not a signing CA")
	}
	if err := leaf.CheckSignatureFrom(ca); err != nil {
		t.Fatalf("the leaf is not signed by the CA: %v", err)
	}

	leafKey, ok := leaf.PublicKey.(*ecdsa.PublicKey)
	if !ok {
		t.Fatalf("the leaf holds a %T, not an ECDSA/SM2 key", leaf.PublicKey)
	}
	if !leafKey.Equal(&requestKey.PublicKey) {
		t.Fatal("the leaf does not carry the public key of the request")
	}

	if leaf.Subject.CommonName != "svc.internal" {
		t.Fatalf("the subject of the request was not carried over: %q", leaf.Subject.CommonName)
	}
	if len(leaf.DNSNames) != 2 || leaf.DNSNames[0] != "svc.internal" {
		t.Fatalf("the names of the request were not carried over: %v", leaf.DNSNames)
	}
	if len(leaf.EmailAddresses) != 1 || leaf.EmailAddresses[0] != "svc@example.com" {
		t.Fatalf("the email addresses of the request were not carried over: %v", leaf.EmailAddresses)
	}

	if !strings.Contains(summary, "svc.internal") {
		t.Fatalf("the summary does not name what was issued: %q", summary)
	}
}

func TestIssueChainRejectsBadRequests(t *testing.T) {
	cases := []struct {
		name    string
		request func(t *testing.T) []byte
		want    string
	}{
		{
			name: "not pem",
			request: func(t *testing.T) []byte {
				return []byte("not a certificate request")
			},
			want: "not PEM encoded",
		},
		{
			name: "tampered subject",
			request: func(t *testing.T) []byte {
				requestPEM, _ := newRequest(t)

				block, _ := pem.Decode(requestPEM)
				der := append([]byte(nil), block.Bytes...)
				// Flip a byte of the common name: the encoding stays valid, so the
				// only thing that can fail is the signature check.
				index := bytes.Index(der, []byte("svc.internal"))
				if index < 0 {
					t.Fatal("could not find the common name in the encoded request")
				}
				der[index] ^= 0x01

				return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der})
			},
			want: "signature is invalid",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			chain, summary, err := testca.IssueChain(tc.request(t), time.Hour, "unit test ca")
			if err == nil {
				t.Fatal("a bad request was accepted")
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("the error does not mention %q: %v", tc.want, err)
			}
			if chain != nil || summary != "" {
				t.Fatalf("a failed issue returned a chain: %q / %q", chain, summary)
			}
		})
	}
}
