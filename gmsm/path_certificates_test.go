package gmsm

import (
	"context"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"strings"
	"testing"
	"time"

	"github.com/emmansun/gmsm/sm2"
	"github.com/emmansun/gmsm/smx509"
	"github.com/hashicorp/vault/sdk/logical"
)

const certificateTestKey = "sm2-cert"

func mustWriteCertificate(t *testing.T, b *backend, s logical.Storage, path string, data map[string]interface{}) *logical.Response {
	t.Helper()

	resp, err := b.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      path,
		Storage:   s,
		Data:      data,
	})
	if err != nil {
		t.Fatalf("request to %q failed: %v", path, err)
	}
	if resp != nil && resp.IsError() {
		t.Fatalf("request to %q returned an error: %v", path, resp.Error())
	}

	return resp
}

func mustFailCertificate(t *testing.T, b *backend, s logical.Storage, path string, data map[string]interface{}, want string) {
	t.Helper()

	resp, err := b.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      path,
		Storage:   s,
		Data:      data,
	})

	var got string
	switch {
	case resp != nil && resp.IsError():
		// The handler answers user errors with a response that carries the
		// message, and a bare logical.ErrInvalidRequest on the side.
		got = resp.Error().Error()
	case err != nil:
		got = err.Error()
	}
	if got == "" {
		t.Fatalf("expected the request to %q to fail", path)
	}
	if !strings.Contains(got, want) {
		t.Fatalf("expected the error to mention %q, got %q", want, got)
	}
}

// certificatePolicy loads the policy the way the path handlers do, so the test
// can reach the key material it needs to sign certificates with.
func certificatePolicy(t *testing.T, b *backend, s logical.Storage, name string) *Policy {
	t.Helper()

	p, _, err := b.GetPolicy(context.Background(), PolicyRequest{
		Storage: s,
		Name:    name,
	}, b.GetRandomReader())
	if err != nil {
		t.Fatalf("could not load policy %q: %v", name, err)
	}
	if p == nil {
		t.Fatalf("policy %q does not exist", name)
	}

	return p
}

// signerForVersion rebuilds the SM2 private key of a key version, which the
// backend never exposes over the API.
func signerForVersion(t *testing.T, p *Policy, version int) *sm2.PrivateKey {
	t.Helper()

	entry, err := p.safeGetKeyEntry(version)
	if err != nil {
		t.Fatalf("could not read key version %d: %v", version, err)
	}

	key, err := sm2.NewPrivateKeyFromInt(entry.EC_D)
	if err != nil {
		t.Fatalf("could not rebuild the SM2 private key: %v", err)
	}

	return key
}

func newTestCACertificate(t *testing.T, key *sm2.PrivateKey, commonName string) (*smx509.Certificate, []byte) {
	t.Helper()

	template := &smx509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: commonName},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              smx509.KeyUsageCertSign | smx509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}

	der, err := smx509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("could not create the CA certificate: %v", err)
	}

	cert, err := smx509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("could not parse the CA certificate: %v", err)
	}

	return cert, der
}

func newTestLeafCertificate(t *testing.T, key *sm2.PrivateKey, parent *smx509.Certificate, commonName string) []byte {
	t.Helper()

	template := &smx509.Certificate{
		SerialNumber:          big.NewInt(2),
		Subject:               pkix.Name{CommonName: commonName},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              smx509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
	}

	der, err := smx509.CreateCertificate(rand.Reader, template, parent, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("could not create the leaf certificate: %v", err)
	}

	return der
}

func newTestCsrTemplate(t *testing.T, commonName string) string {
	t.Helper()

	// The template is produced with a throwaway key: only its subject and names
	// are reused, the key and signature come from the version being requested.
	key, err := sm2.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("could not generate a template key: %v", err)
	}

	der, err := smx509.CreateCertificateRequest(rand.Reader, &smx509.CertificateRequest{
		Subject:  pkix.Name{CommonName: commonName},
		DNSNames: []string{commonName},
	}, key)
	if err != nil {
		t.Fatalf("could not create the template request: %v", err)
	}

	return encodeCertificatePEM(der, "CERTIFICATE REQUEST")
}

func encodeCertificatePEM(der []byte, blockType string) string {
	return string(pem.EncodeToMemory(&pem.Block{Type: blockType, Bytes: der}))
}

func TestCreateCsrEndpoint(t *testing.T) {
	b, s := createBackendWithStorage(t)
	mustWriteCertificate(t, b, s, "keys/"+certificateTestKey, map[string]interface{}{"type": "sm2"})

	resp := mustWriteCertificate(t, b, s, "keys/"+certificateTestKey+"/csr", map[string]interface{}{
		"csr": newTestCsrTemplate(t, "svc.internal"),
	})

	if version, _ := resp.Data["key_version"].(int); version != 1 {
		t.Fatalf("expected the latest key version in the response, got %#v", resp.Data)
	}

	csrPEM, _ := resp.Data["csr"].(string)
	block, _ := pem.Decode([]byte(csrPEM))
	if block == nil || block.Type != "CERTIFICATE REQUEST" {
		t.Fatalf("expected a PEM encoded certificate request, got %q", csrPEM)
	}

	csr, err := smx509.ParseCertificateRequest(block.Bytes)
	if err != nil {
		t.Fatalf("could not parse the generated request: %v", err)
	}
	if err := csr.CheckSignature(); err != nil {
		t.Fatalf("the generated request is not signed correctly: %v", err)
	}
	if csr.Subject.CommonName != "svc.internal" {
		t.Fatalf("the template subject was not carried over: %q", csr.Subject.CommonName)
	}
	if len(csr.DNSNames) != 1 || csr.DNSNames[0] != "svc.internal" {
		t.Fatalf("the template names were not carried over: %v", csr.DNSNames)
	}

	// The request has to be for the key stored in the backend, not for the key
	// that signed the template.
	p := certificatePolicy(t, b, s, certificateTestKey)
	entry, err := p.safeGetKeyEntry(1)
	if err != nil {
		t.Fatalf("could not read key version 1: %v", err)
	}
	storedKey := &ecdsa.PublicKey{Curve: sm2.P256(), X: entry.EC_X, Y: entry.EC_Y}

	csrKey, ok := csr.PublicKey.(*ecdsa.PublicKey)
	if !ok {
		t.Fatalf("unexpected public key type %T", csr.PublicKey)
	}
	if !storedKey.Equal(csrKey) {
		t.Fatal("the request does not carry the public key of the selected key version")
	}
}

func TestCreateCsrEndpointWithoutTemplate(t *testing.T) {
	b, s := createBackendWithStorage(t)
	mustWriteCertificate(t, b, s, "keys/"+certificateTestKey, map[string]interface{}{"type": "sm2"})

	resp := mustWriteCertificate(t, b, s, "keys/"+certificateTestKey+"/csr", nil)

	block, _ := pem.Decode([]byte(resp.Data["csr"].(string)))
	if block == nil {
		t.Fatal("expected a PEM encoded certificate request")
	}
	csr, err := smx509.ParseCertificateRequest(block.Bytes)
	if err != nil {
		t.Fatalf("could not parse the generated request: %v", err)
	}
	if err := csr.CheckSignature(); err != nil {
		t.Fatalf("the generated request is not signed correctly: %v", err)
	}
	if csr.Subject.CommonName != "" {
		t.Fatalf("expected an empty subject, got %q", csr.Subject.CommonName)
	}
}

func TestCreateCsrEndpointErrors(t *testing.T) {
	b, s := createBackendWithStorage(t)
	mustWriteCertificate(t, b, s, "keys/sm4-key", nil)
	mustWriteCertificate(t, b, s, "keys/"+certificateTestKey, map[string]interface{}{"type": "sm2"})

	cases := []struct {
		name string
		path string
		data map[string]interface{}
		want string
	}{
		{
			name: "unknown key",
			path: "keys/missing/csr",
			want: "not found",
		},
		{
			name: "key type cannot sign",
			path: "keys/sm4-key/csr",
			want: "does not support certificates",
		},
		{
			name: "unknown version",
			path: "keys/" + certificateTestKey + "/csr",
			data: map[string]interface{}{"version": 9},
			want: "no such key version",
		},
		{
			name: "template is not pem",
			path: "keys/" + certificateTestKey + "/csr",
			data: map[string]interface{}{"csr": "definitely not a pem block"},
			want: "could not decode PEM",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			mustFailCertificate(t, b, s, tc.path, tc.data, tc.want)
		})
	}
}

func TestSetCertificateEndpoint(t *testing.T) {
	b, s := createBackendWithStorage(t)
	mustWriteCertificate(t, b, s, "keys/"+certificateTestKey, map[string]interface{}{"type": "sm2"})

	key := signerForVersion(t, certificatePolicy(t, b, s, certificateTestKey), 1)
	ca, caDER := newTestCACertificate(t, key, "test-ca")
	leafDER := newTestLeafCertificate(t, key, ca, "svc.internal")
	chain := encodeCertificatePEM(leafDER, "CERTIFICATE") + encodeCertificatePEM(caDER, "CERTIFICATE")

	resp := mustWriteCertificate(t, b, s, "keys/"+certificateTestKey+"/set-certificate", map[string]interface{}{
		"certificate_chain": chain,
	})
	if got, _ := resp.Data["certificate_chain"].(string); got != chain {
		t.Fatalf("the response does not echo the imported chain, got %q", got)
	}

	// The chain has to land on the key version so export and read can use it.
	p := certificatePolicy(t, b, s, certificateTestKey)
	entry, err := p.safeGetKeyEntry(1)
	if err != nil {
		t.Fatalf("could not read key version 1: %v", err)
	}
	if len(entry.CertificateChain) != 2 {
		t.Fatalf("expected two certificates on the key version, got %d", len(entry.CertificateChain))
	}

	exportResp, err := b.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.ReadOperation,
		Path:      "export/certificate-chain/" + certificateTestKey,
		Storage:   s,
	})
	if err != nil {
		t.Fatalf("export failed: %v", err)
	}
	if exportResp == nil || exportResp.IsError() {
		t.Fatalf("export returned an error: %v", exportResp)
	}
	exported, _ := exportResp.Data["keys"].(map[string]string)
	if !strings.Contains(exported["1"], "BEGIN CERTIFICATE") {
		t.Fatalf("the exported chain is not a PEM bundle: %q", exported["1"])
	}

	readResp, err := b.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.ReadOperation,
		Path:      "keys/" + certificateTestKey,
		Storage:   s,
	})
	if err != nil {
		t.Fatalf("reading the key failed: %v", err)
	}
	keys, _ := readResp.Data["keys"].(map[string]map[string]interface{})
	if _, ok := keys["1"]["certificate_chain"]; !ok {
		t.Fatalf("the key metadata does not expose the chain: %#v", keys["1"])
	}
}

func TestSetCertificateEndpointRejectsForeignKey(t *testing.T) {
	b, s := createBackendWithStorage(t)
	mustWriteCertificate(t, b, s, "keys/"+certificateTestKey, map[string]interface{}{"type": "sm2"})
	mustWriteCertificate(t, b, s, "keys/other-key", map[string]interface{}{"type": "sm2"})

	foreignKey := signerForVersion(t, certificatePolicy(t, b, s, "other-key"), 1)
	ca, caDER := newTestCACertificate(t, foreignKey, "test-ca")
	leafDER := newTestLeafCertificate(t, foreignKey, ca, "svc.internal")
	chain := encodeCertificatePEM(leafDER, "CERTIFICATE") + encodeCertificatePEM(caDER, "CERTIFICATE")

	mustFailCertificate(t, b, s, "keys/"+certificateTestKey+"/set-certificate", map[string]interface{}{
		"certificate_chain": chain,
	}, "does not match the key version selected")
}

func TestSetCertificateEndpointRejectsCAFirst(t *testing.T) {
	b, s := createBackendWithStorage(t)
	mustWriteCertificate(t, b, s, "keys/"+certificateTestKey, map[string]interface{}{"type": "sm2"})

	key := signerForVersion(t, certificatePolicy(t, b, s, certificateTestKey), 1)
	ca, caDER := newTestCACertificate(t, key, "test-ca")
	leafDER := newTestLeafCertificate(t, key, ca, "svc.internal")

	// Same certificates, wrong order.
	chain := encodeCertificatePEM(caDER, "CERTIFICATE") + encodeCertificatePEM(leafDER, "CERTIFICATE")

	mustFailCertificate(t, b, s, "keys/"+certificateTestKey+"/set-certificate", map[string]interface{}{
		"certificate_chain": chain,
	}, "not a leaf certificate")
}

func TestSetCertificateEndpointRejectsInvalidInput(t *testing.T) {
	b, s := createBackendWithStorage(t)
	mustWriteCertificate(t, b, s, "keys/sm4-key", nil)
	mustWriteCertificate(t, b, s, "keys/"+certificateTestKey, map[string]interface{}{"type": "sm2"})

	cases := []struct {
		name string
		path string
		data map[string]interface{}
		want string
	}{
		{
			name: "key type cannot sign",
			path: "keys/sm4-key/set-certificate",
			data: map[string]interface{}{"certificate_chain": "irrelevant"},
			want: "does not support certificates",
		},
		{
			name: "unknown key",
			path: "keys/missing/set-certificate",
			data: map[string]interface{}{"certificate_chain": "irrelevant"},
			want: "not found",
		},
		{
			name: "chain is not pem",
			path: "keys/" + certificateTestKey + "/set-certificate",
			data: map[string]interface{}{"certificate_chain": "not a pem block"},
			want: "could not decode PEM",
		},
		{
			name: "chain holds no certificate",
			path: "keys/" + certificateTestKey + "/set-certificate",
			data: map[string]interface{}{"certificate_chain": encodeCertificatePEM([]byte("not a certificate"), "PRIVATE KEY")},
			want: "did not contain a PEM certificate",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			mustFailCertificate(t, b, s, tc.path, tc.data, tc.want)
		})
	}
}
