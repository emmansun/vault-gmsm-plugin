package main

import (
	"crypto/rand"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/emmansun/gmsm/sm2"
	"github.com/emmansun/gmsm/smx509"
)

var oidCertificatePolicies = asn1.ObjectIdentifier{2, 5, 29, 32}

// policyInformation is one entry of the certificate policies extension, which
// carries no qualifiers here.
type policyInformation struct {
	Policy asn1.ObjectIdentifier
}

// checkable writes a DER document as a PEM block and answers with its path,
// which is the form the walkthrough feeds the tool.
func checkable(t *testing.T, blockType string, der []byte) string {
	t.Helper()

	path := filepath.Join(t.TempDir(), "document.pem")
	file, err := os.Create(path)
	if err != nil {
		t.Fatalf("could not create %s: %v", path, err)
	}
	defer file.Close()

	if err := pem.Encode(file, &pem.Block{Type: blockType, Bytes: der}); err != nil {
		t.Fatalf("could not write %s: %v", path, err)
	}

	return path
}

func newAuthority(t *testing.T) (*sm2.PrivateKey, *smx509.Certificate) {
	t.Helper()

	key, err := sm2.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("could not generate a key: %v", err)
	}

	now := time.Now()
	template := &smx509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "Test CA"},
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.Add(24 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              smx509.KeyUsageCertSign | smx509.KeyUsageCRLSign,
		SignatureAlgorithm:    smx509.SM2WithSM3,
	}
	der, err := smx509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("could not create the authority: %v", err)
	}

	cert, err := smx509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("could not parse the authority: %v", err)
	}

	return key, cert
}

func TestCheckCRLTellsADeltaFromAFullList(t *testing.T) {
	key, ca := newAuthority(t)
	caPath := checkable(t, "CERTIFICATE", ca.Raw)

	delta := func(base int64) string {
		indicator, err := asn1.Marshal(big.NewInt(base))
		if err != nil {
			t.Fatalf("could not encode the base: %v", err)
		}

		now := time.Now()
		der, err := smx509.CreateRevocationList(rand.Reader, &smx509.RevocationList{
			Number:             big.NewInt(base + 1),
			ThisUpdate:         now,
			NextUpdate:         now.Add(time.Hour),
			ExtraExtensions:    []pkix.Extension{{Id: oidDeltaCRLIndicator, Critical: true, Value: indicator}},
			SignatureAlgorithm: smx509.SM2WithSM3,
		}, ca, key)
		if err != nil {
			t.Fatalf("could not create the delta: %v", err)
		}

		return checkable(t, "X509 CRL", der)
	}

	if err := checkCRL(delta(7), caPath, "", false, -1, "7"); err != nil {
		t.Fatalf("a delta of base 7 was refused: %v", err)
	}
	if err := checkCRL(delta(7), caPath, "", false, -1, "6"); err == nil {
		t.Fatal("a delta of base 7 passed as one of base 6")
	}
	if err := checkCRL(delta(7), caPath, "", false, -1, ""); err != nil {
		t.Fatalf("a delta was refused when no base was asked for: %v", err)
	}

	// A full list says nothing about a base, so a client that expects a delta
	// is told it has nothing to apply this one to.
	if err := checkCRL(caPath, caPath, "", false, -1, "7"); err == nil {
		t.Fatal("a document that is not a list passed as a delta")
	}
}

func TestRunHoldsACertificateToItsDeadlineAndPolicy(t *testing.T) {
	key, ca := newAuthority(t)
	caPath := checkable(t, "CERTIFICATE", ca.Raw)

	policy, err := asn1.Marshal([]policyInformation{{
		Policy: asn1.ObjectIdentifier{2, 23, 140, 1, 2, 1},
	}})
	if err != nil {
		t.Fatalf("could not encode the policy: %v", err)
	}

	now := time.Now()
	deadline := now.Add(time.Hour).UTC().Truncate(time.Second)

	// The key identifier of a leaf is the digest of its key, so it is the same
	// twenty bytes whatever is signed with it.
	subjectKeyID := make([]byte, 20)
	if _, err := rand.Read(subjectKeyID); err != nil {
		t.Fatalf("could not generate a key identifier: %v", err)
	}

	template := &smx509.Certificate{
		SerialNumber:       big.NewInt(2),
		Subject:            pkix.Name{CommonName: "web.example.com"},
		SubjectKeyId:       subjectKeyID,
		DNSNames:           []string{"web.example.com"},
		NotBefore:          now.Add(-time.Minute),
		NotAfter:           deadline,
		ExtraExtensions:    []pkix.Extension{{Id: oidCertificatePolicies, Value: policy}},
		SignatureAlgorithm: smx509.SM2WithSM3,
	}
	der, err := smx509.CreateCertificate(rand.Reader, template, ca, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("could not create the certificate: %v", err)
	}
	leafPath := checkable(t, "CERTIFICATE", der)

	format := func(at time.Time) string { return at.Format(time.RFC3339) }
	if err := run(leafPath, caPath, format(deadline), "2.23.140.1.2.1"); err != nil {
		t.Fatalf("a certificate within its deadline and policy was refused: %v", err)
	}
	if err := run(leafPath, caPath, format(deadline.Add(-time.Minute)), ""); err == nil {
		t.Fatal("a certificate outlived a deadline that should have capped it")
	}
	if err := run(leafPath, caPath, format(deadline.Add(time.Hour)), ""); err != nil {
		t.Fatalf("a deadline past the validity of the certificate was refused: %v", err)
	}
	if err := run(leafPath, caPath, "", "1.3.6.1.4.1.99999.1"); err == nil {
		t.Fatal("a certificate that states another policy passed as one that states this one")
	}
}
