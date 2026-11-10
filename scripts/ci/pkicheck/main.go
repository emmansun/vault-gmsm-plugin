// Command pkicheck verifies that a certificate the pki-gmsm mount issued is
// really signed by the authority the mount handed out with it. The CI
// walkthrough uses it because neither the Vault CLI nor the certificate
// tooling on a runner parses an SM2 signed certificate, while this check runs
// in the same module as the plugin.
//
// Usage:
//
//	pkicheck -cert leaf.pem -ca ca.pem
package main

import (
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"os"
	"time"

	"github.com/emmansun/gmsm/smx509"
)

func main() {
	certPath := flag.String("cert", "", "PEM certificate to check")
	caPath := flag.String("ca", "", "PEM certificate of the authority that should have signed it")
	flag.Parse()

	if err := run(*certPath, *caPath); err != nil {
		fmt.Fprintf(os.Stderr, "pkicheck: %v\n", err)
		os.Exit(1)
	}
}

func run(certPath, caPath string) error {
	if certPath == "" || caPath == "" {
		return errors.New("both -cert and -ca are required")
	}

	leaf, err := readCertificate(certPath)
	if err != nil {
		return fmt.Errorf("could not read the certificate: %w", err)
	}
	ca, err := readCertificate(caPath)
	if err != nil {
		return fmt.Errorf("could not read the authority: %w", err)
	}

	if leaf.SignatureAlgorithm != smx509.SM2WithSM3 {
		return fmt.Errorf("the certificate is signed with %v, want %v", leaf.SignatureAlgorithm, smx509.SM2WithSM3)
	}
	if err := leaf.CheckSignatureFrom(ca); err != nil {
		return fmt.Errorf("the certificate is not signed by the authority: %w", err)
	}

	// The key identifier is the SM3 digest of the public key, truncated the way
	// RFC 5280 method 1 truncates a digest, so it is 20 bytes whatever the hash.
	if len(leaf.SubjectKeyId) != 20 {
		return fmt.Errorf("the certificate has a %d byte subject key identifier, want 20", len(leaf.SubjectKeyId))
	}
	if string(leaf.AuthorityKeyId) != string(ca.SubjectKeyId) {
		return fmt.Errorf("the certificate names authority key identifier %x, want %x", leaf.AuthorityKeyId, ca.SubjectKeyId)
	}

	now := time.Now()
	if now.Before(leaf.NotBefore) || now.After(leaf.NotAfter) {
		return fmt.Errorf("the certificate is not valid now: %s to %s",
			leaf.NotBefore.Format(time.RFC3339), leaf.NotAfter.Format(time.RFC3339))
	}

	fmt.Printf("%s issued by %s, serial %x, valid until %s\n",
		leaf.Subject.CommonName, ca.Subject.CommonName, leaf.SerialNumber, leaf.NotAfter.Format(time.RFC3339))

	return nil
}

func readCertificate(path string) (*smx509.Certificate, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	block, _ := pem.Decode(raw)
	if block == nil || block.Type != "CERTIFICATE" {
		return nil, fmt.Errorf("%s does not hold a PEM certificate", path)
	}

	cert, err := smx509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("%s does not hold a certificate this module can parse: %w", path, err)
	}

	return cert, nil
}
