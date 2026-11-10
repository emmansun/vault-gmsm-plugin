// Package testca issues SM2 certificate chains from certificate requests.
//
// It exists for the integration tests only: the plugin hands out a request but
// must never be able to sign a certificate, so something else has to act as the
// CA that a real deployment would use.
package testca

import (
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"time"

	"github.com/emmansun/gmsm/sm2"
	"github.com/emmansun/gmsm/smx509"
)

// IssueChain verifies the signature on csrPEM, issues a leaf certificate for the
// public key it carries and returns the leaf and the generated CA as one PEM
// bundle, leaf first. The description returned alongside names what was issued.
func IssueChain(csrPEM []byte, validity time.Duration, caName string) ([]byte, string, error) {
	block, _ := pem.Decode(csrPEM)
	if block == nil {
		return nil, "", errors.New("the request is not PEM encoded")
	}

	csr, err := smx509.ParseCertificateRequest(block.Bytes)
	if err != nil {
		return nil, "", fmt.Errorf("could not parse the request: %w", err)
	}

	// Whoever produces the request is responsible for its signature, so checking
	// it here makes a broken signer fail the run instead of yielding a
	// certificate that no CA would have accepted.
	if err := csr.CheckSignature(); err != nil {
		return nil, "", fmt.Errorf("the request signature is invalid: %w", err)
	}

	caKey, err := sm2.GenerateKey(rand.Reader)
	if err != nil {
		return nil, "", fmt.Errorf("could not generate the CA key: %w", err)
	}

	now := time.Now()

	caTemplate := &smx509.Certificate{
		SerialNumber:          serialNumber(),
		Subject:               pkix.Name{CommonName: caName},
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.Add(validity),
		KeyUsage:              smx509.KeyUsageCertSign | smx509.KeyUsageCRLSign | smx509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}

	caDER, err := smx509.CreateCertificate(rand.Reader, caTemplate, caTemplate, &caKey.PublicKey, caKey)
	if err != nil {
		return nil, "", fmt.Errorf("could not create the CA certificate: %w", err)
	}
	caCert, err := smx509.ParseCertificate(caDER)
	if err != nil {
		return nil, "", fmt.Errorf("could not parse the CA certificate: %w", err)
	}

	// The subject and the names come from the request, the key comes from the
	// request too; only the issuer and the validity are the CA's business.
	leafTemplate := &smx509.Certificate{
		SerialNumber:          serialNumber(),
		Subject:               csr.Subject,
		DNSNames:              csr.DNSNames,
		EmailAddresses:        csr.EmailAddresses,
		IPAddresses:           csr.IPAddresses,
		URIs:                  csr.URIs,
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.Add(validity),
		KeyUsage:              smx509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []smx509.ExtKeyUsage{smx509.ExtKeyUsageServerAuth, smx509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
	}

	leafDER, err := smx509.CreateCertificate(rand.Reader, leafTemplate, caCert, csr.PublicKey, caKey)
	if err != nil {
		return nil, "", fmt.Errorf("could not create the leaf certificate: %w", err)
	}

	leaf, err := smx509.ParseCertificate(leafDER)
	if err != nil {
		return nil, "", fmt.Errorf("could not parse the leaf certificate: %w", err)
	}

	// A chain that does not belong to the request would be rejected by the
	// plugin, so catch that here where the reason is obvious.
	leafKey, ok := leaf.PublicKey.(*ecdsa.PublicKey)
	if !ok {
		return nil, "", fmt.Errorf("the issued certificate holds a %T, not an ECDSA/SM2 key", leaf.PublicKey)
	}
	requestKey, ok := csr.PublicKey.(*ecdsa.PublicKey)
	if !ok || !leafKey.Equal(requestKey) {
		return nil, "", errors.New("the issued certificate does not carry the public key of the request")
	}
	if err := leaf.CheckSignatureFrom(caCert); err != nil {
		return nil, "", fmt.Errorf("the issued certificate is not signed by the CA: %w", err)
	}

	chain := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: leafDER})
	chain = append(chain, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER})...)

	summary := fmt.Sprintf("issued %q for SANs %v from %q", csr.Subject.CommonName, csr.DNSNames, caName)

	return chain, summary, nil
}

// serialNumber returns a random positive serial number, which is what keeps
// repeated runs from reusing the serial of a certificate already seen by a
// client that caches them.
func serialNumber() *big.Int {
	limit := new(big.Int).Lsh(big.NewInt(1), 128)
	serial, err := rand.Int(rand.Reader, limit)
	if err != nil {
		// The caller cannot do anything about a broken random source and would
		// report the error at every step, so fail loudly here instead.
		panic(fmt.Sprintf("testca: could not draw a serial number: %v", err))
	}

	return serial
}
