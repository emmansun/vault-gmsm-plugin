// Command pkicheck verifies that a certificate the pki-gmsm mount issued is
// really signed by the authority the mount handed out with it, and asks the
// responder of the mount about it. The CI walkthrough uses it because neither
// the Vault CLI nor the certificate tooling on a runner parses an SM2 signed
// certificate or a response signed with SM2, while these checks run in the same
// module as the plugin.
//
// Usage:
//
//	pkicheck -cert leaf.pem -ca ca.pem
//	pkicheck -request -cert leaf.pem -ca ca.pem
//	pkicheck -response -ca ca.pem -status good < answer.der
//	pkicheck -response -ca ca.pem -status revoked -reason 1 < answer.der
//	pkicheck -crl old.pem -ca old-ca.pem -serial 1F:2C:0E -reason 1
package main

import (
	"encoding/base64"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"io"
	"math/big"
	"os"
	"strings"
	"time"

	"github.com/emmansun/gmsm/smx509"
	"github.com/emmansun/vault-gmsm-plugin/internal/ocspclient"
)

func main() {
	certPath := flag.String("cert", "", "PEM certificate to check")
	caPath := flag.String("ca", "", "PEM certificate of the authority that should have signed it")
	ask := flag.Bool("request", false, "print the base64 OCSP request about the certificate instead")
	answer := flag.Bool("response", false, "read a DER OCSP response from stdin and check it")
	want := flag.String("status", "", "the status the response should report: good, revoked or unknown")
	crlPath := flag.String("crl", "", "check the certificate revocation list at this path instead")
	serial := flag.String("serial", "", "with -crl, the serial the list must name")
	absent := flag.Bool("absent", false, "with -crl, the serial must not be named")
	reason := flag.Int("reason", -1, "with -crl or -response, the reason code the revocation must state")
	flag.Parse()

	var err error
	switch {
	case *ask && *answer:
		err = errors.New("choose one of -request and -response")
	case *crlPath != "":
		err = checkCRL(*crlPath, *caPath, *serial, *absent, *reason)
	case *ask:
		err = printRequest(*certPath, *caPath)
	case *answer:
		err = checkResponse(os.Stdin, *caPath, *want, *reason)
	default:
		err = run(*certPath, *caPath)
	}

	if err != nil {
		fmt.Fprintf(os.Stderr, "pkicheck: %v\n", err)
		os.Exit(1)
	}
}

// printRequest answers with the request as a client sends it, because building
// one needs the key hashed the way the responder hashes it.
func printRequest(certPath, caPath string) error {
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

	der, err := ocspclient.Request(leaf.SerialNumber, ca)
	if err != nil {
		return fmt.Errorf("could not build the request: %w", err)
	}

	fmt.Println(base64.StdEncoding.EncodeToString(der))

	return nil
}

// checkResponse reads the DER of an answer and says what it holds. The signature
// is checked against the authority, because an answer nothing verified would
// pass whatever it claimed.
func checkResponse(answer io.Reader, caPath, want string, reason int) error {
	if caPath == "" {
		return errors.New("-ca is required")
	}

	der, err := io.ReadAll(answer)
	if err != nil {
		return fmt.Errorf("could not read the answer: %w", err)
	}

	ca, err := readCertificate(caPath)
	if err != nil {
		return fmt.Errorf("could not read the authority: %w", err)
	}

	result, err := ocspclient.Verify(der, ca)
	if err != nil {
		return err
	}
	if result.Status != ocspclient.Successful {
		return fmt.Errorf("the responder refused the request with status %d", result.Status)
	}
	if want != "" && !strings.EqualFold(result.CertStatus.String(), want) {
		return fmt.Errorf("the responder reports the certificate as %v, want %s", result.CertStatus, want)
	}
	if reason >= 0 && result.CertStatus != ocspclient.CertRevoked {
		return errors.New("a reason was asked for, but the certificate is not reported as revoked")
	}
	if reason >= 0 && result.RevocationReason != reason {
		return fmt.Errorf("the answer reports reason %d, want %d", result.RevocationReason, reason)
	}

	fmt.Printf("serial %x is %v, this update %s, next update %s\n",
		result.Serial, result.CertStatus,
		result.ThisUpdate.Format(time.RFC3339), result.NextUpdate.Format(time.RFC3339))
	if result.CertStatus == ocspclient.CertRevoked {
		fmt.Printf("revoked at %s with reason %d\n",
			result.RevokedAt.Format(time.RFC3339), result.RevocationReason)
	}

	return nil
}

// checkCRL verifies that a list was signed by the authority that should have
// signed it, and says whether it names one serial. The signature is what a
// client checks, so a list nothing verified would pass whatever it contained.
func checkCRL(path, caPath, serial string, absent bool, reason int) error {
	if caPath == "" {
		return errors.New("-ca is required")
	}
	if reason >= 0 && serial == "" {
		return errors.New("-reason needs -serial to say which revocation it describes")
	}

	der, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	if block, _ := pem.Decode(der); block != nil {
		der = block.Bytes
	}

	list, err := smx509.ParseRevocationList(der)
	if err != nil {
		return fmt.Errorf("%s is not a certificate revocation list: %w", path, err)
	}

	ca, err := readCertificate(caPath)
	if err != nil {
		return fmt.Errorf("could not read the authority: %w", err)
	}
	if err := list.CheckSignatureFrom(ca); err != nil {
		return fmt.Errorf("the list is not signed by the authority: %w", err)
	}

	if serial != "" {
		wanted, err := parseSerial(serial)
		if err != nil {
			return err
		}

		var entry *smx509.RevocationListEntry
		for i := range list.RevokedCertificateEntries {
			if list.RevokedCertificateEntries[i].SerialNumber.Cmp(wanted) == 0 {
				entry = &list.RevokedCertificateEntries[i]
				break
			}
		}

		if absent && entry != nil {
			return fmt.Errorf("the list names %s, which it should not", serial)
		}
		if !absent && entry == nil {
			return fmt.Errorf("the list does not name %s", serial)
		}
		if entry != nil && reason >= 0 && entry.ReasonCode != reason {
			return fmt.Errorf("%s is revoked with reason %d, want %d", serial, entry.ReasonCode, reason)
		}
	}

	fmt.Printf("list %v of %s names %d revoked certificates\n",
		list.Number, ca.Subject.CommonName, len(list.RevokedCertificateEntries))
	if serial != "" {
		state := "is revoked"
		if absent {
			state = "is not named"
		}
		fmt.Printf("%s %s\n", serial, state)
	}

	return nil
}

// parseSerial reads a serial the way the API reports it, colon separated and in
// either case, and answers with the number the list is compared against.
func parseSerial(text string) (*big.Int, error) {
	cleaned := strings.ToUpper(strings.ReplaceAll(strings.TrimSpace(text), ":", ""))
	if cleaned == "" {
		return nil, errors.New("the serial is empty")
	}

	serial, ok := new(big.Int).SetString(cleaned, 16)
	if !ok {
		return nil, fmt.Errorf("the serial %q is not hexadecimal", text)
	}

	return serial, nil
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
