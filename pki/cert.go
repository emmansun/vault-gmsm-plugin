package pki

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net"
	"net/url"
	"strings"
	"time"

	"github.com/emmansun/gmsm/sm2"
	"github.com/emmansun/gmsm/sm3"
	"github.com/emmansun/gmsm/smx509"
	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
)

const (
	// defaultRootTTL is how long a generated root is valid for. It is fixed
	// instead of derived from the system lease TTL, which would cap a CA at
	// weeks and surprise everyone who did not pass ttl explicitly.
	defaultRootTTL = 10 * 365 * 24 * time.Hour

	// defaultNotBefore backdates a certificate so that a client whose clock is
	// slightly behind does not reject it on arrival.
	defaultNotBefore = 30 * time.Second

	// crlValidity is how long a rebuilt CRL claims to be current. Clients must
	// fetch a new one before it expires.
	crlValidity = 72 * time.Hour
)

// newSerial returns a random 128 bit serial number. RFC 5280 caps the DER
// encoding at 20 octets, and 128 random bits are far apart enough that a client
// cache never sees a serial twice.
func newSerial() (*big.Int, error) {
	limit := new(big.Int).Lsh(big.NewInt(1), 128)

	serial, err := rand.Int(rand.Reader, limit)
	if err != nil {
		return nil, fmt.Errorf("could not draw a serial number: %w", err)
	}
	if serial.Sign() == 0 {
		serial.SetInt64(1)
	}

	return serial, nil
}

// formatSerial renders a stored serial the way the PKI engine reports it, so a
// script that compares serial_number across engines keeps working.
func formatSerial(serial string) string {
	var out strings.Builder
	for i := 0; i < len(serial); i += 2 {
		if i > 0 {
			out.WriteByte(':')
		}
		out.WriteString(strings.ToUpper(serial[i : i+2]))
	}

	return out.String()
}

// normalizeSerial accepts the spellings a caller can reasonably supply, with or
// without separators and in either case, and returns the canonical form the
// storage keys use.
func normalizeSerial(raw string) (string, error) {
	var out strings.Builder
	for _, r := range strings.TrimSpace(raw) {
		switch {
		case r == ':' || r == '-' || r == ' ' || r == '\t' || r == '\n' || r == '\r':
			continue
		case r >= '0' && r <= '9', r >= 'a' && r <= 'f', r >= 'A' && r <= 'F':
			out.WriteString(strings.ToLower(string(r)))
		default:
			return "", fmt.Errorf("serial number %q contains %q, which is not a hexadecimal digit", raw, r)
		}
	}

	serial := out.String()
	if serial == "" {
		return "", errors.New("serial number is empty")
	}
	if len(serial)%2 != 0 {
		serial = "0" + serial
	}

	return serial, nil
}

// subjectKeyID derives the key identifier the way RFC 5280 method (1) does, but
// with SM3: the input is the subjectPublicKey BIT STRING contents and the first
// 160 bits are used. Setting the field matters: smx509 derives it with SHA-1
// when it is left empty, which does not belong in an SM2 certificate.
func subjectKeyID(pub crypto.PublicKey) ([]byte, error) {
	point, err := subjectPublicKeyBytes(pub)
	if err != nil {
		return nil, err
	}

	sum := sm3.Sum(point)
	return sum[:20], nil
}

// subjectPublicKeyBytes returns the contents of the subjectPublicKey BIT STRING,
// which is what the identifier hash is defined over.
func subjectPublicKeyBytes(pub crypto.PublicKey) ([]byte, error) {
	spki, err := smx509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return nil, fmt.Errorf("could not marshal the public key: %w", err)
	}

	var info struct {
		Algorithm pkix.AlgorithmIdentifier
		PublicKey asn1.BitString
	}
	if _, err := asn1.Unmarshal(spki, &info); err != nil {
		return nil, fmt.Errorf("could not unpack the public key: %w", err)
	}

	return info.PublicKey.Bytes, nil
}

// checkSM2PublicKey refuses a key that is not on the SM2 curve. smx509 parses
// other curves for compatibility, but this CA signs nothing but SM2.
func checkSM2PublicKey(pub crypto.PublicKey) (*ecdsa.PublicKey, error) {
	key, ok := pub.(*ecdsa.PublicKey)
	if !ok || key.Curve != sm2.P256() {
		return nil, fmt.Errorf("only SM2 public keys can be signed by this mount, got %T", pub)
	}

	return key, nil
}

func pemCertificate(der []byte) string {
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
}

func pemCertificates(der [][]byte) []string {
	bundle := make([]string, len(der))
	for i, cert := range der {
		bundle[i] = pemCertificate(cert)
	}

	return bundle
}

// parseCertificates decodes a PEM bundle and keeps the order the caller
// supplied. Blocks that are not certificates are ignored, so a bundle may carry
// a private key or comments without upsetting the caller.
func parseCertificates(pemText string) ([]*smx509.Certificate, error) {
	var certs []*smx509.Certificate

	remaining := []byte(strings.TrimSpace(pemText))
	for len(remaining) > 0 {
		var block *pem.Block
		block, remaining = pem.Decode(remaining)
		if block == nil {
			return nil, errors.New("could not decode a PEM block in the certificate")
		}
		if block.Type != "CERTIFICATE" {
			continue
		}

		cert, err := smx509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("could not parse a certificate: %w", err)
		}

		certs = append(certs, cert)
	}

	if len(certs) == 0 {
		return nil, errors.New("the bundle did not contain a PEM certificate")
	}

	return certs, nil
}

// parseCertificateRequest accepts the PEM a client produces as well as the
// base64 DER form, and verifies the signature before anyone signs it.
func parseCertificateRequest(raw string) (*smx509.CertificateRequest, error) {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return nil, errors.New("csr is required")
	}

	var der []byte
	if block, _ := pem.Decode([]byte(trimmed)); block != nil {
		if block.Type != "CERTIFICATE REQUEST" && block.Type != "NEW CERTIFICATE REQUEST" {
			return nil, fmt.Errorf("the PEM block is a %s, not a certificate request", block.Type)
		}
		der = block.Bytes
	} else {
		compact := strings.NewReplacer("\n", "", "\r", "", " ", "", "\t", "").Replace(trimmed)
		decoded, err := base64.StdEncoding.DecodeString(compact)
		if err != nil {
			return nil, errors.New("csr is neither PEM nor base64 encoded DER")
		}
		der = decoded
	}

	csr, err := smx509.ParseCertificateRequest(der)
	if err != nil {
		return nil, fmt.Errorf("could not parse the certificate request: %w", err)
	}
	if err := csr.CheckSignature(); err != nil {
		return nil, fmt.Errorf("the certificate request signature is invalid: %w", err)
	}

	return csr, nil
}

// marshalPrivateKey renders a private key for the response. The default form is
// SEC 1, which is what the export path of the gmsm backend produces; callers
// that need PKCS#8 ask for it with private_key_format.
func marshalPrivateKey(key *sm2.PrivateKey, format, privateKeyFormat string) (string, error) {
	var (
		der       []byte
		blockType string
	)

	if privateKeyFormat == "pkcs8" {
		encoded, err := smx509.MarshalPKCS8PrivateKey(key)
		if err != nil {
			return "", fmt.Errorf("could not marshal the private key: %w", err)
		}
		der, blockType = encoded, "PRIVATE KEY"
	} else {
		encoded, err := smx509.MarshalECPrivateKey(&key.PrivateKey)
		if err != nil {
			return "", fmt.Errorf("could not marshal the private key: %w", err)
		}
		der, blockType = encoded, "EC PRIVATE KEY"
	}

	if format == "der" {
		return base64.StdEncoding.EncodeToString(der), nil
	}

	return string(pem.EncodeToMemory(&pem.Block{Type: blockType, Bytes: der})), nil
}

// renderCertificate renders a DER certificate in the requested format: PEM text
// or base64 encoded DER.
func renderCertificate(der []byte, format string) string {
	if format == "der" {
		return base64.StdEncoding.EncodeToString(der)
	}

	return pemCertificate(der)
}

// certificateFormat validates the format field of an operation that returns a
// certificate. A PEM bundle only makes sense when the private key comes with
// the certificate, so the bundle that carries one is offered there alone.
func certificateFormat(d *framework.FieldData, bundle bool) (string, error) {
	format := d.Get("format").(string)

	switch format {
	case "pem", "der":
		return format, nil
	case "pem_bundle":
		if bundle {
			return format, nil
		}
		return "", fmt.Errorf(`format "pem_bundle" is only available when a private key is returned`)
	default:
		return "", fmt.Errorf(`format %q is not supported; use "pem" or "der"`, format)
	}
}

// privateKeyFormat validates the encoding asked for a returned private key.
func privateKeyFormat(d *framework.FieldData) (string, error) {
	format := d.Get("private_key_format").(string)

	switch format {
	case "der", "pkcs8":
		return format, nil
	default:
		return "", fmt.Errorf(`private_key_format %q is not supported; use "der" or "pkcs8"`, format)
	}
}

// subjectFieldSchemas describes the distinguished name fields every issuing
// path accepts. The map is rebuilt per path because the framework keeps the
// pointer values and two paths must not share them.
func subjectFieldSchemas() map[string]*framework.FieldSchema {
	return map[string]*framework.FieldSchema{
		"organization": {
			Type:        framework.TypeCommaStringSlice,
			Description: "Organization (O) values of the subject, as a comma separated list.",
		},
		"ou": {
			Type:        framework.TypeCommaStringSlice,
			Description: "Organizational unit (OU) values of the subject, as a comma separated list.",
		},
		"country": {
			Type:        framework.TypeCommaStringSlice,
			Description: "Country (C) values of the subject, as a comma separated list.",
		},
		"locality": {
			Type:        framework.TypeCommaStringSlice,
			Description: "Locality (L) values of the subject, as a comma separated list.",
		},
		"province": {
			Type:        framework.TypeCommaStringSlice,
			Description: "Province (ST) values of the subject, as a comma separated list.",
		},
		"street_address": {
			Type:        framework.TypeCommaStringSlice,
			Description: "Street address values of the subject, as a comma separated list.",
		},
		"postal_code": {
			Type:        framework.TypeCommaStringSlice,
			Description: "Postal code values of the subject, as a comma separated list.",
		},
		"serial_number": {
			Type:        framework.TypeString,
			Description: "Serial number value of the subject (OID 2.5.4.5), if any. This is not the certificate serial.",
		},
	}
}

// subjectFromFields builds the distinguished name, with the common name the
// caller resolved rather than the one in the request.
func subjectFromFields(d *framework.FieldData, commonName string) pkix.Name {
	subject := pkix.Name{CommonName: commonName}

	if v, ok := d.GetOk("organization"); ok {
		subject.Organization = v.([]string)
	}
	if v, ok := d.GetOk("ou"); ok {
		subject.OrganizationalUnit = v.([]string)
	}
	if v, ok := d.GetOk("country"); ok {
		subject.Country = v.([]string)
	}
	if v, ok := d.GetOk("locality"); ok {
		subject.Locality = v.([]string)
	}
	if v, ok := d.GetOk("province"); ok {
		subject.Province = v.([]string)
	}
	if v, ok := d.GetOk("street_address"); ok {
		subject.StreetAddress = v.([]string)
	}
	if v, ok := d.GetOk("postal_code"); ok {
		subject.PostalCode = v.([]string)
	}
	if v, ok := d.GetOk("serial_number"); ok {
		subject.SerialNumber = v.(string)
	}

	return subject
}

// certificateRequest is everything the signing step needs that is not the
// issuer itself. The caller has already resolved the policy: these names are
// allowed, these usages are granted, this is the validity.
type certificateRequest struct {
	Subject        pkix.Name
	DNSNames       []string
	EmailAddresses []string
	IPAddresses    []net.IP
	URIs           []*url.URL

	PublicKey   crypto.PublicKey
	KeyUsage    smx509.KeyUsage
	ExtKeyUsage []smx509.ExtKeyUsage

	// UnknownExtKeyUsage carries the usages the role names by OID.
	UnknownExtKeyUsage []asn1.ObjectIdentifier

	IsCA       bool
	MaxPathLen int
	TTL        time.Duration

	// NotBefore is how far the notBefore field is backdated. A zero value
	// falls back to defaultNotBefore.
	NotBefore time.Duration
}

// rootCertificate builds a self-signed CA certificate for key.
func (b *backend) rootCertificate(ctx context.Context, s logical.Storage, subject pkix.Name, key *sm2.PrivateKey, ttl time.Duration, maxPathLen int) (*smx509.Certificate, error) {
	urls, err := b.urls(ctx, s)
	if err != nil {
		return nil, err
	}

	serial, err := newSerial()
	if err != nil {
		return nil, err
	}

	identifier, err := subjectKeyID(&key.PublicKey)
	if err != nil {
		return nil, err
	}

	now := time.Now()
	template := &smx509.Certificate{
		SerialNumber:          serial,
		Subject:               subject,
		NotBefore:             now.Add(-defaultNotBefore),
		NotAfter:              now.Add(ttl),
		KeyUsage:              smx509.KeyUsageCertSign | smx509.KeyUsageCRLSign | smx509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		IsCA:                  true,
		SubjectKeyId:          identifier,
		// smx509 only copies the parent identifier when the issuer differs from
		// the subject, so a self-signed root has to name itself here.
		AuthorityKeyId:        identifier,
		IssuingCertificateURL: urls.IssuingCertificates,
		CRLDistributionPoints: urls.CRLDistributionPoints,
		OCSPServer:            urls.OCSPServers,
		SignatureAlgorithm:    smx509.SM2WithSM3,
	}
	if maxPathLen >= 0 {
		template.MaxPathLen = maxPathLen
		template.MaxPathLenZero = maxPathLen == 0
	}

	der, err := smx509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		return nil, fmt.Errorf("could not create the certificate authority certificate: %w", err)
	}

	return smx509.ParseCertificate(der)
}

// signWithIssuer issues one certificate from the mount's authority. The TTL is
// clamped to what the authority has left, and the clamp is reported so the
// caller can pass the warning on instead of silently shortening a certificate.
func (b *backend) signWithIssuer(ctx context.Context, s logical.Storage, issuer *issuerEntry, signer *sm2.PrivateKey, request certificateRequest) (*smx509.Certificate, []string, error) {
	issuerCert, err := issuer.certificate()
	if err != nil {
		return nil, nil, err
	}

	urls, err := b.urls(ctx, s)
	if err != nil {
		return nil, nil, err
	}

	var warnings []string
	now := time.Now()

	notBefore := request.NotBefore
	if notBefore <= 0 {
		notBefore = defaultNotBefore
	}

	ttl := request.TTL
	if !issuerCert.NotAfter.IsZero() && now.Add(ttl).After(issuerCert.NotAfter) {
		ttl = issuerCert.NotAfter.Sub(now)
		warnings = append(warnings, "the requested TTL was shortened to the remaining validity of the certificate authority")
	}
	if ttl <= 0 {
		return nil, nil, errors.New("the certificate authority has expired")
	}

	serial, err := newSerial()
	if err != nil {
		return nil, nil, err
	}

	identifier, err := subjectKeyID(request.PublicKey)
	if err != nil {
		return nil, nil, err
	}

	template := &smx509.Certificate{
		SerialNumber:          serial,
		Subject:               request.Subject,
		NotBefore:             now.Add(-notBefore),
		NotAfter:              now.Add(ttl),
		KeyUsage:              request.KeyUsage,
		ExtKeyUsage:           request.ExtKeyUsage,
		UnknownExtKeyUsage:    request.UnknownExtKeyUsage,
		BasicConstraintsValid: true,
		IsCA:                  request.IsCA,
		SubjectKeyId:          identifier,
		DNSNames:              request.DNSNames,
		EmailAddresses:        request.EmailAddresses,
		IPAddresses:           request.IPAddresses,
		URIs:                  request.URIs,
		IssuingCertificateURL: urls.IssuingCertificates,
		CRLDistributionPoints: urls.CRLDistributionPoints,
		OCSPServer:            urls.OCSPServers,
		SignatureAlgorithm:    smx509.SM2WithSM3,
	}
	if request.IsCA && request.MaxPathLen >= 0 {
		template.MaxPathLen = request.MaxPathLen
		template.MaxPathLenZero = request.MaxPathLen == 0
	}

	der, err := smx509.CreateCertificate(rand.Reader, template, issuerCert, request.PublicKey, signer)
	if err != nil {
		return nil, nil, fmt.Errorf("could not create the certificate: %w", err)
	}

	cert, err := smx509.ParseCertificate(der)
	if err != nil {
		return nil, nil, fmt.Errorf("could not parse the certificate that was just created: %w", err)
	}

	return cert, warnings, nil
}

// serialHex is the storage key of a certificate, without the separators the API
// displays.
func serialHex(serial *big.Int) string {
	return hex.EncodeToString(serial.Bytes())
}
