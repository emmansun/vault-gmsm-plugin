package pki

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/emmansun/gmsm/sm2"
	"github.com/emmansun/gmsm/smx509"
	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
)

// issuanceFieldSchemas are the fields both issue and sign accept: what to put
// in the certificate and how to render it.
func issuanceFieldSchemas() map[string]*framework.FieldSchema {
	return map[string]*framework.FieldSchema{
		"name": {
			Type:        framework.TypeString,
			Description: "Name of the role that decides what may be issued.",
		},
		"common_name": {
			Type:        framework.TypeString,
			Description: "Common name (CN) of the certificate.",
		},
		"alt_names": {
			Type:        framework.TypeCommaStringSlice,
			Description: "Additional names, as a comma separated list. An entry containing @ is treated as an email address, everything else as a DNS name.",
		},
		"ip_sans": {
			Type:        framework.TypeCommaStringSlice,
			Description: "IP addresses to place in the subject alternative names, as a comma separated list.",
		},
		"uri_sans": {
			Type:        framework.TypeCommaStringSlice,
			Description: "URIs to place in the subject alternative names, as a comma separated list.",
		},
		"ttl": {
			Type:        framework.TypeDurationSecond,
			Default:     0,
			Description: "Validity of the certificate. Defaults to the ttl of the role and is shortened to its max_ttl.",
		},
		"exclude_cn_from_sans": {
			Type:        framework.TypeBool,
			Default:     false,
			Description: "Do not copy the common name into the subject alternative names.",
		},
		"format": {
			Type:        framework.TypeString,
			Default:     "pem",
			Description: `Encoding of the returned certificate: "pem", "der" (base64 encoded) or, where a private key is returned, "pem_bundle".`,
		},
	}
}

// pathIssue issues a certificate for a key this mount generates. The private
// key leaves the mount in the response and is never stored, unlike the key of
// the certificate authority.
func (b *backend) pathIssue() *framework.Path {
	fields := issuanceFieldSchemas()
	fields["private_key_format"] = &framework.FieldSchema{
		Type:        framework.TypeString,
		Default:     "der",
		Description: `Encoding of the returned private key: "der" for SEC 1, "pkcs8" for PKCS#8.`,
	}
	fields["key_type"] = &framework.FieldSchema{
		Type:        framework.TypeString,
		Default:     "sm2",
		Description: `Type of the generated key. Only "sm2" is supported.`,
	}

	return &framework.Path{
		Pattern: "issue/" + framework.GenericNameRegex("name") + "$",

		DisplayAttrs: &framework.DisplayAttributes{
			OperationPrefix: operationPrefix,
			OperationVerb:   "issue",
			OperationSuffix: "certificate",
		},

		Fields: fields,

		Callbacks: map[logical.Operation]framework.OperationFunc{
			logical.UpdateOperation: b.pathIssueWrite,
		},

		HelpSynopsis:    pathIssueHelpSyn,
		HelpDescription: pathIssueHelpDesc,
	}
}

func (b *backend) pathIssueWrite(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	roleName := strings.TrimSpace(d.Get("name").(string))

	if err := checkSM2KeyType(d.Get("key_type").(string)); err != nil {
		return logical.ErrorResponse(err.Error()), logical.ErrInvalidRequest
	}

	format, keyFormat, err := outputFormats(d, true)
	if err != nil {
		return logical.ErrorResponse(err.Error()), logical.ErrInvalidRequest
	}

	role, resp, err := b.roleForRequest(ctx, req.Storage, roleName)
	if resp != nil || err != nil {
		return resp, err
	}

	names, err := namesFromFields(d)
	if err != nil {
		return logical.ErrorResponse(err.Error()), logical.ErrInvalidRequest
	}
	if !d.Get("exclude_cn_from_sans").(bool) {
		addCommonName(&names)
	}
	if err := role.validate(names); err != nil {
		return logical.ErrorResponse(err.Error()), logical.ErrInvalidRequest
	}

	keyUsage, err := role.keyUsage()
	if err != nil {
		return nil, err
	}
	extKeyUsage, unknownExtKeyUsage, err := role.extKeyUsage()
	if err != nil {
		return nil, err
	}

	ttl, warnings := effectiveTTL(role, d.Get("ttl").(int))

	key, err := sm2.GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("could not generate the certificate key: %w", err)
	}

	cert, issuer, chain, signWarnings, err := b.signForMount(ctx, req.Storage, certificateRequest{
		Subject:            role.subject(names.CommonName),
		DNSNames:           names.DNSNames,
		EmailAddresses:     names.EmailAddresses,
		IPAddresses:        names.IPAddresses,
		URIs:               names.URIs,
		PublicKey:          &key.PublicKey,
		KeyUsage:           keyUsage,
		ExtKeyUsage:        extKeyUsage,
		UnknownExtKeyUsage: unknownExtKeyUsage,
		TTL:                ttl,
		NotBefore:          role.NotBeforeDuration,
	}, role.IssuerRef)
	if err != nil {
		return issuerError(err)
	}
	warnings = append(warnings, signWarnings...)

	if err := b.storeIssuedCertificate(ctx, req.Storage, cert, roleName, issuer.ID, !role.NoStore); err != nil {
		return nil, err
	}

	privateKey, err := marshalPrivateKey(key, format, keyFormat)
	if err != nil {
		return nil, err
	}

	data := certificateResponseData(cert, issuer, chain, format)
	data["private_key"] = privateKey
	data["private_key_type"] = "sm2"
	if format == "pem_bundle" {
		data["certificate"] = privateKey + data["certificate"].(string)
	}

	return &logical.Response{Data: data, Warnings: warnings}, nil
}

// pathSign signs a certificate request with a key the caller already holds.
func (b *backend) pathSign() *framework.Path {
	fields := issuanceFieldSchemas()
	fields["csr"] = &framework.FieldSchema{
		Type:        framework.TypeString,
		Description: "PEM or base64 encoded DER certificate request. Its signature is verified before it is signed.",
	}

	return &framework.Path{
		Pattern: "sign/" + framework.GenericNameRegex("name") + "$",

		DisplayAttrs: &framework.DisplayAttributes{
			OperationPrefix: operationPrefix,
			OperationVerb:   "sign",
			OperationSuffix: "certificate",
		},

		Fields: fields,

		Callbacks: map[logical.Operation]framework.OperationFunc{
			logical.UpdateOperation: b.pathSignWrite,
		},

		HelpSynopsis:    pathSignHelpSyn,
		HelpDescription: pathSignHelpDesc,
	}
}

func (b *backend) pathSignWrite(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	roleName := strings.TrimSpace(d.Get("name").(string))

	format, err := certificateFormat(d, false)
	if err != nil {
		return logical.ErrorResponse(err.Error()), logical.ErrInvalidRequest
	}

	role, resp, err := b.roleForRequest(ctx, req.Storage, roleName)
	if resp != nil || err != nil {
		return resp, err
	}

	csr, err := parseCertificateRequest(d.Get("csr").(string))
	if err != nil {
		return logical.ErrorResponse(err.Error()), logical.ErrInvalidRequest
	}

	publicKey, err := checkSM2PublicKey(csr.PublicKey)
	if err != nil {
		return logical.ErrorResponse(err.Error()), logical.ErrInvalidRequest
	}

	names, err := namesFromFields(d)
	if err != nil {
		return logical.ErrorResponse(err.Error()), logical.ErrInvalidRequest
	}

	// The role decides how much of the request is taken over. What the caller
	// wrote in this request wins over the request to sign, which is what makes
	// it possible to narrow a certificate without touching the request.
	if role.UseCSRCommonName && names.CommonName == "" {
		names.CommonName = strings.TrimSpace(csr.Subject.CommonName)
	}
	if role.UseCSRSANs {
		names.DNSNames = appendUniqueAll(names.DNSNames, csr.DNSNames)
		names.EmailAddresses = appendUniqueAll(names.EmailAddresses, csr.EmailAddresses)
		names.IPAddresses = appendUniqueIPs(names.IPAddresses, csr.IPAddresses)
		names.URIs = appendUniqueURIs(names.URIs, csr.URIs)
	}
	if !d.Get("exclude_cn_from_sans").(bool) {
		addCommonName(&names)
	}

	if err := role.validate(names); err != nil {
		return logical.ErrorResponse(err.Error()), logical.ErrInvalidRequest
	}

	keyUsage, err := role.keyUsage()
	if err != nil {
		return nil, err
	}
	extKeyUsage, unknownExtKeyUsage, err := role.extKeyUsage()
	if err != nil {
		return nil, err
	}

	ttl, warnings := effectiveTTL(role, d.Get("ttl").(int))

	cert, issuer, chain, signWarnings, err := b.signForMount(ctx, req.Storage, certificateRequest{
		Subject:            role.subject(names.CommonName),
		DNSNames:           names.DNSNames,
		EmailAddresses:     names.EmailAddresses,
		IPAddresses:        names.IPAddresses,
		URIs:               names.URIs,
		PublicKey:          publicKey,
		KeyUsage:           keyUsage,
		ExtKeyUsage:        extKeyUsage,
		UnknownExtKeyUsage: unknownExtKeyUsage,
		TTL:                ttl,
		NotBefore:          role.NotBeforeDuration,
	}, role.IssuerRef)
	if err != nil {
		return issuerError(err)
	}
	warnings = append(warnings, signWarnings...)

	if err := b.storeIssuedCertificate(ctx, req.Storage, cert, roleName, issuer.ID, !role.NoStore); err != nil {
		return nil, err
	}

	return &logical.Response{
		Data:     certificateResponseData(cert, issuer, chain, format),
		Warnings: warnings,
	}, nil
}

// signForMount loads the authority a role names, signs one certificate and
// returns it with the issuer and the chain. It holds the lock for the whole step
// so a concurrent delete cannot pull the key from under it.
func (b *backend) signForMount(ctx context.Context, s logical.Storage, request certificateRequest, issuerRef string) (*smx509.Certificate, *issuerEntry, []*smx509.Certificate, []string, error) {
	b.caMu.Lock()
	defer b.caMu.Unlock()

	_, issuer, err := b.issuerByRef(ctx, s, issuerRef)
	if err != nil {
		return nil, nil, nil, nil, &issuerLookupError{err: err}
	}
	if issuer == nil {
		return nil, nil, nil, nil, errNoIssuer
	}

	chain, err := issuer.chain()
	if err != nil {
		return nil, nil, nil, nil, err
	}

	signer, err := b.issuerSigner(ctx, s, issuer)
	if err != nil {
		return nil, nil, nil, nil, err
	}

	cert, warnings, err := b.signWithIssuer(ctx, s, issuer, signer, request)
	if err != nil {
		return nil, nil, nil, nil, err
	}

	return cert, issuer, chain, warnings, nil
}

// issuerLookupError marks a ref that names no issuer as a mistake in the
// request, which is what makes it a 400 rather than a 500.
type issuerLookupError struct {
	err error
}

func (e *issuerLookupError) Error() string { return e.err.Error() }

func (e *issuerLookupError) Unwrap() error { return e.err }

// issuerError turns a missing authority into the 400 every path answers with,
// and leaves every other failure as it is.
func issuerError(err error) (*logical.Response, error) {
	var lookup *issuerLookupError
	if err == errNoIssuer || errors.As(err, &lookup) {
		return logical.ErrorResponse(err.Error()), logical.ErrInvalidRequest
	}

	return nil, err
}

// certificateResponseData is the part of an issuance response that does not
// depend on whether a private key came with it.
func certificateResponseData(cert *smx509.Certificate, issuer *issuerEntry, chain []*smx509.Certificate, format string) map[string]interface{} {
	der := make([][]byte, len(chain))
	for i, c := range chain {
		der[i] = c.Raw
	}

	return map[string]interface{}{
		"certificate":   renderCertificate(cert.Raw, format),
		"issuing_ca":    renderCertificate(issuer.Certificate, format),
		"ca_chain":      pemCertificates(der),
		"serial_number": formatSerial(serialHex(cert.SerialNumber)),
		"expiration":    cert.NotAfter.Unix(),
		"issuer_id":     issuer.ID,
	}
}

// roleForRequest loads the role of a request. A missing role is a bad request
// rather than a miss: the path exists, the policy it names does not.
func (b *backend) roleForRequest(ctx context.Context, s logical.Storage, name string) (*roleEntry, *logical.Response, error) {
	if name == "" {
		return nil, logical.ErrorResponse("a role name is required"), logical.ErrInvalidRequest
	}

	role, err := b.role(ctx, s, name)
	if err != nil {
		return nil, nil, err
	}
	if role == nil {
		return nil, logical.ErrorResponse(fmt.Sprintf("role %q does not exist; create it with POST roles/%s first", name, name)), logical.ErrInvalidRequest
	}

	return role, nil, nil
}

// namesFromFields builds the names the request asks for, without the common
// name in the subject alternative names: that step is separate so a request to
// sign can merge the names of the request first.
func namesFromFields(d *framework.FieldData) (requestNames, error) {
	names := requestNames{CommonName: strings.TrimSpace(d.Get("common_name").(string))}

	names.DNSNames, names.EmailAddresses = parseAltNames(d.Get("alt_names").([]string))

	ips, err := parseIPSANs(d.Get("ip_sans").([]string))
	if err != nil {
		return requestNames{}, err
	}
	names.IPAddresses = ips

	uris, err := parseURISANs(d.Get("uri_sans").([]string))
	if err != nil {
		return requestNames{}, err
	}
	names.URIs = uris

	return names, nil
}

// effectiveTTL resolves the validity of one certificate: what the request asks
// for, what the role allows, and the warning when the two differ.
func effectiveTTL(role *roleEntry, requested int) (time.Duration, []string) {
	var warnings []string

	ttl := role.TTL
	if requested > 0 {
		ttl = time.Duration(requested) * time.Second
	}
	if ttl > role.MaxTTL {
		ttl = role.MaxTTL
		warnings = append(warnings, "the requested TTL was shortened to max_ttl of the role")
	}

	return ttl, warnings
}

const pathIssueHelpSyn = `Issue a certificate for a generated key`

const pathIssueHelpDesc = `
Generates an SM2 key and issues a certificate for it, following the policy of
the named role. The private key is returned once and is not kept in the mount;
only the certificate is stored, unless the role asks for no_store. The common
name is copied into the subject alternative names unless the request excludes
it, which is what clients that ignore the CN need.
`

const pathSignHelpSyn = `Sign a certificate request`

const pathSignHelpDesc = `
Signs a certificate request with the authority of the mount, following the
policy of the named role. The signature of the request is verified first, and
the public key has to be an SM2 key. Whether the common name and the subject
alternative names of the request are taken over is decided by the role.
`
