package pki

import (
	"context"
	"crypto/rand"
	"crypto/x509/pkix"
	"fmt"
	"strings"
	"time"

	"github.com/emmansun/gmsm/sm2"
	"github.com/emmansun/gmsm/smx509"
	"github.com/hashicorp/go-uuid"
	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
)

// defaultIntermediateTTL is how long the intermediate certificate requested by
// root/sign-intermediate is valid for, before the remaining validity of the
// signing authority clamps it.
const defaultIntermediateTTL = 5 * 365 * 24 * time.Hour

// rootFields describes what a request to create an authority may carry. Both
// root/generate and root/rotate take the same set, because a rotation is a
// generation that leaves the authority it replaces in place.
func rootFields() map[string]*framework.FieldSchema {
	fields := subjectFieldSchemas()
	fields["type"] = &framework.FieldSchema{
		Type: framework.TypeString,
		Description: `What to do with the generated private key: "internal" keeps it
in the mount and never returns it, "exported" returns it in the response once.`,
	}
	fields["common_name"] = &framework.FieldSchema{
		Type:        framework.TypeString,
		Description: "Common name (CN) of the certificate authority.",
	}
	fields["ttl"] = &framework.FieldSchema{
		Type:        framework.TypeDurationSecond,
		Default:     int(defaultRootTTL / time.Second),
		Description: "Validity of the generated certificate authority. Defaults to ten years.",
	}
	fields["max_path_length"] = &framework.FieldSchema{
		Type:        framework.TypeInt,
		Default:     -1,
		Description: `Maximum number of intermediate authorities allowed below this one. -1 means no limit, 0 forbids any.`,
	}
	fields["key_type"] = &framework.FieldSchema{
		Type:        framework.TypeString,
		Default:     "sm2",
		Description: `Type of the generated key. Only "sm2" is supported.`,
	}
	fields["format"] = &framework.FieldSchema{
		Type:        framework.TypeString,
		Default:     "pem",
		Description: `Encoding of the returned certificate: "pem" or "der" (base64 encoded).`,
	}
	fields["private_key_format"] = &framework.FieldSchema{
		Type:        framework.TypeString,
		Default:     "der",
		Description: `Encoding of the returned private key: "der" for SEC 1, "pkcs8" for PKCS#8.`,
	}

	return fields
}

// pathRootGenerate creates the self-signed authority of the mount. A mount is
// generated once, so a second call is refused rather than quietly replacing the
// first: certificates already issued would stop verifying against the new one.
// root/rotate is the operation that adds another authority beside it.
func (b *backend) pathRootGenerate() *framework.Path {
	return &framework.Path{
		Pattern: "root/generate/" + framework.GenericNameRegex("type"),

		DisplayAttrs: &framework.DisplayAttributes{
			OperationPrefix: operationPrefix,
			OperationVerb:   "generate-root",
		},

		Fields: rootFields(),

		Callbacks: map[logical.Operation]framework.OperationFunc{
			logical.UpdateOperation: b.pathRootGenerateWrite,
		},

		HelpSynopsis:    pathRootGenerateHelpSyn,
		HelpDescription: pathRootGenerateHelpDesc,
	}
}

// pathRootRotate generates a new self-signed authority and makes it the one the
// mount signs with. The authority it replaces stays in the mount: the
// certificates that one signed keep verifying against it, and its list keeps
// answering for the serials it revoked, until it is retired on its own.
func (b *backend) pathRootRotate() *framework.Path {
	return &framework.Path{
		Pattern: "root/rotate/" + framework.GenericNameRegex("type"),

		DisplayAttrs: &framework.DisplayAttributes{
			OperationPrefix: operationPrefix,
			OperationVerb:   "rotate-root",
		},

		Fields: rootFields(),

		Callbacks: map[logical.Operation]framework.OperationFunc{
			logical.UpdateOperation: b.pathRootRotateWrite,
		},

		HelpSynopsis:    pathRootRotateHelpSyn,
		HelpDescription: pathRootRotateHelpDesc,
	}
}

func (b *backend) pathRootGenerateWrite(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	return b.generateAuthority(ctx, req, d, false)
}

func (b *backend) pathRootRotateWrite(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	return b.generateAuthority(ctx, req, d, true)
}

// generateAuthority implements both root/generate and root/rotate. rotate says
// whether an authority that is already in the mount may stay where it is.
func (b *backend) generateAuthority(ctx context.Context, req *logical.Request, d *framework.FieldData, rotate bool) (*logical.Response, error) {
	caType := d.Get("type").(string)
	switch caType {
	case "internal", "exported":
	default:
		return logical.ErrorResponse(fmt.Sprintf("type %q is not supported; use internal or exported", caType)), logical.ErrInvalidRequest
	}

	commonName := strings.TrimSpace(d.Get("common_name").(string))
	if commonName == "" {
		return logical.ErrorResponse("common_name is required"), logical.ErrInvalidRequest
	}

	if err := checkSM2KeyType(d.Get("key_type").(string)); err != nil {
		return logical.ErrorResponse(err.Error()), logical.ErrInvalidRequest
	}

	format, privateKeyFormat, err := outputFormats(d, caType == "exported")
	if err != nil {
		return logical.ErrorResponse(err.Error()), logical.ErrInvalidRequest
	}

	ttl := time.Duration(d.Get("ttl").(int)) * time.Second
	if ttl <= 0 {
		ttl = defaultRootTTL
	}

	b.caMu.Lock()
	defer b.caMu.Unlock()

	previous, err := b.issuer(ctx, req.Storage)
	if err != nil {
		return nil, err
	}
	if previous != nil && !rotate {
		return logical.ErrorResponse("this mount already holds a certificate authority; add another with root/rotate/:type, or delete this one with DELETE /root"), logical.ErrInvalidRequest
	}

	subject := subjectFromFields(d, commonName)
	key, cert, issuer, err := b.newSelfSignedIssuer(ctx, req.Storage, subject, ttl, d.Get("max_path_length").(int))
	if err != nil {
		return nil, err
	}

	data, err := authorityResponseData(key, cert, issuer, format, privateKeyFormat, caType == "exported")
	if err != nil {
		return nil, err
	}
	if previous != nil {
		data["previous_issuer_id"] = previous.ID
	}

	return &logical.Response{Data: data}, nil
}

// newSelfSignedIssuer generates a key, certifies it as an authority, stores
// both and makes the record the one the mount signs with.
func (b *backend) newSelfSignedIssuer(ctx context.Context, s logical.Storage, subject pkix.Name, ttl time.Duration, maxPathLen int) (*sm2.PrivateKey, *smx509.Certificate, *issuerEntry, error) {
	key, err := sm2.GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("could not generate the certificate authority key: %w", err)
	}

	cert, err := b.rootCertificate(ctx, s, subject, key, ttl, maxPathLen)
	if err != nil {
		return nil, nil, nil, err
	}

	keyID, err := uuid.GenerateUUID()
	if err != nil {
		return nil, nil, nil, err
	}
	issuerID, err := uuid.GenerateUUID()
	if err != nil {
		return nil, nil, nil, err
	}

	pkcs8, err := smx509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("could not marshal the certificate authority key: %w", err)
	}
	if err := putJSON(ctx, s, keyPrefix+keyID, &keyEntry{PrivateKey: pkcs8}); err != nil {
		return nil, nil, nil, err
	}

	issuer := &issuerEntry{
		ID:          issuerID,
		Certificate: cert.Raw,
		KeyID:       keyID,
		Serial:      serialHex(cert.SerialNumber),
		Created:     time.Now(),
	}
	if err := b.putIssuer(ctx, s, issuerID, issuer); err != nil {
		return nil, nil, nil, err
	}

	return key, cert, issuer, nil
}

// authorityResponseData renders the answer of an operation that created an
// authority, with the private key added when the caller asked for it.
func authorityResponseData(key *sm2.PrivateKey, cert *smx509.Certificate, issuer *issuerEntry, format, privateKeyFormat string, exported bool) (map[string]interface{}, error) {
	certificate := renderCertificate(cert.Raw, format)
	data := map[string]interface{}{
		"certificate":   certificate,
		"issuing_ca":    certificate,
		"ca_chain":      []string{certificate},
		"serial_number": formatSerial(issuer.Serial),
		"expiration":    cert.NotAfter.Unix(),
		"issuer_id":     issuer.ID,
		"key_id":        issuer.KeyID,
	}

	if !exported {
		return data, nil
	}

	privateKey, err := marshalPrivateKey(key, format, privateKeyFormat)
	if err != nil {
		return nil, err
	}
	data["private_key"] = privateKey
	data["private_key_type"] = "sm2"
	if format == "pem_bundle" {
		data["certificate"] = privateKey + certificate
	}

	return data, nil
}

// pathRootDelete removes the authority and everything issued under it, which is
// how a mount is emptied. A mount that has been rotated holds more than one
// authority and answers with a refusal here: they are retired one at a time,
// because each of them speaks for the certificates it signed. The roles
// survive, because they are policy rather than state of the authority.
func (b *backend) pathRootDelete() *framework.Path {
	return &framework.Path{
		Pattern: "root$",

		DisplayAttrs: &framework.DisplayAttributes{
			OperationPrefix: operationPrefix,
			OperationVerb:   "delete-root",
		},

		Callbacks: map[logical.Operation]framework.OperationFunc{
			logical.DeleteOperation: b.pathRootDeleteWrite,
		},

		HelpSynopsis:    pathRootDeleteHelpSyn,
		HelpDescription: pathRootDeleteHelpDesc,
	}
}

func (b *backend) pathRootDeleteWrite(ctx context.Context, req *logical.Request, _ *framework.FieldData) (*logical.Response, error) {
	b.caMu.Lock()
	defer b.caMu.Unlock()

	// A rotation leaves more than one authority behind, and each of them speaks
	// for the certificates it signed. Wiping them all in one call would throw
	// that history away without an operator seeing what went with it, so they
	// are retired one at a time.
	issuers, err := req.Storage.List(ctx, issuerPrefix)
	if err != nil {
		return nil, err
	}
	if len(issuers) > 1 {
		return logical.ErrorResponse(fmt.Sprintf("this mount holds %d authorities; retire them one at a time with DELETE /issuer/:ref until one is left", len(issuers))), logical.ErrInvalidRequest
	}

	for _, prefix := range []string{issuerPrefix, keyPrefix, certPrefix, revokedPrefix, crlPrefix} {
		if _, err := b.deletePrefix(ctx, req.Storage, prefix); err != nil {
			return nil, err
		}
	}

	for _, path := range []string{configIssuerPath, configPendingKeyPath} {
		if err := req.Storage.Delete(ctx, path); err != nil {
			return nil, err
		}
	}

	return nil, nil
}

// pathRootSignIntermediate signs a CA request with the authority of the mount,
// which is how a second mount becomes an intermediate of this one.
func (b *backend) pathRootSignIntermediate() *framework.Path {
	fields := subjectFieldSchemas()
	fields["csr"] = &framework.FieldSchema{
		Type:        framework.TypeString,
		Description: "PEM encoded certificate request of the intermediate, as produced by intermediate/generate.",
	}
	fields["common_name"] = &framework.FieldSchema{
		Type:        framework.TypeString,
		Description: "Common name to place in the certificate. Required unless use_csr_values is set.",
	}
	fields["ttl"] = &framework.FieldSchema{
		Type:        framework.TypeDurationSecond,
		Default:     int(defaultIntermediateTTL / time.Second),
		Description: "Validity of the intermediate certificate, before the remaining validity of this authority clamps it.",
	}
	fields["max_path_length"] = &framework.FieldSchema{
		Type:        framework.TypeInt,
		Default:     -1,
		Description: "Maximum number of authorities below the intermediate. -1 means no limit.",
	}
	fields["permitted_dns_domains"] = &framework.FieldSchema{
		Type: framework.TypeCommaStringSlice,
		Description: `DNS names the intermediate may vouch for, as a comma separated list. An
entry starting with a dot also allows the subdomains below it.`,
	}
	fields["excluded_dns_domains"] = &framework.FieldSchema{
		Type: framework.TypeCommaStringSlice,
		Description: `DNS names the intermediate must not vouch for, as a comma separated
list. An entry starting with a dot also excludes the subdomains below it.`,
	}
	fields["permitted_ip_addresses"] = &framework.FieldSchema{
		Type:        framework.TypeCommaStringSlice,
		Description: "IP ranges the intermediate may vouch for, as a comma separated list of CIDR blocks.",
	}
	fields["excluded_ip_addresses"] = &framework.FieldSchema{
		Type:        framework.TypeCommaStringSlice,
		Description: "IP ranges the intermediate must not vouch for, as a comma separated list of CIDR blocks.",
	}
	fields["use_csr_values"] = &framework.FieldSchema{
		Type:        framework.TypeBool,
		Default:     false,
		Description: "Use the subject and the names of the request instead of the fields of this request.",
	}
	fields["format"] = &framework.FieldSchema{
		Type:        framework.TypeString,
		Default:     "pem",
		Description: `Encoding of the returned certificate: "pem" or "der" (base64 encoded).`,
	}

	return &framework.Path{
		Pattern: "root/sign-intermediate",

		DisplayAttrs: &framework.DisplayAttributes{
			OperationPrefix: operationPrefix,
			OperationVerb:   "sign-intermediate",
		},

		Fields: fields,

		Callbacks: map[logical.Operation]framework.OperationFunc{
			logical.UpdateOperation: b.pathRootSignIntermediateWrite,
		},

		HelpSynopsis:    pathRootSignIntermediateHelpSyn,
		HelpDescription: pathRootSignIntermediateHelpDesc,
	}
}

func (b *backend) pathRootSignIntermediateWrite(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	format, err := certificateFormat(d, false)
	if err != nil {
		return logical.ErrorResponse(err.Error()), logical.ErrInvalidRequest
	}

	csr, err := parseCertificateRequest(d.Get("csr").(string))
	if err != nil {
		return logical.ErrorResponse(err.Error()), logical.ErrInvalidRequest
	}

	publicKey, err := checkSM2PublicKey(csr.PublicKey)
	if err != nil {
		return logical.ErrorResponse(err.Error()), logical.ErrInvalidRequest
	}

	useCSRValues := d.Get("use_csr_values").(bool)

	var subject pkix.Name
	if useCSRValues {
		subject = csr.Subject
		if strings.TrimSpace(subject.CommonName) == "" {
			return logical.ErrorResponse("the certificate request has no common name; supply common_name"), logical.ErrInvalidRequest
		}
	} else {
		commonName := strings.TrimSpace(d.Get("common_name").(string))
		if commonName == "" {
			return logical.ErrorResponse("common_name is required unless use_csr_values is set"), logical.ErrInvalidRequest
		}
		subject = subjectFromFields(d, commonName)
	}

	constraints, err := nameConstraintsFromFields(d)
	if err != nil {
		return logical.ErrorResponse(err.Error()), logical.ErrInvalidRequest
	}

	b.caMu.Lock()
	defer b.caMu.Unlock()

	issuer, chain, resp, err := b.caBundle(ctx, req.Storage)
	if resp != nil || err != nil {
		return resp, err
	}
	signer, err := b.issuerSigner(ctx, req.Storage, issuer)
	if err != nil {
		return nil, err
	}
	defer b.closeSigner(signer)

	request := certificateRequest{
		Subject:         subject,
		PublicKey:       publicKey,
		KeyUsage:        smx509.KeyUsageCertSign | smx509.KeyUsageCRLSign | smx509.KeyUsageDigitalSignature,
		IsCA:            true,
		MaxPathLen:      d.Get("max_path_length").(int),
		TTL:             time.Duration(d.Get("ttl").(int)) * time.Second,
		NameConstraints: constraints,
	}
	if useCSRValues {
		request.DNSNames = csr.DNSNames
		request.EmailAddresses = csr.EmailAddresses
		request.IPAddresses = csr.IPAddresses
		request.URIs = csr.URIs
	}

	cert, warnings, err := b.signWithIssuer(ctx, req.Storage, issuer, signer, request)
	if err != nil {
		return issuerError(err)
	}

	if err := b.storeIssuedCertificate(ctx, req.Storage, cert, "intermediate", issuer.ID, true); err != nil {
		return nil, err
	}

	der := make([][]byte, len(chain))
	for i, c := range chain {
		der[i] = c.Raw
	}

	return &logical.Response{
		Data: map[string]interface{}{
			"certificate":   renderCertificate(cert.Raw, format),
			"issuing_ca":    renderCertificate(issuer.Certificate, format),
			"ca_chain":      pemCertificates(der),
			"serial_number": formatSerial(serialHex(cert.SerialNumber)),
			"expiration":    cert.NotAfter.Unix(),
			"issuer_id":     issuer.ID,
		},
		Warnings: warnings,
	}, nil
}

// checkSM2KeyType refuses a key type the mount cannot generate. The message
// names the field so a caller does not have to guess which parameter it was.
func checkSM2KeyType(raw string) error {
	if raw == "" || raw == "sm2" {
		return nil
	}

	return fmt.Errorf("key_type %q is not supported; this mount only issues SM2 keys", raw)
}

// outputFormats validates the pair of encoding fields of an operation that may
// return a private key.
func outputFormats(d *framework.FieldData, bundle bool) (string, string, error) {
	format, err := certificateFormat(d, bundle)
	if err != nil {
		return "", "", err
	}

	keyFormat, err := privateKeyFormat(d)
	if err != nil {
		return "", "", err
	}

	return format, keyFormat, nil
}

const pathRootGenerateHelpSyn = `Generate a self-signed certificate authority`

const pathRootGenerateHelpDesc = `
Generates an SM2 key and a self-signed CA certificate for it. The private key
stays in the mount unless the type of the request is "exported", in which case
it is returned once. This creates the authority of a mount that has none; use
root/rotate/:type to add another one.
`

const pathRootRotateHelpSyn = `Generate a new certificate authority and sign with it`

const pathRootRotateHelpDesc = `
Generates an SM2 key and a self-signed CA certificate for it, and makes it the
authority this mount signs with. The authority it replaces stays in the mount,
where its certificates keep verifying against it and its revocation list keeps
answering for its serials; issuers lists all of them, issuer/:ref reads one, and
DELETE /issuer/:ref retires one once its certificates have expired.
`

const pathRootDeleteHelpSyn = `Delete the certificate authority and everything under it`

const pathRootDeleteHelpDesc = `
Removes the authority, its key, every certificate the mount stored and the
revocation state. Roles are kept, because they describe policy rather than the
authority itself. A mount that has been rotated holds more than one authority;
retire them one at a time with DELETE /issuer/:ref until one is left.
`

const pathRootSignIntermediateHelpSyn = `Sign an intermediate certificate request`

const pathRootSignIntermediateHelpDesc = `
Issues a CA certificate for the public key in the request, from the authority of
this mount. The result is what intermediate/set-signed expects on the other
mount.
`
