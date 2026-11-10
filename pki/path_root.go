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

// pathRootGenerate creates the self-signed authority of the mount. The mount
// holds one authority, so a second call is refused rather than quietly
// replacing the first: certificates already issued would stop verifying
// against the new one.
func (b *backend) pathRootGenerate() *framework.Path {
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

	return &framework.Path{
		Pattern: "root/generate/" + framework.GenericNameRegex("type"),

		DisplayAttrs: &framework.DisplayAttributes{
			OperationPrefix: operationPrefix,
			OperationVerb:   "generate-root",
		},

		Fields: fields,

		Callbacks: map[logical.Operation]framework.OperationFunc{
			logical.UpdateOperation: b.pathRootGenerateWrite,
		},

		HelpSynopsis:    pathRootGenerateHelpSyn,
		HelpDescription: pathRootGenerateHelpDesc,
	}
}

func (b *backend) pathRootGenerateWrite(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
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

	existing, err := b.issuer(ctx, req.Storage)
	if err != nil {
		return nil, err
	}
	if existing != nil {
		return logical.ErrorResponse("this mount already holds a certificate authority; delete it with DELETE /root before generating another"), logical.ErrInvalidRequest
	}

	key, err := sm2.GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("could not generate the certificate authority key: %w", err)
	}

	cert, err := b.rootCertificate(ctx, req.Storage, subjectFromFields(d, commonName), key, ttl, d.Get("max_path_length").(int))
	if err != nil {
		return nil, err
	}

	keyID, err := uuid.GenerateUUID()
	if err != nil {
		return nil, err
	}
	issuerID, err := uuid.GenerateUUID()
	if err != nil {
		return nil, err
	}

	pkcs8, err := smx509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return nil, fmt.Errorf("could not marshal the certificate authority key: %w", err)
	}
	if err := putJSON(ctx, req.Storage, keyPrefix+keyID, &keyEntry{PrivateKey: pkcs8}); err != nil {
		return nil, err
	}

	issuer := &issuerEntry{
		Certificate: cert.Raw,
		KeyID:       keyID,
		Serial:      serialHex(cert.SerialNumber),
		Created:     time.Now(),
	}
	if err := b.putIssuer(ctx, req.Storage, issuerID, issuer); err != nil {
		return nil, err
	}

	data := map[string]interface{}{
		"certificate":   renderCertificate(cert.Raw, format),
		"issuing_ca":    renderCertificate(cert.Raw, format),
		"ca_chain":      []string{renderCertificate(cert.Raw, format)},
		"serial_number": formatSerial(issuer.Serial),
		"expiration":    cert.NotAfter.Unix(),
		"issuer_id":     issuerID,
		"key_id":        keyID,
	}

	if caType == "exported" {
		privateKey, err := marshalPrivateKey(key, format, privateKeyFormat)
		if err != nil {
			return nil, err
		}
		data["private_key"] = privateKey
		data["private_key_type"] = "sm2"
		if format == "pem_bundle" {
			data["certificate"] = privateKey + data["certificate"].(string)
		}
	}

	return &logical.Response{Data: data}, nil
}

// pathRootDelete removes the authority and everything issued under it. The
// roles survive, because they are policy rather than state of the authority.
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

	request := certificateRequest{
		Subject:    subject,
		PublicKey:  publicKey,
		KeyUsage:   smx509.KeyUsageCertSign | smx509.KeyUsageCRLSign | smx509.KeyUsageDigitalSignature,
		IsCA:       true,
		MaxPathLen: d.Get("max_path_length").(int),
		TTL:        time.Duration(d.Get("ttl").(int)) * time.Second,
	}
	if useCSRValues {
		request.DNSNames = csr.DNSNames
		request.EmailAddresses = csr.EmailAddresses
		request.IPAddresses = csr.IPAddresses
		request.URIs = csr.URIs
	}

	cert, warnings, err := b.signWithIssuer(ctx, req.Storage, issuer, signer, request)
	if err != nil {
		return nil, err
	}

	if err := b.storeIssuedCertificate(ctx, req.Storage, cert, "intermediate", true); err != nil {
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
it is returned once. A mount holds a single authority, so this fails once one
exists.
`

const pathRootDeleteHelpSyn = `Delete the certificate authority and everything under it`

const pathRootDeleteHelpDesc = `
Removes the authority, its key, every certificate the mount stored and the
revocation state. Roles are kept, because they describe policy rather than the
authority itself.
`

const pathRootSignIntermediateHelpSyn = `Sign an intermediate certificate request`

const pathRootSignIntermediateHelpDesc = `
Issues a CA certificate for the public key in the request, from the authority of
this mount. The result is what intermediate/set-signed expects on the other
mount.
`
