package pki

import (
	"context"
	"crypto/ecdsa"
	"crypto/rand"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"strings"
	"time"

	"github.com/emmansun/gmsm/sm2"
	"github.com/emmansun/gmsm/smx509"
	"github.com/hashicorp/go-uuid"
	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
)

// pathIntermediateGenerate creates the key of an intermediate and the request
// for its certificate. Nothing is signed here: the request goes to the
// authority above, and intermediate/set-signed completes the mount once the
// signed certificate comes back.
func (b *backend) pathIntermediateGenerate() *framework.Path {
	fields := subjectFieldSchemas()
	fields["type"] = &framework.FieldSchema{
		Type: framework.TypeString,
		Description: `What to do with the generated private key: "internal" keeps it in
the mount and never returns it, "exported" returns it in the response once.`,
	}
	fields["common_name"] = &framework.FieldSchema{
		Type:        framework.TypeString,
		Description: "Common name (CN) of the intermediate certificate.",
	}
	fields["ttl"] = &framework.FieldSchema{
		Type:        framework.TypeDurationSecond,
		Default:     int(defaultIntermediateTTL / time.Second),
		Description: "Validity to request for the intermediate certificate.",
	}
	fields["key_type"] = &framework.FieldSchema{
		Type:        framework.TypeString,
		Default:     "sm2",
		Description: `Type of the generated key. Only "sm2" is supported.`,
	}
	fields["format"] = &framework.FieldSchema{
		Type:        framework.TypeString,
		Default:     "pem",
		Description: `Encoding of the returned request: "pem" or "der" (base64 encoded).`,
	}
	fields["private_key_format"] = &framework.FieldSchema{
		Type:        framework.TypeString,
		Default:     "der",
		Description: `Encoding of the returned private key: "der" for SEC 1, "pkcs8" for PKCS#8.`,
	}

	return &framework.Path{
		Pattern: "intermediate/generate/" + framework.GenericNameRegex("type"),

		DisplayAttrs: &framework.DisplayAttributes{
			OperationPrefix: operationPrefix,
			OperationVerb:   "generate-intermediate",
		},

		Fields: fields,

		Callbacks: map[logical.Operation]framework.OperationFunc{
			logical.UpdateOperation: b.pathIntermediateGenerateWrite,
		},

		HelpSynopsis:    pathIntermediateGenerateHelpSyn,
		HelpDescription: pathIntermediateGenerateHelpDesc,
	}
}

func (b *backend) pathIntermediateGenerateWrite(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
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

	format, keyFormat, err := outputFormats(d, caType == "exported")
	if err != nil {
		return logical.ErrorResponse(err.Error()), logical.ErrInvalidRequest
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
		return nil, fmt.Errorf("could not generate the intermediate key: %w", err)
	}

	keyID, err := uuid.GenerateUUID()
	if err != nil {
		return nil, err
	}

	pkcs8, err := smx509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return nil, fmt.Errorf("could not marshal the intermediate key: %w", err)
	}

	// A second generate replaces the first request, so the key of the first
	// does not linger in the mount with nothing that will ever use it.
	previous, err := b.pendingKeyID(ctx, req.Storage)
	if err != nil {
		return nil, err
	}
	if previous != "" {
		if err := req.Storage.Delete(ctx, keyPrefix+previous); err != nil {
			return nil, err
		}
	}

	if err := putJSON(ctx, req.Storage, keyPrefix+keyID, &keyEntry{PrivateKey: pkcs8}); err != nil {
		return nil, err
	}
	if err := b.setPendingKeyID(ctx, req.Storage, keyID); err != nil {
		return nil, err
	}

	template := &smx509.CertificateRequest{
		Subject:            subjectFromFields(d, commonName),
		SignatureAlgorithm: smx509.SM2WithSM3,
	}
	der, err := smx509.CreateCertificateRequest(rand.Reader, template, key)
	if err != nil {
		return nil, fmt.Errorf("could not create the certificate request: %w", err)
	}

	csr := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der}))
	if format == "der" {
		csr = base64.StdEncoding.EncodeToString(der)
	}

	data := map[string]interface{}{
		"csr":    csr,
		"key_id": keyID,
	}
	if caType == "exported" {
		privateKey, err := marshalPrivateKey(key, format, keyFormat)
		if err != nil {
			return nil, err
		}
		data["private_key"] = privateKey
		data["private_key_type"] = "sm2"
		if format == "pem_bundle" {
			data["csr"] = privateKey + csr
		}
	}

	return &logical.Response{Data: data}, nil
}

// pathIntermediateSetSigned completes an intermediate mount from the
// certificate the authority above issued for the request of this mount.
func (b *backend) pathIntermediateSetSigned() *framework.Path {
	return &framework.Path{
		Pattern: "intermediate/set-signed$",

		DisplayAttrs: &framework.DisplayAttributes{
			OperationPrefix: operationPrefix,
			OperationVerb:   "set-signed-intermediate",
		},

		Fields: map[string]*framework.FieldSchema{
			"certificate": {
				Type: framework.TypeString,
				Description: `PEM bundle of the signed intermediate certificate, followed by
the certificates above it.`,
			},
		},

		Callbacks: map[logical.Operation]framework.OperationFunc{
			logical.UpdateOperation: b.pathIntermediateSetSignedWrite,
		},

		HelpSynopsis:    pathIntermediateSetSignedHelpSyn,
		HelpDescription: pathIntermediateSetSignedHelpDesc,
	}
}

func (b *backend) pathIntermediateSetSignedWrite(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	certs, err := parseCertificates(d.Get("certificate").(string))
	if err != nil {
		return logical.ErrorResponse(err.Error()), logical.ErrInvalidRequest
	}

	b.caMu.Lock()
	defer b.caMu.Unlock()

	existing, err := b.issuer(ctx, req.Storage)
	if err != nil {
		return nil, err
	}
	if existing != nil {
		return logical.ErrorResponse("this mount already holds a certificate authority; delete it with DELETE /root before setting another"), logical.ErrInvalidRequest
	}

	keyID, err := b.pendingKeyID(ctx, req.Storage)
	if err != nil {
		return nil, err
	}
	if keyID == "" {
		return logical.ErrorResponse("no intermediate request is pending; call intermediate/generate/:type first"), logical.ErrInvalidRequest
	}

	key, err := b.issuerSigner(ctx, req.Storage, &issuerEntry{KeyID: keyID})
	if err != nil {
		return nil, err
	}
	defer b.closeSigner(key)

	leaf := certs[0]
	if !leaf.IsCA {
		return logical.ErrorResponse("the certificate is not a certificate authority"), logical.ErrInvalidRequest
	}

	publicKey, ok := leaf.PublicKey.(*ecdsa.PublicKey)
	if !ok || !publicKey.Equal(key.Public()) {
		return logical.ErrorResponse("the certificate does not belong to the pending key of this mount"), logical.ErrInvalidRequest
	}

	issuer := &issuerEntry{
		Certificate: leaf.Raw,
		KeyID:       keyID,
		Name:        strings.TrimSpace(leaf.Subject.CommonName),
		Serial:      serialHex(leaf.SerialNumber),
		Created:     time.Now(),
	}

	if len(certs) > 1 {
		if err := leaf.CheckSignatureFrom(certs[1]); err != nil {
			return logical.ErrorResponse(fmt.Sprintf("the certificate is not signed by the certificate above it: %v", err)), logical.ErrInvalidRequest
		}
		for _, cert := range certs[1:] {
			issuer.Chain = append(issuer.Chain, cert.Raw)
		}
	}

	issuerID, err := uuid.GenerateUUID()
	if err != nil {
		return nil, err
	}
	if err := b.putIssuer(ctx, req.Storage, issuerID, issuer); err != nil {
		return nil, err
	}

	// The key now belongs to the issuer, so the pending marker goes away.
	if err := req.Storage.Delete(ctx, configPendingKeyPath); err != nil {
		return nil, err
	}

	return &logical.Response{Data: map[string]interface{}{
		"certificate":   pemCertificate(leaf.Raw),
		"serial_number": formatSerial(issuer.Serial),
		"issuer_id":     issuerID,
	}}, nil
}

const pathIntermediateGenerateHelpSyn = `Generate an intermediate key and its certificate request`

const pathIntermediateGenerateHelpDesc = `
Generates an SM2 key and a certificate request for it. Send the request to
root/sign-intermediate on the mount that holds the authority above, then hand
the signed certificate back to intermediate/set-signed. Until then the key sits
in the mount with nothing to sign.
`

const pathIntermediateSetSignedHelpSyn = `Complete an intermediate from a signed certificate`

const pathIntermediateSetSignedHelpDesc = `
Takes the certificate that the authority above issued for the pending request,
verifies that it belongs to the pending key and that the chain above it signed
it, and makes it the authority of this mount.
`
