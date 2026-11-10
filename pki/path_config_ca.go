package pki

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/emmansun/gmsm/smx509"
	"github.com/hashicorp/go-uuid"
	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
)

// pathConfigCA adopts a certificate authority that was created elsewhere. The
// mount keeps the private key and signs with it from then on, and the chain
// above the certificate becomes the chain it publishes.
func (b *backend) pathConfigCA() *framework.Path {
	return &framework.Path{
		Pattern: "config/ca$",

		DisplayAttrs: &framework.DisplayAttributes{
			OperationPrefix: operationPrefix + "-config",
			OperationVerb:   "import",
			OperationSuffix: "ca",
		},

		Fields: map[string]*framework.FieldSchema{
			"pem_bundle": {
				Type: framework.TypeString,
				Description: `PEM bundle with the private key of the authority followed by its
certificate and the certificates above it.`,
			},
		},

		Callbacks: map[logical.Operation]framework.OperationFunc{
			logical.UpdateOperation: b.pathConfigCAWrite,
		},

		HelpSynopsis:    pathConfigCAHelpSyn,
		HelpDescription: pathConfigCAHelpDesc,
	}
}

func (b *backend) pathConfigCAWrite(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	key, certs, err := parseAuthorityBundle(d.Get("pem_bundle").(string))
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
		return logical.ErrorResponse("this mount already holds a certificate authority; add another with root/rotate/:type, or delete this one with DELETE /root"), logical.ErrInvalidRequest
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

	leaf := certs[0]
	issuer := &issuerEntry{
		ID:          issuerID,
		Certificate: leaf.Raw,
		KeyID:       keyID,
		Name:        strings.TrimSpace(leaf.Subject.CommonName),
		Serial:      serialHex(leaf.SerialNumber),
		Created:     time.Now(),
	}
	for _, cert := range certs[1:] {
		issuer.Chain = append(issuer.Chain, cert.Raw)
	}
	if err := b.putIssuer(ctx, req.Storage, issuerID, issuer); err != nil {
		return nil, err
	}

	der := make([][]byte, len(certs))
	for i, cert := range certs {
		der[i] = cert.Raw
	}

	return &logical.Response{Data: map[string]interface{}{
		"certificate":   pemCertificate(leaf.Raw),
		"ca_chain":      pemCertificates(der),
		"serial_number": formatSerial(issuer.Serial),
		"expiration":    leaf.NotAfter.Unix(),
		"issuer_id":     issuerID,
		"key_id":        keyID,
	}}, nil
}

const pathConfigCAHelpSyn = `Import a certificate authority created elsewhere`

const pathConfigCAHelpDesc = `
Takes a PEM bundle with an SM2 private key and the certificate of the authority
that belongs to it, followed by the certificates above it, and makes it the
authority of this mount. The certificate has to carry the public key of the key
and the chain has to sign in order, because a mount that stores a mismatched
pair can only fail when a certificate is requested. A mount that already holds
an authority is refused; rotate it or delete it first.
`
