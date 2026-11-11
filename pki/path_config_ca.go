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
// mount either keeps the private key and signs with it, or names the provider of
// a key an appliance holds, and signs through that.
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
				Description: `PEM bundle with the certificate of the authority and the certificates above it,
optionally preceded by its private key.`,
			},
			"provider": {
				Type:        framework.TypeString,
				Description: "Name of the registered signer provider that holds the private key of the authority, for a bundle that carries no key.",
			},
			"reference": {
				Type:        framework.TypeString,
				Description: "What the provider needs to find the key. It is recorded with the authority and read every time it signs.",
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
	provider := strings.TrimSpace(d.Get("provider").(string))
	reference := strings.TrimSpace(d.Get("reference").(string))

	key, certs, err := parseAuthorityBundle(d.Get("pem_bundle").(string))
	if err != nil {
		return logical.ErrorResponse(err.Error()), logical.ErrInvalidRequest
	}
	if key == nil && provider == "" {
		return logical.ErrorResponse("the bundle carries no private key; name the provider that holds it with provider, and the reference it goes by"), logical.ErrInvalidRequest
	}
	if key != nil && provider != "" {
		return logical.ErrorResponse("the bundle carries a private key and names a provider; import one or the other"), logical.ErrInvalidRequest
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

	record := &keyEntry{Provider: provider, Reference: reference}
	if key != nil {
		pkcs8, err := smx509.MarshalPKCS8PrivateKey(key)
		if err != nil {
			return nil, fmt.Errorf("could not marshal the certificate authority key: %w", err)
		}
		record.PrivateKey = pkcs8
	} else {
		// The holder of the key is asked now, so that an authority nobody can
		// sign with is refused at import rather than when a certificate is
		// first requested for it.
		signer, err := externalSigner(ctx, issuer, record)
		if err != nil {
			return logical.ErrorResponse(err.Error()), logical.ErrInvalidRequest
		}
		defer b.closeSigner(signer)

		if err := checkSignerKey(issuer, signer); err != nil {
			return logical.ErrorResponse(err.Error()), logical.ErrInvalidRequest
		}
	}

	if err := putJSON(ctx, req.Storage, keyPrefix+keyID, record); err != nil {
		return nil, err
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
Takes a PEM bundle with the certificate of an authority and the certificates
above it, and optionally its SM2 private key, and makes it the authority of this
mount. The certificate has to be a CA and the chain has to sign in order,
because a mount that stores a mismatched chain can only fail when a certificate
is requested. A mount that already holds an authority is refused; rotate it or
delete it first.

A bundle without a key belongs to an authority whose key is held in an HSM, a
PKCS#11 token or a key management service. Its certificate is imported the same
way, and provider names the registered signer implementation while reference is
whatever that implementation needs to find the key. The provider is asked during
this call, and its key has to be the one the certificate carries: a mount that
accepted a different one would sign certificates that verify only against
themselves.
`
