package pki

import (
	"context"
	"net/http"

	"github.com/emmansun/gmsm/smx509"
	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
)

// pathCA reads the issuer certificate as JSON. The certificate is also
// available as a raw PEM body on ca/pem, which is what a client that wants to
// write it straight to a file should use.
func (b *backend) pathCA() *framework.Path {
	return &framework.Path{
		Pattern: "ca$",

		DisplayAttrs: &framework.DisplayAttributes{
			OperationPrefix: operationPrefix,
			OperationVerb:   "read-ca",
		},

		Callbacks: map[logical.Operation]framework.OperationFunc{
			logical.ReadOperation: b.pathCARead,
		},

		HelpSynopsis:    pathCAHelpSyn,
		HelpDescription: pathCAHelpDesc,
	}
}

func (b *backend) pathCAPEM() *framework.Path {
	return &framework.Path{
		Pattern: "ca/pem$",

		DisplayAttrs: &framework.DisplayAttributes{
			OperationPrefix: operationPrefix,
			OperationVerb:   "read-ca",
			OperationSuffix: "pem",
		},

		Callbacks: map[logical.Operation]framework.OperationFunc{
			logical.ReadOperation: b.pathCAPEMRead,
		},

		HelpSynopsis:    pathCAHelpSyn,
		HelpDescription: pathCAHelpDesc,
	}
}

func (b *backend) pathCAChain() *framework.Path {
	return &framework.Path{
		Pattern: "ca_chain$",

		DisplayAttrs: &framework.DisplayAttributes{
			OperationPrefix: operationPrefix,
			OperationVerb:   "read-ca",
			OperationSuffix: "chain",
		},

		Callbacks: map[logical.Operation]framework.OperationFunc{
			logical.ReadOperation: b.pathCAChainRead,
		},

		HelpSynopsis:    pathCAHelpSyn,
		HelpDescription: pathCAHelpDesc,
	}
}

func (b *backend) pathCARead(ctx context.Context, req *logical.Request, _ *framework.FieldData) (*logical.Response, error) {
	issuer, chain, resp, err := b.caBundle(ctx, req.Storage)
	if resp != nil || err != nil {
		return resp, err
	}

	der := make([][]byte, len(chain))
	for i, cert := range chain {
		der[i] = cert.Raw
	}

	data := map[string]interface{}{
		"certificate":   pemCertificate(issuer.Certificate),
		"ca_chain":      pemCertificates(der),
		"serial_number": formatSerial(issuer.Serial),
	}

	id, err := b.issuerID(ctx, req.Storage)
	if err != nil {
		return nil, err
	}
	if id != "" {
		data["issuer_id"] = id
	}

	return &logical.Response{Data: data}, nil
}

func (b *backend) pathCAPEMRead(ctx context.Context, req *logical.Request, _ *framework.FieldData) (*logical.Response, error) {
	issuer, _, resp, err := b.caBundle(ctx, req.Storage)
	if resp != nil || err != nil {
		return resp, err
	}

	return &logical.Response{
		Data: map[string]interface{}{
			logical.HTTPContentType: "application/pem-encoding",
			logical.HTTPRawBody:     []byte(pemCertificate(issuer.Certificate)),
			logical.HTTPStatusCode:  http.StatusOK,
		},
	}, nil
}

func (b *backend) pathCAChainRead(ctx context.Context, req *logical.Request, _ *framework.FieldData) (*logical.Response, error) {
	_, chain, resp, err := b.caBundle(ctx, req.Storage)
	if resp != nil || err != nil {
		return resp, err
	}

	der := make([][]byte, len(chain))
	for i, cert := range chain {
		der[i] = cert.Raw
	}

	return &logical.Response{Data: map[string]interface{}{
		"ca_chain": pemCertificates(der),
	}}, nil
}

// caBundle loads the issuer and the chain above it. Every response that needs a
// CA goes through here, so a mount without one answers with the same message
// everywhere.
func (b *backend) caBundle(ctx context.Context, s logical.Storage) (*issuerEntry, []*smx509.Certificate, *logical.Response, error) {
	issuer, err := b.issuer(ctx, s)
	if err != nil {
		return nil, nil, nil, err
	}
	if issuer == nil {
		return nil, nil, logical.ErrorResponse(errNoIssuer.Error()), logical.ErrInvalidRequest
	}

	chain, err := issuer.chain()
	if err != nil {
		return nil, nil, nil, err
	}

	return issuer, chain, nil, nil
}

// issuerID returns the identifier of the issuer the mount signs with, or an
// empty string when the mount holds none.
func (b *backend) issuerID(ctx context.Context, s logical.Storage) (string, error) {
	index, err := getJSON[issuerIndex](ctx, s, configIssuerPath)
	if err != nil || index == nil {
		return "", err
	}

	return index.ID, nil
}

// legacyIssuerID is the authority that the records written before a certificate
// recorded its issuer belong to: the one the index remembers, or, on a mount
// that has never signed with another authority, the one it signs with now.
func (b *backend) legacyIssuerID(ctx context.Context, s logical.Storage) (string, error) {
	index, err := getJSON[issuerIndex](ctx, s, configIssuerPath)
	if err != nil || index == nil {
		return "", err
	}
	if index.LegacyOwner != "" {
		return index.LegacyOwner, nil
	}

	return index.ID, nil
}

const pathCAHelpSyn = `Read the certificate authority certificate and chain`

const pathCAHelpDesc = `
The certificate of the authority that signs in this mount, together with the
chain above it. The raw PEM body is served on ca/pem for clients that write the
file straight to disk.
`
