package pki

import (
	"context"

	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
)

// pathIssuersList lists the authorities the mount holds. A mount has one until
// it is rotated, and the list is what says whether a rotation has happened.
func (b *backend) pathIssuersList() *framework.Path {
	return &framework.Path{
		Pattern: "issuers/?$",

		DisplayAttrs: &framework.DisplayAttributes{
			OperationPrefix: operationPrefix + "-issuers",
			OperationVerb:   "list",
		},

		Callbacks: map[logical.Operation]framework.OperationFunc{
			logical.ListOperation: b.pathIssuersListRead,
		},

		HelpSynopsis:    pathIssuersListHelpSyn,
		HelpDescription: pathIssuersListHelpDesc,
	}
}

// pathIssuer reads one authority by identifier or by name. It is the only way
// to look at an authority other than the one the mount signs with.
func (b *backend) pathIssuer() *framework.Path {
	return &framework.Path{
		Pattern: "issuer/" + framework.GenericNameRegex("ref") + "$",

		DisplayAttrs: &framework.DisplayAttributes{
			OperationPrefix: operationPrefix + "-issuers",
			OperationVerb:   "read",
			OperationSuffix: "issuer",
		},

		Fields: map[string]*framework.FieldSchema{
			"ref": {
				Type:        framework.TypeString,
				Description: `Identifier or name of the issuer, or "default" for the one this mount signs with.`,
			},
		},

		Callbacks: map[logical.Operation]framework.OperationFunc{
			logical.ReadOperation: b.pathIssuerRead,
		},

		HelpSynopsis:    pathIssuerHelpSyn,
		HelpDescription: pathIssuerHelpDesc,
	}
}

func (b *backend) pathIssuersListRead(ctx context.Context, req *logical.Request, _ *framework.FieldData) (*logical.Response, error) {
	ids, err := req.Storage.List(ctx, issuerPrefix)
	if err != nil {
		return nil, err
	}

	return logical.ListResponse(ids), nil
}

func (b *backend) pathIssuerRead(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	ref := d.Get("ref").(string)

	id, issuer, err := b.issuerByRef(ctx, req.Storage, ref)
	if err != nil {
		return logical.ErrorResponse(err.Error()), logical.ErrInvalidRequest
	}
	if issuer == nil {
		return logical.ErrorResponse(errNoIssuer.Error()), logical.ErrInvalidRequest
	}

	chain, err := issuer.chain()
	if err != nil {
		return nil, err
	}
	der := make([][]byte, len(chain))
	for i, cert := range chain {
		der[i] = cert.Raw
	}

	defaultID, err := b.issuerID(ctx, req.Storage)
	if err != nil {
		return nil, err
	}

	return &logical.Response{Data: map[string]interface{}{
		"issuer_id":     id,
		"issuer_name":   issuer.Name,
		"certificate":   pemCertificate(issuer.Certificate),
		"ca_chain":      pemCertificates(der),
		"serial_number": formatSerial(issuer.Serial),
		"key_id":        issuer.KeyID,
		"created":       issuer.Created.Unix(),
		"is_default":    defaultID != "" && id == defaultID,
	}}, nil
}

const pathIssuersListHelpSyn = `List the issuers of this mount`

const pathIssuersListHelpDesc = `
Lists the identifiers of every authority the mount holds. The one requests to
issue use is called default, and its identifier is the one ca reports.
`

const pathIssuerHelpSyn = `Read one issuer of this mount`

const pathIssuerHelpDesc = `
Returns the certificate, the chain, the key identifier and the name of one
authority, addressed by its identifier, by the name an operator gave it, or by
the word default. is_default says whether certificates are signed with it.
`
