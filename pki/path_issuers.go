package pki

import (
	"context"
	"fmt"
	"time"

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

// pathIssuer reads one authority by identifier or by name, and retires it. It
// is the only way to look at, or remove, an authority other than the one the
// mount signs with.
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
			logical.ReadOperation:   b.pathIssuerRead,
			logical.DeleteOperation: b.pathIssuerDeleteWrite,
		},

		HelpSynopsis:    pathIssuerHelpSyn,
		HelpDescription: pathIssuerHelpDesc,
	}
}

// pathIssuerDefault makes one authority the one this mount signs with. After a
// rotation it is what returns the mount to the authority it replaced, without
// deleting either of them.
func (b *backend) pathIssuerDefault() *framework.Path {
	return &framework.Path{
		Pattern: "issuer/" + framework.GenericNameRegex("ref") + "/default$",

		DisplayAttrs: &framework.DisplayAttributes{
			OperationPrefix: operationPrefix + "-issuers",
			OperationVerb:   "set",
			OperationSuffix: "default-issuer",
		},

		Fields: map[string]*framework.FieldSchema{
			"ref": {
				Type:        framework.TypeString,
				Description: `Identifier or name of the issuer to sign with.`,
			},
		},

		Callbacks: map[logical.Operation]framework.OperationFunc{
			logical.UpdateOperation: b.pathIssuerDefaultWrite,
		},

		HelpSynopsis:    pathIssuerDefaultHelpSyn,
		HelpDescription: pathIssuerDefaultHelpDesc,
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

func (b *backend) pathIssuerDefaultWrite(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	ref := d.Get("ref").(string)

	b.caMu.Lock()
	defer b.caMu.Unlock()

	id, issuer, err := b.issuerByRef(ctx, req.Storage, ref)
	if err != nil {
		return logical.ErrorResponse(err.Error()), logical.ErrInvalidRequest
	}
	if issuer == nil {
		return logical.ErrorResponse(errNoIssuer.Error()), logical.ErrInvalidRequest
	}

	current, err := b.issuerID(ctx, req.Storage)
	if err != nil {
		return nil, err
	}

	data := map[string]interface{}{
		"issuer_id":   id,
		"issuer_name": issuer.Name,
		"is_default":  true,
	}
	if current == id {
		return &logical.Response{
			Data:     data,
			Warnings: []string{fmt.Sprintf("issuer %s already signs in this mount", issuerLabel(id, issuer))},
		}, nil
	}

	if err := b.setIssuerDefault(ctx, req.Storage, id); err != nil {
		return nil, err
	}

	return &logical.Response{Data: data}, nil
}

// pathIssuerDeleteWrite retires one authority. A certificate that a client can
// still present keeps the authority alive, because retiring it takes the list
// that reports its revocation with it.
func (b *backend) pathIssuerDeleteWrite(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	ref := d.Get("ref").(string)

	b.caMu.Lock()
	defer b.caMu.Unlock()

	id, issuer, err := b.issuerByRef(ctx, req.Storage, ref)
	if err != nil {
		return logical.ErrorResponse(err.Error()), logical.ErrInvalidRequest
	}
	if issuer == nil {
		return logical.ErrorResponse(errNoIssuer.Error()), logical.ErrInvalidRequest
	}

	live, latest, err := b.liveCertificates(ctx, req.Storage, id)
	if err != nil {
		return nil, err
	}
	if live > 0 {
		last := latest.UTC().Format(time.RFC3339)
		message := fmt.Sprintf("issuer %s still has certificates that have not expired, the last until %s; retire it once they have", issuerLabel(id, issuer), last)
		if live == 1 {
			message = fmt.Sprintf("issuer %s still has a certificate that has not expired, valid until %s; retire it once it has", issuerLabel(id, issuer), last)
		}
		return logical.ErrorResponse(message), logical.ErrInvalidRequest
	}

	certificates, revocations, err := b.retireIssuer(ctx, req.Storage, issuer)
	if err != nil {
		return nil, err
	}

	defaultID, err := b.issuerID(ctx, req.Storage)
	if err != nil {
		return nil, err
	}

	return &logical.Response{Data: map[string]interface{}{
		"issuer_id":            id,
		"certificates_removed": certificates,
		"revocations_removed":  revocations,
		"default_issuer_id":    defaultID,
	}}, nil
}

// issuerLabel names an authority in a message: the name an operator gave it
// when there is one, and its identifier otherwise.
func issuerLabel(id string, issuer *issuerEntry) string {
	if issuer != nil && issuer.Name != "" {
		return fmt.Sprintf("%q", issuer.Name)
	}

	return fmt.Sprintf("%q", id)
}

const pathIssuersListHelpSyn = `List the issuers of this mount`

const pathIssuersListHelpDesc = `
Lists the identifiers of every authority the mount holds. The one requests to
issue use is called default, and its identifier is the one ca reports.
`

const pathIssuerHelpSyn = `Read or retire one issuer of this mount`

const pathIssuerHelpDesc = `
Returns the certificate, the chain, the key identifier and the name of one
authority, addressed by its identifier, by the name an operator gave it, or by
the word default; is_default says whether certificates are signed with it.
DELETE retires the authority: its key, the certificates it issued, the
revocations it recorded and its list go with it. An authority that still has
unexpired certificates is refused, because retiring it would take the list that
reports their revocations with it.
`

const pathIssuerDefaultHelpSyn = `Sign with one of the issuers of this mount`

const pathIssuerDefaultHelpDesc = `
Makes the named authority the one that issues and signs from now on. Both
remain in the mount, which is how a rotation is undone without keeping two
mounts around.
`
