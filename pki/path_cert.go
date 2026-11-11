package pki

import (
	"context"

	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
)

// serialPattern accepts the serial in every spelling a caller may have, with
// or without separators and in either case.
const serialPattern = `(?P<serial>[0-9A-Fa-f:\-]+)`

// pathCert reads back one certificate the mount issued.
func (b *backend) pathCert() *framework.Path {
	return &framework.Path{
		Pattern: "cert/" + serialPattern + "$",

		DisplayAttrs: &framework.DisplayAttributes{
			OperationPrefix: operationPrefix,
			OperationVerb:   "read",
			OperationSuffix: "certificate",
		},

		Fields: map[string]*framework.FieldSchema{
			"serial": {
				Type:        framework.TypeString,
				Description: "Serial number of the certificate, in hexadecimal with or without colons.",
			},
		},

		Callbacks: map[logical.Operation]framework.OperationFunc{
			logical.ReadOperation: b.pathCertRead,
		},

		HelpSynopsis:    pathCertHelpSyn,
		HelpDescription: pathCertHelpDesc,
	}
}

func (b *backend) pathCertRead(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	serial, err := normalizeSerial(d.Get("serial").(string))
	if err != nil {
		return logical.ErrorResponse(err.Error()), logical.ErrInvalidRequest
	}

	record, err := b.certificateRecord(ctx, req.Storage, serial)
	if err != nil {
		return nil, err
	}
	if record == nil {
		return nil, nil
	}

	data := map[string]interface{}{
		"serial_number": formatSerial(serial),
		"role":          record.Role,
		"issued":        record.Issued.Unix(),
		"expiration":    record.Expiration.Unix(),
	}
	if record.IssuerID != "" {
		data["issuer_id"] = record.IssuerID
	}
	if len(record.Certificate) > 0 {
		data["certificate"] = pemCertificate(record.Certificate)
	}

	revocation, err := b.revocationRecord(ctx, req.Storage, serial)
	if err != nil {
		return nil, err
	}
	if revocation != nil {
		data["revocation_time"] = revocation.RevocationTime
		data["revocation_time_rfc3339"] = revocation.RFC3339
		data["revocation_reason"] = revocation.Reason
	}

	return &logical.Response{Data: data}, nil
}

// pathCertsList lists the serials the mount issued and kept.
func (b *backend) pathCertsList() *framework.Path {
	return &framework.Path{
		Pattern: "certs/?$",

		DisplayAttrs: &framework.DisplayAttributes{
			OperationPrefix: operationPrefix + "-certs",
			OperationVerb:   "list",
		},

		Callbacks: map[logical.Operation]framework.OperationFunc{
			logical.ListOperation: b.pathCertsListRead,
		},

		HelpSynopsis:    pathCertsListHelpSyn,
		HelpDescription: pathCertsListHelpDesc,
	}
}

func (b *backend) pathCertsListRead(ctx context.Context, req *logical.Request, _ *framework.FieldData) (*logical.Response, error) {
	serials, err := req.Storage.List(ctx, certPrefix)
	if err != nil {
		return nil, err
	}

	display := make([]string, len(serials))
	for i, serial := range serials {
		display[i] = formatSerial(serial)
	}

	return logical.ListResponse(display), nil
}

// pathCertsRevoked lists the serials the mount revoked, whichever authority
// signed them. It is the other half of what certs answers: a reconciliation
// against a database of subscribers needs both, because a serial that is
// revoked but never listed is a certificate nobody looked for.
func (b *backend) pathCertsRevoked() *framework.Path {
	return &framework.Path{
		Pattern: "certs/revoked$",

		DisplayAttrs: &framework.DisplayAttributes{
			OperationPrefix: operationPrefix + "-certs",
			OperationVerb:   "list",
			OperationSuffix: "revoked",
		},

		Callbacks: map[logical.Operation]framework.OperationFunc{
			logical.ListOperation: b.pathCertsRevokedRead,
		},

		HelpSynopsis:    pathCertsRevokedHelpSyn,
		HelpDescription: pathCertsRevokedHelpDesc,
	}
}

func (b *backend) pathCertsRevokedRead(ctx context.Context, req *logical.Request, _ *framework.FieldData) (*logical.Response, error) {
	serials, err := req.Storage.List(ctx, revokedPrefix)
	if err != nil {
		return nil, err
	}

	display := make([]string, len(serials))
	for i, serial := range serials {
		display[i] = formatSerial(serial)
	}

	return logical.ListResponse(display), nil
}

const pathCertHelpSyn = `Read a certificate the mount issued`

const pathCertHelpDesc = `
Returns the certificate for a serial number, together with when it was issued,
when it expires and whether it was revoked. The certificate is left out of the
record for a role that asked for no_store; such a certificate is only known by
its metadata and its revocation.
`

const pathCertsListHelpSyn = `List the serials of the certificates the mount issued`

const pathCertsListHelpDesc = `
Lists the serial number of every certificate the mount kept, in the
colon-separated form that cert/:serial accepts.
`

const pathCertsRevokedHelpSyn = `List the serials the mount revoked`

const pathCertsRevokedHelpDesc = `
Lists the serial number of every certificate that was revoked, in the
colon-separated form that cert/:serial accepts, including the serials of the
certificates the mount did not keep.
`
