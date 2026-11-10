package pki

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
)

// pathRevoke marks a certificate as revoked. The revocation is recorded next to
// the certificate rather than in it: nothing needs to be reissued, the next CRL
// simply names the serial.
func (b *backend) pathRevoke() *framework.Path {
	return &framework.Path{
		Pattern: "revoke$",

		DisplayAttrs: &framework.DisplayAttributes{
			OperationPrefix: operationPrefix,
			OperationVerb:   "revoke",
		},

		Fields: map[string]*framework.FieldSchema{
			"serial_number": {
				Type:        framework.TypeString,
				Description: "Serial number of the certificate to revoke, in hexadecimal with or without colons.",
			},
		},

		Callbacks: map[logical.Operation]framework.OperationFunc{
			logical.UpdateOperation: b.pathRevokeWrite,
		},

		HelpSynopsis:    pathRevokeHelpSyn,
		HelpDescription: pathRevokeHelpDesc,
	}
}

func (b *backend) pathRevokeWrite(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	raw := strings.TrimSpace(d.Get("serial_number").(string))
	if raw == "" {
		return logical.ErrorResponse("serial_number is required"), logical.ErrInvalidRequest
	}

	serial, err := normalizeSerial(raw)
	if err != nil {
		return logical.ErrorResponse(err.Error()), logical.ErrInvalidRequest
	}

	b.caMu.Lock()
	defer b.caMu.Unlock()

	issuerID, err := b.issuerID(ctx, req.Storage)
	if err != nil {
		return nil, err
	}
	if issuerID == "" {
		return logical.ErrorResponse(errNoIssuer.Error()), logical.ErrInvalidRequest
	}

	record, err := b.certificateRecord(ctx, req.Storage, serial)
	if err != nil {
		return nil, err
	}
	if record == nil {
		return logical.ErrorResponse(fmt.Sprintf("serial number %s has not been issued by this mount", formatSerial(serial))), logical.ErrInvalidRequest
	}

	existing, err := b.revocationRecord(ctx, req.Storage, serial)
	if err != nil {
		return nil, err
	}
	if existing != nil {
		// Revoking twice is a retry, not a mistake: answer with the revocation
		// that is already in place and leave the CRL alone.
		return &logical.Response{
			Data: map[string]interface{}{
				"revocation_time":         existing.RevocationTime,
				"revocation_time_rfc3339": existing.RFC3339,
			},
			Warnings: []string{fmt.Sprintf("certificate with serial number %s is already revoked", formatSerial(serial))},
		}, nil
	}

	now := time.Now()
	revocation := &revocationEntry{
		IssuerID:       issuerID,
		RevocationTime: now.Unix(),
		RFC3339:        now.Format(time.RFC3339),
	}
	if !record.Expiration.IsZero() {
		revocation.Expiration = record.Expiration.Unix()
	}

	if err := putJSON(ctx, req.Storage, revokedPrefix+serial, revocation); err != nil {
		return nil, err
	}
	if err := b.markCRLDirty(ctx, req.Storage); err != nil {
		return nil, err
	}

	return &logical.Response{Data: map[string]interface{}{
		"revocation_time":         revocation.RevocationTime,
		"revocation_time_rfc3339": revocation.RFC3339,
	}}, nil
}

const pathRevokeHelpSyn = `Revoke a certificate the mount issued`

const pathRevokeHelpDesc = `
Marks a serial number as revoked. The certificate stays where it is; the
revocation appears in the next certificate revocation list. Revoking a serial
that is already revoked answers with the existing revocation and changes
nothing, so a retry is safe.
`
