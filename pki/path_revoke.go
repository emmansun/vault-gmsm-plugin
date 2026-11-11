package pki

import (
	"context"
	"errors"
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
			"certificate": {
				Type:        framework.TypeString,
				Description: "PEM certificate to revoke, as an alternative to serial_number. The serial is taken from it.",
			},
			"revocation_reason": {
				Type:        framework.TypeInt,
				Default:     0,
				Description: "Reason code of RFC 5280 for the revocation: 0 unspecified, 1 keyCompromise, 2 cACompromise, 3 affiliationChanged, 4 superseded, 5 cessationOfOperation, 6 certificateHold, 8 removeFromCRL, 9 privilegeWithdrawn, 10 aACompromise.",
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
	serial, err := serialToRevoke(d)
	if err != nil {
		return logical.ErrorResponse(err.Error()), logical.ErrInvalidRequest
	}

	reason := d.Get("revocation_reason").(int)
	if err := checkRevocationReason(reason); err != nil {
		return logical.ErrorResponse(err.Error()), logical.ErrInvalidRequest
	}

	b.caMu.Lock()
	defer b.caMu.Unlock()

	record, err := b.certificateRecord(ctx, req.Storage, serial)
	if err != nil {
		return nil, err
	}
	if record == nil {
		return logical.ErrorResponse(fmt.Sprintf("serial number %s has not been issued by this mount", formatSerial(serial))), logical.ErrInvalidRequest
	}

	// The revocation belongs to the authority that signed the certificate, so it
	// reaches that authority's list even after the mount has moved on. A record
	// written before certificates named their issuer belongs to the one that was
	// signing when it was written.
	issuerID := record.IssuerID
	if issuerID == "" {
		issuerID, err = b.legacyIssuerID(ctx, req.Storage)
		if err != nil {
			return nil, err
		}
	}
	if issuerID == "" {
		return logical.ErrorResponse(errNoIssuer.Error()), logical.ErrInvalidRequest
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
				"revocation_reason":       existing.Reason,
			},
			Warnings: []string{fmt.Sprintf("certificate with serial number %s is already revoked", formatSerial(serial))},
		}, nil
	}

	now := time.Now()
	revocation := &revocationEntry{
		IssuerID:       issuerID,
		RevocationTime: now.Unix(),
		RFC3339:        now.Format(time.RFC3339),
		Reason:         reason,
	}
	if !record.Expiration.IsZero() {
		revocation.Expiration = record.Expiration.Unix()
	}

	if err := putJSON(ctx, req.Storage, revokedPrefix+serial, revocation); err != nil {
		return nil, err
	}
	if err := b.markCRLDirty(ctx, req.Storage, issuerID); err != nil {
		return nil, err
	}

	return &logical.Response{Data: map[string]interface{}{
		"revocation_time":         revocation.RevocationTime,
		"revocation_time_rfc3339": revocation.RFC3339,
		"revocation_reason":       revocation.Reason,
	}}, nil
}

// serialToRevoke reads the serial to revoke from whichever of the two forms the
// caller supplied. A caller that supplies both is refused rather than guessed
// at: the two may name different certificates.
func serialToRevoke(d *framework.FieldData) (string, error) {
	rawSerial := strings.TrimSpace(d.Get("serial_number").(string))
	rawCertificate := strings.TrimSpace(d.Get("certificate").(string))

	switch {
	case rawSerial != "" && rawCertificate != "":
		return "", errors.New("supply serial_number or certificate, not both")
	case rawSerial != "":
		return normalizeSerial(rawSerial)
	case rawCertificate == "":
		return "", errors.New("serial_number or certificate is required")
	}

	certs, err := parseCertificates(rawCertificate)
	if err != nil {
		return "", err
	}

	return serialHex(certs[0].SerialNumber), nil
}

// checkRevocationReason refuses a code that RFC 5280 does not define. Reason 7
// was never assigned, and a list that carries it is read differently by every
// client that meets one.
func checkRevocationReason(code int) error {
	switch code {
	case 0, 1, 2, 3, 4, 5, 6, 8, 9, 10:
		return nil
	default:
		return fmt.Errorf("revocation_reason %d is not a reason code of RFC 5280", code)
	}
}

const pathRevokeHelpSyn = `Revoke a certificate the mount issued`

const pathRevokeHelpDesc = `
Marks a certificate as revoked, by serial number or by the certificate itself.
The certificate stays where it is; the revocation appears in the next
certificate revocation list, together with the reason it was given.

Revoking a serial that is already revoked answers with the existing revocation
and changes nothing, so a retry is safe. The reason of the first revocation is
the one that stays.
`
