package pki

import (
	"context"
	"time"

	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
)

// defaultSafetyBuffer keeps tidy away from certificates that are still in use
// somewhere with a slightly wrong clock.
const defaultSafetyBuffer = 72 * time.Hour

// pathTidy removes state that can no longer matter. It runs synchronously: the
// mount is small enough that an operator would rather have the answer than a
// background job.
func (b *backend) pathTidy() *framework.Path {
	return &framework.Path{
		Pattern: "tidy$",

		DisplayAttrs: &framework.DisplayAttributes{
			OperationPrefix: operationPrefix,
			OperationVerb:   "tidy",
		},

		Fields: map[string]*framework.FieldSchema{
			"safety_buffer": {
				Type:        framework.TypeDurationSecond,
				Default:     int(defaultSafetyBuffer / time.Second),
				Description: "How long past the expiration of a certificate it is kept.",
			},
			"tidy_cert_store": {
				Type:        framework.TypeBool,
				Default:     false,
				Description: "Remove the records of certificates that expired longer than the safety buffer ago.",
			},
			"tidy_revoked_certs": {
				Type:        framework.TypeBool,
				Default:     true,
				Description: "Remove the revocations of certificates that expired longer than the safety buffer ago.",
			},
		},

		Callbacks: map[logical.Operation]framework.OperationFunc{
			logical.UpdateOperation: b.pathTidyWrite,
		},

		HelpSynopsis:    pathTidyHelpSyn,
		HelpDescription: pathTidyHelpDesc,
	}
}

func (b *backend) pathTidyWrite(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	cutoff := time.Now().Add(-time.Duration(d.Get("safety_buffer").(int)) * time.Second)

	b.caMu.Lock()
	defer b.caMu.Unlock()

	var (
		certificatesRemoved int
		revocationsRemoved  int
	)

	if d.Get("tidy_cert_store").(bool) {
		removed, err := b.deleteExpiredCertificates(ctx, req.Storage, cutoff)
		if err != nil {
			return nil, err
		}
		certificatesRemoved = removed
	}

	if d.Get("tidy_revoked_certs").(bool) {
		removed, touched, err := b.deleteExpiredRevocations(ctx, req.Storage, cutoff)
		if err != nil {
			return nil, err
		}
		revocationsRemoved = removed

		// Only the lists that lost an entry need rebuilding, which is why the
		// scan reports the issuers it touched rather than waking every one of
		// them up.
		for issuerID := range touched {
			if err := b.markCRLDirty(ctx, req.Storage, issuerID); err != nil {
				return nil, err
			}
		}
	}

	return &logical.Response{Data: map[string]interface{}{
		"certificates_removed": certificatesRemoved,
		"revocations_removed":  revocationsRemoved,
	}}, nil
}

func (b *backend) deleteExpiredCertificates(ctx context.Context, s logical.Storage, cutoff time.Time) (int, error) {
	serials, err := s.List(ctx, certPrefix)
	if err != nil {
		return 0, err
	}

	removed := 0
	for _, serial := range serials {
		record, err := b.certificateRecord(ctx, s, serial)
		if err != nil {
			return removed, err
		}
		if record == nil || record.Expiration.IsZero() || record.Expiration.After(cutoff) {
			continue
		}

		if err := s.Delete(ctx, certPrefix+serial); err != nil {
			return removed, err
		}
		removed++
	}

	return removed, nil
}

// deleteExpiredRevocations drops a revocation once the certificate it names has
// been expired for longer than the safety buffer. A revocation without an
// expiration is kept: the certificate behind it may still be valid. It answers
// with the issuers whose lists lost an entry.
func (b *backend) deleteExpiredRevocations(ctx context.Context, s logical.Storage, cutoff time.Time) (int, map[string]struct{}, error) {
	serials, err := s.List(ctx, revokedPrefix)
	if err != nil {
		return 0, nil, err
	}

	removed := 0
	touched := map[string]struct{}{}
	for _, serial := range serials {
		record, err := b.revocationRecord(ctx, s, serial)
		if err != nil {
			return removed, touched, err
		}
		if record == nil || record.Expiration == 0 || time.Unix(record.Expiration, 0).After(cutoff) {
			continue
		}

		if err := s.Delete(ctx, revokedPrefix+serial); err != nil {
			return removed, touched, err
		}
		removed++
		if record.IssuerID != "" {
			touched[record.IssuerID] = struct{}{}
		}
	}

	return removed, touched, nil
}

const pathTidyHelpSyn = `Remove the state of certificates that expired long ago`

const pathTidyHelpDesc = `
Drops the records of certificates that expired longer than the safety buffer
ago, and the revocations that name them, so the mount does not grow forever. A
revocation whose certificate is still valid, or whose expiration is not known,
is kept. The certificate revocation list is rebuilt on the next read.
`
