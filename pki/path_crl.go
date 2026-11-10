package pki

import (
	"context"
	"crypto/rand"
	"fmt"
	"math/big"
	"net/http"
	"strconv"
	"time"

	"github.com/emmansun/gmsm/smx509"
	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
)

// pathCRL serves the certificate revocation list as JSON, with the list in a
// field. The raw forms are on crl/pem and crl/der.
func (b *backend) pathCRL() *framework.Path {
	return &framework.Path{
		Pattern: "crl$",

		DisplayAttrs: &framework.DisplayAttributes{
			OperationPrefix: operationPrefix,
			OperationVerb:   "read",
			OperationSuffix: "crl",
		},

		Callbacks: map[logical.Operation]framework.OperationFunc{
			logical.ReadOperation: b.pathCRLRead,
		},

		HelpSynopsis:    pathCRLHelpSyn,
		HelpDescription: pathCRLHelpDesc,
	}
}

func (b *backend) pathCRLPEM() *framework.Path {
	return &framework.Path{
		Pattern: "crl/pem$",

		DisplayAttrs: &framework.DisplayAttributes{
			OperationPrefix: operationPrefix,
			OperationVerb:   "read",
			OperationSuffix: "crl-pem",
		},

		Callbacks: map[logical.Operation]framework.OperationFunc{
			logical.ReadOperation: b.pathCRLPEMRead,
		},

		HelpSynopsis:    pathCRLHelpSyn,
		HelpDescription: pathCRLHelpDesc,
	}
}

func (b *backend) pathCRLDER() *framework.Path {
	return &framework.Path{
		Pattern: "crl/der$",

		DisplayAttrs: &framework.DisplayAttributes{
			OperationPrefix: operationPrefix,
			OperationVerb:   "read",
			OperationSuffix: "crl-der",
		},

		Callbacks: map[logical.Operation]framework.OperationFunc{
			logical.ReadOperation: b.pathCRLDERRead,
		},

		HelpSynopsis:    pathCRLHelpSyn,
		HelpDescription: pathCRLHelpDesc,
	}
}

// pathCRLRotate rebuilds the list with a new number and a fresh validity, which
// is what an operator reaches for when the cached one has gone stale.
func (b *backend) pathCRLRotate() *framework.Path {
	return &framework.Path{
		Pattern: "crl/rotate$",

		DisplayAttrs: &framework.DisplayAttributes{
			OperationPrefix: operationPrefix,
			OperationVerb:   "rotate",
			OperationSuffix: "crl",
		},

		Callbacks: map[logical.Operation]framework.OperationFunc{
			logical.UpdateOperation: b.pathCRLRotateWrite,
		},

		HelpSynopsis:    pathCRLRotateHelpSyn,
		HelpDescription: pathCRLRotateHelpDesc,
	}
}

func (b *backend) pathCRLRead(ctx context.Context, req *logical.Request, _ *framework.FieldData) (*logical.Response, error) {
	entry, resp, err := b.crlForRead(ctx, req.Storage)
	if resp != nil || err != nil {
		return resp, err
	}

	return &logical.Response{Data: map[string]interface{}{
		"certificate": pemCRL(entry.DER),
		"number":      entry.Number,
		"this_update": entry.ThisUpdate.Unix(),
		"next_update": entry.NextUpdate.Unix(),
	}}, nil
}

func (b *backend) pathCRLPEMRead(ctx context.Context, req *logical.Request, _ *framework.FieldData) (*logical.Response, error) {
	entry, resp, err := b.crlForRead(ctx, req.Storage)
	if resp != nil || err != nil {
		return resp, err
	}

	return &logical.Response{Data: map[string]interface{}{
		logical.HTTPContentType: "application/pem-encoding",
		logical.HTTPRawBody:     []byte(pemCRL(entry.DER)),
		logical.HTTPStatusCode:  http.StatusOK,
	}}, nil
}

func (b *backend) pathCRLDERRead(ctx context.Context, req *logical.Request, _ *framework.FieldData) (*logical.Response, error) {
	entry, resp, err := b.crlForRead(ctx, req.Storage)
	if resp != nil || err != nil {
		return resp, err
	}

	return &logical.Response{Data: map[string]interface{}{
		logical.HTTPContentType: "application/pkix-crl",
		logical.HTTPRawBody:     entry.DER,
		logical.HTTPStatusCode:  http.StatusOK,
	}}, nil
}

func (b *backend) pathCRLRotateWrite(ctx context.Context, req *logical.Request, _ *framework.FieldData) (*logical.Response, error) {
	b.caMu.Lock()
	defer b.caMu.Unlock()

	issuer, err := b.issuer(ctx, req.Storage)
	if err != nil {
		return nil, err
	}
	if issuer == nil {
		return logical.ErrorResponse(errNoIssuer.Error()), logical.ErrInvalidRequest
	}

	previous, err := b.currentCRL(ctx, req.Storage, issuer.ID)
	if err != nil {
		return nil, err
	}

	entry, err := b.buildCRL(ctx, req.Storage, issuer, previous)
	if err != nil {
		return nil, err
	}

	return &logical.Response{Data: map[string]interface{}{
		"number":      entry.Number,
		"this_update": entry.ThisUpdate.Unix(),
		"next_update": entry.NextUpdate.Unix(),
	}}, nil
}

// crlForRead answers with a usable list, rebuilding the cached one when it is
// missing, stale or marks a revocation that arrived since it was signed.
func (b *backend) crlForRead(ctx context.Context, s logical.Storage) (*crlEntry, *logical.Response, error) {
	b.caMu.Lock()
	defer b.caMu.Unlock()

	issuer, err := b.issuer(ctx, s)
	if err != nil {
		return nil, nil, err
	}
	if issuer == nil {
		return nil, logical.ErrorResponse(errNoIssuer.Error()), logical.ErrInvalidRequest
	}

	cached, err := b.currentCRL(ctx, s, issuer.ID)
	if err != nil {
		return nil, nil, err
	}
	if cached != nil && !cached.Dirty && len(cached.DER) > 0 && time.Now().Before(cached.NextUpdate) {
		return cached, nil, nil
	}

	entry, err := b.buildCRL(ctx, s, issuer, cached)
	if err != nil {
		return nil, nil, err
	}

	return entry, nil, nil
}

// markCRLDirty records that a revocation arrived after the cached list of this
// issuer was signed. The list itself is rebuilt on the next read, so a revoke
// does not pay for signing it.
func (b *backend) markCRLDirty(ctx context.Context, s logical.Storage, issuerID string) error {
	entry, err := b.currentCRL(ctx, s, issuerID)
	if err != nil || entry == nil || entry.Dirty {
		return err
	}

	entry.Dirty = true
	return putJSON(ctx, s, crlPrefix+issuerID, entry)
}

// buildCRL signs a new list from every revocation of this issuer and caches it.
// The number only ever grows, so a client can tell two lists apart; each issuer
// counts on its own, which keeps the numbering of one from moving the other.
func (b *backend) buildCRL(ctx context.Context, s logical.Storage, issuer *issuerEntry, previous *crlEntry) (*crlEntry, error) {
	if issuer.ID == "" {
		return nil, fmt.Errorf("the issuer record has no identifier")
	}

	number := 1
	if previous != nil && previous.Number != "" {
		parsed, err := strconv.Atoi(previous.Number)
		if err != nil {
			return nil, fmt.Errorf("the number of the cached CRL, %q, is not a number: %w", previous.Number, err)
		}
		number = parsed + 1
	}

	entries, err := b.crlEntries(ctx, s, issuer.ID)
	if err != nil {
		return nil, err
	}

	cert, err := issuer.certificate()
	if err != nil {
		return nil, err
	}
	signer, err := b.issuerSigner(ctx, s, issuer)
	if err != nil {
		return nil, err
	}

	now := time.Now()
	template := &smx509.RevocationList{
		Number:                    big.NewInt(int64(number)),
		ThisUpdate:                now,
		NextUpdate:                now.Add(crlValidity),
		RevokedCertificateEntries: entries,
		SignatureAlgorithm:        smx509.SM2WithSM3,
	}

	der, err := smx509.CreateRevocationList(rand.Reader, template, cert, signer)
	if err != nil {
		return nil, fmt.Errorf("could not create the certificate revocation list: %w", err)
	}

	entry := &crlEntry{
		Number:     strconv.Itoa(number),
		ThisUpdate: now,
		NextUpdate: template.NextUpdate,
		DER:        der,
	}
	if err := putJSON(ctx, s, crlPrefix+issuer.ID, entry); err != nil {
		return nil, err
	}

	return entry, nil
}

// crlEntries turns the revocation records of one issuer into entries of its
// list. A revocation belongs to the authority that signed the certificate, so a
// merged list would name serials its own signature says nothing about.
func (b *backend) crlEntries(ctx context.Context, s logical.Storage, issuerID string) ([]smx509.RevocationListEntry, error) {
	names, err := s.List(ctx, revokedPrefix)
	if err != nil {
		return nil, err
	}

	entries := make([]smx509.RevocationListEntry, 0, len(names))
	for _, name := range names {
		record, err := b.revocationRecord(ctx, s, name)
		if err != nil {
			return nil, err
		}
		if record == nil || record.IssuerID != issuerID {
			continue
		}

		serial, ok := new(big.Int).SetString(name, 16)
		if !ok {
			return nil, fmt.Errorf("the storage key of a revocation, %q, is not a serial number", name)
		}

		entries = append(entries, smx509.RevocationListEntry{
			SerialNumber:   serial,
			RevocationTime: time.Unix(record.RevocationTime, 0),
		})
	}

	return entries, nil
}

const pathCRLHelpSyn = `Read the certificate revocation list`

const pathCRLHelpDesc = `
The certificate revocation list of the mount, signed by its authority. The
signed list is kept as it is and rebuilt when a certificate has been revoked
since or when it has expired, so two reads of an unchanged list answer with the
same bytes. Use crl/rotate to force a new list with a new number.
`

const pathCRLRotateHelpSyn = `Rebuild the certificate revocation list`

const pathCRLRotateHelpDesc = `
Signs a new list with the next number and a fresh validity, whether or not
anything changed. A client that watches the number sees the rotation.
`
