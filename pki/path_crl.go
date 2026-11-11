package pki

import (
	"context"
	"crypto/rand"
	"crypto/x509/pkix"
	"encoding/asn1"
	"fmt"
	"math/big"
	"net/http"
	"strconv"
	"time"

	"github.com/emmansun/gmsm/smx509"
	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
)

// oidExtensionDeltaCRLIndicator is the extension by which a list says which full
// list it carries the changes of. It is critical: a client that cannot read it
// must not take the entries as a complete list.
var oidExtensionDeltaCRLIndicator = asn1.ObjectIdentifier{2, 5, 29, 27}

// crlReadPath builds one of the paths a list is served on: the JSON that reports
// its number and times, or the raw body of the list itself. Each of them exists
// for the list of the mount and for the list of one authority named in the path.
func crlReadPath(pattern, prefix, suffix string, handler framework.OperationFunc, fields map[string]*framework.FieldSchema, synopsis, description string) *framework.Path {
	return &framework.Path{
		Pattern: pattern,

		DisplayAttrs: &framework.DisplayAttributes{
			OperationPrefix: prefix,
			OperationVerb:   "read",
			OperationSuffix: suffix,
		},

		Fields: fields,

		Callbacks: map[logical.Operation]framework.OperationFunc{
			logical.ReadOperation: handler,
		},

		HelpSynopsis:    synopsis,
		HelpDescription: description,
	}
}

// crlRotatePath is the counterpart that signs a new list whether or not anything
// changed, which is what an operator reaches for when the cached one has gone
// stale.
func crlRotatePath(pattern, prefix, suffix string, handler framework.OperationFunc, fields map[string]*framework.FieldSchema, synopsis, description string) *framework.Path {
	return &framework.Path{
		Pattern: pattern,

		DisplayAttrs: &framework.DisplayAttributes{
			OperationPrefix: prefix,
			OperationVerb:   "rotate",
			OperationSuffix: suffix,
		},

		Fields: fields,

		Callbacks: map[logical.Operation]framework.OperationFunc{
			logical.UpdateOperation: handler,
		},

		HelpSynopsis:    synopsis,
		HelpDescription: description,
	}
}

// pathCRL serves the certificate revocation list as JSON, with the list in a
// field. The raw forms are on crl/pem and crl/der.
func (b *backend) pathCRL() *framework.Path {
	return crlReadPath("crl$", operationPrefix, "crl", b.pathCRLRead, nil, pathCRLHelpSyn, pathCRLHelpDesc)
}

func (b *backend) pathCRLPEM() *framework.Path {
	return crlReadPath("crl/pem$", operationPrefix, "crl-pem", b.pathCRLPEMRead, nil, pathCRLHelpSyn, pathCRLHelpDesc)
}

func (b *backend) pathCRLDER() *framework.Path {
	return crlReadPath("crl/der$", operationPrefix, "crl-der", b.pathCRLDERRead, nil, pathCRLHelpSyn, pathCRLHelpDesc)
}

// pathCRLRotate rebuilds the list with a new number and a fresh validity.
func (b *backend) pathCRLRotate() *framework.Path {
	return crlRotatePath("crl/rotate$", operationPrefix, "crl", b.pathCRLRotateWrite, nil,
		pathCRLRotateHelpSyn, pathCRLRotateHelpDesc)
}

// pathDeltaCRL serves the changes since the full list, which is what a client
// that already holds that list fetches to catch up. The forms and the paths
// mirror the full list.
func (b *backend) pathDeltaCRL() *framework.Path {
	return crlReadPath("crl/delta$", operationPrefix, "crl-delta", b.pathDeltaCRLRead, nil,
		pathDeltaCRLHelpSyn, pathDeltaCRLHelpDesc)
}

func (b *backend) pathDeltaCRLPEM() *framework.Path {
	return crlReadPath("crl/delta/pem$", operationPrefix, "crl-delta-pem", b.pathDeltaCRLPEMRead, nil,
		pathDeltaCRLHelpSyn, pathDeltaCRLHelpDesc)
}

func (b *backend) pathDeltaCRLDER() *framework.Path {
	return crlReadPath("crl/delta/der$", operationPrefix, "crl-delta-der", b.pathDeltaCRLDERRead, nil,
		pathDeltaCRLHelpSyn, pathDeltaCRLHelpDesc)
}

func (b *backend) pathDeltaCRLRotate() *framework.Path {
	return crlRotatePath("crl/rotate-delta$", operationPrefix, "crl-delta", b.pathDeltaCRLRotateWrite, nil,
		pathDeltaCRLRotateHelpSyn, pathDeltaCRLRotateHelpDesc)
}

// pathIssuerCRL serves the list of one authority, addressed the way issuer/:ref
// is: by identifier, by name, or as default. A rotated mount needs it, because
// the certificates of the authority it replaced point at a list of their own,
// and crl answers only for the one that signs now.
func (b *backend) pathIssuerCRL() *framework.Path {
	return crlReadPath("issuer/"+framework.GenericNameRegex("ref")+"/crl$", operationPrefix+"-issuers",
		"issuer-crl", b.pathIssuerCRLRead, issuerCRLFields(), pathIssuerCRLHelpSyn, pathIssuerCRLHelpDesc)
}

func (b *backend) pathIssuerCRLPEM() *framework.Path {
	return crlReadPath("issuer/"+framework.GenericNameRegex("ref")+"/crl/pem$", operationPrefix+"-issuers",
		"issuer-crl-pem", b.pathIssuerCRLPEMRead, issuerCRLFields(), pathIssuerCRLHelpSyn, pathIssuerCRLHelpDesc)
}

func (b *backend) pathIssuerCRLDER() *framework.Path {
	return crlReadPath("issuer/"+framework.GenericNameRegex("ref")+"/crl/der$", operationPrefix+"-issuers",
		"issuer-crl-der", b.pathIssuerCRLDERRead, issuerCRLFields(), pathIssuerCRLHelpSyn, pathIssuerCRLHelpDesc)
}

// pathIssuerCRLRotate is the same forced rebuild for one authority: it signs a
// new list of that issuer under the next number of that issuer.
func (b *backend) pathIssuerCRLRotate() *framework.Path {
	return crlRotatePath("issuer/"+framework.GenericNameRegex("ref")+"/crl/rotate$", operationPrefix+"-issuers",
		"issuer-crl", b.pathIssuerCRLRotateWrite, issuerCRLFields(), pathIssuerCRLRotateHelpSyn, pathIssuerCRLRotateHelpDesc)
}

func (b *backend) pathIssuerDeltaCRL() *framework.Path {
	return crlReadPath("issuer/"+framework.GenericNameRegex("ref")+"/crl/delta$", operationPrefix+"-issuers",
		"issuer-crl-delta", b.pathIssuerDeltaCRLRead, issuerCRLFields(), pathIssuerDeltaCRLHelpSyn, pathIssuerDeltaCRLHelpDesc)
}

func (b *backend) pathIssuerDeltaCRLPEM() *framework.Path {
	return crlReadPath("issuer/"+framework.GenericNameRegex("ref")+"/crl/delta/pem$", operationPrefix+"-issuers",
		"issuer-crl-delta-pem", b.pathIssuerDeltaCRLPEMRead, issuerCRLFields(), pathIssuerDeltaCRLHelpSyn, pathIssuerDeltaCRLHelpDesc)
}

func (b *backend) pathIssuerDeltaCRLDER() *framework.Path {
	return crlReadPath("issuer/"+framework.GenericNameRegex("ref")+"/crl/delta/der$", operationPrefix+"-issuers",
		"issuer-crl-delta-der", b.pathIssuerDeltaCRLDERRead, issuerCRLFields(), pathIssuerDeltaCRLHelpSyn, pathIssuerDeltaCRLHelpDesc)
}

func (b *backend) pathIssuerDeltaCRLRotate() *framework.Path {
	return crlRotatePath("issuer/"+framework.GenericNameRegex("ref")+"/crl/rotate-delta$", operationPrefix+"-issuers",
		"issuer-crl-delta", b.pathIssuerDeltaCRLRotateWrite, issuerCRLFields(),
		pathIssuerDeltaCRLRotateHelpSyn, pathIssuerDeltaCRLRotateHelpDesc)
}

// issuerCRLFields is the ref of every path that serves a list of one authority.
func issuerCRLFields() map[string]*framework.FieldSchema {
	return map[string]*framework.FieldSchema{"ref": issuerRefField()}
}

func (b *backend) pathCRLRead(ctx context.Context, req *logical.Request, _ *framework.FieldData) (*logical.Response, error) {
	return b.crlJSON(ctx, req.Storage, issuerRefDefault, false)
}

func (b *backend) pathCRLPEMRead(ctx context.Context, req *logical.Request, _ *framework.FieldData) (*logical.Response, error) {
	return b.crlPEM(ctx, req.Storage, issuerRefDefault, false)
}

func (b *backend) pathCRLDERRead(ctx context.Context, req *logical.Request, _ *framework.FieldData) (*logical.Response, error) {
	return b.crlDER(ctx, req.Storage, issuerRefDefault, false)
}

func (b *backend) pathCRLRotateWrite(ctx context.Context, req *logical.Request, _ *framework.FieldData) (*logical.Response, error) {
	return b.crlRotate(ctx, req.Storage, issuerRefDefault, false)
}

func (b *backend) pathDeltaCRLRead(ctx context.Context, req *logical.Request, _ *framework.FieldData) (*logical.Response, error) {
	return b.crlJSON(ctx, req.Storage, issuerRefDefault, true)
}

func (b *backend) pathDeltaCRLPEMRead(ctx context.Context, req *logical.Request, _ *framework.FieldData) (*logical.Response, error) {
	return b.crlPEM(ctx, req.Storage, issuerRefDefault, true)
}

func (b *backend) pathDeltaCRLDERRead(ctx context.Context, req *logical.Request, _ *framework.FieldData) (*logical.Response, error) {
	return b.crlDER(ctx, req.Storage, issuerRefDefault, true)
}

func (b *backend) pathDeltaCRLRotateWrite(ctx context.Context, req *logical.Request, _ *framework.FieldData) (*logical.Response, error) {
	return b.crlRotate(ctx, req.Storage, issuerRefDefault, true)
}

// The handlers below answer the same way for the authority the path names,
// which is what a mount that has rotated needs: the certificates it signed keep
// pointing at a list that belongs to them.
func (b *backend) pathIssuerCRLRead(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	return b.crlJSON(ctx, req.Storage, d.Get("ref").(string), false)
}

func (b *backend) pathIssuerCRLPEMRead(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	return b.crlPEM(ctx, req.Storage, d.Get("ref").(string), false)
}

func (b *backend) pathIssuerCRLDERRead(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	return b.crlDER(ctx, req.Storage, d.Get("ref").(string), false)
}

func (b *backend) pathIssuerCRLRotateWrite(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	return b.crlRotate(ctx, req.Storage, d.Get("ref").(string), false)
}

func (b *backend) pathIssuerDeltaCRLRead(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	return b.crlJSON(ctx, req.Storage, d.Get("ref").(string), true)
}

func (b *backend) pathIssuerDeltaCRLPEMRead(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	return b.crlPEM(ctx, req.Storage, d.Get("ref").(string), true)
}

func (b *backend) pathIssuerDeltaCRLDERRead(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	return b.crlDER(ctx, req.Storage, d.Get("ref").(string), true)
}

func (b *backend) pathIssuerDeltaCRLRotateWrite(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	return b.crlRotate(ctx, req.Storage, d.Get("ref").(string), true)
}

func (b *backend) crlJSON(ctx context.Context, s logical.Storage, ref string, delta bool) (*logical.Response, error) {
	entry, resp, err := b.crlForRead(ctx, s, ref, delta)
	if resp != nil || err != nil {
		return resp, err
	}

	data := map[string]interface{}{
		"certificate": pemCRL(entry.DER),
		"number":      entry.Number,
		"this_update": entry.ThisUpdate.Unix(),
		"next_update": entry.NextUpdate.Unix(),
	}
	if delta {
		data["base_number"] = entry.BaseNumber
	}

	return &logical.Response{Data: data}, nil
}

func (b *backend) crlPEM(ctx context.Context, s logical.Storage, ref string, delta bool) (*logical.Response, error) {
	entry, resp, err := b.crlForRead(ctx, s, ref, delta)
	if resp != nil || err != nil {
		return resp, err
	}

	return &logical.Response{Data: map[string]interface{}{
		logical.HTTPContentType: "application/pem-encoding",
		logical.HTTPRawBody:     []byte(pemCRL(entry.DER)),
		logical.HTTPStatusCode:  http.StatusOK,
	}}, nil
}

func (b *backend) crlDER(ctx context.Context, s logical.Storage, ref string, delta bool) (*logical.Response, error) {
	entry, resp, err := b.crlForRead(ctx, s, ref, delta)
	if resp != nil || err != nil {
		return resp, err
	}

	return &logical.Response{Data: map[string]interface{}{
		logical.HTTPContentType: "application/pkix-crl",
		logical.HTTPRawBody:     entry.DER,
		logical.HTTPStatusCode:  http.StatusOK,
	}}, nil
}

func (b *backend) crlRotate(ctx context.Context, s logical.Storage, ref string, delta bool) (*logical.Response, error) {
	b.caMu.Lock()
	defer b.caMu.Unlock()

	issuer, resp, err := b.crlIssuer(ctx, s, ref)
	if err != nil || resp != nil {
		return resp, err
	}

	config, err := b.crlConfig(ctx, s)
	if err != nil {
		return nil, err
	}

	if !delta {
		previous, err := b.currentCRL(ctx, s, issuer.ID)
		if err != nil {
			return nil, err
		}

		entry, err := b.buildCRL(ctx, s, issuer, previous, config)
		if err != nil {
			return issuerError(err)
		}

		return crlRotationResponse(entry, false), nil
	}

	// A delta is relative to a full list, so the base is signed again when it is
	// missing or has expired: a client cannot apply a delta to a list it may no
	// longer use. A base that merely went dirty is left alone when reads do not
	// advance it, because renumbering it would leave the delta with nothing to
	// carry.
	var full *crlEntry
	if config.rebuilds() {
		full, err = b.fullCRLFor(ctx, s, issuer, config)
	} else {
		full, err = b.currentCRL(ctx, s, issuer.ID)
		if err == nil && (full == nil || len(full.DER) == 0 || time.Now().After(full.NextUpdate)) {
			full, err = b.buildCRL(ctx, s, issuer, full, config)
		}
	}
	if err != nil {
		return issuerError(err)
	}

	previous, err := b.currentDeltaCRL(ctx, s, issuer.ID)
	if err != nil {
		return nil, err
	}

	entry, err := b.buildDeltaCRL(ctx, s, issuer, full, previous, config)
	if err != nil {
		return issuerError(err)
	}

	return crlRotationResponse(entry, true), nil
}

// crlRotationResponse says what the new list is: its number, the base it follows
// when it is a delta, and the span it claims to be current.
func crlRotationResponse(entry *crlEntry, delta bool) *logical.Response {
	data := map[string]interface{}{
		"number":      entry.Number,
		"this_update": entry.ThisUpdate.Unix(),
		"next_update": entry.NextUpdate.Unix(),
	}
	if delta {
		data["base_number"] = entry.BaseNumber
	}

	return &logical.Response{Data: data}
}

// crlForRead answers with a usable list of one authority: the full one, or the
// changes since it. A list that can be served as it is costs the read lock
// only, so a client fetching one does not queue behind a certificate being
// issued; a list that has to be signed is built and stored under the write
// lock, because the number must not move twice.
func (b *backend) crlForRead(ctx context.Context, s logical.Storage, ref string, delta bool) (*crlEntry, *logical.Response, error) {
	entry, resp, err := b.servedCRL(ctx, s, ref, delta)
	if err != nil || resp != nil || entry != nil {
		return entry, resp, err
	}

	return b.signCRL(ctx, s, ref, delta)
}

// servedCRL answers with a cached list when it can be served as it is, and with
// nothing when one has to be signed. A missing authority is answered here too,
// because saying so needs no lock of its own.
func (b *backend) servedCRL(ctx context.Context, s logical.Storage, ref string, delta bool) (*crlEntry, *logical.Response, error) {
	b.caMu.RLock()
	defer b.caMu.RUnlock()

	issuer, resp, err := b.crlIssuer(ctx, s, ref)
	if err != nil || resp != nil {
		return nil, resp, err
	}

	config, err := b.crlConfig(ctx, s)
	if err != nil {
		return nil, nil, err
	}

	full, err := b.currentCRL(ctx, s, issuer.ID)
	if err != nil {
		return nil, nil, err
	}
	if full == nil || len(full.DER) == 0 {
		return nil, nil, nil
	}

	// A delta follows a full list, so it can only be served when that list
	// would be: a read that signs a new base moves the base the delta names.
	if config.rebuilds() && (full.Dirty || !time.Now().Before(full.NextUpdate)) {
		return nil, nil, nil
	}
	if !delta {
		return full, nil, nil
	}

	previous, err := b.currentDeltaCRL(ctx, s, issuer.ID)
	if err != nil {
		return nil, nil, err
	}
	if previous != nil && previous.BaseNumber == full.Number && len(previous.DER) > 0 {
		if !previous.Dirty && time.Now().Before(previous.NextUpdate) {
			return previous, nil, nil
		}
	}

	return nil, nil, nil
}

// signCRL builds the list a read could not serve. It is the one path of a read
// that writes, so it holds the write lock: the revocations it names cannot
// arrive halfway through, and the number it takes is not taken twice.
func (b *backend) signCRL(ctx context.Context, s logical.Storage, ref string, delta bool) (*crlEntry, *logical.Response, error) {
	b.caMu.Lock()
	defer b.caMu.Unlock()

	issuer, resp, err := b.crlIssuer(ctx, s, ref)
	if err != nil || resp != nil {
		return nil, resp, err
	}

	config, err := b.crlConfig(ctx, s)
	if err != nil {
		return nil, nil, err
	}

	full, err := b.fullCRLFor(ctx, s, issuer, config)
	if err != nil {
		resp, err := issuerError(err)
		return nil, resp, err
	}
	if !delta {
		return full, nil, nil
	}

	previous, err := b.currentDeltaCRL(ctx, s, issuer.ID)
	if err != nil {
		return nil, nil, err
	}
	// A delta whose base is not the list that is served now would be applied to
	// the wrong one, so it is rebuilt whatever the configuration says. A delta
	// also follows a revocation on its own: unlike a full list it is cheap to
	// sign, and an operator who turned auto_rebuild off did so to keep the full
	// list from moving, not to leave a client without the changes.
	if previous != nil && previous.BaseNumber == full.Number && len(previous.DER) > 0 {
		if !previous.Dirty && time.Now().Before(previous.NextUpdate) {
			return previous, nil, nil
		}
	}

	entry, err := b.buildDeltaCRL(ctx, s, issuer, full, previous, config)
	if err != nil {
		resp, err := issuerError(err)
		return nil, resp, err
	}

	return entry, nil, nil
}

// fullCRLFor serves the full list of one authority, signing a new one only when
// there is nothing to serve or the configuration allows a rebuild.
func (b *backend) fullCRLFor(ctx context.Context, s logical.Storage, issuer *issuerEntry, config *crlConfig) (*crlEntry, error) {
	cached, err := b.currentCRL(ctx, s, issuer.ID)
	if err != nil {
		return nil, err
	}
	if cached != nil && len(cached.DER) > 0 {
		if !config.rebuilds() || (!cached.Dirty && time.Now().Before(cached.NextUpdate)) {
			return cached, nil
		}
	}

	return b.buildCRL(ctx, s, issuer, cached, config)
}

// crlIssuer resolves the authority whose list is asked for: the one the path
// names, or the one this mount signs with. A mount that has rotated holds more
// than one, and each list speaks only for the certificates of its own issuer.
func (b *backend) crlIssuer(ctx context.Context, s logical.Storage, ref string) (*issuerEntry, *logical.Response, error) {
	_, issuer, err := b.issuerByRef(ctx, s, ref)
	if err != nil {
		return nil, logical.ErrorResponse(err.Error()), logical.ErrInvalidRequest
	}
	if issuer == nil {
		return nil, logical.ErrorResponse(errNoIssuer.Error()), logical.ErrInvalidRequest
	}

	return issuer, nil, nil
}

// markCRLDirty records that a revocation arrived after the cached lists of this
// issuer were signed. Both are rebuilt on the next read, so a revoke does not
// pay for a signature nobody asked for.
func (b *backend) markCRLDirty(ctx context.Context, s logical.Storage, issuerID string) error {
	entry, err := b.currentCRL(ctx, s, issuerID)
	if err != nil {
		return err
	}
	if entry != nil && !entry.Dirty {
		entry.Dirty = true
		if err := putJSON(ctx, s, crlStorePath(issuerID), entry); err != nil {
			return err
		}
	}

	delta, err := b.currentDeltaCRL(ctx, s, issuerID)
	if err != nil {
		return err
	}
	if delta != nil && !delta.Dirty {
		delta.Dirty = true
		if err := putJSON(ctx, s, deltaCRLStorePath(issuerID), delta); err != nil {
			return err
		}
	}

	return nil
}

// buildCRL signs a new full list from every revocation of this issuer and caches
// it. The number only ever grows, so a client can tell two lists apart; each
// issuer counts on its own, which keeps the numbering of one from moving the
// other.
func (b *backend) buildCRL(ctx context.Context, s logical.Storage, issuer *issuerEntry, previous *crlEntry, config *crlConfig) (*crlEntry, error) {
	if issuer.ID == "" {
		return nil, fmt.Errorf("the issuer record has no identifier")
	}
	if err := issuer.checkUsage(usageCRL, "sign a revocation list"); err != nil {
		return nil, err
	}

	number, err := nextCRLNumber(previous)
	if err != nil {
		return nil, err
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
	defer b.closeSigner(signer)

	now := time.Now()
	template := &smx509.RevocationList{
		Number:                    big.NewInt(number),
		ThisUpdate:                now,
		NextUpdate:                now.Add(config.lifetime()),
		RevokedCertificateEntries: entries,
		SignatureAlgorithm:        smx509.SM2WithSM3,
	}

	der, err := smx509.CreateRevocationList(rand.Reader, template, cert, signer)
	if err != nil {
		return nil, fmt.Errorf("could not create the certificate revocation list: %w", err)
	}

	entry := &crlEntry{
		Number:     strconv.FormatInt(number, 10),
		ThisUpdate: now,
		NextUpdate: template.NextUpdate,
		DER:        der,
	}
	if err := putJSON(ctx, s, crlStorePath(issuer.ID), entry); err != nil {
		return nil, err
	}

	return entry, nil
}

// buildDeltaCRL signs the changes since the full list it names. The number of a
// delta follows the number of its base, so the two can be compared, and the
// indicator extension says which full list a client has to hold to apply it.
func (b *backend) buildDeltaCRL(ctx context.Context, s logical.Storage, issuer *issuerEntry, full, previous *crlEntry, config *crlConfig) (*crlEntry, error) {
	if issuer.ID == "" {
		return nil, fmt.Errorf("the issuer record has no identifier")
	}
	if err := issuer.checkUsage(usageCRL, "sign a revocation list"); err != nil {
		return nil, err
	}

	base, err := strconv.Atoi(full.Number)
	if err != nil {
		return nil, fmt.Errorf("the number of the full list, %q, is not a number: %w", full.Number, err)
	}

	number := base + 1
	if previous != nil && previous.Number != "" {
		parsed, err := strconv.Atoi(previous.Number)
		if err != nil {
			return nil, fmt.Errorf("the number of the cached delta, %q, is not a number: %w", previous.Number, err)
		}
		if parsed >= number {
			number = parsed + 1
		}
	}

	changes, err := b.deltaCRLEntries(ctx, s, issuer.ID, full.ThisUpdate)
	if err != nil {
		return nil, err
	}

	indicator, err := asn1.Marshal(big.NewInt(int64(base)))
	if err != nil {
		return nil, fmt.Errorf("could not encode the base of the delta: %w", err)
	}

	cert, err := issuer.certificate()
	if err != nil {
		return nil, err
	}
	signer, err := b.issuerSigner(ctx, s, issuer)
	if err != nil {
		return nil, err
	}
	defer b.closeSigner(signer)

	now := time.Now()
	template := &smx509.RevocationList{
		Number:                    big.NewInt(int64(number)),
		ThisUpdate:                now,
		NextUpdate:                now.Add(config.lifetime()),
		RevokedCertificateEntries: changes,
		ExtraExtensions: []pkix.Extension{{
			Id:       oidExtensionDeltaCRLIndicator,
			Critical: true,
			Value:    indicator,
		}},
		SignatureAlgorithm: smx509.SM2WithSM3,
	}

	der, err := smx509.CreateRevocationList(rand.Reader, template, cert, signer)
	if err != nil {
		return nil, fmt.Errorf("could not create the delta of the certificate revocation list: %w", err)
	}

	entry := &crlEntry{
		Number:     strconv.Itoa(number),
		BaseNumber: full.Number,
		ThisUpdate: now,
		NextUpdate: template.NextUpdate,
		DER:        der,
	}
	if err := putJSON(ctx, s, deltaCRLStorePath(issuer.ID), entry); err != nil {
		return nil, err
	}

	return entry, nil
}

// nextCRLNumber is the number of the list that follows one. It only ever grows.
func nextCRLNumber(previous *crlEntry) (int64, error) {
	if previous == nil || previous.Number == "" {
		return 1, nil
	}

	parsed, err := strconv.ParseInt(previous.Number, 10, 64)
	if err != nil {
		return 0, fmt.Errorf("the number of the cached CRL, %q, is not a number: %w", previous.Number, err)
	}

	return parsed + 1, nil
}

// crlEntries turns the revocation records of one issuer into entries of its
// list. A revocation belongs to the authority that signed the certificate, so a
// merged list would name serials its own signature says nothing about; one
// recorded before the mount named the authority with it belongs to the
// authority that was signing at the time. The reason is carried over as it was
// recorded; leaving it out would make a compromise look like a certificate that
// simply ceased to be used. A certificate that has expired is left out: a list
// says what a client may still be shown, not what happened, and without that it
// would grow until someone ran tidy.
func (b *backend) crlEntries(ctx context.Context, s logical.Storage, issuerID string) ([]smx509.RevocationListEntry, error) {
	names, err := s.List(ctx, revokedPrefix)
	if err != nil {
		return nil, err
	}

	legacyID, err := b.legacyIssuerID(ctx, s)
	if err != nil {
		return nil, err
	}

	now := time.Now()
	entries := make([]smx509.RevocationListEntry, 0, len(names))
	for _, name := range names {
		record, err := b.revocationRecord(ctx, s, name)
		if err != nil {
			return nil, err
		}
		if record == nil || !belongsToIssuer(record.IssuerID, issuerID, legacyID) || record.hasExpired(now) {
			continue
		}

		serial, ok := new(big.Int).SetString(name, 16)
		if !ok {
			return nil, fmt.Errorf("the storage key of a revocation, %q, is not a serial number", name)
		}

		entries = append(entries, smx509.RevocationListEntry{
			SerialNumber:   serial,
			RevocationTime: time.Unix(record.RevocationTime, 0),
			ReasonCode:     record.Reason,
		})
	}

	return entries, nil
}

// deltaCRLEntries is what changed since a full list was signed: the revocations
// recorded at or after that moment. A revocation that arrived in the same second
// as the list appears in both rather than in neither.
func (b *backend) deltaCRLEntries(ctx context.Context, s logical.Storage, issuerID string, since time.Time) ([]smx509.RevocationListEntry, error) {
	all, err := b.crlEntries(ctx, s, issuerID)
	if err != nil {
		return nil, err
	}

	moment := since.Truncate(time.Second)
	changes := make([]smx509.RevocationListEntry, 0, len(all))
	for _, entry := range all {
		if !entry.RevocationTime.Before(moment) {
			changes = append(changes, entry)
		}
	}

	return changes, nil
}

// currentDeltaCRL returns the cached delta of one issuer, or nil when none has
// been built yet. It needs no legacy path: a mount written before delta lists
// existed builds one on the first read.
func (b *backend) currentDeltaCRL(ctx context.Context, s logical.Storage, issuerID string) (*crlEntry, error) {
	return getJSON[crlEntry](ctx, s, deltaCRLStorePath(issuerID))
}

const pathCRLHelpSyn = `Read the certificate revocation list`

const pathCRLHelpDesc = `
The certificate revocation list of the mount, signed by its authority. The
signed list is kept as it is and rebuilt when a certificate has been revoked
since or when it has expired, so two reads of an unchanged list answer with the
same bytes. A certificate that has passed its expiration is left out of it, so
a list only names the certificates a client may still be shown. Use crl/rotate
to force a new list with a new number, and config/crl to say how long a list
claims to be current and whether a read may rebuild it.
`

const pathCRLRotateHelpSyn = `Rebuild the certificate revocation list`

const pathCRLRotateHelpDesc = `
Signs a new list with the next number and a fresh validity, whether or not
anything changed. A client that watches the number sees the rotation.
`

const pathDeltaCRLHelpSyn = `Read the changes since the last full revocation list`

const pathDeltaCRLHelpDesc = `
A delta list names only the revocations recorded since the full list it is based
on, so a client that holds that list catches up without fetching it again. Its
number follows the number of its base, and the delta CRL indicator extension
carries that base, so a client can tell which full list the delta applies to.

A delta that is missing, stale, or outdated by a revocation is rebuilt on the
next read, unless config/crl turns that off. A client that cannot reach a full
list has nothing to apply a delta to, so publish the full list and offer the
delta beside it.
`

const pathDeltaCRLRotateHelpSyn = `Rebuild the changes since the last full list`

const pathDeltaCRLRotateHelpDesc = `
Signs a new delta with the next number of the delta of this authority, whether or
not anything changed. The base is the full list as it stands now, which is
rebuilt first when it has gone stale.
`

const pathIssuerCRLHelpSyn = `Read the list of one issuer`

const pathIssuerCRLHelpDesc = `
Answers with the certificate revocation list of one authority of the mount, in
the same three forms as crl: JSON, PEM and DER. The list names only the
revocations of that authority, because a serial another one signed has nothing
to do with it, and it is numbered on its own.

A mount that has rotated keeps answering for the authority it replaced, which
is what lets the certificates of that authority be checked with the list that
can speak for them. Retiring the authority takes its list away.
`

const pathIssuerCRLRotateHelpSyn = `Rebuild the list of one issuer`

const pathIssuerCRLRotateHelpDesc = `
Signs a new list of the named authority with the next number of that authority
and a fresh validity, whether or not anything changed.
`

const pathIssuerDeltaCRLHelpSyn = `Read the changes since the last full list of one issuer`

const pathIssuerDeltaCRLHelpDesc = `
Answers with the delta of one authority, in the same three forms as crl/delta:
JSON, PEM and DER. The number of the delta follows the number of the full list
of that authority, and the delta CRL indicator says which list a client has to
hold to apply it.

A mount that has rotated keeps a delta for the authority it replaced as well,
because the certificates of that authority keep asking for the list it signed.
`

const pathIssuerDeltaCRLRotateHelpSyn = `Rebuild the delta of one issuer`

const pathIssuerDeltaCRLRotateHelpDesc = `
Signs a new delta of the named authority against its full list as it stands now,
whether or not anything changed.
`
