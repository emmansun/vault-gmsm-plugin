package pki

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
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
			"ref": issuerRefField(),
			"issuer_name": {
				Type:        framework.TypeString,
				Description: `Name to address this authority by instead of its identifier. An empty write clears it.`,
			},
			"usage": {
				Type: framework.TypeCommaStringSlice,
				Description: `What the key of this authority may be used for, as a comma
separated list: "issuing-certificates", "crl-signing", "ocsp-signing" or
"read-only". An authority that is never given one may do all three.`,
			},
			"leaf_not_after_behavior": {
				Type: framework.TypeString,
				Description: `What to do with a certificate that would outlive this authority:
"err" refuses it, "truncate" shortens it with a warning, and "permit" lets it
stand. Defaults to truncate.`,
			},
			"issuing_certificates": {
				Type:        framework.TypeCommaStringSlice,
				Description: "Addresses of this authority and the chain above it, as published in the certificates it signs. Overrides config/urls for this authority alone.",
			},
			"crl_distribution_points": {
				Type:        framework.TypeCommaStringSlice,
				Description: "Addresses of the list of this authority, as published in the certificates it signs. Overrides config/urls for this authority alone.",
			},
			"ocsp_servers": {
				Type:        framework.TypeCommaStringSlice,
				Description: "Addresses of the responder of this authority, as published in the certificates it signs. Overrides config/urls for this authority alone.",
			},
		},

		Callbacks: map[logical.Operation]framework.OperationFunc{
			logical.ReadOperation:   b.pathIssuerRead,
			logical.UpdateOperation: b.pathIssuerWrite,
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

// pathIssuerJSON serves one authority as a JSON document: the certificate, the
// chain above it and the settings that are not part of the certificate, which
// is what an operator reads to reproduce the authority elsewhere.
func (b *backend) pathIssuerJSON() *framework.Path {
	return &framework.Path{
		Pattern: "issuer/" + framework.GenericNameRegex("ref") + "/json$",

		DisplayAttrs: &framework.DisplayAttributes{
			OperationPrefix: operationPrefix + "-issuers",
			OperationVerb:   "read",
			OperationSuffix: "issuer-json",
		},

		Fields: map[string]*framework.FieldSchema{"ref": issuerRefField()},

		Callbacks: map[logical.Operation]framework.OperationFunc{
			logical.ReadOperation: b.pathIssuerJSONRead,
		},

		HelpSynopsis:    pathIssuerHelpSyn,
		HelpDescription: pathIssuerHelpDesc,
	}
}

// pathIssuerPEM and pathIssuerDER serve the certificate of one authority as a
// raw body, the way ca/pem does for the one the mount signs with.
func (b *backend) pathIssuerPEM() *framework.Path {
	return &framework.Path{
		Pattern: "issuer/" + framework.GenericNameRegex("ref") + "/pem$",

		DisplayAttrs: &framework.DisplayAttributes{
			OperationPrefix: operationPrefix + "-issuers",
			OperationVerb:   "read",
			OperationSuffix: "issuer-pem",
		},

		Fields: map[string]*framework.FieldSchema{"ref": issuerRefField()},

		Callbacks: map[logical.Operation]framework.OperationFunc{
			logical.ReadOperation: b.pathIssuerPEMRead,
		},

		HelpSynopsis:    pathIssuerHelpSyn,
		HelpDescription: pathIssuerHelpDesc,
	}
}

func (b *backend) pathIssuerDER() *framework.Path {
	return &framework.Path{
		Pattern: "issuer/" + framework.GenericNameRegex("ref") + "/der$",

		DisplayAttrs: &framework.DisplayAttributes{
			OperationPrefix: operationPrefix + "-issuers",
			OperationVerb:   "read",
			OperationSuffix: "issuer-der",
		},

		Fields: map[string]*framework.FieldSchema{"ref": issuerRefField()},

		Callbacks: map[logical.Operation]framework.OperationFunc{
			logical.ReadOperation: b.pathIssuerDERRead,
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
	id, issuer, resp, err := b.issuerForPath(ctx, req, d)
	if resp != nil || err != nil {
		return resp, err
	}

	data, err := b.issuerData(ctx, req.Storage, id, issuer)
	if err != nil {
		return nil, err
	}

	return &logical.Response{Data: data}, nil
}

// pathIssuerWrite changes what an authority may do and where it points its
// certificates. Only the fields of the request change, so a write that sets one
// of them leaves the rest where they are.
func (b *backend) pathIssuerWrite(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	b.caMu.Lock()
	defer b.caMu.Unlock()

	id, issuer, resp, err := b.issuerForPath(ctx, req, d)
	if resp != nil || err != nil {
		return resp, err
	}

	if _, ok := d.Raw["issuer_name"]; ok {
		name := strings.TrimSpace(d.Get("issuer_name").(string))
		if err := b.checkIssuerName(ctx, req.Storage, id, name); err != nil {
			return logical.ErrorResponse(err.Error()), logical.ErrInvalidRequest
		}
		issuer.Name = name
	}

	if _, ok := d.Raw["usage"]; ok {
		usage, err := issuerUsages(d.Get("usage").([]string))
		if err != nil {
			return logical.ErrorResponse(err.Error()), logical.ErrInvalidRequest
		}
		issuer.Usage = usage
	}

	if _, ok := d.Raw["leaf_not_after_behavior"]; ok {
		behavior, err := leafBehavior(d.Get("leaf_not_after_behavior").(string))
		if err != nil {
			return logical.ErrorResponse(err.Error()), logical.ErrInvalidRequest
		}
		issuer.LeafNotAfterBehavior = behavior
	}

	urls := &urlConfig{}
	if issuer.URLs != nil {
		*urls = *issuer.URLs
	}
	touched := false
	for _, field := range []string{"issuing_certificates", "crl_distribution_points", "ocsp_servers"} {
		if _, ok := d.Raw[field]; !ok {
			continue
		}

		// An address that config/urls refuses is refused here as well: a
		// certificate nobody can follow is worse than one with no address.
		if err := validateAbsoluteURLs(field, d.Get(field).([]string)); err != nil {
			return logical.ErrorResponse(err.Error()), logical.ErrInvalidRequest
		}
		touched = true
	}
	if _, ok := d.Raw["issuing_certificates"]; ok {
		urls.IssuingCertificates = trimmedList(d.Get("issuing_certificates").([]string))
	}
	if _, ok := d.Raw["crl_distribution_points"]; ok {
		urls.CRLDistributionPoints = trimmedList(d.Get("crl_distribution_points").([]string))
	}
	if _, ok := d.Raw["ocsp_servers"]; ok {
		urls.OCSPServers = trimmedList(d.Get("ocsp_servers").([]string))
	}
	if touched {
		// An authority that overrides nothing publishes the addresses of
		// config/urls, which is what an empty list means.
		issuer.URLs = nil
		if len(urls.IssuingCertificates)+len(urls.CRLDistributionPoints)+len(urls.OCSPServers) > 0 {
			issuer.URLs = urls
		}
	}

	if err := putJSON(ctx, req.Storage, issuerPrefix+id, issuer); err != nil {
		return nil, err
	}

	data, err := b.issuerData(ctx, req.Storage, id, issuer)
	if err != nil {
		return nil, err
	}

	return &logical.Response{Data: data}, nil
}

func (b *backend) pathIssuerJSONRead(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	id, issuer, resp, err := b.issuerForPath(ctx, req, d)
	if resp != nil || err != nil {
		return resp, err
	}

	bundle, err := b.issuerBundle(ctx, req.Storage, id, issuer)
	if err != nil {
		return nil, err
	}

	body, err := json.Marshal(bundle)
	if err != nil {
		return nil, fmt.Errorf("could not encode the issuer: %w", err)
	}

	return &logical.Response{Data: map[string]interface{}{
		logical.HTTPContentType: "application/json",
		logical.HTTPRawBody:     body,
		logical.HTTPStatusCode:  http.StatusOK,
	}}, nil
}

func (b *backend) pathIssuerPEMRead(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	_, issuer, resp, err := b.issuerForPath(ctx, req, d)
	if resp != nil || err != nil {
		return resp, err
	}

	return &logical.Response{Data: map[string]interface{}{
		logical.HTTPContentType: "application/pem-encoding",
		logical.HTTPRawBody:     []byte(pemCertificate(issuer.Certificate)),
		logical.HTTPStatusCode:  http.StatusOK,
	}}, nil
}

func (b *backend) pathIssuerDERRead(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	_, issuer, resp, err := b.issuerForPath(ctx, req, d)
	if resp != nil || err != nil {
		return resp, err
	}

	return &logical.Response{Data: map[string]interface{}{
		logical.HTTPContentType: "application/pkix-cert",
		logical.HTTPRawBody:     issuer.Certificate,
		logical.HTTPStatusCode:  http.StatusOK,
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

// issuerRefField is the ref every path that addresses one authority accepts.
func issuerRefField() *framework.FieldSchema {
	return &framework.FieldSchema{
		Type:        framework.TypeString,
		Description: `Identifier or name of the issuer, or "default" for the one this mount signs with.`,
	}
}

// issuerForPath resolves the ref of a path to one authority, with the answer a
// mount that holds none gives everywhere.
func (b *backend) issuerForPath(ctx context.Context, req *logical.Request, d *framework.FieldData) (string, *issuerEntry, *logical.Response, error) {
	id, issuer, err := b.issuerByRef(ctx, req.Storage, d.Get("ref").(string))
	if err != nil {
		return "", nil, logical.ErrorResponse(err.Error()), logical.ErrInvalidRequest
	}
	if issuer == nil {
		return "", nil, logical.ErrorResponse(errNoIssuer.Error()), logical.ErrInvalidRequest
	}

	return id, issuer, nil, nil
}

// issuerData is how one authority is reported: its identity, what it may do and
// the addresses it publishes. The addresses are the ones written on the
// authority, and an empty list means it publishes the ones of config/urls.
func (b *backend) issuerData(ctx context.Context, s logical.Storage, id string, issuer *issuerEntry) (map[string]interface{}, error) {
	der, err := issuerChainDER(issuer)
	if err != nil {
		return nil, err
	}

	defaultID, err := b.issuerID(ctx, s)
	if err != nil {
		return nil, err
	}

	urls := issuerURLs(issuer)
	return map[string]interface{}{
		"issuer_id":               id,
		"issuer_name":             issuer.Name,
		"certificate":             pemCertificate(issuer.Certificate),
		"ca_chain":                pemCertificates(der),
		"serial_number":           formatSerial(issuer.Serial),
		"key_id":                  issuer.KeyID,
		"created":                 issuer.Created.Unix(),
		"is_default":              defaultID != "" && id == defaultID,
		"usage":                   issuer.usageList(),
		"leaf_not_after_behavior": issuer.leafBehavior(),
		"issuing_certificates":    urls.IssuingCertificates,
		"crl_distribution_points": urls.CRLDistributionPoints,
		"ocsp_servers":            urls.OCSPServers,
	}, nil
}

// issuerChainDER is the chain of an authority as DER, in the order ca_chain
// reports it.
func issuerChainDER(issuer *issuerEntry) ([][]byte, error) {
	chain, err := issuer.chain()
	if err != nil {
		return nil, err
	}

	der := make([][]byte, len(chain))
	for i, cert := range chain {
		der[i] = cert.Raw
	}

	return der, nil
}

// issuerURLs is what an authority publishes of its own, empty when it publishes
// the mount-wide addresses.
func issuerURLs(issuer *issuerEntry) *urlConfig {
	if issuer.URLs == nil {
		return &urlConfig{}
	}

	return issuer.URLs
}

// issuerBundle is the JSON form of one authority: what issuer/:ref reports,
// without the times that are of interest only to a client of the mount.
type issuerBundle struct {
	IssuerID              string   `json:"issuer_id"`
	IssuerName            string   `json:"issuer_name"`
	Certificate           string   `json:"certificate"`
	CAChain               []string `json:"ca_chain"`
	SerialNumber          string   `json:"serial_number"`
	KeyID                 string   `json:"key_id"`
	Usage                 []string `json:"usage"`
	LeafNotAfterBehavior  string   `json:"leaf_not_after_behavior"`
	IssuingCertificates   []string `json:"issuing_certificates,omitempty"`
	CRLDistributionPoints []string `json:"crl_distribution_points,omitempty"`
	OCSPServers           []string `json:"ocsp_servers,omitempty"`
	Default               bool     `json:"default"`
}

func (b *backend) issuerBundle(ctx context.Context, s logical.Storage, id string, issuer *issuerEntry) (*issuerBundle, error) {
	der, err := issuerChainDER(issuer)
	if err != nil {
		return nil, err
	}

	defaultID, err := b.issuerID(ctx, s)
	if err != nil {
		return nil, err
	}

	urls := issuerURLs(issuer)
	return &issuerBundle{
		IssuerID:              id,
		IssuerName:            issuer.Name,
		Certificate:           pemCertificate(issuer.Certificate),
		CAChain:               pemCertificates(der),
		SerialNumber:          formatSerial(issuer.Serial),
		KeyID:                 issuer.KeyID,
		Usage:                 issuer.usageList(),
		LeafNotAfterBehavior:  issuer.leafBehavior(),
		IssuingCertificates:   urls.IssuingCertificates,
		CRLDistributionPoints: urls.CRLDistributionPoints,
		OCSPServers:           urls.OCSPServers,
		Default:               defaultID != "" && id == defaultID,
	}, nil
}

// checkIssuerName refuses a name another authority already has, and the word
// the API reserves for the authority the mount signs with.
func (b *backend) checkIssuerName(ctx context.Context, s logical.Storage, id, name string) error {
	if name == "" {
		return nil
	}
	if name == issuerRefDefault {
		return fmt.Errorf("issuer_name %q is reserved for the authority this mount signs with", name)
	}

	ids, err := s.List(ctx, issuerPrefix)
	if err != nil {
		return err
	}
	for _, other := range ids {
		if other == id {
			continue
		}
		record, err := b.issuerByID(ctx, s, other)
		if err != nil {
			return err
		}
		if record != nil && record.Name == name {
			return fmt.Errorf("issuer_name %q is already the name of the authority %q", name, other)
		}
	}

	return nil
}

// issuerUsages reads the usage of an authority. The four names are the whole
// set, and read-only is the one that excludes the other three.
func issuerUsages(entries []string) ([]string, error) {
	var usages []string
	readOnly := false

	for _, entry := range entries {
		switch value := strings.TrimSpace(entry); value {
		case "":
			continue
		case usageIssuing, usageCRL, usageOCSP:
			usages = append(usages, value)
		case usageReadOnly:
			readOnly = true
		default:
			return nil, fmt.Errorf("usage %q is not one of %q, %q, %q or %q", value, usageIssuing, usageCRL, usageOCSP, usageReadOnly)
		}
	}

	if readOnly {
		if len(usages) > 0 {
			return nil, fmt.Errorf("%q cannot be combined with a usage it excludes", usageReadOnly)
		}
		return []string{usageReadOnly}, nil
	}
	if len(usages) == 0 {
		return nil, errors.New("usage names nothing; leave the field out to allow everything")
	}

	return usages, nil
}

// leafBehavior reads what an authority does with a certificate that would
// outlive it.
func leafBehavior(raw string) (string, error) {
	switch value := strings.TrimSpace(raw); value {
	case leafNotAfterErr, leafNotAfterTruncate, leafNotAfterPermit:
		return value, nil
	default:
		return "", fmt.Errorf("leaf_not_after_behavior %q is not one of %q, %q or %q", raw, leafNotAfterErr, leafNotAfterTruncate, leafNotAfterPermit)
	}
}

// trimmedList removes the empty entries of a list, so that a write which names
// nothing clears the setting rather than storing an address of nothing.
func trimmedList(entries []string) []string {
	var list []string
	for _, entry := range entries {
		if value := strings.TrimSpace(entry); value != "" {
			list = append(list, value)
		}
	}

	return list
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

const pathIssuerHelpSyn = `Read, change or retire one issuer of this mount`

const pathIssuerHelpDesc = `
Returns the certificate, the chain, the key identifier, the name and the
settings of one authority, addressed by its identifier, by the name an operator
gave it, or by the word default; is_default says whether certificates are signed
with it. POST changes what the authority may do, how it treats a certificate
that would outlive it, and the addresses its certificates publish. It is served
with the certificate of the authority as a raw body on issuer/:ref/pem and
issuer/:ref/der, and as one JSON document on issuer/:ref/json.
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
