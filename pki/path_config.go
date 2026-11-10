package pki

import (
	"context"
	"fmt"
	"net/url"
	"strings"

	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
)

// pathConfigURLs sets the addresses that end up in every certificate the mount
// issues. They are usually filled in once, before the first certificate is
// issued, because a certificate cannot be corrected afterwards.
func (b *backend) pathConfigURLs() *framework.Path {
	return &framework.Path{
		Pattern: "config/urls$",

		DisplayAttrs: &framework.DisplayAttributes{
			OperationPrefix: operationPrefix + "-config",
			OperationVerb:   "write",
			OperationSuffix: "urls",
		},

		Fields: map[string]*framework.FieldSchema{
			"issuing_certificates": {
				Type:        framework.TypeCommaStringSlice,
				Description: "URLs of the certificate of this authority, published in the authority information access extension.",
			},
			"crl_distribution_points": {
				Type:        framework.TypeCommaStringSlice,
				Description: "URLs where the certificate revocation list is published.",
			},
			"ocsp_servers": {
				Type:        framework.TypeCommaStringSlice,
				Description: "URLs of OCSP responders. Nothing in this mount answers OCSP itself.",
			},
		},

		Callbacks: map[logical.Operation]framework.OperationFunc{
			logical.ReadOperation:   b.pathConfigURLsRead,
			logical.UpdateOperation: b.pathConfigURLsWrite,
		},

		HelpSynopsis:    pathConfigURLsHelpSyn,
		HelpDescription: pathConfigURLsHelpDesc,
	}
}

func (b *backend) pathConfigURLsRead(ctx context.Context, req *logical.Request, _ *framework.FieldData) (*logical.Response, error) {
	config, err := b.urls(ctx, req.Storage)
	if err != nil {
		return nil, err
	}

	return &logical.Response{Data: map[string]interface{}{
		"issuing_certificates":    config.IssuingCertificates,
		"crl_distribution_points": config.CRLDistributionPoints,
		"ocsp_servers":            config.OCSPServers,
	}}, nil
}

func (b *backend) pathConfigURLsWrite(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	for _, field := range []string{"issuing_certificates", "crl_distribution_points", "ocsp_servers"} {
		if err := validateAbsoluteURLs(field, d.Get(field).([]string)); err != nil {
			return logical.ErrorResponse(err.Error()), logical.ErrInvalidRequest
		}
	}

	config := &urlConfig{
		IssuingCertificates:   d.Get("issuing_certificates").([]string),
		CRLDistributionPoints: d.Get("crl_distribution_points").([]string),
		OCSPServers:           d.Get("ocsp_servers").([]string),
	}
	if err := putJSON(ctx, req.Storage, configURLsPath, config); err != nil {
		return nil, err
	}

	return nil, nil
}

// validateAbsoluteURLs refuses an address a client could not fetch. A relative
// URL in a certificate is worse than no URL, because nothing points it out
// until a client fails to validate the chain.
func validateAbsoluteURLs(field string, entries []string) error {
	for _, raw := range entries {
		trimmed := strings.TrimSpace(raw)
		if trimmed == "" {
			continue
		}

		parsed, err := url.Parse(trimmed)
		if err != nil {
			return fmt.Errorf("%s entry %q is not a URL: %w", field, raw, err)
		}
		if parsed.Scheme == "" || parsed.Host == "" {
			return fmt.Errorf("%s entry %q is not an absolute URL with a scheme and a host", field, raw)
		}
	}

	return nil
}

const pathConfigURLsHelpSyn = `Set the URLs published in issued certificates`

const pathConfigURLsHelpDesc = `
The addresses clients use to fetch this authority, its certificate revocation
list and an OCSP responder. They are written into every certificate issued
after this call, so a certificate issued before it keeps the addresses that
were in force when it was signed.
`
