package gmsm

import (
	"context"
	"encoding/pem"
	"errors"
	"fmt"
	"strings"

	"github.com/emmansun/gmsm/smx509"
	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/helper/errutil"
	"github.com/hashicorp/vault/sdk/logical"
)

// pathCreateCsr issues a certificate request for a key version. The private key
// never leaves the backend: the caller only gets back a PEM encoded request to
// hand to a CA.
func (b *backend) pathCreateCsr() *framework.Path {
	return &framework.Path{
		Pattern: "keys/" + framework.GenericNameRegex("name") + "/csr",

		DisplayAttrs: &framework.DisplayAttributes{
			OperationPrefix: operationPrefix,
			OperationVerb:   "generate-csr",
		},

		Fields: map[string]*framework.FieldSchema{
			"name": {
				Type:        framework.TypeString,
				Description: "Name of the key",
			},

			"version": {
				Type:        framework.TypeInt,
				Description: "Version of the key to use. Defaults to the latest version.",
			},

			"csr": {
				Type: framework.TypeString,
				Description: `PEM encoded certificate request to use as a template. Its
subject, names and extensions are carried over; the public key and the signature
always come from the selected key version. When omitted an empty subject is used.`,
			},
		},

		Callbacks: map[logical.Operation]framework.OperationFunc{
			logical.UpdateOperation: b.pathCreateCsrWrite,
		},

		HelpSynopsis:    pathCreateCsrHelpSyn,
		HelpDescription: pathCreateCsrHelpDesc,
	}
}

// pathSetCertificate stores an externally signed certificate chain on a key
// version, so it can be exported alongside the public key.
func (b *backend) pathSetCertificate() *framework.Path {
	return &framework.Path{
		Pattern: "keys/" + framework.GenericNameRegex("name") + "/set-certificate",

		DisplayAttrs: &framework.DisplayAttributes{
			OperationPrefix: operationPrefix,
			OperationVerb:   "set-certificate",
		},

		Fields: map[string]*framework.FieldSchema{
			"name": {
				Type:        framework.TypeString,
				Description: "Name of the key",
			},

			"version": {
				Type:        framework.TypeInt,
				Description: "Version of the key the chain belongs to. Defaults to the latest version.",
			},

			"certificate_chain": {
				Type: framework.TypeString,
				Description: `PEM encoded certificate chain: one or more concatenated
blocks, ordered so that the end-entity certificate comes first. The leaf
certificate public key must belong to the selected key version.`,
			},
		},

		Callbacks: map[logical.Operation]framework.OperationFunc{
			logical.UpdateOperation: b.pathSetCertificateWrite,
		},

		HelpSynopsis:    pathSetCertificateHelpSyn,
		HelpDescription: pathSetCertificateHelpDesc,
	}
}

func (b *backend) pathCreateCsrWrite(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	p, resp, err := b.certificatePathPolicy(ctx, req, d)
	if resp != nil || err != nil {
		return resp, err
	}
	if !b.System().CachingDisabled() {
		p.Lock(false)
	}
	defer p.Unlock()

	keyVersion := requestedKeyVersion(p, d)

	template, err := parseCsrTemplate(d.Get("csr").(string))
	if err != nil {
		return logical.ErrorResponse(err.Error()), logical.ErrInvalidRequest
	}

	pemCSR, err := p.CreateCsr(keyVersion, template)
	if err != nil {
		switch err.(type) {
		case errutil.UserError:
			return logical.ErrorResponse(err.Error()), logical.ErrInvalidRequest
		default:
			return nil, err
		}
	}

	return &logical.Response{
		Data: map[string]interface{}{
			"name":        p.Name,
			"type":        p.Type.String(),
			"key_version": keyVersion,
			"csr":         string(pemCSR),
		},
	}, nil
}

func (b *backend) pathSetCertificateWrite(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	p, resp, err := b.certificatePathPolicy(ctx, req, d)
	if resp != nil || err != nil {
		return resp, err
	}
	// This one writes and persists, so it needs the write lock.
	if !b.System().CachingDisabled() {
		p.Lock(true)
	}
	defer p.Unlock()

	keyVersion := requestedKeyVersion(p, d)

	pemChain := d.Get("certificate_chain").(string)
	certChain, err := parseCertificateChain(pemChain)
	if err != nil {
		return logical.ErrorResponse(err.Error()), logical.ErrInvalidRequest
	}

	if err := p.ValidateAndPersistCertificateChain(ctx, keyVersion, certChain, req.Storage); err != nil {
		switch err.(type) {
		case errutil.UserError:
			return logical.ErrorResponse(err.Error()), logical.ErrInvalidRequest
		default:
			return nil, err
		}
	}

	return &logical.Response{
		Data: map[string]interface{}{
			"name":              p.Name,
			"type":              p.Type.String(),
			"key_version":       keyVersion,
			"certificate_chain": pemChain,
		},
	}, nil
}

// certificatePathPolicy loads the policy named in the request and rejects the
// ones that cannot carry certificates: only the key types that sign have a
// public key a certificate could belong to. Derivation needs no separate check
// because derived keys are rejected when they are created.
func (b *backend) certificatePathPolicy(ctx context.Context, req *logical.Request, d *framework.FieldData) (*Policy, *logical.Response, error) {
	name := d.Get("name").(string)

	p, _, err := b.GetPolicy(ctx, PolicyRequest{
		Storage: req.Storage,
		Name:    name,
	}, b.GetRandomReader())
	if err != nil {
		return nil, nil, err
	}
	if p == nil {
		return nil, logical.ErrorResponse(fmt.Sprintf("key %q not found", name)), logical.ErrInvalidRequest
	}
	if !p.Type.SigningSupported() {
		return nil, logical.ErrorResponse(fmt.Sprintf("key type %v does not support certificates", p.Type)), logical.ErrInvalidRequest
	}

	return p, nil, nil
}

// requestedKeyVersion resolves the version field, defaulting to the latest
// version of the policy.
func requestedKeyVersion(p *Policy, d *framework.FieldData) int {
	if version, ok := d.GetOk("version"); ok {
		return version.(int)
	}

	return p.LatestVersion
}

// parseCsrTemplate decodes a PEM encoded certificate request and keeps the
// template as supplied. An empty string yields an empty template, which is what
// a caller that only wants the key in a request passes.
func parseCsrTemplate(pemCSR string) (*smx509.CertificateRequest, error) {
	if strings.TrimSpace(pemCSR) == "" {
		return &smx509.CertificateRequest{}, nil
	}

	block, _ := pem.Decode([]byte(pemCSR))
	if block == nil {
		return nil, errors.New("could not decode PEM certificate request")
	}

	template, err := smx509.ParseCertificateRequest(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("could not parse certificate request: %w", err)
	}

	return template, nil
}

// parseCertificateChain decodes a concatenated PEM bundle, preserving the order
// the caller supplied. Blocks that are not certificates are ignored, so a bundle
// may carry private keys or comments without upsetting the import.
func parseCertificateChain(pemChain string) ([]*smx509.Certificate, error) {
	var certChain []*smx509.Certificate

	remaining := []byte(strings.TrimSpace(pemChain))
	for len(remaining) > 0 {
		var block *pem.Block
		block, remaining = pem.Decode(remaining)
		if block == nil {
			return nil, errors.New("could not decode PEM block in certificate chain")
		}
		if block.Type != "CERTIFICATE" {
			continue
		}

		cert, err := smx509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("could not parse certificate in certificate chain: %w", err)
		}

		certChain = append(certChain, cert)
	}

	if len(certChain) == 0 {
		return nil, errors.New("certificate chain did not contain a PEM certificate")
	}

	return certChain, nil
}

const pathCreateCsrHelpSyn = `Generate a certificate request for a key version`

const pathCreateCsrHelpDesc = `
This path produces a PKCS#10 certificate request signed by the named key. The
request is generated locally, so the private key never has to leave the backend
or be exposed to the caller.
`

const pathSetCertificateHelpSyn = `Import an externally signed certificate chain`

const pathSetCertificateHelpDesc = `
This path associates a certificate chain with a key version. The leaf
certificate has to carry the public key of that version; the rest of the chain
is stored untouched and handed back when the key is exported.
`
