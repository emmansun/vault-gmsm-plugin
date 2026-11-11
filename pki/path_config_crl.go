package pki

import (
	"context"
	"time"

	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
)

// pathConfigCRL sets how long the mount tells a client its answers stay
// current, and whether a read may sign a list that went stale. Both the
// responder and the lists read it.
func (b *backend) pathConfigCRL() *framework.Path {
	return &framework.Path{
		Pattern: "config/crl$",

		DisplayAttrs: &framework.DisplayAttributes{
			OperationPrefix: operationPrefix + "-config",
			OperationVerb:   "write",
			OperationSuffix: "crl",
		},

		Fields: map[string]*framework.FieldSchema{
			"expiry": {
				Type:        framework.TypeDurationSecond,
				Default:     int(crlValidity / time.Second),
				Description: "How long a signed revocation list claims to be current, which is what its next update field states. 0 keeps the default.",
			},
			"ocsp_expiry": {
				Type:        framework.TypeDurationSecond,
				Default:     int(ocspValidity / time.Second),
				Description: "How long an OCSP answer stays current, which is what its next update field states. 0 leaves the field out, so a client is told to ask again whenever it wants.",
			},
			"auto_rebuild": {
				Type:        framework.TypeBool,
				Default:     true,
				Description: "Whether a read may sign a list that went stale or that a revocation has outdated. Turn it off when something else rotates the lists on a schedule of its own.",
			},
		},

		Callbacks: map[logical.Operation]framework.OperationFunc{
			logical.ReadOperation:   b.pathConfigCRLRead,
			logical.UpdateOperation: b.pathConfigCRLWrite,
		},

		HelpSynopsis:    pathConfigCRLHelpSyn,
		HelpDescription: pathConfigCRLHelpDesc,
	}
}

func (b *backend) pathConfigCRLRead(ctx context.Context, req *logical.Request, _ *framework.FieldData) (*logical.Response, error) {
	config, err := b.crlConfig(ctx, req.Storage)
	if err != nil {
		return nil, err
	}

	return &logical.Response{Data: map[string]interface{}{
		"expiry":       config.lifetime().String(),
		"ocsp_expiry":  config.ocspLifetime().String(),
		"auto_rebuild": config.rebuilds(),
	}}, nil
}

func (b *backend) pathConfigCRLWrite(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	rebuild := d.Get("auto_rebuild").(bool)
	config := &crlConfig{
		Expiry:      int64(d.Get("expiry").(int)),
		OCSPExpiry:  int64(d.Get("ocsp_expiry").(int)),
		AutoRebuild: &rebuild,
	}
	if err := putJSON(ctx, req.Storage, configCRLPath, config); err != nil {
		return nil, err
	}

	return nil, nil
}

const pathConfigCRLHelpSyn = `Set the lifetime of revocation lists and OCSP answers`

const pathConfigCRLHelpDesc = `
A signed list and an answer of the responder both say when they stop being
current. The interval is set here rather than in the answer, so it can be
shortened when clients poll the mount directly and lengthened when something in
front of it caches the answers.

auto_rebuild says whether a read may sign a list that has gone stale or that a
revocation has outdated. It is on by default, so a client always finds a list
that covers what the mount knows. Turn it off when something else calls
crl/rotate on a schedule of its own, and reads then answer with the bytes that
were last signed.

A write replaces the record as a whole. A value of 0 for expiry keeps the
default lifetime, and 0 for ocsp_expiry leaves the next update field out of an
answer, which tells a client that a fresher answer is available at any time.
`
