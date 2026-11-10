package gmsm

import (
	"context"
	"fmt"

	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
)

// keysConfigStorageKey is where settings shared by every key of the mount are
// persisted.
const keysConfigStorageKey = "config/keys"

// keysMountConfig collects the switches that apply to the mount as a whole
// rather than to a single named key.
type keysMountConfig struct {
	// DisableUpsert blocks the encrypt path from creating a key implicitly
	// when the requested name does not exist yet.
	DisableUpsert bool `json:"disable_upsert"`
}

func (b *backend) pathConfigKeys() *framework.Path {
	return &framework.Path{
		Pattern: "config/keys",

		DisplayAttrs: &framework.DisplayAttributes{
			OperationPrefix: operationPrefix,
		},

		Fields: map[string]*framework.FieldSchema{
			"disable_upsert": {
				Type: framework.TypeBool,
				Description: `When enabled, encrypting with a key name that does
not exist yet is rejected instead of creating the key on the fly.`,
			},
		},

		Operations: map[logical.Operation]framework.OperationHandler{
			logical.UpdateOperation: &framework.PathOperation{
				Callback: b.pathConfigKeysWrite,
				DisplayAttrs: &framework.DisplayAttributes{
					OperationVerb:   "configure",
					OperationSuffix: "keys",
				},
			},
			logical.ReadOperation: &framework.PathOperation{
				Callback: b.pathConfigKeysRead,
				DisplayAttrs: &framework.DisplayAttributes{
					OperationSuffix: "keys-configuration",
				},
			},
		},

		HelpSynopsis:    pathConfigKeysHelpSyn,
		HelpDescription: pathConfigKeysHelpDesc,
	}
}

// readKeysMountConfig loads the mount wide settings. The zero value is used
// when the configuration was never written, so upserting stays allowed.
func (b *backend) readKeysMountConfig(ctx context.Context, storage logical.Storage) (*keysMountConfig, error) {
	entry, err := storage.Get(ctx, keysConfigStorageKey)
	if err != nil {
		return nil, fmt.Errorf("error loading keys configuration: %w", err)
	}

	cfg := new(keysMountConfig)
	if entry == nil {
		return cfg, nil
	}
	if err := entry.DecodeJSON(cfg); err != nil {
		return nil, fmt.Errorf("error decoding keys configuration: %w", err)
	}

	return cfg, nil
}

func (b *backend) writeKeysMountConfig(ctx context.Context, storage logical.Storage, cfg *keysMountConfig) error {
	entry, err := logical.StorageEntryJSON(keysConfigStorageKey, cfg)
	if err != nil {
		return fmt.Errorf("error encoding keys configuration: %w", err)
	}

	return storage.Put(ctx, entry)
}

func keysMountConfigResponse(cfg *keysMountConfig) *logical.Response {
	return &logical.Response{
		Data: map[string]interface{}{
			"disable_upsert": cfg.DisableUpsert,
		},
	}
}

func (b *backend) pathConfigKeysWrite(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	cfg, err := b.readKeysMountConfig(ctx, req.Storage)
	if err != nil {
		return nil, err
	}

	disableUpsert := d.Get("disable_upsert").(bool)
	if cfg.DisableUpsert == disableUpsert {
		return keysMountConfigResponse(cfg), nil
	}

	cfg.DisableUpsert = disableUpsert
	if err := b.writeKeysMountConfig(ctx, req.Storage, cfg); err != nil {
		return nil, err
	}

	return keysMountConfigResponse(cfg), nil
}

func (b *backend) pathConfigKeysRead(ctx context.Context, req *logical.Request, _ *framework.FieldData) (*logical.Response, error) {
	cfg, err := b.readKeysMountConfig(ctx, req.Storage)
	if err != nil {
		return nil, err
	}

	return keysMountConfigResponse(cfg), nil
}

const pathConfigKeysHelpSyn = `Configure behaviour shared by every key of the mount`

const pathConfigKeysHelpDesc = `
Settings written here apply to all keys of the mount. Currently the only
option is disable_upsert, which stops the encrypt endpoint from creating keys
implicitly.
`
