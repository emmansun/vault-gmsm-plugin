package gmsm

import (
	"context"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"time"

	"github.com/emmansun/gmsm/smx509"
	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
)

// importableKeyType maps the type accepted by the import paths onto the key
// types that can hold imported material. Managed keys are configured elsewhere
// and SM4-CMAC is not implemented at all, so both are rejected by name instead
// of falling into the generic "unknown key type" answer.
func importableKeyType(raw string) (KeyType, error) {
	switch raw {
	case "ecdsa-sm2":
		return KeyType_ECDSA_SM2, nil
	case "sm4-gcm96":
		return KeyType_SM4_GCM96, nil
	case "hmac":
		return KeyType_HMAC, nil
	case "sm4-cmac":
		return 0, ErrCmacUnsupported
	case "managed_key":
		return 0, fmt.Errorf("managed keys are not imported, they are configured with managed_key_name or managed_key_id")
	case "":
		return 0, fmt.Errorf("type is required when importing key material")
	}

	return 0, fmt.Errorf("unknown key type %v", raw)
}

// importMaterial turns the three material fields into what the policy layer
// expects: the bytes to import and whether they are a private key. Exactly one
// field may be set, and the field has to match the key type.
func importMaterial(d *framework.FieldData, keyType KeyType) ([]byte, bool, error) {
	privateKeyPEM := d.Get("private_key").(string)
	publicKeyPEM := d.Get("public_key").(string)
	symmetricKey := d.Get("key").(string)

	set := 0
	for _, value := range []string{privateKeyPEM, publicKeyPEM, symmetricKey} {
		if value != "" {
			set++
		}
	}
	switch set {
	case 1:
	case 0:
		return nil, false, fmt.Errorf("one of private_key, public_key or key is required")
	default:
		return nil, false, fmt.Errorf("only one of private_key, public_key or key may be supplied")
	}

	if keyType == KeyType_ECDSA_SM2 {
		if symmetricKey != "" {
			return nil, false, fmt.Errorf("key carries symmetric material and is only used for sm4-gcm96 and hmac")
		}

		if privateKeyPEM != "" {
			if _, err := parsePrivateKey([]byte(privateKeyPEM)); err != nil {
				return nil, false, err
			}

			return []byte(privateKeyPEM), true, nil
		}

		block, _ := pem.Decode([]byte(publicKeyPEM))
		if block == nil {
			return nil, false, fmt.Errorf("public_key must be a PEM encoded public key")
		}
		if _, err := smx509.ParsePKIXPublicKey(block.Bytes); err != nil {
			return nil, false, fmt.Errorf("error parsing public key: %w", err)
		}

		return []byte(publicKeyPEM), false, nil
	}

	if privateKeyPEM != "" || publicKeyPEM != "" {
		return nil, false, fmt.Errorf("private_key and public_key are only used for ecdsa-sm2; supply key for %s", keyType)
	}

	raw, err := base64.StdEncoding.DecodeString(symmetricKey)
	if err != nil {
		return nil, false, fmt.Errorf("key must be base64 encoded: %w", err)
	}

	// Symmetric material is always the private half; the policy layer checks
	// the length.
	return raw, true, nil
}

func (b *backend) pathImportKey() *framework.Path {
	return &framework.Path{
		Pattern: "keys/" + framework.GenericNameRegex("name") + "/import",

		DisplayAttrs: &framework.DisplayAttributes{
			OperationPrefix: operationPrefix,
			OperationVerb:   "import",
			OperationSuffix: "key",
		},

		Fields: map[string]*framework.FieldSchema{
			"name": {
				Type:        framework.TypeString,
				Description: "Name of the key",
			},

			"type": {
				Type: framework.TypeString,
				Description: `The type of key to import. Currently "ecdsa-sm2",
"sm4-gcm96" and "hmac" are supported.`,
			},

			"private_key": {
				Type: framework.TypeString,
				Description: `The SM2 private key in PEM form, either PKCS#8
(BEGIN PRIVATE KEY) or SEC 1 (BEGIN EC PRIVATE KEY). The public
key is derived from it.`,
			},

			"public_key": {
				Type: framework.TypeString,
				Description: `The SM2 public key in PEM form (BEGIN PUBLIC KEY).
Importing only the public half limits the key to verification and
encryption: operations that need the private key fail.`,
			},

			"key": {
				Type: framework.TypeString,
				Description: `The base64 encoded key material of a symmetric key:
16 bytes for sm4-gcm96, between 32 and 512 bytes for hmac.`,
			},

			"exportable": {
				Type: framework.TypeBool,
				Description: `Whether the imported key material may be exported
again. Once set, this cannot be disabled.`,
			},

			"allow_plaintext_backup": {
				Type: framework.TypeBool,
				Description: `Whether the imported key may be backed up in
plaintext form. Once set, this cannot be disabled.`,
			},

			"allow_rotation": {
				Type: framework.TypeBool,
				Description: `Whether the imported key may be rotated inside
Vault. Defaults to false, which keeps rotate from replacing the
imported version with a generated one.`,
			},

			"auto_rotate_period": {
				Type:    framework.TypeDurationSecond,
				Default: 0,
				Description: `How often the key should be rotated automatically.
Requires allow_rotation, and must be at least an hour. Zero
disables automatic rotation.`,
			},
		},

		Callbacks: map[logical.Operation]framework.OperationFunc{
			logical.UpdateOperation: b.pathImportKeyWrite,
		},

		HelpSynopsis:    pathImportKeyHelpSyn,
		HelpDescription: pathImportKeyHelpDesc,
	}
}

func (b *backend) pathImportKeyWrite(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	name := d.Get("name").(string)

	keyType, err := importableKeyType(d.Get("type").(string))
	if err != nil {
		return logical.ErrorResponse(err.Error()), logical.ErrInvalidRequest
	}

	material, isPrivateKey, err := importMaterial(d, keyType)
	if err != nil {
		return logical.ErrorResponse(err.Error()), logical.ErrInvalidRequest
	}

	allowRotation := d.Get("allow_rotation").(bool)
	autoRotatePeriod := time.Second * time.Duration(d.Get("auto_rotate_period").(int))
	if autoRotatePeriod != 0 {
		if !allowRotation {
			return logical.ErrorResponse("auto_rotate_period requires allow_rotation: an imported key stays fixed unless rotation is allowed"), logical.ErrInvalidRequest
		}
		if autoRotatePeriod < time.Hour {
			return logical.ErrorResponse("auto rotate period must be 0 to disable or at least an hour"), logical.ErrInvalidRequest
		}
	}

	// Import creates a key; it never extends one, so a typo cannot splice
	// external material onto an existing ring. Adding a version is what
	// keys/:name/import_version is for.
	existing, err := b.lm.getPolicyFromStorage(ctx, req.Storage, name)
	if err != nil {
		return nil, err
	}
	if existing != nil {
		return logical.ErrorResponse(fmt.Sprintf("key %q already exists; use keys/%s/import_version to add a version", name, name)), logical.ErrInvalidRequest
	}

	err = b.ImportKey(ctx, PolicyRequest{
		Storage:                  req.Storage,
		Name:                     name,
		KeyType:                  keyType,
		Exportable:               d.Get("exportable").(bool),
		AllowPlaintextBackup:     d.Get("allow_plaintext_backup").(bool),
		AutoRotatePeriod:         autoRotatePeriod,
		AllowImportedKeyRotation: allowRotation,
		IsPrivateKey:             isPrivateKey,
	}, material)
	if err != nil {
		return logical.ErrorResponse(err.Error()), logical.ErrInvalidRequest
	}

	return b.importedKeyResponse(ctx, req, name)
}

func (b *backend) pathImportKeyVersion() *framework.Path {
	return &framework.Path{
		Pattern: "keys/" + framework.GenericNameRegex("name") + "/import_version",

		DisplayAttrs: &framework.DisplayAttributes{
			OperationPrefix: operationPrefix,
			OperationVerb:   "import",
			OperationSuffix: "key-version",
		},

		Fields: map[string]*framework.FieldSchema{
			"name": {
				Type:        framework.TypeString,
				Description: "Name of the key",
			},

			"private_key": {
				Type: framework.TypeString,
				Description: `The SM2 private key in PEM form, either PKCS#8
(BEGIN PRIVATE KEY) or SEC 1 (BEGIN EC PRIVATE KEY).`,
			},

			"public_key": {
				Type:        framework.TypeString,
				Description: `The SM2 public key in PEM form (BEGIN PUBLIC KEY).`,
			},

			"key": {
				Type:        framework.TypeString,
				Description: `The base64 encoded key material of a symmetric key.`,
			},

			"version": {
				Type: framework.TypeInt,
				Description: `The key version to complete. Only a version that holds
a public key and no private key can be completed. Leaving this unset
completes the latest version when that one holds a public key alone, and
otherwise adds a new version.`,
			},
		},

		Callbacks: map[logical.Operation]framework.OperationFunc{
			logical.UpdateOperation: b.pathImportKeyVersionWrite,
		},

		HelpSynopsis:    pathImportKeyVersionHelpSyn,
		HelpDescription: pathImportKeyVersionHelpDesc,
	}
}

func (b *backend) pathImportKeyVersionWrite(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	name := d.Get("name").(string)

	p, _, err := b.GetPolicy(ctx, PolicyRequest{
		Storage: req.Storage,
		Name:    name,
	}, b.GetRandomReader())
	if err != nil {
		return nil, err
	}
	if p == nil {
		return logical.ErrorResponse(fmt.Sprintf("key %q not found", name)), logical.ErrInvalidRequest
	}
	// Importing persists, so it needs the write lock.
	if !b.System().CachingDisabled() {
		p.Lock(true)
	}
	defer p.Unlock()

	if !p.Imported {
		return logical.ErrorResponse(fmt.Sprintf("key %q was generated by Vault and does not accept imported material", name)), logical.ErrInvalidRequest
	}
	if p.ImportedKeyRotated {
		return logical.ErrorResponse(fmt.Sprintf("key %q has been rotated inside Vault, so it no longer accepts imported material", name)), logical.ErrInvalidRequest
	}

	material, isPrivateKey, err := importMaterial(d, p.Type)
	if err != nil {
		return logical.ErrorResponse(err.Error()), logical.ErrInvalidRequest
	}

	version := d.Get("version").(int)
	if version == 0 {
		if err := p.ImportPublicOrPrivate(ctx, req.Storage, material, isPrivateKey, b.GetRandomReader()); err != nil {
			return logical.ErrorResponse(err.Error()), logical.ErrInvalidRequest
		}
	} else {
		if !isPrivateKey {
			return logical.ErrorResponse("version is only used to complete a version that holds a public key only, which needs private_key"), logical.ErrInvalidRequest
		}
		// This rejects a version that already holds a private key, a version
		// that holds only a public key (nothing to replace) and every
		// non-asymmetric type, so the caller is never told a key was imported
		// when it was not.
		if err := p.KeyVersionCanBeUpdated(version, isPrivateKey); err != nil {
			return logical.ErrorResponse(err.Error()), logical.ErrInvalidRequest
		}
		if err := p.ImportPrivateKeyForVersion(ctx, req.Storage, version, material); err != nil {
			return logical.ErrorResponse(err.Error()), logical.ErrInvalidRequest
		}
	}

	return b.formatKeyPolicy(p, nil)
}

// importedKeyResponse re-reads the policy so the answer to an import has the
// same shape as a read or a create, instead of leaving the caller to ask again.
func (b *backend) importedKeyResponse(ctx context.Context, req *logical.Request, name string) (*logical.Response, error) {
	p, _, err := b.GetPolicy(ctx, PolicyRequest{
		Storage: req.Storage,
		Name:    name,
	}, b.GetRandomReader())
	if err != nil {
		return nil, err
	}
	if p == nil {
		return nil, fmt.Errorf("imported key %q cannot be read back", name)
	}
	if !b.System().CachingDisabled() {
		p.Lock(false)
	}
	defer p.Unlock()

	return b.formatKeyPolicy(p, nil)
}

const pathImportKeyHelpSyn = `Import key material`

const pathImportKeyHelpDesc = `
This path creates a key from key material that was generated elsewhere. The
material is supplied in the request, so it has to travel over TLS to the
server; transit's wrapping key exchange and byok-export are not implemented.

For ecdsa-sm2 the public half may be imported on its own, which leaves the key
usable for verification and encryption only.
`

const pathImportKeyVersionHelpSyn = `Import key material as a new version`

const pathImportKeyVersionHelpDesc = `
This path adds key material to a key that was itself imported. Keys generated
by Vault do not accept imported material, and neither does a key that has been
rotated inside Vault, because its ring would then hold both imported and
generated versions.

Supplying version completes an existing version that holds a public key only.
`
