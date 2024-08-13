package gmsm

import (
	"context"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"strings"
	"time"

	"github.com/emmansun/gmsm/sm2"
	"github.com/fatih/structs"
	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/helper/keysutil"
	"github.com/hashicorp/vault/sdk/logical"
)

func (b *backend) pathListKeys() *framework.Path {
	return &framework.Path{
		Pattern: "keys/?$",

		DisplayAttrs: &framework.DisplayAttributes{
			OperationPrefix: operationPrefix,
			OperationSuffix: "keys",
		},

		Callbacks: map[logical.Operation]framework.OperationFunc{
			logical.ListOperation: b.pathKeysList,
		},

		HelpSynopsis:    pathPolicyHelpSyn,
		HelpDescription: pathPolicyHelpDesc,
	}
}

func (b *backend) pathKeys() *framework.Path {
	return &framework.Path{
		Pattern: "keys/" + framework.GenericNameRegex("name"),
		DisplayAttrs: &framework.DisplayAttributes{
			OperationPrefix: operationPrefix,
			OperationSuffix: "key",
		},
		Fields: map[string]*framework.FieldSchema{
			"name": {
				Type:        framework.TypeString,
				Description: "Name of the key",
			},

			"type": {
				Type:    framework.TypeString,
				Default: "sm4-gcm96",
				Description: `
The type of key to create. Currently, "sm4-gcm96" (symmetric), "ecdsa-sm2"
(asymmetric) are supported.  Defaults to "sm4-gcm96".
`,
			},

			"derived": {
				Type: framework.TypeBool,
				Description: `Enables key derivation mode. This
allows for per-transaction unique
keys for encryption operations.`,
			},

			"convergent_encryption": {
				Type: framework.TypeBool,
				Description: `Whether to support convergent encryption.
This is only supported when using a key with
key derivation enabled and will require all
requests to carry both a context and 96-bit
(12-byte) nonce. The given nonce will be used
in place of a randomly generated nonce. As a
result, when the same context and nonce are
supplied, the same ciphertext is generated. It
is *very important* when using this mode that
you ensure that all nonces are unique for a
given context. Failing to do so will severely
impact the ciphertext's security.`,
			},

			"exportable": {
				Type: framework.TypeBool,
				Description: `Enables keys to be exportable.
This allows for all the valid keys
in the key ring to be exported.`,
			},

			"allow_plaintext_backup": {
				Type: framework.TypeBool,
				Description: `Enables taking a backup of the named
key in plaintext format. Once set,
this cannot be disabled.`,
			},

			"context": {
				Type: framework.TypeString,
				Description: `Base64 encoded context for key derivation.
When reading a key with key derivation enabled,
if the key type supports public keys, this will
return the public key for the given context.`,
			},

			"auto_rotate_period": {
				Type:    framework.TypeDurationSecond,
				Default: 0,
				Description: `Amount of time the key should live before
being automatically rotated. A value of 0
(default) disables automatic rotation for the
key.`,
			},
			"key_size": {
				Type:        framework.TypeInt,
				Default:     0,
				Description: fmt.Sprintf("The key size in bytes for the algorithm.  Only applies to HMAC and must be no fewer than %d bytes and no more than %d", keysutil.HmacMinKeySize, keysutil.HmacMaxKeySize),
			},
			"managed_key_name": {
				Type:        framework.TypeString,
				Description: "The name of the managed key to use for this gmsm transit key",
			},
			"managed_key_id": {
				Type:        framework.TypeString,
				Description: "The UUID of the managed key to use for this gmsm transit key",
			},
		},

		Operations: map[logical.Operation]framework.OperationHandler{
			logical.UpdateOperation: &framework.PathOperation{
				Callback: b.pathPolicyWrite,
				DisplayAttrs: &framework.DisplayAttributes{
					OperationVerb: "create",
				},
			},
			logical.DeleteOperation: &framework.PathOperation{
				Callback: b.pathPolicyDelete,
				DisplayAttrs: &framework.DisplayAttributes{
					OperationVerb: "delete",
				},
			},
			logical.ReadOperation: &framework.PathOperation{
				Callback: b.pathPolicyRead,
				DisplayAttrs: &framework.DisplayAttributes{
					OperationVerb: "read",
				},
			},
		},

		HelpSynopsis:    pathPolicyHelpSyn,
		HelpDescription: pathPolicyHelpDesc,
	}
}

func (b *backend) pathKeysList(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	entries, err := req.Storage.List(ctx, "policy/")
	if err != nil {
		return nil, err
	}

	return logical.ListResponse(entries), nil
}

func (b *backend) pathPolicyWrite(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	name := d.Get("name").(string)
	derived := d.Get("derived").(bool)
	convergent := d.Get("convergent_encryption").(bool)
	keyType := d.Get("type").(string)
	keySize := d.Get("key_size").(int)
	exportable := d.Get("exportable").(bool)
	allowPlaintextBackup := d.Get("allow_plaintext_backup").(bool)
	autoRotatePeriod := time.Second * time.Duration(d.Get("auto_rotate_period").(int))
	managedKeyName := d.Get("managed_key_name").(string)
	managedKeyId := d.Get("managed_key_id").(string)

	if autoRotatePeriod != 0 && autoRotatePeriod < time.Hour {
		return logical.ErrorResponse("auto rotate period must be 0 to disable or at least an hour"), nil
	}

	if !derived && convergent {
		return logical.ErrorResponse("convergent encryption requires derivation to be enabled"), nil
	}

	polReq := PolicyRequest{
		Upsert:               true,
		Storage:              req.Storage,
		Name:                 name,
		Derived:              derived,
		Convergent:           convergent,
		Exportable:           exportable,
		AllowPlaintextBackup: allowPlaintextBackup,
		AutoRotatePeriod:     autoRotatePeriod,
	}
	switch keyType {
	case "sm4-gcm96":
		polReq.KeyType = KeyType_SM4_GCM96
	case "ecdsa-sm2":
		polReq.KeyType = KeyType_ECDSA_SM2
	case "hmac":
		polReq.KeyType = KeyType_HMAC
	case "managed_key":
		polReq.KeyType = KeyType_MANAGED_KEY
	case "sm4-cmac":
		polReq.KeyType = KeyType_SM4_CMAC
	default:
		return logical.ErrorResponse(fmt.Sprintf("unknown key type %v", keyType)), logical.ErrInvalidRequest
	}
	if keySize != 0 {
		if polReq.KeyType != KeyType_HMAC {
			return logical.ErrorResponse(fmt.Sprintf("key_size is not valid for algorithm %v", polReq.KeyType)), logical.ErrInvalidRequest
		}
		if keySize < HmacMinKeySize || keySize > HmacMaxKeySize {
			return logical.ErrorResponse(fmt.Sprintf("invalid key_size %d", keySize)), logical.ErrInvalidRequest
		}
		polReq.KeySize = keySize
	}

	if polReq.KeyType == KeyType_MANAGED_KEY {
		keyId, err := GetManagedKeyUUID(ctx, b, managedKeyName, managedKeyId)
		if err != nil {
			return nil, err
		}

		polReq.ManagedKeyUUID = keyId
	}

	if polReq.KeyType.CMACSupported() {
		return logical.ErrorResponse(ErrCmacEntOnly.Error()), logical.ErrInvalidRequest
	}

	p, upserted, err := b.GetPolicy(ctx, polReq, b.GetRandomReader())
	if err != nil {
		return nil, err
	}
	if p == nil {
		return nil, fmt.Errorf("error generating key: returned policy was nil")
	}
	if b.System().CachingDisabled() {
		p.Unlock()
	}

	resp, err := b.formatKeyPolicy(p, nil)
	if err != nil {
		return nil, err
	}
	if !upserted {
		resp.AddWarning(fmt.Sprintf("key %s already existed", name))
	}
	return resp, nil
}

// Built-in helper type for returning asymmetric keys
type asymKey struct {
	Name             string    `json:"name" structs:"name" mapstructure:"name"`
	PublicKey        string    `json:"public_key" structs:"public_key" mapstructure:"public_key"`
	CertificateChain string    `json:"certificate_chain" structs:"certificate_chain" mapstructure:"certificate_chain"`
	CreationTime     time.Time `json:"creation_time" structs:"creation_time" mapstructure:"creation_time"`
}

func (b *backend) pathPolicyRead(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	name := d.Get("name").(string)

	p, _, err := b.GetPolicy(ctx, PolicyRequest{
		Storage: req.Storage,
		Name:    name,
	}, b.GetRandomReader())
	if err != nil {
		return nil, err
	}
	if p == nil {
		return nil, nil
	}
	if !b.System().CachingDisabled() {
		p.Lock(false)
	}
	defer p.Unlock()

	contextRaw := d.Get("context").(string)
	var context []byte
	if len(contextRaw) != 0 {
		context, err = base64.StdEncoding.DecodeString(contextRaw)
		if err != nil {
			return logical.ErrorResponse("failed to base64-decode context"), logical.ErrInvalidRequest
		}
	}

	return b.formatKeyPolicy(p, context)
}

func (b *backend) formatKeyPolicy(p *Policy, context []byte) (*logical.Response, error) {
	// Return the response
	resp := &logical.Response{
		Data: map[string]interface{}{
			"name":                   p.Name,
			"type":                   p.Type.String(),
			"derived":                p.Derived,
			"deletion_allowed":       p.DeletionAllowed,
			"min_available_version":  p.MinAvailableVersion,
			"min_decryption_version": p.MinDecryptionVersion,
			"min_encryption_version": p.MinEncryptionVersion,
			"latest_version":         p.LatestVersion,
			"exportable":             p.Exportable,
			"allow_plaintext_backup": p.AllowPlaintextBackup,
			"supports_encryption":    p.Type.EncryptionSupported(),
			"supports_decryption":    p.Type.DecryptionSupported(),
			"supports_signing":       p.Type.SigningSupported(),
			"supports_derivation":    p.Type.DerivationSupported(),
			"auto_rotate_period":     int64(p.AutoRotatePeriod.Seconds()),
			"imported_key":           p.Imported,
		},
	}
	if p.KeySize != 0 {
		resp.Data["key_size"] = p.KeySize
	}

	if p.Imported {
		resp.Data["imported_key_allow_rotation"] = p.AllowImportedKeyRotation
	}

	if p.BackupInfo != nil {
		resp.Data["backup_info"] = map[string]interface{}{
			"time":    p.BackupInfo.Time,
			"version": p.BackupInfo.Version,
		}
	}
	if p.RestoreInfo != nil {
		resp.Data["restore_info"] = map[string]interface{}{
			"time":    p.RestoreInfo.Time,
			"version": p.RestoreInfo.Version,
		}
	}

	if p.Derived {
		switch p.KDF {
		case Kdf_hmac_sm3_counter:
			resp.Data["kdf"] = "hmac-sm3-counter"
			resp.Data["kdf_mode"] = "hmac-sm3-counter"
		case keysutil.Kdf_hkdf_sha256:
			resp.Data["kdf"] = "hkdf_sm3"
		}
		resp.Data["convergent_encryption"] = p.ConvergentEncryption
		if p.ConvergentEncryption {
			resp.Data["convergent_encryption_version"] = p.ConvergentVersion
		}
	}

	switch p.Type {
	case KeyType_SM4_GCM96:
		retKeys := map[string]int64{}
		for k, v := range p.Keys {
			retKeys[k] = v.DeprecatedCreationTime
		}
		resp.Data["keys"] = retKeys

	case KeyType_ECDSA_SM2:
		retKeys := map[string]map[string]interface{}{}
		for k, v := range p.Keys {
			key := asymKey{
				PublicKey:    v.FormattedPublicKey,
				CreationTime: v.CreationTime,
			}
			if key.CreationTime.IsZero() {
				key.CreationTime = time.Unix(v.DeprecatedCreationTime, 0)
			}
			if v.CertificateChain != nil {
				var pemCerts []string
				for _, derCertBytes := range v.CertificateChain {
					pemCert := strings.TrimSpace(string(pem.EncodeToMemory(
						&pem.Block{
							Type:  "CERTIFICATE",
							Bytes: derCertBytes,
						})))
					pemCerts = append(pemCerts, pemCert)
				}
				key.CertificateChain = strings.Join(pemCerts, "\n")
			}

			switch p.Type {
			case KeyType_ECDSA_SM2:
				key.Name = sm2.P256().Params().Name
			}

			retKeys[k] = structs.New(key).Map()
		}
		resp.Data["keys"] = retKeys
	}

	return resp, nil
}

func (b *backend) pathPolicyDelete(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	name := d.Get("name").(string)

	// Delete does its own locking
	err := b.lm.DeletePolicy(ctx, req.Storage, name)
	if err != nil {
		return logical.ErrorResponse(fmt.Sprintf("error deleting policy %s: %s", name, err)), err
	}

	return nil, nil
}

const pathPolicyHelpSyn = `Managed named encryption keys`

const pathPolicyHelpDesc = `
This path is used to manage the named keys that are available.
Doing a write with no value against a new named key will create
it using a randomly generated key.
`
