package gmsm

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"strconv"
	"strings"

	"github.com/emmansun/gmsm/sm2"
	"github.com/emmansun/gmsm/smx509"
	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/helper/keysutil"
	"github.com/hashicorp/vault/sdk/logical"
)

const (
	exportTypeEncryptionKey    = "encryption-key"
	exportTypeSigningKey       = "signing-key"
	exportTypeHMACKey          = "hmac-key"
	exportTypePublicKey        = "public-key"
	exportTypeCertificateChain = "certificate-chain"
	exportTypeCMACKey          = "cmac-key"
)

func (b *backend) pathExportKeys() *framework.Path {
	return &framework.Path{
		Pattern: "export/" + framework.GenericNameRegex("type") + "/" + framework.GenericNameRegex("name") + framework.OptionalParamRegex("version"),
		DisplayAttrs: &framework.DisplayAttributes{
			OperationPrefix: operationPrefix,
			OperationVerb:   "export",
			OperationSuffix: "key|key-version",
		},
		Fields: map[string]*framework.FieldSchema{
			"type": {
				Type:        framework.TypeString,
				Description: "Type of key to export (encryption-key, signing-key, hmac-key)",
			},
			"name": {
				Type:        framework.TypeString,
				Description: "Name of the key",
			},
			"version": {
				Type:        framework.TypeString,
				Description: "Version of the key",
			},
		},

		Callbacks: map[logical.Operation]framework.OperationFunc{
			logical.ReadOperation: b.pathPolicyExportRead,
		},

		HelpSynopsis:    pathExportHelpSyn,
		HelpDescription: pathExportHelpDesc,
	}
}

func (b *backend) pathPolicyExportRead(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	exportType := d.Get("type").(string)
	name := d.Get("name").(string)
	version := d.Get("version").(string)

	supportExport := true
	switch exportType {
	case exportTypeEncryptionKey:
	case exportTypeSigningKey:
	case exportTypeHMACKey:
	case exportTypeCMACKey:
		// this is enterprise function only
		supportExport = false
	case exportTypePublicKey:
	case exportTypeCertificateChain:
		supportExport = true
	default:
		return logical.ErrorResponse(fmt.Sprintf("invalid export type: %s", exportType)), logical.ErrInvalidRequest
	}

	if !supportExport {
		return logical.ErrorResponse(ErrCmacEntOnly.Error()), logical.ErrInvalidRequest
	}

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

	if !p.Exportable && exportType != exportTypePublicKey && exportType != exportTypeCertificateChain {
		return logical.ErrorResponse("private key material is not exportable"), nil
	}

	switch exportType {
	case exportTypeEncryptionKey:
		if !p.Type.EncryptionSupported() {
			return logical.ErrorResponse("encryption not supported for the key"), logical.ErrInvalidRequest
		}
	case exportTypeSigningKey:
		if !p.Type.SigningSupported() {
			return logical.ErrorResponse("signing not supported for the key"), logical.ErrInvalidRequest
		}
	case exportTypeCertificateChain:
		if !p.Type.SigningSupported() {
			return logical.ErrorResponse("certificate chain not supported for keys that do not support signing"), logical.ErrInvalidRequest
		}
	}

	retKeys := map[string]string{}
	switch version {
	case "":
		for k, v := range p.Keys {
			exportKey, err := getExportKey(p, &v, exportType)
			if err != nil {
				return nil, err
			}
			retKeys[k] = exportKey
		}

	default:
		var versionValue int
		if version == "latest" {
			versionValue = p.LatestVersion
		} else {
			version = strings.TrimPrefix(version, "v")
			versionValue, err = strconv.Atoi(version)
			if err != nil {
				return logical.ErrorResponse("invalid key version"), logical.ErrInvalidRequest
			}
		}

		if versionValue < p.MinDecryptionVersion {
			return logical.ErrorResponse("version for export is below minimum decryption version"), logical.ErrInvalidRequest
		}
		key, ok := p.Keys[strconv.Itoa(versionValue)]
		if !ok {
			return logical.ErrorResponse("version does not exist or cannot be found"), logical.ErrInvalidRequest
		}

		exportKey, err := getExportKey(p, &key, exportType)
		if err != nil {
			return nil, err
		}

		retKeys[strconv.Itoa(versionValue)] = exportKey
	}

	resp := &logical.Response{
		Data: map[string]interface{}{
			"name": p.Name,
			"type": p.Type.String(),
			"keys": retKeys,
		},
	}

	return resp, nil
}

func getExportKey(policy *Policy, key *keysutil.KeyEntry, exportType string) (string, error) {
	if policy == nil {
		return "", errors.New("nil policy provided")
	}

	switch exportType {
	case exportTypeHMACKey:
		return strings.TrimSpace(base64.StdEncoding.EncodeToString(key.HMACKey)), nil

	case exportTypeEncryptionKey:
		switch policy.Type {
		case KeyType_SM4_GCM96:
			return strings.TrimSpace(base64.StdEncoding.EncodeToString(key.Key)), nil
		case KeyType_ECDSA_SM2:
			ecKey, err := keyEntryToECPrivateKey(key, sm2.P256())
			if err != nil {
				return "", err
			}
			return ecKey, nil
		}
	case exportTypeSigningKey:
		ecKey, err := keyEntryToECPrivateKey(key, sm2.P256())
		if err != nil {
			return "", err
		}
		return ecKey, nil

	case exportTypePublicKey:
		switch policy.Type {
		case KeyType_ECDSA_SM2:
			ecKey, err := keyEntryToECPublicKey(key, sm2.P256())
			if err != nil {
				return "", err
			}
			return ecKey, nil
		}
	case exportTypeCertificateChain:
		if key.CertificateChain == nil {
			return "", errors.New("selected key version does not have a certificate chain imported")
		}

		var pemCerts []string
		for _, derCertBytes := range key.CertificateChain {
			pemCert := strings.TrimSpace(string(pem.EncodeToMemory(
				&pem.Block{
					Type:  "CERTIFICATE",
					Bytes: derCertBytes,
				})))
			pemCerts = append(pemCerts, pemCert)
		}
		certChain := strings.Join(pemCerts, "\n")

		return certChain, nil
	case exportTypeCMACKey:
		switch policy.Type {
		case KeyType_SM4_CMAC:
			return strings.TrimSpace(base64.StdEncoding.EncodeToString(key.Key)), nil
		}
	}

	return "", fmt.Errorf("unknown key type %v", policy.Type)
}

func keyEntryToECPrivateKey(k *keysutil.KeyEntry, curve elliptic.Curve) (string, error) {
	if k == nil {
		return "", errors.New("nil KeyEntry provided")
	}

	privKey := &ecdsa.PrivateKey{
		PublicKey: ecdsa.PublicKey{
			Curve: curve,
			X:     k.EC_X,
			Y:     k.EC_Y,
		},
		D: k.EC_D,
	}
	ecder, err := smx509.MarshalECPrivateKey(privKey)
	if err != nil {
		return "", err
	}
	if ecder == nil {
		return "", errors.New("no data returned when marshalling to private key")
	}

	block := pem.Block{
		Type:  "EC PRIVATE KEY",
		Bytes: ecder,
	}
	return strings.TrimSpace(string(pem.EncodeToMemory(&block))), nil
}

func keyEntryToECPublicKey(k *keysutil.KeyEntry, curve elliptic.Curve) (string, error) {
	if k == nil {
		return "", errors.New("nil KeyEntry provided")
	}

	pubKey := ecdsa.PublicKey{
		Curve: curve,
		X:     k.EC_X,
		Y:     k.EC_Y,
	}

	blockType := "PUBLIC KEY"
	derBytes, err := smx509.MarshalPKIXPublicKey(&pubKey)
	if err != nil {
		return "", err
	}

	pemBlock := pem.Block{
		Type:  blockType,
		Bytes: derBytes,
	}

	return strings.TrimSpace(string(pem.EncodeToMemory(&pemBlock))), nil
}

const pathExportHelpSyn = `Export named encryption or signing key`

const pathExportHelpDesc = `
This path is used to export the named keys that are configured as
exportable.
`
