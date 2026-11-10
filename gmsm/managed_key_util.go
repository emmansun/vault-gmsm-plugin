package gmsm

import (
	"context"
	"errors"

	"github.com/hashicorp/vault/sdk/helper/keysutil"
	"github.com/hashicorp/vault/sdk/logical"
)

// The managed key helpers below are required by the policy code paths that
// handle KeyType_MANAGED_KEY. Managed keys are a Vault enterprise feature, so
// every helper reports that the plugin cannot serve the request.
var errManagedKeysUnsupported = errors.New("managed keys are not supported by this plugin")

func (p *Policy) decryptWithManagedKey(params keysutil.ManagedKeyParameters, keyEntry keysutil.KeyEntry, ciphertext []byte, nonce []byte, aad []byte) (plaintext []byte, err error) {
	return nil, errManagedKeysUnsupported
}

func (p *Policy) encryptWithManagedKey(params keysutil.ManagedKeyParameters, keyEntry keysutil.KeyEntry, plaintext []byte, nonce []byte, aad []byte) (ciphertext []byte, err error) {
	return nil, errManagedKeysUnsupported
}

func (p *Policy) signWithManagedKey(options *keysutil.SigningOptions, keyEntry keysutil.KeyEntry, input []byte) (sig []byte, err error) {
	return nil, errManagedKeysUnsupported
}

func (p *Policy) verifyWithManagedKey(options *SigningOptions, keyEntry keysutil.KeyEntry, input, sig []byte) (verified bool, err error) {
	return false, errManagedKeysUnsupported
}

func (p *Policy) HMACWithManagedKey(ctx context.Context, ver int, managedKeySystemView logical.ManagedKeySystemView, backendUUID string, algorithm string, data []byte) (hmacBytes []byte, err error) {
	return nil, errManagedKeysUnsupported
}

func (p *Policy) RotateManagedKey(ctx context.Context, storage logical.Storage, managedKeyUUID string) error {
	return errManagedKeysUnsupported
}

func GetManagedKeyUUID(ctx context.Context, b *backend, keyName string, keyId string) (uuid string, err error) {
	return "", errManagedKeysUnsupported
}
