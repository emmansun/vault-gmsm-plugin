package gmsm

import (
	"bytes"
	"context"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"path"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/emmansun/gmsm/sm4"
	"github.com/hashicorp/errwrap"
	uuid "github.com/hashicorp/go-uuid"
	"github.com/hashicorp/vault/sdk/helper/errutil"
	"github.com/hashicorp/vault/sdk/helper/jsonutil"
	"github.com/hashicorp/vault/sdk/helper/kdf"
	"github.com/hashicorp/vault/sdk/helper/keysutil"
	"github.com/hashicorp/vault/sdk/logical"
	"golang.org/x/crypto/hkdf"
)

// Careful with iota; don't put anything before it in this const block because
// we need the default of zero to be the old-style KDF
const (
	Kdf_hmac_sha256_counter = iota // built-in helper
	Kdf_hkdf_sha256                // golang.org/x/crypto/hkdf
)

// Or this one...we need the default of zero to be the original SM4-GCM96
const (
	KeyType_SM4_GCM96 = iota
)

type KeyData struct {
	Policy       *Policy       `json:"policy"`
	ArchivedKeys *archivedKeys `json:"archived_keys"`
}

type KeyType int

func (kt KeyType) EncryptionSupported() bool {
	switch kt {
	case KeyType_SM4_GCM96:
		return true
	}
	return false
}

func (kt KeyType) DecryptionSupported() bool {
	switch kt {
	case KeyType_SM4_GCM96:
		return true
	}
	return false
}

func (kt KeyType) SigningSupported() bool {
	return false
}

func (kt KeyType) HashSignatureInput() bool {
	return false
}

func (kt KeyType) DerivationSupported() bool {
	switch kt {
	case KeyType_SM4_GCM96:
		return true
	}
	return false
}

func (kt KeyType) String() string {
	switch kt {
	case KeyType_SM4_GCM96:
		return "sm4-gcm96"
	}
	return "[unknown]"
}

// PolicyConfig is used to create a new policy
type PolicyConfig struct {
	// The name of the policy
	Name string `json:"name"`

	// The type of key
	Type KeyType

	// Derived keys MUST provide a context and the master underlying key is
	// never used.
	Derived              bool
	KDF                  int
	ConvergentEncryption bool

	// Whether the key is exportable
	Exportable bool

	// Whether the key is allowed to be deleted
	DeletionAllowed bool

	// AllowPlaintextBackup allows taking backup of the policy in plaintext
	AllowPlaintextBackup bool

	// VersionTemplate is used to prefix the ciphertext with information about
	// the key version. It must inclide {{version}} and a delimiter between the
	// version prefix and the ciphertext.
	VersionTemplate string

	// StoragePrefix is used to add a prefix when storing and retrieving the
	// policy object.
	StoragePrefix string
}

// keyEntryMap is used to allow JSON marshal/unmarshal
type keyEntryMap map[string]keysutil.KeyEntry

// Policy is the struct used to store metadata
type Policy struct {
	// This is a pointer on purpose: if we are running with cache disabled we
	// need to actually swap in the lock manager's lock for this policy with
	// the local lock.
	l *sync.RWMutex
	// writeLocked allows us to implement Lock() and Unlock()
	writeLocked bool
	// Stores whether it's been deleted. This acts as a guard for operations
	// that may write data, e.g. if one request rotates and that request is
	// served after a delete.
	deleted uint32

	Name string      `json:"name"`
	Key  []byte      `json:"key,omitempty"` //DEPRECATED
	Keys keyEntryMap `json:"keys"`

	// Derived keys MUST provide a context and the master underlying key is
	// never used. If convergent encryption is true, the context will be used
	// as the nonce as well.
	Derived              bool `json:"derived"`
	KDF                  int  `json:"kdf"`
	ConvergentEncryption bool `json:"convergent_encryption"`

	// Whether the key is exportable
	Exportable bool `json:"exportable"`

	// The minimum version of the key allowed to be used for decryption
	MinDecryptionVersion int `json:"min_decryption_version"`

	// The minimum version of the key allowed to be used for encryption
	MinEncryptionVersion int `json:"min_encryption_version"`

	// The latest key version in this policy
	LatestVersion int `json:"latest_version"`

	// The latest key version in the archive. We never delete these, so this is
	// a max.
	ArchiveVersion int `json:"archive_version"`

	// ArchiveMinVersion is the minimum version of the key in the archive.
	ArchiveMinVersion int `json:"archive_min_version"`

	// MinAvailableVersion is the minimum version of the key present. All key
	// versions before this would have been deleted.
	MinAvailableVersion int `json:"min_available_version"`

	// Whether the key is allowed to be deleted
	DeletionAllowed bool `json:"deletion_allowed"`

	// The version of the convergent nonce to use
	ConvergentVersion int `json:"convergent_version"`

	// The type of key
	Type KeyType `json:"type"`

	// BackupInfo indicates the information about the backup action taken on
	// this policy
	BackupInfo *keysutil.BackupInfo `json:"backup_info"`

	// RestoreInfo indicates the information about the restore action taken on
	// this policy
	RestoreInfo *keysutil.RestoreInfo `json:"restore_info"`

	// AllowPlaintextBackup allows taking backup of the policy in plaintext
	AllowPlaintextBackup bool `json:"allow_plaintext_backup"`

	// VersionTemplate is used to prefix the ciphertext with information about
	// the key version. It must inclide {{version}} and a delimiter between the
	// version prefix and the ciphertext.
	VersionTemplate string `json:"version_template"`

	// StoragePrefix is used to add a prefix when storing and retrieving the
	// policy object.
	StoragePrefix string `json:"storage_prefix"`

	// versionPrefixCache stores caches of version prefix strings and the split
	// version template.
	versionPrefixCache sync.Map
}

// NewPolicy takes a policy config and returns a Policy with those settings.
func NewPolicy(config PolicyConfig) *Policy {
	return &Policy{
		l:                    new(sync.RWMutex),
		Name:                 config.Name,
		Type:                 config.Type,
		Derived:              config.Derived,
		KDF:                  config.KDF,
		ConvergentEncryption: config.ConvergentEncryption,
		ConvergentVersion:    -1,
		Exportable:           config.Exportable,
		DeletionAllowed:      config.DeletionAllowed,
		AllowPlaintextBackup: config.AllowPlaintextBackup,
		VersionTemplate:      config.VersionTemplate,
		StoragePrefix:        config.StoragePrefix,
	}
}

// LoadPolicy will load a policy from the provided storage path and set the
// necessary un-exported variables. It is particularly useful when accessing a
// policy without the lock manager.
func LoadPolicy(ctx context.Context, s logical.Storage, path string) (*Policy, error) {
	raw, err := s.Get(ctx, path)
	if err != nil {
		return nil, err
	}
	if raw == nil {
		return nil, nil
	}

	var policy Policy
	err = jsonutil.DecodeJSON(raw.Value, &policy)
	if err != nil {
		return nil, err
	}

	policy.l = new(sync.RWMutex)

	return &policy, nil
}

func (p *Policy) Lock(exclusive bool) {
	if exclusive {
		p.l.Lock()
		p.writeLocked = true
	} else {
		p.l.RLock()
	}
}

func (p *Policy) Unlock() {
	if p.writeLocked {
		p.writeLocked = false
		p.l.Unlock()
	} else {
		p.l.RUnlock()
	}
}

// ArchivedKeys stores old keys. This is used to keep the key loading time sane
// when there are huge numbers of rotations.
type archivedKeys struct {
	Keys []keysutil.KeyEntry `json:"keys"`
}

func (p *Policy) LoadArchive(ctx context.Context, storage logical.Storage) (*archivedKeys, error) {
	archive := &archivedKeys{}

	raw, err := storage.Get(ctx, path.Join(p.StoragePrefix, "archive", p.Name))
	if err != nil {
		return nil, err
	}
	if raw == nil {
		archive.Keys = make([]keysutil.KeyEntry, 0)
		return archive, nil
	}

	if err := jsonutil.DecodeJSON(raw.Value, archive); err != nil {
		return nil, err
	}

	return archive, nil
}

func (p *Policy) storeArchive(ctx context.Context, storage logical.Storage, archive *archivedKeys) error {
	// Encode the policy
	buf, err := json.Marshal(archive)
	if err != nil {
		return err
	}

	// Write the policy into storage
	err = storage.Put(ctx, &logical.StorageEntry{
		Key:   path.Join(p.StoragePrefix, "archive", p.Name),
		Value: buf,
	})
	if err != nil {
		return err
	}

	return nil
}

// handleArchiving manages the movement of keys to and from the policy archive.
// This should *ONLY* be called from Persist() since it assumes that the policy
// will be persisted afterwards.
func (p *Policy) handleArchiving(ctx context.Context, storage logical.Storage) error {
	// We need to move keys that are no longer accessible to archivedKeys, and keys
	// that now need to be accessible back here.
	//
	// For safety, because there isn't really a good reason to, we never delete
	// keys from the archive even when we move them back.

	// Check if we have the latest minimum version in the current set of keys
	_, keysContainsMinimum := p.Keys[strconv.Itoa(p.MinDecryptionVersion)]

	// Sanity checks
	switch {
	case p.MinDecryptionVersion < 1:
		return fmt.Errorf("minimum decryption version of %d is less than 1", p.MinDecryptionVersion)
	case p.LatestVersion < 1:
		return fmt.Errorf("latest version of %d is less than 1", p.LatestVersion)
	case !keysContainsMinimum && p.ArchiveVersion != p.LatestVersion:
		return fmt.Errorf("need to move keys from archive but archive version not up-to-date")
	case p.ArchiveVersion > p.LatestVersion:
		return fmt.Errorf("archive version of %d is greater than the latest version %d",
			p.ArchiveVersion, p.LatestVersion)
	case p.MinEncryptionVersion > 0 && p.MinEncryptionVersion < p.MinDecryptionVersion:
		return fmt.Errorf("minimum decryption version of %d is greater than minimum encryption version %d",
			p.MinDecryptionVersion, p.MinEncryptionVersion)
	case p.MinDecryptionVersion > p.LatestVersion:
		return fmt.Errorf("minimum decryption version of %d is greater than the latest version %d",
			p.MinDecryptionVersion, p.LatestVersion)
	}

	archive, err := p.LoadArchive(ctx, storage)
	if err != nil {
		return err
	}

	if !keysContainsMinimum {
		// Need to move keys *from* archive
		for i := p.MinDecryptionVersion; i <= p.LatestVersion; i++ {
			p.Keys[strconv.Itoa(i)] = archive.Keys[i-p.MinAvailableVersion]
		}

		return nil
	}

	// Need to move keys *to* archive

	// We need a size that is equivalent to the latest version (number of keys)
	// but adding one since slice numbering starts at 0 and we're indexing by
	// key version
	if len(archive.Keys)+p.MinAvailableVersion < p.LatestVersion+1 {
		// Increase the size of the archive slice
		newKeys := make([]keysutil.KeyEntry, p.LatestVersion-p.MinAvailableVersion+1)
		copy(newKeys, archive.Keys)
		archive.Keys = newKeys
	}

	// We are storing all keys in the archive, so we ensure that it is up to
	// date up to p.LatestVersion
	for i := p.ArchiveVersion + 1; i <= p.LatestVersion; i++ {
		archive.Keys[i-p.MinAvailableVersion] = p.Keys[strconv.Itoa(i)]
		p.ArchiveVersion = i
	}

	// Trim the keys if required
	if p.ArchiveMinVersion < p.MinAvailableVersion {
		archive.Keys = archive.Keys[p.MinAvailableVersion-p.ArchiveMinVersion:]
		p.ArchiveMinVersion = p.MinAvailableVersion
	}

	err = p.storeArchive(ctx, storage, archive)
	if err != nil {
		return err
	}

	// Perform deletion afterwards so that if there is an error saving we
	// haven't messed with the current policy
	for i := p.LatestVersion - len(p.Keys) + 1; i < p.MinDecryptionVersion; i++ {
		delete(p.Keys, strconv.Itoa(i))
	}

	return nil
}

func (p *Policy) Persist(ctx context.Context, storage logical.Storage) (retErr error) {
	if atomic.LoadUint32(&p.deleted) == 1 {
		return errors.New("key has been deleted, not persisting")
	}

	// Other functions will take care of restoring other values; this is just
	// responsible for archiving and keys since the archive function can modify
	// keys. At the moment one of the other functions calling persist will also
	// roll back keys, but better safe than sorry and this doesn't happen
	// enough to worry about the speed tradeoff.
	priorArchiveVersion := p.ArchiveVersion
	var priorKeys keyEntryMap

	if p.Keys != nil {
		priorKeys = keyEntryMap{}
		for k, v := range p.Keys {
			priorKeys[k] = v
		}
	}

	defer func() {
		if retErr != nil {
			p.ArchiveVersion = priorArchiveVersion
			p.Keys = priorKeys
		}
	}()

	err := p.handleArchiving(ctx, storage)
	if err != nil {
		return err
	}

	// Encode the policy
	buf, err := p.Serialize()
	if err != nil {
		return err
	}

	// Write the policy into storage
	err = storage.Put(ctx, &logical.StorageEntry{
		Key:   path.Join(p.StoragePrefix, "policy", p.Name),
		Value: buf,
	})
	if err != nil {
		return err
	}

	return nil
}

func (p *Policy) Serialize() ([]byte, error) {
	return json.Marshal(p)
}

func (p *Policy) NeedsUpgrade() bool {
	// Ensure we've moved from Key -> Keys
	if p.Key != nil && len(p.Key) > 0 {
		return true
	}

	// With archiving, past assumptions about the length of the keys map are no
	// longer valid
	if p.LatestVersion == 0 && len(p.Keys) != 0 {
		return true
	}

	// We disallow setting the version to 0, since they start at 1 since moving
	// to rotate-able keys, so update if it's set to 0
	if p.MinDecryptionVersion == 0 {
		return true
	}

	// On first load after an upgrade, copy keys to the archive
	if p.ArchiveVersion == 0 {
		return true
	}

	// Need to write the version if zero; for version 3 on we set this to -1 to
	// ignore it since we store this information in each key entry
	if p.ConvergentEncryption && p.ConvergentVersion == 0 {
		return true
	}

	if p.Keys[strconv.Itoa(p.LatestVersion)].HMACKey == nil || len(p.Keys[strconv.Itoa(p.LatestVersion)].HMACKey) == 0 {
		return true
	}

	return false
}

func (p *Policy) Upgrade(ctx context.Context, storage logical.Storage, randReader io.Reader) (retErr error) {
	priorKey := p.Key
	priorLatestVersion := p.LatestVersion
	priorMinDecryptionVersion := p.MinDecryptionVersion
	priorConvergentVersion := p.ConvergentVersion
	var priorKeys keyEntryMap

	if p.Keys != nil {
		priorKeys = keyEntryMap{}
		for k, v := range p.Keys {
			priorKeys[k] = v
		}
	}

	defer func() {
		if retErr != nil {
			p.Key = priorKey
			p.LatestVersion = priorLatestVersion
			p.MinDecryptionVersion = priorMinDecryptionVersion
			p.ConvergentVersion = priorConvergentVersion
			p.Keys = priorKeys
		}
	}()

	persistNeeded := false
	// Ensure we've moved from Key -> Keys
	if p.Key != nil && len(p.Key) > 0 {
		p.MigrateKeyToKeysMap()
		persistNeeded = true
	}

	// With archiving, past assumptions about the length of the keys map are no
	// longer valid
	if p.LatestVersion == 0 && len(p.Keys) != 0 {
		p.LatestVersion = len(p.Keys)
		persistNeeded = true
	}

	// We disallow setting the version to 0, since they start at 1 since moving
	// to rotate-able keys, so update if it's set to 0
	if p.MinDecryptionVersion == 0 {
		p.MinDecryptionVersion = 1
		persistNeeded = true
	}

	// On first load after an upgrade, copy keys to the archive
	if p.ArchiveVersion == 0 {
		persistNeeded = true
	}

	if p.ConvergentEncryption && p.ConvergentVersion == 0 {
		p.ConvergentVersion = 1
		persistNeeded = true
	}

	if p.Keys[strconv.Itoa(p.LatestVersion)].HMACKey == nil || len(p.Keys[strconv.Itoa(p.LatestVersion)].HMACKey) == 0 {
		entry := p.Keys[strconv.Itoa(p.LatestVersion)]
		hmacKey, err := uuid.GenerateRandomBytesWithReader(32, randReader)
		if err != nil {
			return err
		}
		entry.HMACKey = hmacKey
		p.Keys[strconv.Itoa(p.LatestVersion)] = entry
		persistNeeded = true
	}

	if persistNeeded {
		err := p.Persist(ctx, storage)
		if err != nil {
			return err
		}
	}

	return nil
}

// GetKey is used to derive the encryption key that should be used depending
// on the policy. If derivation is disabled the raw key is used and no context
// is required, otherwise the KDF mode is used with the context to derive the
// proper key.
func (p *Policy) GetKey(context []byte, ver, numBytes int) ([]byte, error) {
	// Fast-path non-derived keys
	if !p.Derived {
		keyEntry, err := p.safeGetKeyEntry(ver)
		if err != nil {
			return nil, err
		}

		return keyEntry.Key, nil
	}

	return p.DeriveKey(context, nil, ver, numBytes)
}

// DeriveKey is used to derive a symmetric key given a context and salt.  This does not
// check the policies Derived flag, but just implements the derivation logic.  GetKey
// is responsible for switching on the policy config.
func (p *Policy) DeriveKey(context, salt []byte, ver int, numBytes int) ([]byte, error) {
	if !p.Type.DerivationSupported() {
		return nil, errutil.UserError{Err: fmt.Sprintf("derivation not supported for key type %v", p.Type)}
	}

	if p.Keys == nil || p.LatestVersion == 0 {
		return nil, errutil.InternalError{Err: "unable to access the key; no key versions found"}
	}

	if ver <= 0 || ver > p.LatestVersion {
		return nil, errutil.UserError{Err: "invalid key version"}
	}

	// Ensure a context is provided
	if len(context) == 0 {
		return nil, errutil.UserError{Err: "missing 'context' for key derivation; the key was created using a derived key, which means additional, per-request information must be included in order to perform operations with the key"}
	}

	keyEntry, err := p.safeGetKeyEntry(ver)
	if err != nil {
		return nil, err
	}

	switch p.KDF {
	case Kdf_hmac_sha256_counter:
		prf := kdf.HMACSHA256PRF
		prfLen := kdf.HMACSHA256PRFLen
		return kdf.CounterMode(prf, prfLen, keyEntry.Key, append(context, salt...), 256)

	case Kdf_hkdf_sha256:
		reader := hkdf.New(sha256.New, keyEntry.Key, salt, context)
		derBytes := bytes.NewBuffer(nil)
		derBytes.Grow(numBytes)
		limReader := &io.LimitedReader{
			R: reader,
			N: int64(numBytes),
		}

		switch p.Type {
		case KeyType_SM4_GCM96:
			n, err := derBytes.ReadFrom(limReader)
			if err != nil {
				return nil, errutil.InternalError{Err: fmt.Sprintf("error reading returned derived bytes: %v", err)}
			}
			if n != int64(numBytes) {
				return nil, errutil.InternalError{Err: fmt.Sprintf("unable to read enough derived bytes, needed %d, got %d", numBytes, n)}
			}
			return derBytes.Bytes(), nil

		default:
			return nil, errutil.InternalError{Err: "unsupported key type for derivation"}
		}

	default:
		return nil, errutil.InternalError{Err: "unsupported key derivation mode"}
	}
}

func (p *Policy) safeGetKeyEntry(ver int) (keysutil.KeyEntry, error) {
	keyVerStr := strconv.Itoa(ver)
	keyEntry, ok := p.Keys[keyVerStr]
	if !ok {
		return keyEntry, errutil.UserError{Err: "no such key version"}
	}
	return keyEntry, nil
}

func (p *Policy) convergentVersion(ver int) int {
	if !p.ConvergentEncryption {
		return 0
	}

	convergentVersion := p.ConvergentVersion
	if convergentVersion == 0 {
		// For some reason, not upgraded yet
		convergentVersion = 1
	}
	currKey := p.Keys[strconv.Itoa(ver)]
	if currKey.ConvergentVersion != 0 {
		convergentVersion = currKey.ConvergentVersion
	}

	return convergentVersion
}

// SymmetricOpts are the arguments to symmetric operations that are "optional", e.g.
// not always used.  This improves the aesthetics of calls to those functions.
type SymmetricOpts struct {
	// Whether to use convergent encryption
	Convergent bool
	// The version of the convergent encryption scheme
	ConvergentVersion int
	// The nonce, if not randomly generated
	Nonce []byte
	// Additional data to include in AEAD authentication
	AdditionalData []byte
	// The HMAC key, for generating IVs in convergent encryption
	HMACKey []byte
}

func (p *Policy) Encrypt(ver int, context, nonce []byte, value string) (string, error) {
	if !p.Type.EncryptionSupported() {
		return "", errutil.UserError{Err: fmt.Sprintf("message encryption not supported for key type %v", p.Type)}
	}

	// Decode the plaintext value
	plaintext, err := base64.StdEncoding.DecodeString(value)
	if err != nil {
		return "", errutil.UserError{Err: err.Error()}
	}

	switch {
	case ver == 0:
		ver = p.LatestVersion
	case ver < 0:
		return "", errutil.UserError{Err: "requested version for encryption is negative"}
	case ver > p.LatestVersion:
		return "", errutil.UserError{Err: "requested version for encryption is higher than the latest key version"}
	case ver < p.MinEncryptionVersion:
		return "", errutil.UserError{Err: "requested version for encryption is less than the minimum encryption key version"}
	}

	var ciphertext []byte

	switch p.Type {
	case KeyType_SM4_GCM96:
		hmacKey := context

		var encKey []byte
		var deriveHMAC bool

		encBytes := 16
		hmacBytes := 0
		if p.convergentVersion(ver) > 2 {
			deriveHMAC = true
			hmacBytes = 32
		}

		key, err := p.GetKey(context, ver, encBytes+hmacBytes)
		if err != nil {
			return "", err
		}

		if len(key) < encBytes+hmacBytes {
			return "", errutil.InternalError{Err: "could not derive key, length too small"}
		}

		encKey = key[:encBytes]
		if len(encKey) != encBytes {
			return "", errutil.InternalError{Err: "could not derive enc key, length not correct"}
		}
		if deriveHMAC {
			hmacKey = key[encBytes:]
			if len(hmacKey) != hmacBytes {
				return "", errutil.InternalError{Err: "could not derive hmac key, length not correct"}
			}
		}

		ciphertext, err = p.SymmetricEncryptRaw(ver, encKey, plaintext,
			SymmetricOpts{
				Convergent: p.ConvergentEncryption,
				HMACKey:    hmacKey,
				Nonce:      nonce,
			})

		if err != nil {
			return "", err
		}

	default:
		return "", errutil.InternalError{Err: fmt.Sprintf("unsupported key type %v", p.Type)}
	}

	// Convert to base64
	encoded := base64.StdEncoding.EncodeToString(ciphertext)

	// Prepend some information
	encoded = p.getVersionPrefix(ver) + encoded

	return encoded, nil
}

// Symmetrically encrypt a plaintext given the convergence configuration and appropriate keys
func (p *Policy) SymmetricEncryptRaw(ver int, encKey, plaintext []byte, opts SymmetricOpts) ([]byte, error) {
	var aead cipher.AEAD
	var err error
	nonce := opts.Nonce

	switch p.Type {
	case KeyType_SM4_GCM96:
		// Setup the cipher
		sm4Cipher, err := sm4.NewCipher(encKey)
		if err != nil {
			return nil, errutil.InternalError{Err: err.Error()}
		}

		// Setup the GCM AEAD
		gcm, err := cipher.NewGCM(sm4Cipher)
		if err != nil {
			return nil, errutil.InternalError{Err: err.Error()}
		}

		aead = gcm

	}

	if opts.Convergent {
		convergentVersion := p.convergentVersion(ver)
		switch convergentVersion {
		case 1:
			if len(opts.Nonce) != aead.NonceSize() {
				return nil, errutil.UserError{Err: fmt.Sprintf("base64-decoded nonce must be %d bytes long when using convergent encryption with this key", aead.NonceSize())}
			}
		case 2, 3:
			if len(opts.HMACKey) == 0 {
				return nil, errutil.InternalError{Err: fmt.Sprintf("invalid hmac key length of zero")}
			}
			nonceHmac := hmac.New(sha256.New, opts.HMACKey)
			nonceHmac.Write(plaintext)
			nonceSum := nonceHmac.Sum(nil)
			nonce = nonceSum[:aead.NonceSize()]
		default:
			return nil, errutil.InternalError{Err: fmt.Sprintf("unhandled convergent version %d", convergentVersion)}
		}
	} else if len(nonce) == 0 {
		// Compute random nonce
		nonce, err = uuid.GenerateRandomBytes(aead.NonceSize())
		if err != nil {
			return nil, errutil.InternalError{Err: err.Error()}
		}
	}

	// Encrypt and tag with AEAD
	ciphertext := aead.Seal(nil, nonce, plaintext, opts.AdditionalData)

	// Place the encrypted data after the nonce
	if !opts.Convergent || p.convergentVersion(ver) > 1 {
		ciphertext = append(nonce, ciphertext...)
	}
	return ciphertext, nil
}

func (p *Policy) HMACKey(version int) ([]byte, error) {
	switch {
	case version < 0:
		return nil, fmt.Errorf("key version does not exist (cannot be negative)")
	case version > p.LatestVersion:
		return nil, fmt.Errorf("key version does not exist; latest key version is %d", p.LatestVersion)
	}
	keyEntry, err := p.safeGetKeyEntry(version)
	if err != nil {
		return nil, err
	}
	if keyEntry.HMACKey == nil {
		return nil, fmt.Errorf("no HMAC key exists for that key version")
	}

	return keyEntry.HMACKey, nil
}

// Rotate rotates the policy and persists it to storage.
// If the rotation partially fails, the policy state will be restored.
func (p *Policy) Rotate(ctx context.Context, storage logical.Storage, randReader io.Reader) (retErr error) {
	priorLatestVersion := p.LatestVersion
	priorMinDecryptionVersion := p.MinDecryptionVersion
	var priorKeys keyEntryMap

	if p.Keys != nil {
		priorKeys = keyEntryMap{}
		for k, v := range p.Keys {
			priorKeys[k] = v
		}
	}

	defer func() {
		if retErr != nil {
			p.LatestVersion = priorLatestVersion
			p.MinDecryptionVersion = priorMinDecryptionVersion
			p.Keys = priorKeys
		}
	}()

	if err := p.RotateInMemory(randReader); err != nil {
		return err
	}

	return p.Persist(ctx, storage)
}

// RotateInMemory rotates the policy but does not persist it to storage.
func (p *Policy) RotateInMemory(randReader io.Reader) (retErr error) {
	now := time.Now()
	entry := keysutil.KeyEntry{
		CreationTime:           now,
		DeprecatedCreationTime: now.Unix(),
	}

	hmacKey, err := uuid.GenerateRandomBytesWithReader(32, randReader)
	if err != nil {
		return err
	}
	entry.HMACKey = hmacKey

	switch p.Type {
	case KeyType_SM4_GCM96:
		// Default to 128 bit key
		numBytes := 16
		newKey, err := uuid.GenerateRandomBytesWithReader(numBytes, randReader)
		if err != nil {
			return err
		}
		entry.Key = newKey
	}

	if p.ConvergentEncryption {
		if p.ConvergentVersion == -1 || p.ConvergentVersion > 1 {
			entry.ConvergentVersion = currentConvergentVersion
		}
	}

	p.LatestVersion += 1

	if p.Keys == nil {
		// This is an initial key rotation when generating a new policy. We
		// don't need to call migrate here because if we've called getPolicy to
		// get the policy in the first place it will have been run.
		p.Keys = keyEntryMap{}
	}
	p.Keys[strconv.Itoa(p.LatestVersion)] = entry

	// This ensures that with new key creations min decryption version is set
	// to 1 rather than the int default of 0, since keys start at 1 (either
	// fresh or after migration to the key map)
	if p.MinDecryptionVersion == 0 {
		p.MinDecryptionVersion = 1
	}

	return nil
}

func (p *Policy) MigrateKeyToKeysMap() {
	now := time.Now()
	p.Keys = keyEntryMap{
		"1": keysutil.KeyEntry{
			Key:                    p.Key,
			CreationTime:           now,
			DeprecatedCreationTime: now.Unix(),
		},
	}
	p.Key = nil
}

// Backup should be called with an exclusive lock held on the policy
func (p *Policy) Backup(ctx context.Context, storage logical.Storage) (out string, retErr error) {
	if !p.Exportable {
		return "", fmt.Errorf("exporting is disallowed on the policy")
	}

	if !p.AllowPlaintextBackup {
		return "", fmt.Errorf("plaintext backup is disallowed on the policy")
	}

	priorBackupInfo := p.BackupInfo

	defer func() {
		if retErr != nil {
			p.BackupInfo = priorBackupInfo
		}
	}()

	// Create a record of this backup operation in the policy
	p.BackupInfo = &keysutil.BackupInfo{
		Time:    time.Now(),
		Version: p.LatestVersion,
	}
	err := p.Persist(ctx, storage)
	if err != nil {
		return "", errwrap.Wrapf("failed to persist policy with backup info: {{err}}", err)
	}

	// Load the archive only after persisting the policy as the archive can get
	// adjusted while persisting the policy
	archivedKeys, err := p.LoadArchive(ctx, storage)
	if err != nil {
		return "", err
	}

	keyData := &KeyData{
		Policy:       p,
		ArchivedKeys: archivedKeys,
	}

	encodedBackup, err := jsonutil.EncodeJSON(keyData)
	if err != nil {
		return "", err
	}

	return base64.StdEncoding.EncodeToString(encodedBackup), nil
}

func (p *Policy) getTemplateParts() ([]string, error) {
	partsRaw, ok := p.versionPrefixCache.Load("template-parts")
	if ok {
		return partsRaw.([]string), nil
	}

	template := p.VersionTemplate
	if template == "" {
		template = keysutil.DefaultVersionTemplate
	}

	tplParts := strings.Split(template, "{{version}}")
	if len(tplParts) != 2 {
		return nil, errutil.InternalError{Err: "error parsing version template"}
	}

	p.versionPrefixCache.Store("template-parts", tplParts)
	return tplParts, nil
}

func (p *Policy) getVersionPrefix(ver int) string {
	prefixRaw, ok := p.versionPrefixCache.Load(ver)
	if ok {
		return prefixRaw.(string)
	}

	template := p.VersionTemplate
	if template == "" {
		template = keysutil.DefaultVersionTemplate
	}

	prefix := strings.Replace(template, "{{version}}", strconv.Itoa(ver), -1)
	p.versionPrefixCache.Store(ver, prefix)

	return prefix
}

func (p *Policy) Decrypt(context, nonce []byte, value string) (string, error) {
	if !p.Type.DecryptionSupported() {
		return "", errutil.UserError{Err: fmt.Sprintf("message decryption not supported for key type %v", p.Type)}
	}

	tplParts, err := p.getTemplateParts()
	if err != nil {
		return "", err
	}

	// Verify the prefix
	if !strings.HasPrefix(value, tplParts[0]) {
		return "", errutil.UserError{Err: "invalid ciphertext: no prefix"}
	}

	splitVerCiphertext := strings.SplitN(strings.TrimPrefix(value, tplParts[0]), tplParts[1], 2)
	if len(splitVerCiphertext) != 2 {
		return "", errutil.UserError{Err: "invalid ciphertext: wrong number of fields"}
	}

	ver, err := strconv.Atoi(splitVerCiphertext[0])
	if err != nil {
		return "", errutil.UserError{Err: "invalid ciphertext: version number could not be decoded"}
	}

	if ver == 0 {
		// Compatibility mode with initial implementation, where keys start at
		// zero
		ver = 1
	}

	if ver > p.LatestVersion {
		return "", errutil.UserError{Err: "invalid ciphertext: version is too new"}
	}

	if p.MinDecryptionVersion > 0 && ver < p.MinDecryptionVersion {
		return "", errutil.UserError{Err: keysutil.ErrTooOld}
	}

	convergentVersion := p.convergentVersion(ver)
	if convergentVersion == 1 && (nonce == nil || len(nonce) == 0) {
		return "", errutil.UserError{Err: "invalid convergent nonce supplied"}
	}

	// Decode the base64
	decoded, err := base64.StdEncoding.DecodeString(splitVerCiphertext[1])
	if err != nil {
		return "", errutil.UserError{Err: "invalid ciphertext: could not decode base64"}
	}

	var plain []byte

	switch p.Type {
	case KeyType_SM4_GCM96:
		numBytes := 16

		encKey, err := p.GetKey(context, ver, numBytes)
		if err != nil {
			return "", err
		}

		if len(encKey) != numBytes {
			return "", errutil.InternalError{Err: "could not derive enc key, length not correct"}
		}

		plain, err = p.SymmetricDecryptRaw(encKey, decoded,
			SymmetricOpts{
				Convergent:        p.ConvergentEncryption,
				ConvergentVersion: p.ConvergentVersion,
			})
		if err != nil {
			return "", err
		}

	default:
		return "", errutil.InternalError{Err: fmt.Sprintf("unsupported key type %v", p.Type)}
	}

	return base64.StdEncoding.EncodeToString(plain), nil
}

// Symmetrically decrypt a ciphertext given the convergence configuration and appropriate keys
func (p *Policy) SymmetricDecryptRaw(encKey, ciphertext []byte, opts SymmetricOpts) ([]byte, error) {
	var aead cipher.AEAD
	var nonce []byte

	switch p.Type {
	case KeyType_SM4_GCM96:
		// Setup the cipher
		sm4Cipher, err := sm4.NewCipher(encKey)
		if err != nil {
			return nil, errutil.InternalError{Err: err.Error()}
		}

		// Setup the GCM AEAD
		gcm, err := cipher.NewGCM(sm4Cipher)
		if err != nil {
			return nil, errutil.InternalError{Err: err.Error()}
		}

		aead = gcm
	}

	if len(ciphertext) < aead.NonceSize() {
		return nil, errutil.UserError{Err: "invalid ciphertext length"}
	}

	// Extract the nonce and ciphertext
	var trueCT []byte
	if opts.Convergent && opts.ConvergentVersion == 1 {
		trueCT = ciphertext
	} else {
		nonce = ciphertext[:aead.NonceSize()]
		trueCT = ciphertext[aead.NonceSize():]
	}

	// Verify and Decrypt
	plain, err := aead.Open(nil, nonce, trueCT, opts.AdditionalData)
	if err != nil {
		return nil, err
	}
	return plain, nil
}
