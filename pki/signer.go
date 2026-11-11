package pki

import (
	"bytes"
	"context"
	"crypto"
	"errors"
	"fmt"
	"strings"
	"sync"

	"github.com/emmansun/gmsm/sm2"
	"github.com/emmansun/gmsm/smx509"
	"github.com/hashicorp/vault/sdk/logical"
)

// issuerKey is what signs with the key of an authority. It is a crypto.Signer,
// so the builders of certificates and lists take it, and a crypto.MessageSigner,
// so the whole message reaches the key: an SM2 signature covers a digest that
// includes the public key and the identifier of the signer, so a key that is
// handed a digest computed elsewhere would produce one this mount cannot check.
//
// Close releases what the implementation opened to reach the key. The mount
// closes every signer it resolves, once, as soon as the bytes are signed, so a
// session of a token or a link to a key management service does not outlive the
// request that needed it. A key the mount holds has nothing to release, and
// says so rather than being a second kind of signer.
//
// Nothing here carries a context: the builders of certificates and lists hand
// the signer bytes and no deadline, so an implementation that talks over a
// network applies a limit of its own.
type issuerKey interface {
	crypto.Signer
	crypto.MessageSigner

	Close() error
}

// SignerProvider hands out the keys that are held elsewhere than the mount: in
// an HSM, a PKCS#11 token or a key management service. The mount never sees
// those keys, which is the point: it asks for a signer and hands it the bytes it
// was going to sign.
//
// A provider is registered by the program that embeds the plugin, because
// talking to an appliance takes the library of the appliance:
//
//	pki.RegisterSignerProvider("pkcs11", mypkcs11.Provider{Module: "/usr/lib/softhsm2.so"})
//
// Nothing in this repository registers one, so a mount that was not built with a
// provider signs only with the keys it holds itself.
type SignerProvider interface {
	// Signer returns the signer of one key. The reference is what the operator
	// wrote when the authority was imported. The mount closes what it is handed
	// once the bytes are signed, so a provider may open a session for each call
	// and let the close return it to a pool.
	Signer(ctx context.Context, reference string) (issuerKey, error)
}

var (
	signerProvidersMu sync.RWMutex
	signerProviders   = map[string]SignerProvider{}
)

// RegisterSignerProvider adds a provider under the name config/ca accepts. A
// second registration of the same name is refused: two implementations
// answering for one reference would be found only when a certificate had been
// signed with the wrong key.
func RegisterSignerProvider(name string, provider SignerProvider) error {
	name = strings.TrimSpace(name)
	if name == "" {
		return errors.New("a signer provider needs a name")
	}
	if provider == nil {
		return fmt.Errorf("signer provider %q is nil", name)
	}

	signerProvidersMu.Lock()
	defer signerProvidersMu.Unlock()

	if _, taken := signerProviders[name]; taken {
		return fmt.Errorf("a signer provider named %q is already registered", name)
	}
	signerProviders[name] = provider

	return nil
}

// signerProvider resolves a registered name. A provider that is not there is a
// failure of the mount rather than a mistake in the request, because the record
// naming it was written when it was.
func signerProvider(name string) (SignerProvider, error) {
	signerProvidersMu.RLock()
	defer signerProvidersMu.RUnlock()

	provider, ok := signerProviders[name]
	if !ok {
		return nil, fmt.Errorf("no signer provider named %q is registered in this plugin; the key of an external authority cannot be used without one", name)
	}

	return provider, nil
}

// issuerSigner resolves what signs with the key of an authority: the key the
// mount holds, or the one an appliance holds behind a provider. Both failures —
// a record that is gone and a key that cannot be resolved — mean the mount
// cannot sign, so they are errors rather than bad requests.
func (b *backend) issuerSigner(ctx context.Context, s logical.Storage, issuer *issuerEntry) (issuerKey, error) {
	entry, err := getJSON[keyEntry](ctx, s, keyPrefix+issuer.KeyID)
	if err != nil {
		return nil, err
	}
	if entry == nil {
		return nil, fmt.Errorf("the private key of issuer %s is missing", issuerLabel(issuer.ID, issuer))
	}

	var signer issuerKey
	if entry.Provider == "" {
		signer, err = localSigner(entry)
	} else {
		signer, err = externalSigner(ctx, issuer, entry)
	}
	if err != nil {
		return nil, err
	}

	if err := checkSignerKey(issuer, signer); err != nil {
		// The caller never sees a signer that failed the check, so the release
		// belongs here: a provider answering with the wrong key would otherwise
		// hold a session for every refused request.
		b.closeSigner(signer)
		return nil, err
	}

	return signer, nil
}

// closeSigner releases what a signer holds. The signature is made by the time
// this runs, so a close that fails cannot change what the request returns; it
// is recorded, because a provider that leaks a session is worth knowing about,
// but a request that produced its answer is not failed afterwards.
func (b *backend) closeSigner(signer issuerKey) {
	if err := signer.Close(); err != nil {
		b.Logger().Debug("could not release a signer: " + err.Error())
	}
}

// localSigner reads the key the mount holds. A record that carries neither a
// private key nor a provider is damaged rather than external.
func localSigner(entry *keyEntry) (localKey, error) {
	if len(entry.PrivateKey) == 0 {
		return localKey{}, errors.New("the key record carries no private key and names no provider")
	}

	key, err := smx509.ParsePKCS8PrivateKey(entry.PrivateKey)
	if err != nil {
		return localKey{}, fmt.Errorf("could not parse the issuer private key: %w", err)
	}

	sm2Key, ok := key.(*sm2.PrivateKey)
	if !ok {
		return localKey{}, fmt.Errorf("the issuer private key is a %T, not an SM2 key", key)
	}

	return localKey{PrivateKey: sm2Key}, nil
}

// localKey is a key the mount holds, wearing the close the seam asks for. It is
// a struct because a method cannot be added to the type of the key of the SM2
// package, and a key in storage has nothing to release.
type localKey struct {
	*sm2.PrivateKey
}

func (localKey) Close() error { return nil }

// externalSigner asks the provider of the key for a signer. The key itself never
// reaches the mount; what comes back signs the bytes it is handed.
func externalSigner(ctx context.Context, issuer *issuerEntry, entry *keyEntry) (issuerKey, error) {
	provider, err := signerProvider(entry.Provider)
	if err != nil {
		return nil, err
	}

	signer, err := provider.Signer(ctx, entry.Reference)
	if err != nil {
		return nil, fmt.Errorf("could not reach the signer %q of issuer %s: %w", entry.Reference, issuerLabel(issuer.ID, issuer), err)
	}
	if signer == nil {
		return nil, fmt.Errorf("signer provider %q answered with no signer for %q", entry.Provider, entry.Reference)
	}

	return signer, nil
}

// checkSignerKey refuses a signer whose public key is not the one in the
// certificate of the authority. The builders check a signature against the key
// the signer reports, so a certificate signed with the wrong key passes them and
// fails only when a client checks it, which is the one failure that cannot be
// repaired afterwards. An intermediate waiting for its certificate has nothing
// to compare, and is let through.
func checkSignerKey(issuer *issuerEntry, signer issuerKey) error {
	if len(issuer.Certificate) == 0 {
		return nil
	}

	cert, err := issuer.certificate()
	if err != nil {
		return err
	}
	want, err := smx509.MarshalPKIXPublicKey(cert.PublicKey)
	if err != nil {
		return fmt.Errorf("could not encode the public key of issuer %s: %w", issuerLabel(issuer.ID, issuer), err)
	}
	got, err := smx509.MarshalPKIXPublicKey(signer.Public())
	if err != nil {
		return fmt.Errorf("could not encode the public key the signer of issuer %s reports: %w", issuerLabel(issuer.ID, issuer), err)
	}
	if !bytes.Equal(want, got) {
		return fmt.Errorf("the signer of issuer %s holds a key its certificate does not carry", issuerLabel(issuer.ID, issuer))
	}

	return nil
}
