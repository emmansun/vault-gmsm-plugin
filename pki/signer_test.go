package pki

import (
	"context"
	"crypto"
	"crypto/rand"
	"encoding/pem"
	"fmt"
	"io"
	"strings"
	"sync"
	"testing"
	"time"

	"crypto/x509/pkix"

	"github.com/emmansun/gmsm/sm2"
	"github.com/emmansun/gmsm/smx509"
	"github.com/emmansun/vault-gmsm-plugin/internal/ocspclient"
	"github.com/hashicorp/vault/sdk/logical"
)

// heldToken is a key an appliance holds: it signs what it is given and the
// caller never sees the private half. It counts its signatures so that a test
// can tell a key that was used from one that was only stored, and its closes so
// that a leaked session shows up as a number that does not add up.
type heldToken struct {
	mu     sync.Mutex
	key    *sm2.PrivateKey
	signs  int
	closes int
}

func (t *heldToken) Public() crypto.PublicKey { return &t.key.PublicKey }

func (t *heldToken) Sign(r io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	return t.key.Sign(r, digest, opts)
}

func (t *heldToken) SignMessage(r io.Reader, msg []byte, opts crypto.SignerOpts) ([]byte, error) {
	t.mu.Lock()
	t.signs++
	t.mu.Unlock()

	return t.key.SignMessage(r, msg, opts)
}

func (t *heldToken) Close() error {
	t.mu.Lock()
	t.closes++
	t.mu.Unlock()

	return nil
}

func (t *heldToken) signed() int {
	t.mu.Lock()
	defer t.mu.Unlock()

	return t.signs
}

func (t *heldToken) closed() int {
	t.mu.Lock()
	defer t.mu.Unlock()

	return t.closes
}

// testSignerProvider resolves a reference to one of the tokens it holds, which
// is what an HSM or a key management service does over a slower link. It counts
// the signers it hands out, which is what the mount has to release.
type testSignerProvider struct {
	tokens map[string]*heldToken

	mu    sync.Mutex
	opens int
}

func (p *testSignerProvider) Signer(_ context.Context, reference string) (issuerKey, error) {
	token, ok := p.tokens[reference]
	if !ok {
		return nil, fmt.Errorf("no key named %q is loaded", reference)
	}

	p.mu.Lock()
	p.opens++
	p.mu.Unlock()

	return token, nil
}

func (p *testSignerProvider) opened() int {
	p.mu.Lock()
	defer p.mu.Unlock()

	return p.opens
}

// registerProvider registers a provider under a name no other test uses, which
// is the one step an operator adds when they build the plugin.
func registerProvider(t *testing.T, provider SignerProvider) string {
	t.Helper()

	name := "test-" + t.Name()
	if err := RegisterSignerProvider(name, provider); err != nil {
		t.Fatalf("could not register the signer provider: %v", err)
	}

	return name
}

// externalAuthority creates an SM2 key and a self-signed CA certificate for it,
// and answers with the key and the PEM bundle that carries the certificate
// alone, which is what the operator of an appliance has.
func externalAuthority(t *testing.T, commonName string) (*sm2.PrivateKey, string) {
	t.Helper()

	key, err := sm2.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("could not generate the key of the external authority: %v", err)
	}

	identifier, err := subjectKeyID(&key.PublicKey)
	if err != nil {
		t.Fatalf("could not derive the subject key identifier: %v", err)
	}
	serial, err := newSerial()
	if err != nil {
		t.Fatalf("could not choose a serial: %v", err)
	}

	now := time.Now()
	template := &smx509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: commonName},
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.Add(24 * time.Hour),
		KeyUsage:              smx509.KeyUsageCertSign | smx509.KeyUsageCRLSign | smx509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		IsCA:                  true,
		SubjectKeyId:          identifier,
		AuthorityKeyId:        identifier,
		SignatureAlgorithm:    smx509.SM2WithSM3,
	}

	der, err := smx509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("could not create the certificate of the external authority: %v", err)
	}

	return key, pemCertificate(der)
}

// keyPEM encodes a key the way an operator hands one over, for the test that
// refuses a bundle carrying both.
func keyPEM(t *testing.T, key *sm2.PrivateKey) string {
	t.Helper()

	der, err := smx509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatalf("could not marshal the key: %v", err)
	}

	return string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}))
}

func importExternal(t *testing.T, b *backend, s logical.Storage, bundle, provider, reference string) *logical.Response {
	t.Helper()

	return mustWrite(t, b, s, "config/ca", map[string]interface{}{
		"pem_bundle": bundle,
		"provider":   provider,
		"reference":  reference,
	})
}

// TestExternalSignerSignsEverythingTheMountPublishes imports an authority whose
// key is held by a provider, then signs a certificate, a list, a delta and an
// answer with it. Each of them has to verify against the certificate that was
// imported, which is the whole contract of the seam.
func TestExternalSignerSignsEverythingTheMountPublishes(t *testing.T) {
	key, bundle := externalAuthority(t, "Externally Held CA")
	held := &heldToken{key: key}
	name := registerProvider(t, &testSignerProvider{tokens: map[string]*heldToken{"authority-1": held}})

	b, storage := newTestBackend(t)
	imported := importExternal(t, b, storage, bundle, name, "authority-1")
	root := parseCert(t, pemData(t, imported.Data, "certificate"))

	writeWebRole(t, b, storage)
	leaf, issued := askAboutIssues(t, b, storage, "web.example.com")
	if err := leaf.CheckSignatureFrom(root); err != nil {
		t.Fatalf("the certificate is not signed by the imported authority: %v", err)
	}

	if err := parseRevocationList(t, mustRead(t, b, storage, "crl")).CheckSignatureFrom(root); err != nil {
		t.Fatalf("the list is not signed by the imported authority: %v", err)
	}
	if err := parseRevocationList(t, mustRead(t, b, storage, "crl/delta")).CheckSignatureFrom(root); err != nil {
		t.Fatalf("the delta is not signed by the imported authority: %v", err)
	}

	answer, _ := askOCSP(t, b, storage, leaf.SerialNumber, root)
	if answer.CertStatus != ocspclient.CertGood {
		t.Fatalf("the responder reports the certificate as %v", answer.CertStatus)
	}

	// A revocation reaches the list the external key signed.
	serial := pemData(t, issued.Data, "serial_number")
	mustWrite(t, b, storage, "revoke", map[string]interface{}{
		"serial_number":     serial,
		"revocation_reason": 1,
	})
	if got := formatSerial(serialHex(oneEntry(t, parseRevocationList(t, mustRead(t, b, storage, "crl"))).SerialNumber)); got != serial {
		t.Fatalf("the list names %s, want %s", got, serial)
	}

	if held.signed() == 0 {
		t.Fatal("the provider was never asked to sign, so nothing went through it")
	}
}

// TestExternalAuthorityIsRefusedWhenItCannotSign checks that an authority whose
// key nobody can reach is refused at import rather than when the first
// certificate is requested for it.
func TestExternalAuthorityIsRefusedWhenItCannotSign(t *testing.T) {
	key, bundle := externalAuthority(t, "Externally Held CA")
	other, _ := externalAuthority(t, "Another CA")
	name := registerProvider(t, &testSignerProvider{tokens: map[string]*heldToken{
		"authority-1": {key: key},
		"other":       {key: other},
	}})

	b, storage := newTestBackend(t)

	// A bundle without a key has to say who holds one.
	mustRefuse(t, b, storage, logical.UpdateOperation, "config/ca", map[string]interface{}{
		"pem_bundle": bundle,
	}, "carries no private key")

	// A provider nobody registered cannot be used.
	mustRefuse(t, b, storage, logical.UpdateOperation, "config/ca", map[string]interface{}{
		"pem_bundle": bundle,
		"provider":   "not-registered",
	}, "no signer provider named \"not-registered\" is registered")

	// A provider that does not hold the reference cannot be used either.
	mustRefuse(t, b, storage, logical.UpdateOperation, "config/ca", map[string]interface{}{
		"pem_bundle": bundle,
		"provider":   name,
		"reference":  "nobody",
	}, "no key named \"nobody\" is loaded")

	// A key that is not the one the certificate carries would sign
	// certificates that verify only against themselves.
	mustRefuse(t, b, storage, logical.UpdateOperation, "config/ca", map[string]interface{}{
		"pem_bundle": bundle,
		"provider":   name,
		"reference":  "other",
	}, "holds a key its certificate does not carry")

	// A bundle that carries a key and names a provider says two things.
	mustRefuse(t, b, storage, logical.UpdateOperation, "config/ca", map[string]interface{}{
		"pem_bundle": keyPEM(t, key) + bundle,
		"provider":   name,
		"reference":  "authority-1",
	}, "import one or the other")

	// None of them left an authority behind.
	mustRefuse(t, b, storage, logical.ReadOperation, "ca", nil, "no certificate authority is configured")
}

// TestExternalSignerChecksTheKeyWheneverItSigns covers a provider that starts
// answering with another key after the import: the mount refuses to sign rather
// than produce certificates nobody can check.
func TestExternalSignerChecksTheKeyWheneverItSigns(t *testing.T) {
	key, bundle := externalAuthority(t, "Externally Held CA")
	tokens := map[string]*heldToken{"authority-1": {key: key}}
	name := registerProvider(t, &testSignerProvider{tokens: tokens})

	b, storage := newTestBackend(t)
	importExternal(t, b, storage, bundle, name, "authority-1")
	writeWebRole(t, b, storage)

	other, _ := externalAuthority(t, "Another CA")
	tokens["authority-1"] = &heldToken{key: other}

	resp, err := request(t, b, storage, logical.UpdateOperation, "issue/web", map[string]interface{}{
		"common_name": "web.example.com",
	})
	if err == nil && (resp == nil || !resp.IsError()) {
		t.Fatal("a certificate was issued with a key the imported certificate does not carry")
	}
	if err == nil || !strings.Contains(err.Error(), "holds a key its certificate does not carry") {
		t.Fatalf("the issue was refused with %v and %v, want the message about the key", resp, err)
	}
}

// TestExternalSignerReleasesWhatEveryRequestOpens makes every request that
// signs against a key a provider holds, including one the mount refuses because
// the provider started answering with another key, and checks that the provider
// is handed back as many signers as it handed out. A session per request that is
// never closed looks like this test failing rather than an appliance that runs
// out of sessions a week later.
func TestExternalSignerReleasesWhatEveryRequestOpens(t *testing.T) {
	key, bundle := externalAuthority(t, "Externally Held CA")
	held := &heldToken{key: key}
	provider := &testSignerProvider{tokens: map[string]*heldToken{"authority-1": held}}
	name := registerProvider(t, provider)

	b, storage := newTestBackend(t)
	imported := importExternal(t, b, storage, bundle, name, "authority-1")
	root := parseCert(t, pemData(t, imported.Data, "certificate"))

	writeWebRole(t, b, storage)
	leaf, issued := askAboutIssues(t, b, storage, "web.example.com")
	mustRead(t, b, storage, "crl")
	mustRead(t, b, storage, "crl/delta")
	askOCSP(t, b, storage, leaf.SerialNumber, root)
	mustWrite(t, b, storage, "revoke", map[string]interface{}{
		"serial_number":     pemData(t, issued.Data, "serial_number"),
		"revocation_reason": 1,
	})

	// The provider changes its answer, so the next resolution is the one the
	// mount refuses after it has the signer.
	other, _ := externalAuthority(t, "Another CA")
	replacement := &heldToken{key: other}
	provider.tokens["authority-1"] = replacement

	if resp, err := request(t, b, storage, logical.UpdateOperation, "issue/web", map[string]interface{}{
		"common_name": "web.example.com",
	}); err == nil && (resp == nil || !resp.IsError()) {
		t.Fatal("a certificate was issued with a key the imported certificate does not carry")
	}

	if provider.opened() == 0 {
		t.Fatal("the provider was never asked for a signer, so nothing was released either")
	}
	if got, want := provider.opened(), held.closed()+replacement.closed(); got != want {
		t.Fatalf("the provider handed out %d signers and %d were released", got, want)
	}
}

func TestRegisterSignerProviderRefusesTheSameNameTwice(t *testing.T) {
	provider := &testSignerProvider{}

	if err := RegisterSignerProvider("", provider); err == nil {
		t.Fatal("a provider without a name was registered")
	}

	name := "twice-" + t.Name()
	if err := RegisterSignerProvider(name, provider); err != nil {
		t.Fatalf("the first registration failed: %v", err)
	}
	if err := RegisterSignerProvider(name, provider); err == nil {
		t.Fatal("the same provider name was registered twice")
	}
}
