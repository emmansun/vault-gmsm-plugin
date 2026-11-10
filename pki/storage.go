package pki

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/emmansun/gmsm/sm2"
	"github.com/emmansun/gmsm/smx509"
	"github.com/hashicorp/vault/sdk/logical"
)

// The mount has a namespace of its own in storage, so these prefixes are short
// on purpose. Each record keeps all the state for one thing: a key, the issuer
// that uses it, a role, a certificate the mount issued, a revocation or the
// cached CRL.
const (
	issuerPrefix  = "issuer/"
	keyPrefix     = "key/"
	rolePrefix    = "role/"
	certPrefix    = "cert/"
	revokedPrefix = "revoked/"
	crlPrefix     = "crl/"

	configIssuerPath     = "config/issuer"
	configPendingKeyPath = "config/pending-key"
	configURLsPath       = "config/urls"
)

// issuerIndex points at the issuer the mount currently uses. It exists so that
// a future multi-issuer mount can add issuer records without moving any of the
// other keys.
type issuerIndex struct {
	ID string `json:"id"`
}

// issuerEntry is the certificate the mount signs with, the chain above it and
// the key that belongs to it.
type issuerEntry struct {
	// ID is the storage key of the record. It is not written into it, because
	// the key already says what it is.
	ID          string    `json:"-"`
	Certificate []byte    `json:"certificate"`
	Chain       [][]byte  `json:"chain,omitempty"`
	KeyID       string    `json:"key_id"`
	Name        string    `json:"name,omitempty"`
	Serial      string    `json:"serial"`
	Created     time.Time `json:"created"`
}

func (e *issuerEntry) certificate() (*smx509.Certificate, error) {
	cert, err := smx509.ParseCertificate(e.Certificate)
	if err != nil {
		return nil, fmt.Errorf("could not parse the stored issuer certificate: %w", err)
	}
	return cert, nil
}

// chain returns the issuer certificate followed by the certificates above it,
// which is the order the API reports as ca_chain.
func (e *issuerEntry) chain() ([]*smx509.Certificate, error) {
	leaf, err := e.certificate()
	if err != nil {
		return nil, err
	}

	certs := []*smx509.Certificate{leaf}
	for _, der := range e.Chain {
		cert, err := smx509.ParseCertificate(der)
		if err != nil {
			return nil, fmt.Errorf("could not parse a certificate of the stored chain: %w", err)
		}
		certs = append(certs, cert)
	}

	return certs, nil
}

// keyEntry holds the private half of the issuer. Only this record is seal
// wrapped, and it is the only record that must never leave the mount.
type keyEntry struct {
	PrivateKey []byte `json:"private_key"`
}

// certEntry is a certificate the mount issued. The certificate is left out when
// the role asked for no_store, so the record still answers "was this serial
// issued here" without keeping the certificate itself.
type certEntry struct {
	Certificate []byte    `json:"certificate,omitempty"`
	Role        string    `json:"role,omitempty"`
	IssuerID    string    `json:"issuer_id,omitempty"`
	Issued      time.Time `json:"issued"`
	Expiration  time.Time `json:"expiration"`
}

// revocationEntry records when a serial was revoked. It is the only input the
// CRL is built from, which is why a certificate the mount did not store can
// still be revoked. The expiration is copied from the certificate record when
// there is one, so tidy can drop the entry once the CRL entry has aged out.
type revocationEntry struct {
	IssuerID       string `json:"issuer_id"`
	RevocationTime int64  `json:"revocation_time"`
	RFC3339        string `json:"revocation_time_rfc3339"`
	Expiration     int64  `json:"expiration,omitempty"`
}

// crlEntry caches the signed CRL. The DER has to be kept: an SM2 signature is
// randomised, so rebuilding it on every read would answer with different bytes
// for the same CRL number and defeat every cache in front of it.
type crlEntry struct {
	Number     string    `json:"number"`
	ThisUpdate time.Time `json:"this_update"`
	NextUpdate time.Time `json:"next_update"`
	DER        []byte    `json:"der,omitempty"`
	Dirty      bool      `json:"dirty"`
}

// urlConfig carries the addresses published in the certificates the mount
// issues: where to fetch the issuer, the CRL and an OCSP responder.
type urlConfig struct {
	IssuingCertificates   []string `json:"issuing_certificates"`
	CRLDistributionPoints []string `json:"crl_distribution_points"`
	OCSPServers           []string `json:"ocsp_servers"`
}

// getJSON decodes the record at path, returning nil when it does not exist.
func getJSON[T any](ctx context.Context, s logical.Storage, path string) (*T, error) {
	entry, err := s.Get(ctx, path)
	if err != nil {
		return nil, err
	}
	if entry == nil {
		return nil, nil
	}

	var value T
	if err := entry.DecodeJSON(&value); err != nil {
		return nil, fmt.Errorf("could not decode %s: %w", path, err)
	}

	return &value, nil
}

func putJSON(ctx context.Context, s logical.Storage, path string, value any) error {
	entry, err := logical.StorageEntryJSON(path, value)
	if err != nil {
		return err
	}

	return s.Put(ctx, entry)
}

// issuer returns the issuer the mount signs with, or nil when the mount holds
// no CA yet.
func (b *backend) issuer(ctx context.Context, s logical.Storage) (*issuerEntry, error) {
	index, err := getJSON[issuerIndex](ctx, s, configIssuerPath)
	if err != nil || index == nil {
		return nil, err
	}

	return b.issuerByID(ctx, s, index.ID)
}

func (b *backend) issuerByID(ctx context.Context, s logical.Storage, id string) (*issuerEntry, error) {
	issuer, err := getJSON[issuerEntry](ctx, s, issuerPrefix+id)
	if err != nil || issuer == nil {
		return issuer, err
	}

	issuer.ID = id
	return issuer, nil
}

// issuerByRef resolves what a role or a path names to one issuer record: the
// word default, the identifier of a record or the name an operator gave it. It
// answers with nothing but no error when the mount holds no authority at all,
// because that is a different mistake from naming an issuer that is not there.
func (b *backend) issuerByRef(ctx context.Context, s logical.Storage, ref string) (string, *issuerEntry, error) {
	ref = strings.TrimSpace(ref)
	if ref == "" || ref == issuerRefDefault {
		id, err := b.issuerID(ctx, s)
		if err != nil || id == "" {
			return "", nil, err
		}

		issuer, err := b.issuerByID(ctx, s, id)
		return id, issuer, err
	}

	issuer, err := b.issuerByID(ctx, s, ref)
	if err != nil || issuer != nil {
		return ref, issuer, err
	}

	// A ref is either an identifier or a name, and names are looked up by
	// reading the records: there are few issuers, and an index would be one
	// more thing to keep in step with them.
	ids, err := s.List(ctx, issuerPrefix)
	if err != nil {
		return "", nil, err
	}
	for _, id := range ids {
		candidate, err := b.issuerByID(ctx, s, id)
		if err != nil {
			return "", nil, err
		}
		if candidate != nil && candidate.Name == ref {
			return id, candidate, nil
		}
	}

	return "", nil, fmt.Errorf("issuer %q does not exist in this mount; list them with LIST issuers", ref)
}

// putIssuer stores the issuer and makes it the one this mount signs with.
func (b *backend) putIssuer(ctx context.Context, s logical.Storage, id string, issuer *issuerEntry) error {
	if err := putJSON(ctx, s, issuerPrefix+id, issuer); err != nil {
		return err
	}

	return putJSON(ctx, s, configIssuerPath, &issuerIndex{ID: id})
}

// issuerSigner loads the private key of an issuer and refuses to go on when it
// is missing or of the wrong shape. Both failures mean the mount is damaged, so
// they are reported as errors rather than as bad requests.
func (b *backend) issuerSigner(ctx context.Context, s logical.Storage, issuer *issuerEntry) (*sm2.PrivateKey, error) {
	entry, err := getJSON[keyEntry](ctx, s, keyPrefix+issuer.KeyID)
	if err != nil {
		return nil, err
	}
	if entry == nil {
		return nil, fmt.Errorf("the private key of issuer %q is missing", issuer.Name)
	}

	key, err := smx509.ParsePKCS8PrivateKey(entry.PrivateKey)
	if err != nil {
		return nil, fmt.Errorf("could not parse the issuer private key: %w", err)
	}

	sm2Key, ok := key.(*sm2.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("the issuer private key is a %T, not an SM2 key", key)
	}

	return sm2Key, nil
}

// pendingKeyID is the key of an intermediate waiting for its certificate.
func (b *backend) pendingKeyID(ctx context.Context, s logical.Storage) (string, error) {
	request, err := getJSON[issuerIndex](ctx, s, configPendingKeyPath)
	if err != nil || request == nil {
		return "", err
	}

	return request.ID, nil
}

func (b *backend) setPendingKeyID(ctx context.Context, s logical.Storage, id string) error {
	return putJSON(ctx, s, configPendingKeyPath, &issuerIndex{ID: id})
}

func (b *backend) role(ctx context.Context, s logical.Storage, name string) (*roleEntry, error) {
	return getJSON[roleEntry](ctx, s, rolePrefix+name)
}

// storeIssuedCertificate records a certificate the mount issued, so that
// cert/:serial answers for it and revoke/:serial can find its expiration. A
// role that asks for no_store keeps the record but not the certificate, which
// is what allows such a certificate to be revoked while leaving no copy of it
// in the mount. The issuer is recorded with it, so a revocation later reaches
// the list of the authority that signed it rather than whichever one is current
// by then.
func (b *backend) storeIssuedCertificate(ctx context.Context, s logical.Storage, cert *smx509.Certificate, roleName, issuerID string, keep bool) error {
	entry := &certEntry{
		Role:       roleName,
		IssuerID:   issuerID,
		Issued:     time.Now(),
		Expiration: cert.NotAfter,
	}
	if keep {
		entry.Certificate = cert.Raw
	}

	return putJSON(ctx, s, certPrefix+serialHex(cert.SerialNumber), entry)
}

// certificateRecord returns what the mount knows about a serial, keyed by the
// canonical hexadecimal form.
func (b *backend) certificateRecord(ctx context.Context, s logical.Storage, serial string) (*certEntry, error) {
	return getJSON[certEntry](ctx, s, certPrefix+serial)
}

func (b *backend) revocationRecord(ctx context.Context, s logical.Storage, serial string) (*revocationEntry, error) {
	return getJSON[revocationEntry](ctx, s, revokedPrefix+serial)
}

// currentCRL returns the cached CRL of one issuer, or nil when none has been
// built yet.
func (b *backend) currentCRL(ctx context.Context, s logical.Storage, issuerID string) (*crlEntry, error) {
	entry, err := getJSON[crlEntry](ctx, s, crlPrefix+issuerID)
	if err != nil || entry != nil {
		return entry, err
	}

	// A mount written before each authority kept its own list holds a single CRL
	// at crl/current. It belongs to the only issuer such a mount could have had;
	// with more than one there is nothing to inherit, and serving it under the
	// wrong authority would be worse than rebuilding the list.
	issuers, err := s.List(ctx, issuerPrefix)
	if err != nil || len(issuers) != 1 {
		return nil, err
	}

	return getJSON[crlEntry](ctx, s, crlPrefix+"current")
}

// urls returns the published addresses, defaulting to empty lists so callers do
// not have to check for a missing record.
func (b *backend) urls(ctx context.Context, s logical.Storage) (*urlConfig, error) {
	config, err := getJSON[urlConfig](ctx, s, configURLsPath)
	if err != nil || config == nil {
		return &urlConfig{}, err
	}

	return config, nil
}

// deletePrefix removes every record below prefix and returns how many it
// removed. A name that ends in a slash is a folder, which is walked rather than
// deleted.
func (b *backend) deletePrefix(ctx context.Context, s logical.Storage, prefix string) (int, error) {
	names, err := s.List(ctx, prefix)
	if err != nil {
		return 0, err
	}

	removed := 0
	for _, name := range names {
		if strings.HasSuffix(name, "/") {
			nested, err := b.deletePrefix(ctx, s, prefix+name)
			if err != nil {
				return removed, err
			}
			removed += nested
			continue
		}

		if err := s.Delete(ctx, prefix+name); err != nil {
			return removed, err
		}
		removed++
	}

	return removed, nil
}

// errNoIssuer is the answer to every operation that needs a CA in a mount that
// has none.
var errNoIssuer = errors.New("no certificate authority is configured in this mount; call root/generate/:type or intermediate/generate/:type first")

// issuerRefDefault is what a role or a path means when it names no issuer: the
// one this mount signs with.
const issuerRefDefault = "default"
