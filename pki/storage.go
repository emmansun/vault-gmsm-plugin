package pki

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"

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
	configCRLPath        = "config/crl"
)

// crlStorePath is where the cached list of one authority is kept, and
// deltaCRLStorePath where the changes since one of its lists are.
func crlStorePath(issuerID string) string { return crlPrefix + issuerID }

func deltaCRLStorePath(issuerID string) string { return crlPrefix + "delta/" + issuerID }

// issuerIndex points at the issuer the mount currently uses. It exists so that
// a future multi-issuer mount can add issuer records without moving any of the
// other keys.
type issuerIndex struct {
	ID string `json:"id"`
}

// The usages an authority can be given. An authority that names none is
// allowed all of them, which is what a mount written before the field existed
// holds, and what a generated root starts with.
const (
	usageIssuing  = "issuing-certificates"
	usageCRL      = "crl-signing"
	usageOCSP     = "ocsp-signing"
	usageReadOnly = "read-only"
)

// The ways a certificate that would outlive its authority can be handled:
// refuse it, shorten it, or let it stand.
const (
	leafNotAfterErr      = "err"
	leafNotAfterTruncate = "truncate"
	leafNotAfterPermit   = "permit"
)

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

	// Usage says what the key of this authority may be used for. An empty
	// list means everything, so an authority keeps working when the field is
	// never written.
	Usage []string `json:"usage,omitempty"`

	// LeafNotAfterBehavior decides what happens to a certificate that would
	// outlive the authority. An empty value shortens it, which is what the
	// mount did before the field existed.
	LeafNotAfterBehavior string `json:"leaf_not_after_behavior,omitempty"`

	// URLs are the addresses this authority publishes in its certificates,
	// which override the ones of config/urls one list at a time.
	URLs *urlConfig `json:"urls,omitempty"`
}

// allows answers whether the authority may be used for one thing. An empty
// usage allows everything, and read-only allows nothing.
func (e *issuerEntry) allows(usage string) bool {
	if len(e.Usage) == 0 {
		return true
	}

	for _, entry := range e.Usage {
		if entry == usage {
			return true
		}
	}

	return false
}

// checkUsage refuses an operation the usage of the authority does not cover.
// The refusal is a mistake in the request rather than a failure of the mount,
// so paths answer with it as a 400.
func (e *issuerEntry) checkUsage(usage, action string) error {
	if e.allows(usage) {
		return nil
	}

	return &issuerUsageError{issuer: e, action: action}
}

// usageList is what a read reports: the usages the authority was given, or the
// ones every authority has by default.
func (e *issuerEntry) usageList() []string {
	if len(e.Usage) == 0 {
		return []string{usageIssuing, usageCRL, usageOCSP}
	}

	return e.Usage
}

// leafBehavior is the effective handling of a certificate that would outlive
// the authority.
func (e *issuerEntry) leafBehavior() string {
	if e.LeafNotAfterBehavior == "" {
		return leafNotAfterTruncate
	}

	return e.LeafNotAfterBehavior
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

// keyEntry holds how the mount signs with an authority: the private half of a
// key it holds, or the reference to one an appliance holds. Only this record is
// seal wrapped, and a private key in it is the only secret that must never
// leave the mount.
type keyEntry struct {
	// PrivateKey is the PKCS#8 encoding of a key the mount holds. It is empty
	// when the key lives elsewhere.
	PrivateKey []byte `json:"private_key,omitempty"`

	// Provider names the signer implementation that holds the key, and
	// Reference is what that implementation needs to find it. Both are empty
	// for a key the mount holds itself.
	Provider  string `json:"provider,omitempty"`
	Reference string `json:"reference,omitempty"`
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

// revocationEntry records when a serial was revoked and why. It is the only
// input the CRL is built from, which is why a certificate the mount did not
// store can still be revoked. The expiration is copied from the certificate
// record when there is one, so a list stops naming the serial once the
// certificate can no longer be presented, and tidy can drop the record itself
// afterwards. The reason is a code of RFC 5280, and zero means unspecified,
// which is what a caller that names no reason asks for.
type revocationEntry struct {
	IssuerID       string `json:"issuer_id"`
	RevocationTime int64  `json:"revocation_time"`
	RFC3339        string `json:"revocation_time_rfc3339"`
	Expiration     int64  `json:"expiration,omitempty"`
	Reason         int    `json:"reason,omitempty"`
}

// hasExpired says whether the certificate this revocation names is past its
// expiration, which is what lets a list leave the serial out: a client rejects
// such a certificate on its dates without asking whether it was revoked. A
// record that states no expiration is kept, because the certificate behind it
// may still be presented.
func (r *revocationEntry) hasExpired(now time.Time) bool {
	return r.Expiration != 0 && !time.Unix(r.Expiration, 0).After(now)
}

// crlEntry caches a signed list. The DER has to be kept: an SM2 signature is
// randomised, so rebuilding it on every read would answer with different bytes
// for the same CRL number and defeat every cache in front of it.
type crlEntry struct {
	Number string `json:"number"`
	// BaseNumber is the number of the full list a delta is relative to, and
	// empty for a full list.
	BaseNumber string    `json:"base_number,omitempty"`
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

// crlConfig carries how long the mount says what it hands a client stays
// current. An answer of the responder states when it should be asked again, and
// how long that is belongs to the operator: a mount in front of a stapling
// cache can allow more than one whose clients poll it directly.
type crlConfig struct {
	// Expiry is how long a list claims to be current, and zero keeps the
	// default.
	Expiry int64 `json:"expiry"`

	OCSPExpiry int64 `json:"ocsp_expiry"`

	// AutoRebuild says whether a read may sign a list that went stale or that
	// a revocation has outdated. Nil is a mount written before the setting
	// existed, which always rebuilt.
	AutoRebuild *bool `json:"auto_rebuild,omitempty"`
}

// ocspLifetime is the value of ocsp_expiry as a duration. Zero is allowed and
// means that the answer does not state a next update at all.
func (c *crlConfig) ocspLifetime() time.Duration {
	return time.Duration(c.OCSPExpiry) * time.Second
}

// lifetime is how long a signed list claims to be current.
func (c *crlConfig) lifetime() time.Duration {
	if c.Expiry <= 0 {
		return crlValidity
	}

	return time.Duration(c.Expiry) * time.Second
}

// rebuilds says whether a read signs a list that went stale, or that a
// revocation has outdated. An operator turns it off when something else rotates
// the lists on a schedule of its own.
func (c *crlConfig) rebuilds() bool {
	return c.AutoRebuild == nil || *c.AutoRebuild
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

	return b.setIssuerDefault(ctx, s, id)
}

// setIssuerDefault points the mount at one of the authorities it holds.
func (b *backend) setIssuerDefault(ctx context.Context, s logical.Storage, id string) error {
	return putJSON(ctx, s, configIssuerPath, &issuerIndex{ID: id})
}

// issuers reads every authority the mount holds. The identifiers are sorted so
// that a decision taken over the whole set, such as which one takes over when
// the current one is retired, does not depend on the order storage answers in.
func (b *backend) issuers(ctx context.Context, s logical.Storage) ([]*issuerEntry, error) {
	ids, err := s.List(ctx, issuerPrefix)
	if err != nil {
		return nil, err
	}
	sort.Strings(ids)

	entries := make([]*issuerEntry, 0, len(ids))
	for _, id := range ids {
		issuer, err := b.issuerByID(ctx, s, id)
		if err != nil {
			return nil, err
		}
		if issuer != nil {
			entries = append(entries, issuer)
		}
	}

	return entries, nil
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

// belongsToIssuer says whether a record that names an issuer was signed by the
// authority in question. A record written before the mount recorded the issuer
// with every certificate belongs to the authority the mount signed with at the
// time, which is the default one.
func belongsToIssuer(recordIssuer, issuerID, defaultID string) bool {
	return recordIssuer == issuerID || (recordIssuer == "" && issuerID == defaultID)
}

// liveCertificates counts the certificates of one issuer that a client can
// still present, and reports the one that expires last. A certificate revoked
// early counts as well: what makes it harmless is its expiration, and retiring
// the authority takes the list that would have said it was revoked with it.
func (b *backend) liveCertificates(ctx context.Context, s logical.Storage, issuerID string) (int, time.Time, error) {
	defaultID, err := b.issuerID(ctx, s)
	if err != nil {
		return 0, time.Time{}, err
	}

	names, err := s.List(ctx, certPrefix)
	if err != nil {
		return 0, time.Time{}, err
	}

	now := time.Now()
	count := 0
	var latest time.Time
	for _, name := range names {
		record, err := b.certificateRecord(ctx, s, name)
		if err != nil {
			return 0, time.Time{}, err
		}
		if record == nil || !belongsToIssuer(record.IssuerID, issuerID, defaultID) {
			continue
		}
		if !record.Expiration.After(now) {
			continue
		}

		count++
		if record.Expiration.After(latest) {
			latest = record.Expiration
		}
	}

	return count, latest, nil
}

// retireIssuer removes one authority and the state only it can speak for: its
// key, its cached list, the revocations it recorded and the certificates it
// issued. What belongs to the other authorities is left alone. The mount signs
// with another authority afterwards, or with none when this was the last one.
func (b *backend) retireIssuer(ctx context.Context, s logical.Storage, issuer *issuerEntry) (int, int, error) {
	defaultID, err := b.issuerID(ctx, s)
	if err != nil {
		return 0, 0, err
	}

	certificates := 0
	names, err := s.List(ctx, certPrefix)
	if err != nil {
		return 0, 0, err
	}
	for _, name := range names {
		record, err := b.certificateRecord(ctx, s, name)
		if err != nil {
			return 0, 0, err
		}
		if record == nil || !belongsToIssuer(record.IssuerID, issuer.ID, defaultID) {
			continue
		}
		if err := s.Delete(ctx, certPrefix+name); err != nil {
			return certificates, 0, err
		}
		certificates++
	}

	revocations := 0
	names, err = s.List(ctx, revokedPrefix)
	if err != nil {
		return certificates, 0, err
	}
	for _, name := range names {
		record, err := b.revocationRecord(ctx, s, name)
		if err != nil {
			return certificates, revocations, err
		}
		if record == nil || !belongsToIssuer(record.IssuerID, issuer.ID, defaultID) {
			continue
		}
		if err := s.Delete(ctx, revokedPrefix+name); err != nil {
			return certificates, revocations, err
		}
		revocations++
	}

	paths := []string{crlStorePath(issuer.ID), deltaCRLStorePath(issuer.ID), issuerPrefix + issuer.ID}
	if issuer.KeyID != "" {
		paths = append(paths, keyPrefix+issuer.KeyID)
	}
	for _, path := range paths {
		if err := s.Delete(ctx, path); err != nil {
			return certificates, revocations, err
		}
	}

	return certificates, revocations, b.chooseDefaultIssuer(ctx, s, issuer.ID, defaultID)
}

// chooseDefaultIssuer points the mount at an authority that is still there
// after the one it signed with was retired. A mount left without any authority
// forgets the pointer as well, and takes the single list a mount written before
// rotation kept with it, because nothing will serve that list again.
func (b *backend) chooseDefaultIssuer(ctx context.Context, s logical.Storage, retiredID, defaultID string) error {
	remaining, err := b.issuers(ctx, s)
	if err != nil {
		return err
	}

	if len(remaining) == 0 {
		for _, path := range []string{configIssuerPath, crlPrefix + "current"} {
			if err := s.Delete(ctx, path); err != nil {
				return err
			}
		}
		return nil
	}

	if retiredID != defaultID {
		return nil
	}

	return b.setIssuerDefault(ctx, s, remaining[0].ID)
}

// currentCRL returns the cached CRL of one issuer, or nil when none has been
// built yet.
func (b *backend) currentCRL(ctx context.Context, s logical.Storage, issuerID string) (*crlEntry, error) {
	entry, err := getJSON[crlEntry](ctx, s, crlStorePath(issuerID))
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

// urlsFor is what a certificate of one authority publishes: the addresses
// written on that authority, and the ones of config/urls for every list it does
// not override.
func (b *backend) urlsFor(ctx context.Context, s logical.Storage, issuer *issuerEntry) (*urlConfig, error) {
	config, err := b.urls(ctx, s)
	if err != nil || issuer == nil || issuer.URLs == nil {
		return config, err
	}

	if len(issuer.URLs.IssuingCertificates) > 0 {
		config.IssuingCertificates = issuer.URLs.IssuingCertificates
	}
	if len(issuer.URLs.CRLDistributionPoints) > 0 {
		config.CRLDistributionPoints = issuer.URLs.CRLDistributionPoints
	}
	if len(issuer.URLs.OCSPServers) > 0 {
		config.OCSPServers = issuer.URLs.OCSPServers
	}

	return config, nil
}

// crlConfig returns how long an answer stays current, defaulting to what the
// mount said before the setting existed so that a mount that never wrote it
// behaves as it did.
func (b *backend) crlConfig(ctx context.Context, s logical.Storage) (*crlConfig, error) {
	config, err := getJSON[crlConfig](ctx, s, configCRLPath)
	if err != nil || config == nil {
		return &crlConfig{OCSPExpiry: int64(ocspValidity / time.Second)}, err
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
