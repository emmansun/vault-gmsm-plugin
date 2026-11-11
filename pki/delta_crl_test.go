package pki

import (
	"bytes"
	"encoding/asn1"
	"math/big"
	"testing"
	"time"

	"github.com/emmansun/gmsm/smx509"
	"github.com/hashicorp/vault/sdk/logical"
)

// deltaBase reads the number of the full list a delta applies to, which is the
// whole point of the indicator extension: a client that cannot read it, or that
// holds a different list, must not take the entries for a complete answer.
func deltaBase(t *testing.T, list *smx509.RevocationList) *big.Int {
	t.Helper()

	for _, ext := range list.Extensions {
		if !ext.Id.Equal(oidExtensionDeltaCRLIndicator) {
			continue
		}
		if !ext.Critical {
			t.Fatal("the delta indicator is not critical, so a client that cannot read it would take the delta for a full list")
		}

		var base *big.Int
		if _, err := asn1.Unmarshal(ext.Value, &base); err != nil {
			t.Fatalf("the delta indicator is not a number: %v", err)
		}

		return base
	}

	t.Fatal("the delta carries no indicator of the list it applies to")
	return nil
}

// TestDeltaCRLFollowsTheFullList checks the parts a client relies on: the delta
// names its base, is numbered above it, and moves with it when a revocation
// renumbers the full list.
func TestDeltaCRLFollowsTheFullList(t *testing.T) {
	b, storage := newTestBackend(t)
	root := generateRoot(t, b, storage)
	writeWebRole(t, b, storage)

	full := parseRevocationList(t, mustRead(t, b, storage, "crl"))
	cached := mustRead(t, b, storage, "crl/delta")

	// A mount that revoked nothing still answers with a delta, because a client
	// that holds the full list has to be able to catch up from it.
	if got := cached.Data["base_number"]; got != full.Number.String() {
		t.Fatalf("the delta is based on %v, want %v", got, full.Number)
	}

	delta := parseRevocationList(t, cached)
	if delta.Number.Cmp(full.Number) <= 0 {
		t.Fatalf("the delta is numbered %v, want above the base %v", delta.Number, full.Number)
	}
	if got := deltaBase(t, delta); got.Cmp(full.Number) != 0 {
		t.Fatalf("the delta applies to list %v, want %v", got, full.Number)
	}
	if len(delta.RevokedCertificateEntries) != 0 {
		t.Fatalf("the delta names %d certificates on a mount that revoked nothing", len(delta.RevokedCertificateEntries))
	}
	if err := delta.CheckSignatureFrom(root); err != nil {
		t.Fatalf("the delta is not signed by the authority: %v", err)
	}

	// A delta is cached as DER like the full list, so two reads of an unchanged
	// one answer with the same bytes.
	der := mustRead(t, b, storage, "crl/delta/der")
	again := mustRead(t, b, storage, "crl/delta/der")
	if !bytes.Equal(der.Data[logical.HTTPRawBody].([]byte), again.Data[logical.HTTPRawBody].([]byte)) {
		t.Fatal("two reads of an unchanged delta answered with different bytes")
	}

	// A revocation renumbers the full list, and the delta follows the list it
	// is based on rather than the one it named before.
	_, issued := askAboutIssues(t, b, storage, "web.example.com")
	mustWrite(t, b, storage, "revoke", map[string]interface{}{
		"serial_number": pemData(t, issued.Data, "serial_number"),
	})

	renewed := parseRevocationList(t, mustRead(t, b, storage, "crl"))
	if renewed.Number.Cmp(full.Number) == 0 {
		t.Fatalf("the full list kept the number %v after a revocation", renewed.Number)
	}
	following := parseRevocationList(t, mustRead(t, b, storage, "crl/delta"))
	if got := deltaBase(t, following); got.Cmp(renewed.Number) != 0 {
		t.Fatalf("the delta applies to list %v after the revocation, want %v", got, renewed.Number)
	}
	if following.Number.Cmp(renewed.Number) <= 0 {
		t.Fatalf("the delta is numbered %v, want above the base %v", following.Number, renewed.Number)
	}
}

// TestDeltaCRLCarriesTheChangesBetweenFullLists is the deployment the deltas are
// for: the full list is published on a schedule and the changes in between are
// carried by the delta.
func TestDeltaCRLCarriesTheChangesBetweenFullLists(t *testing.T) {
	b, storage := newTestBackend(t)
	root := generateRoot(t, b, storage)
	writeWebRole(t, b, storage)

	published := parseRevocationList(t, mustRead(t, b, storage, "crl"))
	mustWrite(t, b, storage, "config/crl", map[string]interface{}{"auto_rebuild": false})

	_, issued := askAboutIssues(t, b, storage, "web.example.com")
	serial := pemData(t, issued.Data, "serial_number")
	mustWrite(t, b, storage, "revoke", map[string]interface{}{
		"serial_number":     serial,
		"revocation_reason": 1,
	})

	// The full list keeps its number, so a client that downloaded it is not told
	// to download it again.
	if got := mustRead(t, b, storage, "crl").Data["number"]; got != published.Number.String() {
		t.Fatalf("the full list is numbered %v with auto_rebuild off, want %v", got, published.Number)
	}

	delta := parseRevocationList(t, mustRead(t, b, storage, "crl/delta"))
	if got := deltaBase(t, delta); got.Cmp(published.Number) != 0 {
		t.Fatalf("the delta applies to list %v, want %v", got, published.Number)
	}
	entry := oneEntry(t, delta)
	if got := formatSerial(serialHex(entry.SerialNumber)); got != serial {
		t.Fatalf("the delta names %s, want %s", got, serial)
	}
	if entry.ReasonCode != 1 {
		t.Fatalf("the delta records reason %d, want 1 (keyCompromise)", entry.ReasonCode)
	}
	if err := delta.CheckSignatureFrom(root); err != nil {
		t.Fatalf("the delta is not signed by the authority: %v", err)
	}

	// A second revocation reaches a delta that is read after it, and the list
	// the client holds still does not move.
	_, second := askAboutIssues(t, b, storage, "second.example.com")
	secondSerial := pemData(t, second.Data, "serial_number")
	mustWrite(t, b, storage, "revoke", map[string]interface{}{
		"serial_number": secondSerial,
	})

	rotated := mustWrite(t, b, storage, "crl/rotate-delta", nil)
	if rotated.Data["base_number"] != published.Number.String() {
		t.Fatalf("rotating the delta named base %v, want %v", rotated.Data["base_number"], published.Number)
	}

	// A delta may repeat an entry rather than lose one: applying the same
	// revocation twice says the same thing once.
	both := parseRevocationList(t, mustRead(t, b, storage, "crl/delta"))
	if len(both.RevokedCertificateEntries) != 2 {
		t.Fatalf("the delta names %d certificates, want the two that were revoked", len(both.RevokedCertificateEntries))
	}

	// Rotating the full list moves the base and leaves the delta empty of what
	// the new list already carries.
	renewed := mustWrite(t, b, storage, "crl/rotate", nil)
	if renewed.Data["number"] == published.Number.String() {
		t.Fatalf("rotating the full list kept the number %v", published.Number)
	}

	following := parseRevocationList(t, mustRead(t, b, storage, "crl/delta"))
	if got := deltaBase(t, following); got.String() != renewed.Data["number"] {
		t.Fatalf("the delta applies to list %v, want %v", got, renewed.Data["number"])
	}
}

func TestDeltaCRLAnswersInEveryForm(t *testing.T) {
	b, storage := newTestBackend(t)
	generateRoot(t, b, storage)
	id := defaultIssuerID(t, b, storage)

	js := parseRevocationList(t, mustRead(t, b, storage, "crl/delta"))

	pemResp := mustRead(t, b, storage, "crl/delta/pem")
	if pemResp.Data[logical.HTTPContentType] != "application/pem-encoding" {
		t.Fatalf("the PEM delta is served as %v", pemResp.Data[logical.HTTPContentType])
	}
	if body := pemResp.Data[logical.HTTPRawBody].([]byte); !bytes.HasPrefix(body, []byte("-----BEGIN X509 CRL-----")) {
		t.Fatalf("crl/delta/pem answered with %q", body)
	}

	derResp := mustRead(t, b, storage, "crl/delta/der")
	if derResp.Data[logical.HTTPContentType] != "application/pkix-crl" {
		t.Fatalf("the DER delta is served as %v", derResp.Data[logical.HTTPContentType])
	}
	der, err := smx509.ParseRevocationList(derResp.Data[logical.HTTPRawBody].([]byte))
	if err != nil {
		t.Fatalf("the DER form is not a list: %v", err)
	}
	if der.Number.Cmp(js.Number) != 0 {
		t.Fatalf("the raw form is numbered %v, the JSON form %v", der.Number, js.Number)
	}

	// The per-issuer form answers the delta of the authority it names, which is
	// how a client finds the changes of a list published elsewhere.
	byIssuer := parseRevocationList(t, mustRead(t, b, storage, "issuer/"+id+"/crl/delta"))
	if byIssuer.Number.Cmp(js.Number) != 0 {
		t.Fatalf("issuer/:ref/crl/delta is numbered %v, want %v", byIssuer.Number, js.Number)
	}
	issuerDER := mustRead(t, b, storage, "issuer/"+id+"/crl/delta/der")
	if issuerDER.Data[logical.HTTPContentType] != "application/pkix-crl" {
		t.Fatalf("the DER delta of one issuer is served as %v", issuerDER.Data[logical.HTTPContentType])
	}
}

func TestDeltaCRLRefusesWhatItCannotName(t *testing.T) {
	b, storage := newTestBackend(t)

	mustRefuse(t, b, storage, logical.ReadOperation, "crl/delta", nil,
		"no certificate authority is configured")
	mustRefuse(t, b, storage, logical.UpdateOperation, "crl/rotate-delta", nil,
		"no certificate authority is configured")

	generateRoot(t, b, storage)

	mustRefuse(t, b, storage, logical.ReadOperation, "issuer/nobody/crl/delta", nil,
		`issuer "nobody" does not exist`)
	mustRefuse(t, b, storage, logical.ReadOperation, "issuer/nobody/crl/delta/pem", nil,
		`issuer "nobody" does not exist`)
	mustRefuse(t, b, storage, logical.UpdateOperation, "issuer/nobody/crl/rotate-delta", nil,
		`issuer "nobody" does not exist`)
}

// TestDeltaCRLGoesAwayWithItsIssuer keeps the promise that retiring an authority
// takes both of its lists with it, so nothing answers for a key that is gone.
func TestDeltaCRLGoesAwayWithItsIssuer(t *testing.T) {
	b, storage := newTestBackend(t)
	generateRoot(t, b, storage)
	previous := defaultIssuerID(t, b, storage)
	rotateAuthority(t, b, storage, "Test Root CA 2027")

	// The authority the mount replaced still answers with a delta of its own
	// until it is retired.
	mustRead(t, b, storage, "issuer/"+previous+"/crl/delta")

	mustDelete(t, b, storage, "issuer/"+previous)
	mustRefuse(t, b, storage, logical.ReadOperation, "issuer/"+previous+"/crl/delta", nil,
		`issuer "`+previous+`" does not exist`)
}

// TestConfigCRLSetsTheLifetimeOfTheLists covers the knob the lists read: what
// they claim to be current, and whether a read may sign a new one.
func TestConfigCRLSetsTheLifetimeOfTheLists(t *testing.T) {
	b, storage := newTestBackend(t)
	generateRoot(t, b, storage)

	// An unconfigured mount behaves as it did before the knob existed.
	config := mustRead(t, b, storage, "config/crl")
	if got := config.Data["expiry"]; got != crlValidity.String() {
		t.Fatalf("an unconfigured mount reports expiry %v, want %v", got, crlValidity)
	}
	if got := config.Data["auto_rebuild"]; got != true {
		t.Fatalf("an unconfigured mount reports auto_rebuild %v, want true", got)
	}

	mustWrite(t, b, storage, "config/crl", map[string]interface{}{"expiry": 3600})
	if got := mustRead(t, b, storage, "config/crl").Data["expiry"]; got != "1h0m0s" {
		t.Fatalf("the configuration reports expiry %v, want 1h0m0s", got)
	}

	full := parseRevocationList(t, mustRead(t, b, storage, "crl"))
	if held := full.NextUpdate.Sub(full.ThisUpdate); held != time.Hour {
		t.Fatalf("the full list holds for %v, want 1h", held)
	}
	delta := parseRevocationList(t, mustRead(t, b, storage, "crl/delta"))
	if held := delta.NextUpdate.Sub(delta.ThisUpdate); held != time.Hour {
		t.Fatalf("the delta holds for %v, want 1h", held)
	}

	// Zero keeps the default lifetime rather than signing a list that expired
	// before a client could read it.
	mustWrite(t, b, storage, "config/crl", map[string]interface{}{"expiry": 0})
	rotated := mustWrite(t, b, storage, "crl/rotate", nil)
	held := time.Unix(rotated.Data["next_update"].(int64), 0).Sub(time.Unix(rotated.Data["this_update"].(int64), 0))
	if held != crlValidity {
		t.Fatalf("a rotation with expiry 0 holds for %v, want %v", held, crlValidity)
	}

	mustWrite(t, b, storage, "config/crl", map[string]interface{}{"auto_rebuild": false})
	if got := mustRead(t, b, storage, "config/crl").Data["auto_rebuild"]; got != false {
		t.Fatalf("the configuration reports auto_rebuild %v, want false", got)
	}

	// A negative lifetime is refused before the handler sees it, because a list
	// that expired before it was signed is worse than none.
	mustRefuse(t, b, storage, logical.UpdateOperation, "config/crl", map[string]interface{}{
		"expiry": -1,
	}, "cannot provide negative value")
}
