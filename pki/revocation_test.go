package pki

import (
	"context"
	"encoding/asn1"
	"testing"
	"time"

	"github.com/emmansun/gmsm/smx509"
	"github.com/emmansun/vault-gmsm-plugin/internal/ocspclient"
	"github.com/hashicorp/vault/sdk/logical"
)

// oidReasonCode is the extension of a list entry that states why a certificate
// was revoked.
var oidReasonCode = asn1.ObjectIdentifier{2, 5, 29, 21}

// oneEntry returns the single entry of a list, which is what these tests
// revoke.
func oneEntry(t *testing.T, list *smx509.RevocationList) smx509.RevocationListEntry {
	t.Helper()

	if len(list.RevokedCertificateEntries) != 1 {
		t.Fatalf("the list names %d certificates, want 1", len(list.RevokedCertificateEntries))
	}

	return list.RevokedCertificateEntries[0]
}

// TestRevokeCarriesTheReasonIntoTheListAndTheAnswer checks the whole way a
// reason travels: it is stored with the revocation, named by the list that a
// client downloads, and repeated by the responder.
func TestRevokeCarriesTheReasonIntoTheListAndTheAnswer(t *testing.T) {
	b, storage := newTestBackend(t)
	root := generateRoot(t, b, storage)
	writeWebRole(t, b, storage)

	leaf, issued := askAboutIssues(t, b, storage, "web.example.com")
	serial := pemData(t, issued.Data, "serial_number")

	revoked := mustWrite(t, b, storage, "revoke", map[string]interface{}{
		"serial_number":     serial,
		"revocation_reason": 1,
	})
	if reason := revoked.Data["revocation_reason"]; reason != 1 {
		t.Fatalf("the response reports reason %v, want 1", reason)
	}

	read := mustRead(t, b, storage, "cert/"+serial)
	if reason := read.Data["revocation_reason"]; reason != 1 {
		t.Fatalf("cert/:serial reports reason %v, want 1", reason)
	}

	list := parseRevocationList(t, mustRead(t, b, storage, "crl"))
	entry := oneEntry(t, list)
	if got := formatSerial(serialHex(entry.SerialNumber)); got != serial {
		t.Fatalf("the list names %s, want %s", got, serial)
	}
	if entry.ReasonCode != 1 {
		t.Fatalf("the list records reason %d, want 1 (keyCompromise)", entry.ReasonCode)
	}
	if err := list.CheckSignatureFrom(root); err != nil {
		t.Fatalf("the list is not signed by the authority: %v", err)
	}

	answer, _ := askOCSP(t, b, storage, leaf.SerialNumber, root)
	if answer.CertStatus != ocspclient.CertRevoked {
		t.Fatalf("the certificate is reported as %v", answer.CertStatus)
	}
	if answer.RevocationReason != 1 {
		t.Fatalf("the answer reports reason %d, want 1 (keyCompromise)", answer.RevocationReason)
	}
}

// TestRevokeAcceptsTheCertificateAndLeavesTheReasonOut covers the other way in:
// the caller hands over the certificate instead of its serial, and says nothing
// about a reason.
func TestRevokeAcceptsTheCertificateAndLeavesTheReasonOut(t *testing.T) {
	b, storage := newTestBackend(t)
	root := generateRoot(t, b, storage)
	writeWebRole(t, b, storage)

	leaf, issued := askAboutIssues(t, b, storage, "web.example.com")
	serial := pemData(t, issued.Data, "serial_number")

	revoked := mustWrite(t, b, storage, "revoke", map[string]interface{}{
		"certificate": pemData(t, issued.Data, "certificate"),
	})
	if reason := revoked.Data["revocation_reason"]; reason != 0 {
		t.Fatalf("a revocation without a reason reports %v", reason)
	}

	entry := oneEntry(t, parseRevocationList(t, mustRead(t, b, storage, "crl")))
	if got := formatSerial(serialHex(entry.SerialNumber)); got != serial {
		t.Fatalf("the list names %s, want %s", got, serial)
	}
	if entry.ReasonCode != 0 {
		t.Fatalf("the list records reason %d for a revocation that named none", entry.ReasonCode)
	}

	// An entry that carries no reason leaves the extension out, rather than
	// stating the code of an unspecified one.
	for _, ext := range entry.Extensions {
		if ext.Id.Equal(oidReasonCode) {
			t.Fatal("the entry carries a reason code of its own")
		}
	}

	answer, _ := askOCSP(t, b, storage, leaf.SerialNumber, root)
	if answer.CertStatus != ocspclient.CertRevoked {
		t.Fatalf("the certificate is reported as %v", answer.CertStatus)
	}
	if answer.RevocationReason != 0 {
		t.Fatalf("the answer reports reason %d for a revocation that named none", answer.RevocationReason)
	}
}

func TestRevokeRefusesWhatItCannotResolve(t *testing.T) {
	b, storage := newTestBackend(t)
	generateRoot(t, b, storage)
	writeWebRole(t, b, storage)

	_, issued := askAboutIssues(t, b, storage, "web.example.com")
	serial := pemData(t, issued.Data, "serial_number")
	certificate := pemData(t, issued.Data, "certificate")

	mustRefuse(t, b, storage, logical.UpdateOperation, "revoke", nil,
		"serial_number or certificate is required")

	// The two forms may name different certificates, so a caller that supplies
	// both is refused rather than guessed at.
	mustRefuse(t, b, storage, logical.UpdateOperation, "revoke", map[string]interface{}{
		"serial_number": serial,
		"certificate":   certificate,
	}, "not both")

	// 7 was never assigned by RFC 5280, and a list that carries it is read
	// differently by every client that meets one.
	mustRefuse(t, b, storage, logical.UpdateOperation, "revoke", map[string]interface{}{
		"serial_number":     serial,
		"revocation_reason": 7,
	}, "is not a reason code of RFC 5280")
	mustRefuse(t, b, storage, logical.UpdateOperation, "revoke", map[string]interface{}{
		"serial_number":     serial,
		"revocation_reason": 11,
	}, "is not a reason code of RFC 5280")

	mustRefuse(t, b, storage, logical.UpdateOperation, "revoke", map[string]interface{}{
		"certificate": "this is not a certificate",
	}, "could not decode a PEM block")
	mustRefuse(t, b, storage, logical.UpdateOperation, "revoke", map[string]interface{}{
		"serial_number": "0102",
	}, "has not been issued by this mount")
}

func TestRevokeTwiceKeepsTheFirstRevocation(t *testing.T) {
	b, storage := newTestBackend(t)
	generateRoot(t, b, storage)
	writeWebRole(t, b, storage)

	_, issued := askAboutIssues(t, b, storage, "web.example.com")
	serial := pemData(t, issued.Data, "serial_number")

	first := mustWrite(t, b, storage, "revoke", map[string]interface{}{
		"serial_number":     serial,
		"revocation_reason": 4,
	})
	second := mustWrite(t, b, storage, "revoke", map[string]interface{}{
		"serial_number":     serial,
		"revocation_reason": 5,
	})

	if len(second.Warnings) == 0 {
		t.Fatal("revoking a serial twice did not warn")
	}
	if second.Data["revocation_time"] != first.Data["revocation_time"] {
		t.Fatal("the second revocation changed the time of the first")
	}
	if reason := second.Data["revocation_reason"]; reason != 4 {
		t.Fatalf("the second revocation reports reason %v, want the first one, 4", reason)
	}

	// The list states what actually happened, which is the first revocation.
	if entry := oneEntry(t, parseRevocationList(t, mustRead(t, b, storage, "crl"))); entry.ReasonCode != 4 {
		t.Fatalf("the list records reason %d, want 4", entry.ReasonCode)
	}
}

// TestCertsRevokedListsAcrossAuthorities checks the listing a reconciliation
// against a database of subscribers needs: every revoked serial of the mount,
// whichever authority signed it.
func TestCertsRevokedListsAcrossAuthorities(t *testing.T) {
	b, storage := newTestBackend(t)
	generateRoot(t, b, storage)
	writeWebRole(t, b, storage)

	// A mount that revoked nothing answers with an empty listing, which is a
	// response without a key rather than a key that names nothing.
	empty, err := request(t, b, storage, logical.ListOperation, "certs/revoked", nil)
	if err != nil {
		t.Fatalf("certs/revoked failed: %v", err)
	}
	if keys, ok := empty.Data["keys"].([]string); ok && len(keys) != 0 {
		t.Fatalf("a mount that revoked nothing lists %v", keys)
	}

	before, issuedBefore := askAboutIssues(t, b, storage, "before.example.com")
	rotateAuthority(t, b, storage, "Test Root CA 2027")
	after, issuedAfter := askAboutIssues(t, b, storage, "after.example.com")

	for _, issued := range []*logical.Response{issuedBefore, issuedAfter} {
		mustWrite(t, b, storage, "revoke", map[string]interface{}{
			"serial_number": pemData(t, issued.Data, "serial_number"),
		})
	}

	listed := mustList(t, b, storage, "certs/revoked")
	if len(listed) != 2 {
		t.Fatalf("the listing names %v, want the two revoked serials", listed)
	}
	for _, serial := range []string{
		formatSerial(serialHex(before.SerialNumber)),
		formatSerial(serialHex(after.SerialNumber)),
	} {
		if !containsName(listed, serial) {
			t.Fatalf("the listing %v does not name %s", listed, serial)
		}
	}

	// Vault adds the slash to a list request before the mount sees it, so the
	// listing has to answer in that form too: the bare path is the one a test
	// writes, and the slashed one is the only one a client can reach.
	if slashed := mustList(t, b, storage, "certs/revoked/"); len(slashed) != 2 {
		t.Fatalf("the listing at certs/revoked/ names %v, want the two revoked serials", slashed)
	}

	// A certificate that was only issued is not a revoked one, so it stays out.
	askAboutIssues(t, b, storage, "kept.example.com")
	if listed := mustList(t, b, storage, "certs/revoked"); len(listed) != 2 {
		t.Fatalf("issuing a certificate changed the listing to %v", listed)
	}
}

// TestCRLStopsNamingCertificatesThatExpired checks what keeps the list from
// growing between tidy runs: a certificate that has expired is left out of the
// list the next time one is signed, because no client may present it any more,
// while the revocation itself stays recorded and keeps answering.
func TestCRLStopsNamingCertificatesThatExpired(t *testing.T) {
	b, storage := newTestBackend(t)
	root := generateRoot(t, b, storage)
	writeWebRole(t, b, storage)

	_, issuedLive := askAboutIssues(t, b, storage, "live.example.com")
	lapsed, issuedLapsed := askAboutIssues(t, b, storage, "lapsed.example.com")
	for _, issued := range []*logical.Response{issuedLive, issuedLapsed} {
		mustWrite(t, b, storage, "revoke", map[string]interface{}{
			"serial_number": pemData(t, issued.Data, "serial_number"),
		})
	}
	liveSerial := pemData(t, issuedLive.Data, "serial_number")
	lapsedSerial := pemData(t, issuedLapsed.Data, "serial_number")

	// The second certificate reaches the expiration it was issued with. The
	// revocation keeps the expiration it was given when it was recorded.
	ctx := context.Background()
	key, err := normalizeSerial(lapsedSerial)
	if err != nil {
		t.Fatalf("the serial %q is not hexadecimal: %v", lapsedSerial, err)
	}
	record, err := b.revocationRecord(ctx, storage, key)
	if err != nil || record == nil {
		t.Fatalf("could not read the revocation of %s: %v", lapsedSerial, err)
	}
	record.Expiration = time.Now().Add(-time.Hour).Unix()
	if err := putJSON(ctx, storage, revokedPrefix+key, record); err != nil {
		t.Fatalf("could not record the expiration of %s: %v", lapsedSerial, err)
	}

	entry := oneEntry(t, parseRevocationList(t, mustRead(t, b, storage, "crl")))
	if got := formatSerial(serialHex(entry.SerialNumber)); got != liveSerial {
		t.Fatalf("the list names %s, want the certificate that is still live", got)
	}

	// The revocation is not forgotten, only left out of the list: the listing,
	// the record and the responder still answer for the serial.
	if listed := mustList(t, b, storage, "certs/revoked"); !containsName(listed, lapsedSerial) {
		t.Fatalf("the listing %v no longer names %s", listed, lapsedSerial)
	}
	if revokedAt := mustRead(t, b, storage, "cert/"+lapsedSerial).Data["revocation_time"]; revokedAt == nil {
		t.Fatal("cert/:serial no longer reports the revocation")
	}
	answer, _ := askOCSP(t, b, storage, lapsed.SerialNumber, root)
	if answer.CertStatus != ocspclient.CertRevoked {
		t.Fatalf("the certificate is reported as %v", answer.CertStatus)
	}

	// A record without an expiration says nothing about when the certificate
	// lapses, so the list keeps naming it rather than guessing.
	record.Expiration = 0
	if err := putJSON(ctx, storage, revokedPrefix+key, record); err != nil {
		t.Fatalf("could not clear the expiration of %s: %v", lapsedSerial, err)
	}
	mustWrite(t, b, storage, "crl/rotate", nil)
	if list := parseRevocationList(t, mustRead(t, b, storage, "crl")); len(list.RevokedCertificateEntries) != 2 {
		t.Fatalf("the list names %d certificates, want the two revoked ones", len(list.RevokedCertificateEntries))
	}
}

func TestConfigCRLSetsHowLongAnAnswerHolds(t *testing.T) {
	b, storage := newTestBackend(t)
	root := generateRoot(t, b, storage)
	writeWebRole(t, b, storage)

	// An unconfigured mount answers the way it did before the knob existed.
	if got := mustRead(t, b, storage, "config/crl").Data["ocsp_expiry"]; got != ocspValidity.String() {
		t.Fatalf("an unconfigured mount reports ocsp_expiry %v, want %v", got, ocspValidity)
	}

	mustWrite(t, b, storage, "config/crl", map[string]interface{}{"ocsp_expiry": 90})
	if got := mustRead(t, b, storage, "config/crl").Data["ocsp_expiry"]; got != "1m30s" {
		t.Fatalf("the configuration reports ocsp_expiry %v, want 1m30s", got)
	}

	leaf, _ := askAboutIssues(t, b, storage, "web.example.com")
	answer, _ := askOCSP(t, b, storage, leaf.SerialNumber, root)
	if held := answer.NextUpdate.Sub(answer.ThisUpdate); held != 90*time.Second {
		t.Fatalf("the answer holds for %v, want 1m30s", held)
	}

	// Zero leaves the next update out: a client is told to ask again whenever
	// it wants, not that the answer expired the moment it arrived.
	mustWrite(t, b, storage, "config/crl", map[string]interface{}{"ocsp_expiry": 0})
	answer, _ = askOCSP(t, b, storage, leaf.SerialNumber, root)
	if !answer.NextUpdate.IsZero() {
		t.Fatalf("an answer without a lifetime states a next update at %s", answer.NextUpdate)
	}

	mustFail(t, b, storage, logical.UpdateOperation, "config/crl", map[string]interface{}{
		"ocsp_expiry": -1,
	})
}
