package pki

import (
	"context"
	"encoding/json"
	"net/http"
	"testing"

	"github.com/emmansun/vault-gmsm-plugin/internal/ocspclient"
	"github.com/hashicorp/vault/sdk/logical"
)

// stripIssuer rewrites a record as a mount written before certificates named
// their authority left it: everything the version of the time recorded, and no
// issuer_id. The fields are kept as they are encoded, so the record decodes the
// same way it did.
func stripIssuer(t *testing.T, s logical.Storage, path string) {
	t.Helper()

	ctx := context.Background()
	entry, err := s.Get(ctx, path)
	if err != nil || entry == nil {
		t.Fatalf("could not read %s: %v", path, err)
	}

	var fields map[string]json.RawMessage
	if err := entry.DecodeJSON(&fields); err != nil {
		t.Fatalf("could not decode %s: %v", path, err)
	}
	delete(fields, "issuer_id")

	raw, err := json.Marshal(fields)
	if err != nil {
		t.Fatalf("could not encode %s: %v", path, err)
	}
	if err := s.Put(ctx, &logical.StorageEntry{Key: path, Value: raw}); err != nil {
		t.Fatalf("could not write %s: %v", path, err)
	}
}

// storedKey turns the serial the API reports into the key the record of it is
// kept under.
func storedKey(t *testing.T, serial string) string {
	t.Helper()

	key, err := normalizeSerial(serial)
	if err != nil {
		t.Fatalf("the serial %q is not hexadecimal: %v", serial, err)
	}

	return key
}

// TestRecordsWrittenWithoutAnIssuerStayWithTheirAuthority covers a mount that is
// upgraded and then rotated. The record of a certificate issued before the mount
// recorded the issuer names none, and it belongs to the authority that signed at
// the time, not to the one the mount moves on to: handed to the new authority,
// the revocation would reach the wrong list, the responder of the authority that
// signed it would forget the certificate, and retiring that authority would look
// safe while the certificate was still out there.
func TestRecordsWrittenWithoutAnIssuerStayWithTheirAuthority(t *testing.T) {
	b, storage := newTestBackend(t)
	oldRoot := generateRoot(t, b, storage)
	oldID := defaultIssuerID(t, b, storage)
	writeWebRole(t, b, storage)

	leaf, issued := askAboutIssues(t, b, storage, "before.example.com")
	serial := pemData(t, issued.Data, "serial_number")
	stripIssuer(t, storage, certPrefix+storedKey(t, serial))

	// The authority the mount signs with is replaced from here on.
	newID := rotateAuthority(t, b, storage, "Rotated Root CA")
	if id := mustRead(t, b, storage, "cert/"+serial).Data["issuer_id"]; id != oldID {
		t.Fatalf("the record of a certificate issued before the rotation names %v, want %s", id, oldID)
	}

	mustWrite(t, b, storage, "revoke", map[string]interface{}{"serial_number": serial})

	oldList := parseRevocationList(t, mustRead(t, b, storage, "issuer/"+oldID+"/crl"))
	if got := formatSerial(serialHex(oneEntry(t, oldList).SerialNumber)); got != serial {
		t.Fatalf("the list of the authority that signed names %s, want %s", got, serial)
	}
	newList := parseRevocationList(t, mustRead(t, b, storage, "issuer/"+newID+"/crl"))
	if len(newList.RevokedCertificateEntries) != 0 {
		t.Fatalf("the list of the authority that took over names %d certificates", len(newList.RevokedCertificateEntries))
	}

	answer, code := askOCSP(t, b, storage, leaf.SerialNumber, oldRoot)
	if code != http.StatusOK || answer.CertStatus != ocspclient.CertRevoked {
		t.Fatalf("the responder of the authority that signed answered %d with %v", code, answer.CertStatus)
	}

	// The certificate is still that authority's, so retiring it has to wait for
	// it, and takes the record with it once it has expired.
	mustRefuse(t, b, storage, logical.DeleteOperation, "issuer/"+oldID, nil, "has not expired")

	expireCertificates(t, b, storage)
	retired := mustDelete(t, b, storage, "issuer/"+oldID)
	if retired.Data["certificates_removed"] != 1 {
		t.Fatalf("the retirement removed %v certificates", retired.Data["certificates_removed"])
	}
}

// TestRevocationsWrittenWithoutAnIssuerStayOnTheList covers the other half of
// the same upgrade: a revocation recorded before the mount named the authority
// has to reach the list of the authority that is signing, rather than no list at
// all.
func TestRevocationsWrittenWithoutAnIssuerStayOnTheList(t *testing.T) {
	b, storage := newTestBackend(t)
	generateRoot(t, b, storage)
	writeWebRole(t, b, storage)

	_, issued := askAboutIssues(t, b, storage, "web.example.com")
	serial := pemData(t, issued.Data, "serial_number")
	mustWrite(t, b, storage, "revoke", map[string]interface{}{"serial_number": serial})

	stripIssuer(t, storage, revokedPrefix+storedKey(t, serial))
	mustWrite(t, b, storage, "crl/rotate", nil)

	list := parseRevocationList(t, mustRead(t, b, storage, "crl"))
	if got := formatSerial(serialHex(oneEntry(t, list).SerialNumber)); got != serial {
		t.Fatalf("the list names %s, want %s", got, serial)
	}
}
