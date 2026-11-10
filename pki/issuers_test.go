package pki

import (
	"bytes"
	"context"
	"strings"
	"testing"
	"time"

	"github.com/hashicorp/vault/sdk/logical"
)

// defaultIssuerID reads the identifier of the issuer the mount signs with, which
// the API reports rather than the storage key a client never sees.
func defaultIssuerID(t *testing.T, b *backend, s logical.Storage) string {
	t.Helper()

	resp := mustRead(t, b, s, "ca")
	id, ok := resp.Data["issuer_id"].(string)
	if !ok || id == "" {
		t.Fatal("the authority read has no issuer identifier")
	}

	return id
}

func TestIssuerListAndRead(t *testing.T) {
	b, storage := newTestBackend(t)

	// A mount with no authority answers with an empty listing rather than a key
	// that names nothing.
	empty, err := request(t, b, storage, logical.ListOperation, "issuers", nil)
	if err != nil {
		t.Fatalf("issuers failed: %v", err)
	}
	if keys, ok := empty.Data["keys"].([]string); ok && len(keys) != 0 {
		t.Fatalf("a mount without an authority lists %v", keys)
	}
	mustFail(t, b, storage, logical.ReadOperation, "issuer/default", nil)

	root := generateRoot(t, b, storage)
	id := defaultIssuerID(t, b, storage)

	if keys := mustList(t, b, storage, "issuers"); len(keys) != 1 || keys[0] != id {
		t.Fatalf("the mount lists %v, want only %s", keys, id)
	}

	byID := mustRead(t, b, storage, "issuer/"+id)
	if byID.Data["issuer_id"] != id {
		t.Fatalf("the issuer reads back as %v", byID.Data["issuer_id"])
	}
	if byID.Data["is_default"] != true {
		t.Fatal("the only issuer is not reported as the one in use")
	}

	wantSerial := formatSerial(serialHex(root.SerialNumber))
	if byID.Data["serial_number"] != wantSerial {
		t.Fatalf("the issuer reports serial %v, want %s", byID.Data["serial_number"], wantSerial)
	}
	readBack := parseCert(t, pemData(t, byID.Data, "certificate"))
	if !bytes.Equal(readBack.Raw, root.Raw) {
		t.Fatal("the issuer certificate is not the one ca reports")
	}

	// The word default addresses the same record, which is what a role names
	// when it does not care which authority signs.
	byDefault := mustRead(t, b, storage, "issuer/default")
	if byDefault.Data["issuer_id"] != id {
		t.Fatalf("issuer/default reads back as %v, want %s", byDefault.Data["issuer_id"], id)
	}

	mustFail(t, b, storage, logical.ReadOperation, "issuer/not-there", nil)
}

func TestRoleNamesTheIssuer(t *testing.T) {
	b, storage := newTestBackend(t)
	generateRoot(t, b, storage)
	id := defaultIssuerID(t, b, storage)

	// A role is policy, so it can name an issuer that is not there yet; the
	// mistake is reported when a certificate is asked for.
	mustWrite(t, b, storage, "roles/later", map[string]interface{}{
		"allowed_domains":  "example.com",
		"allow_subdomains": true,
		"issuer_ref":       "not-there",
	})

	resp, err := request(t, b, storage, logical.UpdateOperation, "issue/later", map[string]interface{}{
		"common_name": "web.example.com",
	})
	if err == nil && (resp == nil || !resp.IsError()) {
		t.Fatal("an issue naming an issuer that does not exist was accepted")
	}
	if resp == nil || !strings.Contains(resp.Error().Error(), `issuer "not-there" does not exist`) {
		t.Fatalf("the unknown issuer was reported as %v", resp)
	}

	mustWrite(t, b, storage, "roles/current", map[string]interface{}{
		"allowed_domains":  "example.com",
		"allow_subdomains": true,
		"issuer_ref":       "default",
	})
	issued := mustWrite(t, b, storage, "issue/current", map[string]interface{}{
		"common_name": "web.example.com",
	})
	if issued.Data["issuer_id"] != id {
		t.Fatalf("the certificate names issuer %v, want %s", issued.Data["issuer_id"], id)
	}
}

func TestIssuedCertificateRemembersItsIssuer(t *testing.T) {
	b, storage := newTestBackend(t)
	generateRoot(t, b, storage)
	writeWebRole(t, b, storage)
	id := defaultIssuerID(t, b, storage)

	issued := mustWrite(t, b, storage, "issue/web", map[string]interface{}{
		"common_name": "web.example.com",
	})
	serial := pemData(t, issued.Data, "serial_number")

	key, err := normalizeSerial(serial)
	if err != nil {
		t.Fatalf("the issued serial %q is not hexadecimal: %v", serial, err)
	}
	record, err := b.certificateRecord(context.Background(), storage, key)
	if err != nil {
		t.Fatalf("could not read the certificate record: %v", err)
	}
	if record == nil {
		t.Fatal("the certificate was not stored")
	}
	if record.IssuerID != id {
		t.Fatalf("the record names issuer %q, want %s", record.IssuerID, id)
	}

	read := mustRead(t, b, storage, "cert/"+serial)
	if read.Data["issuer_id"] != id {
		t.Fatalf("cert/:serial names issuer %v, want %s", read.Data["issuer_id"], id)
	}
}

func TestCRLBelongsToItsIssuer(t *testing.T) {
	b, storage := newTestBackend(t)
	generateRoot(t, b, storage)
	writeWebRole(t, b, storage)
	id := defaultIssuerID(t, b, storage)

	issued := mustWrite(t, b, storage, "issue/web", map[string]interface{}{
		"common_name": "web.example.com",
	})
	mustWrite(t, b, storage, "revoke", map[string]interface{}{
		"serial_number": pemData(t, issued.Data, "serial_number"),
	})

	if number := mustRead(t, b, storage, "crl").Data["number"]; number != "1" {
		t.Fatalf("the first list is numbered %v", number)
	}

	cached, err := b.currentCRL(context.Background(), storage, id)
	if err != nil {
		t.Fatalf("could not read the cached list: %v", err)
	}
	if cached == nil || cached.Number != "1" || len(cached.DER) == 0 {
		t.Fatalf("the list of the issuer is not cached under its own key: %v", cached)
	}

	// A mount written before each authority kept its own list holds the record at
	// crl/current, and with a single authority it is still served.
	ctx := context.Background()
	if err := storage.Delete(ctx, crlPrefix+id); err != nil {
		t.Fatalf("could not drop the cached list: %v", err)
	}
	legacy := &crlEntry{
		Number:     "7",
		ThisUpdate: cached.ThisUpdate,
		NextUpdate: cached.NextUpdate,
		DER:        cached.DER,
	}
	if err := putJSON(ctx, storage, crlPrefix+"current", legacy); err != nil {
		t.Fatalf("could not write the old record: %v", err)
	}
	if number := mustRead(t, b, storage, "crl").Data["number"]; number != "7" {
		t.Fatalf("the old record was not served: the list is numbered %v", number)
	}
}

func TestOldCRLIsIgnoredOnceThereAreTwoIssuers(t *testing.T) {
	b, storage := newTestBackend(t)
	generateRoot(t, b, storage)

	ctx := context.Background()
	legacy := &crlEntry{
		Number:     "9",
		ThisUpdate: time.Now(),
		NextUpdate: time.Now().Add(time.Hour),
		DER:        []byte("the list of an authority nobody signs with"),
	}
	if err := putJSON(ctx, storage, crlPrefix+"current", legacy); err != nil {
		t.Fatalf("could not write the old record: %v", err)
	}

	// A second issuer is what a rotation leaves behind. The old single record
	// belongs to neither of them, so it is rebuilt rather than served.
	if err := putJSON(ctx, storage, issuerPrefix+"second", &issuerEntry{Serial: "00"}); err != nil {
		t.Fatalf("could not write the second issuer: %v", err)
	}

	if number := mustRead(t, b, storage, "crl").Data["number"]; number == "9" {
		t.Fatal("the list of one authority was served under another")
	}
}
