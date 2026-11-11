package pki

import (
	"bytes"
	"testing"

	"github.com/emmansun/gmsm/smx509"
	"github.com/hashicorp/vault/sdk/logical"
)

// issuerCertificate reads one authority of the mount, which is what a list it
// signed has to verify against.
func issuerCertificate(t *testing.T, b *backend, s logical.Storage, ref string) *smx509.Certificate {
	t.Helper()

	return parseCert(t, pemData(t, mustRead(t, b, s, "issuer/"+ref).Data, "certificate"))
}

// TestIssuerCRLSpeaksForItsOwnAuthority is the reason the endpoints exist: after
// a rotation each authority keeps a list of its own, because a client checks an
// old certificate against the list its issuer signed.
func TestIssuerCRLSpeaksForItsOwnAuthority(t *testing.T) {
	b, storage := newTestBackend(t)
	root := generateRoot(t, b, storage)
	writeWebRole(t, b, storage)

	previous := defaultIssuerID(t, b, storage)
	old := mustWrite(t, b, storage, "issue/web", map[string]interface{}{
		"common_name": "old.example.com",
	})
	oldSerial := pemData(t, old.Data, "serial_number")
	mustWrite(t, b, storage, "revoke", map[string]interface{}{
		"serial_number": oldSerial,
	})

	rotated := rotateAuthority(t, b, storage, "Test Root CA 2027")
	successor := issuerCertificate(t, b, storage, rotated)

	// The mount serves the list of the authority it signs with, which knows
	// nothing of the certificate the previous one issued.
	current := parseRevocationList(t, mustRead(t, b, storage, "crl"))
	if len(current.RevokedCertificateEntries) != 0 {
		t.Fatalf("the list of the new authority names %d certificates", len(current.RevokedCertificateEntries))
	}
	if err := current.CheckSignatureFrom(successor); err != nil {
		t.Fatalf("the list of the mount is not signed by the authority it signs with: %v", err)
	}

	// The authority that signed the certificate keeps its own list, and that
	// list is the one its certificates can be checked against.
	retired := parseRevocationList(t, mustRead(t, b, storage, "issuer/"+previous+"/crl"))
	if len(retired.RevokedCertificateEntries) != 1 {
		t.Fatalf("the list of the previous authority names %d certificates, want 1", len(retired.RevokedCertificateEntries))
	}
	if got := formatSerial(serialHex(retired.RevokedCertificateEntries[0].SerialNumber)); got != oldSerial {
		t.Fatalf("the list names %s, want %s", got, oldSerial)
	}
	if err := retired.CheckSignatureFrom(root); err != nil {
		t.Fatalf("the list of the previous authority is not signed by it: %v", err)
	}

	// A revocation recorded against one authority never reaches the list of the
	// other, in either direction.
	fresh := mustWrite(t, b, storage, "issue/web", map[string]interface{}{
		"common_name": "new.example.com",
	})
	freshSerial := pemData(t, fresh.Data, "serial_number")
	mustWrite(t, b, storage, "revoke", map[string]interface{}{
		"serial_number": freshSerial,
	})

	current = parseRevocationList(t, mustRead(t, b, storage, "crl"))
	if len(current.RevokedCertificateEntries) != 1 {
		t.Fatalf("the list of the new authority names %d certificates, want 1", len(current.RevokedCertificateEntries))
	}
	if got := formatSerial(serialHex(current.RevokedCertificateEntries[0].SerialNumber)); got != freshSerial {
		t.Fatalf("the list of the new authority names %s, want %s", got, freshSerial)
	}
	retired = parseRevocationList(t, mustRead(t, b, storage, "issuer/"+previous+"/crl"))
	if len(retired.RevokedCertificateEntries) != 1 {
		t.Fatalf("the list of the previous authority names %d certificates after the second revocation", len(retired.RevokedCertificateEntries))
	}
	if got := formatSerial(serialHex(retired.RevokedCertificateEntries[0].SerialNumber)); got != oldSerial {
		t.Fatalf("the list of the previous authority names %s, want %s", got, oldSerial)
	}

	// default addresses the authority that signs now, so it agrees with crl.
	byDefault := parseRevocationList(t, mustRead(t, b, storage, "issuer/default/crl"))
	if byDefault.Number.Cmp(current.Number) != 0 {
		t.Fatalf("issuer/default answers with number %v, want %v", byDefault.Number, current.Number)
	}
}

func TestIssuerCRLAnswersInEveryForm(t *testing.T) {
	b, storage := newTestBackend(t)
	generateRoot(t, b, storage)
	id := defaultIssuerID(t, b, storage)

	raw := mustRead(t, b, storage, "issuer/"+id+"/crl/pem")
	body, ok := raw.Data[logical.HTTPRawBody].([]byte)
	if !ok || !bytes.HasPrefix(body, []byte("-----BEGIN X509 CRL-----")) {
		t.Fatalf("issuer/:ref/crl/pem answered with %q", raw.Data[logical.HTTPRawBody])
	}
	if raw.Data[logical.HTTPContentType] != "application/pem-encoding" {
		t.Fatalf("the PEM list is served as %v", raw.Data[logical.HTTPContentType])
	}

	der := mustRead(t, b, storage, "issuer/"+id+"/crl/der")
	derBody, ok := der.Data[logical.HTTPRawBody].([]byte)
	if !ok {
		t.Fatalf("issuer/:ref/crl/der answered with %v", der.Data)
	}
	if der.Data[logical.HTTPContentType] != "application/pkix-crl" {
		t.Fatalf("the DER list is served as %v", der.Data[logical.HTTPContentType])
	}

	parsed, err := smx509.ParseRevocationList(derBody)
	if err != nil {
		t.Fatalf("the DER form is not a list: %v", err)
	}
	js := parseRevocationList(t, mustRead(t, b, storage, "issuer/"+id+"/crl"))
	if parsed.Number.Cmp(js.Number) != 0 {
		t.Fatalf("the raw form is numbered %v, the JSON form %v", parsed.Number, js.Number)
	}

	// A list is cached as DER, so two reads of an unchanged list have to answer
	// with the same bytes: a fresh SM2 signature would defeat every cache.
	again := mustRead(t, b, storage, "issuer/"+id+"/crl/der")
	if !bytes.Equal(derBody, again.Data[logical.HTTPRawBody].([]byte)) {
		t.Fatal("two reads of an unchanged list answered with different bytes")
	}
}

func TestIssuerCRLRotateCountsPerAuthority(t *testing.T) {
	b, storage := newTestBackend(t)
	generateRoot(t, b, storage)
	previous := defaultIssuerID(t, b, storage)
	rotateAuthority(t, b, storage, "Test Root CA 2027")

	before := mustRead(t, b, storage, "crl").Data["number"].(string)
	previousBefore := mustRead(t, b, storage, "issuer/"+previous+"/crl").Data["number"].(string)

	rotated := mustWrite(t, b, storage, "issuer/"+previous+"/crl/rotate", nil)
	if rotated.Data["number"] == previousBefore {
		t.Fatalf("the rotation kept the number %s", previousBefore)
	}
	if got := mustRead(t, b, storage, "issuer/"+previous+"/crl").Data["number"]; got != rotated.Data["number"] {
		t.Fatalf("the read list reports number %v, want %v", got, rotated.Data["number"])
	}

	// Each authority numbers its own list, so rotating one must not move the
	// number of the other.
	if got := mustRead(t, b, storage, "crl").Data["number"]; got != before {
		t.Fatalf("rotating one list moved the number of the other to %v", got)
	}
}

func TestIssuerCRLRefusesWhatItCannotName(t *testing.T) {
	b, storage := newTestBackend(t)

	mustRefuse(t, b, storage, logical.ReadOperation, "issuer/default/crl", nil,
		"no certificate authority is configured")
	mustRefuse(t, b, storage, logical.UpdateOperation, "issuer/default/crl/rotate", nil,
		"no certificate authority is configured")

	generateRoot(t, b, storage)

	mustRefuse(t, b, storage, logical.ReadOperation, "issuer/nobody/crl", nil,
		`issuer "nobody" does not exist`)
	mustRefuse(t, b, storage, logical.ReadOperation, "issuer/nobody/crl/der", nil,
		`issuer "nobody" does not exist`)
	mustRefuse(t, b, storage, logical.UpdateOperation, "issuer/nobody/crl/rotate", nil,
		`issuer "nobody" does not exist`)
}
