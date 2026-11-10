package pki

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"strings"
	"testing"
	"time"

	"github.com/emmansun/gmsm/sm2"
	"github.com/emmansun/gmsm/smx509"
	"github.com/hashicorp/vault/sdk/logical"
)

// mustDelete sends the operation that retires a record, which is a plain
// request rather than one of the writes the other helpers cover.
func mustDelete(t *testing.T, b *backend, s logical.Storage, path string) *logical.Response {
	t.Helper()

	resp, err := request(t, b, s, logical.DeleteOperation, path, nil)
	if resp != nil && resp.IsError() {
		t.Fatalf("%s failed: %v", path, resp.Error())
	}
	if err != nil {
		t.Fatalf("%s failed: %v", path, err)
	}

	return resp
}

// mustRefuse asserts that a request is refused with a message that says why,
// because a refusal without a reason is what sends an operator to the docs.
func mustRefuse(t *testing.T, b *backend, s logical.Storage, op logical.Operation, path string, data map[string]interface{}, want string) {
	t.Helper()

	resp, err := request(t, b, s, op, path, data)
	if err == nil && (resp == nil || !resp.IsError()) {
		t.Fatalf("%s was expected to fail but did not", path)
	}
	if resp == nil || !strings.Contains(resp.Error().Error(), want) {
		t.Fatalf("%s was refused with %v, want a message mentioning %q", path, resp, want)
	}
}

// rotateAuthority adds a self-signed authority beside the one the mount already
// has and returns its identifier.
func rotateAuthority(t *testing.T, b *backend, s logical.Storage, commonName string) string {
	t.Helper()

	resp := mustWrite(t, b, s, "root/rotate/internal", map[string]interface{}{
		"common_name": commonName,
	})
	id, ok := resp.Data["issuer_id"].(string)
	if !ok || id == "" {
		t.Fatal("the rotated authority has no identifier")
	}

	return id
}

// expireCertificates moves the expiration of every certificate the mount stored
// into the past, which is what an operator waiting for them to lapse would get.
func expireCertificates(t *testing.T, b *backend, s logical.Storage) {
	t.Helper()

	ctx := context.Background()
	names, err := s.List(ctx, certPrefix)
	if err != nil {
		t.Fatalf("could not list the certificates: %v", err)
	}

	for _, name := range names {
		record, err := b.certificateRecord(ctx, s, name)
		if err != nil || record == nil {
			t.Fatalf("could not read the record of %s: %v", name, err)
		}
		record.Expiration = time.Now().Add(-time.Hour)
		if err := putJSON(ctx, s, certPrefix+name, record); err != nil {
			t.Fatalf("could not expire %s: %v", name, err)
		}
	}
}

// importableAuthority returns the PEM of a private key and of a self-signed
// certificate for it, which is what an operator brings from a CA that was
// created elsewhere.
func importableAuthority(t *testing.T, commonName string) (string, string) {
	t.Helper()

	key, err := sm2.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("could not generate a key: %v", err)
	}

	identifier, err := subjectKeyID(&key.PublicKey)
	if err != nil {
		t.Fatalf("could not derive the key identifier: %v", err)
	}

	now := time.Now()
	template := &smx509.Certificate{
		SerialNumber:          big.NewInt(42),
		Subject:               pkix.Name{CommonName: commonName},
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.Add(24 * time.Hour),
		KeyUsage:              smx509.KeyUsageCertSign | smx509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
		SubjectKeyId:          identifier,
		AuthorityKeyId:        identifier,
		SignatureAlgorithm:    smx509.SM2WithSM3,
	}
	der, err := smx509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("could not create the certificate: %v", err)
	}

	keyDER, err := smx509.MarshalECPrivateKey(&key.PrivateKey)
	if err != nil {
		t.Fatalf("could not marshal the key: %v", err)
	}

	return string(pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})),
		string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
}

func TestRootRotateKeepsTheOldAuthority(t *testing.T) {
	b, storage := newTestBackend(t)
	oldRoot := generateRoot(t, b, storage)
	oldID := defaultIssuerID(t, b, storage)
	writeWebRole(t, b, storage)

	before := parseCert(t, pemData(t, mustWrite(t, b, storage, "issue/web", map[string]interface{}{
		"common_name": "before.example.com",
	}).Data, "certificate"))

	rotated := mustWrite(t, b, storage, "root/rotate/internal", map[string]interface{}{
		"common_name": "Rotated Root CA",
	})
	newID, ok := rotated.Data["issuer_id"].(string)
	if !ok || newID == "" || newID == oldID {
		t.Fatalf("the rotated authority answers with identifier %v", rotated.Data["issuer_id"])
	}
	if rotated.Data["previous_issuer_id"] != oldID {
		t.Fatalf("the rotation names %v as the authority it replaced, want %s", rotated.Data["previous_issuer_id"], oldID)
	}

	newRoot := parseCert(t, pemData(t, rotated.Data, "certificate"))

	if keys := mustList(t, b, storage, "issuers"); len(keys) != 2 {
		t.Fatalf("the mount lists %v after a rotation", keys)
	}
	if id := defaultIssuerID(t, b, storage); id != newID {
		t.Fatalf("the mount signs with %s after a rotation, want %s", id, newID)
	}

	// What the old authority signed still verifies against it, and what the
	// mount signs now comes from the new one.
	if err := before.CheckSignatureFrom(oldRoot); err != nil {
		t.Fatalf("the certificate issued before the rotation does not verify: %v", err)
	}
	after := mustWrite(t, b, storage, "issue/web", map[string]interface{}{
		"common_name": "after.example.com",
	})
	if after.Data["issuer_id"] != newID {
		t.Fatalf("the certificate issued after the rotation names %v, want %s", after.Data["issuer_id"], newID)
	}
	if err := parseCert(t, pemData(t, after.Data, "certificate")).CheckSignatureFrom(newRoot); err != nil {
		t.Fatalf("the certificate issued after the rotation is not signed by the new authority: %v", err)
	}

	// The authority it replaced is still there, still readable, and a role that
	// names it still gets certificates from it.
	old := mustRead(t, b, storage, "issuer/"+oldID)
	if old.Data["is_default"] != false {
		t.Fatal("the replaced authority is still reported as the one in use")
	}
	mustWrite(t, b, storage, "roles/legacy", map[string]interface{}{
		"allowed_domains":  "example.com",
		"allow_subdomains": true,
		"issuer_ref":       oldID,
	})
	legacy := mustWrite(t, b, storage, "issue/legacy", map[string]interface{}{
		"common_name": "legacy.example.com",
	})
	if legacy.Data["issuer_id"] != oldID {
		t.Fatalf("the role naming the old authority got a certificate from %v", legacy.Data["issuer_id"])
	}
	if err := parseCert(t, pemData(t, legacy.Data, "certificate")).CheckSignatureFrom(oldRoot); err != nil {
		t.Fatalf("the certificate of the old authority is not signed by it: %v", err)
	}
}

func TestIssuerDefaultSwitch(t *testing.T) {
	b, storage := newTestBackend(t)
	oldRoot := generateRoot(t, b, storage)
	oldID := defaultIssuerID(t, b, storage)
	newID := rotateAuthority(t, b, storage, "Second Root CA")

	resp := mustWrite(t, b, storage, "issuer/"+oldID+"/default", nil)
	if resp.Data["issuer_id"] != oldID || resp.Data["is_default"] != true {
		t.Fatalf("the switch answers with %v", resp.Data)
	}
	if id := defaultIssuerID(t, b, storage); id != oldID {
		t.Fatalf("the mount signs with %s after the switch, want %s", id, oldID)
	}
	if readBack := parseCert(t, pemData(t, mustRead(t, b, storage, "ca").Data, "certificate")); !bytes.Equal(readBack.Raw, oldRoot.Raw) {
		t.Fatal("ca reports a certificate that is not the one the switch selected")
	}

	// Asking for the authority that already signs is not an error, but it says
	// that nothing happened.
	again := mustWrite(t, b, storage, "issuer/"+oldID+"/default", nil)
	if len(again.Warnings) == 0 {
		t.Fatal("switching to the authority already in use did not warn")
	}

	// And the switch goes back the other way as well.
	mustWrite(t, b, storage, "issuer/"+newID+"/default", nil)
	if id := defaultIssuerID(t, b, storage); id != newID {
		t.Fatalf("the mount signs with %s after switching back, want %s", id, newID)
	}
}

func TestDeleteIssuerWaitsForItsCertificates(t *testing.T) {
	b, storage := newTestBackend(t)
	generateRoot(t, b, storage)
	writeWebRole(t, b, storage)
	id := defaultIssuerID(t, b, storage)

	issued := mustWrite(t, b, storage, "issue/web", map[string]interface{}{
		"common_name": "web.example.com",
	})
	serial := pemData(t, issued.Data, "serial_number")
	keyID := mustRead(t, b, storage, "issuer/"+id).Data["key_id"].(string)

	mustRefuse(t, b, storage, logical.DeleteOperation, "issuer/"+id, nil, "has not expired")

	// Retiring the authority is what removes the list that would have reported
	// the revocation of its certificates, so it has to outlive them.
	expireCertificates(t, b, storage)

	resp := mustDelete(t, b, storage, "issuer/"+id)
	if resp.Data["certificates_removed"] != 1 {
		t.Fatalf("the retirement removed %v certificates", resp.Data["certificates_removed"])
	}
	if resp.Data["default_issuer_id"] != "" {
		t.Fatalf("the mount still signs with %v", resp.Data["default_issuer_id"])
	}

	ctx := context.Background()
	key, err := normalizeSerial(serial)
	if err != nil {
		t.Fatalf("the serial %q is not hexadecimal: %v", serial, err)
	}
	for _, path := range []string{issuerPrefix + id, keyPrefix + keyID, certPrefix + key, crlPrefix + id} {
		entry, err := storage.Get(ctx, path)
		if err != nil {
			t.Fatalf("could not read %s: %v", path, err)
		}
		if entry != nil {
			t.Fatalf("%s survived the retirement of the authority", path)
		}
	}

	mustFail(t, b, storage, logical.ReadOperation, "ca", nil)
}

func TestDeleteIssuerTakesItsRevocations(t *testing.T) {
	b, storage := newTestBackend(t)
	generateRoot(t, b, storage)
	writeWebRole(t, b, storage)
	oldID := defaultIssuerID(t, b, storage)

	issued := mustWrite(t, b, storage, "issue/web", map[string]interface{}{
		"common_name": "web.example.com",
	})
	serial := pemData(t, issued.Data, "serial_number")
	mustWrite(t, b, storage, "revoke", map[string]interface{}{"serial_number": serial})
	if number := mustRead(t, b, storage, "crl").Data["number"]; number != "1" {
		t.Fatalf("the list of the old authority is numbered %v", number)
	}

	newID := rotateAuthority(t, b, storage, "Second Root CA")
	expireCertificates(t, b, storage)

	resp := mustDelete(t, b, storage, "issuer/"+oldID)
	if resp.Data["revocations_removed"] != 1 {
		t.Fatalf("the retirement removed %v revocations", resp.Data["revocations_removed"])
	}
	if resp.Data["default_issuer_id"] != newID {
		t.Fatalf("the mount signs with %v after the retirement, want %s", resp.Data["default_issuer_id"], newID)
	}

	key, err := normalizeSerial(serial)
	if err != nil {
		t.Fatalf("the serial %q is not hexadecimal: %v", serial, err)
	}
	entry, err := storage.Get(context.Background(), revokedPrefix+key)
	if err != nil {
		t.Fatalf("could not read the revocation: %v", err)
	}
	if entry != nil {
		t.Fatal("the revocation of the retired authority survived it")
	}

	// The authority that is left is the one in use, and it has no revocations of
	// its own, so its list is empty rather than carrying the other one's.
	if number := mustRead(t, b, storage, "crl").Data["number"]; number != "1" {
		t.Fatalf("the list of the remaining authority is numbered %v", number)
	}
	if id := mustRead(t, b, storage, "issuer/"+newID).Data["is_default"]; id != true {
		t.Fatal("the remaining authority is not the one in use")
	}
}

func TestDeleteRootRefusesAfterRotation(t *testing.T) {
	b, storage := newTestBackend(t)
	generateRoot(t, b, storage)
	oldID := defaultIssuerID(t, b, storage)
	newID := rotateAuthority(t, b, storage, "Second Root CA")

	mustRefuse(t, b, storage, logical.DeleteOperation, "root", nil, "retire them one at a time")

	mustDelete(t, b, storage, "issuer/"+oldID)
	if id := defaultIssuerID(t, b, storage); id != newID {
		t.Fatalf("the mount signs with %s, want %s", id, newID)
	}

	// With one authority left, the bulk delete is the way to empty the mount.
	mustDelete(t, b, storage, "root")
	mustFail(t, b, storage, logical.ReadOperation, "ca", nil)

	empty, err := request(t, b, storage, logical.ListOperation, "issuers", nil)
	if err != nil {
		t.Fatalf("issuers failed: %v", err)
	}
	if keys, ok := empty.Data["keys"].([]string); ok && len(keys) != 0 {
		t.Fatalf("the mount still lists %v", keys)
	}
}

func TestRotatedAuthorityCanBeAdopted(t *testing.T) {
	b, storage := newTestBackend(t)
	generateRoot(t, b, storage)
	oldID := defaultIssuerID(t, b, storage)

	// An exported rotation hands the key out as well, so the authority it created
	// can be taken to another mount.
	rotated := mustWrite(t, b, storage, "root/rotate/exported", map[string]interface{}{
		"common_name": "Exported Root CA",
	})
	if rotated.Data["previous_issuer_id"] != oldID {
		t.Fatalf("the rotation names %v as the authority it replaced", rotated.Data["previous_issuer_id"])
	}
	privateKey := pemData(t, rotated.Data, "private_key")
	if !strings.HasPrefix(privateKey, "-----BEGIN EC PRIVATE KEY-----") {
		t.Fatalf("the exported key is not SEC 1 PEM: %s", privateKey)
	}

	other, otherStorage := newTestBackend(t)
	certificate := pemData(t, rotated.Data, "certificate")
	adopted := mustWrite(t, other, otherStorage, "config/ca", map[string]interface{}{
		"pem_bundle": privateKey + certificate,
	})
	if adopted.Data["serial_number"] != rotated.Data["serial_number"] {
		t.Fatalf("the adopted authority reports serial %v, want %v", adopted.Data["serial_number"], rotated.Data["serial_number"])
	}

	writeWebRole(t, other, otherStorage)
	issued := mustWrite(t, other, otherStorage, "issue/web", map[string]interface{}{
		"common_name": "web.example.com",
	})
	if err := parseCert(t, pemData(t, issued.Data, "certificate")).CheckSignatureFrom(parseCert(t, certificate)); err != nil {
		t.Fatalf("the adopted authority did not sign the certificate: %v", err)
	}
}

func TestImportAuthority(t *testing.T) {
	b, storage := newTestBackend(t)
	keyPEM, certPEM := importableAuthority(t, "Imported Root CA")

	resp := mustWrite(t, b, storage, "config/ca", map[string]interface{}{
		"pem_bundle": keyPEM + certPEM,
	})
	cert := parseCert(t, pemData(t, resp.Data, "certificate"))
	if resp.Data["serial_number"] != formatSerial(serialHex(cert.SerialNumber)) {
		t.Fatalf("the import answers serial %v", resp.Data["serial_number"])
	}
	if id := defaultIssuerID(t, b, storage); id != resp.Data["issuer_id"] {
		t.Fatalf("the mount signs with %s, want %v", id, resp.Data["issuer_id"])
	}

	// The mount signs with the key it was given, not only with its certificate.
	writeWebRole(t, b, storage)
	issued := mustWrite(t, b, storage, "issue/web", map[string]interface{}{
		"common_name": "web.example.com",
	})
	if err := parseCert(t, pemData(t, issued.Data, "certificate")).CheckSignatureFrom(cert); err != nil {
		t.Fatalf("the certificate is not signed by the imported authority: %v", err)
	}

	// A second import would leave one of the two authorities unaccounted for.
	mustRefuse(t, b, storage, logical.UpdateOperation, "config/ca", map[string]interface{}{
		"pem_bundle": keyPEM + certPEM,
	}, "already holds a certificate authority")
}

func TestImportAuthorityRefusesMismatchedPair(t *testing.T) {
	b, storage := newTestBackend(t)

	keyPEM, _ := importableAuthority(t, "First Root CA")
	_, otherCertPEM := importableAuthority(t, "Other Root CA")

	mustRefuse(t, b, storage, logical.UpdateOperation, "config/ca", map[string]interface{}{
		"pem_bundle": keyPEM + otherCertPEM,
	}, "does not carry the public key")

	mustFail(t, b, storage, logical.ReadOperation, "ca", nil)
}
