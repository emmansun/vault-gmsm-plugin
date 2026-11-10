package pki

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/x509/pkix"
	"encoding/pem"
	"testing"
	"time"

	"github.com/emmansun/gmsm/sm2"
	"github.com/emmansun/gmsm/sm3"
	"github.com/emmansun/gmsm/smx509"
	"github.com/hashicorp/vault/sdk/logical"
)

func newTestBackend(t *testing.T) (*backend, logical.Storage) {
	t.Helper()

	storage := &logical.InmemStorage{}
	conf := &logical.BackendConfig{
		StorageView: storage,
		System:      logical.TestSystemView(),
	}

	b, err := Backend(context.Background(), conf)
	if err != nil {
		t.Fatalf("could not build the backend: %v", err)
	}
	if err := b.Setup(context.Background(), conf); err != nil {
		t.Fatalf("could not set up the backend: %v", err)
	}

	return b, storage
}

func request(t *testing.T, b *backend, s logical.Storage, op logical.Operation, path string, data map[string]interface{}) (*logical.Response, error) {
	t.Helper()

	return b.HandleRequest(context.Background(), &logical.Request{
		Operation: op,
		Path:      path,
		Storage:   s,
		Data:      data,
	})
}

func mustWrite(t *testing.T, b *backend, s logical.Storage, path string, data map[string]interface{}) *logical.Response {
	t.Helper()

	resp, err := request(t, b, s, logical.UpdateOperation, path, data)
	if resp != nil && resp.IsError() {
		// The handlers answer a user error with a response that carries the
		// message and a bare logical.ErrInvalidRequest on the side, so the
		// response is what says why the request was refused.
		t.Fatalf("%s failed: %v", path, resp.Error())
	}
	if err != nil {
		t.Fatalf("%s failed: %v", path, err)
	}

	return resp
}

func mustRead(t *testing.T, b *backend, s logical.Storage, path string) *logical.Response {
	t.Helper()

	resp, err := request(t, b, s, logical.ReadOperation, path, nil)
	if err != nil {
		t.Fatalf("%s failed: %v", path, err)
	}
	if resp == nil {
		t.Fatalf("%s answered with nothing", path)
	}
	if resp.IsError() {
		t.Fatalf("%s failed: %v", path, resp.Error())
	}

	return resp
}

func mustList(t *testing.T, b *backend, s logical.Storage, path string) []string {
	t.Helper()

	resp, err := request(t, b, s, logical.ListOperation, path, nil)
	if err != nil {
		t.Fatalf("%s failed: %v", path, err)
	}
	if resp == nil {
		t.Fatalf("%s answered with nothing", path)
	}

	keys, ok := resp.Data["keys"].([]string)
	if !ok {
		t.Fatalf("%s did not answer with a list: %#v", path, resp.Data)
	}

	return keys
}

func mustFail(t *testing.T, b *backend, s logical.Storage, op logical.Operation, path string, data map[string]interface{}) {
	t.Helper()

	resp, err := request(t, b, s, op, path, data)
	if err == nil && (resp == nil || !resp.IsError()) {
		t.Fatalf("%s was expected to fail but did not", path)
	}
}

// mustMiss asserts that a read answers with nothing, which is how the API says
// that the object is not there.
func mustMiss(t *testing.T, b *backend, s logical.Storage, path string) {
	t.Helper()

	resp, err := request(t, b, s, logical.ReadOperation, path, nil)
	if err != nil {
		t.Fatalf("%s failed: %v", path, err)
	}
	if resp != nil {
		t.Fatalf("%s answered with %v, want nothing", path, resp.Data)
	}
}

func containsName(names []string, want string) bool {
	for _, name := range names {
		if name == want {
			return true
		}
	}

	return false
}

func pemData(t *testing.T, data map[string]interface{}, field string) string {
	t.Helper()

	value, ok := data[field].(string)
	if !ok || value == "" {
		t.Fatalf("the response has no %q", field)
	}

	return value
}

func parseCert(t *testing.T, pemText string) *smx509.Certificate {
	t.Helper()

	block, _ := pem.Decode([]byte(pemText))
	if block == nil {
		t.Fatalf("the response is not PEM")
	}

	cert, err := smx509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatalf("could not parse the certificate: %v", err)
	}

	return cert
}

func generateRoot(t *testing.T, b *backend, s logical.Storage) *smx509.Certificate {
	t.Helper()

	resp := mustWrite(t, b, s, "root/generate/internal", map[string]interface{}{
		"common_name":  "Test Root CA",
		"organization": "Acme",
	})
	if _, ok := resp.Data["private_key"]; ok {
		t.Fatal("an internal root returned its private key")
	}

	return parseCert(t, pemData(t, resp.Data, "certificate"))
}

func writeWebRole(t *testing.T, b *backend, s logical.Storage) {
	t.Helper()

	mustWrite(t, b, s, "roles/web", map[string]interface{}{
		"allowed_domains":  "example.com",
		"allow_subdomains": true,
	})
}

func TestRootGenerateAndRead(t *testing.T) {
	b, storage := newTestBackend(t)

	root := generateRoot(t, b, storage)

	if root.Subject.CommonName != "Test Root CA" {
		t.Fatalf("the root has common name %q", root.Subject.CommonName)
	}
	if !root.IsCA {
		t.Fatal("the root is not a certificate authority")
	}
	if root.SignatureAlgorithm != smx509.SM2WithSM3 {
		t.Fatalf("the root is signed with %v", root.SignatureAlgorithm)
	}
	if len(root.SubjectKeyId) == 0 {
		t.Fatal("the root has no subject key identifier")
	}
	if string(root.SubjectKeyId) != string(root.AuthorityKeyId) {
		t.Fatal("a self-signed root names a different authority key identifier")
	}

	resp := mustRead(t, b, storage, "ca")
	if serial, ok := resp.Data["serial_number"].(string); !ok || serial == "" {
		t.Fatal("the authority has no serial number")
	}
	if _, ok := resp.Data["issuer_id"]; !ok {
		t.Fatal("the authority read has no issuer identifier")
	}

	raw := mustRead(t, b, storage, "ca/pem")
	if _, ok := raw.Data[logical.HTTPRawBody].([]byte); !ok {
		t.Fatal("ca/pem did not answer with a raw body")
	}

	if _, err := request(t, b, storage, logical.UpdateOperation, "root/generate/internal", map[string]interface{}{
		"common_name": "Second Root",
	}); err == nil {
		t.Fatal("a second authority was generated in the same mount")
	}
}

func TestIssueCertificate(t *testing.T) {
	b, storage := newTestBackend(t)
	root := generateRoot(t, b, storage)
	writeWebRole(t, b, storage)

	resp := mustWrite(t, b, storage, "issue/web", map[string]interface{}{
		"common_name": "web.example.com",
		"alt_names":   "api.example.com,ops@mail.example.com",
		"ip_sans":     "10.0.0.1",
		"ttl":         3600,
	})

	cert := parseCert(t, pemData(t, resp.Data, "certificate"))

	if cert.Subject.CommonName != "web.example.com" {
		t.Fatalf("the certificate has common name %q", cert.Subject.CommonName)
	}
	if len(cert.Subject.Organization) != 0 {
		t.Fatalf("the role did not set an organization but the certificate has %v", cert.Subject.Organization)
	}

	wantNames := []string{"web.example.com", "api.example.com"}
	if len(cert.DNSNames) != len(wantNames) {
		t.Fatalf("the certificate has DNS names %v", cert.DNSNames)
	}
	for _, name := range wantNames {
		if !containsName(cert.DNSNames, name) {
			t.Fatalf("the certificate has DNS names %v, want %v", cert.DNSNames, wantNames)
		}
	}
	if len(cert.EmailAddresses) != 1 || cert.EmailAddresses[0] != "ops@mail.example.com" {
		t.Fatalf("the certificate has email addresses %v", cert.EmailAddresses)
	}
	if len(cert.IPAddresses) != 1 || cert.IPAddresses[0].String() != "10.0.0.1" {
		t.Fatalf("the certificate has IP addresses %v", cert.IPAddresses)
	}

	if cert.SignatureAlgorithm != smx509.SM2WithSM3 {
		t.Fatalf("the certificate is signed with %v", cert.SignatureAlgorithm)
	}
	if err := cert.CheckSignatureFrom(root); err != nil {
		t.Fatalf("the certificate is not signed by the authority: %v", err)
	}
	if string(cert.AuthorityKeyId) != string(root.SubjectKeyId) {
		t.Fatal("the certificate names an authority key identifier that is not the root's")
	}

	wantUsage := smx509.KeyUsageDigitalSignature | smx509.KeyUsageKeyAgreement
	if cert.KeyUsage != wantUsage {
		t.Fatalf("the key usage is %v, want %v", cert.KeyUsage, wantUsage)
	}

	remaining := time.Until(cert.NotAfter)
	if remaining > time.Hour+time.Minute || remaining < time.Hour-time.Minute {
		t.Fatalf("the certificate lives for %v, want about an hour", remaining)
	}

	privateKey := pemData(t, resp.Data, "private_key")
	if block, _ := pem.Decode([]byte(privateKey)); block == nil || block.Type != "EC PRIVATE KEY" {
		t.Fatal("the response does not carry a SEC 1 private key")
	}

	serial := resp.Data["serial_number"].(string)
	stored := mustRead(t, b, storage, "cert/"+serial)
	if stored.Data["serial_number"] != serial {
		t.Fatalf("cert/:serial answered with serial %q", stored.Data["serial_number"])
	}
	if _, ok := stored.Data["certificate"]; !ok {
		t.Fatal("the stored certificate is missing from cert/:serial")
	}

	listed := mustList(t, b, storage, "certs")
	if len(listed) != 1 || listed[0] != serial {
		t.Fatalf("the certificate listing is %v, want [%s]", listed, serial)
	}
}

// TestIssuedCertificateCarriesSM3KeyIdentifier ties the identifier helper to a
// real certificate: what smx509 wrote has to be the SM3 of the public key.
func TestIssuedCertificateCarriesSM3KeyIdentifier(t *testing.T) {
	b, storage := newTestBackend(t)
	generateRoot(t, b, storage)
	writeWebRole(t, b, storage)

	resp := mustWrite(t, b, storage, "issue/web", map[string]interface{}{
		"common_name": "web.example.com",
	})

	cert := parseCert(t, pemData(t, resp.Data, "certificate"))

	publicKey, ok := cert.PublicKey.(*ecdsa.PublicKey)
	if !ok {
		t.Fatalf("the certificate carries a %T", cert.PublicKey)
	}

	point, err := subjectPublicKeyBytes(publicKey)
	if err != nil {
		t.Fatalf("could not extract the public key: %v", err)
	}
	sum := sm3.Sum(point)

	if string(cert.SubjectKeyId) != string(sum[:20]) {
		t.Fatalf("the certificate carries %x as its key identifier", cert.SubjectKeyId)
	}
}

func TestIssueRefusedByPolicy(t *testing.T) {
	b, storage := newTestBackend(t)
	generateRoot(t, b, storage)
	writeWebRole(t, b, storage)

	mustFail(t, b, storage, logical.UpdateOperation, "issue/web", map[string]interface{}{
		"common_name": "web.other.com",
	})

	mustFail(t, b, storage, logical.UpdateOperation, "issue/web", map[string]interface{}{})

	mustFail(t, b, storage, logical.UpdateOperation, "issue/absent", map[string]interface{}{
		"common_name": "web.example.com",
	})
}

func TestIssueWithoutAuthority(t *testing.T) {
	b, storage := newTestBackend(t)
	writeWebRole(t, b, storage)

	mustFail(t, b, storage, logical.UpdateOperation, "issue/web", map[string]interface{}{
		"common_name": "web.example.com",
	})

	mustFail(t, b, storage, logical.ReadOperation, "ca", nil)
}

func TestSignCertificateRequest(t *testing.T) {
	b, storage := newTestBackend(t)
	generateRoot(t, b, storage)
	writeWebRole(t, b, storage)

	key, err := sm2.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("could not generate a key: %v", err)
	}

	der, err := smx509.CreateCertificateRequest(rand.Reader, &smx509.CertificateRequest{
		Subject:  pkix.Name{CommonName: "signed.example.com"},
		DNSNames: []string{"signed.example.com", "alt.example.com"},
	}, key)
	if err != nil {
		t.Fatalf("could not create the request: %v", err)
	}

	resp := mustWrite(t, b, storage, "sign/web", map[string]interface{}{
		"csr": string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der})),
	})
	if _, ok := resp.Data["private_key"]; ok {
		t.Fatal("sign returned a private key")
	}

	cert := parseCert(t, pemData(t, resp.Data, "certificate"))
	if cert.Subject.CommonName != "signed.example.com" {
		t.Fatalf("the certificate has common name %q", cert.Subject.CommonName)
	}
	if len(cert.DNSNames) != 2 {
		t.Fatalf("the certificate has DNS names %v", cert.DNSNames)
	}
	if !cert.PublicKey.(*ecdsa.PublicKey).Equal(&key.PublicKey) {
		t.Fatal("the certificate does not carry the public key of the request")
	}
}

func TestRevokeAndCRL(t *testing.T) {
	b, storage := newTestBackend(t)
	root := generateRoot(t, b, storage)
	writeWebRole(t, b, storage)

	issued := mustWrite(t, b, storage, "issue/web", map[string]interface{}{
		"common_name": "web.example.com",
	})
	serial := issued.Data["serial_number"].(string)

	before := parseRevocationList(t, mustRead(t, b, storage, "crl"))
	if len(before.RevokedCertificateEntries) != 0 {
		t.Fatalf("a fresh list already names %d certificates", len(before.RevokedCertificateEntries))
	}

	revoked := mustWrite(t, b, storage, "revoke", map[string]interface{}{
		"serial_number": serial,
	})
	revocationTime, ok := revoked.Data["revocation_time"].(int64)
	if !ok || revocationTime <= 0 {
		t.Fatalf("the revocation has no time: %#v", revoked.Data)
	}

	after := parseRevocationList(t, mustRead(t, b, storage, "crl"))
	if len(after.RevokedCertificateEntries) != 1 {
		t.Fatalf("the list names %d certificates, want 1", len(after.RevokedCertificateEntries))
	}
	if got := formatSerial(serialHex(after.RevokedCertificateEntries[0].SerialNumber)); got != serial {
		t.Fatalf("the list names %s, want %s", got, serial)
	}
	if err := after.CheckSignatureFrom(root); err != nil {
		t.Fatalf("the list is not signed by the authority: %v", err)
	}

	// The cached list has to answer with the same bytes twice: a new SM2
	// signature on every read would defeat every cache in front of it.
	first := pemData(t, mustRead(t, b, storage, "crl").Data, "certificate")
	second := pemData(t, mustRead(t, b, storage, "crl").Data, "certificate")
	if first != second {
		t.Fatal("two reads of an unchanged list answered with different bytes")
	}

	// The list is a CRL, not a certificate: the block type says which, and the
	// raw endpoint has to answer with the same text.
	block, _ := pem.Decode([]byte(first))
	if block == nil || block.Type != "X509 CRL" {
		t.Fatalf("the list is labelled %v, want X509 CRL", block)
	}
	raw := mustRead(t, b, storage, "crl/pem")
	body, ok := raw.Data[logical.HTTPRawBody].([]byte)
	if !ok || !bytes.HasPrefix(body, []byte("-----BEGIN X509 CRL-----")) {
		t.Fatalf("crl/pem answered with %q", raw.Data[logical.HTTPRawBody])
	}

	again := mustWrite(t, b, storage, "revoke", map[string]interface{}{
		"serial_number": serial,
	})
	if len(again.Warnings) == 0 {
		t.Fatal("revoking a serial twice did not warn")
	}
	if again.Data["revocation_time"] != revoked.Data["revocation_time"] {
		t.Fatal("the second revocation changed the time of the first")
	}

	stored := mustRead(t, b, storage, "cert/"+serial)
	if stored.Data["revocation_time"] != revocationTime {
		t.Fatal("cert/:serial does not report the revocation")
	}

	mustFail(t, b, storage, logical.UpdateOperation, "revoke", map[string]interface{}{
		"serial_number": "00",
	})
}

func TestCRLRotateIncrementsTheNumber(t *testing.T) {
	b, storage := newTestBackend(t)
	generateRoot(t, b, storage)

	first := mustRead(t, b, storage, "crl")
	rotated := mustWrite(t, b, storage, "crl/rotate", nil)

	firstNumber := first.Data["number"].(string)
	secondNumber := rotated.Data["number"].(string)
	if firstNumber == secondNumber {
		t.Fatalf("the rotation kept the number %s", firstNumber)
	}

	if got := mustRead(t, b, storage, "crl").Data["number"]; got != secondNumber {
		t.Fatalf("the read list reports number %v, want %s", got, secondNumber)
	}
}

// parseRevocationList decodes the PEM the crl endpoint answers with.
func parseRevocationList(t *testing.T, resp *logical.Response) *smx509.RevocationList {
	t.Helper()

	block, _ := pem.Decode([]byte(pemData(t, resp.Data, "certificate")))
	if block == nil {
		t.Fatal("the list is not PEM")
	}

	list, err := smx509.ParseRevocationList(block.Bytes)
	if err != nil {
		t.Fatalf("could not parse the list: %v", err)
	}

	return list
}

func TestConfigURLsReachTheCertificates(t *testing.T) {
	b, storage := newTestBackend(t)

	mustFail(t, b, storage, logical.UpdateOperation, "config/urls", map[string]interface{}{
		"crl_distribution_points": "not-a-url",
	})

	mustWrite(t, b, storage, "config/urls", map[string]interface{}{
		"issuing_certificates":    "https://ca.example.com/ca.pem",
		"crl_distribution_points": "https://ca.example.com/crl.pem",
		"ocsp_servers":            "https://ca.example.com/ocsp",
	})

	root := generateRoot(t, b, storage)

	if len(root.IssuingCertificateURL) != 1 || root.IssuingCertificateURL[0] != "https://ca.example.com/ca.pem" {
		t.Fatalf("the authority names %v as its own address", root.IssuingCertificateURL)
	}
	if len(root.CRLDistributionPoints) != 1 || root.CRLDistributionPoints[0] != "https://ca.example.com/crl.pem" {
		t.Fatalf("the authority names %v as the list address", root.CRLDistributionPoints)
	}
	if len(root.OCSPServer) != 1 {
		t.Fatalf("the authority names %v as its responder", root.OCSPServer)
	}
}

func TestNoStoreKeepsOnlyMetadata(t *testing.T) {
	b, storage := newTestBackend(t)
	generateRoot(t, b, storage)

	mustWrite(t, b, storage, "roles/quiet", map[string]interface{}{
		"allowed_domains":  "example.com",
		"allow_subdomains": true,
		"no_store":         true,
	})

	resp := mustWrite(t, b, storage, "issue/quiet", map[string]interface{}{
		"common_name": "web.example.com",
	})
	serial := resp.Data["serial_number"].(string)

	stored := mustRead(t, b, storage, "cert/"+serial)
	if _, ok := stored.Data["certificate"]; ok {
		t.Fatal("a no_store certificate was kept in the mount")
	}

	// Revoking it still works, which is the reason the metadata is kept.
	mustWrite(t, b, storage, "revoke", map[string]interface{}{"serial_number": serial})
}

func TestIntermediateFlow(t *testing.T) {
	authority, authorityStorage := newTestBackend(t)
	generateRoot(t, authority, authorityStorage)

	intermediate, intermediateStorage := newTestBackend(t)

	generated := mustWrite(t, intermediate, intermediateStorage, "intermediate/generate/internal", map[string]interface{}{
		"common_name": "Test Intermediate CA",
	})
	if _, ok := generated.Data["private_key"]; ok {
		t.Fatal("an internal intermediate returned its private key")
	}

	signed := mustWrite(t, authority, authorityStorage, "root/sign-intermediate", map[string]interface{}{
		"csr":            generated.Data["csr"],
		"use_csr_values": true,
	})

	completed := mustWrite(t, intermediate, intermediateStorage, "intermediate/set-signed", map[string]interface{}{
		"certificate": signed.Data["certificate"],
	})

	intermediateCert := parseCert(t, pemData(t, completed.Data, "certificate"))
	if intermediateCert.Subject.CommonName != "Test Intermediate CA" {
		t.Fatalf("the intermediate has common name %q", intermediateCert.Subject.CommonName)
	}
	if !intermediateCert.IsCA {
		t.Fatal("the intermediate is not a certificate authority")
	}

	mustWrite(t, intermediate, intermediateStorage, "roles/web", map[string]interface{}{
		"allowed_domains":  "example.com",
		"allow_subdomains": true,
	})

	issued := mustWrite(t, intermediate, intermediateStorage, "issue/web", map[string]interface{}{
		"common_name": "web.example.com",
	})
	leaf := parseCert(t, pemData(t, issued.Data, "certificate"))

	if err := leaf.CheckSignatureFrom(intermediateCert); err != nil {
		t.Fatalf("the leaf is not signed by the intermediate: %v", err)
	}

	// A mount that already holds an authority cannot be given another one.
	mustFail(t, intermediate, intermediateStorage, logical.UpdateOperation, "root/generate/internal", map[string]interface{}{
		"common_name": "Second Authority",
	})
}

func TestRootDeleteClearsTheAuthority(t *testing.T) {
	b, storage := newTestBackend(t)
	generateRoot(t, b, storage)
	writeWebRole(t, b, storage)

	issued := mustWrite(t, b, storage, "issue/web", map[string]interface{}{
		"common_name": "web.example.com",
	})
	serial := issued.Data["serial_number"].(string)

	if _, err := request(t, b, storage, logical.DeleteOperation, "root", nil); err != nil {
		t.Fatalf("deleting the authority failed: %v", err)
	}

	mustFail(t, b, storage, logical.ReadOperation, "ca", nil)
	mustMiss(t, b, storage, "cert/"+serial)

	// Roles are policy, not state of the authority, so they stay.
	if listed := mustList(t, b, storage, "roles"); len(listed) != 1 || listed[0] != "web" {
		t.Fatalf("the roles after the deletion are %v", listed)
	}
}

func TestTidyRemovesExpiredState(t *testing.T) {
	b, storage := newTestBackend(t)
	ctx := context.Background()
	now := time.Now()

	if err := putJSON(ctx, storage, certPrefix+"0a0b", &certEntry{
		Role:       "web",
		Issued:     now.Add(-48 * time.Hour),
		Expiration: now.Add(-24 * time.Hour),
	}); err != nil {
		t.Fatalf("could not store the certificate record: %v", err)
	}
	if err := putJSON(ctx, storage, certPrefix+"0c0d", &certEntry{
		Role:       "web",
		Issued:     now,
		Expiration: now.Add(24 * time.Hour),
	}); err != nil {
		t.Fatalf("could not store the certificate record: %v", err)
	}
	if err := putJSON(ctx, storage, revokedPrefix+"0a0b", &revocationEntry{
		RevocationTime: now.Add(-47 * time.Hour).Unix(),
		RFC3339:        now.Add(-47 * time.Hour).Format(time.RFC3339),
		Expiration:     now.Add(-24 * time.Hour).Unix(),
	}); err != nil {
		t.Fatalf("could not store the revocation: %v", err)
	}

	resp := mustWrite(t, b, storage, "tidy", map[string]interface{}{
		"safety_buffer":   0,
		"tidy_cert_store": true,
	})

	if resp.Data["certificates_removed"] != 1 {
		t.Fatalf("tidy removed %v certificates", resp.Data["certificates_removed"])
	}
	if resp.Data["revocations_removed"] != 1 {
		t.Fatalf("tidy removed %v revocations", resp.Data["revocations_removed"])
	}

	if listed := mustList(t, b, storage, "certs"); len(listed) != 1 || listed[0] != formatSerial("0c0d") {
		t.Fatalf("the remaining certificates are %v", listed)
	}
}

func TestRoleLifecycle(t *testing.T) {
	b, storage := newTestBackend(t)

	mustWrite(t, b, storage, "roles/web", map[string]interface{}{
		"allowed_domains":  "example.com",
		"allow_subdomains": true,
		"ttl":              60,
	})

	role := mustRead(t, b, storage, "roles/web")
	if role.Data["ttl"].(int64) != 60 {
		t.Fatalf("the role lives for %v seconds", role.Data["ttl"])
	}

	patch, err := request(t, b, storage, logical.PatchOperation, "roles/web", map[string]interface{}{
		"max_ttl": 120,
	})
	if err != nil {
		t.Fatalf("patching the role failed: %v", err)
	}
	if patch != nil && patch.IsError() {
		t.Fatalf("patching the role failed: %v", patch.Error())
	}

	role = mustRead(t, b, storage, "roles/web")
	if role.Data["max_ttl"].(int64) != 120 {
		t.Fatalf("the patched max_ttl is %v", role.Data["max_ttl"])
	}
	if role.Data["ttl"].(int64) != 60 {
		t.Fatalf("the patch changed ttl to %v", role.Data["ttl"])
	}

	if _, err := request(t, b, storage, logical.DeleteOperation, "roles/web", nil); err != nil {
		t.Fatalf("deleting the role failed: %v", err)
	}
	if resp, err := request(t, b, storage, logical.ReadOperation, "roles/web", nil); err != nil || resp != nil {
		t.Fatalf("the role survived its deletion: %v %v", resp, err)
	}
}
