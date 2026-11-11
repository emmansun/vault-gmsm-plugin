package pki

import (
	"bytes"
	"crypto/rand"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"net/http"
	"strings"
	"testing"

	"github.com/emmansun/gmsm/sm2"
	"github.com/emmansun/gmsm/smx509"
	"github.com/emmansun/vault-gmsm-plugin/internal/ocspclient"
	"github.com/hashicorp/vault/sdk/logical"
)

// webCSR builds a request for a name under the domain of the web role, which is
// what a caller of sign brings.
func webCSR(t *testing.T, commonName string) string {
	t.Helper()

	key, err := sm2.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("could not generate a key: %v", err)
	}

	der, err := smx509.CreateCertificateRequest(rand.Reader, &smx509.CertificateRequest{
		Subject:  pkix.Name{CommonName: commonName},
		DNSNames: []string{commonName},
	}, key)
	if err != nil {
		t.Fatalf("could not create the request: %v", err)
	}

	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der}))
}

func TestIssuerSettingsAreWrittenOneFieldAtATime(t *testing.T) {
	b, storage := newTestBackend(t)
	generateRoot(t, b, storage)
	id := defaultIssuerID(t, b, storage)

	// An authority nobody wrote settings on may do everything, which keeps a
	// mount that was written before these fields existed working as it did.
	initial := mustRead(t, b, storage, "issuer/"+id)
	if got := strings.Join(initial.Data["usage"].([]string), ","); got != usageIssuing+","+usageCRL+","+usageOCSP {
		t.Fatalf("an authority without settings reports usage %q", got)
	}
	if initial.Data["leaf_not_after_behavior"] != leafNotAfterTruncate {
		t.Fatalf("an authority without settings treats a long certificate as %v", initial.Data["leaf_not_after_behavior"])
	}

	written := mustWrite(t, b, storage, "issuer/"+id, map[string]interface{}{
		"issuer_name":             "primary",
		"usage":                   "issuing-certificates,ocsp-signing",
		"leaf_not_after_behavior": "err",
		"crl_distribution_points": "https://ca.example.com/primary.crl",
	})
	if written.Data["issuer_name"] != "primary" {
		t.Fatalf("the write answers with name %v", written.Data["issuer_name"])
	}

	// The name addresses the authority from now on, and a read through it says
	// what was written and nothing else.
	named := mustRead(t, b, storage, "issuer/primary")
	if named.Data["issuer_id"] != id {
		t.Fatalf("issuer/primary reads back as %v, want %s", named.Data["issuer_id"], id)
	}
	if got := strings.Join(named.Data["usage"].([]string), ","); got != usageIssuing+","+usageOCSP {
		t.Fatalf("the authority reports usage %q", got)
	}
	if named.Data["leaf_not_after_behavior"] != leafNotAfterErr {
		t.Fatalf("the authority treats a long certificate as %v", named.Data["leaf_not_after_behavior"])
	}
	if points := named.Data["crl_distribution_points"].([]string); len(points) != 1 {
		t.Fatalf("the authority publishes %v as its list", points)
	}

	// A write that names one setting leaves the others where they are, which is
	// what makes these settings changeable without reading them first.
	mustWrite(t, b, storage, "issuer/primary", map[string]interface{}{
		"leaf_not_after_behavior": "permit",
	})
	readBack := mustRead(t, b, storage, "issuer/primary")
	if readBack.Data["leaf_not_after_behavior"] != leafNotAfterPermit {
		t.Fatalf("the second write left the behavior at %v", readBack.Data["leaf_not_after_behavior"])
	}
	if got := strings.Join(readBack.Data["usage"].([]string), ","); got != usageIssuing+","+usageOCSP {
		t.Fatalf("the second write changed the usage to %q", got)
	}
	if points := readBack.Data["crl_distribution_points"].([]string); len(points) != 1 {
		t.Fatalf("the second write changed the list to %v", points)
	}

	// Clearing the addresses returns the authority to the ones of config/urls.
	mustWrite(t, b, storage, "issuer/primary", map[string]interface{}{
		"crl_distribution_points": "",
	})
	if points := mustRead(t, b, storage, "issuer/primary").Data["crl_distribution_points"].([]string); len(points) != 0 {
		t.Fatalf("the cleared list still holds %v", points)
	}

	mustRefuse(t, b, storage, logical.UpdateOperation, "issuer/primary", map[string]interface{}{
		"usage": "signing-certificates",
	}, "is not one of")
	mustRefuse(t, b, storage, logical.UpdateOperation, "issuer/primary", map[string]interface{}{
		"usage": "read-only,crl-signing",
	}, "cannot be combined")
	mustRefuse(t, b, storage, logical.UpdateOperation, "issuer/primary", map[string]interface{}{
		"leaf_not_after_behavior": "ignore",
	}, "is not one of")
	mustRefuse(t, b, storage, logical.UpdateOperation, "issuer/primary", map[string]interface{}{
		"ocsp_servers": "ocsp.example.com",
	}, "not an absolute URL")
	mustRefuse(t, b, storage, logical.UpdateOperation, "issuer/primary", map[string]interface{}{
		"issuer_name": issuerRefDefault,
	}, "is reserved")

	// A name belongs to one authority, so a second one cannot take it.
	second := rotateAuthority(t, b, storage, "Second Root CA")
	mustRefuse(t, b, storage, logical.UpdateOperation, "issuer/"+second, map[string]interface{}{
		"issuer_name": "primary",
	}, "is already the name")
}

func TestIssuerUsageGatesWhatTheKeySigns(t *testing.T) {
	b, storage := newTestBackend(t)
	root := generateRoot(t, b, storage)
	writeWebRole(t, b, storage)
	id := defaultIssuerID(t, b, storage)

	leaf := parseCert(t, pemData(t, mustWrite(t, b, storage, "issue/web", map[string]interface{}{
		"common_name": "web.example.com",
	}).Data, "certificate"))

	// Answering a status query signs the answer, which is what the authority is
	// this far allowed to do.
	answer, code := askOCSP(t, b, storage, leaf.SerialNumber, root)
	if code != http.StatusOK || answer.CertStatus != ocspclient.CertGood {
		t.Fatalf("the responder answered with status %d and HTTP %d", answer.Status, code)
	}

	// Signing the list is what exercises the key on a read, so this fills the
	// cache that the read below serves without signing anything.
	if number := mustRead(t, b, storage, "crl").Data["number"]; number != "1" {
		t.Fatalf("the list is numbered %v", number)
	}

	mustWrite(t, b, storage, "issuer/"+id, map[string]interface{}{"usage": "read-only"})

	for _, path := range []string{"issue/web", "issuer/" + id + "/issue/web"} {
		mustRefuse(t, b, storage, logical.UpdateOperation, path, map[string]interface{}{
			"common_name": "web.example.com",
		}, "not allowed to issue certificates")
	}
	for _, path := range []string{"sign/web", "issuer/" + id + "/sign/web"} {
		mustRefuse(t, b, storage, logical.UpdateOperation, path, map[string]interface{}{
			"csr": webCSR(t, "web.example.com"),
		}, "not allowed to issue certificates")
	}
	mustRefuse(t, b, storage, logical.UpdateOperation, "crl/rotate", nil, "not allowed to sign a revocation list")

	// A refusal travels in the protocol, because a client that gets a JSON
	// error cannot tell it apart from a responder that is not there.
	answer, code = askOCSP(t, b, storage, leaf.SerialNumber, root)
	if code != http.StatusUnauthorized || answer.Status != ocspclient.Unauthorized {
		t.Fatalf("the responder answered with status %d and HTTP %d, want %d and %d",
			answer.Status, code, ocspclient.Unauthorized, http.StatusUnauthorized)
	}

	// The cached list is still served: reading one is not signing it, and a
	// client that already trusts the authority has to keep getting an answer.
	mustRead(t, b, storage, "crl")

	// A key that may sign lists and nothing else is what a responder run
	// beside the mount looks like.
	mustWrite(t, b, storage, "issuer/"+id, map[string]interface{}{"usage": "crl-signing"})
	if rotated := mustWrite(t, b, storage, "crl/rotate", nil); rotated.Data["number"] != "2" {
		t.Fatalf("the rotated list is numbered %v, want 2", rotated.Data["number"])
	}
	mustRefuse(t, b, storage, logical.UpdateOperation, "issue/web", map[string]interface{}{
		"common_name": "web.example.com",
	}, "not allowed to issue certificates")
}

func TestIssuerPathsNameTheAuthority(t *testing.T) {
	b, storage := newTestBackend(t)
	oldRoot := generateRoot(t, b, storage)
	oldID := defaultIssuerID(t, b, storage)
	writeWebRole(t, b, storage)
	newID := rotateAuthority(t, b, storage, "Second Root CA")

	// The mount signs with the new authority, and the path is how a certificate
	// from the one it replaced is still issued.
	fromOld := mustWrite(t, b, storage, "issuer/"+oldID+"/issue/web", map[string]interface{}{
		"common_name": "old.example.com",
	})
	if fromOld.Data["issuer_id"] != oldID {
		t.Fatalf("the path naming the old authority got a certificate from %v", fromOld.Data["issuer_id"])
	}
	if err := parseCert(t, pemData(t, fromOld.Data, "certificate")).CheckSignatureFrom(oldRoot); err != nil {
		t.Fatalf("the certificate is not signed by the authority the path names: %v", err)
	}

	fromDefault := mustWrite(t, b, storage, "issuer/default/issue/web", map[string]interface{}{
		"common_name": "web.example.com",
	})
	if fromDefault.Data["issuer_id"] != newID {
		t.Fatalf("issuer/default issued from %v, want %s", fromDefault.Data["issuer_id"], newID)
	}

	// sign takes the same ref, and still answers without a private key.
	signed := mustWrite(t, b, storage, "issuer/"+oldID+"/sign/web", map[string]interface{}{
		"csr": webCSR(t, "signed.example.com"),
	})
	if signed.Data["issuer_id"] != oldID {
		t.Fatalf("the request signed under the old authority names %v", signed.Data["issuer_id"])
	}
	if err := parseCert(t, pemData(t, signed.Data, "certificate")).CheckSignatureFrom(oldRoot); err != nil {
		t.Fatalf("the signed request is not signed by the authority the path names: %v", err)
	}
	if _, ok := signed.Data["private_key"]; ok {
		t.Fatal("sign returned a private key")
	}

	// The ref of the path wins over the one the role names, because the path is
	// the more specific instruction.
	mustWrite(t, b, storage, "roles/pinned", map[string]interface{}{
		"allowed_domains":  "example.com",
		"allow_subdomains": true,
		"issuer_ref":       newID,
	})
	pinned := mustWrite(t, b, storage, "issuer/"+oldID+"/issue/pinned", map[string]interface{}{
		"common_name": "pinned.example.com",
	})
	if pinned.Data["issuer_id"] != oldID {
		t.Fatalf("the path naming the old authority issued from %v", pinned.Data["issuer_id"])
	}

	// A ref that names no authority is a mistake in the request, not a miss.
	mustRefuse(t, b, storage, logical.UpdateOperation, "issuer/not-there/issue/web", map[string]interface{}{
		"common_name": "web.example.com",
	}, "does not exist")
}

func TestIssuerBundleIsServedInEveryForm(t *testing.T) {
	b, storage := newTestBackend(t)
	root := generateRoot(t, b, storage)
	id := defaultIssuerID(t, b, storage)

	mustWrite(t, b, storage, "issuer/"+id, map[string]interface{}{
		"issuer_name":             "primary",
		"usage":                   "issuing-certificates",
		"crl_distribution_points": "https://ca.example.com/primary.crl",
	})

	// The JSON document is what an operator keeps to reproduce the authority
	// elsewhere, so it carries the certificate and the settings together.
	bundle := mustRead(t, b, storage, "issuer/primary/json")
	if contentType := bundle.Data[logical.HTTPContentType]; contentType != "application/json" {
		t.Fatalf("the bundle is served as %v", contentType)
	}
	body, ok := bundle.Data[logical.HTTPRawBody].([]byte)
	if !ok {
		t.Fatalf("the bundle is not a raw body: %v", bundle.Data)
	}

	var document struct {
		IssuerID              string   `json:"issuer_id"`
		IssuerName            string   `json:"issuer_name"`
		Certificate           string   `json:"certificate"`
		CAChain               []string `json:"ca_chain"`
		SerialNumber          string   `json:"serial_number"`
		Usage                 []string `json:"usage"`
		LeafNotAfterBehavior  string   `json:"leaf_not_after_behavior"`
		CRLDistributionPoints []string `json:"crl_distribution_points"`
		Default               bool     `json:"default"`
	}
	if err := json.Unmarshal(body, &document); err != nil {
		t.Fatalf("the bundle is not JSON: %v", err)
	}

	if document.IssuerID != id || document.IssuerName != "primary" {
		t.Fatalf("the bundle names %q and %q", document.IssuerID, document.IssuerName)
	}
	if !document.Default {
		t.Fatal("the only authority is not the one in use in its own bundle")
	}
	if document.SerialNumber != formatSerial(serialHex(root.SerialNumber)) {
		t.Fatalf("the bundle reports serial %q", document.SerialNumber)
	}
	if len(document.CAChain) != 1 || document.CAChain[0] != document.Certificate {
		t.Fatalf("the bundle carries a chain of %d certificates", len(document.CAChain))
	}
	if len(document.Usage) != 1 || document.Usage[0] != usageIssuing {
		t.Fatalf("the bundle reports usage %v", document.Usage)
	}
	if document.LeafNotAfterBehavior != leafNotAfterTruncate {
		t.Fatalf("the bundle reports a behavior of %q", document.LeafNotAfterBehavior)
	}
	if len(document.CRLDistributionPoints) != 1 {
		t.Fatalf("the bundle reports %v as the list", document.CRLDistributionPoints)
	}

	// The raw forms are the certificate itself, so a client can write the file
	// straight to disk.
	pemBody := mustRead(t, b, storage, "issuer/primary/pem")
	if contentType := pemBody.Data[logical.HTTPContentType]; contentType != "application/pem-encoding" {
		t.Fatalf("the PEM form is served as %v", contentType)
	}
	block, _ := pem.Decode(pemBody.Data[logical.HTTPRawBody].([]byte))
	if block == nil || block.Type != "CERTIFICATE" || !bytes.Equal(block.Bytes, root.Raw) {
		t.Fatal("issuer/:ref/pem does not carry the certificate of the authority")
	}

	derBody := mustRead(t, b, storage, "issuer/primary/der")
	if contentType := derBody.Data[logical.HTTPContentType]; contentType != "application/pkix-cert" {
		t.Fatalf("the DER form is served as %v", contentType)
	}
	if !bytes.Equal(derBody.Data[logical.HTTPRawBody].([]byte), root.Raw) {
		t.Fatal("issuer/:ref/der does not carry the certificate of the authority")
	}

	mustRefuse(t, b, storage, logical.ReadOperation, "issuer/not-there/json", nil, "does not exist")
}

func TestIssuerLeafNotAfterBehavior(t *testing.T) {
	b, storage := newTestBackend(t)

	// An authority that lives for an hour, and a role whose certificates would
	// live for two, so every one of them outlives the authority.
	mustWrite(t, b, storage, "root/generate/internal", map[string]interface{}{
		"common_name": "Short Root CA",
		"ttl":         3600,
	})
	id := defaultIssuerID(t, b, storage)
	mustWrite(t, b, storage, "roles/long", map[string]interface{}{
		"allowed_domains":  "example.com",
		"allow_subdomains": true,
		"ttl":              7200,
		"max_ttl":          7200,
	})
	issuerCert := parseCert(t, pemData(t, mustRead(t, b, storage, "issuer/"+id).Data, "certificate"))

	// Truncating is what the mount did before the setting existed, so it is
	// what an authority nobody wrote does.
	shortened := mustWrite(t, b, storage, "issue/long", map[string]interface{}{
		"common_name": "web.example.com",
	})
	if len(shortened.Warnings) == 0 {
		t.Fatal("a certificate shortened to the life of the authority did not warn")
	}
	if leaf := parseCert(t, pemData(t, shortened.Data, "certificate")); leaf.NotAfter.After(issuerCert.NotAfter) {
		t.Fatalf("the certificate is valid until %s, past the authority's %s", leaf.NotAfter, issuerCert.NotAfter)
	}

	// Refusing names the two dates that are in the way, because reconciling them
	// is what the operator has to do.
	mustWrite(t, b, storage, "issuer/"+id, map[string]interface{}{"leaf_not_after_behavior": "err"})
	mustRefuse(t, b, storage, logical.UpdateOperation, "issue/long", map[string]interface{}{
		"common_name": "web.example.com",
	}, "past issuer")

	// Permitting is the one way a leaf may outlive its issuer, and it is what a
	// mount in front of a longer-lived authority needs.
	mustWrite(t, b, storage, "issuer/"+id, map[string]interface{}{"leaf_not_after_behavior": "permit"})
	permitted := mustWrite(t, b, storage, "issue/long", map[string]interface{}{
		"common_name": "web.example.com",
	})
	if leaf := parseCert(t, pemData(t, permitted.Data, "certificate")); !leaf.NotAfter.After(issuerCert.NotAfter) {
		t.Fatalf("the certificate is valid until %s, not past the authority's %s", leaf.NotAfter, issuerCert.NotAfter)
	}
}

func TestIssuerPublishesItsOwnAddresses(t *testing.T) {
	b, storage := newTestBackend(t)
	mustWrite(t, b, storage, "config/urls", map[string]interface{}{
		"issuing_certificates":    "https://ca.example.com/ca.pem",
		"crl_distribution_points": "https://ca.example.com/crl.pem",
		"ocsp_servers":            "https://ca.example.com/ocsp",
	})
	generateRoot(t, b, storage)
	writeWebRole(t, b, storage)
	id := defaultIssuerID(t, b, storage)

	// One list is overridden, and the other two still come from config/urls.
	mustWrite(t, b, storage, "issuer/"+id, map[string]interface{}{
		"crl_distribution_points": "https://ca.example.com/primary.crl",
	})
	leaf := parseCert(t, pemData(t, mustWrite(t, b, storage, "issue/web", map[string]interface{}{
		"common_name": "web.example.com",
	}).Data, "certificate"))

	if len(leaf.CRLDistributionPoints) != 1 || leaf.CRLDistributionPoints[0] != "https://ca.example.com/primary.crl" {
		t.Fatalf("the certificate publishes %v as the list", leaf.CRLDistributionPoints)
	}
	if len(leaf.IssuingCertificateURL) != 1 || leaf.IssuingCertificateURL[0] != "https://ca.example.com/ca.pem" {
		t.Fatalf("the certificate publishes %v as the authority", leaf.IssuingCertificateURL)
	}
	if len(leaf.OCSPServer) != 1 || leaf.OCSPServer[0] != "https://ca.example.com/ocsp" {
		t.Fatalf("the certificate publishes %v as the responder", leaf.OCSPServer)
	}

	// Clearing the override returns the authority to the mount-wide address.
	mustWrite(t, b, storage, "issuer/"+id, map[string]interface{}{"crl_distribution_points": ""})
	leaf = parseCert(t, pemData(t, mustWrite(t, b, storage, "issue/web", map[string]interface{}{
		"common_name": "web.example.com",
	}).Data, "certificate"))
	if len(leaf.CRLDistributionPoints) != 1 || leaf.CRLDistributionPoints[0] != "https://ca.example.com/crl.pem" {
		t.Fatalf("the certificate publishes %v as the list", leaf.CRLDistributionPoints)
	}
}
