package pki

import (
	"encoding/asn1"
	"strings"
	"testing"
	"time"

	"github.com/emmansun/gmsm/smx509"
	"github.com/hashicorp/vault/sdk/logical"
)

// oidOtherNameDepartment is the identifier the tests write an other name
// under: the one a directory uses for a department of a person.
var oidOtherNameDepartment = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 311, 20, 2, 3}

// writeProfileRole writes the role the profile tests issue from: the policy
// every role needs, with the profile fields of one test on top.
func writeProfileRole(t *testing.T, b *backend, s logical.Storage, fields map[string]interface{}) {
	t.Helper()

	role := map[string]interface{}{
		"allowed_domains":  "example.com",
		"allow_subdomains": true,
	}
	for key, value := range fields {
		role[key] = value
	}

	mustWrite(t, b, s, "roles/web", role)
}

// warningAbout answers whether one of the warnings mentions the word, which is
// how a test says that the shortening was reported rather than silent.
func warningAbout(warnings []string, part string) bool {
	for _, warning := range warnings {
		if strings.Contains(warning, part) {
			return true
		}
	}

	return false
}

// otherNames reads the otherName entries out of the subject alternative names
// extension, which smx509 keeps as an extension rather than as a field. Each
// entry is rendered the way a caller writes it.
func otherNames(t *testing.T, cert *smx509.Certificate) []string {
	t.Helper()

	var value []byte
	for _, extension := range cert.Extensions {
		if extension.Id.Equal(oidSubjectAltName) {
			value = extension.Value
		}
	}
	if value == nil {
		t.Fatal("the certificate has no subject alternative names")
	}

	var names []asn1.RawValue
	if _, err := asn1.Unmarshal(value, &names); err != nil {
		t.Fatalf("could not read the subject alternative names: %v", err)
	}

	var others []string
	for _, name := range names {
		if name.Class != asn1.ClassContextSpecific || name.Tag != generalNameOtherName {
			continue
		}

		var identifier asn1.ObjectIdentifier
		rest, err := asn1.Unmarshal(name.Bytes, &identifier)
		if err != nil {
			t.Fatalf("could not read an other name: %v", err)
		}

		// The value sits in an explicit wrapper, so its contents are the whole
		// encoding of the string rather than the characters of it.
		var wrapper asn1.RawValue
		if _, err := asn1.Unmarshal(rest, &wrapper); err != nil {
			t.Fatalf("could not read the value of an other name: %v", err)
		}

		var text asn1.RawValue
		if _, err := asn1.Unmarshal(wrapper.Bytes, &text); err != nil {
			t.Fatalf("could not read the value of an other name: %v", err)
		}

		format := "ia5"
		if text.Tag == asn1.TagUTF8String {
			format = "utf8"
		}
		others = append(others, identifier.String()+";"+format+":"+string(text.Bytes))
	}

	return others
}

func TestCertificateStatesThePoliciesOfTheRole(t *testing.T) {
	b, storage := newTestBackend(t)
	generateRoot(t, b, storage)
	writeWebRole(t, b, storage)

	// A role that names no policy issues a certificate that states none.
	plain := parseCert(t, pemData(t, mustWrite(t, b, storage, "issue/web", map[string]interface{}{
		"common_name": "web.example.com",
	}).Data, "certificate"))
	if len(plain.PolicyIdentifiers) != 0 {
		t.Fatalf("a role that names no policy issued %v", plain.PolicyIdentifiers)
	}

	writeProfileRole(t, b, storage, map[string]interface{}{
		"policy_identifiers": "2.23.140.1.2.1,1.3.6.1.4.1.99999.1",
	})

	resp := mustWrite(t, b, storage, "issue/web", map[string]interface{}{
		"common_name": "web.example.com",
	})
	cert := parseCert(t, pemData(t, resp.Data, "certificate"))

	want := []asn1.ObjectIdentifier{{2, 23, 140, 1, 2, 1}, {1, 3, 6, 1, 4, 1, 99999, 1}}
	if len(cert.PolicyIdentifiers) != len(want) {
		t.Fatalf("the certificate states the policies %v, want %v", cert.PolicyIdentifiers, want)
	}
	for i := range want {
		if !cert.PolicyIdentifiers[i].Equal(want[i]) {
			t.Fatalf("the certificate states the policies %v, want %v", cert.PolicyIdentifiers, want)
		}
	}

	stored := mustRead(t, b, storage, "roles/web").Data["policy_identifiers"].([]string)
	if len(stored) != 2 || stored[0] != "2.23.140.1.2.1" {
		t.Fatalf("the role reads back the policies %v", stored)
	}
}

func TestOtherNamesTravelWithTheNamesAroundThem(t *testing.T) {
	b, storage := newTestBackend(t)
	generateRoot(t, b, storage)
	writeProfileRole(t, b, storage, map[string]interface{}{
		"allowed_other_sans": oidOtherNameDepartment.String() + ";utf8:*",
	})

	cert := parseCert(t, pemData(t, mustWrite(t, b, storage, "issue/web", map[string]interface{}{
		"common_name": "web.example.com",
		"alt_names":   "api.example.com",
		"ip_sans":     "10.1.2.3",
		"other_sans":  oidOtherNameDepartment.String() + ";utf8:department",
	}).Data, "certificate"))

	// The other name is an entry of the same extension as the names around it,
	// so writing one must not drop the others.
	if !containsName(cert.DNSNames, "web.example.com") || !containsName(cert.DNSNames, "api.example.com") {
		t.Fatalf("the certificate carries the DNS names %v", cert.DNSNames)
	}
	if len(cert.IPAddresses) != 1 || cert.IPAddresses[0].String() != "10.1.2.3" {
		t.Fatalf("the certificate carries the IP addresses %v", cert.IPAddresses)
	}

	others := otherNames(t, cert)
	want := oidOtherNameDepartment.String() + ";utf8:department"
	if len(others) != 1 || others[0] != want {
		t.Fatalf("the certificate carries the other names %v, want %v", others, want)
	}

	// The subject is not empty, so the names are not the only identity of the
	// certificate and RFC 5280 does not make the extension critical.
	for _, extension := range cert.Extensions {
		if extension.Id.Equal(oidSubjectAltName) && extension.Critical {
			t.Fatal("the names are critical although the certificate has a subject")
		}
	}
}

func TestRoleRefusesAnOtherNameItDoesNotAllow(t *testing.T) {
	b, storage := newTestBackend(t)
	generateRoot(t, b, storage)

	// A role that names no other name allows none of them.
	writeWebRole(t, b, storage)
	mustFail(t, b, storage, logical.UpdateOperation, "issue/web", map[string]interface{}{
		"common_name": "web.example.com",
		"other_sans":  oidOtherNameDepartment.String() + ";utf8:department",
	})

	writeProfileRole(t, b, storage, map[string]interface{}{
		"allowed_other_sans": oidOtherNameDepartment.String() + ";utf8:finance",
	})
	mustFail(t, b, storage, logical.UpdateOperation, "issue/web", map[string]interface{}{
		"common_name": "web.example.com",
		"other_sans":  oidOtherNameDepartment.String() + ";utf8:payroll",
	})

	// The pattern is matched as a whole, so the identifier, the form and the
	// value all have to agree.
	mustWrite(t, b, storage, "issue/web", map[string]interface{}{
		"common_name": "web.example.com",
		"other_sans":  oidOtherNameDepartment.String() + ";utf8:finance",
	})
}

func TestNotAfterCapsTheCertificate(t *testing.T) {
	b, storage := newTestBackend(t)
	generateRoot(t, b, storage)

	deadline := time.Now().Add(2 * time.Hour).Truncate(time.Second)
	writeProfileRole(t, b, storage, map[string]interface{}{
		"not_after": deadline.Format(time.RFC3339),
	})

	resp := mustWrite(t, b, storage, "issue/web", map[string]interface{}{
		"common_name": "web.example.com",
		"ttl":         30 * 24 * 3600,
	})

	cert := parseCert(t, pemData(t, resp.Data, "certificate"))
	if cert.NotAfter.After(deadline) {
		t.Fatalf("the certificate is valid until %v, past the not_after %v", cert.NotAfter, deadline)
	}
	if !warningAbout(resp.Warnings, "not_after") {
		t.Fatalf("the shortening to the not_after was not reported: %v", resp.Warnings)
	}

	// A role read answers the deadline in the form it was written.
	written, ok := mustRead(t, b, storage, "roles/web").Data["not_after"].(time.Time)
	if !ok || !written.Equal(deadline) {
		t.Fatalf("the role reads back the deadline %v, want %v", written, deadline)
	}
}

func TestNotAfterInThePastRefusesToIssue(t *testing.T) {
	b, storage := newTestBackend(t)
	generateRoot(t, b, storage)

	writeProfileRole(t, b, storage, map[string]interface{}{
		"not_after": time.Now().Add(-time.Hour).Format(time.RFC3339),
	})

	mustFail(t, b, storage, logical.UpdateOperation, "issue/web", map[string]interface{}{
		"common_name": "web.example.com",
	})
}

func TestIntermediateCarriesNameConstraints(t *testing.T) {
	authority, authorityStorage := newTestBackend(t)
	generateRoot(t, authority, authorityStorage)

	intermediate, intermediateStorage := newTestBackend(t)
	generated := mustWrite(t, intermediate, intermediateStorage, "intermediate/generate/internal", map[string]interface{}{
		"common_name": "Constrained Intermediate CA",
	})

	signed := mustWrite(t, authority, authorityStorage, "root/sign-intermediate", map[string]interface{}{
		"csr":                    generated.Data["csr"],
		"use_csr_values":         true,
		"permitted_dns_domains":  ".example.com,.example.org",
		"excluded_dns_domains":   "secret.example.com",
		"permitted_ip_addresses": "10.0.0.0/8",
		"excluded_ip_addresses":  "10.9.0.0/16",
	})

	cert := parseCert(t, pemData(t, signed.Data, "certificate"))
	if !containsName(cert.PermittedDNSDomains, ".example.com") || !containsName(cert.PermittedDNSDomains, ".example.org") {
		t.Fatalf("the intermediate permits the domains %v", cert.PermittedDNSDomains)
	}
	if !containsName(cert.ExcludedDNSDomains, "secret.example.com") {
		t.Fatalf("the intermediate excludes the domains %v", cert.ExcludedDNSDomains)
	}
	if len(cert.PermittedIPRanges) != 1 || cert.PermittedIPRanges[0].String() != "10.0.0.0/8" {
		t.Fatalf("the intermediate permits the ranges %v", cert.PermittedIPRanges)
	}
	if len(cert.ExcludedIPRanges) != 1 || cert.ExcludedIPRanges[0].String() != "10.9.0.0/16" {
		t.Fatalf("the intermediate excludes the ranges %v", cert.ExcludedIPRanges)
	}
	if !cert.PermittedDNSDomainsCritical {
		t.Fatal("the constraints are not critical, so a client may ignore them")
	}
	if len(cert.UnhandledCriticalExtensions) != 0 {
		t.Fatalf("the certificate carries extensions a client cannot check: %v", cert.UnhandledCriticalExtensions)
	}
}

func TestSignIntermediateRefusesAConstraintItCannotWrite(t *testing.T) {
	authority, authorityStorage := newTestBackend(t)
	generateRoot(t, authority, authorityStorage)

	intermediate, intermediateStorage := newTestBackend(t)
	generated := mustWrite(t, intermediate, intermediateStorage, "intermediate/generate/internal", map[string]interface{}{
		"common_name": "Constrained Intermediate CA",
	})

	// A bare address says something other than a range does, so it is refused
	// rather than widened to a single host.
	mustFail(t, authority, authorityStorage, logical.UpdateOperation, "root/sign-intermediate", map[string]interface{}{
		"csr":                    generated.Data["csr"],
		"use_csr_values":         true,
		"permitted_ip_addresses": "10.1.2.3",
	})
}

func TestRoleRefusesAProfileItCannotWrite(t *testing.T) {
	b, storage := newTestBackend(t)

	mustFail(t, b, storage, logical.UpdateOperation, "roles/bad", map[string]interface{}{
		"policy_identifiers": "not-an-oid",
	})
	mustFail(t, b, storage, logical.UpdateOperation, "roles/bad", map[string]interface{}{
		"policy_identifiers": "1",
	})
	mustFail(t, b, storage, logical.UpdateOperation, "roles/bad", map[string]interface{}{
		"allowed_other_sans": oidOtherNameDepartment.String() + ";utf16:department",
	})
	mustFail(t, b, storage, logical.UpdateOperation, "roles/bad", map[string]interface{}{
		"allowed_other_sans": "department",
	})
}
