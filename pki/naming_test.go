package pki

import (
	"net"
	"net/url"
	"testing"
)

// sansRole is a role whose policy is exercised with subject alternative names
// only, so it does not insist on a common name.
func sansRole() *roleEntry {
	role := newRole()
	role.RequireCN = false

	return role
}

func domainRole() *roleEntry {
	role := sansRole()
	role.AllowedDomains = []string{"example.com"}
	role.AllowSubdomains = true

	return role
}

func TestValidateDNSNames(t *testing.T) {
	role := domainRole()

	if err := role.validate(requestNames{DNSNames: []string{"web.example.com"}}); err != nil {
		t.Fatalf("a name below an allowed domain was refused: %v", err)
	}

	if err := role.validate(requestNames{DNSNames: []string{"example.com"}}); err == nil {
		t.Fatal("a bare domain was accepted although allow_bare_domains is off")
	}

	if err := role.validate(requestNames{DNSNames: []string{"web.other.com"}}); err == nil {
		t.Fatal("a name outside the allowed domains was accepted")
	}

	// A label that merely ends in the domain is not a subdomain of it.
	if err := role.validate(requestNames{DNSNames: []string{"notexample.com"}}); err == nil {
		t.Fatal("a name that only ends in the domain was accepted")
	}
}

func TestValidateBareDomain(t *testing.T) {
	role := domainRole()
	role.AllowBareDomains = true

	if err := role.validate(requestNames{DNSNames: []string{"example.com"}}); err != nil {
		t.Fatalf("a bare allowed domain was refused: %v", err)
	}
}

func TestValidateGlobDomain(t *testing.T) {
	role := sansRole()
	role.AllowedDomains = []string{"*.internal.example.com"}
	role.AllowGlobDomains = true

	if err := role.validate(requestNames{DNSNames: []string{"host.internal.example.com"}}); err != nil {
		t.Fatalf("a name matching the glob was refused: %v", err)
	}

	if err := role.validate(requestNames{DNSNames: []string{"host.other.example.com"}}); err == nil {
		t.Fatal("a name outside the glob was accepted")
	}
}

func TestValidateWildcardCertificate(t *testing.T) {
	role := domainRole()
	role.AllowWildcardCertificates = false

	if err := role.validate(requestNames{DNSNames: []string{"*.example.com"}}); err == nil {
		t.Fatal("a wildcard was accepted although the role forbids it")
	}

	role.AllowWildcardCertificates = true
	if err := role.validate(requestNames{DNSNames: []string{"*.example.com"}}); err != nil {
		t.Fatalf("a wildcard for an allowed domain was refused: %v", err)
	}

	if err := role.validate(requestNames{DNSNames: []string{"a.*.example.com"}}); err == nil {
		t.Fatal("a wildcard that is not the left-most label was accepted")
	}
}

func TestValidateLocalhost(t *testing.T) {
	role := sansRole()
	role.AllowAnyName = true
	role.AllowLocalhost = false

	if err := role.validate(requestNames{DNSNames: []string{"localhost"}}); err == nil {
		t.Fatal("localhost was accepted although the role forbids it")
	}

	role.AllowLocalhost = true
	if err := role.validate(requestNames{DNSNames: []string{"localhost"}}); err != nil {
		t.Fatalf("localhost was refused although the role allows it: %v", err)
	}
}

func TestValidateHostnameSyntax(t *testing.T) {
	role := domainRole()

	if err := role.validate(requestNames{DNSNames: []string{"under_score.example.com"}}); err == nil {
		t.Fatal("a name with an underscore was accepted although enforce_hostnames is on")
	}

	role.EnforceHostnames = false
	if err := role.validate(requestNames{DNSNames: []string{"under_score.example.com"}}); err != nil {
		t.Fatalf("a name with an underscore was refused although enforce_hostnames is off: %v", err)
	}
}

func TestValidateIPAddresses(t *testing.T) {
	role := sansRole()
	role.AllowIPSANs = false

	if err := role.validate(requestNames{IPAddresses: []net.IP{net.ParseIP("10.0.0.1")}}); err == nil {
		t.Fatal("an IP address was accepted although the role forbids them")
	}

	role.AllowIPSANs = true
	if err := role.validate(requestNames{IPAddresses: []net.IP{net.ParseIP("10.0.0.1")}}); err != nil {
		t.Fatalf("an IP address was refused although the role allows them: %v", err)
	}
}

func TestValidateEmailNames(t *testing.T) {
	role := domainRole()

	if err := role.validate(requestNames{EmailAddresses: []string{"user@mail.example.com"}}); err != nil {
		t.Fatalf("an email address below an allowed domain was refused: %v", err)
	}

	// The domain part takes the same route through the policy as a DNS name,
	// so the bare domain needs allow_bare_domains like any other name.
	if err := role.validate(requestNames{EmailAddresses: []string{"user@example.com"}}); err == nil {
		t.Fatal("an email address at a bare domain was accepted although allow_bare_domains is off")
	}

	role.AllowBareDomains = true
	if err := role.validate(requestNames{EmailAddresses: []string{"user@example.com"}}); err != nil {
		t.Fatalf("an email address at an allowed bare domain was refused: %v", err)
	}

	if err := role.validate(requestNames{EmailAddresses: []string{"user@other.com"}}); err == nil {
		t.Fatal("an email address outside the allowed domains was accepted")
	}

	if err := role.validate(requestNames{EmailAddresses: []string{"not an address"}}); err == nil {
		t.Fatal("a malformed email address was accepted")
	}
}

func TestValidateCommonName(t *testing.T) {
	role := newRole()
	role.RequireCN = true

	if err := role.validate(requestNames{}); err == nil {
		t.Fatal("a request without a common name was accepted although the role requires one")
	}

	role.RequireCN = false
	if err := role.validate(requestNames{}); err != nil {
		t.Fatalf("a request without a common name was refused: %v", err)
	}

	hostRole := domainRole()
	if err := hostRole.validate(requestNames{CommonName: "web.example.com"}); err != nil {
		t.Fatalf("a common name that is a host name in an allowed domain was refused: %v", err)
	}
	if err := hostRole.validate(requestNames{CommonName: "not a name"}); err == nil {
		t.Fatal("a common name that is neither an email nor a host name was accepted")
	}

	// An email common name takes the email route through the policy.
	if err := hostRole.validate(requestNames{CommonName: "user@mail.example.com"}); err != nil {
		t.Fatalf("an email common name below an allowed domain was refused: %v", err)
	}
}

func TestValidateURISANs(t *testing.T) {
	role := sansRole()
	role.AllowedURISANs = []string{"spiffe://example.com/*"}

	allowed, err := url.Parse("spiffe://example.com/service")
	if err != nil {
		t.Fatalf("could not parse the test URI: %v", err)
	}
	if err := role.validate(requestNames{URIs: []*url.URL{allowed}}); err != nil {
		t.Fatalf("a URI matching the allowed pattern was refused: %v", err)
	}

	refused, err := url.Parse("https://example.com/service")
	if err != nil {
		t.Fatalf("could not parse the test URI: %v", err)
	}
	if err := role.validate(requestNames{URIs: []*url.URL{refused}}); err == nil {
		t.Fatal("a URI outside the allowed patterns was accepted")
	}
}

func TestAddCommonName(t *testing.T) {
	names := requestNames{CommonName: "web.example.com"}
	addCommonName(&names)
	addCommonName(&names)

	if len(names.DNSNames) != 1 || names.DNSNames[0] != "web.example.com" {
		t.Fatalf("the common name was not added once as a DNS name: %v", names.DNSNames)
	}

	email := requestNames{CommonName: "user@example.com"}
	addCommonName(&email)
	if len(email.EmailAddresses) != 1 {
		t.Fatalf("an email common name did not become an email SAN: %v", email.EmailAddresses)
	}

	ip := requestNames{CommonName: "10.0.0.1"}
	addCommonName(&ip)
	addCommonName(&ip)
	if len(ip.IPAddresses) != 1 {
		t.Fatalf("an IP common name was added %d times", len(ip.IPAddresses))
	}
}

func TestValidHostname(t *testing.T) {
	for _, name := range []string{"example.com", "a-b.example.com", "example"} {
		if !validHostname(name) {
			t.Fatalf("%q was refused as a host name", name)
		}
	}

	for _, name := range []string{"", "-example.com", "example-.com", "exa mple.com", "1.2.3.4", "under_score.example.com"} {
		if validHostname(name) {
			t.Fatalf("%q was accepted as a host name", name)
		}
	}
}
