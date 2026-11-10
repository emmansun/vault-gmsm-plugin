package pki

import (
	"fmt"
	"net"
	"net/mail"
	"net/url"
	"path"
	"strconv"
	"strings"
)

// requestNames is what a request asks to put in the certificate, after the
// names of a request to sign have been merged in.
type requestNames struct {
	CommonName     string
	DNSNames       []string
	EmailAddresses []string
	IPAddresses    []net.IP
	URIs           []*url.URL
}

// parseAltNames splits a comma separated list into DNS names and email
// addresses. Vault treats an entry containing "@" as an email, and so do we.
func parseAltNames(entries []string) (dns []string, emails []string) {
	for _, entry := range entries {
		name := strings.TrimSpace(entry)
		if name == "" {
			continue
		}
		if strings.Contains(name, "@") {
			emails = append(emails, name)
			continue
		}
		dns = append(dns, name)
	}

	return dns, emails
}

func parseIPSANs(entries []string) ([]net.IP, error) {
	var ips []net.IP
	for _, entry := range entries {
		raw := strings.TrimSpace(entry)
		if raw == "" {
			continue
		}
		ip := net.ParseIP(raw)
		if ip == nil {
			return nil, fmt.Errorf("ip_sans entry %q is not an IP address", raw)
		}
		ips = append(ips, ip)
	}

	return ips, nil
}

func parseURISANs(entries []string) ([]*url.URL, error) {
	var uris []*url.URL
	for _, entry := range entries {
		raw := strings.TrimSpace(entry)
		if raw == "" {
			continue
		}
		uri, err := url.Parse(raw)
		if err != nil {
			return nil, fmt.Errorf("uri_sans entry %q is not a URI: %w", raw, err)
		}
		if uri.Scheme == "" {
			return nil, fmt.Errorf("uri_sans entry %q has no scheme", raw)
		}
		uris = append(uris, uri)
	}

	return uris, nil
}

// addCommonName puts the common name into the subject alternative names, which
// is what a client that only knows about SANs needs. A name that looks like an
// email or an IP address goes to the matching field. It is safe to call more
// than once, which matters when the names of a request to sign are merged in
// before the common name is resolved.
func addCommonName(names *requestNames) {
	cn := names.CommonName
	if cn == "" {
		return
	}

	switch {
	case strings.Contains(cn, "@"):
		names.EmailAddresses = appendUnique(names.EmailAddresses, cn)
	case net.ParseIP(cn) != nil:
		names.IPAddresses = appendUniqueIPs(names.IPAddresses, []net.IP{net.ParseIP(cn)})
	default:
		names.DNSNames = appendUnique(names.DNSNames, cn)
	}
}

func appendUnique(list []string, value string) []string {
	for _, existing := range list {
		if existing == value {
			return list
		}
	}

	return append(list, value)
}

func appendUniqueAll(list, values []string) []string {
	for _, value := range values {
		list = appendUnique(list, value)
	}

	return list
}

func appendUniqueIPs(list, values []net.IP) []net.IP {
next:
	for _, value := range values {
		for _, existing := range list {
			if existing.Equal(value) {
				continue next
			}
		}
		list = append(list, value)
	}

	return list
}

func appendUniqueURIs(list, values []*url.URL) []*url.URL {
next:
	for _, value := range values {
		for _, existing := range list {
			if existing.String() == value.String() {
				continue next
			}
		}
		list = append(list, value)
	}

	return list
}

// validate checks every name of the request against the policy of the role. It
// runs before anything is signed, so a refusal never leaves a certificate
// behind.
func (r *roleEntry) validate(names requestNames) error {
	if names.CommonName == "" {
		if r.RequireCN {
			return fmt.Errorf("the request does not resolve to a common name and this role requires one")
		}
	} else if err := r.checkCommonName(names.CommonName); err != nil {
		return err
	}

	for _, name := range names.DNSNames {
		if err := r.checkDNSName(name, "subject alternative name"); err != nil {
			return err
		}
	}

	for _, email := range names.EmailAddresses {
		if err := r.checkEmail(email); err != nil {
			return err
		}
	}

	if len(names.IPAddresses) > 0 && !r.AllowIPSANs {
		return fmt.Errorf("this role does not allow IP subject alternative names")
	}

	for _, uri := range names.URIs {
		if err := r.checkURI(uri); err != nil {
			return err
		}
	}

	return nil
}

func (r *roleEntry) checkCommonName(name string) error {
	if strings.Contains(name, "@") {
		if err := r.checkEmail(name); err != nil {
			return err
		}
	} else if err := r.checkDNSName(name, "common name"); err != nil {
		return err
	}

	// The validators are an additional gate: even a name the domain policy
	// accepts has to look like the kind of name the role expects.
	if !r.AllowAnyName && len(r.CNValidations) > 0 && !r.validCommonName(name) {
		return fmt.Errorf("common name %q is neither an email address nor a host name, which this role requires", name)
	}

	return nil
}

func (r *roleEntry) validCommonName(name string) bool {
	for _, validation := range r.CNValidations {
		switch strings.ToLower(strings.TrimSpace(validation)) {
		case "email":
			if _, err := mail.ParseAddress(name); err == nil {
				return true
			}
		case "hostname":
			if validHostname(strings.TrimPrefix(name, "*.")) {
				return true
			}
		}
	}

	return false
}

func (r *roleEntry) checkDNSName(name, kind string) error {
	if strings.Contains(name, "*") {
		if !r.AllowWildcardCertificates {
			return fmt.Errorf("%s %q contains a wildcard, which this role does not allow", kind, name)
		}
		if strings.Count(name, "*") > 1 || !strings.HasPrefix(name, "*.") {
			return fmt.Errorf("%s %q is not a wildcard this CA issues; the asterisk may only be the entire left-most label", kind, name)
		}
	}

	bare := strings.TrimPrefix(name, "*.")

	if r.EnforceHostnames && !validHostname(bare) {
		return fmt.Errorf("%s %q is not a valid host name", kind, name)
	}

	if isLocalhost(bare) && !r.AllowLocalhost {
		return fmt.Errorf("%s %q is localhost, which this role does not allow", kind, name)
	}

	// The domain policy sees the whole name, asterisk included, so a wildcard
	// has to sit below an allowed domain and allow_subdomains has to cover it:
	// "*.example.com" is one label below example.com, as it is for a client.
	if !r.AllowAnyName && !r.domainAllowed(name) {
		return fmt.Errorf("%s %q is not allowed by this role", kind, name)
	}

	return nil
}

func (r *roleEntry) checkEmail(email string) error {
	parsed, err := mail.ParseAddress(email)
	if err != nil || parsed.Address != email {
		return fmt.Errorf("email address %q is not valid", email)
	}

	if !r.AllowAnyName {
		at := strings.LastIndex(email, "@")
		if !r.domainAllowed(email[at+1:]) {
			return fmt.Errorf("email address %q is not allowed by this role", email)
		}
	}

	return nil
}

func (r *roleEntry) checkURI(uri *url.URL) error {
	raw := uri.String()
	for _, allowed := range r.AllowedURISANs {
		if matched, err := path.Match(strings.TrimSpace(allowed), raw); err == nil && matched {
			return nil
		}
	}

	return fmt.Errorf("URI subject alternative name %q is not allowed by this role", raw)
}

// domainAllowed answers whether a DNS name or an email domain falls under the
// allowed_domains list. The three matching modes are independent, as they are
// in the PKI engine.
func (r *roleEntry) domainAllowed(name string) bool {
	lower := strings.ToLower(strings.TrimSuffix(name, "."))

	for _, entry := range r.AllowedDomains {
		domain := strings.ToLower(strings.TrimSuffix(strings.TrimSpace(entry), "."))
		if domain == "" {
			continue
		}

		switch {
		case r.AllowGlobDomains && globMatch(domain, lower):
			return true
		case r.AllowBareDomains && lower == domain:
			return true
		case r.AllowSubdomains && strings.HasSuffix(lower, "."+domain):
			return true
		}
	}

	return false
}

func globMatch(pattern, name string) bool {
	matched, err := path.Match(pattern, name)

	return err == nil && matched
}

func isLocalhost(name string) bool {
	lower := strings.ToLower(name)

	return lower == "localhost" || strings.HasSuffix(lower, ".localhost")
}

// validHostname checks a DNS name the way a client will when it verifies the
// certificate: label lengths, label characters and no numeric last label, which
// would make the name an IPv4 address in disguise.
func validHostname(name string) bool {
	if name == "" || len(name) > 253 {
		return false
	}

	labels := strings.Split(strings.TrimSuffix(name, "."), ".")
	for _, label := range labels {
		if label == "" || len(label) > 63 {
			return false
		}
		if strings.HasPrefix(label, "-") || strings.HasSuffix(label, "-") {
			return false
		}
		for _, r := range label {
			isLetter := r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z'
			isDigit := r >= '0' && r <= '9'
			if !isLetter && !isDigit && r != '-' {
				return false
			}
		}
	}

	if _, err := strconv.Atoi(labels[len(labels)-1]); err == nil {
		return false
	}

	return true
}
