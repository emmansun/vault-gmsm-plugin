package pki

import (
	"crypto/x509/pkix"
	"encoding/asn1"
	"fmt"
	"net"
	"strings"
	"unicode/utf8"

	"github.com/hashicorp/vault/sdk/framework"
)

// The extensions a request can ask for that smx509 does not build from a field
// of the template. A certificate carries at most one of each, and smx509 skips
// its own only when the caller supplies one, which is why the names and the
// policies are written here rather than added beside them.
var (
	oidSubjectAltName      = asn1.ObjectIdentifier{2, 5, 29, 17}
	oidCertificatePolicies = asn1.ObjectIdentifier{2, 5, 29, 32}
)

// The tags of the GeneralName choice, RFC 5280 section 4.2.1.6. Each one is
// implicitly tagged, so the value of a name is its contents rather than a
// nested encoding.
const (
	generalNameOtherName = 0
	generalNameEmail     = 1
	generalNameDNS       = 2
	generalNameURI       = 6
	generalNameIP        = 7
)

// otherSan is one otherName of the subject alternative names: the identifier
// the name is registered under, and a value in one of the two string forms a
// certificate may carry.
type otherSan struct {
	OID    asn1.ObjectIdentifier
	Format string
	Value  string
}

// String renders the entry the way a caller writes it, which is also what the
// patterns of allowed_other_sans are matched against.
func (o otherSan) String() string {
	return o.OID.String() + ";" + o.Format + ":" + o.Value
}

// parseOtherSAN reads one "oid;format:value" entry. Only the first colon
// separates the format from the value, because a value may carry one of its
// own.
func parseOtherSAN(entry string) (otherSan, error) {
	separator := strings.Index(entry, ";")
	if separator < 0 {
		return otherSan{}, fmt.Errorf("other SAN %q does not name its identifier and value with a semicolon", entry)
	}

	oid, err := parseOID(entry[:separator])
	if err != nil {
		return otherSan{}, err
	}

	rest := entry[separator+1:]
	colon := strings.Index(rest, ":")
	if colon < 0 {
		return otherSan{}, fmt.Errorf("other SAN %q does not say which form its value is in", entry)
	}

	format := strings.ToLower(strings.TrimSpace(rest[:colon]))
	switch format {
	case "utf8", "ia5":
	default:
		return otherSan{}, fmt.Errorf(`other SAN %q names the form %q; use "utf8" or "ia5"`, entry, rest[:colon])
	}

	return otherSan{OID: oid, Format: format, Value: rest[colon+1:]}, nil
}

// parseOtherSANs reads the other names of a request. A value is checked against
// the form it names here, so a certificate is never asked to hold a string its
// extension cannot carry.
func parseOtherSANs(entries []string) ([]otherSan, error) {
	var sans []otherSan

	for _, entry := range entries {
		raw := strings.TrimSpace(entry)
		if raw == "" {
			continue
		}

		san, err := parseOtherSAN(raw)
		if err != nil {
			return nil, err
		}

		switch san.Format {
		case "utf8":
			if !utf8.ValidString(san.Value) {
				return nil, fmt.Errorf("other SAN %q is not valid UTF-8", raw)
			}
		case "ia5":
			if _, err := asn1.MarshalWithParams(san.Value, "ia5"); err != nil {
				return nil, fmt.Errorf("other SAN %q carries a character an IA5 string cannot hold", raw)
			}
		}

		sans = append(sans, san)
	}

	return sans, nil
}

// checkOtherSANs holds a request to the other names the role allows. An entry
// is matched as a whole against the patterns, so the identifier, the form and
// the value all have to agree.
func (r *roleEntry) checkOtherSANs(sans []otherSan) error {
	if len(sans) == 0 {
		return nil
	}
	if len(r.AllowedOtherSANs) == 0 {
		return fmt.Errorf("this role does not allow other subject alternative names")
	}

next:
	for _, san := range sans {
		name := san.String()
		for _, pattern := range r.AllowedOtherSANs {
			allowed, err := parseOtherSAN(strings.TrimSpace(pattern))
			if err != nil {
				continue
			}
			if globMatch(allowed.String(), name) {
				continue next
			}
		}

		return fmt.Errorf("other subject alternative name %q is not allowed by this role", name)
	}

	return nil
}

// marshalSANs writes the whole subject alternative name extension: the names
// smx509 would have written from the template fields, followed by the other
// names.
func marshalSANs(names requestNames, others []otherSan) ([]byte, error) {
	var entries []asn1.RawValue

	for _, name := range names.EmailAddresses {
		entries = append(entries, generalName(generalNameEmail, []byte(name)))
	}
	for _, name := range names.DNSNames {
		entries = append(entries, generalName(generalNameDNS, []byte(name)))
	}
	for _, ip := range names.IPAddresses {
		address := ip
		if v4 := ip.To4(); v4 != nil {
			address = v4
		}
		entries = append(entries, generalName(generalNameIP, address))
	}
	for _, uri := range names.URIs {
		entries = append(entries, generalName(generalNameURI, []byte(uri.String())))
	}
	for _, other := range others {
		entry, err := other.marshal()
		if err != nil {
			return nil, err
		}
		entries = append(entries, entry)
	}

	return asn1.Marshal(entries)
}

func generalName(tag int, value []byte) asn1.RawValue {
	return asn1.RawValue{Class: asn1.ClassContextSpecific, Tag: tag, Bytes: value}
}

// marshal writes the name the way the subject alternative names hold it. An
// otherName is the sequence of the identifier and the value in a context
// specific wrapper, and the [0] tag of the name replaces the tag of that
// sequence rather than wrapping it, so only its contents are kept.
func (o otherSan) marshal() (asn1.RawValue, error) {
	value, err := o.marshalValue()
	if err != nil {
		return asn1.RawValue{}, err
	}

	encoded, err := asn1.Marshal(struct {
		TypeID asn1.ObjectIdentifier
		Value  asn1.RawValue
	}{
		TypeID: o.OID,
		Value:  asn1.RawValue{Class: asn1.ClassContextSpecific, Tag: 0, IsCompound: true, Bytes: value},
	})
	if err != nil {
		return asn1.RawValue{}, fmt.Errorf("could not encode the other name %q: %w", o, err)
	}

	var sequence asn1.RawValue
	if _, err := asn1.Unmarshal(encoded, &sequence); err != nil {
		return asn1.RawValue{}, fmt.Errorf("could not encode the other name %q: %w", o, err)
	}

	return asn1.RawValue{Class: asn1.ClassContextSpecific, Tag: generalNameOtherName, IsCompound: true, Bytes: sequence.Bytes}, nil
}

func (o otherSan) marshalValue() ([]byte, error) {
	encoded, err := asn1.MarshalWithParams(o.Value, o.Format)
	if err != nil {
		return nil, fmt.Errorf("could not encode the value of the other name %q: %w", o, err)
	}

	return encoded, nil
}

// marshalCertificatePolicies writes the certificate policies extension. Only
// the identifiers are written: a qualifier points at a document this mount
// cannot vouch for.
func marshalCertificatePolicies(identifiers []asn1.ObjectIdentifier) ([]byte, error) {
	type policyInformation struct {
		Policy asn1.ObjectIdentifier
	}

	infos := make([]policyInformation, len(identifiers))
	for i, identifier := range identifiers {
		infos[i] = policyInformation{Policy: identifier}
	}

	encoded, err := asn1.Marshal(infos)
	if err != nil {
		return nil, fmt.Errorf("could not encode the certificate policies: %w", err)
	}

	return encoded, nil
}

// nameConstraints is what an intermediate may vouch for. A certificate that
// carries none of them vouches for every name, which is why they are written
// down per request instead of being derived from the names around them.
type nameConstraints struct {
	PermittedDNSDomains []string
	ExcludedDNSDomains  []string
	PermittedIPRanges   []*net.IPNet
	ExcludedIPRanges    []*net.IPNet
}

// empty answers whether the request constrains anything at all.
func (c nameConstraints) empty() bool {
	return len(c.PermittedDNSDomains) == 0 && len(c.ExcludedDNSDomains) == 0 &&
		len(c.PermittedIPRanges) == 0 && len(c.ExcludedIPRanges) == 0
}

// nameConstraintsFromFields reads the four fields of root/sign-intermediate
// that restrict the names the intermediate may vouch for.
func nameConstraintsFromFields(d *framework.FieldData) (nameConstraints, error) {
	permitted, err := dnsConstraints(d.Get("permitted_dns_domains").([]string))
	if err != nil {
		return nameConstraints{}, err
	}
	excluded, err := dnsConstraints(d.Get("excluded_dns_domains").([]string))
	if err != nil {
		return nameConstraints{}, err
	}
	permittedIPs, err := parseIPRanges(d.Get("permitted_ip_addresses").([]string))
	if err != nil {
		return nameConstraints{}, err
	}
	excludedIPs, err := parseIPRanges(d.Get("excluded_ip_addresses").([]string))
	if err != nil {
		return nameConstraints{}, err
	}

	return nameConstraints{
		PermittedDNSDomains: permitted,
		ExcludedDNSDomains:  excluded,
		PermittedIPRanges:   permittedIPs,
		ExcludedIPRanges:    excludedIPs,
	}, nil
}

// dnsConstraints trims the entries and refuses one the extension cannot hold.
func dnsConstraints(entries []string) ([]string, error) {
	var domains []string

	for _, entry := range entries {
		domain := strings.TrimSpace(entry)
		if domain == "" {
			continue
		}
		for _, r := range domain {
			if r > 0x7f {
				return nil, fmt.Errorf("name constraint %q carries a character an IA5 string cannot hold", domain)
			}
		}
		domains = append(domains, domain)
	}

	return domains, nil
}

// parseIPRanges reads the ranges of an IP constraint. A bare address is refused
// rather than widened to a single host: the two mean different things, and the
// caller should say which one it meant.
func parseIPRanges(entries []string) ([]*net.IPNet, error) {
	var ranges []*net.IPNet

	for _, entry := range entries {
		raw := strings.TrimSpace(entry)
		if raw == "" {
			continue
		}

		_, network, err := net.ParseCIDR(raw)
		if err != nil {
			return nil, fmt.Errorf("name constraint %q is not an IP range in CIDR form: %w", raw, err)
		}
		ranges = append(ranges, network)
	}

	return ranges, nil
}

// certificateExtensions builds the extensions smx509 would otherwise write from
// the template. The subject alternative names are written whole because the
// other names are entries of that one extension, and the policies are written
// here so the result does not depend on a setting of the toolchain.
func certificateExtensions(request certificateRequest) ([]pkix.Extension, error) {
	var extensions []pkix.Extension

	if len(request.OtherSANs) > 0 {
		value, err := marshalSANs(requestNames{
			DNSNames:       request.DNSNames,
			EmailAddresses: request.EmailAddresses,
			IPAddresses:    request.IPAddresses,
			URIs:           request.URIs,
		}, request.OtherSANs)
		if err != nil {
			return nil, err
		}

		extensions = append(extensions, pkix.Extension{
			Id: oidSubjectAltName,
			// RFC 5280 makes the extension critical when the subject is empty,
			// because the names are then the only identity the certificate has.
			Critical: len(request.Subject.ToRDNSequence()) == 0,
			Value:    value,
		})
	}

	if len(request.PolicyIdentifiers) > 0 {
		value, err := marshalCertificatePolicies(request.PolicyIdentifiers)
		if err != nil {
			return nil, err
		}

		extensions = append(extensions, pkix.Extension{Id: oidCertificatePolicies, Value: value})
	}

	return extensions, nil
}
