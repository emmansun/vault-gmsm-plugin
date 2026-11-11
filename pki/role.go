package pki

import (
	"crypto/x509/pkix"
	"encoding/asn1"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/emmansun/gmsm/smx509"
	"github.com/hashicorp/vault/sdk/framework"
)

const (
	// defaultRoleTTL is what a certificate is valid for when neither the role
	// nor the request asks for something else. It is a fixed default instead of
	// the system lease TTL, which would cap every certificate at a month.
	defaultRoleTTL = 720 * time.Hour

	// defaultRoleMaxTTL is the longest validity a request on the role can ask
	// for. Ten years is what keeps a CA that is expected to outlive its
	// certificates useful.
	defaultRoleMaxTTL = 8760 * time.Hour
)

// roleEntry is the issuing policy of one role: what names may be requested,
// what usages the certificate carries and how long it lives. It is stored as
// one record per role and is the only thing a caller writes before issuing.
type roleEntry struct {
	IssuerRef string `json:"issuer_ref"`

	TTL               time.Duration `json:"ttl"`
	MaxTTL            time.Duration `json:"max_ttl"`
	NotBeforeDuration time.Duration `json:"not_before_duration"`

	// NotAfter is the latest time a certificate of this role may be valid
	// until, and zero when the role sets no deadline of its own.
	NotAfter time.Time `json:"not_after"`

	NoStore       bool `json:"no_store"`
	GenerateLease bool `json:"generate_lease"`

	Organization        []string `json:"organization"`
	OU                  []string `json:"ou"`
	Country             []string `json:"country"`
	Locality            []string `json:"locality"`
	Province            []string `json:"province"`
	StreetAddress       []string `json:"street_address"`
	PostalCode          []string `json:"postal_code"`
	SubjectSerialNumber string   `json:"serial_number"`
	RequireCN           bool     `json:"require_cn"`

	AllowedDomains            []string `json:"allowed_domains"`
	AllowBareDomains          bool     `json:"allow_bare_domains"`
	AllowSubdomains           bool     `json:"allow_subdomains"`
	AllowGlobDomains          bool     `json:"allow_glob_domains"`
	AllowAnyName              bool     `json:"allow_any_name"`
	AllowWildcardCertificates bool     `json:"allow_wildcard_certificates"`
	AllowLocalhost            bool     `json:"allow_localhost"`
	EnforceHostnames          bool     `json:"enforce_hostnames"`
	AllowIPSANs               bool     `json:"allow_ip_sans"`
	AllowedURISANs            []string `json:"allowed_uri_sans"`
	AllowedOtherSANs          []string `json:"allowed_other_sans"`
	CNValidations             []string `json:"cn_validations"`

	// PolicyIdentifiers are the certificate policies a certificate of this
	// role states, as dotted decimal OIDs.
	PolicyIdentifiers []string `json:"policy_identifiers"`

	KeyUsage        []string `json:"key_usage"`
	ExtKeyUsage     []string `json:"ext_key_usage"`
	ExtKeyUsageOIDs []string `json:"ext_key_usage_oids"`

	ServerFlag          bool `json:"server_flag"`
	ClientFlag          bool `json:"client_flag"`
	CodeSigningFlag     bool `json:"code_signing_flag"`
	EmailProtectionFlag bool `json:"email_protection_flag"`

	UseCSRCommonName bool `json:"use_csr_common_name"`
	UseCSRSANs       bool `json:"use_csr_sans"`
}

// newRole returns the policy a role has before anything is written. The
// defaults match the PKI engine except where docs/pki.md lists a difference.
func newRole() *roleEntry {
	return &roleEntry{
		IssuerRef:                 "default",
		TTL:                       defaultRoleTTL,
		MaxTTL:                    defaultRoleMaxTTL,
		NotBeforeDuration:         defaultNotBefore,
		RequireCN:                 true,
		AllowWildcardCertificates: true,
		AllowLocalhost:            true,
		EnforceHostnames:          true,
		AllowIPSANs:               true,
		CNValidations:             []string{"email", "hostname"},
		KeyUsage:                  []string{"DigitalSignature", "KeyAgreement"},
		ServerFlag:                true,
		ClientFlag:                true,
		UseCSRCommonName:          true,
		UseCSRSANs:                true,
	}
}

// subject builds the distinguished name of an issued certificate from the
// role, with the common name the request resolved.
func (r *roleEntry) subject(commonName string) pkix.Name {
	return pkix.Name{
		CommonName:         commonName,
		Organization:       r.Organization,
		OrganizationalUnit: r.OU,
		Country:            r.Country,
		Locality:           r.Locality,
		Province:           r.Province,
		StreetAddress:      r.StreetAddress,
		PostalCode:         r.PostalCode,
		SerialNumber:       r.SubjectSerialNumber,
	}
}

// keyUsage converts the stored names to the bit mask the certificate carries.
func (r *roleEntry) keyUsage() (smx509.KeyUsage, error) {
	var usage smx509.KeyUsage
	for _, name := range r.KeyUsage {
		value, ok := keyUsageNames[strings.ToLower(strings.TrimSpace(name))]
		if !ok {
			return 0, fmt.Errorf("key_usage %q is not a known key usage", name)
		}
		usage |= value
	}

	return usage, nil
}

// extKeyUsage combines the four flags with the explicit lists. Flags are
// additive, as they are in the PKI engine. An OID the Go constants do not name
// goes to the unknown list, which is where a certificate carries a usage its
// issuer knows but this package does not.
func (r *roleEntry) extKeyUsage() ([]smx509.ExtKeyUsage, []asn1.ObjectIdentifier, error) {
	var usage []smx509.ExtKeyUsage

	if r.ServerFlag {
		usage = append(usage, smx509.ExtKeyUsageServerAuth)
	}
	if r.ClientFlag {
		usage = append(usage, smx509.ExtKeyUsageClientAuth)
	}
	if r.CodeSigningFlag {
		usage = append(usage, smx509.ExtKeyUsageCodeSigning)
	}
	if r.EmailProtectionFlag {
		usage = append(usage, smx509.ExtKeyUsageEmailProtection)
	}

	for _, name := range r.ExtKeyUsage {
		value, ok := extKeyUsageNames[strings.ToLower(strings.TrimSpace(name))]
		if !ok {
			return nil, nil, fmt.Errorf("ext_key_usage %q is not a known extended key usage", name)
		}
		usage = append(usage, value)
	}

	var unknown []asn1.ObjectIdentifier
	for _, raw := range r.ExtKeyUsageOIDs {
		oid, err := parseOID(raw)
		if err != nil {
			return nil, nil, err
		}
		unknown = append(unknown, oid)
	}

	return usage, unknown, nil
}

var keyUsageNames = map[string]smx509.KeyUsage{
	"digitalsignature":  smx509.KeyUsageDigitalSignature,
	"contentcommitment": smx509.KeyUsageContentCommitment,
	"keyencipherment":   smx509.KeyUsageKeyEncipherment,
	"dataencipherment":  smx509.KeyUsageDataEncipherment,
	"keyagreement":      smx509.KeyUsageKeyAgreement,
	"certsign":          smx509.KeyUsageCertSign,
	"crlsign":           smx509.KeyUsageCRLSign,
	"encipheronly":      smx509.KeyUsageEncipherOnly,
	"decipheronly":      smx509.KeyUsageDecipherOnly,
}

var extKeyUsageNames = map[string]smx509.ExtKeyUsage{
	"any":             smx509.ExtKeyUsageAny,
	"serverauth":      smx509.ExtKeyUsageServerAuth,
	"clientauth":      smx509.ExtKeyUsageClientAuth,
	"codesigning":     smx509.ExtKeyUsageCodeSigning,
	"emailprotection": smx509.ExtKeyUsageEmailProtection,
	"timestamping":    smx509.ExtKeyUsageTimeStamping,
	"ocspsigning":     smx509.ExtKeyUsageOCSPSigning,
}

// policyIdentifiers converts the policies of a role to the form a certificate
// carries. A role that names none issues a certificate that states none.
func (r *roleEntry) policyIdentifiers() ([]asn1.ObjectIdentifier, error) {
	identifiers := make([]asn1.ObjectIdentifier, 0, len(r.PolicyIdentifiers))
	for _, raw := range r.PolicyIdentifiers {
		oid, err := parseOID(raw)
		if err != nil {
			return nil, fmt.Errorf("policy_identifiers: %w", err)
		}
		identifiers = append(identifiers, oid)
	}

	return identifiers, nil
}

// parseOID turns the dotted decimal form into the identifier the certificate
// carries, so a bad value is refused when the role is written rather than when
// a certificate is requested.
func parseOID(raw string) (asn1.ObjectIdentifier, error) {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return nil, errors.New("an object identifier is empty")
	}

	parts := strings.Split(trimmed, ".")
	if len(parts) < 2 {
		return nil, fmt.Errorf("%q is not a dotted decimal OID", raw)
	}

	oid := make(asn1.ObjectIdentifier, len(parts))
	for i, part := range parts {
		value, err := strconv.Atoi(part)
		if err != nil || value < 0 {
			return nil, fmt.Errorf("%q is not a dotted decimal OID", raw)
		}
		oid[i] = value
	}

	return oid, nil
}

// roleFieldSchemas describes every writable field of a role.
func roleFieldSchemas() map[string]*framework.FieldSchema {
	return map[string]*framework.FieldSchema{
		"issuer_ref": {
			Type:        framework.TypeString,
			Default:     "default",
			Description: `Issuer to sign with. The mount holds a single authority, so only "default" is accepted.`,
		},
		"ttl": {
			Type:        framework.TypeDurationSecond,
			Default:     int(defaultRoleTTL / time.Second),
			Description: "Validity of an issued certificate when the request does not ask for one.",
		},
		"max_ttl": {
			Type:        framework.TypeDurationSecond,
			Default:     int(defaultRoleMaxTTL / time.Second),
			Description: "Longest validity a request may ask for. A longer ttl is shortened to this, with a warning.",
		},
		"not_before_duration": {
			Type:        framework.TypeDurationSecond,
			Default:     int(defaultNotBefore / time.Second),
			Description: "How far the notBefore field is backdated. It does not extend the validity.",
		},
		"not_after": {
			Type:        framework.TypeTime,
			Description: "Latest time a certificate of this role may be valid until, in RFC 3339 form. A longer validity is shortened to it, and a request made after it is refused.",
		},
		"policy_identifiers": {
			Type:        framework.TypeCommaStringSlice,
			Description: "Certificate policies the certificate states, as dotted decimal OIDs.",
		},
		"no_store": {
			Type:        framework.TypeBool,
			Default:     false,
			Description: "Do not keep the issued certificate in the mount. Such a certificate can only be revoked when it is supplied with the revocation.",
		},
		"generate_lease": {
			Type:        framework.TypeBool,
			Default:     false,
			Description: "Accepted for compatibility. Leases are not implemented, so this only produces a warning.",
		},
		"organization": {
			Type:        framework.TypeCommaStringSlice,
			Description: "Organization (O) values of the issued subject.",
		},
		"ou": {
			Type:        framework.TypeCommaStringSlice,
			Description: "Organizational unit (OU) values of the issued subject.",
		},
		"country": {
			Type:        framework.TypeCommaStringSlice,
			Description: "Country (C) values of the issued subject.",
		},
		"locality": {
			Type:        framework.TypeCommaStringSlice,
			Description: "Locality (L) values of the issued subject.",
		},
		"province": {
			Type:        framework.TypeCommaStringSlice,
			Description: "Province (ST) values of the issued subject.",
		},
		"street_address": {
			Type:        framework.TypeCommaStringSlice,
			Description: "Street address values of the issued subject.",
		},
		"postal_code": {
			Type:        framework.TypeCommaStringSlice,
			Description: "Postal code values of the issued subject.",
		},
		"serial_number": {
			Type:        framework.TypeString,
			Description: "Serial number value of the issued subject (OID 2.5.4.5). This is not the certificate serial.",
		},
		"require_cn": {
			Type:        framework.TypeBool,
			Default:     true,
			Description: "Refuse a request that ends up without a common name.",
		},
		"allowed_domains": {
			Type:        framework.TypeCommaStringSlice,
			Description: "Domains this role may issue for. Combined with allow_bare_domains, allow_subdomains and allow_glob_domains.",
		},
		"allow_bare_domains": {
			Type:        framework.TypeBool,
			Default:     false,
			Description: "Allow a name that equals an allowed domain exactly.",
		},
		"allow_subdomains": {
			Type:        framework.TypeBool,
			Default:     false,
			Description: "Allow names below an allowed domain.",
		},
		"allow_glob_domains": {
			Type:        framework.TypeBool,
			Default:     false,
			Description: "Treat the entries of allowed_domains as shell glob patterns.",
		},
		"allow_any_name": {
			Type:        framework.TypeBool,
			Default:     false,
			Description: "Allow any name. Hostname and wildcard checks still apply.",
		},
		"allow_wildcard_certificates": {
			Type:        framework.TypeBool,
			Default:     true,
			Description: "Allow a wildcard as the entire left-most label.",
		},
		"allow_localhost": {
			Type:        framework.TypeBool,
			Default:     true,
			Description: "Allow localhost and names below it.",
		},
		"enforce_hostnames": {
			Type:        framework.TypeBool,
			Default:     true,
			Description: "Require common names and DNS names to be valid host names.",
		},
		"allow_ip_sans": {
			Type:        framework.TypeBool,
			Default:     true,
			Description: "Allow IP addresses in the subject alternative names.",
		},
		"allowed_uri_sans": {
			Type:        framework.TypeCommaStringSlice,
			Description: "URI subject alternative names this role may issue. Entries may contain glob patterns.",
		},
		"allowed_other_sans": {
			Type:        framework.TypeCommaStringSlice,
			Description: `Other subject alternative names this role may issue, as OID;form:value entries with glob patterns allowed, e.g. "1.3.6.1.4.1.311.20.2.3;utf8:department" or "1.3.6.1.4.1.311.20.2.3;utf8:*".`,
		},
		"cn_validations": {
			Type:        framework.TypeCommaStringSlice,
			Default:     []string{"email", "hostname"},
			Description: `How the common name is validated: "email", "hostname" or both. At least one has to accept it.`,
		},
		"key_usage": {
			Type:        framework.TypeCommaStringSlice,
			Default:     []string{"DigitalSignature", "KeyAgreement"},
			Description: "Key usages of the issued certificate. Names are the Go constants with the KeyUsage prefix removed.",
		},
		"ext_key_usage": {
			Type:        framework.TypeCommaStringSlice,
			Description: "Extended key usages, named after the Go constants with the ExtKeyUsage prefix removed.",
		},
		"ext_key_usage_oids": {
			Type:        framework.TypeCommaStringSlice,
			Description: "Extended key usages as dotted decimal OIDs, for values the Go constants do not cover.",
		},
		"server_flag": {
			Type:        framework.TypeBool,
			Default:     true,
			Description: "Mark the certificate for server authentication.",
		},
		"client_flag": {
			Type:        framework.TypeBool,
			Default:     true,
			Description: "Mark the certificate for client authentication.",
		},
		"code_signing_flag": {
			Type:        framework.TypeBool,
			Default:     false,
			Description: "Mark the certificate for code signing.",
		},
		"email_protection_flag": {
			Type:        framework.TypeBool,
			Default:     false,
			Description: "Mark the certificate for email protection.",
		},
		"use_csr_common_name": {
			Type:        framework.TypeBool,
			Default:     true,
			Description: "Take the common name from the request that is signed, when it carries one.",
		},
		"use_csr_sans": {
			Type:        framework.TypeBool,
			Default:     true,
			Description: "Take the subject alternative names from the request that is signed.",
		},
	}
}

// applyRoleFields writes the fields the caller actually supplied. It is used
// both for creating a role, from the defaults, and for patching one, from the
// stored record.
func applyRoleFields(role *roleEntry, d *framework.FieldData) {
	if _, ok := d.Raw["issuer_ref"]; ok {
		role.IssuerRef = d.Get("issuer_ref").(string)
	}
	if _, ok := d.Raw["ttl"]; ok {
		role.TTL = time.Duration(d.Get("ttl").(int)) * time.Second
	}
	if _, ok := d.Raw["max_ttl"]; ok {
		role.MaxTTL = time.Duration(d.Get("max_ttl").(int)) * time.Second
	}
	if _, ok := d.Raw["not_before_duration"]; ok {
		role.NotBeforeDuration = time.Duration(d.Get("not_before_duration").(int)) * time.Second
	}
	if _, ok := d.Raw["not_after"]; ok {
		role.NotAfter = d.Get("not_after").(time.Time)
	}
	if _, ok := d.Raw["policy_identifiers"]; ok {
		role.PolicyIdentifiers = d.Get("policy_identifiers").([]string)
	}
	if _, ok := d.Raw["no_store"]; ok {
		role.NoStore = d.Get("no_store").(bool)
	}
	if _, ok := d.Raw["generate_lease"]; ok {
		role.GenerateLease = d.Get("generate_lease").(bool)
	}
	if _, ok := d.Raw["organization"]; ok {
		role.Organization = d.Get("organization").([]string)
	}
	if _, ok := d.Raw["ou"]; ok {
		role.OU = d.Get("ou").([]string)
	}
	if _, ok := d.Raw["country"]; ok {
		role.Country = d.Get("country").([]string)
	}
	if _, ok := d.Raw["locality"]; ok {
		role.Locality = d.Get("locality").([]string)
	}
	if _, ok := d.Raw["province"]; ok {
		role.Province = d.Get("province").([]string)
	}
	if _, ok := d.Raw["street_address"]; ok {
		role.StreetAddress = d.Get("street_address").([]string)
	}
	if _, ok := d.Raw["postal_code"]; ok {
		role.PostalCode = d.Get("postal_code").([]string)
	}
	if _, ok := d.Raw["serial_number"]; ok {
		role.SubjectSerialNumber = d.Get("serial_number").(string)
	}
	if _, ok := d.Raw["require_cn"]; ok {
		role.RequireCN = d.Get("require_cn").(bool)
	}
	if _, ok := d.Raw["allowed_domains"]; ok {
		role.AllowedDomains = d.Get("allowed_domains").([]string)
	}
	if _, ok := d.Raw["allow_bare_domains"]; ok {
		role.AllowBareDomains = d.Get("allow_bare_domains").(bool)
	}
	if _, ok := d.Raw["allow_subdomains"]; ok {
		role.AllowSubdomains = d.Get("allow_subdomains").(bool)
	}
	if _, ok := d.Raw["allow_glob_domains"]; ok {
		role.AllowGlobDomains = d.Get("allow_glob_domains").(bool)
	}
	if _, ok := d.Raw["allow_any_name"]; ok {
		role.AllowAnyName = d.Get("allow_any_name").(bool)
	}
	if _, ok := d.Raw["allow_wildcard_certificates"]; ok {
		role.AllowWildcardCertificates = d.Get("allow_wildcard_certificates").(bool)
	}
	if _, ok := d.Raw["allow_localhost"]; ok {
		role.AllowLocalhost = d.Get("allow_localhost").(bool)
	}
	if _, ok := d.Raw["enforce_hostnames"]; ok {
		role.EnforceHostnames = d.Get("enforce_hostnames").(bool)
	}
	if _, ok := d.Raw["allow_ip_sans"]; ok {
		role.AllowIPSANs = d.Get("allow_ip_sans").(bool)
	}
	if _, ok := d.Raw["allowed_uri_sans"]; ok {
		role.AllowedURISANs = d.Get("allowed_uri_sans").([]string)
	}
	if _, ok := d.Raw["allowed_other_sans"]; ok {
		role.AllowedOtherSANs = d.Get("allowed_other_sans").([]string)
	}
	if _, ok := d.Raw["cn_validations"]; ok {
		role.CNValidations = d.Get("cn_validations").([]string)
	}
	if _, ok := d.Raw["key_usage"]; ok {
		role.KeyUsage = d.Get("key_usage").([]string)
	}
	if _, ok := d.Raw["ext_key_usage"]; ok {
		role.ExtKeyUsage = d.Get("ext_key_usage").([]string)
	}
	if _, ok := d.Raw["ext_key_usage_oids"]; ok {
		role.ExtKeyUsageOIDs = d.Get("ext_key_usage_oids").([]string)
	}
	if _, ok := d.Raw["server_flag"]; ok {
		role.ServerFlag = d.Get("server_flag").(bool)
	}
	if _, ok := d.Raw["client_flag"]; ok {
		role.ClientFlag = d.Get("client_flag").(bool)
	}
	if _, ok := d.Raw["code_signing_flag"]; ok {
		role.CodeSigningFlag = d.Get("code_signing_flag").(bool)
	}
	if _, ok := d.Raw["email_protection_flag"]; ok {
		role.EmailProtectionFlag = d.Get("email_protection_flag").(bool)
	}
	if _, ok := d.Raw["use_csr_common_name"]; ok {
		role.UseCSRCommonName = d.Get("use_csr_common_name").(bool)
	}
	if _, ok := d.Raw["use_csr_sans"]; ok {
		role.UseCSRSANs = d.Get("use_csr_sans").(bool)
	}
}

// validateRole refuses a policy that cannot produce a certificate, so the
// mistake is reported where it was made rather than at the first request.
func validateRole(role *roleEntry) error {
	// Whether the ref names an issuer is a question about the mount rather than
	// about the role, and an operator may write the role before the authority it
	// names is there, so the ref is resolved when a certificate is issued.
	if role.IssuerRef != strings.TrimSpace(role.IssuerRef) || strings.Contains(role.IssuerRef, "/") {
		return fmt.Errorf("issuer_ref %q cannot contain a slash or a leading or trailing space", role.IssuerRef)
	}
	if role.TTL <= 0 {
		return errors.New("ttl must be positive")
	}
	if role.MaxTTL <= 0 {
		return errors.New("max_ttl must be positive")
	}
	if role.TTL > role.MaxTTL {
		return errors.New("ttl cannot be longer than max_ttl")
	}
	if role.NotBeforeDuration > role.MaxTTL {
		return errors.New("not_before_duration cannot be longer than max_ttl")
	}

	for _, validation := range role.CNValidations {
		switch strings.ToLower(strings.TrimSpace(validation)) {
		case "email", "hostname":
		default:
			return fmt.Errorf(`cn_validations entry %q is not supported; use "email" or "hostname"`, validation)
		}
	}

	if _, err := role.policyIdentifiers(); err != nil {
		return err
	}

	// A pattern is parsed here for the same reason: a role that can never match
	// what a request writes refuses every request, and that is better said now.
	for _, pattern := range role.AllowedOtherSANs {
		if _, err := parseOtherSAN(strings.TrimSpace(pattern)); err != nil {
			return fmt.Errorf("allowed_other_sans: %w", err)
		}
	}

	if _, err := role.keyUsage(); err != nil {
		return err
	}
	if _, _, err := role.extKeyUsage(); err != nil {
		return err
	}

	return nil
}

// roleData is the representation read back by roles/:name.
func roleData(role *roleEntry) map[string]interface{} {
	return map[string]interface{}{
		"issuer_ref":                  role.IssuerRef,
		"ttl":                         int64(role.TTL / time.Second),
		"max_ttl":                     int64(role.MaxTTL / time.Second),
		"not_before_duration":         int64(role.NotBeforeDuration / time.Second),
		"not_after":                   role.NotAfter,
		"no_store":                    role.NoStore,
		"generate_lease":              role.GenerateLease,
		"organization":                role.Organization,
		"ou":                          role.OU,
		"country":                     role.Country,
		"locality":                    role.Locality,
		"province":                    role.Province,
		"street_address":              role.StreetAddress,
		"postal_code":                 role.PostalCode,
		"serial_number":               role.SubjectSerialNumber,
		"require_cn":                  role.RequireCN,
		"allowed_domains":             role.AllowedDomains,
		"allow_bare_domains":          role.AllowBareDomains,
		"allow_subdomains":            role.AllowSubdomains,
		"allow_glob_domains":          role.AllowGlobDomains,
		"allow_any_name":              role.AllowAnyName,
		"allow_wildcard_certificates": role.AllowWildcardCertificates,
		"allow_localhost":             role.AllowLocalhost,
		"enforce_hostnames":           role.EnforceHostnames,
		"allow_ip_sans":               role.AllowIPSANs,
		"allowed_uri_sans":            role.AllowedURISANs,
		"allowed_other_sans":          role.AllowedOtherSANs,
		"cn_validations":              role.CNValidations,
		"policy_identifiers":          role.PolicyIdentifiers,
		"key_usage":                   role.KeyUsage,
		"ext_key_usage":               role.ExtKeyUsage,
		"ext_key_usage_oids":          role.ExtKeyUsageOIDs,
		"server_flag":                 role.ServerFlag,
		"client_flag":                 role.ClientFlag,
		"code_signing_flag":           role.CodeSigningFlag,
		"email_protection_flag":       role.EmailProtectionFlag,
		"use_csr_common_name":         role.UseCSRCommonName,
		"use_csr_sans":                role.UseCSRSANs,
	}
}
