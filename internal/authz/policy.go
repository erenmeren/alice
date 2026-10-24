package authz

// Service policy, schema 1 (R55, design docs/superpowers/specs/2026-10-21-scoped-rbac-and-service-ownership-design.md
// §7.3): what may enter a service (the names of its certificates, how certificates enter, the ACME providers,
// challenges and key types) and the defaults it sets (the renewal window of a new ACME certificate, the revocation mode
// of an incident), whether automatic deployment may run for it, and who else receives its e-mails. The document is
// parsed here with every unknown field refused; the checks are pure and run inside the callers' own transactions
// (LoadPolicy reads the current version).

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/mail"
	"net/netip"
	"slices"
	"strconv"
	"strings"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"alice/internal/platform/db"
	"alice/internal/platform/validate"
)

// PolicySchema is the policy schema this Alice reads and writes.
const PolicySchema = 1

// Bounds and values of schema 1.
const (
	MaxPolicyBytes        = 64 << 10 // service_policies.body is at most 65536 bytes
	MaxPolicyDomains      = 200
	MaxPolicyProviders    = 50
	MaxPolicyAddresses    = 20
	MinPolicyRenewDays    = 1
	MaxPolicyRenewDays    = 60
	maxPolicyAddressBytes = 254
)

// The certificate sources a policy may allow (how a certificate enters the service).
const (
	SourceACME     = "acme"
	SourceUploaded = "uploaded"
	SourceCSR      = "csr"
)

// The values of deployment.auto_deploy and incident.revoke_mode.
const (
	AutoDeployAllowed   = "allowed"
	AutoDeployForbidden = "forbidden"
	RevokeAfterVerified = "after_verified"
	RevokeNow           = "now"
)

var (
	policySources    = []string{SourceACME, SourceUploaded, SourceCSR}
	policyChallenges = []string{"dns01", "http01"}
	// PolicyKeyTypes are the ACME key policies (keygen.Policies; a test in inventory keeps the two lists equal).
	PolicyKeyTypes   = []string{"ecdsa_p256", "ecdsa_p384", "rsa_2048", "rsa_3072", "rsa_4096"}
	policyAutoDeploy = []string{AutoDeployAllowed, AutoDeployForbidden}
	policyRevoke     = []string{RevokeAfterVerified, RevokeNow}
	policyLocales    = []string{"en", "tr"}
)

// ReservedPolicyKeys are the top-level keys kept for later work (design §7.4): refused now with
// ErrPolicyFieldUnavailable, so adding them later breaks no client. "canary" left the list with R65 (canary.go).
var ReservedPolicyKeys = []string{"verification", "drift", "windows", "thresholds"}

// Policy is one service policy (schema 1). Every field is optional: absent (and an empty list) is no constraint, or
// today's default. The zero value with Schema 1 is the empty policy every service starts with.
type Policy struct {
	Schema             int                  `json:"schema"`
	Domains            []string             `json:"domains,omitempty"`
	CertificateSources []string             `json:"certificate_sources,omitempty"`
	ACME               *ACMEPolicy          `json:"acme,omitempty"`
	Deployment         *DeploymentPolicy    `json:"deployment,omitempty"`
	Incident           *IncidentPolicy      `json:"incident,omitempty"`
	Notifications      *NotificationsPolicy `json:"notifications,omitempty"`
	Canary             *CanaryPolicy        `json:"canary,omitempty"`
}

// ACMEPolicy limits the service's ACME certificates (providers, challenges, key types) and sets the renewal window a
// new one starts with.
type ACMEPolicy struct {
	Providers       []uuid.UUID `json:"providers,omitempty"`
	Challenges      []string    `json:"challenges,omitempty"`
	KeyTypes        []string    `json:"key_types,omitempty"`
	RenewBeforeDays *int        `json:"renew_before_days,omitempty"`
}

// DeploymentPolicy says whether automatic deployment may run for the service's Key Vault bindings and ACME
// certificates.
type DeploymentPolicy struct {
	AutoDeploy string `json:"auto_deploy,omitempty"`
}

// IncidentPolicy sets the revocation mode an incident on the service's certificates starts with.
type IncidentPolicy struct {
	RevokeMode string `json:"revoke_mode,omitempty"`
}

// NotificationsPolicy is who receives the service's e-mails besides its owners (design §7.2; read by the
// notification routing): the Administrators (absent: true) and extra addresses.
type NotificationsPolicy struct {
	Administrators *bool           `json:"administrators,omitempty"`
	Addresses      []PolicyAddress `json:"addresses,omitempty"`
}

// PolicyAddress is an extra recipient of the service's e-mails, in its language.
type PolicyAddress struct {
	Email  string `json:"email"`
	Locale string `json:"locale"`
}

// Errors of a policy and of its checks (the API maps each to its ALC-SVC code).
var (
	// ErrPolicyMalformed: the document is not a JSON object of schema 1's fields (an unknown field, a wrong type).
	ErrPolicyMalformed = errors.New("authz: the policy is not a policy document")
	// ErrPolicyFieldUnavailable: a top-level key reserved for later work (*FieldUnavailableError names it).
	ErrPolicyFieldUnavailable = errors.New("authz: the policy field is not available yet")
	// ErrDomainNotAllowed: a name is outside the service's domains (*DomainError names it).
	ErrDomainNotAllowed = errors.New("authz: a name is outside the service's domains")
	// ErrSourceNotAllowed: the service does not accept certificates from this source (*SourceError names it).
	ErrSourceNotAllowed = errors.New("authz: the service does not accept certificates from this source")
	// ErrACMENotAllowed: the provider, challenge or key type is not one the service allows (*ACMEPolicyError).
	ErrACMENotAllowed = errors.New("authz: the service does not allow this ACME provider, challenge or key type")
	// ErrAutoDeployForbidden: the service's policy forbids automatic deployment.
	ErrAutoDeployForbidden = errors.New("authz: the service's policy forbids automatic deployment")
)

// FieldUnavailableError names the reserved key a policy used.
type FieldUnavailableError struct{ Key string }

func (e *FieldUnavailableError) Error() string {
	return ErrPolicyFieldUnavailable.Error() + ": " + e.Key
}

// Is makes errors.Is(err, ErrPolicyFieldUnavailable) true.
func (e *FieldUnavailableError) Is(target error) bool { return target == ErrPolicyFieldUnavailable }

// DomainError names the first name outside the service's domains, and the request field that carried it ("" when the
// caller knows it better).
type DomainError struct{ Name, Field string }

func (e *DomainError) Error() string { return ErrDomainNotAllowed.Error() + ": " + e.Name }

// Is makes errors.Is(err, ErrDomainNotAllowed) true.
func (e *DomainError) Is(target error) bool { return target == ErrDomainNotAllowed }

// SourceError names the source the service does not accept.
type SourceError struct{ Source string }

func (e *SourceError) Error() string { return ErrSourceNotAllowed.Error() + ": " + e.Source }

// Is makes errors.Is(err, ErrSourceNotAllowed) true.
func (e *SourceError) Is(target error) bool { return target == ErrSourceNotAllowed }

// ACMEPolicyError names the request field whose value the service does not allow: provider_id, challenge or key_type.
type ACMEPolicyError struct{ Field string }

func (e *ACMEPolicyError) Error() string { return ErrACMENotAllowed.Error() + ": " + e.Field }

// Is makes errors.Is(err, ErrACMENotAllowed) true.
func (e *ACMEPolicyError) Is(target error) bool { return target == ErrACMENotAllowed }

// EmptyPolicy is the policy every service starts with.
func EmptyPolicy() Policy { return Policy{Schema: PolicySchema} }

// ParsePolicy reads and validates a policy document: a JSON object of schema 1 with no unknown field
// (ErrPolicyMalformed), no reserved key (*FieldUnavailableError), and valid values (validate.Errors with fields named
// prefix + the document's path, e.g. "body.domains.2"). The answer is normalized: names in lower case, empty lists and
// objects dropped, so that equal policies have equal documents (Document).
func ParsePolicy(raw []byte, prefix string) (Policy, error) {
	raw = bytes.TrimSpace(raw)
	if len(raw) == 0 || len(raw) > MaxPolicyBytes || raw[0] != '{' {
		return Policy{}, ErrPolicyMalformed
	}
	var top map[string]json.RawMessage
	if err := json.Unmarshal(raw, &top); err != nil {
		return Policy{}, ErrPolicyMalformed
	}
	for _, k := range ReservedPolicyKeys {
		if _, ok := top[k]; ok {
			return Policy{}, &FieldUnavailableError{Key: k}
		}
	}
	var p Policy
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&p); err != nil || dec.More() {
		return Policy{}, ErrPolicyMalformed
	}
	var v validate.Errors
	p.normalize(&v, prefix)
	if err := v.Err(); err != nil {
		return Policy{}, err
	}
	return p, nil
}

func (p *Policy) normalize(v *validate.Errors, prefix string) {
	if p.Schema != PolicySchema {
		v.Add(prefix+"schema", validate.OneOf, map[string]string{"values": strconv.Itoa(PolicySchema)})
	}
	if len(p.Domains) > MaxPolicyDomains {
		v.Add(prefix+"domains", validate.TooLong, map[string]string{"max": strconv.Itoa(MaxPolicyDomains)})
	} else {
		for i, d := range p.Domains {
			field := prefix + "domains." + strconv.Itoa(i)
			n, ok := normalizeDomainEntry(d)
			switch {
			case !ok:
				v.Add(field, validate.Pattern, nil)
			case slices.Contains(p.Domains[:i], n):
				v.Add(field, validate.Duplicate, nil)
			}
			p.Domains[i] = n
		}
	}
	p.CertificateSources = closedList(v, prefix+"certificate_sources", p.CertificateSources, policySources)
	if a := p.ACME; a != nil {
		if len(a.Providers) > MaxPolicyProviders {
			v.Add(prefix+"acme.providers", validate.TooLong, map[string]string{"max": strconv.Itoa(MaxPolicyProviders)})
		}
		for i, id := range a.Providers {
			field := prefix + "acme.providers." + strconv.Itoa(i)
			switch {
			case id == uuid.Nil:
				v.Add(field, validate.Required, nil)
			case slices.Contains(a.Providers[:i], id):
				v.Add(field, validate.Duplicate, nil)
			}
		}
		a.Challenges = closedList(v, prefix+"acme.challenges", a.Challenges, policyChallenges)
		a.KeyTypes = closedList(v, prefix+"acme.key_types", a.KeyTypes, PolicyKeyTypes)
		if a.RenewBeforeDays != nil && (*a.RenewBeforeDays < MinPolicyRenewDays || *a.RenewBeforeDays > MaxPolicyRenewDays) {
			v.Add(prefix+"acme.renew_before_days", validate.OutOfRange, map[string]string{"min": strconv.Itoa(MinPolicyRenewDays),
				"max": strconv.Itoa(MaxPolicyRenewDays)})
		}
		if len(a.Providers) == 0 {
			a.Providers = nil
		}
		if a.Providers == nil && a.Challenges == nil && a.KeyTypes == nil && a.RenewBeforeDays == nil {
			p.ACME = nil
		}
	}
	if d := p.Deployment; d != nil {
		closedValue(v, prefix+"deployment.auto_deploy", d.AutoDeploy, policyAutoDeploy)
		if d.AutoDeploy == "" {
			p.Deployment = nil
		}
	}
	if in := p.Incident; in != nil {
		closedValue(v, prefix+"incident.revoke_mode", in.RevokeMode, policyRevoke)
		if in.RevokeMode == "" {
			p.Incident = nil
		}
	}
	if n := p.Notifications; n != nil {
		if len(n.Addresses) > MaxPolicyAddresses {
			v.Add(prefix+"notifications.addresses", validate.TooLong, map[string]string{"max": strconv.Itoa(MaxPolicyAddresses)})
		} else {
			for i, ad := range n.Addresses {
				field := prefix + "notifications.addresses." + strconv.Itoa(i)
				switch {
				case !bareAddress(ad.Email):
					v.Add(field+".email", validate.Email, nil)
				case slices.ContainsFunc(n.Addresses[:i], func(o PolicyAddress) bool { return strings.EqualFold(o.Email, ad.Email) }):
					v.Add(field+".email", validate.Duplicate, nil)
				}
				if !slices.Contains(policyLocales, ad.Locale) {
					v.Add(field+".locale", validate.OneOf, map[string]string{"values": strings.Join(policyLocales, ", ")})
				}
			}
		}
		if len(n.Addresses) == 0 {
			n.Addresses = nil
		}
		if n.Administrators == nil && n.Addresses == nil {
			p.Notifications = nil
		}
	}
	if c := p.Canary; c != nil && !c.normalize(v, prefix+"canary") {
		p.Canary = nil
	}
	if len(p.Domains) == 0 {
		p.Domains = nil
	}
}

// closedList checks a list of closed values (each once); an empty list is no constraint (nil).
func closedList(v *validate.Errors, field string, in, values []string) []string {
	for i, s := range in {
		switch {
		case !slices.Contains(values, s):
			v.Add(field+"."+strconv.Itoa(i), validate.OneOf, map[string]string{"values": strings.Join(values, ", ")})
		case slices.Contains(in[:i], s):
			v.Add(field+"."+strconv.Itoa(i), validate.Duplicate, nil)
		}
	}
	if len(in) == 0 {
		return nil
	}
	return in
}

// closedValue checks an optional closed value ("" is absent).
func closedValue(v *validate.Errors, field, s string, values []string) {
	if s != "" && !slices.Contains(values, s) {
		v.Add(field, validate.OneOf, map[string]string{"values": strings.Join(values, ", ")})
	}
}

// bareAddress accepts only the plain form local@domain (as the notification settings do: the address the audit row
// and the mailer use is the same text).
func bareAddress(s string) bool {
	if s == "" || len(s) > maxPolicyAddressBytes {
		return false
	}
	a, err := mail.ParseAddress(s)
	return err == nil && a.Name == "" && a.Address == s
}

// normalizeDomainEntry reads one domains entry: a DNS name (lower case), a wildcard "*.suffix" over at least two
// labels, an IP address or a CIDR block written with its network address. It answers the stored form.
func normalizeDomainEntry(s string) (string, bool) {
	s = strings.TrimSpace(s)
	if strings.Contains(s, "/") {
		p, err := netip.ParsePrefix(s)
		if err != nil || p.Masked() != p || p.Addr().Is4In6() {
			return s, false // a block written with host bits, or IPv4 written as IPv6: say what is meant
		}
		return p.String(), true
	}
	if a, err := netip.ParseAddr(s); err == nil {
		if a.Zone() != "" {
			return s, false
		}
		return a.Unmap().String(), true
	}
	n := foldASCII(s)
	return n, validDNSName(n)
}

// foldASCII lowers the ASCII letters only (a DNS name is ASCII; strings.ToLower would follow the Unicode rules, which
// the Turkish dotted and dotless i make locale-dependent).
func foldASCII(s string) string {
	b := []byte(s)
	for i, c := range b {
		if 'A' <= c && c <= 'Z' {
			b[i] = c + ('a' - 'A')
		}
	}
	return string(b)
}

// validDNSName is certs.ValidDNSName (authz knows the platform only): lower-case LDH labels of 1..63, at most 253 in
// all, an optional leading "*." over at least two labels.
func validDNSName(s string) bool {
	if len(s) == 0 || len(s) > 253 {
		return false
	}
	rest := s
	if strings.HasPrefix(s, "*.") {
		rest = s[2:]
		if !strings.Contains(rest, ".") {
			return false
		}
	}
	for _, label := range strings.Split(rest, ".") {
		if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for j := 0; j < len(label); j++ {
			c := label[j]
			if (c < 'a' || c > 'z') && (c < '0' || c > '9') && c != '-' {
				return false
			}
		}
	}
	return true
}

// Document is the policy as stored and answered (keys in a fixed order, empty fields left out).
func (p Policy) Document() json.RawMessage {
	b, err := json.Marshal(p)
	if err != nil { // a Policy always marshals
		panic(fmt.Sprintf("authz: marshal the policy: %v", err))
	}
	return b
}

// topLevel is the document by top-level key, for ChangedKeys.
func (p Policy) topLevel() map[string]string {
	var m map[string]json.RawMessage
	_ = json.Unmarshal(p.Document(), &m)
	out := make(map[string]string, len(m))
	for k, v := range m {
		out[k] = string(v)
	}
	return out
}

// ChangedKeys lists, sorted, the top-level keys whose value differs between two policies (added and removed ones
// included): what the audit row of a policy change names.
func ChangedKeys(old, updated Policy) []string {
	a, b := old.topLevel(), updated.topLevel()
	var out []string
	for k, v := range b {
		if a[k] != v {
			out = append(out, k)
		}
	}
	for k := range a {
		if _, ok := b[k]; !ok {
			out = append(out, k)
		}
	}
	slices.Sort(out)
	return out
}

// SameDomains reports whether two policies constrain the same names (the same entries, in any order).
func SameDomains(a, b Policy) bool {
	x, y := slices.Clone(a.Domains), slices.Clone(b.Domains)
	slices.Sort(x)
	slices.Sort(y)
	return slices.Equal(x, y)
}

// NameAllowed reports whether a certificate name may enter the service: always when the policy has no domains;
// otherwise a DNS name matches an entry equal to it or a wildcard entry "*.suffix" whose ".suffix" it ends with (at any
// depth, wildcard names included: "*.pay.example.com" matches "a.b.pay.example.com" and "*.x.pay.example.com", not
// "pay.example.com"), and an IP address matches an IP entry equal to it or a CIDR entry containing it.
func (p Policy) NameAllowed(name string) bool {
	if len(p.Domains) == 0 {
		return true
	}
	if ip, err := netip.ParseAddr(strings.TrimSpace(name)); err == nil {
		ip = ip.WithZone("").Unmap()
		for _, e := range p.Domains {
			if pre, err := netip.ParsePrefix(e); err == nil && pre.Contains(ip) {
				return true
			}
			if a, err := netip.ParseAddr(e); err == nil && a == ip {
				return true
			}
		}
		return false
	}
	n := strings.TrimSuffix(foldASCII(strings.TrimSpace(name)), ".")
	for _, e := range p.Domains {
		if suffix, ok := strings.CutPrefix(e, "*"); ok {
			if len(n) > len(suffix) && strings.HasSuffix(n, suffix) {
				return true
			}
			continue
		}
		if n == e {
			return true
		}
	}
	return false
}

// CheckNames is the domains rule for the names of a certificate entering the service: a *DomainError naming the first
// name outside (with field), or nil.
func (p Policy) CheckNames(field string, names []string) error {
	for _, n := range names {
		if !p.NameAllowed(n) {
			return &DomainError{Name: n, Field: field}
		}
	}
	return nil
}

// CertificateNames are the names of a certificate the domains rule judges: its subject alternative names and its
// common name when that is a DNS name or an IP address (a common name such as "My server" names no host).
func CertificateNames(commonName string, sans []string) []string {
	out := slices.Clone(sans)
	cn := strings.TrimSpace(commonName)
	if cn == "" || slices.ContainsFunc(out, func(s string) bool { return strings.EqualFold(s, cn) }) {
		return out
	}
	if _, err := netip.ParseAddr(cn); err == nil || validDNSName(foldASCII(cn)) {
		out = append([]string{cn}, out...)
	}
	return out
}

// CheckSource refuses a source the policy's certificate_sources does not list (*SourceError); no list allows all.
func (p Policy) CheckSource(source string) error {
	if len(p.CertificateSources) > 0 && !slices.Contains(p.CertificateSources, source) {
		return &SourceError{Source: source}
	}
	return nil
}

// CheckACME refuses an ACME certificate whose provider, challenge or key type the policy does not allow
// (*ACMEPolicyError naming the request field).
func (p Policy) CheckACME(provider uuid.UUID, challenge, keyType string) error {
	return p.CheckACMEChanges(&provider, &challenge, &keyType)
}

// CheckACMEChanges is CheckACME for a change of an ACME certificate: only the values given (non-nil) are judged, so a
// policy made stricter after the certificate was created refuses no change of its other fields (a policy is never
// applied to what exists).
func (p Policy) CheckACMEChanges(provider *uuid.UUID, challenge, keyType *string) error {
	a := p.ACME
	switch {
	case a == nil:
		return nil
	case provider != nil && len(a.Providers) > 0 && !slices.Contains(a.Providers, *provider):
		return &ACMEPolicyError{Field: "provider_id"}
	case challenge != nil && len(a.Challenges) > 0 && !slices.Contains(a.Challenges, *challenge):
		return &ACMEPolicyError{Field: "challenge"}
	case keyType != nil && len(a.KeyTypes) > 0 && !slices.Contains(a.KeyTypes, *keyType):
		return &ACMEPolicyError{Field: "key_type"}
	}
	return nil
}

// AutoDeployForbidden reports whether the policy forbids automatic deployment.
func (p Policy) AutoDeployForbidden() bool {
	return p.Deployment != nil && p.Deployment.AutoDeploy == AutoDeployForbidden
}

// CheckAutoDeploy refuses switching automatic deployment on while the policy forbids it (ErrAutoDeployForbidden).
func (p Policy) CheckAutoDeploy() error {
	if p.AutoDeployForbidden() {
		return ErrAutoDeployForbidden
	}
	return nil
}

// RenewBeforeDays is the renewal window a new ACME certificate of the service starts with (0: Alice's default).
func (p Policy) RenewBeforeDays() int {
	if p.ACME == nil || p.ACME.RenewBeforeDays == nil {
		return 0
	}
	return *p.ACME.RenewBeforeDays
}

// RevokeMode is the revocation mode an incident on the service's certificates starts with ("": Alice's default).
func (p Policy) RevokeMode() string {
	if p.Incident == nil {
		return ""
	}
	return p.Incident.RevokeMode
}

// LoadPolicy reads the current policy of a service in q (a transaction: the version its other statements see). A
// stored document this Alice cannot read is an error, never "no constraint". An unknown service is the empty policy:
// the caller resolved the service first.
func LoadPolicy(ctx context.Context, q db.Querier, service uuid.UUID) (Policy, error) {
	var body []byte
	err := q.QueryRow(ctx, `SELECT p.body FROM services s JOIN service_policies p ON p.service_id = s.id AND p.version = s.policy_version
WHERE s.id = $1`, service).Scan(&body)
	if errors.Is(err, pgx.ErrNoRows) {
		return EmptyPolicy(), nil
	}
	if err != nil {
		return Policy{}, fmt.Errorf("authz: read the service's policy: %w", err)
	}
	p, err := ParsePolicy(body, "")
	if err != nil {
		return Policy{}, fmt.Errorf("authz: the stored policy of service %s does not parse: %w", service, err)
	}
	return p, nil
}
