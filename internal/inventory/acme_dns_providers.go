package inventory

import (
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"

	"alice/internal/acme/solver/dnssolver"
	"alice/internal/certs"
	"alice/internal/platform/azureid"
	"alice/internal/platform/validate"
	"alice/internal/providers"
	"alice/internal/secrets"
)

// Built-in DNS providers (R57). A DNS publisher (acme_hooks row) of a kind other than webhook is a DNS service Alice
// drives through its API: Cloudflare (an API token), Azure DNS (a service principal with a client secret or a
// certificate, or the managed identity of Alice's machine; a subscription and a resource group) or Amazon Route 53
// (an access key, optionally assuming a role). Its non-secret settings are the row's settings (shown, audited); its
// credentials are one JSON document sealed in the row's secret columns (AAD acme_hooks/<id>/secret, as a hook's
// secret), write-only like the hook's secret: the views carry SecretConfigured only. A provider has no URL and no CA
// bundle (it reaches the provider's fixed hosts with the system roots). Creating or changing one makes no network call.

// DNS publisher kinds (acme_hooks.kind).
const (
	ACMEHookKindWebhook    = dnssolver.KindWebhook
	ACMEHookKindCloudflare = dnssolver.KindCloudflare
	ACMEHookKindAzureDNS   = dnssolver.KindAzureDNS
	ACMEHookKindRoute53    = dnssolver.KindRoute53
)

// Limits of a provider's credentials and settings.
const (
	minDNSTokenLen      = 20
	maxDNSTokenLen      = 256
	minAWSSecretLen     = 16
	maxAWSSecretLen     = 128
	maxResourceGroupLen = 90
)

var (
	awsAccessKeyRE  = regexp.MustCompile(`^[A-Z0-9]{16,128}$`)
	awsRoleARNRE    = regexp.MustCompile(`^arn:aws:iam::[0-9]{12}:role/[A-Za-z0-9+=,.@_/-]{1,512}$`)
	awsExternalIDRE = regexp.MustCompile(`^[A-Za-z0-9+=,.@:/-]+$`) // 2..1224 characters (Go's regexp repeats at most 1000)
	resourceGroupRE = regexp.MustCompile(`^[-\w._()]+$`)
)

// ACMEDNSSettings are a provider's non-secret settings (empty for a hook and for Cloudflare). The certificate fields
// are Alice's own reading of an Azure sign-in certificate, never input.
type ACMEDNSSettings struct {
	// Azure DNS.
	Auth           string     `json:"auth,omitempty"` // providers.AzureAuth*
	TenantID       string     `json:"tenant_id,omitempty"`
	ClientID       string     `json:"client_id,omitempty"`
	SubscriptionID string     `json:"subscription_id,omitempty"`
	ResourceGroup  string     `json:"resource_group,omitempty"`
	CertThumbprint string     `json:"cert_thumbprint,omitempty"`
	CertNotAfter   *time.Time `json:"cert_not_after,omitempty"`
	// Amazon Route 53.
	AccessKeyID string `json:"access_key_id,omitempty"`
	RoleARN     string `json:"role_arn,omitempty"`
	ExternalID  string `json:"external_id,omitempty"`
}

// ACMEDNSCredentials are a provider's credentials as an administrator gives them. Zero clears them in place.
type ACMEDNSCredentials struct {
	APIToken        secrets.Plaintext // Cloudflare
	ClientSecret    secrets.Plaintext // Azure DNS, client_secret
	Certificate     certs.Upload      // Azure DNS, certificate: the certificate registered with the application and its RSA key
	SecretAccessKey secrets.Plaintext // Route 53
}

// Given reports whether any credential was given.
func (c ACMEDNSCredentials) Given() bool {
	return len(c.APIToken.Bytes()) > 0 || len(c.ClientSecret.Bytes()) > 0 || hasCertificate(c.Certificate) || len(c.SecretAccessKey.Bytes()) > 0
}

// Zero clears every credential in place (the PEM key and the PFX too).
func (c ACMEDNSCredentials) Zero() {
	c.APIToken.Zero()
	c.ClientSecret.Zero()
	c.SecretAccessKey.Zero()
	clear(c.Certificate.PrivateKeyPEM)
	clear(c.Certificate.PFX)
}

// dnsCredentialDoc is the sealed form of a provider's credentials (base64 in JSON). Only the fields of the kind and
// sign-in method are set; a managed identity's document is "{}".
type dnsCredentialDoc struct {
	APIToken        []byte `json:"api_token,omitempty"`
	ClientSecret    []byte `json:"client_secret,omitempty"`
	CertificateDER  []byte `json:"certificate_der,omitempty"`
	PrivateKeyDER   []byte `json:"private_key_der,omitempty"`
	SecretAccessKey []byte `json:"secret_access_key,omitempty"`
}

func (d *dnsCredentialDoc) zero() {
	clear(d.APIToken)
	clear(d.ClientSecret)
	clear(d.PrivateKeyDER)
	clear(d.SecretAccessKey)
}

// encode writes the document into a buffer the caller owns and clears (no intermediate copy of a secret is left to
// the JSON encoder's pools).
func (d *dnsCredentialDoc) encode() []byte {
	out := []byte{'{'}
	field := func(name string, v []byte) {
		if len(v) == 0 {
			return
		}
		if len(out) > 1 {
			out = append(out, ',')
		}
		out = append(out, '"')
		out = append(out, name...)
		out = append(out, '"', ':', '"')
		out = base64.StdEncoding.AppendEncode(out, v)
		out = append(out, '"')
	}
	field("api_token", d.APIToken)
	field("client_secret", d.ClientSecret)
	field("certificate_der", d.CertificateDER)
	field("private_key_der", d.PrivateKeyDER)
	field("secret_access_key", d.SecretAccessKey)
	return append(out, '}')
}

var errDamagedCredentials = errors.New("inventory: the stored DNS provider credentials are damaged")

func decodeDNSCredentials(b []byte) (dnsCredentialDoc, error) {
	var d dnsCredentialDoc
	if err := json.Unmarshal(b, &d); err != nil {
		return dnsCredentialDoc{}, errDamagedCredentials
	}
	return d, nil
}

// refuseSettings refuses every settings field given in st (the fields of another kind).
func refuseSettings(errs *validate.Errors, st ACMEDNSSettings) {
	for _, f := range []struct {
		field string
		set   bool
	}{{"auth", st.Auth != ""}, {"tenant_id", st.TenantID != ""}, {"client_id", st.ClientID != ""}, {"subscription_id", st.SubscriptionID != ""},
		{"resource_group", st.ResourceGroup != ""}, {"access_key_id", st.AccessKeyID != ""}, {"role_arn", st.RoleARN != ""},
		{"external_id", st.ExternalID != ""}} {
		if f.set {
			errs.Add(f.field, validate.Pattern, nil)
		}
	}
}

func validKind(kind string) bool { return slices.Contains(dnssolver.Kinds(), kind) }

func kindValues() map[string]string {
	return map[string]string{"values": strings.Join(dnssolver.Kinds(), ", ")}
}

// printableNoSpace reports visible ASCII only (an HTTP header value or a signing key: no space, no control character).
func printableNoSpace(b []byte) bool {
	for _, c := range b {
		if c < 0x21 || c > 0x7e {
			return false
		}
	}
	return true
}

func lengthError(field string, n, lo, hi int) *validate.FieldError {
	switch {
	case n == 0:
		return &validate.FieldError{Field: field, Code: validate.Required}
	case n < lo:
		return &validate.FieldError{Field: field, Code: validate.TooShort, Params: map[string]string{"min": strconv.Itoa(lo)}}
	case n > hi:
		return &validate.FieldError{Field: field, Code: validate.TooLong, Params: map[string]string{"max": strconv.Itoa(hi)}}
	}
	return nil
}

// dnsProviderState is what validation produces for a provider: the stored settings and, when credentials were given
// (or a managed identity needs none), the document to seal.
type dnsProviderState struct {
	settings ACMEDNSSettings
	doc      *dnsCredentialDoc // nil: the stored credentials stay
	release  func()            // zeroes what doc holds
}

// validateDNSProvider checks a provider's settings and credentials. cur is the stored settings of a change (nil for a
// new provider); credentials are required for a new provider, and for a change that alters what they belong to (the
// Azure sign-in method, the AWS access key).
func (s *Service) validateDNSProvider(kind string, cur *ACMEDNSSettings, in ACMEDNSSettings, cred ACMEDNSCredentials, now time.Time) (dnsProviderState, validate.Errors) {
	var errs validate.Errors
	st := dnsProviderState{release: func() {}}
	add := func(fe *validate.FieldError) {
		if fe != nil {
			errs = append(errs, *fe)
		}
	}
	notFor := func(field string, given bool) {
		if given {
			errs.Add(field, validate.Pattern, nil)
		}
	}
	switch kind {
	case ACMEHookKindCloudflare:
		refuseSettings(&errs, in)
		notFor("client_secret", len(cred.ClientSecret.Bytes()) > 0)
		notFor("certificate", hasCertificate(cred.Certificate))
		notFor("secret_access_key", len(cred.SecretAccessKey.Bytes()) > 0)
		tok := cred.APIToken.Bytes()
		if cur != nil && len(tok) == 0 {
			break // the stored token stays
		}
		if fe := lengthError("api_token", len(tok), minDNSTokenLen, maxDNSTokenLen); fe != nil {
			add(fe)
		} else if !printableNoSpace(tok) {
			errs.Add("api_token", validate.Pattern, nil)
		}
		if len(errs) == 0 {
			st.doc = &dnsCredentialDoc{APIToken: slices.Clone(tok)}
		}
	case ACMEHookKindAzureDNS:
		notFor("api_token", len(cred.APIToken.Bytes()) > 0)
		notFor("secret_access_key", len(cred.SecretAccessKey.Bytes()) > 0)
		errs = append(errs, s.validateAzureDNS(cur, in, cred, now, &st)...)
	case ACMEHookKindRoute53:
		notFor("api_token", len(cred.APIToken.Bytes()) > 0)
		notFor("client_secret", len(cred.ClientSecret.Bytes()) > 0)
		notFor("certificate", hasCertificate(cred.Certificate))
		errs = append(errs, validateRoute53(cur, in, cred, &st)...)
	default:
		errs.Add("kind", validate.OneOf, kindValues())
	}
	if len(errs) > 0 {
		st.release()
		if st.doc != nil {
			st.doc.zero()
		}
		return dnsProviderState{}, errs
	}
	return st, nil
}

func (s *Service) validateAzureDNS(cur *ACMEDNSSettings, in ACMEDNSSettings, cred ACMEDNSCredentials, now time.Time, st *dnsProviderState) validate.Errors {
	var errs validate.Errors
	refuseSettings(&errs, ACMEDNSSettings{AccessKeyID: in.AccessKeyID, RoleARN: in.RoleARN, ExternalID: in.ExternalID})
	// The sign-in rules are the Key Vault credential's (one rule for both Azure sign-ins), with its field names.
	keep := cur != nil && cur.Auth == in.Auth && !cred.Given()
	vc := VaultCredentialInput{Auth: in.Auth, TenantID: in.TenantID, ClientID: in.ClientID, ClientSecret: cred.ClientSecret,
		Certificate: cred.Certificate}
	norm, verrs := validateVaultCredential(vc)
	for _, fe := range verrs {
		if keep && fe.Code == validate.Required && (fe.Field == "client_secret" || fe.Field == "certificate") {
			continue // the stored secret or certificate of the same sign-in method stays
		}
		errs = append(errs, fe)
	}
	sub, ok := azureid.NormalizeGUID(in.SubscriptionID)
	switch {
	case strings.TrimSpace(in.SubscriptionID) == "":
		errs.Add("subscription_id", validate.Required, nil)
	case !ok:
		errs.Add("subscription_id", validate.Pattern, nil)
	}
	rg := strings.TrimSpace(in.ResourceGroup)
	switch {
	case rg == "":
		errs.Add("resource_group", validate.Required, nil)
	case len(rg) > maxResourceGroupLen:
		errs.Add("resource_group", validate.TooLong, map[string]string{"max": strconv.Itoa(maxResourceGroupLen)})
	case !resourceGroupRE.MatchString(rg) || strings.HasSuffix(rg, ".") || !isASCII(rg):
		errs.Add("resource_group", validate.Pattern, nil)
	}
	if len(errs) > 0 {
		return errs
	}
	st.settings = ACMEDNSSettings{Auth: norm.Auth, TenantID: norm.TenantID, ClientID: norm.ClientID, SubscriptionID: sub, ResourceGroup: rg}
	if keep {
		st.settings.CertThumbprint, st.settings.CertNotAfter = cur.CertThumbprint, cur.CertNotAfter
		return nil // the stored credentials of the same sign-in method stay
	}
	switch norm.Auth {
	case providers.AzureAuthClientSecret:
		st.doc = &dnsCredentialDoc{ClientSecret: slices.Clone(cred.ClientSecret.Bytes())}
	case providers.AzureAuthCertificate:
		_, info, keyDER, release, err := s.vaultIdentity(VaultCredentialInput{Auth: norm.Auth, Certificate: cred.Certificate}, now)
		if err != nil {
			field := "certificate"
			errs.Add(field, certificateCode(err), nil)
			return errs
		}
		st.doc = &dnsCredentialDoc{CertificateDER: info.CertificateDER, PrivateKeyDER: slices.Clone(keyDER)}
		release()
		st.settings.CertThumbprint, st.settings.CertNotAfter = info.CertThumbprint, info.CertNotAfter
	default:
		st.doc = &dnsCredentialDoc{} // a managed identity has no secret
	}
	return nil
}

// certificateCode is the validation code of an Azure sign-in certificate the certs parser refused.
func certificateCode(err error) string {
	if errors.Is(err, ErrCertificateNotYetValid) {
		return validate.OutOfRange
	}
	return validate.Pattern
}

func isASCII(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] >= 0x80 {
			return false
		}
	}
	return true
}

func validateRoute53(cur *ACMEDNSSettings, in ACMEDNSSettings, cred ACMEDNSCredentials, st *dnsProviderState) validate.Errors {
	var errs validate.Errors
	refuseSettings(&errs, ACMEDNSSettings{Auth: in.Auth, TenantID: in.TenantID, ClientID: in.ClientID, SubscriptionID: in.SubscriptionID,
		ResourceGroup: in.ResourceGroup})
	key := strings.TrimSpace(in.AccessKeyID)
	switch {
	case key == "":
		errs.Add("access_key_id", validate.Required, nil)
	case !awsAccessKeyRE.MatchString(key):
		errs.Add("access_key_id", validate.Pattern, nil)
	}
	role, ext := strings.TrimSpace(in.RoleARN), strings.TrimSpace(in.ExternalID)
	if role != "" && !awsRoleARNRE.MatchString(role) {
		errs.Add("role_arn", validate.Pattern, nil)
	}
	if ext != "" && (role == "" || len(ext) < 2 || len(ext) > 1224 || !awsExternalIDRE.MatchString(ext)) {
		errs.Add("external_id", validate.Pattern, nil)
	}
	secret := cred.SecretAccessKey.Bytes()
	keep := cur != nil && cur.AccessKeyID == key && len(secret) == 0
	if !keep {
		if fe := lengthError("secret_access_key", len(secret), minAWSSecretLen, maxAWSSecretLen); fe != nil {
			errs = append(errs, *fe)
		} else if !printableNoSpace(secret) {
			errs.Add("secret_access_key", validate.Pattern, nil)
		}
	}
	if len(errs) > 0 {
		return errs
	}
	st.settings = ACMEDNSSettings{AccessKeyID: key, RoleARN: role, ExternalID: ext}
	if !keep {
		st.doc = &dnsCredentialDoc{SecretAccessKey: slices.Clone(secret)}
	}
	return nil
}

// dnsSettingsDetails are the audit details of a provider's settings: identifiers only (the external ID is reported as
// set or not: it guards the role and is not shown in an audit row).
func dnsSettingsDetails(kind string, st ACMEDNSSettings) map[string]string {
	d := map[string]string{"kind": kind}
	switch kind {
	case ACMEHookKindAzureDNS:
		d["auth"], d["tenant_id"], d["client_id"] = st.Auth, st.TenantID, st.ClientID
		d["subscription_id"], d["resource_group"] = st.SubscriptionID, st.ResourceGroup
		if st.CertThumbprint != "" {
			d["cert_thumbprint"] = st.CertThumbprint
		}
	case ACMEHookKindRoute53:
		d["access_key_id"], d["role_arn"] = st.AccessKeyID, st.RoleARN
		d["external_id_set"] = strconv.FormatBool(st.ExternalID != "")
	}
	return d
}

// dnsSolverConfig fills the solver configuration of a provider from its settings and its opened credentials document
// (whose secrets the configuration takes over: the caller zeroes the configuration, which zeroes them).
func dnsSolverConfig(kind string, st ACMEDNSSettings, doc dnsCredentialDoc, base *x509.CertPool, cfg *dnssolver.Config) {
	switch kind {
	case ACMEHookKindCloudflare:
		cfg.Cloudflare.APIToken, cfg.Cloudflare.BaseRoots = secrets.NewPlaintext(doc.APIToken), base
	case ACMEHookKindAzureDNS:
		a := &cfg.AzureDNS
		a.Auth, a.TenantID, a.ClientID, a.SubscriptionID, a.ResourceGroup = st.Auth, st.TenantID, st.ClientID, st.SubscriptionID, st.ResourceGroup
		a.ClientSecret, a.CertificateDER, a.PrivateKeyDER = secrets.NewPlaintext(doc.ClientSecret), doc.CertificateDER, secrets.NewPlaintext(doc.PrivateKeyDER)
		a.BaseRoots = base
	case ACMEHookKindRoute53:
		r := &cfg.Route53
		r.AccessKeyID, r.RoleARN, r.ExternalID = st.AccessKeyID, st.RoleARN, st.ExternalID
		r.SecretAccessKey, r.BaseRoots = secrets.NewPlaintext(doc.SecretAccessKey), base
	}
}
