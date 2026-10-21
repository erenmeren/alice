package authz_test

import (
	"errors"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"alice/internal/authz"
	"alice/internal/platform/validate"
)

func parse(t *testing.T, doc string) authz.Policy {
	t.Helper()
	p, err := authz.ParsePolicy([]byte(doc), "body.")
	require.NoError(t, err, doc)
	return p
}

func fieldCodes(t *testing.T, err error) map[string]string {
	t.Helper()
	var v validate.Errors
	require.True(t, errors.As(err, &v), "%v", err)
	out := map[string]string{}
	for _, fe := range v {
		out[fe.Field] = fe.Code
	}
	return out
}

func TestParsePolicyNormalizes(t *testing.T) {
	p := parse(t, `{"schema":1,"domains":[" Pay.Example.COM ","*.pay.example.com","10.20.0.0/16","2001:db8::1"],
"certificate_sources":["acme"],"acme":{"challenges":[],"key_types":[]},"deployment":{"auto_deploy":""},
"notifications":{"addresses":[]}}`)
	assert.Equal(t, []string{"pay.example.com", "*.pay.example.com", "10.20.0.0/16", "2001:db8::1"}, p.Domains)
	assert.Nil(t, p.ACME, "an ACME object without a constraint is no constraint")
	assert.Nil(t, p.Deployment)
	assert.Nil(t, p.Notifications)
	assert.JSONEq(t, `{"schema":1,"domains":["pay.example.com","*.pay.example.com","10.20.0.0/16","2001:db8::1"],"certificate_sources":["acme"]}`,
		string(p.Document()))

	empty := parse(t, `{"schema":1,"domains":[]}`)
	assert.JSONEq(t, `{"schema":1}`, string(empty.Document()), "an empty list is no constraint")
	assert.JSONEq(t, `{"schema":1}`, string(authz.EmptyPolicy().Document()))
}

func TestParsePolicyRefuses(t *testing.T) {
	for _, doc := range []string{``, `[]`, `"x"`, `{"schema":1,"unknown":true}`, `{"schema":1,"acme":{"providers":["x"]}}`,
		`{"schema":1,"acme":{"extra":1}}`, `{"schema":1} {}`, `{"schema":"1"}`} {
		_, err := authz.ParsePolicy([]byte(doc), "body.")
		assert.ErrorIs(t, err, authz.ErrPolicyMalformed, doc)
	}
	for _, k := range authz.ReservedPolicyKeys {
		_, err := authz.ParsePolicy([]byte(`{"schema":1,"`+k+`":{}}`), "body.")
		var fu *authz.FieldUnavailableError
		require.ErrorAs(t, err, &fu, k)
		assert.Equal(t, k, fu.Key)
		assert.ErrorIs(t, err, authz.ErrPolicyFieldUnavailable)
	}
	_, err := authz.ParsePolicy([]byte(`{"schema":2,"domains":["a..b","*.com","10.0.0.1/8","x.example.com","X.example.com","fe80::1%eth0"],
"certificate_sources":["acme","ftp","acme"],"acme":{"providers":["00000000-0000-0000-0000-000000000000"],"challenges":["tls"],
"key_types":["dsa"],"renew_before_days":61},"deployment":{"auto_deploy":"sometimes"},"incident":{"revoke_mode":"later"},
"notifications":{"addresses":[{"email":"Team <t@example.com>","locale":"en"},{"email":"a@example.com","locale":"de"},
{"email":"A@example.com","locale":"tr"}]}}`), "body.")
	assert.Equal(t, map[string]string{
		"body.schema":                           validate.OneOf,
		"body.domains.0":                        validate.Pattern,
		"body.domains.1":                        validate.Pattern,
		"body.domains.2":                        validate.Pattern,
		"body.domains.4":                        validate.Duplicate,
		"body.domains.5":                        validate.Pattern,
		"body.certificate_sources.1":            validate.OneOf,
		"body.certificate_sources.2":            validate.Duplicate,
		"body.acme.providers.0":                 validate.Required,
		"body.acme.challenges.0":                validate.OneOf,
		"body.acme.key_types.0":                 validate.OneOf,
		"body.acme.renew_before_days":           validate.OutOfRange,
		"body.deployment.auto_deploy":           validate.OneOf,
		"body.incident.revoke_mode":             validate.OneOf,
		"body.notifications.addresses.0.email":  validate.Email,
		"body.notifications.addresses.1.locale": validate.OneOf,
		"body.notifications.addresses.2.email":  validate.Duplicate,
	}, fieldCodes(t, err))

	many := `{"schema":1,"domains":[`
	for i := range authz.MaxPolicyDomains + 1 {
		if i > 0 {
			many += ","
		}
		many += `"h` + uuid.NewString()[:8] + `.example.com"`
	}
	_, err = authz.ParsePolicy([]byte(many+`]}`), "body.")
	assert.Equal(t, map[string]string{"body.domains": validate.TooLong}, fieldCodes(t, err))
}

// Design §12 Phase 5: wildcard depth, wildcard names, IP/CIDR, an empty list.
func TestPolicyDomains(t *testing.T) {
	p := parse(t, `{"schema":1,"domains":["pay.example.com","*.pay.example.com","10.20.0.0/16","192.0.2.7","2001:db8::/32"]}`)
	for name, want := range map[string]bool{
		"pay.example.com":       true,
		"PAY.example.com.":      true,
		"a.pay.example.com":     true,
		"a.b.c.pay.example.com": true, // any depth
		"*.pay.example.com":     true, // a wildcard name under the wildcard entry
		"*.x.pay.example.com":   true,
		"evilpay.example.com":   false, // a suffix, not a label boundary
		"example.com":           false,
		"*.example.com":         false, // wider than the entry
		"other.example.com":     false,
		"10.20.3.4":             true,
		"10.21.0.1":             false,
		"192.0.2.7":             true,
		"192.0.2.8":             false,
		"2001:db8::5":           true,
		"2001:db9::5":           false,
		"::ffff:10.20.0.9":      true, // an IPv4 address written as IPv6 is the IPv4 address
	} {
		assert.Equal(t, want, p.NameAllowed(name), name)
	}
	exact := parse(t, `{"schema":1,"domains":["pay.example.com"]}`)
	assert.False(t, exact.NameAllowed("*.pay.example.com"), "an exact entry does not admit a wildcard below it")
	assert.False(t, exact.NameAllowed("a.pay.example.com"))
	assert.False(t, exact.NameAllowed("10.0.0.1"), "a DNS entry admits no IP address")

	none := parse(t, `{"schema":1}`)
	assert.True(t, none.NameAllowed("anything.example.org"), "no domains: no constraint")
	assert.True(t, none.NameAllowed("10.9.9.9"))

	err := p.CheckNames("names", []string{"a.pay.example.com", "x.example.org", "y.example.org"})
	var de *authz.DomainError
	require.ErrorAs(t, err, &de)
	assert.Equal(t, authz.DomainError{Name: "x.example.org", Field: "names"}, *de)
	assert.ErrorIs(t, err, authz.ErrDomainNotAllowed)
	assert.NoError(t, p.CheckNames("names", []string{"pay.example.com"}))

	assert.Equal(t, []string{"pay.example.com", "a.pay.example.com"}, authz.CertificateNames("pay.example.com", []string{"a.pay.example.com"}))
	assert.Equal(t, []string{"a.pay.example.com"}, authz.CertificateNames("My server", []string{"a.pay.example.com"}))
	assert.Equal(t, []string{"a.pay.example.com"}, authz.CertificateNames("A.pay.example.com", []string{"a.pay.example.com"}))
}

func TestPolicyChecks(t *testing.T) {
	prov := uuid.New()
	p := parse(t, `{"schema":1,"certificate_sources":["acme","csr"],"acme":{"providers":["`+prov.String()+`"],"challenges":["dns01"],
"key_types":["ecdsa_p256"],"renew_before_days":14},"deployment":{"auto_deploy":"forbidden"},"incident":{"revoke_mode":"now"}}`)
	assert.NoError(t, p.CheckSource(authz.SourceACME))
	var se *authz.SourceError
	require.ErrorAs(t, p.CheckSource(authz.SourceUploaded), &se)
	assert.Equal(t, authz.SourceUploaded, se.Source)

	assert.NoError(t, p.CheckACME(prov, "dns01", "ecdsa_p256"))
	for field, err := range map[string]error{
		"provider_id": p.CheckACME(uuid.New(), "dns01", "ecdsa_p256"),
		"challenge":   p.CheckACME(prov, "http01", "ecdsa_p256"),
		"key_type":    p.CheckACME(prov, "dns01", "rsa_2048"),
	} {
		var ae *authz.ACMEPolicyError
		require.ErrorAs(t, err, &ae, field)
		assert.Equal(t, field, ae.Field)
		assert.ErrorIs(t, err, authz.ErrACMENotAllowed)
	}
	assert.True(t, p.AutoDeployForbidden())
	assert.ErrorIs(t, p.CheckAutoDeploy(), authz.ErrAutoDeployForbidden)
	assert.Equal(t, 14, p.RenewBeforeDays())
	assert.Equal(t, authz.RevokeNow, p.RevokeMode())

	none := authz.EmptyPolicy()
	assert.NoError(t, none.CheckSource(authz.SourceUploaded))
	assert.NoError(t, none.CheckACME(uuid.New(), "http01", "rsa_4096"))
	assert.NoError(t, none.CheckAutoDeploy())
	assert.Zero(t, none.RenewBeforeDays())
	assert.Empty(t, none.RevokeMode())
}

func TestChangedKeys(t *testing.T) {
	a := parse(t, `{"schema":1,"domains":["a.example.com"],"incident":{"revoke_mode":"now"}}`)
	b := parse(t, `{"schema":1,"domains":["a.example.com"],"deployment":{"auto_deploy":"forbidden"}}`)
	assert.Equal(t, []string{"deployment", "incident"}, authz.ChangedKeys(a, b))
	assert.Empty(t, authz.ChangedKeys(a, a))
	assert.True(t, authz.SameDomains(parse(t, `{"schema":1,"domains":["x.example.com","y.example.com"]}`),
		parse(t, `{"schema":1,"domains":["Y.example.com","x.example.com"]}`)))
	assert.False(t, authz.SameDomains(a, authz.EmptyPolicy()))
}
