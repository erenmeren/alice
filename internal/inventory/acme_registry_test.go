package inventory

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"reflect"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"alice/internal/acme"
	"alice/internal/acme/transport"
	"alice/internal/platform/validate"
	"alice/internal/secrets"
)

// testCertPEM is a self-signed certificate (PEM) named cn.
func testCertPEM(t *testing.T, cn string) string {
	t.Helper()
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	tpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: cn}, NotBefore: time.Unix(0, 0),
		NotAfter: time.Unix(4e9, 0), IsCA: true, BasicConstraintsValid: true}
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, &k.PublicKey, k)
	require.NoError(t, err)
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
}

func feCode(err *validate.FieldError) string {
	if err == nil {
		return ""
	}
	return err.Code
}

func TestNormACMEURL(t *testing.T) {
	for _, c := range []struct{ in, want, code string }{
		{"https://acme.example.com/directory", "https://acme.example.com/directory", ""},
		{"  https://ca.corp.example:8443/acme/dir  ", "https://ca.corp.example:8443/acme/dir", ""},
		{"https://[2001:db8::1]/dir", "https://[2001:db8::1]/dir", ""},
		{"", "", validate.Required},
		{"http://acme.example.com/directory", "", validate.Pattern},
		{"HTTPS://acme.example.com/directory", "https://acme.example.com/directory", ""},
		{"https://user:pw@acme.example.com/directory", "", validate.Pattern},
		{"https://user@acme.example.com/directory", "", validate.Pattern},
		{"https://acme.example.com/directory?token=abc", "", validate.Pattern},
		{"https://acme.example.com/directory?", "", validate.Pattern},
		{"https://acme.example.com/directory#frag", "", validate.Pattern},
		{"https:///directory", "", validate.Pattern},
		{"https://acme.example.com/dir ectory", "", validate.Pattern},
		{"https://acme.example.com/dïr", "", validate.Pattern},
		{"ftp://acme.example.com/", "", validate.Pattern},
		{"https:acme.example.com", "", validate.Pattern},
		{"https://" + strings.Repeat("a", 2048) + ".example", "", validate.TooLong},
	} {
		got, fe := normACMEURL("directory_url", c.in)
		assert.Equal(t, c.code, feCode(fe), c.in)
		assert.Equal(t, c.want, got, c.in)
		if fe != nil {
			assert.Equal(t, "directory_url", fe.Field)
		}
	}
	assert.Equal(t, "ca.corp.example:8443", urlHost("https://ca.corp.example:8443/acme/dir"))
	assert.Equal(t, "", urlHost("%zz"))
}

func TestNormCABundle(t *testing.T) {
	one, two := testCertPEM(t, "root one"), testCertPEM(t, "root two")
	keyPEM := string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: []byte{1, 2, 3}}))
	withHeaders := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Headers: map[string]string{"Proc-Type": "4,ENCRYPTED"}, Bytes: []byte{1}}))
	garbage := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: []byte("not der")}))
	var eleven strings.Builder
	for range 11 {
		eleven.WriteString(one)
	}
	for _, c := range []struct {
		name, in, code string
		certs          int
	}{
		{"empty", "", "", 0},
		{"blank", " \n\t", "", 0},
		{"one", one, "", 1},
		{"two with white space", "\n" + one + "\r\n\n" + two + "\n", "", 2},
		{"ten", strings.Repeat(one, 10), "", 10},
		{"eleven", eleven.String(), validate.OutOfRange, 0},
		{"private key", keyPEM, validate.Pattern, 0},
		{"certificate and private key", one + keyPEM, validate.Pattern, 0},
		{"headers", withHeaders, validate.Pattern, 0},
		{"not a certificate", garbage, validate.Pattern, 0},
		{"text before", "Subject: root\n" + one, validate.Pattern, 0},
		{"text after", one + "trailing", validate.Pattern, 0},
		{"no PEM", "MIIBkTCB+wIJ", validate.Pattern, 0},
		{"truncated", one[:len(one)-30], validate.Pattern, 0},
		{"too large", one + strings.Repeat(" ", 64<<10), validate.TooLong, 0},
	} {
		got, fe := normCABundle("ca_bundle_pem", c.in)
		assert.Equal(t, c.code, feCode(fe), c.name)
		if c.code == "" {
			assert.Equal(t, c.certs, strings.Count(got, "-----BEGIN CERTIFICATE-----"), c.name)
			assert.NotContains(t, got, "PRIVATE", c.name)
			if c.certs > 0 {
				again, fe := normCABundle("ca_bundle_pem", got)
				assert.Nil(t, fe)
				assert.Equal(t, got, again, "the stored form is canonical")
			}
		} else {
			assert.Empty(t, got, c.name)
		}
	}
}

func TestNormEAB(t *testing.T) {
	key := base64.RawURLEncoding.EncodeToString([]byte("0123456789abcdef0123456789abcdef"))
	for _, c := range []struct {
		name, kid, hmac string
		fields          []string
	}{
		{"ok", "kid-1", key, nil},
		{"padding and new line", " kid-1 ", key + "==\n", nil},
		{"standard alphabet", "kid", base64.StdEncoding.EncodeToString([]byte("0123456789abcdef>>>???")), []string{"eab_hmac"}},
		{"short", "kid", base64.RawURLEncoding.EncodeToString([]byte("0123456789abcde")), []string{"eab_hmac"}},
		{"empty", "", "", []string{"eab_kid", "eab_hmac"}},
		{"kid with space", "k id", key, []string{"eab_kid"}},
		{"kid too long", strings.Repeat("k", 256), key, []string{"eab_kid"}},
		{"hmac too long", "kid", strings.Repeat("A", 1025), []string{"eab_hmac"}},
	} {
		in := &ACMEEABInput{KID: c.kid, HMAC: secrets.NewPlaintext([]byte(c.hmac))}
		kid, text, errs := normEAB(in)
		var fields []string
		for _, e := range errs {
			fields = append(fields, e.Field)
		}
		assert.Equal(t, c.fields, fields, c.name)
		if c.fields == nil {
			assert.Equal(t, "kid-1", strings.TrimSpace(kid), c.name)
			assert.Equal(t, key, string(text), c.name)
			text[0] = 'X'
			assert.NotEqual(t, byte('X'), in.HMAC.Bytes()[0], "a copy: sealing and zeroing it leaves the input to its owner")
		} else {
			assert.Nil(t, text, c.name)
		}
	}
}

func TestNormSuffixesAndNameAllowed(t *testing.T) {
	got, fe := normSuffixes("allowed_suffixes", []string{" Corp.Example.COM ", ".dev.example.org", "xn--bcher-kva.example"})
	require.Nil(t, fe)
	assert.Equal(t, []string{"corp.example.com", ".dev.example.org", "xn--bcher-kva.example"}, got)
	empty, fe := normSuffixes("allowed_suffixes", nil)
	require.Nil(t, fe)
	assert.NotNil(t, empty, "stored as '{}'")
	assert.Empty(t, empty)
	for _, c := range []struct {
		in   []string
		code string
	}{
		{[]string{"*.example.com"}, validate.Pattern},
		{[]string{"com"}, validate.Pattern},
		{[]string{".com"}, validate.Pattern},
		{[]string{"example.com."}, validate.Pattern},
		{[]string{"exa_mple.com"}, validate.Pattern},
		{[]string{"-example.com"}, validate.Pattern},
		{[]string{"example..com"}, validate.Pattern},
		{[]string{"."}, validate.Pattern},
		{[]string{""}, validate.Pattern},
		{[]string{"bücher.example"}, validate.Pattern},
		{[]string{strings.Repeat("a", 64) + ".example"}, validate.Pattern},
		{[]string{"Example.com", "example.COM"}, validate.Duplicate},
		{make([]string, 101), validate.OutOfRange},
	} {
		_, fe := normSuffixes("allowed_suffixes", c.in)
		assert.Equal(t, c.code, feCode(fe), "%q", c.in)
	}

	list := []string{"corp.example.com", ".dev.example.org"}
	for name, want := range map[string]bool{
		"corp.example.com": true, "www.corp.example.com": true, "*.corp.example.com": true, "A.Corp.Example.Com": true,
		"evilcorp.example.com": false, "corp.example.com.evil.test": false, "example.com": false,
		"dev.example.org": false, "api.dev.example.org": true, "*.dev.example.org": false, // as dns01: a wildcard is judged by its base name
		"*.api.dev.example.org": true, "notdev.example.org": false,
		"": false, "*.": false, "bad_name.corp.example.com": false, ".corp.example.com": false,
	} {
		assert.Equal(t, want, ACMENameAllowed(list, name), name)
	}
	assert.False(t, ACMENameAllowed(nil, "corp.example.com"), "an empty list admits nothing (A9)")
	assert.False(t, ACMENameAllowed([]string{"*bad"}, "bad"), "an invalid entry admits nothing")
	assert.Equal(t, 1024, len(suffixesDetail(slicesOf(strings.Repeat("a", 60)+".example", 30))))
}

func slicesOf(s string, n int) []string {
	out := make([]string, n)
	for i := range out {
		out[i] = s
	}
	return out
}

func TestNormContact(t *testing.T) {
	for in, want := range map[string]string{
		"": "", "  ": "", "ops@Corp.Example.COM": "ops@corp.example.com", "mailto:Ops.Team+acme@example.org": "Ops.Team+acme@example.org",
	} {
		got, fe := normContact(in)
		assert.Nil(t, fe, in)
		assert.Equal(t, want, got, in)
	}
	for _, in := range []string{"ops", "@example.com", "ops@", "a@b@example.com", "ops@example", "o ps@example.com", "ops@exa_mple.com",
		"ops@example.com,evil@example.com", "<ops@example.com>", "öps@example.com", "ops@exa\nmple.com", "ops@" + strings.Repeat("a", 250) + ".com",
		"ops@.example.com"} {
		_, fe := normContact(in)
		assert.Equal(t, validate.Email, feCode(fe), "%q", in)
	}
}

func TestHookValidation(t *testing.T) {
	for _, c := range []struct {
		secret, code string
	}{
		{"0123456789abcdef", ""}, {"with spaces and !#$% 0123", ""}, {strings.Repeat("s", 256), ""},
		{"", validate.Required}, {"short", validate.TooShort}, {strings.Repeat("s", 257), validate.TooLong},
		{"0123456789abcdef\n", validate.Pattern}, {"0123456789abcdeé", validate.Pattern}, {"0123456789\x00abcdef", validate.Pattern},
	} {
		assert.Equal(t, c.code, feCode(validHookSecret([]byte(c.secret))), "%q", c.secret)
	}
	for _, c := range []struct {
		wait, poll int
		fields     []string
	}{
		{0, 1, nil}, {5, 60, nil}, {120, 0, []string{"poll_timeout_seconds"}}, {20, 100, nil},
		{21, 100, []string{"poll_timeout_seconds"}}, {-1, 10, []string{"propagation_wait_seconds"}}, {121, 10, []string{"propagation_wait_seconds"}},
		{0, 101, []string{"poll_timeout_seconds"}},
	} {
		var fields []string
		for _, e := range validHookWaits(c.wait, c.poll) {
			fields = append(fields, e.Field)
		}
		assert.Equal(t, c.fields, fields, "%d+%d", c.wait, c.poll)
	}
	assert.Equal(t, 2*time.Minute, acmeHookBudget, "the waits stay within the ACME client's call budget")
}

func TestValidateProviderAndHookInputs(t *testing.T) {
	bundle := testCertPEM(t, "root")
	f, errs := validateACMEProvider(ACMEProviderInput{Name: " Corp CA ", DirectoryURL: "https://ca.corp.example/dir", CABundlePEM: bundle,
		AllowedSuffixes: []string{"Corp.Example"}, EAB: &ACMEEABInput{KID: "kid", HMAC: secrets.NewPlaintext([]byte(base64.RawURLEncoding.EncodeToString(make([]byte, 32))))}})
	require.Empty(t, errs)
	assert.Equal(t, "Corp CA", f.name)
	assert.Equal(t, ACMEPresetCustom, f.preset)
	assert.Equal(t, []string{"corp.example"}, f.suffixes)
	assert.NotNil(t, f.eabHMAC)
	f.clear()
	assert.Equal(t, make([]byte, len(f.eabHMAC)), f.eabHMAC, "clear zeroes the HMAC text")

	_, errs = validateACMEProvider(ACMEProviderInput{Name: "", DirectoryURL: "http://x", Preset: "buypass", CABundlePEM: "x",
		AllowedSuffixes: []string{"*"}, EAB: &ACMEEABInput{}})
	var fields []string
	for _, e := range errs {
		fields = append(fields, e.Field)
	}
	assert.Equal(t, []string{"name", "directory_url", "preset", "ca_bundle_pem", "allowed_suffixes", "eab_kid", "eab_hmac"}, fields)

	cur := ACMEProvider{Name: "A", DirectoryURL: "https://a.example/dir", Preset: ACMEPresetCustom, AllowedSuffixes: []string{"a.example"}, EABConfigured: true, EABKID: "k"}
	name, dir, same := "B", "https://b.example/dir", []string{"A.example"}
	pf, changed, errs := validateProviderPatch(cur, ACMEProviderPatch{Name: &name, DirectoryURL: &dir, AllowedSuffixes: &same, RemoveEAB: true})
	require.Empty(t, errs)
	assert.Equal(t, []string{"name", "directory_url", "eab"}, changed)
	assert.Equal(t, "", pf.eabKID)
	_, _, errs = validateProviderPatch(cur, ACMEProviderPatch{EAB: &ACMEEABInput{KID: "k", HMAC: secrets.NewPlaintext([]byte(strings.Repeat("A", 22)))}, RemoveEAB: true})
	require.Len(t, errs, 1)
	assert.Equal(t, "eab", errs[0].Field)
	_, changed, errs = validateProviderPatch(ACMEProvider{Name: "A"}, ACMEProviderPatch{RemoveEAB: true})
	assert.Empty(t, errs)
	assert.Empty(t, changed, "removing a binding that does not exist changes nothing")

	hf, errs := validateACMEHook(ACMEHookInput{Name: "hook", URL: "https://dns.example/hook", Secret: secrets.NewPlaintext([]byte("0123456789abcdef"))})
	require.Empty(t, errs)
	assert.Equal(t, DefaultACMEPropagationWaitSeconds, hf.wait)
	assert.Equal(t, DefaultACMEPollTimeoutSeconds, hf.poll)
	zero := 0
	hf, errs = validateACMEHook(ACMEHookInput{Name: "hook", URL: "https://dns.example/hook", Secret: secrets.NewPlaintext([]byte("0123456789abcdef")),
		PropagationWaitSeconds: &zero, PollTimeoutSeconds: 100})
	require.Empty(t, errs)
	assert.Equal(t, 0, hf.wait)
	_, errs = validateACMEHook(ACMEHookInput{URL: "https://u:p@dns.example/hook?x=1"})
	fields = nil
	for _, e := range errs {
		fields = append(fields, e.Field)
	}
	assert.Equal(t, []string{"name", "url", "secret"}, fields)

	hcur := ACMEHook{Name: "h", URL: "https://dns.example/hook", PropagationWaitSeconds: 25, PollTimeoutSeconds: 60}
	poll := 100
	_, _, errs = validateHookPatch(hcur, ACMEHookPatch{PollTimeoutSeconds: &poll})
	require.Len(t, errs, 1, "25 + 100 is over the budget")
	url := "https://dns2.example/hook"
	hf, changed, errs = validateHookPatch(hcur, ACMEHookPatch{URL: &url, Secret: secrets.NewPlaintext([]byte("fedcba9876543210"))})
	require.Empty(t, errs)
	assert.Equal(t, []string{"url", "secret"}, changed)
	assert.Equal(t, "fedcba9876543210", string(hf.secret))
}

// The refused inputs are zeroed too: a caller's secret never outlives the call.
func TestRefusedInputsAreZeroed(t *testing.T) {
	s := &Service{}
	hmac := []byte("not base64url!!!")
	_, err := s.CreateACMEProvider(context.Background(), Actor{}, ACMEProviderInput{Name: "x", DirectoryURL: "https://x.example/d",
		EAB: &ACMEEABInput{KID: "k", HMAC: secrets.NewPlaintext(hmac)}})
	var errs validate.Errors
	require.ErrorAs(t, err, &errs)
	assert.Equal(t, make([]byte, len(hmac)), hmac)

	secret := []byte("short")
	_, err = s.CreateACMEHook(context.Background(), Actor{}, ACMEHookInput{Name: "h", URL: "https://h.example/", Secret: secrets.NewPlaintext(secret)})
	require.ErrorAs(t, err, &errs)
	assert.Equal(t, make([]byte, len(secret)), secret)

	_, err = s.RegisterACMEAccount(context.Background(), Actor{}, uuid.New(), "not an address", true)
	require.ErrorAs(t, err, &errs, "the contact is checked before anything else")
}

func TestACMEFailureMapping(t *testing.T) {
	for _, r := range acme.Reasons() {
		var ie *ACMEError
		require.ErrorAs(t, acmeFailure(fmt.Errorf("ctx: %w", &acme.Error{Reason: r, Status: 400})), &ie, r)
		assert.Equal(t, r, ie.Reason)
		var ae *acme.Error
		assert.ErrorAs(t, ie, &ae, "the closed *acme.Error stays reachable")
		assert.Equal(t, "inventory: the certificate authority exchange failed: "+r, ie.Error())
	}
	var ie *ACMEError
	require.ErrorAs(t, acmeFailure(&acme.Error{Reason: "acme.from_the_future"}), &ie)
	assert.Equal(t, acme.ReasonDirectoryInvalid, ie.Reason)
	require.ErrorAs(t, acmeFailure(transport.ErrCABundle), &ie)
	assert.Equal(t, acme.ReasonTLSTrustFailed, ie.Reason)
	require.ErrorAs(t, acmeFailure(errors.New("secret text https://ca/?token=x")), &ie)
	assert.Equal(t, acme.ReasonDirectoryInvalid, ie.Reason)
	assert.NotContains(t, ie.Error(), "token")
	assert.Nil(t, ie.Unwrap(), "a foreign error is not kept")
	assert.Same(t, ie, acmeFailure(fmt.Errorf("again: %w", ie)))
	assert.ErrorIs(t, acmeFailure(context.Canceled), context.Canceled)
	assert.NoError(t, acmeFailure(nil))
}

// secretWords are the substrings no field name or JSON tag of a view may hold; a bool XxxConfigured flag
// ("eab_configured", "secret_configured") says only whether a write-only secret exists.
var secretWords = regexp.MustCompile(`(?i)secret|hmac|key|password|private|passphrase|token|ciphertext|nonce|dek`)

// reporter is the part of *testing.T secretFree uses (a recorder checks the checker).
type reporter interface {
	Errorf(format string, args ...any)
	Helper()
}

type recorder struct{ failed bool }

func (r *recorder) Errorf(string, ...any) { r.failed = true }
func (r *recorder) Helper()               {}

// secretFree checks a view type: no secret-sounding field (except the bool *Configured flags) and no field whose
// type could hold one (bytes, a secrets type, an interface, a function, a channel), recursively.
func secretFree(t reporter, typ reflect.Type, path string) {
	t.Helper()
	for typ.Kind() == reflect.Pointer || typ.Kind() == reflect.Slice || typ.Kind() == reflect.Array {
		if typ.Kind() == reflect.Slice && typ.Elem().Kind() == reflect.Uint8 {
			t.Errorf("%s is a byte slice", path)
			return
		}
		typ = typ.Elem()
	}
	switch typ.Kind() {
	case reflect.Interface, reflect.Func, reflect.Chan, reflect.Map, reflect.UnsafePointer:
		t.Errorf("%s has kind %s", path, typ.Kind())
		return
	case reflect.Struct:
	default:
		return
	}
	if strings.HasPrefix(typ.PkgPath(), "alice/internal/secrets") || strings.HasPrefix(typ.PkgPath(), "crypto") {
		t.Errorf("%s is %s", path, typ)
		return
	}
	if typ == reflect.TypeOf(time.Time{}) || typ == reflect.TypeOf(uuid.UUID{}) {
		return
	}
	for i := range typ.NumField() {
		f := typ.Field(i)
		tag := strings.Split(f.Tag.Get("json"), ",")[0]
		configured := f.Type.Kind() == reflect.Bool && strings.HasSuffix(f.Name, "Configured") && strings.HasSuffix(tag, "_configured")
		if !configured {
			assert.False(t, secretWords.MatchString(f.Name), "%s.%s", path, f.Name)
			assert.False(t, secretWords.MatchString(tag), "%s.%s json %q", path, f.Name, tag)
		}
		if f.IsExported() {
			assert.NotEmpty(t, tag, "%s.%s needs a json tag", path, f.Name)
		} else {
			t.Errorf("%s.%s: a view has exported fields only", path, f.Name)
		}
		secretFree(t, f.Type, path+"."+f.Name)
	}
}

// Every view the ACME services return is secret-free (no field can carry a key, an HMAC or a hook secret).
func TestACMEViewsAreSecretFree(t *testing.T) {
	for _, v := range []any{ACMEProvider{}, ACMEAccount{}, ACMEHook{}} {
		secretFree(t, reflect.TypeOf(v), reflect.TypeOf(v).Name())
	}
	// The checker itself catches what it must.
	type leaky struct {
		EABHMAC []byte `json:"eab_hmac"`
	}
	inner := &recorder{}
	secretFree(inner, reflect.TypeOf(leaky{}), "leaky")
	assert.True(t, inner.failed, "a byte slice named eab_hmac is refused")
	type configured struct {
		SecretConfigured string `json:"secret_configured"`
	}
	inner = &recorder{}
	secretFree(inner, reflect.TypeOf(configured{}), "configured")
	assert.True(t, inner.failed, "only a bool may be a *Configured flag")
	type signer struct {
		Signer any `json:"signer"`
	}
	inner = &recorder{}
	secretFree(inner, reflect.TypeOf(signer{}), "signer")
	assert.True(t, inner.failed, "an interface could hold a key")
}

// The rest of the module's audit keys allowed by the denylist (audit.checkDetails) is tested by the integration
// tests; here: the hook's detail keys never name the secret.
func TestHookDetailsNameNoSecret(t *testing.T) {
	d := hookDetails(hookFields{name: "h", url: "https://dns.example/hook?q", secret: []byte("0123456789abcdef")})
	for k, v := range d {
		assert.False(t, secretWords.MatchString(k), k)
		assert.NotContains(t, v, "0123456789abcdef")
	}
	assert.Equal(t, "dns.example", d["url_host"])
}

func TestKeyLocations(t *testing.T) {
	id := uuid.MustParse("01234567-89ab-cdef-0123-456789abcdef")
	assert.Equal(t, secrets.Location{Table: "acme_providers", RowID: id.String(), Column: "eab_hmac"}, eabLocation(id))
	assert.Equal(t, secrets.Location{Table: "acme_accounts", RowID: id.String(), Column: "key"}, accountKeyLocation(id))
	assert.Equal(t, secrets.Location{Table: "acme_hooks", RowID: id.String(), Column: "secret"}, hookSecretLocation(id))
	assert.Nil(t, actorRef(Actor{}))
	assert.Equal(t, id, *actorRef(Actor{UserID: id}))
	ct, nonce, dek, v := envCols(nil)
	assert.Nil(t, ct)
	assert.Nil(t, nonce)
	assert.Nil(t, dek)
	assert.Nil(t, v)
	assert.Equal(t, []string{"letsencrypt", "letsencrypt_staging", "zerossl", "custom"}, ACMEPresets())
}

// M1: only an answer that the account is gone finishes a deactivation retry.
func TestAccountGone(t *testing.T) {
	assert.True(t, accountGone(fmt.Errorf("x: %w", acme.ErrNoAccount)))
	for _, typ := range []string{"unauthorized", "accountDoesNotExist"} {
		assert.True(t, accountGone(&acme.Error{Reason: acme.ReasonAccountRejected, ProblemType: acme.ProblemPrefix + typ, Status: 403}), typ)
	}
	assert.False(t, accountGone(&acme.Error{Reason: acme.ReasonAccountRejected, ProblemType: acme.ProblemPrefix + "invalidContact"}))
	assert.False(t, accountGone(&acme.Error{Reason: acme.ReasonProviderUnreachable, ProblemType: acme.ProblemPrefix + "unauthorized"}))
	assert.False(t, accountGone(errors.New("network")))
	assert.Equal(t, 5*time.Minute, ACMERolloverSettleAge, "two CA calls and a margin")
}
