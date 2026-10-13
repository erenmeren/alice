package acme

import (
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"go/ast"
	"go/parser"
	"go/token"
	"math/big"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func certPEM(der []byte) []byte {
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
}

// selfSigned makes a certificate with an authority key id and a serial whose high bit is set.
func selfSigned(t *testing.T) ([]byte, *x509.Certificate) {
	t.Helper()
	k := p256(t)
	serial := new(big.Int).SetBytes([]byte{0x80, 1, 2, 3})
	tpl := &x509.Certificate{SerialNumber: serial, Subject: pkix.Name{CommonName: "x"}, NotBefore: time.Now(), NotAfter: time.Now().Add(time.Hour),
		AuthorityKeyId: []byte{1, 2, 3, 4}, SubjectKeyId: []byte{1, 2, 3, 4}}
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, k.Public(), k)
	require.NoError(t, err)
	c, err := x509.ParseCertificate(der)
	require.NoError(t, err)
	return der, c
}

func TestCertID(t *testing.T) {
	_, c := selfSigned(t)
	id, err := CertID(c)
	require.NoError(t, err)
	assert.Equal(t, "AQIDBA.AIABAgM", id, "the serial keeps its DER leading zero")
	c.SerialNumber = big.NewInt(0x7f)
	id, err = CertID(c)
	require.NoError(t, err)
	assert.Equal(t, "AQIDBA.fw", id)
	c.SerialNumber = big.NewInt(0)
	id, err = CertID(c)
	require.NoError(t, err)
	assert.Equal(t, "AQIDBA.AA", id)
	c.AuthorityKeyId = nil
	_, err = CertID(c)
	require.Error(t, err)
}

func TestParseProblem(t *testing.T) {
	for in, want := range map[string]Problem{
		`{"type":"urn:ietf:params:acme:error:rateLimited","status":429,"detail":"secret"}`: {Type: ProblemPrefix + "rateLimited", Status: 429},
		`{"type":"urn:acme:error:badNonce","status":400}`:                                  {Type: ProblemPrefix + "badNonce", Status: 400},
		`{"type":"https://evil.test/?q=1","status":400}`:                                   {Status: 400},
		`{"type":"urn:ietf:params:acme:error:bad name","status":4000}`:                     {},
		`{"type":"urn:ietf:params:acme:error:","status":400.5}`:                            {},
		`{"type":7,"status":"400"}`:                                                        {},
		`not json`:                                                                         {},
		`{"type":"urn:ietf:params:acme:error:` + strings.Repeat("a", 41) + `"}`:            {},
	} {
		assert.Equal(t, want, ParseProblem([]byte(in)), in)
	}
	assert.Equal(t, Problem{}, ParseProblem([]byte(`{"type":"urn:ietf:params:acme:error:x"`+strings.Repeat(" ", maxProblemBytes)+`}`)))
}

func TestParseDirectory(t *testing.T) {
	d, err := ParseDirectory([]byte(`{"newNonce":"https://ca.test/n","newAccount":"https://ca.test/a","newOrder":"https://ca.test/o",
		"keyChange":"http://ca.test/k","renewalInfo":"https://ca.test/ari","meta":{"termsOfService":"http://ca.test/tos",
		"website":"javascript:alert(1)","externalAccountRequired":true}}`))
	require.NoError(t, err)
	assert.Equal(t, "https://ca.test/n", d.NewNonce)
	assert.Empty(t, d.KeyChange, "an http keyChange is dropped")
	assert.Equal(t, "https://ca.test/ari", d.RenewalInfo)
	assert.Equal(t, "http://ca.test/tos", d.TermsOfService)
	assert.Empty(t, d.Website)
	assert.True(t, d.ExternalAccountRequired)
	for _, bad := range []string{`{}`, `[]`, `x`, `{"newNonce":"https://a/n","newAccount":"https://a/a"}`,
		`{"newNonce":"https://a/n","newAccount":"https://u:p@a/a","newOrder":"https://a/o"}`,
		`{"newNonce":"https://a/n","newAccount":"https://a/a","newOrder":"mailto:x@y"}`,
		`{"newNonce":1,"newAccount":"https://a/a","newOrder":"https://a/o"}`,
		`{"newNonce":"https://a/n","newAccount":"https://a/a","newOrder":"https://a/` + strings.Repeat("o", maxURLLen) + `"}`,
		`{"newNonce":"https://a/n","newAccount":"https://a/a","newOrder":"https://a/o"` + strings.Repeat(" ", maxDirectoryBytes) + `}`} {
		_, err := ParseDirectory([]byte(bad))
		assert.Error(t, err, bad)
	}
}

func TestParseARI(t *testing.T) {
	s, e, err := ParseARI([]byte(`{"suggestedWindow":{"start":"2030-01-01T00:00:00+01:00","end":"2030-01-01T02:00:00Z"}}`))
	require.NoError(t, err)
	assert.Equal(t, time.Date(2029, 12, 31, 23, 0, 0, 0, time.UTC), s)
	assert.Equal(t, time.Date(2030, 1, 1, 2, 0, 0, 0, time.UTC), e)
	for _, bad := range []string{`{}`, `x`, `{"suggestedWindow":{"start":1,"end":2}}`,
		`{"suggestedWindow":{"start":"2030-01-01T00:00:00Z","end":"2030-01-01T00:00:00Z"}}`,
		`{"suggestedWindow":{"start":"tomorrow","end":"2030-01-01T00:00:00Z"}}`,
		`{"suggestedWindow":{"start":"0001-01-01T00:00:00Z","end":"0001-01-02T00:00:00Z"}}`,
		`{"suggestedWindow":{"start":"1999-12-31T23:00:00Z","end":"2030-01-01T00:00:00Z"}}`,
		`{"suggestedWindow":{"start":"` + strings.Repeat("9", 65) + `","end":"2030-01-01T00:00:00Z"}}`,
		`{"suggestedWindow":{"start":"2030-01-01T00:00:00Z","end":"2030-01-02T00:00:00Z"}}` + strings.Repeat(" ", maxARIBytes)} {
		_, _, err := ParseARI([]byte(bad))
		assert.Error(t, err, bad)
	}
}

func TestParseARIAcceptsTheYear2000(t *testing.T) {
	s, _, err := ParseARI([]byte(`{"suggestedWindow":{"start":"2000-01-01T00:00:00Z","end":"2000-01-02T00:00:00Z"}}`))
	require.NoError(t, err)
	assert.Equal(t, 2000, s.Year())
}

func TestParseRetryAfter(t *testing.T) {
	now := time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC)
	assert.Equal(t, 120*time.Second, parseRetryAfter("120", now))
	assert.Equal(t, MaxRetryAfter, parseRetryAfter("999999999999", now))
	assert.Equal(t, MaxRetryAfter, parseRetryAfter("86401", now))
	assert.Equal(t, MaxRetryAfter, parseRetryAfter("9223372036854775807", now))
	assert.Equal(t, MaxRetryAfter, parseRetryAfter("99999999999999999999999999999", now), "int64 overflow is capped, not ignored")
	assert.Zero(t, parseRetryAfter("-99999999999999999999999999999", now))
	assert.Zero(t, parseRetryAfter("-5", now))
	assert.Zero(t, parseRetryAfter("soon", now))
	assert.Zero(t, parseRetryAfter("", now))
	assert.Equal(t, time.Hour, parseRetryAfter(now.Add(time.Hour).Format(http1123), now))
	assert.Equal(t, MaxRetryAfter, parseRetryAfter(now.Add(100*time.Hour).Format(http1123), now))
	assert.Zero(t, parseRetryAfter(now.Add(-time.Hour).Format(http1123), now))
}

const http1123 = "Mon, 02 Jan 2006 15:04:05 GMT"

// Every Reason* constant of problem.go is in Reasons() and Reasons() holds nothing else, so the registry test
// in internal/api sees every reason this package can return.
func TestReasonsListsEveryConstant(t *testing.T) {
	f, err := parser.ParseFile(token.NewFileSet(), "problem.go", nil, 0)
	require.NoError(t, err)
	var consts []string
	ast.Inspect(f, func(n ast.Node) bool {
		vs, ok := n.(*ast.ValueSpec)
		if !ok {
			return true
		}
		for i, name := range vs.Names {
			if strings.HasPrefix(name.Name, "Reason") && i < len(vs.Values) {
				if lit, ok := vs.Values[i].(*ast.BasicLit); ok && lit.Kind == token.STRING {
					v, err := strconv.Unquote(lit.Value)
					require.NoError(t, err)
					consts = append(consts, v)
				}
			}
		}
		return true
	})
	require.NotEmpty(t, consts)
	assert.ElementsMatch(t, consts, Reasons())
}

func TestNormalizeNames(t *testing.T) {
	got, err := NormalizeNames([]string{"WWW.Example.Test.", "*.example.test", "xn--bcher-kva.test", "a1.b-2.test"})
	require.NoError(t, err)
	assert.Equal(t, []string{"www.example.test", "*.example.test", "xn--bcher-kva.test", "a1.b-2.test"}, got)
	_, err = NormalizeNames([]string{"a\x00b.test"})
	e := reasonErr(t, err, ReasonIdentifierRefused)
	assert.Equal(t, "a?b.test", e.Identifier)
	_, err = NormalizeNames([]string{strings.Repeat("a.", 127) + "test"})
	require.Error(t, err)
}
