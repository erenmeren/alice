package route53

import (
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"alice/internal/secrets"
)

// The AWS SigV4 test suite (aws-sig-v4-test-suite, the vectors botocore and the AWS SDKs run) signs every request
// with the documentation's example credentials: key ID "AKIDEXAMPLE" and the secret access key that AWS's
// documentation prints as its example ("wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY"), for region us-east-1, service
// "service", at 2015-08-30T12:36:00Z. It is a published example, not a key of any account (gitleaks and trivy accept it).
var (
	suiteKeyID  = "AKIDEXAMPLE"
	suiteSecret = "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY"
	suiteDate   = "20150830T123600Z"
)

type suiteVector struct {
	name    string
	method  string
	target  string // path and query, as the request line has it
	headers [][2]string
	body    string
	sig     string
}

// The vectors whose path has unreserved characters only (single and double encoding agree there: the suite was
// written for the single encoding of S3, see TestCanonicalURIDoubleEncodes).
var suiteVectors = []suiteVector{
	{name: "get-vanilla", method: "GET", target: "/",
		sig: "5fa00fa31553b73ebf1942676e86291e8372ff2a2260956d9b8aae1d763fbf31"},
	{name: "get-vanilla-query-order-key-case", method: "GET", target: "/?Param2=value2&Param1=value1",
		sig: "b97d918cfa904a5beff61c982a1b6f458b799221646efd99d3219ec94cdf2500"},
	{name: "get-vanilla-empty-query-key", method: "GET", target: "/?Param1=value1",
		sig: "a67d582fa61cc504c4bae71f336f98b97f1ea3c7a6bfe1b6e45aec72011b9aeb"},
	{name: "get-vanilla-query-unreserved", method: "GET",
		target: "/?-._~0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz=-._~0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz",
		sig:    "9c3e54bfcdf0b19771a7f523ee5669cdf59bc7cc0884027167c21bb143a40197"},
	{name: "post-vanilla", method: "POST", target: "/",
		sig: "5da7c1a2acd57cee7505fc6676e4e544621c30862966e37dddb68e92efbe5d6b"},
	{name: "post-x-www-form-urlencoded", method: "POST", target: "/",
		headers: [][2]string{{"Content-Type", "application/x-www-form-urlencoded"}}, body: "Param1=value1",
		sig: "ff11897932ad3f4e8b18135d722051e5ac45fc38421b1da7b9d196a0fe09473a"},
	{name: "post-x-www-form-urlencoded-parameters", method: "POST", target: "/",
		headers: [][2]string{{"Content-Type", "application/x-www-form-urlencoded; charset=utf8"}}, body: "Param1=value1",
		sig: "1a72ec8f64bd914b0e42e42607c7fbce7fb2c7465f63e3092b3b0d39fa77a6fe"},
	{name: "get-header-value-trim", method: "GET", target: "/",
		headers: [][2]string{{"My-Header1", " value1"}, {"My-Header2", ` "a   b   c"`}},
		sig:     "acc3ed3afb60bb290fc8d2dd0098b9911fcaa05412b367055dee359757a9c736"},
}

func TestSigV4SuiteVectors(t *testing.T) {
	for _, v := range suiteVectors {
		t.Run(v.name, func(t *testing.T) {
			req, err := http.NewRequest(v.method, "https://example.amazonaws.com"+v.target, strings.NewReader(v.body))
			require.NoError(t, err)
			req.Header.Set("X-Amz-Date", suiteDate)
			names := []string{"host", "x-amz-date"}
			for _, h := range v.headers {
				req.Header.Set(h[0], h[1])
				names = append(names, h[0])
			}
			got := authorization(req, []byte(v.body), suiteKeyID, []byte(suiteSecret), "us-east-1", "service", names)
			signed := strings.Join(sortedLower(names), ";")
			assert.Equal(t, "AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE/20150830/us-east-1/service/aws4_request, SignedHeaders="+
				signed+", Signature="+v.sig, got)
		})
	}
}

func sortedLower(names []string) []string {
	out := make([]string, len(names))
	for i, n := range names {
		out[i] = strings.Map(func(r rune) rune {
			if r >= 'A' && r <= 'Z' {
				return r + 32
			}
			return r
		}, n)
	}
	for i := range out {
		for j := i + 1; j < len(out); j++ {
			if out[j] < out[i] {
				out[i], out[j] = out[j], out[i]
			}
		}
	}
	return out
}

// The test suite's get-utf8 vector signs "/ሴ" as "/%E1%88%B4" (S3's single encoding). Alice signs for Route 53 and
// STS, where AWS encodes each segment of the escaped path once more; the paths Alice builds never hold a byte that
// needs encoding, so the two rules give the same canonical URI for every real request.
func TestCanonicalURIDoubleEncodes(t *testing.T) {
	req, err := http.NewRequest("GET", "https://example.amazonaws.com/ሴ", nil)
	require.NoError(t, err)
	assert.Equal(t, "/%E1%88%B4", req.URL.EscapedPath())
	assert.Equal(t, "/%25E1%2588%25B4", canonicalURI(req.URL.EscapedPath()))
	assert.Equal(t, "/", canonicalURI(""))
	assert.Equal(t, "/2013-04-01/hostedzone/Z0123ABC/rrset", canonicalURI("/2013-04-01/hostedzone/Z0123ABC/rrset"))
}

func TestCanonicalQuery(t *testing.T) {
	assert.Empty(t, canonicalQuery(""))
	assert.Equal(t, "a=&b=1&b=2", canonicalQuery("b=2&&a&b=1"))
	assert.Equal(t, "dnsname=_acme-challenge.example.com&maxitems=10", canonicalQuery("maxitems=10&dnsname=_acme-challenge.example.com"))
	assert.Equal(t, "k=a%20b%2Bc", canonicalQuery("k=a+b%2Bc"), "a form space is %20, a plus is %2B")
	assert.Equal(t, "k=%25zz", canonicalQuery("k=%zz"), "an undecodable value is used as it stands")
}

func TestSignAddsDateTokenAndHeaders(t *testing.T) {
	at := time.Date(2026, 10, 21, 8, 9, 10, 0, time.UTC)
	req, err := http.NewRequest("POST", "https://"+Host+"/2013-04-01/hostedzone/Z1/rrset/", strings.NewReader("<x/>"))
	require.NoError(t, err)
	req.Header.Set("Content-Type", "application/xml")
	c := credentials{keyID: "ASIATESTKEY0123456", secret: secrets.NewPlaintext([]byte(suiteSecret)), token: secrets.NewPlaintext([]byte("tok/en+=="))}
	sign(req, []byte("<x/>"), c, Region, "route53", at)
	assert.Equal(t, "20261021T080910Z", req.Header.Get("X-Amz-Date"))
	assert.Equal(t, "tok/en+==", req.Header.Get("X-Amz-Security-Token"))
	a := req.Header.Get("Authorization")
	assert.True(t, strings.HasPrefix(a, "AWS4-HMAC-SHA256 Credential=ASIATESTKEY0123456/20261021/us-east-1/route53/aws4_request, "+
		"SignedHeaders=content-type;host;x-amz-date;x-amz-security-token, Signature="), a)

	get, err := http.NewRequest("GET", "https://"+Host+"/2013-04-01/change/C1", nil)
	require.NoError(t, err)
	sign(get, nil, credentials{keyID: suiteKeyID, secret: secrets.NewPlaintext([]byte(suiteSecret))}, Region, "route53", at)
	assert.Empty(t, get.Header.Get("X-Amz-Security-Token"))
	assert.Contains(t, get.Header.Get("Authorization"), "SignedHeaders=host;x-amz-date, ")
}
