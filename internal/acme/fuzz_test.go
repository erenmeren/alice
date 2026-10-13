package acme

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"math/big"
	"strings"
	"testing"
	"time"
)

// The parsers read what a CA (or anything at its address) sends: no input may panic, and every result must
// stay inside its documented bounds.

func FuzzParseProblem(f *testing.F) {
	for _, s := range []string{
		`{"type":"urn:ietf:params:acme:error:rateLimited","status":429,"detail":"x"}`,
		`{"type":"urn:acme:error:badNonce","status":400}`,
		`{"type":"about:blank"}`, `{"type":null,"status":1e400}`, `{"subproblems":[{"type":"x"}]}`, `[]`, `"`, ``,
	} {
		f.Add([]byte(s))
	}
	f.Fuzz(func(t *testing.T, b []byte) {
		p := ParseProblem(b)
		if len(b) > maxProblemBytes && p != (Problem{}) {
			t.Fatalf("a document over %d bytes was read", maxProblemBytes)
		}
		if p.Type != "" && (!strings.HasPrefix(p.Type, ProblemPrefix) || len(p.Type) > len(ProblemPrefix)+40) {
			t.Fatalf("type %q escaped the namespace", p.Type)
		}
		if p.Status != 0 && (p.Status < 100 || p.Status > 599) {
			t.Fatalf("status %d", p.Status)
		}
	})
}

func FuzzParseARI(f *testing.F) {
	for _, s := range []string{
		`{"suggestedWindow":{"start":"2030-01-01T00:00:00Z","end":"2030-01-02T00:00:00Z"},"explanationURL":"https://x"}`,
		`{"suggestedWindow":{"start":"2030-01-01T00:00:00+14:00","end":"2030-01-01T00:00:00-12:00"}}`,
		`{"suggestedWindow":{"start":"9999-12-31T23:59:59Z","end":"0000-01-01T00:00:00Z"}}`,
		`{"suggestedWindow":null}`, `{}`, `x`,
	} {
		f.Add([]byte(s))
	}
	f.Fuzz(func(t *testing.T, b []byte) {
		start, end, err := ParseARI(b)
		if len(b) > maxARIBytes && err == nil {
			t.Fatalf("a document over %d bytes was read", maxARIBytes)
		}
		if err == nil && (!start.Before(end) || start.Year() < 2000) {
			t.Fatalf("window %v..%v accepted", start, end)
		}
	})
}

func FuzzParseDirectory(f *testing.F) {
	for _, s := range []string{
		`{"newNonce":"https://ca/n","newAccount":"https://ca/a","newOrder":"https://ca/o","keyChange":"https://ca/k",` +
			`"renewalInfo":"https://ca/ari","meta":{"termsOfService":"https://ca/tos","externalAccountRequired":true}}`,
		`{"newNonce":"http://ca/n","newAccount":"https://ca/a","newOrder":"https://ca/o"}`,
		`{"newNonce":"https://u@ca/n","newAccount":"https://ca/a","newOrder":"https://169.254.169.254/o"}`,
		`{"meta":{"website":"javascript:x"}}`, `null`, `{`,
	} {
		f.Add([]byte(s))
	}
	f.Fuzz(func(t *testing.T, b []byte) {
		d, err := ParseDirectory(b)
		if err != nil {
			return
		}
		for _, u := range []string{d.NewNonce, d.NewAccount, d.NewOrder} {
			if !strings.HasPrefix(u, "https://") {
				t.Fatalf("required URL %q is not https", u)
			}
		}
		for _, u := range []string{d.KeyChange, d.RenewalInfo} {
			if u != "" && !strings.HasPrefix(u, "https://") {
				t.Fatalf("optional URL %q is not https", u)
			}
		}
		for _, u := range []string{d.NewNonce, d.NewAccount, d.NewOrder, d.KeyChange, d.RenewalInfo, d.TermsOfService, d.Website} {
			if len(u) > 3*maxURLLen {
				t.Fatalf("URL too long: %d", len(u))
			}
		}
	})
}

// FuzzCheckChain feeds the check of the chain a CA hands back (the leaf's DER and, as the library reads a PEM
// download, the rest as PEM blocks): only a parseable chain whose leaf holds the ordered key and exactly the ordered
// names is accepted; everything else is ReasonDirectoryInvalid.
func FuzzCheckChain(f *testing.F) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		f.Fatal(err)
	}
	tpl := &x509.Certificate{SerialNumber: big.NewInt(7), Subject: pkix.Name{CommonName: "a.example.test"},
		DNSNames: []string{"a.example.test", "*.b.example.test"}, NotBefore: time.Unix(1e9, 0), NotAfter: time.Unix(2e9, 0)}
	leaf, err := x509.CreateCertificate(rand.Reader, tpl, tpl, key.Public(), key)
	if err != nil {
		f.Fatal(err)
	}
	pemLeaf := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: leaf})
	f.Add(leaf, pemLeaf, "a.example.test,*.b.example.test")
	f.Add(leaf, []byte{}, "A.example.test,*.b.example.test")
	f.Add(leaf, []byte("-----BEGIN CERTIFICATE-----\nx\n-----END CERTIFICATE-----\n"), "a.example.test,*.b.example.test")
	f.Add(leaf, pemLeaf, "a.example.test")
	f.Add(leaf[:len(leaf)/2], []byte{}, "a.example.test,*.b.example.test")
	f.Add([]byte{0x30, 0x82, 0xff, 0xff}, []byte{}, "")
	f.Fuzz(func(t *testing.T, leafDER, rest []byte, names string) {
		chain := [][]byte{leafDER}
		for len(rest) > 0 && len(chain) < 16 {
			var b *pem.Block
			if b, rest = pem.Decode(rest); b == nil {
				break
			}
			chain = append(chain, b.Bytes)
		}
		want := strings.Split(names, ",")
		err := checkChain(chain, key.Public(), want)
		if err != nil {
			var e *Error
			if !errors.As(err, &e) || e.Reason != ReasonDirectoryInvalid {
				t.Fatalf("refusal %v is not %s", err, ReasonDirectoryInvalid)
			}
		}
		// The expected verdict: a leaf that does not parse is a garbled answer; a parseable leaf of another key or
		// other names is the wrong certificate; then any chain certificate that does not parse is a garbled answer.
		var expect error
		c, perr := x509.ParseCertificate(chain[0])
		switch {
		case perr != nil:
			expect = ErrBadAnswer
		case !key.PublicKey.Equal(c.PublicKey) || !sameNames(c.DNSNames, want):
			expect = ErrChainKeyMismatch
		default:
			for _, der := range chain[1:] {
				if _, perr := x509.ParseCertificate(der); perr != nil {
					expect = ErrBadAnswer
					break
				}
			}
		}
		if expect == nil {
			if err != nil {
				t.Fatalf("refused a good chain: %v", err)
			}
			return
		}
		if !errors.Is(err, expect) {
			t.Fatalf("got %v, want %v", err, expect)
		}
	})
}

// FuzzNormalizeNames feeds the order's names (newline separated): an accepted list is lower-case, without a
// trailing dot or a duplicate, 1..MaxNames long, every name a valid DNS name of at most 253 characters; a refusal
// is ReasonIdentifierRefused with a short, printable identifier.
func FuzzNormalizeNames(f *testing.F) {
	for _, s := range []string{"www.example.test", "WWW.Example.Test.\n*.example.test", "xn--bcher-kva.test", "a.b\na.b", "*.*.x.test",
		"1.2.3.4", "a..test", "-a.test", "a\x00b.test", "", "\n", strings.Repeat("a.", 127) + "test", "é.test"} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		in := strings.Split(s, "\n")
		out, err := NormalizeNames(in)
		if err != nil {
			var e *Error
			if !errors.As(err, &e) || e.Reason != ReasonIdentifierRefused || len(e.Identifier) > 64 ||
				strings.ContainsFunc(e.Identifier, func(r rune) bool { return r < 0x21 || r > 0x7e }) {
				t.Fatalf("refusal %#v", err)
			}
			return
		}
		if len(out) != len(in) || len(out) == 0 || len(out) > MaxNames {
			t.Fatalf("%d names in, %d out", len(in), len(out))
		}
		seen := map[string]bool{}
		for _, n := range out {
			if seen[n] || !validName(n) || n != asciiLower(n) || strings.HasSuffix(n, ".") || len(n) > 253 {
				t.Fatalf("accepted %q", n)
			}
			if strings.Contains(strings.TrimPrefix(n, "*."), "*") {
				t.Fatalf("wildcard outside the first label: %q", n)
			}
			seen[n] = true
		}
	})
}
