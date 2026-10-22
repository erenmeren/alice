package winhelper

import (
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"reflect"
	"testing"

	"alice/internal/testutil/pki"
)

func hexSHA256(b []byte) string {
	s := sha256.Sum256(b)
	return hex.EncodeToString(s[:])
}

func TestForbids(t *testing.T) {
	ca := pki.NewCA("Guard Test", pki.ECDSA256, testNow)
	for _, kt := range []pki.KeyType{pki.RSA2048, pki.ECDSA256} {
		l := ca.Issue(pki.Opts{CommonName: "www.example.test", SANs: []string{"www.example.test"}, KeyType: kt}, testNow)
		spkiDER, err := x509.MarshalPKIXPublicKey(l.Cert.PublicKey)
		if err != nil {
			t.Fatal(err)
		}
		leaf, spki := hexSHA256(l.Cert.Raw), hexSHA256(spkiDER)
		other := hexSHA256([]byte("other"))
		for name, c := range map[string]struct {
			spki, leaf []string
			want       bool
		}{
			"leaf listed":       {nil, []string{other, leaf}, true},
			"spki listed":       {[]string{spki}, nil, true},
			"spki in leaf list": {nil, []string{spki}, false},
			"unlisted":          {[]string{other}, []string{other}, false},
			"no lists":          {nil, nil, false},
			"empty lists":       {[]string{}, []string{}, false},
		} {
			if got := Forbids(l.Cert.Raw, c.spki, c.leaf); got != c.want {
				t.Errorf("%s %s: got %v", kt, name, got)
			}
		}
	}
	// A DER that does not parse cannot be shown safe: forbidden whenever a list is given (Linux's rule).
	if !Forbids([]byte("not a certificate"), nil, []string{hexSHA256([]byte("x"))}) {
		t.Fatal("an unparsable DER was allowed")
	}
	if Forbids([]byte("not a certificate"), nil, nil) {
		t.Fatal("without a list nothing is checked")
	}
}

func TestGuardWith(t *testing.T) {
	a, b, c := hexSHA256([]byte("a")), hexSHA256([]byte("b")), hexSHA256([]byte("c"))
	g := guard{SPKI: []string{a}, Leaf: []string{b}}.with(guard{SPKI: []string{a, c}, Leaf: []string{c}})
	if !reflect.DeepEqual(g, guard{SPKI: []string{a, c}, Leaf: []string{b, c}}) {
		t.Fatalf("%+v", g)
	}
	l := pki.SelfSigned("x.example.test", pki.ECDSA256, testNow)
	if !g.with(guard{Leaf: []string{hexSHA256(l.Cert.Raw)}}).forbids(l.Cert.Raw) || g.forbids(l.Cert.Raw) {
		t.Fatal("forbids")
	}
}
