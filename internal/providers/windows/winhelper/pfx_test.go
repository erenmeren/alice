package winhelper

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/pbkdf2"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/asn1"
	"encoding/pem"
	"errors"
	"reflect"
	"strings"
	"testing"

	"software.sslmate.com/src/go-pkcs12"

	"alice/internal/testutil/pki"
)

func pkcs8Of(t *testing.T, l pki.Leaf) []byte {
	t.Helper()
	b, _ := pem.Decode(l.KeyPEM)
	if b == nil || b.Type != "PRIVATE KEY" {
		t.Fatal("no PKCS #8 key")
	}
	return b.Bytes
}

func TestBuildPFXDecodes(t *testing.T) {
	ca := pki.NewCA("PFX Test", pki.ECDSA256, testNow)
	for _, kt := range []pki.KeyType{pki.RSA2048, pki.ECDSA256} {
		l := ca.Issue(pki.Opts{CommonName: "www.example.test", SANs: []string{"www.example.test"}, KeyType: kt}, testNow)
		key := pkcs8Of(t, l)
		keyCopy := bytes.Clone(key)
		pw := NewPFXPassword()
		if len(pw) != pfxPasswordLen {
			t.Fatal(len(pw))
		}
		pwCopy := bytes.Clone(pw)
		pfx, err := BuildPFX(l.Cert.Raw, key, pw)
		if err != nil {
			t.Fatal(err)
		}
		// BuildPFX clears nothing of its inputs (the caller does).
		if !bytes.Equal(key, keyCopy) || !bytes.Equal(pw, pwCopy) {
			t.Fatal("BuildPFX changed its inputs")
		}
		gotKey, leaf, cas, err := pkcs12.DecodeChain(pfx, string(pw))
		if err != nil {
			t.Fatalf("%s: %v", kt, err)
		}
		if !bytes.Equal(leaf.Raw, l.Cert.Raw) || len(cas) != 0 {
			t.Fatalf("%s: leaf or chain differs", kt)
		}
		want, _ := x509.ParsePKCS8PrivateKey(key)
		if !reflect.DeepEqual(gotKey, want) {
			t.Fatalf("%s: key differs", kt)
		}
		if _, _, _, err := pkcs12.DecodeChain(pfx, "wrong"); err == nil {
			t.Fatalf("%s: a wrong password passed the MAC", kt)
		}
		// Neither the password nor the key's plain bytes are in the output.
		if bytes.Contains(pfx, pw) || bytes.Contains(pfx, bmpString(pw)[:len(pw)]) || bytes.Contains(pfx, privateScalar(t, want)) {
			t.Fatalf("%s: the password or the key is in the PFX", kt)
		}
		// Each PFX is new: salts and IV are random.
		again, _ := BuildPFX(l.Cert.Raw, key, pw)
		if bytes.Equal(again, pfx) {
			t.Fatal("two PFX are equal")
		}
	}
}

// privateScalar is the secret part of a key (the public part is in the certificate as well).
func privateScalar(t *testing.T, k any) []byte {
	t.Helper()
	switch k := k.(type) {
	case *rsa.PrivateKey:
		return k.D.Bytes()[:32]
	case *ecdsa.PrivateKey:
		b, err := k.Bytes()
		if err != nil {
			t.Fatal(err)
		}
		return b
	}
	t.Fatalf("%T", k)
	return nil
}

func TestBuildPFXRefusals(t *testing.T) {
	l := pki.SelfSigned("x.example.test", pki.ECDSA256, testNow)
	key := pkcs8Of(t, l)
	pw := NewPFXPassword()
	for name, c := range map[string]struct{ der, key, pw []byte }{
		"no leaf":         {nil, key, pw},
		"no key":          {l.Cert.Raw, nil, pw},
		"no password":     {l.Cert.Raw, key, nil},
		"non-ASCII":       {l.Cert.Raw, key, []byte("pässword")},
		"NUL in password": {l.Cert.Raw, key, []byte("a\x00b")},
	} {
		out, err := BuildPFX(c.der, c.key, c.pw)
		if err == nil || out != nil {
			t.Errorf("%s: no error", name)
			continue
		}
		if strings.Contains(err.Error(), string(key)) || strings.Contains(err.Error(), string(pw)) {
			t.Errorf("%s: the error holds the key or the password", name)
		}
	}
}

func TestNewPFXPasswordIsPrintableAndFresh(t *testing.T) {
	a := NewPFXPassword()
	b := NewPFXPassword()
	if bytes.Equal(a, b) {
		t.Fatal("two passwords are equal")
	}
	for _, c := range a {
		if c < 0x21 || c > 0x7e {
			t.Fatalf("byte %#x", c)
		}
	}
}

func TestPBKDF2MatchesTheStandardLibrary(t *testing.T) {
	pw, salt := []byte("password"), []byte("saltsaltsaltsalt")
	for _, n := range []int{16, 32, 48} {
		want, err := pbkdf2.Key(sha256.New, string(pw), salt, 1000, n)
		if err != nil {
			t.Fatal(err)
		}
		if got := pbkdf2SHA256(pw, salt, 1000, n); !bytes.Equal(got, want) {
			t.Fatalf("%d: differs", n)
		}
	}
}

func TestBMPString(t *testing.T) {
	if got := bmpString([]byte("ab")); !bytes.Equal(got, []byte{0, 'a', 0, 'b', 0, 0}) {
		t.Fatalf("%v", got)
	}
}

// pfxBags is the bags of BuildPFX's one data ContentInfo, in order.
func pfxBags(t *testing.T, pfx []byte) []safeBag {
	t.Helper()
	var pdu pfxPdu
	var authSafe, contents []byte
	var infos []contentInfo
	var bags []safeBag
	if _, err := asn1.Unmarshal(pfx, &pdu); err != nil {
		t.Fatal(err)
	}
	if _, err := asn1.Unmarshal(pdu.AuthSafe.Content.Bytes, &authSafe); err != nil {
		t.Fatal(err)
	}
	if _, err := asn1.Unmarshal(authSafe, &infos); err != nil || len(infos) != 1 {
		t.Fatal(err, len(infos))
	}
	if _, err := asn1.Unmarshal(infos[0].Content.Bytes, &contents); err != nil {
		t.Fatal(err)
	}
	if _, err := asn1.Unmarshal(contents, &bags); err != nil {
		t.Fatal(err)
	}
	return bags
}

func TestBuildPFXWithIntermediates(t *testing.T) {
	ca := pki.NewCA("PFX Chain", pki.ECDSA256, testNow)
	other := pki.NewCA("PFX Chain Other", pki.RSA2048, testNow)
	l := ca.Issue(leafOpts, testNow)
	key := pkcs8Of(t, l)
	pw := NewPFXPassword()
	inter := [][]byte{ca.Intermediate.Raw, other.Intermediate.Raw}
	pfx, err := BuildPFX(l.Cert.Raw, key, pw, inter...)
	if err != nil {
		t.Fatal(err)
	}
	// The test's own reader: the leaf is the bag that shares the key's localKeyId, the chain follows in order.
	leaf, chain, err := pki.OpenPFX(pfx, pw)
	if err != nil || !bytes.Equal(leaf, l.Cert.Raw) || !reflect.DeepEqual(chain, inter) {
		t.Fatalf("%v leaf=%v chain=%d", err, bytes.Equal(leaf, l.Cert.Raw), len(chain))
	}
	if _, _, err := pki.OpenPFX(pfx, NewPFXPassword()); !errors.Is(err, pki.ErrPFXPassword) {
		t.Fatalf("another password: %v", err)
	}
	// go-pkcs12 reads the same chain.
	_, gl, cas, err := pkcs12.DecodeChain(pfx, string(pw))
	if err != nil || !bytes.Equal(gl.Raw, l.Cert.Raw) || len(cas) != 2 || !bytes.Equal(cas[0].Raw, inter[0]) || !bytes.Equal(cas[1].Raw, inter[1]) {
		t.Fatalf("go-pkcs12: %v", err)
	}
	// W2's two bags first, then one certBag per intermediate without any attribute.
	bags := pfxBags(t, pfx)
	if len(bags) != 4 || !bags[0].ID.Equal(oidCertBag) || !bags[1].ID.Equal(oidPKCS8ShroudedKeyBag) ||
		len(bags[0].Attributes) != 1 || len(bags[1].Attributes) != 1 {
		t.Fatalf("bags: %d", len(bags))
	}
	for _, b := range bags[2:] {
		if !b.ID.Equal(oidCertBag) || len(b.Attributes) != 0 {
			t.Fatalf("intermediate bag %v with %d attributes", b.ID, len(b.Attributes))
		}
	}
	// No intermediate: W2's structure, the leaf and its key.
	plain, err := BuildPFX(l.Cert.Raw, key, pw)
	if err != nil {
		t.Fatal(err)
	}
	if bags := pfxBags(t, plain); len(bags) != 2 {
		t.Fatalf("%d bags", len(bags))
	}
	if leaf, chain, err := pki.OpenPFX(plain, pw); err != nil || !bytes.Equal(leaf, l.Cert.Raw) || len(chain) != 0 {
		t.Fatalf("%v %d", err, len(chain))
	}
	// An empty intermediate is refused.
	if out, err := BuildPFX(l.Cert.Raw, key, pw, nil); err == nil || out != nil {
		t.Fatal("an empty intermediate was written")
	}
}
