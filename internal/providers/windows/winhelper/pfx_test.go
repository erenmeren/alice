package winhelper

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/pbkdf2"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/pem"
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
