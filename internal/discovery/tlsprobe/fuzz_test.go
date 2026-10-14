package tlsprobe

import (
	"bytes"
	"regexp"
	"slices"
	"testing"
	"time"
	"unicode/utf8"

	"alice/internal/testutil/pki"
)

var fingerprintRE = regexp.MustCompile(`^[0-9a-f]{64}$`)

// FuzzParsePresentedChain (Review Focus 6): no input panics; an accepted chain keeps the leaf and the
// other certificates in order with their exact DER (a non-leaf with unstorable dates is dropped and
// counted), and everything it keeps fits the discovery_certificates
// CHECKs (fingerprint form, key algorithm set, valid UTF-8 without NUL, name and SAN bounds, ordered
// validity dates inside the years 1 to 9999). A refusal is always one of the two parse codes.
func FuzzParsePresentedChain(f *testing.F) {
	now := time.Date(2026, 10, 14, 12, 0, 0, 0, time.UTC)
	ca := pki.NewCA("Fuzz", pki.ECDSA256, now)
	leaf := ca.Issue(pki.Opts{CommonName: "fuzz.test", SANs: []string{"fuzz.test", "192.0.2.1"}}, now)
	rsaLeaf := ca.Issue(pki.Opts{CommonName: "rsa.test", KeyType: pki.RSA2048}, now)
	self := pki.SelfSigned("self.test", pki.Ed25519, now)
	flipped := slices.Clone(leaf.Cert.Raw)
	flipped[len(flipped)/2] ^= 0xff
	for _, s := range []struct{ a, b []byte }{
		{leaf.Cert.Raw, ca.Intermediate.Raw}, {ca.Root.Raw, nil}, {rsaLeaf.Cert.Raw, ca.Root.Raw}, {self.Cert.Raw, self.Cert.Raw},
		{flipped, nil}, {nil, nil}, {[]byte{0x30, 0x82, 0xff, 0xff}, leaf.Cert.Raw[:20]},
	} {
		for n := range uint8(4) {
			f.Add(s.a, s.b, n)
		}
	}
	f.Fuzz(func(t *testing.T, a, b []byte, shape uint8) {
		var der [][]byte
		switch shape % 4 {
		case 0:
			der = [][]byte{a}
		case 1:
			der = [][]byte{a, b}
		case 2:
			der = [][]byte{a, b, a}
		default:
			der = slices.Repeat([][]byte{a}, MaxCertificates+int(shape/4)%3)
		}
		c, err := ParsePresentedChain(der)
		if err != nil {
			code, ok := CodeOf(err)
			if !ok || (code != CodeMalformed && code != CodeChainTooLarge) {
				t.Fatalf("refusal %v is not a parse code", err)
			}
			if len(c.Certificates) != 0 {
				t.Fatal("a refused chain kept certificates")
			}
			return
		}
		if len(c.Certificates)+c.DroppedCerts != len(der) || len(der) > MaxCertificates || c.DroppedCerts < 0 {
			t.Fatalf("%d certificates kept and %d dropped of %d", len(c.Certificates), c.DroppedCerts, len(der))
		}
		if leaf, ok := c.Leaf(); !ok || !bytes.Equal(leaf.Raw, der[0]) {
			t.Fatal("the leaf is not the first certificate presented")
		}
		next := 0 // the kept certificates are a subsequence of der, in order
		for i, cert := range c.Certificates {
			for next < len(der) && !bytes.Equal(cert.Raw, der[next]) {
				next++
			}
			if next == len(der) {
				t.Fatalf("certificate %d is not a DER presented, in order", i)
			}
			next++
			if !fingerprintRE.MatchString(cert.FingerprintSHA256) {
				t.Fatalf("fingerprint %q", cert.FingerprintSHA256)
			}
			switch cert.KeyAlgorithm {
			case "rsa", "ecdsa", "ed25519", "other":
			default:
				t.Fatalf("key algorithm %q", cert.KeyAlgorithm)
			}
			for _, s := range []string{cert.SubjectCN, cert.IssuerCN} {
				if !storable(s, maxNameBytes) {
					t.Fatalf("name %q is not storable", s)
				}
			}
			if len(cert.DNSNames)+len(cert.IPAddresses) > MaxSANs {
				t.Fatalf("%d SANs kept", len(cert.DNSNames)+len(cert.IPAddresses))
			}
			for _, s := range append(slices.Clone(cert.DNSNames), cert.IPAddresses...) {
				if !storable(s, maxSANBytes) {
					t.Fatalf("SAN %q is not storable", s)
				}
			}
			if cert.NotAfter.Before(cert.NotBefore) || cert.NotBefore.Year() < 1 || cert.NotAfter.Year() > 9999 {
				t.Fatalf("validity %v .. %v", cert.NotBefore, cert.NotAfter)
			}
		}
	})
}

func storable(s string, limit int) bool {
	return len(s) <= limit && utf8.ValidString(s) && !bytes.ContainsRune([]byte(s), 0)
}
