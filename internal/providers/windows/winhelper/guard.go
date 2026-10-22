package winhelper

import (
	"crypto"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"slices"
)

// guard is the rollback guard (R48, W2 Ruling 11), the port of cmd/alice-helper/rollbackguard.go: the
// SHA-256 of the SubjectPublicKeyInfo of every public key and the SHA-256 of the DER of every leaf a
// restore must never put back. An operation keeps the lists iis-deploy received in its journal;
// iis-restore adds the lists it receives. Both lists are winproto.ValidForbidden.
type guard struct {
	SPKI []string
	Leaf []string
}

// with is the union of g and o (o's entries that g lacks, after g's).
func (g guard) with(o guard) guard {
	u := guard{SPKI: slices.Clone(g.SPKI), Leaf: slices.Clone(g.Leaf)}
	for _, h := range o.SPKI {
		if !slices.Contains(u.SPKI, h) {
			u.SPKI = append(u.SPKI, h)
		}
	}
	for _, h := range o.Leaf {
		if !slices.Contains(u.Leaf, h) {
			u.Leaf = append(u.Leaf, h)
		}
	}
	return u
}

// forbids is Forbids with g's lists.
func (g guard) forbids(certDER []byte) bool { return Forbids(certDER, g.SPKI, g.Leaf) }

// Forbids reports whether a restore must not put back the certificate whose DER is certDER (read from
// the store, never from the journal): its DER SHA-256 is in leaf, or the SHA-256 of its public key's
// SubjectPublicKeyInfo is in spki. With a list, a DER that does not parse is forbidden too: what it
// holds cannot be shown safe. Without a list nothing is checked (Linux's rule).
//
// Linux also checks the key file's own public key, because there the key is a separate file a restore
// puts back. On Windows the private key is bound to the store certificate (CERT_KEY_PROV_INFO) and
// schannel uses it only with that certificate's public key: a key that differs from the certificate's
// SPKI cannot complete a handshake for it, so checking the certificate's SPKI is not a weakening.
func Forbids(certDER []byte, spki, leaf []string) bool {
	if len(spki) == 0 && len(leaf) == 0 {
		return false
	}
	c, err := x509.ParseCertificate(certDER)
	if err != nil {
		return true
	}
	sum := sha256.Sum256(c.Raw)
	return slices.Contains(leaf, hex.EncodeToString(sum[:])) || slices.Contains(spki, spkiSHA256(c.PublicKey, c.RawSubjectPublicKeyInfo))
}

// spkiSHA256 is the hex SHA-256 of the public key's re-encoded SubjectPublicKeyInfo, as Alice computes
// certificates.public_key_sha256 (internal/certs); raw is the fallback when the key cannot be encoded.
func spkiSHA256(pub crypto.PublicKey, raw []byte) string {
	if der, err := x509.MarshalPKIXPublicKey(pub); err == nil {
		raw = der
	}
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:])
}
