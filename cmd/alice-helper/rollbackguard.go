//go:build linux

package main

import (
	"crypto"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"slices"
)

// guard is the rollback guard of protocol 10 (R48): the SHA-256 of the SubjectPublicKeyInfo of
// every public key and the SHA-256 of the DER of every leaf a restore must never put back (a
// compromised key, a revoked certificate). An operation keeps the lists nginx-deploy received in
// its journal; nginx-restore and a re-sent operation add the lists they receive (Alice reads them
// again before every rollback). Both lists are helperproto.ValidForbidden.
type guard struct {
	SPKI []string
	Leaf []string
}

// empty reports a guard that forbids nothing (an older Alice sends none): restores are not checked.
func (g guard) empty() bool { return len(g.SPKI) == 0 && len(g.Leaf) == 0 }

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

// forbids reports whether the backed-up pair (the certificate file's and the key file's bytes)
// holds forbidden material: the leaf (the first CERTIFICATE block) is listed, or the leaf's public
// key or the key file's public key is. With a list, a backup that cannot be read as a certificate
// and a private key (PKCS #8, PKCS #1, SEC 1) is forbidden too: what it holds cannot be shown safe.
// Without a list nothing is checked (a deployment of an older Alice restores as before).
func (g guard) forbids(certPEM, keyPEM []byte) bool {
	if g.empty() {
		return false
	}
	leaf := firstCertificate(certPEM)
	if leaf == nil {
		return true
	}
	sum := sha256.Sum256(leaf.Raw)
	if slices.Contains(g.Leaf, hex.EncodeToString(sum[:])) || slices.Contains(g.SPKI, spkiSHA256(leaf.PublicKey, leaf.RawSubjectPublicKeyInfo)) {
		return true
	}
	pub := keyPublic(keyPEM)
	if pub == nil {
		return true
	}
	return slices.Contains(g.SPKI, spkiSHA256(pub, nil))
}

// spkiSHA256 is the hex SHA-256 of the public key's re-encoded SubjectPublicKeyInfo, as Alice
// computes certificates.public_key_sha256 (internal/certs); raw is the fallback when the key cannot
// be encoded.
func spkiSHA256(pub crypto.PublicKey, raw []byte) string {
	if der, err := x509.MarshalPKIXPublicKey(pub); err == nil {
		raw = der
	}
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:])
}

// firstCertificate parses the leaf of a PEM text as Nginx reads it (leafDER: the first block labelled CERTIFICATE,
// X509 CERTIFICATE or TRUSTED CERTIFICATE; nil when there is none or it does not parse).
func firstCertificate(p []byte) *x509.Certificate {
	der := leafDER(p)
	if der == nil {
		return nil
	}
	c, err := x509.ParseCertificate(der)
	if err != nil {
		return nil
	}
	return c
}

// keyPublic is the public key of the first private key block of a PEM text (nil when there is none
// or it does not parse). The decoded block is cleared.
func keyPublic(p []byte) crypto.PublicKey {
	for rest := p; ; {
		var b *pem.Block
		b, rest = pem.Decode(rest)
		if b == nil {
			return nil
		}
		var priv any
		var err error
		switch b.Type {
		case "PRIVATE KEY":
			priv, err = x509.ParsePKCS8PrivateKey(b.Bytes)
		case "RSA PRIVATE KEY":
			priv, err = x509.ParsePKCS1PrivateKey(b.Bytes)
		case "EC PRIVATE KEY":
			priv, err = x509.ParseECPrivateKey(b.Bytes)
		default:
			clear(b.Bytes)
			continue
		}
		clear(b.Bytes)
		signer, ok := priv.(crypto.Signer)
		if err != nil || !ok {
			return nil
		}
		return signer.Public()
	}
}
