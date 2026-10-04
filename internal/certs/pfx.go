package certs

import (
	"crypto/x509"

	"software.sslmate.com/src/go-pkcs12"

	"alice/internal/secrets"
)

// ExportPFX builds the PFX of an import (R40 row 25): pkcs12.LegacyDES, empty password, the leaf
// and p.Chain without a self-signed root. keyDER is the key as PKCS #8; it must belong to p.Leaf and
// pass the key rules of an upload (RSA of 2048 to 16384 bits, ECDSA P-256 or P-384). keyDER and p
// are not modified. It does not check validity: the caller (the inventory import) refuses an
// expired or not-yet-valid leaf first. The result holds the private key (an empty password protects nothing): the
// caller zeroes it as soon as it has been sent. Errors never contain key material.
func ExportPFX(keyDER secrets.Plaintext, p Parsed) (secrets.Plaintext, error) {
	if p.Leaf == nil {
		return secrets.Plaintext{}, invalid("there is no certificate to export")
	}
	chain := WithoutRoot(p).Chain
	if len(chain)+1 > maxCertificates {
		return secrets.Plaintext{}, invalid("too many certificates")
	}
	key, err := x509.ParsePKCS8PrivateKey(keyDER.Bytes())
	if err != nil {
		return secrets.Plaintext{}, invalid("the private key cannot be parsed")
	}
	signer, err := checkPrivateKey(key)
	if err != nil {
		return secrets.Plaintext{}, err
	}
	if !samePublicKey(p.Leaf.PublicKey, signer.Public()) {
		return secrets.Plaintext{}, ErrKeyMismatch
	}
	pfx, err := pkcs12.LegacyDES.Encode(key, p.Leaf, chain, "")
	if err != nil {
		return secrets.Plaintext{}, invalid("the PFX cannot be built")
	}
	return secrets.NewPlaintext(pfx), nil
}
