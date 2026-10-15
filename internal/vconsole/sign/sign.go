// Package sign is the seam between the vendor console and whatever holds the license signing key.
// Phase 1 has the passphrase key file; a YubiKey implementation (PIV or OpenPGP) joins in Phase 2
// behind the same interface.
package sign

import (
	"context"
	"crypto/ed25519"

	"alice/internal/license"
	"alice/internal/license/issuer"
)

// Signer issues a signed license file for a payload. Implementations may ask for a PIN or a touch;
// Issue must honour ctx.
type Signer interface {
	KeyID() string
	Public() ed25519.PublicKey
	Issue(ctx context.Context, p license.Payload) ([]byte, error)
}

// FileSigner signs with the passphrase-protected key file opened by issuer.OpenKey.
type FileSigner struct{ key *issuer.SigningKey }

// NewFileSigner wraps an opened license signing key.
func NewFileSigner(k *issuer.SigningKey) *FileSigner { return &FileSigner{key: k} }

// KeyID returns the key ID written into every license.
func (s *FileSigner) KeyID() string { return s.key.KeyID() }

// Public returns the verification key.
func (s *FileSigner) Public() ed25519.PublicKey { return s.key.Public() }

// Issue signs p.
func (s *FileSigner) Issue(ctx context.Context, p license.Payload) ([]byte, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	return s.key.Issue(p)
}

// Verify checks a license file against the signer's own public key, the way the product would
// with that key in its key set. The issuing code calls it on every file it just produced.
func Verify(raw []byte, s Signer) (license.File, error) {
	ks := license.NewKeySet(license.PublicKey{ID: s.KeyID(), Key: s.Public(), Status: license.KeyActive})
	return license.Check(raw, ks)
}
