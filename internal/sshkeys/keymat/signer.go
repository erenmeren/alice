package keymat

import (
	"golang.org/x/crypto/ssh"

	"alice/internal/secrets"
)

// Signer returns an SSH signer for one test login. release clears what can be cleared of the parsed
// key; the signer must not be used after it.
func Signer(pkcs8 secrets.Plaintext) (ssh.Signer, func(), error) {
	priv, err := parse(pkcs8)
	if err != nil {
		return nil, nil, err
	}
	s, err := ssh.NewSignerFromKey(priv)
	if err != nil {
		wipe(priv)
		return nil, nil, ErrKeyData
	}
	return s, func() { wipe(priv) }, nil
}
