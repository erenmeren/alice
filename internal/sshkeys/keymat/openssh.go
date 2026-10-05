package keymat

import (
	"encoding/pem"

	"golang.org/x/crypto/ssh"

	"alice/internal/secrets"
)

// onBlock sees the PEM block's DER before it is cleared (tests only; nil in production).
var onBlock func([]byte)

// OpenSSHFile returns the OpenSSH private-key file of a stored key (spec §13.5; R41 row 4):
// unencrypted with a nil passphrase, otherwise aes256-ctr with bcrypt-pbkdf. The caller zeroes the
// result; the DER of the PEM block is cleared here. pem.EncodeToMemory's growth copies cannot be.
func OpenSSHFile(pkcs8 secrets.Plaintext, comment string, passphrase []byte) (secrets.Plaintext, error) {
	if passphrase != nil && (len(passphrase) < MinPassphrase || len(passphrase) > MaxPassphrase) {
		return secrets.Plaintext{}, ErrPassphrase
	}
	if !validComment(comment) {
		return secrets.Plaintext{}, ErrLine
	}
	priv, err := parse(pkcs8)
	if err != nil {
		return secrets.Plaintext{}, err
	}
	defer wipe(priv)
	var block *pem.Block
	if passphrase == nil {
		block, err = ssh.MarshalPrivateKey(priv, comment)
	} else {
		block, err = ssh.MarshalPrivateKeyWithPassphrase(priv, comment, passphrase)
	}
	if err != nil {
		return secrets.Plaintext{}, ErrKeyData
	}
	out := pem.EncodeToMemory(block)
	if onBlock != nil {
		onBlock(block.Bytes)
	}
	clear(block.Bytes)
	return secrets.NewPlaintext(out), nil
}
