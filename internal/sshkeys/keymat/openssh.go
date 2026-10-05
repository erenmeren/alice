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
// result. Alice clears the parsed Ed25519 key and the DER bytes of the PEM block it is handed. It
// cannot clear what golang.org/x/crypto/ssh keeps while it builds the block (copies of the private key
// in its marshalling buffers, and for a passphrase the bcrypt-derived AES key and IV), nor the growth
// copies of pem.EncodeToMemory, nor big.Int limbs of RSA and ECDSA keys (known limitation P4-04).
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
