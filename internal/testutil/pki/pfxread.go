package pki

import (
	"bytes"
	"crypto"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/pbkdf2"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"errors"
)

// The errors of OpenPFX.
var (
	ErrPFXPassword = errors.New("pki: the PFX's MAC does not verify under this password")
	ErrPFXNoKey    = errors.New("pki: the PFX holds no key that matches one of its certificates")
	ErrNotPFX      = errors.New("pki: not a PFX in the format winhelper.BuildPFX writes")
)

var (
	oidShroudedKeyBagType = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 12, 10, 1, 2}
	oidLocalKeyID         = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 21}
)

type (
	p12Attribute struct {
		ID    asn1.ObjectIdentifier
		Value asn1.RawValue
	}
	p12AttributedBag struct {
		ID         asn1.ObjectIdentifier
		Value      asn1.RawValue
		Attributes []p12Attribute `asn1:"set,optional"`
	}
	p12EncryptedKey struct {
		Algorithm     pkix.AlgorithmIdentifier
		EncryptedData []byte
	}
	p12PBKDF2Read struct {
		Salt       []byte
		Iterations int
		KeyLength  int                      `asn1:"optional"`
		Prf        pkix.AlgorithmIdentifier `asn1:"optional"`
	}
)

// OpenPFX reads a PFX in the format winhelper.BuildPFX writes, with the standard library only (the
// reader of the helper's tests and of the emulator wintest): one data ContentInfo of clear certBags and
// one pkcs8ShroudedKeyBag under PBES2 (PBKDF2-HMAC-SHA256, AES-256-CBC), an HMAC-SHA256 MAC. leaf is
// the certificate whose localKeyId the key bag shares and whose public key is the key's; chain is
// every other certificate, in the file's order. A MAC that does not verify is ErrPFXPassword.
func OpenPFX(pfx, password []byte) (leaf []byte, chain [][]byte, err error) {
	var pdu p12PFX
	if rest, err := asn1.Unmarshal(pfx, &pdu); err != nil || len(rest) != 0 || !pdu.AuthSafe.ContentType.Equal(oidDataType) {
		return nil, nil, ErrNotPFX
	}
	var authSafe []byte
	if _, err := asn1.Unmarshal(pdu.AuthSafe.Content.Bytes, &authSafe); err != nil {
		return nil, nil, ErrNotPFX
	}
	if !pdu.MacData.Mac.Algorithm.Algorithm.Equal(oidSHA256) || pdu.MacData.Iterations < 1 {
		return nil, nil, ErrNotPFX
	}
	mac := hmac.New(sha256.New, p12KDF(3, pdu.MacData.Salt, bmpPassword(string(password)), pdu.MacData.Iterations, 32))
	mac.Write(authSafe)
	if !hmac.Equal(mac.Sum(nil), pdu.MacData.Mac.Digest) {
		return nil, nil, ErrPFXPassword
	}
	var infos []p12ContentInfo
	if _, err := asn1.Unmarshal(authSafe, &infos); err != nil {
		return nil, nil, ErrNotPFX
	}
	type cert struct{ der, id []byte }
	var certs []cert
	var key crypto.PrivateKey
	var keyID []byte
	for _, ci := range infos {
		var contents []byte
		var bags []p12AttributedBag
		if !ci.ContentType.Equal(oidDataType) {
			return nil, nil, ErrNotPFX
		}
		if _, err := asn1.Unmarshal(ci.Content.Bytes, &contents); err != nil {
			return nil, nil, ErrNotPFX
		}
		if _, err := asn1.Unmarshal(contents, &bags); err != nil {
			return nil, nil, ErrNotPFX
		}
		for _, b := range bags {
			var id []byte
			for _, a := range b.Attributes {
				if a.ID.Equal(oidLocalKeyID) {
					id = a.Value.Bytes
				}
			}
			switch {
			case b.ID.Equal(oidCertBagType):
				var cb p12CertBag
				if _, err := asn1.Unmarshal(b.Value.Bytes, &cb); err != nil || !cb.ID.Equal(oidX509CertBag) {
					return nil, nil, ErrNotPFX
				}
				certs = append(certs, cert{cb.Value, id})
			case b.ID.Equal(oidShroudedKeyBagType):
				if key != nil {
					return nil, nil, ErrNotPFX
				}
				if key, err = decryptKey(b.Value.Bytes, password); err != nil {
					return nil, nil, err
				}
				keyID = id
			default:
				return nil, nil, ErrNotPFX
			}
		}
	}
	if key == nil || keyID == nil {
		return nil, nil, ErrPFXNoKey
	}
	for _, c := range certs {
		if leaf == nil && bytes.Equal(c.id, keyID) {
			parsed, err := x509.ParseCertificate(c.der)
			pub, ok := key.(interface{ Public() crypto.PublicKey })
			if err != nil || !ok {
				return nil, nil, ErrNotPFX
			}
			if eq, ok := pub.Public().(interface{ Equal(crypto.PublicKey) bool }); !ok || !eq.Equal(parsed.PublicKey) {
				return nil, nil, ErrPFXNoKey
			}
			leaf = c.der
			continue
		}
		chain = append(chain, c.der)
	}
	if leaf == nil {
		return nil, nil, ErrPFXNoKey
	}
	return leaf, chain, nil
}

// decryptKey opens a pkcs8ShroudedKeyBag of BuildPFX's form.
func decryptKey(der, password []byte) (crypto.PrivateKey, error) {
	var ek p12EncryptedKey
	var params p12PBES2Params
	var kdf p12PBKDF2Read
	var iv []byte
	if _, err := asn1.Unmarshal(der, &ek); err != nil || !ek.Algorithm.Algorithm.Equal(oidPBES2) {
		return nil, ErrNotPFX
	}
	if _, err := asn1.Unmarshal(ek.Algorithm.Parameters.FullBytes, &params); err != nil ||
		!params.KDF.Algorithm.Equal(oidPBKDF2) || !params.Scheme.Algorithm.Equal(oidAES256CBC) {
		return nil, ErrNotPFX
	}
	if _, err := asn1.Unmarshal(params.KDF.Parameters.FullBytes, &kdf); err != nil || !kdf.Prf.Algorithm.Equal(oidHMACSHA256) {
		return nil, ErrNotPFX
	}
	if _, err := asn1.Unmarshal(params.Scheme.Parameters.FullBytes, &iv); err != nil || len(iv) != aes.BlockSize {
		return nil, ErrNotPFX
	}
	k, err := pbkdf2.Key(sha256.New, string(password), kdf.Salt, kdf.Iterations, 32)
	if err != nil || len(ek.EncryptedData) == 0 || len(ek.EncryptedData)%aes.BlockSize != 0 {
		return nil, ErrNotPFX
	}
	block, _ := aes.NewCipher(k) // a 32-byte key is always an AES-256 key
	plain := make([]byte, len(ek.EncryptedData))
	cipher.NewCBCDecrypter(block, iv).CryptBlocks(plain, ek.EncryptedData)
	pad := int(plain[len(plain)-1])
	if pad == 0 || pad > aes.BlockSize {
		return nil, ErrNotPFX
	}
	key, err := x509.ParsePKCS8PrivateKey(plain[:len(plain)-pad])
	if err != nil {
		return nil, ErrNotPFX
	}
	return key, nil
}
