package linuxsshtest

import (
	"bytes"
	"crypto"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"slices"

	"alice/internal/providers/linuxssh/helperproto"
)

// The rollback guard of protocol 10 (R48), ported from cmd/alice-helper rollbackguard.go: a restore
// never puts back a backup whose leaf or public key is listed. An emulator of an older protocol
// (SetProtocol below RollbackGuardMinProtocol) refuses deploy input with the lists (BAD_CONTENT)
// and ignores nginx-restore's stdin, as an older helper does.

// emuGuard is the helper's guard: forbidden SPKI and leaf hashes.
type emuGuard struct {
	spki, leaf []string
}

func (g emuGuard) empty() bool { return len(g.spki) == 0 && len(g.leaf) == 0 }

// with is the union of g and o (the helper's guard.with).
func (g emuGuard) with(o emuGuard) emuGuard {
	u := emuGuard{spki: slices.Clone(g.spki), leaf: slices.Clone(g.leaf)}
	for _, h := range o.spki {
		if !slices.Contains(u.spki, h) {
			u.spki = append(u.spki, h)
		}
	}
	for _, h := range o.leaf {
		if !slices.Contains(u.leaf, h) {
			u.leaf = append(u.leaf, h)
		}
	}
	return u
}

// forbids is the helper's guard.forbids: the leaf listed, the leaf's or the key file's public key
// listed, or (with a list) a backup that cannot be read as a certificate and a private key.
func (g emuGuard) forbids(certPEM, keyPEM []byte) bool {
	if g.empty() {
		return false
	}
	leaf := emuFirstCertificate(certPEM)
	if leaf == nil {
		return true
	}
	if slices.Contains(g.leaf, sum(leaf.Raw)) || slices.Contains(g.spki, emuSPKI(leaf.PublicKey, leaf.RawSubjectPublicKeyInfo)) {
		return true
	}
	pub := emuKeyPublic(keyPEM)
	return pub == nil || slices.Contains(g.spki, emuSPKI(pub, nil))
}

func emuSPKI(pub crypto.PublicKey, raw []byte) string {
	if der, err := x509.MarshalPKIXPublicKey(pub); err == nil {
		raw = der
	}
	s := sha256.Sum256(raw)
	return hex.EncodeToString(s[:])
}

func emuFirstCertificate(p []byte) *x509.Certificate {
	for rest := p; ; {
		var b *pem.Block
		b, rest = pem.Decode(rest)
		if b == nil {
			return nil
		}
		if b.Type == "CERTIFICATE" {
			c, err := x509.ParseCertificate(b.Bytes)
			if err != nil {
				return nil
			}
			return c
		}
	}
}

func emuKeyPublic(p []byte) crypto.PublicKey {
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
			continue
		}
		signer, ok := priv.(crypto.Signer)
		if err != nil || !ok {
			return nil
		}
		return signer.Public()
	}
}

// backupForbidden is the helper's backupForbidden: the operation's backups against the journal's
// lists with extra's.
func (h *nginxHost) backupForbidden(op *opDir, j *emuJournal, extra emuGuard) bool {
	g := j.guard.with(extra)
	if g.empty() {
		return false
	}
	if op.certBak == nil || op.keyBak == nil {
		return true
	}
	cert, key := op.certBak.bytes(), op.keyBak.bytes()
	if sum(cert) != j.oldCertSHA || sum(key) != j.oldKeySHA {
		return true
	}
	return g.forbids(cert, key)
}

// restoreGuard decodes nginx-restore's stdin (the helper's restoreGuard): empty is no list;
// anything but exactly the two valid lists is not ok (INVALID_ARGUMENT).
func restoreGuard(stdin []byte) (emuGuard, bool) {
	if len(stdin) > helperproto.MaxRestoreInput {
		return emuGuard{}, false
	}
	if len(bytes.TrimSpace(stdin)) == 0 {
		return emuGuard{}, true
	}
	var in struct {
		SPKI *[]string `json:"forbidden_spki_sha256"`
		Leaf *[]string `json:"forbidden_leaf_sha256"`
	}
	dec := json.NewDecoder(bytes.NewReader(stdin))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&in); err != nil || dec.More() || in.SPKI == nil || in.Leaf == nil ||
		!helperproto.ValidForbidden(*in.SPKI) || !helperproto.ValidForbidden(*in.Leaf) {
		return emuGuard{}, false
	}
	return emuGuard{spki: *in.SPKI, leaf: *in.Leaf}, true
}
