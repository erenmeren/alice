//go:build linux

package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"

	"golang.org/x/crypto/ssh"

	"alice/internal/providers/linuxssh/helperproto"
	"alice/internal/providers/linuxssh/sshdconf"
)

// sshdOutputLimit caps sshd -T output (it is a few KiB in practice).
const sshdOutputLimit = sshdconf.MaxConfigSize

// sshdConfig runs "sshd -T" (plus extra arguments) and parses the output.
func (s *sys) sshdConfig(ctx context.Context, extra ...string) (sshdconf.Config, []byte, error) {
	out, err := s.runSSHD(ctx, append([]string{"-T"}, extra...)...)
	if err != nil {
		return sshdconf.Config{}, nil, err
	}
	if len(out) > sshdOutputLimit {
		return sshdconf.Config{}, nil, errTooLarge
	}
	cfg, err := sshdconf.Parse(out)
	if err != nil {
		return sshdconf.Config{}, nil, err
	}
	return cfg, out, nil
}

func cmdSSHDDump(ctx context.Context, s *sys, args []string) (any, error) {
	if len(args) != 0 {
		return nil, refused(helperproto.CodeUsage, "sshd-dump takes no arguments")
	}
	s.syslog(helperproto.SubSSHDDump, "")
	_, out, err := s.sshdConfig(ctx)
	if err != nil {
		return helperproto.SSHDDumpResponse{OK: true, Fallback: true}, nil
	}
	return helperproto.SSHDDumpResponse{OK: true, Config: string(out)}, nil
}

// defaultHostKeys are OpenSSH's default HostKey files.
var defaultHostKeys = []string{"/etc/ssh/ssh_host_ed25519_key", "/etc/ssh/ssh_host_ecdsa_key", "/etc/ssh/ssh_host_rsa_key"}

const maxPublicKeySize = 64 << 10

// cmdHostKeys lists the server's host public keys with their fingerprints. The helper computes
// the fingerprints itself (R37 item 4); a .pub file that is a symlink, too large or unparseable
// is skipped.
func cmdHostKeys(ctx context.Context, s *sys, args []string) (any, error) {
	if len(args) != 0 {
		return nil, refused(helperproto.CodeUsage, "hostkeys takes no arguments")
	}
	s.syslog(helperproto.SubHostKeys, "")
	paths := defaultHostKeys
	if cfg, _, err := s.sshdConfig(ctx); err == nil && len(cfg.HostKeys) > 0 {
		paths = cfg.HostKeys
	}
	keys := []helperproto.HostKeyInfo{}
	for _, p := range paths {
		pub := p + ".pub"
		if !helperproto.ValidPath(pub) {
			continue
		}
		data, err := s.readRegular(pub, maxPublicKeySize)
		if err != nil {
			continue
		}
		k, _, _, _, err := ssh.ParseAuthorizedKey(data)
		if err != nil {
			continue
		}
		keys = append(keys, helperproto.HostKeyInfo{Type: k.Type(), Bits: keyBits(k), Fingerprint: ssh.FingerprintSHA256(k), Path: pub})
	}
	return helperproto.HostKeysResponse{OK: true, Keys: keys}, nil
}

// keyBits is the RSA modulus size, the ECDSA curve size, or 256 for Ed25519.
func keyBits(k ssh.PublicKey) int {
	ck, ok := k.(ssh.CryptoPublicKey)
	if !ok {
		return 0
	}
	switch p := ck.CryptoPublicKey().(type) {
	case *rsa.PublicKey:
		return p.N.BitLen()
	case *ecdsa.PublicKey:
		return p.Curve.Params().BitSize
	case ed25519.PublicKey:
		return 256
	default:
		return 0
	}
}
