package lestaging

import (
	"crypto"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"alice/internal/acme/keygen"
	"alice/internal/secrets"
)

// The files of the state directory.
const (
	stateFile      = "state.json"
	accountKeyFile = "account-key.pem"
	certDir        = "certificates"
)

// state is what survives between runs: the account is reused (new registrations are rate limited), certificates
// that were issued but not yet revoked are revoked by the next run, and the CA's earliest retry time is honoured.
type state struct {
	AccountURL string `json:"account_url,omitempty"`
	// Pending are the certificate files (below certDir) still to revoke.
	Pending []string `json:"pending_revocation,omitempty"`
	// CANotBefore is the earliest time the CA allows the next request (Retry-After of a rate limit).
	CANotBefore time.Time `json:"ca_not_before,omitzero"`
}

func loadState(dir string) (*state, error) {
	b, err := os.ReadFile(filepath.Join(dir, stateFile)) //nolint:gosec // the harness's own directory
	if errors.Is(err, os.ErrNotExist) {
		return &state{}, nil
	}
	if err != nil {
		return nil, err
	}
	var s state
	if err := json.Unmarshal(b, &s); err != nil {
		return nil, fmt.Errorf("lestaging: %s is damaged (remove it to start afresh): %w", filepath.Join(dir, stateFile), err)
	}
	return &s, nil
}

func (s *state) save(dir string) error {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	b, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return err
	}
	tmp := filepath.Join(dir, stateFile+".tmp")
	if err := os.WriteFile(tmp, append(b, '\n'), 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, filepath.Join(dir, stateFile))
}

// accountKey opens the account key of an earlier run or makes and stores a new one (stored before it is
// registered, so a lost answer to the registration still finds the same account next time).
func accountKey(dir string) (crypto.Signer, bool, error) {
	path := filepath.Join(dir, accountKeyFile)
	b, err := os.ReadFile(path) //nolint:gosec // the harness's own directory
	if err == nil {
		blk, _ := pem.Decode(b)
		if blk == nil || blk.Type != "PRIVATE KEY" {
			return nil, false, fmt.Errorf("lestaging: %s is not a PKCS#8 key (remove it to register a new account)", path)
		}
		k, err := keygen.ParsePKCS8(secrets.NewPlaintext(blk.Bytes))
		if err != nil {
			return nil, false, fmt.Errorf("lestaging: %s: %w", path, err)
		}
		return k.Signer, true, nil
	}
	if !errors.Is(err, os.ErrNotExist) {
		return nil, false, err
	}
	k, err := keygen.Generate(keygen.ECDSAP256)
	if err != nil {
		return nil, false, err
	}
	defer k.Zero()
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, false, err
	}
	out := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: k.DER.Bytes()})
	defer clear(out)
	if err := os.WriteFile(path, out, 0o600); err != nil {
		return nil, false, err
	}
	return k.Signer, false, nil
}

// keepCertificate stores an issued chain (PEM) and lists the leaf for revocation. The name is the serial.
func (s *state) keepCertificate(dir string, chain [][]byte) (string, error) {
	leaf, err := x509.ParseCertificate(chain[0])
	if err != nil {
		return "", err
	}
	if err := os.MkdirAll(filepath.Join(dir, certDir), 0o700); err != nil {
		return "", err
	}
	name := leaf.SerialNumber.Text(16) + ".pem"
	var out []byte
	for _, der := range chain {
		out = append(out, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})...)
	}
	if err := os.WriteFile(filepath.Join(dir, certDir, name), out, 0o600); err != nil {
		return "", err
	}
	s.Pending = append(s.Pending, name)
	return name, s.save(dir)
}

// done takes a certificate off the revocation list.
func (s *state) done(dir, name string) error {
	for i, n := range s.Pending {
		if n == name {
			s.Pending = append(s.Pending[:i], s.Pending[i+1:]...)
			break
		}
	}
	return s.save(dir)
}

// leafOf reads the leaf DER of a stored certificate.
func leafOf(dir, name string) ([]byte, error) {
	b, err := os.ReadFile(filepath.Join(dir, certDir, filepath.Base(name))) //nolint:gosec // the harness's own directory
	if err != nil {
		return nil, err
	}
	blk, _ := pem.Decode(b)
	if blk == nil || blk.Type != "CERTIFICATE" {
		return nil, fmt.Errorf("lestaging: %s is not a certificate", name)
	}
	return blk.Bytes, nil
}
