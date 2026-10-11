// Command releasesign makes and uses the throw-away release key of TEST packages (make
// release-test, the release harness; R43 row 43). The key is generated at test time, is not
// encrypted, has the key ID rk-test-01, and a package staged with it says TEST_SIGNED=1. Production
// releases are signed offline with licensectl release-sign and a passphrase-protected rk-YYYY-NN key.
//
//	go run ./tools/releasesign generate DIR          DIR/test-release.key and DIR/rk-test-01.pem
//	go run ./tools/releasesign sign KEY FILE...       FILE.sig (raw 64-byte Ed25519, C5)
package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"alice/internal/license/issuer"
)

// Names of the test key files.
const (
	KeyFile   = "test-release.key"
	TestKeyID = "rk-test-01"
)

const usage = `Usage:
  releasesign generate DIR       create DIR/test-release.key and DIR/rk-test-01.pem (TEST key)
  releasesign sign KEY FILE...   write FILE.sig for each FILE
`

func main() { os.Exit(run(os.Args[1:], os.Stdout, os.Stderr)) }

func run(args []string, stdout, stderr io.Writer) int {
	switch {
	case len(args) == 2 && args[0] == "generate":
		return report(stderr, generate(args[1], stdout))
	case len(args) >= 3 && args[0] == "sign":
		return report(stderr, sign(args[1], args[2:], stdout))
	}
	_, _ = fmt.Fprint(stderr, usage)
	return 2
}

func report(stderr io.Writer, err error) int {
	if err != nil {
		_, _ = fmt.Fprintln(stderr, "releasesign:", err)
		return 1
	}
	return 0
}

// generate writes a new test key pair into dir; it refuses deploy/release/keys (the committed
// production public keys) and never overwrites a file.
func generate(dir string, stdout io.Writer) error {
	abs, err := filepath.Abs(dir)
	if err != nil {
		return err
	}
	if strings.HasSuffix(filepath.ToSlash(abs), "/deploy/release/keys") {
		return errors.New("refusing to write a test key into deploy/release/keys: that directory holds the production release public keys")
	}
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return err
	}
	defer clear(priv)
	der, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		return err
	}
	defer clear(der)
	pubPEM, err := issuer.EncodeReleasePublicKey(TestKeyID, pub)
	if err != nil {
		return err
	}
	keyPath, pubPath := filepath.Join(dir, KeyFile), filepath.Join(dir, TestKeyID+".pem")
	for _, p := range []string{keyPath, pubPath} {
		if _, err := os.Lstat(p); err == nil { //nolint:gosec // G703: test tool path from its arguments
			return fmt.Errorf("%s already exists; a key is never overwritten", p)
		}
	}
	if err := os.MkdirAll(dir, 0o700); err != nil { //nolint:gosec // G703: test tool path from its arguments
		return err
	}
	if err := issuer.WriteNew(keyPath, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}), 0o600); err != nil {
		return err
	}
	if err := issuer.WriteNew(pubPath, pubPEM, 0o644); err != nil {
		return err
	}
	_, _ = fmt.Fprintf(stdout, "TEST release key %s: %s, %s (fingerprint %s). Never sign a customer release with it.\n",
		TestKeyID, keyPath, pubPath, issuer.ReleaseFingerprint(pub))
	return nil
}

// sign writes FILE.sig for each file with the test key at keyPath.
func sign(keyPath string, files []string, stdout io.Writer) error {
	raw, err := os.ReadFile(keyPath) //nolint:gosec // G304: test tool path from its arguments
	if err != nil {
		return err
	}
	block, _ := pem.Decode(raw)
	if block == nil || block.Type != "PRIVATE KEY" {
		return fmt.Errorf("%s is not a test release key", keyPath)
	}
	k, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return fmt.Errorf("%s is not a test release key: %w", keyPath, err)
	}
	priv, ok := k.(ed25519.PrivateKey)
	if !ok {
		return fmt.Errorf("%s is not an Ed25519 key", keyPath)
	}
	defer clear(priv)
	for _, f := range files {
		data, err := os.ReadFile(f) //nolint:gosec // G304: test tool path from its arguments
		if err != nil {
			return err
		}
		if _, err := os.Lstat(f + ".sig"); err == nil { //nolint:gosec // G703: test tool path from its arguments
			return fmt.Errorf("%s.sig already exists; a signature is never overwritten", f)
		}
		if err := issuer.WriteNew(f+".sig", ed25519.Sign(priv, data), 0o644); err != nil {
			return err
		}
		_, _ = fmt.Fprintf(stdout, "Signed %s with the TEST key: %s.sig\n", f, f)
	}
	return nil
}
