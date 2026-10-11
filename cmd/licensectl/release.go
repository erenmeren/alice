package main

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"alice/internal/license/issuer"
)

// maxSignedFile bounds what release-sign signs: the release signs checksum files (SHA256SUMS and
// the outer alice-<v>.tar.gz.sha256, C5), never a package itself.
const maxSignedFile = 1 << 20

// releaseKeygen creates the release signing key pair (spec §16.7, SEC-107): rk-YYYY-NN.key
// (encrypted, purpose "release") and rk-YYYY-NN.pem (the public key for deploy/release/keys/).
func releaseKeygen(args []string, stdout, stderr io.Writer, ask prompter) int {
	fs := flags("release-keygen", stderr)
	out := fs.String("out", "", "directory for the key files (not the license key directory)")
	keyID := fs.String("key-id", "", "release key ID, for example rk-2026-01")
	if fs.Parse(args) != nil || *out == "" || *keyID == "" || fs.NArg() != 0 {
		_, _ = fmt.Fprint(stderr, usage)
		return 2
	}
	if !issuer.IsReleaseKeyID(*keyID, false) {
		_, _ = fmt.Fprintf(stderr, "The release key ID %q is not valid: release keys are named like rk-2026-01 (license keys are vk-...).\n", *keyID)
		return 2
	}
	if msg := unsafeReleaseDir(*out); msg != "" {
		_, _ = fmt.Fprintln(stderr, msg)
		return 2
	}
	pass, ok := newPassphrase(stderr, ask)
	if !ok {
		return 1
	}
	defer clear(pass)
	privPath, pubPath, err := issuer.WriteReleaseKeyPair(*out, *keyID, pass, issuer.KeyKDF)
	if errors.Is(err, issuer.ErrKeyExists) {
		_, _ = fmt.Fprintln(stderr, "A key already exists in", *out, "- release-keygen never overwrites a key.")
		return 1
	}
	if err != nil {
		_, _ = fmt.Fprintln(stderr, "release-keygen failed:", err)
		return 1
	}
	pubPEM, err := os.ReadFile(pubPath) //nolint:gosec // G304: the file release-keygen just wrote
	if err != nil {
		_, _ = fmt.Fprintln(stderr, err)
		return 1
	}
	_, pub, err := issuer.ParseReleasePublicKey(pubPEM)
	if err != nil {
		_, _ = fmt.Fprintln(stderr, err)
		return 1
	}
	_, _ = fmt.Fprintf(stdout, "Private release key (encrypted): %s\nPublic release key: %s\nKey ID: %s\nFingerprint (SHA-256): %s\n",
		privPath, pubPath, *keyID, issuer.ReleaseFingerprint(pub))
	_, _ = fmt.Fprintln(stdout, "Next: back the private key up like the license key, copy only "+filepath.Base(pubPath)+
		" into deploy/release/keys/, and publish the fingerprint (docs/vendor/licensing-vendor.md, 'Release key').")
	return 0
}

// unsafeReleaseDir explains why dir must not hold a release private key, or returns "". The
// license and release keys are kept apart (S-12), and deploy/release/keys is committed.
func unsafeReleaseDir(dir string) string {
	for _, name := range []string{issuer.PrivateKeyFile, issuer.PublicKeyFile, issuer.LedgerFile} {
		if _, err := os.Lstat(filepath.Join(dir, name)); err == nil {
			return fmt.Sprintf("%s is the license key directory (it holds %s). Keep the release key in its own directory.", dir, name)
		}
	}
	if abs, err := filepath.Abs(dir); err == nil && strings.HasSuffix(filepath.ToSlash(abs), "/deploy/release/keys") {
		return "deploy/release/keys is committed to the repository and holds public keys only. Write the release key pair " +
			"elsewhere and copy only the .pem file there."
	}
	return ""
}

// newPassphrase asks for a new passphrase twice and checks its strength.
func newPassphrase(stderr io.Writer, ask prompter) ([]byte, bool) {
	pass, err := ask("New key passphrase (at least 6 random words): ")
	if err != nil {
		_, _ = fmt.Fprintln(stderr, err)
		return nil, false
	}
	if err := issuer.CheckPassphrase(pass); err != nil {
		clear(pass)
		_, _ = fmt.Fprintln(stderr, "The passphrase is too weak: use at least 6 words and 24 characters (Diceware).")
		return nil, false
	}
	again, err := ask("Repeat the passphrase: ")
	if err != nil {
		clear(pass)
		_, _ = fmt.Fprintln(stderr, err)
		return nil, false
	}
	defer clear(again)
	if !bytes.Equal(pass, again) {
		clear(pass)
		_, _ = fmt.Fprintln(stderr, "The two passphrases differ. Nothing was written.")
		return nil, false
	}
	return pass, true
}

// releaseSign signs each FILE into FILE.sig (a raw 64-byte Ed25519 signature, C5) after asking for
// the passphrase once. Everything that can be checked without the key is checked first.
func releaseSign(args []string, stdout, stderr io.Writer, ask prompter) int {
	fs := flags("release-sign", stderr)
	keyPath := fs.String("key", "", "encrypted release key file (rk-YYYY-NN.key)")
	if fs.Parse(args) != nil || *keyPath == "" || fs.NArg() == 0 {
		_, _ = fmt.Fprint(stderr, usage)
		return 2
	}
	files := fs.Args()
	contents := make([][]byte, len(files))
	for i, f := range files {
		data, err := readSmallFile(f)
		if err != nil {
			_, _ = fmt.Fprintln(stderr, "Nothing was signed:", err)
			return 1
		}
		if _, err := os.Lstat(f + ".sig"); err == nil {
			_, _ = fmt.Fprintf(stderr, "Nothing was signed: %s.sig already exists; remove it first if it is to be replaced.\n", f)
			return 1
		}
		contents[i] = data
	}
	keyPEM, err := readKeyFile(*keyPath)
	if err != nil {
		_, _ = fmt.Fprintln(stderr, err)
		return 1
	}
	pass, err := ask("Release key passphrase: ")
	if err != nil {
		_, _ = fmt.Fprintln(stderr, err)
		return 1
	}
	k, err := issuer.OpenReleaseKey(keyPEM, pass)
	clear(pass)
	if err != nil {
		_, _ = fmt.Fprintln(stderr, "Cannot open the key:", err)
		return 1
	}
	defer k.Zero()
	for i, f := range files {
		sig, err := k.SignRelease(contents[i])
		if err == nil && !ed25519.Verify(k.Public(), contents[i], sig) {
			err = errors.New("the signature does not verify")
		}
		if err == nil {
			err = issuer.WriteNew(f+".sig", sig, 0o644)
		}
		if err != nil {
			_, _ = fmt.Fprintf(stderr, "Signing %s failed: %v\n", f, err)
			return 1
		}
		sum := sha256.Sum256(contents[i])
		_, _ = fmt.Fprintf(stdout, "Signed %s (SHA-256 %s) with %s: %s.sig\n", f, hex.EncodeToString(sum[:]), k.KeyID(), f)
	}
	return 0
}

// readSmallFile reads a checksum file to sign; anything larger than maxSignedFile is refused.
func readSmallFile(path string) ([]byte, error) {
	f, err := os.Open(path) //nolint:gosec // G304: vendor CLI path from its own arguments
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()
	data, err := io.ReadAll(io.LimitReader(f, maxSignedFile+1))
	if err != nil {
		return nil, err
	}
	if len(data) > maxSignedFile {
		return nil, fmt.Errorf("%s is larger than 1 MiB; release-sign signs checksum files (SHA256SUMS, alice-<v>.tar.gz.sha256), not packages", path)
	}
	return data, nil
}

// releaseVerify checks FILE against SIG with one release public key.
func releaseVerify(args []string, stdout, stderr io.Writer) int {
	fs := flags("release-verify", stderr)
	pubPath := fs.String("pub", "", "release public key file (rk-YYYY-NN.pem)")
	if fs.Parse(args) != nil || *pubPath == "" || fs.NArg() != 2 {
		_, _ = fmt.Fprint(stderr, usage)
		return 2
	}
	raw, err := os.ReadFile(*pubPath) //nolint:gosec // G304: vendor CLI path from its own flags
	if err != nil {
		_, _ = fmt.Fprintln(stderr, err)
		return 1
	}
	id, pub, err := issuer.ParseReleasePublicKey(raw)
	if err != nil {
		_, _ = fmt.Fprintln(stderr, err)
		return 1
	}
	data, err := readSmallFile(fs.Arg(0))
	if err != nil {
		_, _ = fmt.Fprintln(stderr, err)
		return 1
	}
	sig, err := readSmallFile(fs.Arg(1))
	if err != nil {
		_, _ = fmt.Fprintln(stderr, err)
		return 1
	}
	if len(sig) != ed25519.SignatureSize || !ed25519.Verify(pub, data, sig) {
		_, _ = fmt.Fprintln(stdout, "SIGNATURE INVALID")
		return 1
	}
	_, _ = fmt.Fprintf(stdout, "OK (release key %s, fingerprint %s)\n", id, issuer.ReleaseFingerprint(pub))
	return 0
}
