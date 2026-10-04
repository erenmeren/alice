// Command licensectl is the vendor's offline license tool (spec §19.2). It never ships to
// customers, never uses the network, and handles the signing key only in memory.
package main

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"alice/internal/license"
	"alice/internal/license/issuer"
	"alice/internal/platform/clock"
)

// prompter asks for a passphrase (no echo on a terminal; injected by tests).
type prompter func(prompt string) ([]byte, error)

const usage = `Usage: licensectl <command> [flags]

Commands:
  keygen --out DIR --key-id vk-YYYY-NN
        Create the license signing key pair (once; never overwrites a key).
  issue --key FILE --installation ID --customer NAME --targets N --out FILE
        [--from YYYY-MM-DD] [--months 12] [--features a,b] [--replaces LICENSE-ID]
        [--shorten] [--license-id ID] [--ledger FILE]
        Sign a license. Asks for the key passphrase and for "yes" before signing.
        A correction (--replaces) must name a license in the ledger; --shorten
        allows it to end earlier than that license.
  inspect FILE
        Print what a license file says (the signature is not checked).
  verify --pub FILE LICENSE-FILE
        Check a license file's signature: prints OK or SIGNATURE INVALID.
  keyset --pub FILE
        Print the key set entry for internal/license/keys/production.json and the fingerprint.
  ledger-verify --pub FILE [--ledger FILE]
        Check the issuance ledger (default: issued.csv next to the public key).

See docs/vendor/licensing-vendor.md.
`

func main() {
	os.Exit(run(os.Args[1:], os.Stdin, os.Stdout, os.Stderr, terminalPassphrase, clock.Real{}))
}

func run(args []string, stdin io.Reader, stdout, stderr io.Writer, ask prompter, clk clock.Clock) int {
	if len(args) == 0 {
		_, _ = fmt.Fprint(stderr, usage)
		return 2
	}
	switch args[0] {
	case "keygen":
		return keygen(args[1:], stdout, stderr, ask)
	case "issue":
		return issue(args[1:], stdin, stdout, stderr, ask, clk)
	case "inspect":
		return inspect(args[1:], stdout, stderr)
	case "verify":
		return verify(args[1:], stdout, stderr)
	case "keyset":
		return keyset(args[1:], stdout, stderr)
	case "ledger-verify":
		return ledgerVerify(args[1:], stdout, stderr)
	case "help", "-h", "--help":
		_, _ = fmt.Fprint(stdout, usage)
		return 0
	default:
		_, _ = fmt.Fprintf(stderr, "unknown command %q\n\n%s", args[0], usage)
		return 2
	}
}

func flags(name string, stderr io.Writer) *flag.FlagSet {
	fs := flag.NewFlagSet(name, flag.ContinueOnError)
	fs.SetOutput(stderr)
	return fs
}

func keygen(args []string, stdout, stderr io.Writer, ask prompter) int {
	fs := flags("keygen", stderr)
	out := fs.String("out", "", "directory for the key files")
	keyID := fs.String("key-id", "", "key ID, for example vk-2026-01")
	if fs.Parse(args) != nil || *out == "" || *keyID == "" || fs.NArg() != 0 {
		_, _ = fmt.Fprint(stderr, usage)
		return 2
	}
	pass, err := ask("New key passphrase (at least 6 random words): ")
	if err != nil {
		_, _ = fmt.Fprintln(stderr, err)
		return 1
	}
	defer clear(pass)
	if err := issuer.CheckPassphrase(pass); err != nil {
		_, _ = fmt.Fprintln(stderr, "The passphrase is too weak: use at least 6 words and 24 characters (Diceware).")
		return 1
	}
	again, err := ask("Repeat the passphrase: ")
	if err != nil {
		_, _ = fmt.Fprintln(stderr, err)
		return 1
	}
	defer clear(again)
	if !bytes.Equal(pass, again) {
		_, _ = fmt.Fprintln(stderr, "The two passphrases differ. Nothing was written.")
		return 1
	}
	privPath, pubPath, err := issuer.WriteKeyPair(*out, *keyID, pass, issuer.KeyKDF)
	if errors.Is(err, issuer.ErrKeyExists) {
		_, _ = fmt.Fprintln(stderr, "A key already exists in", *out, "- keygen never overwrites a key.")
		return 1
	}
	if err != nil {
		_, _ = fmt.Fprintln(stderr, "keygen failed:", err)
		return 1
	}
	pubPEM, err := os.ReadFile(pubPath) //nolint:gosec // G304: the file keygen just wrote
	if err != nil {
		_, _ = fmt.Fprintln(stderr, err)
		return 1
	}
	pub, err := issuer.ReadPublicKey(pubPEM)
	if err != nil {
		_, _ = fmt.Fprintln(stderr, err)
		return 1
	}
	_, _ = fmt.Fprintf(stdout, "Private key (encrypted): %s\nPublic key: %s\nKey ID: %s\nFingerprint: %s\n",
		privPath, pubPath, pub.ID, license.Fingerprint(pub.Key))
	_, _ = fmt.Fprintln(stdout, "Next: copy the private key file to two encrypted USB drives and make the paper backup "+
		"(docs/vendor/licensing-vendor.md). Only the public key goes into Alice builds (licensectl keyset).")
	return 0
}

func issue(args []string, stdin io.Reader, stdout, stderr io.Writer, ask prompter, clk clock.Clock) int {
	fs := flags("issue", stderr)
	keyPath := fs.String("key", "", "encrypted private key file")
	installation := fs.String("installation", "", "customer's Installation ID")
	customer := fs.String("customer", "", "customer name")
	targets := fs.Int("targets", 0, "number of managed targets")
	from := fs.String("from", "", "first valid day (YYYY-MM-DD); default today")
	months := fs.Int("months", 12, "validity in months")
	features := fs.String("features", "", "comma-separated feature names (unused in v1)")
	replaces := fs.String("replaces", "", "license ID a correction license replaces")
	shorten := fs.Bool("shorten", false, "allow a correction to end earlier than the license it replaces")
	licenseID := fs.String("license-id", "", "license ID; default LIC-<year>-<6 digits>")
	out := fs.String("out", "", "license file to write")
	ledger := fs.String("ledger", "", "issuance ledger; default issued.csv next to the key")
	if fs.Parse(args) != nil || *keyPath == "" || *installation == "" || *customer == "" || *targets == 0 || *out == "" || fs.NArg() != 0 {
		_, _ = fmt.Fprint(stderr, usage)
		return 2
	}
	if *months == 0 {
		_, _ = fmt.Fprintln(stderr, "--months must be between 1 and 60")
		return 1
	}
	p, err := issuer.BuildPayload(issuer.Request{
		Installation: *installation, Customer: *customer, Targets: *targets, From: *from, Months: *months,
		Features: strings.Split(*features, ","), Replaces: *replaces, LicenseID: *licenseID,
	}, clk.Now())
	if err != nil {
		_, _ = fmt.Fprintln(stderr, err)
		return 1
	}
	if _, err := os.Lstat(*out); err == nil {
		_, _ = fmt.Fprintln(stderr, *out, "already exists; choose another --out file.")
		return 1
	}
	keyPEM, err := readKeyFile(*keyPath)
	if err != nil {
		_, _ = fmt.Fprintln(stderr, err)
		return 1
	}
	pass, err := ask("Key passphrase: ")
	if err != nil {
		_, _ = fmt.Fprintln(stderr, err)
		return 1
	}
	k, err := issuer.OpenKey(keyPEM, pass)
	clear(pass)
	if err != nil {
		_, _ = fmt.Fprintln(stderr, "Cannot open the key:", err)
		return 1
	}
	defer k.Zero()

	ledgerPath := *ledger
	if ledgerPath == "" {
		ledgerPath = filepath.Join(filepath.Dir(*keyPath), issuer.LedgerFile)
	}
	if err := precheck(ledgerPath, k, p, *shorten); err != nil {
		_, _ = fmt.Fprintln(stderr, "Nothing was signed:", err)
		return 1
	}

	_, _ = fmt.Fprintf(stdout, "License ID:    %s\nCustomer:      %s\nInstallation:  %s\nValid from:    %s\nValid until:   %s\n"+
		"Targets:       %d\nFeatures:      %s\nReplaces:      %s\nSigning key:   %s\n",
		p.LicenseID, p.Customer, p.InstallationID, p.ValidFrom.Format(time.RFC3339), p.ValidUntil.Format(time.RFC3339),
		p.MaxTargets, strings.Join(p.Features, ","), p.Replaces, k.KeyID())
	_, _ = fmt.Fprint(stdout, `Type "yes" to sign: `)
	line, _ := bufio.NewReader(stdin).ReadString('\n')
	if strings.TrimSpace(line) != "yes" {
		_, _ = fmt.Fprintln(stdout, "Nothing was signed.")
		return 1
	}
	raw, err := k.Issue(p)
	if err != nil {
		_, _ = fmt.Fprintln(stderr, "signing failed:", err)
		return 1
	}
	// Under the ledger lock: re-check against the ledger as it is now (another licensectl may
	// have issued while this one waited for "yes"), record the row, then write the file, so no
	// signed license leaves licensectl without being recorded.
	l, err := issuer.LockLedger(ledgerPath)
	if err != nil {
		_, _ = fmt.Fprintln(stderr, "Nothing was written:", err)
		return 1
	}
	defer func() { _ = l.Unlock() }()
	head, err := l.Record(k, p, raw, *shorten)
	if err != nil {
		_, _ = fmt.Fprintln(stderr, "Nothing was written: the ledger could not be updated:", err)
		return 1
	}
	if err := issuer.WriteNew(*out, raw, 0o644); err != nil {
		_, _ = fmt.Fprintln(stderr, "The ledger records", p.LicenseID+", but", *out, "could not be written:", err)
		_, _ = fmt.Fprintln(stderr, "Issue again with a new license ID.")
		return 1
	}
	sum := sha256.Sum256(raw)
	_, _ = fmt.Fprintf(stdout, "\nWritten: %s\nSHA-256: %s\nLedger:  %s\nLedger rows: %d\nChain head:  %s\n", *out,
		hex.EncodeToString(sum[:]), ledgerPath, head.Rows, head.Chain)
	_, _ = fmt.Fprintln(stdout, "Write the ledger rows and chain head down: they show later whether rows were cut off or an old copy restored.")
	return 0
}

// readKeyFile reads the private key file and refuses one that others can read or write.
func readKeyFile(path string) ([]byte, error) {
	info, err := os.Stat(path)
	if err != nil {
		return nil, fmt.Errorf("cannot read the key file: %w", err)
	}
	if perm := info.Mode().Perm(); perm&0o077 != 0 {
		return nil, fmt.Errorf("the key file %s has mode %04o; others must not have access: run chmod 600 %s", path, perm, path)
	}
	keyPEM, err := os.ReadFile(path) //nolint:gosec // G304: vendor CLI path from its own flags
	if err != nil {
		return nil, fmt.Errorf("cannot read the key file: %w", err)
	}
	return keyPEM, nil
}

// precheck verifies the ledger and checks p against it before the vendor is asked to sign.
// Issue repeats the check under the lock before recording.
func precheck(ledgerPath string, k *issuer.SigningKey, p license.Payload, shorten bool) error {
	l, err := issuer.LockLedger(ledgerPath)
	if err != nil {
		return err
	}
	defer func() { _ = l.Unlock() }()
	entries, err := l.Read(k.Public())
	if err != nil {
		return err
	}
	return issuer.CheckAgainstLedger(entries, p, shorten)
}

// readLicenseFile reads at most one byte more than a license may have; ParseFile refuses it.
func readLicenseFile(path string) ([]byte, error) {
	f, err := os.Open(path) //nolint:gosec // G304: operator-supplied path on the vendor's offline machine
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()
	return io.ReadAll(io.LimitReader(f, license.MaxFileSize+1))
}

// safe returns s for printing to a terminal: unchanged when every character is printable,
// otherwise Go-quoted, so escape sequences in an unsigned file are shown, not executed.
func safe(s string) string {
	for _, r := range s {
		if !strconv.IsPrint(r) {
			return strconv.Quote(s)
		}
	}
	return s
}

func inspect(args []string, stdout, stderr io.Writer) int {
	if len(args) != 1 {
		_, _ = fmt.Fprint(stderr, usage)
		return 2
	}
	raw, err := readLicenseFile(args[0])
	if err != nil {
		_, _ = fmt.Fprintln(stderr, err)
		return 1
	}
	f, err := license.ParseFile(raw)
	var inv *license.InvalidError
	if errors.As(err, &inv) && inv.Problem == license.ProblemNewerFormat {
		_, _ = fmt.Fprintln(stderr, "This license file uses a newer format than this licensectl reads; use a newer licensectl "+
			"(licensectl verify checks its signature).")
		return 1
	}
	if err != nil {
		_, _ = fmt.Fprintln(stderr, "Not a readable license file:", err)
		return 1
	}
	p := f.Payload
	features := make([]string, 0, len(p.Features))
	for _, feat := range p.Features {
		features = append(features, safe(feat))
	}
	rules := "OK"
	if err := p.Validate(); err != nil {
		rules = "NOT VALID (" + err.Error() + ")"
	}
	_, _ = fmt.Fprintf(stdout, "license_id:      %s\ncustomer:        %s\ninstallation_id: %s\nissued_at:       %s\n"+
		"valid_from:      %s\nvalid_until:     %s\nmax_targets:     %d\nfeatures:        %s\nreplaces:        %s\n"+
		"format:          %d\nkey_id:          %s\npayload rules:   %s\nsignature:       not checked (use licensectl verify)\n",
		safe(p.LicenseID), safe(p.Customer), safe(p.InstallationID), p.IssuedAt.Format(time.RFC3339), p.ValidFrom.Format(time.RFC3339),
		p.ValidUntil.Format(time.RFC3339), p.MaxTargets, strings.Join(features, ","), safe(p.Replaces), p.Format, safe(f.KeyID), rules)
	return 0
}

func readPublic(path string, stderr io.Writer) (license.PublicKey, bool) {
	pemBytes, err := os.ReadFile(path) //nolint:gosec // G304: vendor CLI path from its own flags
	if err != nil {
		_, _ = fmt.Fprintln(stderr, err)
		return license.PublicKey{}, false
	}
	pub, err := issuer.ReadPublicKey(pemBytes)
	if err != nil {
		_, _ = fmt.Fprintln(stderr, err)
		return license.PublicKey{}, false
	}
	return pub, true
}

func verify(args []string, stdout, stderr io.Writer) int {
	fs := flags("verify", stderr)
	pubPath := fs.String("pub", "", "public key file")
	if fs.Parse(args) != nil || *pubPath == "" || fs.NArg() != 1 {
		_, _ = fmt.Fprint(stderr, usage)
		return 2
	}
	pub, ok := readPublic(*pubPath, stderr)
	if !ok {
		return 1
	}
	raw, err := readLicenseFile(fs.Arg(0))
	if err != nil {
		_, _ = fmt.Fprintln(stderr, err)
		return 1
	}
	_, err = license.Check(raw, license.NewKeySet(pub))
	if errors.Is(err, license.ErrUnsupportedFormat) {
		// Only a genuine signature gets here (AUD-19); the payload rules of that format are unknown.
		_, _ = fmt.Fprintln(stdout, "SIGNATURE OK, NEWER FORMAT (this licensectl cannot check the rest; use a newer licensectl)")
		return 1
	}
	if err != nil {
		_, _ = fmt.Fprintf(stdout, "SIGNATURE INVALID (%s)\n", license.RejectReason(err))
		return 1
	}
	_, _ = fmt.Fprintln(stdout, "OK")
	return 0
}

func keyset(args []string, stdout, stderr io.Writer) int {
	fs := flags("keyset", stderr)
	pubPath := fs.String("pub", "", "public key file")
	if fs.Parse(args) != nil || *pubPath == "" || fs.NArg() != 0 {
		_, _ = fmt.Fprint(stderr, usage)
		return 2
	}
	pub, ok := readPublic(*pubPath, stderr)
	if !ok {
		return 1
	}
	out, err := license.EncodeKeySet(pub)
	if err != nil {
		_, _ = fmt.Fprintln(stderr, err)
		return 1
	}
	_, _ = fmt.Fprintf(stdout, "%sFingerprint: %s\n", out, license.Fingerprint(pub.Key))
	return 0
}

func ledgerVerify(args []string, stdout, stderr io.Writer) int {
	fs := flags("ledger-verify", stderr)
	pubPath := fs.String("pub", "", "public key file")
	ledger := fs.String("ledger", "", "ledger file; default issued.csv next to the public key")
	if fs.Parse(args) != nil || *pubPath == "" || fs.NArg() != 0 {
		_, _ = fmt.Fprint(stderr, usage)
		return 2
	}
	pub, ok := readPublic(*pubPath, stderr)
	if !ok {
		return 1
	}
	path := *ledger
	if path == "" {
		path = filepath.Join(filepath.Dir(*pubPath), issuer.LedgerFile)
	}
	// A missing ledger is not an empty one: deleting the file must not pass the check.
	if _, err := os.Stat(path); err != nil {
		_, _ = fmt.Fprintf(stderr, "There is no ledger at %s (%v); name it with --ledger.\n", path, err)
		return 1
	}
	head, err := issuer.VerifyLedgerHead(path, pub.Key)
	if err != nil {
		_, _ = fmt.Fprintln(stdout, "LEDGER BROKEN:", err)
		return 1
	}
	noun := "licenses"
	if head.Rows == 1 {
		noun = "license"
	}
	_, _ = fmt.Fprintf(stdout, "Ledger OK: %d %s\nChain head:  %s\n", head.Rows, noun, head.Chain)
	_, _ = fmt.Fprintln(stdout, "Compare the rows and chain head with the ones written down after the last issue.")
	return 0
}
