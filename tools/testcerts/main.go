// Command testcerts writes the owner's certificate test pack: a CA, a good
// certificate/key pair (PEM and PFX) and a broken pair whose key belongs to
// another certificate. Everything is generated on the spot; nothing is
// committed anywhere.
package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"

	"alice/internal/testutil/pki"
)

const pfxPassword = "alice-test"

func main() {
	if err := run(os.Args[1:], os.Stdout); err != nil {
		fmt.Fprintln(os.Stderr, "testcerts:", err)
		os.Exit(1)
	}
}

func run(args []string, stdout io.Writer) error {
	fs := flag.NewFlagSet("testcerts", flag.ContinueOnError)
	out := fs.String("out", "", "directory to create for the test pack (must not exist)")
	name := fs.String("name", "", "host name the certificates are issued for")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *out == "" || *name == "" {
		return errors.New("both -out and -name are required")
	}
	if err := os.Mkdir(*out, 0o700); err != nil {
		return fmt.Errorf("create %s: %w", *out, err)
	}
	now := time.Now() //nolint:forbidigo // a developer tool, not product code
	ca := pki.NewCA("Alice Test Pack", pki.ECDSA256, now)
	good := ca.Issue(pki.Opts{CommonName: *name, SANs: []string{*name}}, now)
	other := ca.Issue(pki.Opts{CommonName: *name, SANs: []string{*name}}, now)
	chain := func(l pki.Leaf) []byte {
		return append(append([]byte{}, l.FullchainPEM...), ca.RootPEM...)
	}
	files := []struct {
		name string
		data []byte
		note string
	}{
		{"ca.pem", ca.RootPEM, "the test root (not trusted by anything)"},
		{"good.pem", chain(good), "leaf, intermediate and root"},
		{"good.key", good.KeyPEM, "the matching private key"},
		{"good.pfx", pki.PFX(good, ca, pfxPassword), "the same pair as PFX, password " + pfxPassword},
		{"broken.pem", chain(other), "a certificate whose key is not good.key"},
		{"broken.key", good.KeyPEM, "good.key again: it does not match broken.pem"},
	}
	for _, f := range files {
		p := filepath.Join(*out, f.name)
		if err := os.WriteFile(p, f.data, 0o600); err != nil {
			return fmt.Errorf("write %s: %w", p, err)
		}
		if _, err := fmt.Fprintf(stdout, "%s  %s\n", p, f.note); err != nil {
			return err
		}
	}
	return nil
}
