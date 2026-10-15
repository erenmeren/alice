package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/jackc/pgx/v5/pgxpool"

	"alice/internal/license/issuer"
	"alice/internal/platform/clock"
	"alice/internal/platform/db"
	"alice/internal/vconsole/audit"
	"alice/internal/vconsole/issue"
	"alice/internal/vconsole/migrations"
	"alice/internal/vconsole/sign"
	"alice/internal/vconsole/store"
)

// prompter asks for a passphrase (no echo on a terminal; injected by tests).
type prompter func(prompt string) ([]byte, error)

const usage = `Usage: vendor-console <command> [flags]

The database is named by the environment variable VENDOR_DATABASE_URL.

Commands:
  migrate
        Create or update the database schema.
  customer add --name NAME [--contact C] [--notes N]
  request add --customer ID --installation ID --targets N
        [--from YYYY-MM-DD] [--months 12] [--features a,b] [--replaces LICENSE-ID]
  request list [--status open]
  request show ID
        Print a request and its hash (the last line).
  issue --request ID --hash HASH --key FILE --out FILE [--license-id ID] [--shorten]
        Sign the request. The hash must be the one "request show" printed; if the
        request changed since, nothing is signed. Asks for the key passphrase.
  audit-verify
        Check the audit chain.
`

const dbEnv = "VENDOR_DATABASE_URL"

func run(args []string, getenv func(string) string, stdout, stderr io.Writer, ask prompter, clk clock.Clock) int {
	if len(args) == 0 {
		_, _ = fmt.Fprint(stderr, usage)
		return 2
	}
	c := &cli{getenv: getenv, out: stdout, err: stderr, ask: ask, clk: clk}
	switch args[0] {
	case "migrate":
		return c.migrate()
	case "customer":
		if len(args) >= 2 && args[1] == "add" {
			return c.customerAdd(args[2:])
		}
	case "request":
		if len(args) >= 2 {
			switch args[1] {
			case "add":
				return c.requestAdd(args[2:])
			case "list":
				return c.requestList(args[2:])
			case "show":
				return c.requestShow(args[2:])
			}
		}
	case "issue":
		return c.issue(args[1:])
	case "audit-verify":
		return c.auditVerify()
	}
	_, _ = fmt.Fprintf(stderr, "vendor-console: unknown command %q\n\n%s", strings.Join(args, " "), usage)
	return 2
}

type cli struct {
	getenv   func(string) string
	out, err io.Writer
	ask      prompter
	clk      clock.Clock
}

func (c *cli) fail(err error) int {
	_, _ = fmt.Fprintf(c.err, "vendor-console: %v\n", err)
	return 1
}

// connect opens the pool. Errors never include the connection string (db.Open guarantees it).
func (c *cli) connect(ctx context.Context) (*pgxpool.Pool, error) {
	url := c.getenv(dbEnv)
	if url == "" {
		return nil, errors.New("set " + dbEnv + " to the PostgreSQL connection string")
	}
	return db.Open(ctx, url)
}

func (c *cli) flags(name string) *flag.FlagSet {
	fs := flag.NewFlagSet(name, flag.ContinueOnError)
	fs.SetOutput(c.err)
	return fs
}

func (c *cli) migrate() int {
	ctx := context.Background()
	pool, err := c.connect(ctx)
	if err != nil {
		return c.fail(err)
	}
	defer pool.Close()
	if err := db.Migrate(ctx, pool, migrations.FS); err != nil {
		return c.fail(err)
	}
	_, _ = fmt.Fprintln(c.out, "migrations applied")
	return 0
}

func (c *cli) customerAdd(args []string) int {
	fs := c.flags("customer add")
	name := fs.String("name", "", "customer name")
	contact := fs.String("contact", "", "contact")
	notes := fs.String("notes", "", "notes")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if strings.TrimSpace(*name) == "" {
		_, _ = fmt.Fprintln(c.err, "vendor-console: --name is required")
		return 2
	}
	ctx := context.Background()
	pool, err := c.connect(ctx)
	if err != nil {
		return c.fail(err)
	}
	defer pool.Close()
	id, err := store.AddCustomer(ctx, pool, store.NewCustomer{Name: *name, Contact: *contact, Notes: *notes})
	if err != nil {
		return c.fail(err)
	}
	_, _ = fmt.Fprintf(c.out, "customer %d\n", id)
	return 0
}

func (c *cli) requestAdd(args []string) int {
	fs := c.flags("request add")
	customer := fs.Int64("customer", 0, "customer ID")
	installation := fs.String("installation", "", "installation ID")
	targets := fs.Int("targets", 0, "number of targets")
	from := fs.String("from", "", "start date")
	months := fs.Int("months", 0, "term in months (default 12)")
	features := fs.String("features", "", "comma separated features")
	replaces := fs.String("replaces", "", "license ID this one corrects")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if *customer == 0 || *installation == "" || *targets == 0 {
		_, _ = fmt.Fprintln(c.err, "vendor-console: --customer, --installation and --targets are required")
		return 2
	}
	ctx := context.Background()
	pool, err := c.connect(ctx)
	if err != nil {
		return c.fail(err)
	}
	defer pool.Close()
	var feats []string
	if *features != "" {
		feats = strings.Split(*features, ",")
	}
	id, err := store.AddRequest(ctx, pool, store.NewRequest{CustomerID: *customer, Installation: *installation,
		Targets: *targets, From: *from, Months: *months, Features: feats, Replaces: *replaces}, c.clk.Now())
	if err != nil {
		return c.fail(err)
	}
	_, _ = fmt.Fprintf(c.out, "request %d\n", id)
	return 0
}

func (c *cli) requestList(args []string) int {
	fs := c.flags("request list")
	status := fs.String("status", "", "only requests with this status")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	ctx := context.Background()
	pool, err := c.connect(ctx)
	if err != nil {
		return c.fail(err)
	}
	defer pool.Close()
	list, err := store.ListRequests(ctx, pool, *status)
	if err != nil {
		return c.fail(err)
	}
	for _, r := range list {
		_, _ = fmt.Fprintf(c.out, "%d  %s  %s  %d  %s\n", r.ID, r.Status, r.Customer, r.Targets, r.Installation)
	}
	return 0
}

func (c *cli) requestShow(args []string) int {
	var id int64
	if len(args) != 1 {
		_, _ = fmt.Fprintln(c.err, "vendor-console: request show needs one request ID")
		return 2
	}
	if _, err := fmt.Sscanf(args[0], "%d", &id); err != nil {
		_, _ = fmt.Fprintf(c.err, "vendor-console: %q is not a request ID\n", args[0])
		return 2
	}
	ctx := context.Background()
	pool, err := c.connect(ctx)
	if err != nil {
		return c.fail(err)
	}
	defer pool.Close()
	r, err := store.GetRequest(ctx, pool, id)
	if err != nil {
		return c.fail(err)
	}
	from := r.From
	if from == "" {
		from = "(the day it is signed)"
	}
	_, _ = fmt.Fprintf(c.out, "request       %d\nstatus        %s\ncustomer      %s\ninstallation  %s\ntargets       %d\nfrom          %s\nmonths        %d\nfeatures      %s\nreplaces      %s\nrequested by  %s\nhash %s\n",
		r.ID, r.Status, r.Customer, r.Installation, r.Targets, from, r.Months, strings.Join(r.Features, ","), r.Replaces,
		r.RequestedBy, store.RequestHash(r))
	return 0
}

func (c *cli) issue(args []string) int {
	fs := c.flags("issue")
	request := fs.Int64("request", 0, "request ID")
	hash := fs.String("hash", "", "request hash from request show")
	keyPath := fs.String("key", "", "license signing key file")
	outPath := fs.String("out", "", "where to write the license file")
	licenseID := fs.String("license-id", "", "license ID (default: generated)")
	shorten := fs.Bool("shorten", false, "allow a correction to end earlier than the license it replaces")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	for _, f := range []struct {
		name    string
		missing bool
	}{{"--request", *request == 0}, {"--hash", *hash == ""}, {"--key", *keyPath == ""}, {"--out", *outPath == ""}} {
		if f.missing {
			_, _ = fmt.Fprintf(c.err, "vendor-console: %s is required\n", f.name)
			return 2
		}
	}
	// Refuse before issuing: a recorded license whose file cannot be written would be awkward to hand over.
	if _, err := os.Lstat(*outPath); err == nil {
		return c.fail(fmt.Errorf("%s exists; choose another --out", *outPath))
	}
	ctx := context.Background()
	pool, err := c.connect(ctx)
	if err != nil {
		return c.fail(err)
	}
	defer pool.Close()
	pem, err := os.ReadFile(*keyPath)
	if err != nil {
		return c.fail(fmt.Errorf("read the key file: %w", err))
	}
	pass, err := c.ask("Key passphrase: ")
	if err != nil {
		return c.fail(err)
	}
	key, err := issuer.OpenKey(pem, pass)
	clear(pass)
	if err != nil {
		return c.fail(err)
	}
	defer key.Zero()
	res, err := issue.Issue(ctx, pool, sign.NewFileSigner(key),
		issue.Params{RequestID: *request, ExpectedHash: *hash, LicenseID: *licenseID, Shorten: *shorten}, c.clk.Now())
	if err != nil {
		return c.fail(err)
	}
	if err := issuer.WriteNew(*outPath, res.File, 0o600); err != nil {
		return c.fail(fmt.Errorf("license %s is recorded but its file could not be written: %w", res.LicenseID, err))
	}
	_, _ = fmt.Fprintf(c.out, "issued %s valid until %s\n", res.LicenseID, res.ValidUntil.Format("2006-01-02"))
	return 0
}

func (c *cli) auditVerify() int {
	ctx := context.Background()
	pool, err := c.connect(ctx)
	if err != nil {
		return c.fail(err)
	}
	defer pool.Close()
	n, err := audit.Verify(ctx, pool)
	if err != nil {
		return c.fail(err)
	}
	if n != 0 {
		_, _ = fmt.Fprintf(c.out, "audit chain BROKEN at sequence %d\n", n)
		return 1
	}
	_, _ = fmt.Fprintln(c.out, "audit chain OK")
	return 0
}
