package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"

	"alice/internal/license/issuer"
	"alice/internal/platform/clock"
	"alice/internal/platform/db"
	"alice/internal/vconsole/issue"
	"alice/internal/vconsole/migrations"
	"alice/internal/vconsole/sign"
	"alice/internal/vconsole/store"
	"alice/internal/vconsole/webuser"
)

// prompter asks for a passphrase (no echo on a terminal; injected by tests).
type prompter func(prompt string) ([]byte, error)

// secretPrompter is a prompter that gives up when ctx ends (the YubiKey PIN, inside the signer's
// time limit).
type secretPrompter func(ctx context.Context, prompt string) ([]byte, error)

// console is the interactive side of a command: the answers to questions (standard input) and
// the PIN prompt.
type console struct {
	in     io.Reader
	secret secretPrompter
}

// withContext makes a secretPrompter of ask: ask runs in a goroutine and, when ctx ends first,
// is left to finish on its own (its answer is zeroed and dropped) while ctx.Err() is returned.
func withContext(ask prompter) secretPrompter {
	return func(ctx context.Context, prompt string) ([]byte, error) {
		if ask == nil {
			return nil, errors.New("no way to ask for the PIN")
		}
		type answer struct {
			p   []byte
			err error
		}
		read := make(chan answer, 1)
		go func() {
			p, err := ask(prompt)
			read <- answer{p, err}
		}()
		select {
		case a := <-read:
			return a.p, a.err
		case <-ctx.Done():
			go func() { a := <-read; clear(a.p) }()
			return nil, ctx.Err()
		}
	}
}

const usage = `Usage: vendor-console <command> [flags]

The database is named by the environment variable VENDOR_DATABASE_URL. Use your own login, and
sslmode=verify-full unless the database is on this computer.

Commands:
  migrate
        Create or update the database schema.
  customer add --name NAME [--contact C] [--notes N]
  request add --customer ID --installation ID --targets N
        [--from YYYY-MM-DD] [--months 12] [--features a,b] [--replaces LICENSE-ID]
  request list [--status open]
  request show ID
        Print a request and its hash (the last line).
  request cancel ID
        Close an open request (a sales login may cancel only its own).
  license export --id LICENSE-ID --out FILE
        Write an issued license file again, byte for byte.
  issue --request ID --hash HASH --out FILE [--license-id ID] [--shorten] [--signer file|openpgp] ...
        Sign the request. The hash must be the one "request show" printed; if the
        request changed since, nothing is signed.
        --signer file (default): --key FILE; asks for the key passphrase.
        --signer openpgp (a YubiKey; builds with -tags yubikey only): --key-id ID and
        (--pub FILE | --keyset FILE) name the key the card must hold; [--reader NAME]
        [--last-pin-try] [--allow-no-touch] [--yes] [--not-in-key-set]. Prints every field of the
        license and the SHA-256 of the signed bytes, asks "Sign this license? [y/N]" (--yes skips
        only the question), then the PIN (never retried) and a touch. --not-in-key-set is needed
        while this build's key set does not list the key ID (customers' builds will not accept
        the license until a release with the key ships).
  signer info [--reader NAME] [--key-id ID [--pub FILE | --keyset FILE]] [--out FILE]
        Show the YubiKey: serial, algorithm, PIN tries and policy, touch policy, signature
        counter, public key and fingerprint; with --key-id whether it matches (exit 1 when the
        card does not hold that key). --out writes the card's public key as a public key file
        (needs --key-id). No PIN.
  signer test --key-id ID (--pub FILE | --keyset FILE) [--reader NAME] [--max-size]
        Sign the fixed text "alice-vendor-console smoke test: not a license" (with --max-size a
        600-byte text starting with it) after the PIN and a touch, and verify the signature.
        The text is not a license and the product cannot accept it.
  license revoke --id LICENSE-ID --reason TEXT
        Mark a license revoked in the vendor records (reminders and lists stop; the customer's
        installation is not affected). The reason goes into the audit. Owner login only.
  verify-licenses (--pub FILE [--pub FILE ...] | --keyset FILE)
        Check every stored license file against the public keys (after a restore, or any time):
        file hash, signature and that the row agrees with the signed file. Prints
        "checked N, problems M" and one line per problem; exit 1 when there are problems.
  audit-verify [--head SEQ:HASH]
        Check the audit chain. With --head (the "Audit head" line of a weekly summary mail),
        also check that the rows up to that checkpoint are still there.
  audit-head
        Print the newest audit row as SEQ:HASH ("empty" for an empty log), to keep elsewhere.
  audit show [--since YYYY-MM-DD] [--actor NAME] [--action PREFIX] [--limit 50] [--details]
        Print audit rows, newest first: sequence, time (UTC), actor, action, subject. --limit is
        at most 1000. --details adds each row's details (installation IDs replaced by inst#<fingerprint>). Owner login only.
  web-user add NAME
        Create a person for the sales web page and print their one-time enrollment code
        (valid 24 hours; shown only once). Owner login only.
  web-user invite NAME
        Print a new enrollment code (a new passkey for someone who lost theirs).
  web-user disable NAME
        Lock the person out and end their sessions.
  web-user enable NAME
  web-user list
  web-user set-email NAME EMAIL
        The address reminders for this person's requests go to ("" removes it). Owner login only.
  settings set KEY VALUE
        Owner login only. Keys: owner_email (where issuance mails, reminders and the weekly
        summary go) and timezone (IANA name for the summary, default Europe/Istanbul).
  settings show
  notify run [--base-url URL] [--dry-run]
        Create due expiry reminders and the weekly summary, then send every pending mail.
        Meant for a timer; needs a login in vendor_notifier. The SMTP server is named by
        VENDOR_SMTP_ADDR (host:port), VENDOR_SMTP_FROM, and VENDOR_SMTP_USER with
        VENDOR_SMTP_PASSWORD if it needs a login (STARTTLS or port 465 required). --base-url
        is the sales web page, for the Renew link. --dry-run prints the counts and changes nothing.
  notify failed
        List the mails that could not be sent (owner or notifier login).
  notify retry ID
        Send a failed mail again on the next notify run (fresh attempt count). Notifier login only.
`

const dbEnv = "VENDOR_DATABASE_URL"

// run is runWith with no standard input (every question is answered no) and ask as the PIN
// prompt.
func run(args []string, getenv func(string) string, stdout, stderr io.Writer, ask prompter, clk clock.Clock) int {
	return runWith(args, getenv, stdout, stderr, ask, clk, console{in: strings.NewReader(""), secret: withContext(ask)})
}

func runWith(args []string, getenv func(string) string, stdout, stderr io.Writer, ask prompter, clk clock.Clock, con console) int {
	if len(args) == 0 {
		_, _ = fmt.Fprint(stderr, usage)
		return 2
	}
	c := &cli{getenv: getenv, out: stdout, err: stderr, ask: ask, clk: clk, con: con}
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
			case "cancel":
				return c.requestCancel(args[2:])
			}
		}
	case "license":
		if len(args) >= 2 {
			switch args[1] {
			case "export":
				return c.licenseExport(args[2:])
			case "revoke":
				return c.licenseRevoke(args[2:])
			}
		}
	case "verify-licenses":
		return c.verifyLicenses(args[1:])
	case "issue":
		return c.issue(args[1:])
	case "signer":
		if len(args) >= 2 {
			switch args[1] {
			case "info":
				return c.signerInfo(args[2:])
			case "test":
				return c.signerTest(args[2:])
			}
		}
	case "audit-verify":
		return c.auditVerify(args[1:])
	case "audit-head":
		return c.auditHead(args[1:])
	case "audit":
		return c.auditCmd(args[1:])
	case "web-user":
		if len(args) >= 2 {
			switch args[1] {
			case "add", "invite", "disable", "enable":
				return c.webUser(args[1], args[2:])
			case "list":
				return c.webUserList()
			case "set-email":
				return c.webUserSetEmail(args[2:])
			}
		}
	case "settings":
		return c.settings(args[1:])
	case "notify":
		if len(args) >= 2 {
			switch args[1] {
			case "run":
				return c.notifyRun(args[2:])
			case "failed":
				return c.notifyFailed(args[2:])
			case "retry":
				return c.notifyRetry(args[2:])
			}
		}
	}
	return c.unknown(args)
}

func (c *cli) unknown(args []string) int {
	_, _ = fmt.Fprintf(c.err, "vendor-console: unknown command %q\n\n%s", strings.Join(args, " "), usage)
	return 2
}

type cli struct {
	getenv   func(string) string
	out, err io.Writer
	ask      prompter
	clk      clock.Clock
	con      console
}

func (c *cli) fail(err error) int {
	_, _ = fmt.Fprintf(c.err, "vendor-console: %v\n", err)
	return 1
}

// connectTimeout bounds how long a command waits for the database.
var connectTimeout = 20 * time.Second

// connect opens the pool. Errors never include the connection string (db.Open guarantees it).
func (c *cli) connect(ctx context.Context) (*pgxpool.Pool, error) {
	url := c.getenv(dbEnv)
	if url == "" {
		return nil, errors.New("set " + dbEnv + " to the PostgreSQL connection string")
	}
	if err := store.RequireTLSVerification(url, dbEnv); err != nil {
		return nil, err
	}
	ctx, cancel := context.WithTimeout(ctx, connectTimeout)
	defer cancel()
	pool, err := db.Open(ctx, url)
	if err != nil {
		if ctx.Err() != nil {
			return nil, fmt.Errorf("could not reach the database within %s", connectTimeout)
		}
		return nil, err
	}
	return pool, nil
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
	keyPath := fs.String("key", "", "license signing key file (--signer file)")
	outPath := fs.String("out", "", "where to write the license file")
	licenseID := fs.String("license-id", "", "license ID (default: generated)")
	shorten := fs.Bool("shorten", false, "allow a correction to end earlier than the license it replaces")
	signer := fs.String("signer", "file", "file or openpgp (a YubiKey)")
	var o openPGPIssue
	fs.StringVar(&o.keyID, "key-id", "", "key ID of the card's key (--signer openpgp)")
	fs.StringVar(&o.pub, "pub", "", "public key file of that key ID (--signer openpgp)")
	fs.StringVar(&o.keyset, "keyset", "", "key set file holding that key ID (--signer openpgp)")
	fs.StringVar(&o.reader, "reader", "", "smart card reader name (--signer openpgp; default: the one YubiKey)")
	fs.BoolVar(&o.lastTry, "last-pin-try", false, "allow the PIN prompt when the card has one try left")
	fs.BoolVar(&o.allowNoTouch, "allow-no-touch", false, "allow a card that signs without a touch")
	fs.BoolVar(&o.yes, "yes", false, "do not ask before signing (the license is still shown)")
	fs.BoolVar(&o.notInKeySet, "not-in-key-set", false, "sign although this build's key set does not list the key ID")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if fs.NArg() != 0 {
		return c.usageErr("issue takes no arguments besides its flags")
	}
	for _, f := range []struct {
		name    string
		missing bool
	}{{"--request", *request == 0}, {"--hash", *hash == ""}, {"--out", *outPath == ""}} {
		if f.missing {
			return c.usageErr("%s is required", f.name)
		}
	}
	p := issue.Params{RequestID: *request, ExpectedHash: *hash, LicenseID: *licenseID, Shorten: *shorten}
	switch *signer {
	case "file":
		var cardFlags []string
		fs.Visit(func(f *flag.Flag) {
			switch f.Name {
			case "key-id", "pub", "keyset", "reader", "last-pin-try", "allow-no-touch", "yes", "not-in-key-set":
				cardFlags = append(cardFlags, "--"+f.Name)
			}
		})
		if len(cardFlags) > 0 {
			return c.usageErr("%s belong to --signer openpgp", strings.Join(cardFlags, ", "))
		}
		if *keyPath == "" {
			return c.usageErr("--key is required")
		}
		return c.issueFile(p, *keyPath, *outPath)
	case "openpgp":
		if *keyPath != "" {
			return c.usageErr("--key belongs to --signer file; a YubiKey is named by --key-id and --pub or --keyset")
		}
		if o.keyID == "" {
			return c.usageErr("--signer openpgp needs --key-id")
		}
		if (o.pub == "") == (o.keyset == "") {
			return c.usageErr("--signer openpgp needs --pub FILE or --keyset FILE (one of them) for the key ID")
		}
		o.params, o.out = p, *outPath
		return c.issueOpenPGP(o)
	default:
		return c.usageErr("--signer is file or openpgp, not %q", *signer)
	}
}

// output is the reserved license output file: created first, so a path that cannot be written is
// found before anything is signed and an existing file is never overwritten. discard removes the
// reservation unless the license was written.
type output struct {
	f       *os.File
	path    string
	written bool
}

func reserveOutput(path string) (*output, error) {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600) //nolint:gosec // G304: the operator names the file
	if err != nil {
		return nil, fmt.Errorf("cannot create the output file: %w", err)
	}
	return &output{f: f, path: path}, nil
}

func (o *output) discard() {
	_ = o.f.Close()
	if !o.written {
		_ = os.Remove(o.path)
	}
}

// deliver writes the issued license to the reserved file and reports it.
func (c *cli) deliver(o *output, res issue.Result) int {
	if _, err := o.f.Write(res.File); err != nil {
		return c.fail(fmt.Errorf("license %s is recorded but its file could not be written (%w); get it again with: license export --id %s --out FILE",
			res.LicenseID, err, res.LicenseID))
	}
	if err := o.f.Close(); err != nil {
		return c.fail(fmt.Errorf("license %s is recorded but its file could not be written (%w); get it again with: license export --id %s --out FILE",
			res.LicenseID, err, res.LicenseID))
	}
	o.written = true
	_, _ = fmt.Fprintf(c.out, "issued %s valid until %s\n", res.LicenseID, res.ValidUntil.Format("2006-01-02"))
	return 0
}

// issueFile signs with the passphrase-protected key file.
func (c *cli) issueFile(p issue.Params, keyPath, outPath string) int {
	out, err := reserveOutput(outPath)
	if err != nil {
		return c.fail(err)
	}
	defer out.discard()
	ctx := context.Background()
	pool, err := c.connect(ctx)
	if err != nil {
		return c.fail(err)
	}
	defer pool.Close()
	pem, err := os.ReadFile(keyPath)
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
	res, err := issue.Issue(ctx, pool, sign.NewFileSigner(key), p, c.clk.Now())
	if err != nil {
		return c.fail(err)
	}
	return c.deliver(out, res)
}

func (c *cli) requestCancel(args []string) int {
	var id int64
	if len(args) != 1 {
		_, _ = fmt.Fprintln(c.err, "vendor-console: request cancel needs one request ID")
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
	if err := store.CancelRequest(ctx, pool, id); err != nil {
		return c.fail(err)
	}
	_, _ = fmt.Fprintf(c.out, "request %d cancelled\n", id)
	return 0
}

func (c *cli) licenseExport(args []string) int {
	fs := c.flags("license export")
	id := fs.String("id", "", "license ID")
	outPath := fs.String("out", "", "where to write the license file")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if *id == "" || *outPath == "" {
		_, _ = fmt.Fprintln(c.err, "vendor-console: --id and --out are required")
		return 2
	}
	ctx := context.Background()
	pool, err := c.connect(ctx)
	if err != nil {
		return c.fail(err)
	}
	defer pool.Close()
	raw, err := store.LicenseFile(ctx, pool, *id)
	if err != nil {
		return c.fail(err)
	}
	if err := issuer.WriteNew(*outPath, raw, 0o600); err != nil {
		return c.fail(err)
	}
	_, _ = fmt.Fprintf(c.out, "wrote %s\n", *outPath)
	return 0
}

// enrollmentTTL is how long a web-user enrollment code stays valid.
const enrollmentTTL = 24 * time.Hour

// webUserErr words a database refusal for the web-user commands, which are for the owner login only.
func (c *cli) webUserErr(err error) int {
	var pe *pgconn.PgError
	if errors.As(err, &pe) && pe.Code == "42501" { // insufficient_privilege
		return c.fail(errors.New("permission denied: the web-user commands need the owner login"))
	}
	return c.fail(err)
}

func (c *cli) webUser(sub string, args []string) int {
	if len(args) != 1 || strings.TrimSpace(args[0]) == "" {
		_, _ = fmt.Fprintf(c.err, "vendor-console: web-user %s needs one NAME\n", sub)
		return 2
	}
	name := args[0]
	ctx := context.Background()
	pool, err := c.connect(ctx)
	if err != nil {
		return c.fail(err)
	}
	defer pool.Close()
	now := c.clk.Now()
	// One transaction each: a user without their code, or a disabled user whose sessions live on, never persists.
	tx, err := pool.Begin(ctx)
	if err != nil {
		return c.fail(err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	var code string
	switch sub {
	case "add":
		id, err := webuser.AddUser(ctx, tx, name)
		if err != nil {
			return c.webUserErr(err)
		}
		if code, err = webuser.NewEnrollment(ctx, tx, id, now, enrollmentTTL); err != nil {
			return c.webUserErr(err)
		}
	case "invite":
		u, err := webuser.GetUserByName(ctx, tx, name)
		if err != nil {
			return c.webUserErr(err)
		}
		// A disabled user could not use the code: LookupEnrollment refuses disabled users.
		if u.Disabled {
			_, _ = fmt.Fprintf(c.err, "vendor-console: %s is disabled; enable it first\n", u.Name)
			return 1
		}
		if code, err = webuser.NewEnrollment(ctx, tx, u.ID, now, enrollmentTTL); err != nil {
			return c.webUserErr(err)
		}
	case "disable", "enable":
		if err := webuser.SetDisabled(ctx, tx, name, sub == "disable", now); err != nil {
			return c.webUserErr(err)
		}
	}
	if err := tx.Commit(ctx); err != nil {
		return c.webUserErr(err)
	}
	if code != "" {
		_, _ = fmt.Fprintf(c.out, "enrollment code for %s (shown once, expires %s):\n%s\n", name,
			now.Add(enrollmentTTL).UTC().Format("2006-01-02 15:04 MST"), code)
	} else {
		_, _ = fmt.Fprintf(c.out, "%s %sd\n", name, sub)
	}
	return 0
}

func (c *cli) webUserList() int {
	ctx := context.Background()
	pool, err := c.connect(ctx)
	if err != nil {
		return c.fail(err)
	}
	defer pool.Close()
	users, err := webuser.ListUsers(ctx, pool)
	if err != nil {
		return c.webUserErr(err)
	}
	for _, u := range users {
		if u.Disabled {
			_, _ = fmt.Fprintf(c.out, "%s  disabled\n", u.Name)
		} else {
			_, _ = fmt.Fprintf(c.out, "%s\n", u.Name)
		}
	}
	return 0
}
