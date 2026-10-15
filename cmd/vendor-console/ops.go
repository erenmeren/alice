package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"alice/internal/license"
	"alice/internal/license/issuer"
	"alice/internal/vconsole/audit"
	"alice/internal/vconsole/notify"
	"alice/internal/vconsole/store"
)

// Limits of "audit show": enough for an investigation, never an unbounded dump to a terminal.
const (
	auditShowDefault = 50
	auditShowMax     = 1000
	// failedListMax caps "notify failed"; more than this many failed mails is an outage to fix
	// at the mail server, not a list to read.
	failedListMax = 200
	// failedFieldRunes is how much of a failed mail's subject and error is shown.
	failedFieldRunes = 80
	// keyFileMax bounds a public key or key set file read from disk.
	keyFileMax = 1 << 20
)

// termSafe makes a database value safe to print on a terminal: control, format (bidi, zero
// width) and line or paragraph separator characters, and invalid UTF-8, become '?', so a value
// cannot move the cursor, recolour the screen or reorder the line it is shown in.
func termSafe(s string) string {
	var b strings.Builder
	for i := 0; i < len(s); {
		r, size := utf8.DecodeRuneInString(s[i:])
		i += size
		if (r == utf8.RuneError && size <= 1) || unicode.IsControl(r) || unicode.Is(unicode.Cf, r) ||
			r == ' ' || r == ' ' {
			b.WriteByte('?')
			continue
		}
		b.WriteRune(r)
	}
	return b.String()
}

// firstRunes keeps the first n runes of s.
func firstRunes(s string, n int) string {
	if utf8.RuneCountInString(s) <= n {
		return s
	}
	return string([]rune(s)[:n])
}

// shortInstallation returns the installation ID cut to its first 8 symbols ("ALICE-ABCD-EFGH…")
// when s is one, in any spelling license.ParseInstallationID accepts, and ok == false otherwise.
// Only values that start with the ALICE prefix are considered: a customer name or note that
// merely happens to decode is left alone.
func shortInstallation(s string) (string, bool) {
	t := strings.TrimSpace(s)
	if len(t) < 5 || !strings.EqualFold(t[:5], "ALICE") {
		return "", false
	}
	id, err := license.ParseInstallationID(t)
	if err != nil {
		return "", false
	}
	return id[:len("ALICE-ABCD-EFGH")] + "…", true
}

// shortenDetails rewrites audit details JSON for display: every string value that is an
// installation ID is shortened (keys are kept). Anything that does not parse is returned as is;
// the caller makes it terminal-safe either way.
func shortenDetails(raw string) string {
	dec := json.NewDecoder(strings.NewReader(raw))
	dec.UseNumber()
	var v any
	if err := dec.Decode(&v); err != nil {
		return raw
	}
	v = shortenValue(v)
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(v); err != nil {
		return raw
	}
	return strings.TrimSuffix(buf.String(), "\n")
}

func shortenValue(v any) any {
	switch x := v.(type) {
	case string:
		if s, ok := shortInstallation(x); ok {
			return s
		}
		return x
	case []any:
		for i := range x {
			x[i] = shortenValue(x[i])
		}
		return x
	case map[string]any:
		for k := range x {
			x[k] = shortenValue(x[k])
		}
		return x
	}
	return v
}

// permissionErr words a privilege refusal for the command that hit it; other errors pass as they are.
func (c *cli) permissionErr(err error, need string) int {
	if isPermissionDenied(err) {
		return c.fail(errors.New("permission denied: " + need))
	}
	return c.fail(err)
}

// auditHead is "audit-head": the checkpoint to keep outside the database.
func (c *cli) auditHead(args []string) int {
	if len(args) != 0 {
		return c.usageErr("audit-head takes no arguments")
	}
	ctx := context.Background()
	pool, err := c.connect(ctx)
	if err != nil {
		return c.fail(err)
	}
	defer pool.Close()
	h, ok, err := audit.CurrentHead(ctx, pool)
	if err != nil {
		return c.permissionErr(err, "audit-head needs the owner login")
	}
	if !ok {
		_, _ = fmt.Fprintln(c.out, "empty")
		return 0
	}
	_, _ = fmt.Fprintln(c.out, h.String())
	return 0
}

// auditVerify is "audit-verify [--head SEQ:HASH]". With a head it also proves that the rows up
// to that checkpoint are still there; it never prints a hash the caller did not give.
func (c *cli) auditVerify(args []string) int {
	fs := c.flags("audit-verify")
	headStr := fs.String("head", "", "checkpoint <seq>:<hash> kept outside the database (the weekly summary's Audit head line)")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if fs.NArg() != 0 {
		return c.usageErr("audit-verify takes no arguments besides --head")
	}
	var head *audit.Head
	if *headStr != "" {
		h, err := audit.ParseHead(strings.TrimSpace(*headStr))
		if err != nil {
			return c.usageErr("--head: %v", err)
		}
		head = &h
	}
	ctx := context.Background()
	pool, err := c.connect(ctx)
	if err != nil {
		return c.fail(err)
	}
	defer pool.Close()
	n, err := audit.Verify(ctx, pool)
	if err != nil {
		return c.permissionErr(err, "audit-verify needs the owner login")
	}
	if n != 0 {
		_, _ = fmt.Fprintf(c.out, "audit chain BROKEN at sequence %d\n", n)
		return 1
	}
	if head == nil {
		_, _ = fmt.Fprintln(c.out, "audit chain OK")
		return 0
	}
	err = audit.VerifyHead(ctx, pool, *head)
	switch {
	case errors.Is(err, audit.ErrHeadMismatch):
		_, _ = fmt.Fprintf(c.out, "audit checkpoint MISMATCH: row %d is missing or is not the row of checkpoint %s; "+
			"audit rows were removed or replaced after the checkpoint was taken\n", head.Seq, head.String())
		return 1
	case errors.Is(err, audit.ErrBroken):
		// The chain changed between the two checks.
		_, _ = fmt.Fprintln(c.out, "audit chain BROKEN")
		return 1
	case err != nil:
		return c.permissionErr(err, "audit-verify --head needs the owner login")
	}
	_, _ = fmt.Fprintf(c.out, "audit chain OK; checkpoint %d found\n", head.Seq)
	return 0
}

// auditCmd dispatches "audit <sub>".
func (c *cli) auditCmd(args []string) int {
	if len(args) >= 1 && args[0] == "show" {
		return c.auditShow(args[1:])
	}
	return c.unknown(append([]string{"audit"}, args...))
}

// auditShow is "audit show": the owner's read of the audit log, newest first and capped.
func (c *cli) auditShow(args []string) int {
	fs := c.flags("audit show")
	since := fs.String("since", "", "only rows at or after this UTC date (YYYY-MM-DD)")
	actor := fs.String("actor", "", "only rows by this login or web user")
	action := fs.String("action", "", "only actions starting with this text (license., request.add, ...)")
	limit := fs.Int("limit", auditShowDefault, "most rows to show (1..1000)")
	details := fs.Bool("details", false, "add each row's details (installation IDs shortened)")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if fs.NArg() != 0 {
		return c.usageErr("audit show takes no arguments besides its flags")
	}
	if *limit < 1 || *limit > auditShowMax {
		return c.usageErr("--limit must be between 1 and %d", auditShowMax)
	}
	var sinceAt *time.Time
	if *since != "" {
		t, err := time.Parse("2006-01-02", *since)
		if err != nil {
			return c.usageErr("--since: give a date as YYYY-MM-DD")
		}
		sinceAt = &t
	}
	ctx := context.Background()
	pool, err := c.connect(ctx)
	if err != nil {
		return c.fail(err)
	}
	defer pool.Close()
	// starts_with, not LIKE: an action filter with % or _ matches those characters literally.
	rows, err := pool.Query(ctx, `SELECT seq, at, actor, action, subject, details::text FROM audit
		WHERE ($1::timestamptz IS NULL OR at >= $1)
		  AND ($2 = '' OR actor = $2)
		  AND ($3 = '' OR starts_with(action, $3))
		ORDER BY seq DESC LIMIT $4`, sinceAt, *actor, *action, *limit)
	if err != nil {
		return c.permissionErr(err, "audit show needs the owner login")
	}
	defer rows.Close()
	n := 0
	for rows.Next() {
		var (
			seq                            int64
			at                             time.Time
			who, act, subject, detailsJSON string
		)
		if err := rows.Scan(&seq, &at, &who, &act, &subject, &detailsJSON); err != nil {
			return c.fail(fmt.Errorf("read the audit: %w", err))
		}
		line := fmt.Sprintf("%d %s %s %s %s", seq, at.UTC().Format("2006-01-02T15:04:05Z"), termSafe(who), termSafe(act),
			termSafe(subject))
		if *details {
			line += " " + termSafe(shortenDetails(detailsJSON))
		}
		_, _ = fmt.Fprintln(c.out, line)
		n++
	}
	if err := rows.Err(); err != nil {
		return c.permissionErr(err, "audit show needs the owner login")
	}
	if n == 0 {
		_, _ = fmt.Fprintln(c.err, "vendor-console: no audit rows match")
	}
	return 0
}

// pubFlags collects repeated --pub values.
type pubFlags []string

func (p *pubFlags) String() string     { return strings.Join(*p, ",") }
func (p *pubFlags) Set(v string) error { *p = append(*p, v); return nil }

// readKeyFile reads a small key file; the path comes from the operator's own flags.
func readKeyFile(path string) ([]byte, error) {
	f, err := os.Open(path) //nolint:gosec // G304: the operator names the file
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()
	raw, err := io.ReadAll(io.LimitReader(f, keyFileMax+1))
	if err != nil {
		return nil, err
	}
	if len(raw) > keyFileMax {
		return nil, fmt.Errorf("%s is larger than a key file can be", path)
	}
	return raw, nil
}

// loadKeySet builds the key set from public key files (as licensectl reads them) or from a key
// set file in the product's production.json format.
func loadKeySet(pubs []string, keysetPath string) (license.KeySet, error) {
	if keysetPath != "" {
		raw, err := readKeyFile(keysetPath)
		if err != nil {
			return license.KeySet{}, fmt.Errorf("read the key set: %w", err)
		}
		return license.ParseKeySet(raw)
	}
	keys := make([]license.PublicKey, 0, len(pubs))
	for _, p := range pubs {
		raw, err := readKeyFile(p)
		if err != nil {
			return license.KeySet{}, fmt.Errorf("read the public key: %w", err)
		}
		k, err := issuer.ReadPublicKey(raw)
		if err != nil {
			return license.KeySet{}, fmt.Errorf("%s: %w", p, err)
		}
		keys = append(keys, k)
	}
	return license.NewKeySet(keys...), nil
}

// verifyLicenses is "verify-licenses (--pub FILE ... | --keyset FILE)", run after a restore.
func (c *cli) verifyLicenses(args []string) int {
	fs := c.flags("verify-licenses")
	var pubs pubFlags
	fs.Var(&pubs, "pub", "public key file (repeatable)")
	keysetPath := fs.String("keyset", "", "key set file (the product's production.json)")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if fs.NArg() != 0 {
		return c.usageErr("verify-licenses takes no arguments besides its flags")
	}
	if (len(pubs) == 0) == (*keysetPath == "") {
		return c.usageErr("verify-licenses needs --pub FILE (repeatable) or --keyset FILE, not both")
	}
	ks, err := loadKeySet(pubs, *keysetPath)
	if err != nil {
		return c.usageErr("%v", err)
	}
	if ks.Len() == 0 {
		return c.usageErr("the key set has no keys")
	}
	ctx := context.Background()
	pool, err := c.connect(ctx)
	if err != nil {
		return c.fail(err)
	}
	defer pool.Close()
	checked, problems, err := store.VerifyLicenses(ctx, pool, ks, c.clk.Now())
	if err != nil {
		return c.permissionErr(err, "verify-licenses needs a login that can read the license files (owner, signer or sales)")
	}
	_, _ = fmt.Fprintf(c.out, "checked %d, problems %d\n", checked, len(problems))
	for _, p := range problems {
		_, _ = fmt.Fprintf(c.out, "%s: %s\n", termSafe(p.LicenseID), termSafe(p.Problem))
	}
	if len(problems) > 0 {
		return 1
	}
	return 0
}

// licenseRevoke is "license revoke --id ID --reason TEXT" (owner login).
func (c *cli) licenseRevoke(args []string) int {
	fs := c.flags("license revoke")
	id := fs.String("id", "", "license ID")
	reason := fs.String("reason", "", "why (one line, at most 200 characters; goes into the audit)")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if fs.NArg() != 0 {
		return c.usageErr("license revoke takes no arguments besides its flags")
	}
	if strings.TrimSpace(*id) == "" || strings.TrimSpace(*reason) == "" {
		return c.usageErr("--id and --reason are required")
	}
	ctx := context.Background()
	pool, err := c.connect(ctx)
	if err != nil {
		return c.fail(err)
	}
	defer pool.Close()
	shown := termSafe(*id)
	err = store.RevokeLicense(ctx, pool, *id, *reason, c.clk.Now())
	switch {
	case err == nil:
		_, _ = fmt.Fprintf(c.out, "license %s revoked (vendor record only: the customer's installation is not affected)\n", shown)
		return 0
	case errors.Is(err, store.ErrInvalidReason):
		return c.usageErr("--reason: %s", strings.TrimPrefix(err.Error(), "store: "))
	case errors.Is(err, store.ErrNotFound):
		return c.fail(fmt.Errorf("no license %s; nothing changed", shown))
	case errors.Is(err, store.ErrAlreadyRevoked):
		return c.fail(fmt.Errorf("license %s is already revoked; nothing changed", shown))
	}
	return c.permissionErr(err, "license revoke needs the owner login")
}

// notifyFailed is "notify failed": the mails SendPending gave up on.
func (c *cli) notifyFailed(args []string) int {
	if len(args) != 0 {
		return c.usageErr("notify failed takes no arguments")
	}
	ctx := context.Background()
	pool, err := c.connect(ctx)
	if err != nil {
		return c.fail(err)
	}
	defer pool.Close()
	list, err := notify.ListFailed(ctx, pool, failedListMax+1)
	if err != nil {
		return c.permissionErr(err, "notify failed needs the owner login or a login in vendor_notifier")
	}
	if len(list) == 0 {
		_, _ = fmt.Fprintln(c.out, "no failed mail")
		return 0
	}
	more := len(list) > failedListMax
	if more {
		list = list[:failedListMax]
	}
	for _, r := range list {
		_, _ = fmt.Fprintf(c.out, "%d  %s  created %s  attempts %d  subject: %s  error: %s\n", r.ID, termSafe(r.Kind),
			r.CreatedAt.UTC().Format("2006-01-02T15:04:05Z"), r.Attempts,
			termSafe(firstRunes(r.Subject, failedFieldRunes)), termSafe(firstRunes(r.LastError, failedFieldRunes)))
	}
	if more {
		_, _ = fmt.Fprintf(c.out, "(only the first %d are shown)\n", failedListMax)
	}
	return 0
}

// notifyRetry is "notify retry ID" (notifier login): the next notify run sends the mail again.
func (c *cli) notifyRetry(args []string) int {
	if len(args) != 1 {
		return c.usageErr("notify retry needs one message ID (from notify failed)")
	}
	id, err := strconv.ParseInt(args[0], 10, 64)
	if err != nil || id < 1 {
		return c.usageErr("%q is not a message ID", args[0])
	}
	ctx := context.Background()
	pool, err := c.connect(ctx)
	if err != nil {
		return c.fail(err)
	}
	defer pool.Close()
	err = notify.RetryFailed(ctx, pool, id, c.clk.Now())
	if errors.Is(err, notify.ErrNotFailed) {
		return c.fail(fmt.Errorf("message %d is not a failed mail (unknown, pending or sent); nothing changed", id))
	}
	if err != nil {
		return c.permissionErr(err, "notify retry needs a login in vendor_notifier")
	}
	_, _ = fmt.Fprintf(c.out, "message %d will be sent by the next notify run\n", id)
	return 0
}
