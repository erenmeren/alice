package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"sort"
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

// installationSymbols is the number of symbols in an installation ID (15 random and one check
// symbol, internal/license installationIDLen).
const installationSymbols = 16

// isIDSymbol reports a byte license.ParseInstallationID reads as a symbol: a digit or an ASCII
// letter in either case, except U (Crockford base32 with O, I and L as typing variants).
func isIDSymbol(c byte) bool {
	switch {
	case c >= '0' && c <= '9':
		return true
	case c >= 'a' && c <= 'z':
		return c != 'u'
	case c >= 'A' && c <= 'Z':
		return c != 'U'
	}
	return false
}

// isIDSeparator reports a byte ParseInstallationID skips between symbols, anywhere and any number
// of times: only '-' and ' '.
func isIDSeparator(c byte) bool { return c == '-' || c == ' ' }

func isHex(c byte) bool { return c >= '0' && c <= '9' || c >= 'a' && c <= 'f' || c >= 'A' && c <= 'F' }

// hexRunMin is the shortest unbroken hex run treated as a hash (a sha256 is 64): a window inside
// one is not taken for an installation ID, which it matches by chance once in 32. Accepted
// residual: a real ID whose 16 symbols are all hex digits, written without separators and padded
// with hex to an unbroken run of 32 or more, is not redacted (half the symbols of a random ID are
// hex, so all 16 being hex happens about once in 65 000 IDs, and the padding has to be deliberate).
const hexRunMin = 32

// longHexRuns numbers the unbroken hex runs of at least hexRunMin bytes in one pass: the result
// holds, per byte, the run's number (from 1), or 0 outside such runs; nil when there is none. A
// window lies inside one run exactly when its first and last byte carry the same non-zero
// number, so the check per window is O(1) and the scan stays linear in len(s).
func longHexRuns(s string) []int32 {
	var ids []int32
	var n int32
	for p := 0; p < len(s); {
		if !isHex(s[p]) {
			p++
			continue
		}
		q := p
		for q < len(s) && isHex(s[q]) {
			q++
		}
		if q-p >= hexRunMin {
			if ids == nil {
				ids = make([]int32, len(s))
			}
			n++
			for i := p; i < q; i++ {
				ids[i] = n
			}
		}
		p = q
	}
	return ids
}

// idSpan is the bytes [start, end) that one installation ID found by redactInstallations covers.
type idSpan struct {
	start, end int
	first      int  // byte of the window's first symbol
	anchored   bool // a literal ALICE prefix is part of the span
	canonical  string
}

// findInstallations returns every window of s that ParseInstallationID would accept: 16 symbols
// with only separators between them (any number, any grouping), whose check symbol is right. All
// windows are found, overlapping ones included, so no glue, grouping or neighbouring text can
// hide an ID: in a run of more than 16 symbols every 16-symbol window is tried. A literal "ALICE"
// (any case) directly before a window, with only separators after it, is part of its span, as the
// parser reads it. Windows inside an unbroken hex run of at least hexRunMin are skipped (hashes).
func findInstallations(s string) []idSpan {
	var spans []idSpan
	var run []int // byte positions of the symbols of the current run
	hexRuns := longHexRuns(s)
	flush := func() {
		for i := 0; i+installationSymbols <= len(run); i++ {
			w := run[i : i+installationSymbols]
			if hexRuns != nil && hexRuns[w[0]] != 0 && hexRuns[w[0]] == hexRuns[w[len(w)-1]] {
				continue
			}
			if !luhn32Valid(s, w) {
				continue // cheap pre-check; ParseInstallationID below stays the deciding step
			}
			sym := make([]byte, 0, len("ALICE-")+installationSymbols)
			sym = append(sym, "ALICE-"...) // so a window that itself starts with ALICE is not read as a prefix
			for _, p := range w {
				sym = append(sym, s[p])
			}
			id, err := license.ParseInstallationID(string(sym))
			if err != nil {
				continue
			}
			start := prefixStart(s, w[0])
			spans = append(spans, idSpan{start: start, end: w[len(w)-1] + 1, first: w[0], anchored: start != w[0], canonical: id})
		}
		run = run[:0]
	}
	for p := 0; p < len(s); p++ {
		switch c := s[p]; {
		case isIDSymbol(c):
			run = append(run, p)
		case isIDSeparator(c):
		default:
			flush()
		}
	}
	flush()
	return spans
}

// symbolValues maps a byte to its Crockford base32 value the way license.ParseInstallationID
// decodes it (any case; O as 0, I and L as 1), or -1.
var symbolValues = func() (t [256]int8) {
	for i := range t {
		t[i] = -1
	}
	const crockford = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"
	for v := 0; v < len(crockford); v++ {
		c := crockford[v]
		t[c] = int8(v) //nolint:gosec // G115: v < 32
		if c >= 'A' && c <= 'Z' {
			t[c+('a'-'A')] = int8(v) //nolint:gosec // G115: v < 32
		}
	}
	for _, c := range "Oo" {
		t[c] = 0
	}
	for _, c := range "IiLl" {
		t[c] = 1
	}
	return t
}()

// luhn32Valid is the product's Luhn mod 32 check over the symbols at positions w of s, without
// allocating. It only filters: a window it accepts is confirmed with ParseInstallationID, and a test
// pins that it agrees with the parser, so it can never hide an ID the parser would accept.
func luhn32Valid(s string, w []int) bool {
	factor, sum := 1, 0
	for i := len(w) - 1; i >= 0; i-- {
		addend := factor * int(symbolValues[s[w[i]]])
		sum += addend/32 + addend%32
		factor = 3 - factor
	}
	return sum%32 == 0
}

// prefixStart returns where a literal "ALICE" before the symbol at p starts (only separators may
// lie between), or p when there is none.
func prefixStart(s string, p int) int {
	q := p
	for q > 0 && isIDSeparator(s[q-1]) {
		q--
	}
	if q >= 5 && strings.EqualFold(s[q-5:q], "ALICE") {
		return q - 5
	}
	return p
}

// preferAnchored drops the chance windows around an ALICE-prefixed ID: a window that starts inside
// a literal "ALICE" prefix word (the letters A, L, I, C, E are symbols too), and an unprefixed window
// that overlaps a prefixed ID's span. Those windows hold no symbol of the prefixed ID that its own
// span does not already hide; without this, about one ID in six would print as two fingerprints.
// A canonical ID never contains L or I, so no real ID starts inside the prefix word.
func preferAnchored(s string, spans []idSpan) []idSpan {
	// Anchored spans sorted by start, with the running maximum of their ends: an unanchored span
	// overlaps one of them exactly when, among those starting before its end, the furthest end lies
	// past its start. A binary search keeps the check O(log n) per span.
	var anchored []idSpan
	for _, sp := range spans {
		if sp.anchored {
			anchored = append(anchored, sp)
		}
	}
	sort.Slice(anchored, func(i, j int) bool { return anchored[i].start < anchored[j].start })
	maxEnd := make([]int, len(anchored))
	for i, a := range anchored {
		maxEnd[i] = a.end
		if i > 0 {
			maxEnd[i] = max(maxEnd[i], maxEnd[i-1])
		}
	}
	overlapsAnchored := func(sp idSpan) bool {
		n := sort.Search(len(anchored), func(i int) bool { return anchored[i].start >= sp.end })
		return n > 0 && maxEnd[n-1] > sp.start
	}
	out := spans[:0:0]
	for _, sp := range spans {
		if !sp.anchored && (insidePrefixWord(s, sp.first) || overlapsAnchored(sp)) {
			continue
		}
		out = append(out, sp)
	}
	return out
}

// insidePrefixWord reports whether byte p is one of the letters of a literal "ALICE" (any case)
// that is followed, after separators only, by a symbol: the way the prefix of an ID is written.
func insidePrefixWord(s string, p int) bool {
	for q := max(0, p-4); q <= p; q++ {
		if q+5 > len(s) || !strings.EqualFold(s[q:q+5], "ALICE") {
			continue
		}
		r := q + 5
		for r < len(s) && isIDSeparator(s[r]) {
			r++
		}
		if r < len(s) && isIDSymbol(s[r]) {
			return true
		}
	}
	return false
}

// installationFingerprint stands in for an installation ID in owner output: "inst#" and the first
// 8 hex digits of sha256 of the canonical ID. The same ID always gives the same fingerprint, so
// rows can be correlated, but no part of the ID is shown.
func installationFingerprint(canonical string) string {
	sum := sha256.Sum256([]byte(canonical))
	return "inst#" + hex.EncodeToString(sum[:4])
}

// redactInstallations replaces every installation ID inside s with its fingerprint. Format
// characters (soft hyphen, zero width, bidi) are removed first, so they cannot split an ID past
// the scan. Overlapping finds are merged into one span that shows the fingerprints of all of them
// joined by '+', so no symbol of any accepted window survives. The price is that ordinary text
// which happens to contain a 16-symbol window with a right check symbol (once in 32 windows) is
// redacted too: in owner output, hiding too much is the safe side.
func redactInstallations(s string) string {
	s = strings.Map(func(r rune) rune {
		if unicode.Is(unicode.Cf, r) {
			return -1
		}
		return r
	}, s)
	spans := preferAnchored(s, findInstallations(s))
	if len(spans) == 0 {
		return s
	}
	sort.SliceStable(spans, func(i, j int) bool { return spans[i].start < spans[j].start })
	var b strings.Builder
	last := 0
	for i := 0; i < len(spans); {
		start, end := spans[i].start, spans[i].end
		var fps []string
		seen := map[string]bool{}
		for ; i < len(spans) && spans[i].start < end; i++ {
			end = max(end, spans[i].end)
			if c := spans[i].canonical; !seen[c] {
				seen[c] = true
				fps = append(fps, installationFingerprint(c))
			}
		}
		b.WriteString(s[last:start])
		b.WriteString(strings.Join(fps, "+"))
		last = end
	}
	b.WriteString(s[last:])
	return b.String()
}

// redactDetails rewrites audit details JSON for display: every installation ID in any string value
// or object key, at any depth, becomes its fingerprint. Text that does not parse as JSON is
// redacted as plain text; the caller makes the result terminal-safe either way.
func redactDetails(raw string) string {
	dec := json.NewDecoder(strings.NewReader(raw))
	dec.UseNumber()
	var v any
	if err := dec.Decode(&v); err != nil {
		return redactInstallations(raw)
	}
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(redactValue(v)); err != nil {
		return redactInstallations(raw)
	}
	return strings.TrimSuffix(buf.String(), "\n")
}

func redactValue(v any) any {
	switch x := v.(type) {
	case string:
		return redactInstallations(x)
	case []any:
		for i := range x {
			x[i] = redactValue(x[i])
		}
		return x
	case map[string]any:
		// Keys in sorted order, so when two keys redact to the same text the later one is always the
		// same and gets the suffix (#2, #3, ...) instead of overwriting the first.
		keys := make([]string, 0, len(x))
		for k := range x {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		out := make(map[string]any, len(x))
		for _, k := range keys {
			nk := redactInstallations(k)
			if _, dup := out[nk]; dup {
				for n := 2; ; n++ {
					if _, taken := out[nk+"#"+strconv.Itoa(n)]; !taken {
						nk += "#" + strconv.Itoa(n)
						break
					}
				}
			}
			out[nk] = redactValue(x[k])
		}
		return out
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
		return c.permissionErr(err, "audit-head needs the owner login or a login in vendor_notifier")
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
	details := fs.Bool("details", false, "add each row's details (installation IDs as fingerprints)")
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
			termSafe(redactInstallations(subject)))
		if *details {
			line += " " + termSafe(redactDetails(detailsJSON))
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
	seen := map[string]bool{}
	for _, p := range pubs {
		raw, err := readKeyFile(p)
		if err != nil {
			return license.KeySet{}, fmt.Errorf("read the public key: %w", err)
		}
		k, err := issuer.ReadPublicKey(raw)
		if err != nil {
			return license.KeySet{}, fmt.Errorf("%s: %w", p, err)
		}
		// NewKeySet would let the later file silently replace the earlier one.
		if seen[k.ID] {
			return license.KeySet{}, fmt.Errorf("two --pub files hold key ID %q", k.ID)
		}
		seen[k.ID] = true
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
	if checked == 0 {
		// An empty database may be legitimate; after a restore it is compared with the expected count.
		_, _ = fmt.Fprintln(c.err, "WARNING: no licenses found")
	}
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
		return c.permissionErr(err, "notify retry must be run with a login in vendor_notifier (a retry is not an owner action)")
	}
	_, _ = fmt.Fprintf(c.out, "message %d will be sent by the next notify run\n", id)
	return 0
}
