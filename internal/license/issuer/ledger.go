package issuer

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/csv"
	"encoding/hex"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"slices"
	"strconv"
	"time"

	"alice/internal/license"
)

const ledgerPrefix = "ALICE-LEDGER-v1\n"

// Ledger errors. ErrLedgerBroken means the file was changed, damaged or signed by another key;
// the others refuse a license that would conflict with what the ledger records.
var (
	ErrLedgerBroken       = errors.New("issuer: the ledger was changed")
	ErrUnknownReplaced    = errors.New("issuer: the license named by --replaces is not in the ledger")
	ErrShortensTerm       = errors.New("issuer: the correction ends earlier than the license it replaces; use --shorten if that is intended")
	ErrReplaceCycle       = errors.New("issuer: the replaced licenses would form a cycle")
	ErrDuplicateLicenseID = errors.New("issuer: a license with this ID was already issued")
)

var ledgerHeader = []string{"license_id", "customer", "installation_id", "issued_at", "valid_from", "valid_until",
	"max_targets", "replaces", "file_sha256", "chain", "signature"}

// Column positions of the chain value and the signature; the entry fields come before them.
const (
	colChain     = 9
	colSignature = 10
)

// LedgerEntry is one issued license (spec §19.2: the vendor's record of who owns what).
type LedgerEntry struct {
	LicenseID      string
	Customer       string
	InstallationID string
	IssuedAt       time.Time
	ValidFrom      time.Time
	ValidUntil     time.Time
	MaxTargets     int
	Replaces       string
	FileSHA256     string
}

func (e LedgerEntry) fields() []string {
	ts := func(t time.Time) string { return t.UTC().Format(time.RFC3339) }
	return []string{e.LicenseID, e.Customer, e.InstallationID, ts(e.IssuedAt), ts(e.ValidFrom), ts(e.ValidUntil),
		strconv.Itoa(e.MaxTargets), e.Replaces, e.FileSHA256}
}

// entryFromFields reads back what fields wrote. It is only called on rows whose signature
// verified, so an error means a bug in the writer, not tampering.
func entryFromFields(f []string) (LedgerEntry, error) {
	var times [3]time.Time
	for i, s := range f[3:6] {
		t, err := time.Parse(time.RFC3339, s)
		if err != nil {
			return LedgerEntry{}, err
		}
		times[i] = t.UTC()
	}
	n, err := strconv.Atoi(f[6])
	if err != nil {
		return LedgerEntry{}, err
	}
	return LedgerEntry{LicenseID: f[0], Customer: f[1], InstallationID: f[2], IssuedAt: times[0], ValidFrom: times[1],
		ValidUntil: times[2], MaxTargets: n, Replaces: f[7], FileSHA256: f[8]}, nil
}

// ledgerChain = SHA-256(previous chain || each field || NUL).
func ledgerChain(prev []byte, fields []string) []byte {
	h := sha256.New()
	h.Write(prev)
	for _, f := range fields {
		h.Write([]byte(f))
		h.Write([]byte{0})
	}
	return h.Sum(nil)
}

// readLedger returns the CSV rows, or nil when the file does not exist yet. Rows of any width
// are returned (ReadLedger reports a wrong width as ErrLedgerBroken); a file that is not CSV
// is ErrLedgerBroken too.
func readLedger(path string) ([][]string, error) {
	f, err := os.Open(path) //nolint:gosec // G304: vendor CLI path from its own flags
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()
	r := csv.NewReader(f)
	r.FieldsPerRecord = -1
	rows, err := r.ReadAll()
	if pe := (*csv.ParseError)(nil); errors.As(err, &pe) {
		return nil, fmt.Errorf("%w: not a CSV file (%w)", ErrLedgerBroken, pe.Err)
	}
	return rows, err
}

// ReadLedger checks every row's chain and signature against pub and returns the entries in
// issuance order. A missing file is an empty ledger.
func ReadLedger(path string, pub ed25519.PublicKey) ([]LedgerEntry, error) {
	if len(pub) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("%w: no valid public key", ErrLedgerBroken)
	}
	entries, _, err := readChain(path, pub)
	return entries, err
}

// readChain is ReadLedger that also returns the last chain value (all zero for no rows).
func readChain(path string, pub ed25519.PublicKey) ([]LedgerEntry, []byte, error) {
	prev := make([]byte, sha256.Size)
	rows, err := readLedger(path)
	if err != nil {
		return nil, nil, fmt.Errorf("read the ledger: %w", err)
	}
	if len(rows) == 0 {
		return nil, prev, nil
	}
	if !slices.Equal(rows[0], ledgerHeader) {
		return nil, nil, fmt.Errorf("%w: the header is not the ledger header", ErrLedgerBroken)
	}
	entries := make([]LedgerEntry, 0, len(rows)-1)
	for i, row := range rows[1:] {
		if len(row) != len(ledgerHeader) {
			return nil, nil, fmt.Errorf("%w: row %d has %d columns", ErrLedgerBroken, i+1, len(row))
		}
		chain := ledgerChain(prev, row[:colChain])
		sig, err := base64.StdEncoding.Strict().DecodeString(row[colSignature])
		if err != nil || hex.EncodeToString(chain) != row[colChain] || !ed25519.Verify(pub, append([]byte(ledgerPrefix), chain...), sig) {
			return nil, nil, fmt.Errorf("%w at row %d (license %s)", ErrLedgerBroken, i+1, row[0])
		}
		e, err := entryFromFields(row[:colChain])
		if err != nil {
			return nil, nil, fmt.Errorf("%w at row %d (license %s): %w", ErrLedgerBroken, i+1, row[0], err)
		}
		entries = append(entries, e)
		prev = chain
	}
	return entries, prev, nil
}

// VerifyLedger checks every row's chain and signature and returns the number of licenses.
func VerifyLedger(path string, pub ed25519.PublicKey) (int, error) {
	entries, err := ReadLedger(path, pub)
	return len(entries), err
}

// AppendLedger appends e after verifying the whole ledger with k's public key, so a changed
// ledger is never extended. Every row carries the chain value and an Ed25519 signature of
// "ALICE-LEDGER-v1\n" || chain, so an edited, removed or reordered row is detected (§16.7).
func AppendLedger(path string, k *SigningKey, e LedgerEntry) error {
	entries, prev, err := readChain(path, k.Public())
	if err != nil {
		return err
	}
	fields := e.fields()
	chain := ledgerChain(prev, fields)
	sig := ed25519.Sign(k.priv, append([]byte(ledgerPrefix), chain...))
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0o600) //nolint:gosec // G304: vendor CLI path from its own flags
	if err != nil {
		return err
	}
	w := csv.NewWriter(f)
	if entries == nil {
		if err := truncateEmpty(f); err != nil {
			_ = f.Close()
			return err
		}
		_ = w.Write(ledgerHeader)
	}
	_ = w.Write(append(fields, hex.EncodeToString(chain), base64.StdEncoding.EncodeToString(sig)))
	w.Flush()
	if err := w.Error(); err != nil {
		_ = f.Close()
		return err
	}
	if err := f.Sync(); err != nil {
		_ = f.Close()
		return err
	}
	return f.Close()
}

// truncateEmpty makes sure a ledger without a header has no content (an empty file or one
// holding only blank lines, which csv skips) before the header is written.
func truncateEmpty(f *os.File) error {
	info, err := f.Stat()
	if err != nil {
		return err
	}
	if info.Size() == 0 {
		return nil
	}
	return f.Truncate(0)
}

// CheckAgainstLedger refuses a license that conflicts with the ledger (R7 corrections): its
// license ID must be new; a correction must name a license in the ledger, may not end earlier
// than that license unless allowShorten, and may not close a cycle of replaced licenses (in
// the server every license of a cycle is superseded, leaving none in force).
func CheckAgainstLedger(entries []LedgerEntry, p license.Payload, allowShorten bool) error {
	byID := make(map[string]LedgerEntry, len(entries))
	for _, e := range entries {
		byID[e.LicenseID] = e
	}
	if _, dup := byID[p.LicenseID]; dup {
		return fmt.Errorf("%w: %s", ErrDuplicateLicenseID, p.LicenseID)
	}
	if p.Replaces == "" {
		return nil
	}
	replaced, ok := byID[p.Replaces]
	if !ok {
		return fmt.Errorf("%w: %s", ErrUnknownReplaced, p.Replaces)
	}
	seen := map[string]bool{}
	for id := p.Replaces; id != "" && !seen[id]; id = byID[id].Replaces {
		if id == p.LicenseID {
			return fmt.Errorf("%w: %s", ErrReplaceCycle, p.LicenseID)
		}
		seen[id] = true
	}
	if p.ValidUntil.Before(replaced.ValidUntil) && !allowShorten {
		return fmt.Errorf("%w (%s ends %s, the correction %s)", ErrShortensTerm, replaced.LicenseID,
			replaced.ValidUntil.Format(time.DateOnly), p.ValidUntil.Format(time.DateOnly))
	}
	return nil
}
