package backup

import (
	"bufio"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"maps"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"

	"alice/internal/audit"
	"alice/internal/backup/dump"
	"alice/internal/backup/format"
	"alice/internal/license"
	"alice/internal/platform/db"
	"alice/internal/platform/settings"
	"alice/internal/secrets"
	"alice/migrations"
)

// RestoreInput is one restore (C8). Passphrase is the raw typed passphrase (never normalised here; secrets does that
// inside Unwrap); when it is nil, AskPassphrase is called once, and only after the file was found to be a backup this
// version can read. Restore clears the passphrase before it returns. Confirm nil means confirmed (the CLI's
// --confirm RESTORE).
type RestoreInput struct {
	Path              string
	Passphrase        []byte
	AskPassphrase     func() ([]byte, error)
	DBOnly            bool
	AcceptBrokenAudit bool
	NoSafetyBackup    bool          // S-17: restore over a live installation that has data but no backup key
	FreeBytes         int64         // S-22: free space measured by the host wrapper; 0 = not checked
	WaitForSessions   time.Duration // M-4: wait for other sessions on the live database (CLI default 150 s; tests 0)
	Confirm           func(m Manifest) bool
	OwnerURL          string // owner role and the live database; the maintenance connection uses database "postgres"

	hook   func(point string) error                                                                           // tests: crash points
	load   func(ctx context.Context, conn *pgx.Conn, dec *dump.Decoder, first dump.Frame) (dump.Stats, error) // tests: dump.Load
	commit func(ctx context.Context, tx pgx.Tx) error                                                         // tests: the swap's COMMIT
}

// RestoreResult is a finished restore: the backup's manifest, the path of the safety backup ("" when none was made),
// and warnings (a dropped TLS pair or time record).
type RestoreResult struct {
	Manifest     Manifest
	SafetyBackup string
	Warnings     []string
}

// ErrNewer means the backup was made by a newer Alice (a newer container format, a newer version in the header, or a
// newer schema in the manifest). Version is the backup's Alice version; "" when the container format itself is newer.
type ErrNewer struct{ Version string }

func (e *ErrNewer) Error() string {
	return "backup: the backup was created by a newer Alice version (" + e.Version + ")"
}

// ErrNotVerified means the staged data failed a check before anything live was touched.
type ErrNotVerified struct{ Reason string }

func (e *ErrNotVerified) Error() string {
	return "backup: the backup could not be verified (" + e.Reason + ")"
}

// ErrAuditBroken means the backup's audit chain is broken at entry Seq (restorable only with AcceptBrokenAudit).
type ErrAuditBroken struct{ Seq int64 }

func (e *ErrAuditBroken) Error() string {
	return "backup: the audit log in the backup is damaged at entry " + strconv.FormatInt(e.Seq, 10)
}

// ErrNoSpace means the free space the host measured is below 2 × the live database size + 1 GiB (S-22).
type ErrNoSpace struct{ Free, Need int64 }

func (e *ErrNoSpace) Error() string {
	return fmt.Sprintf("backup: not enough free disk space for a restore: %d bytes free, %d needed", e.Free, e.Need)
}

// Errors of Restore.
var (
	ErrCancelled      = errors.New("backup: restore cancelled")
	ErrDatabaseInUse  = errors.New("backup: Alice is still connected to the database; stop it first")
	ErrNoSafetyBackup = errors.New("backup: the installation has data but no recovery passphrase, so no safety backup can be made")
	ErrRestoreRunning = errors.New("backup: another restore of this database is running; wait for it to finish")
	ErrSameDirectory  = errors.New("backup: the keys and state directories must be two different directories")
	// ErrUnfinishedStaging means <db>_restore exists without <db> and never reached its swap: it is not verified, so
	// it is neither made live nor dropped; the operator decides.
	ErrUnfinishedStaging = errors.New("backup: an interrupted restore left a database that was never verified and no live database")
)

// The crash points of a restore, in order (tests stop it at each). "cleaned" follows the leftover cleanup; the two
// database renames run in one transaction between "previous" and "renamed".
var restorePoints = []string{"cleaned", "loaded", "verified", "safety-backup", "audited", "staged", "previous", "renamed", "files"}

// Settings keys and fixed names of the restore.
const (
	keyRestoreID      = "backup.restore_id"
	restoreLockKey    = "alice.restore"
	restoreSuffix     = "_restore"
	previousSuffix    = "_previous_"
	maintenanceDB     = "postgres"
	sessionPoll       = 2 * time.Second
	minFreeForRestore = 1 << 30
	// maxDBName keeps "<db>_previous_<yyyymmddThhmmssZ>" within PostgreSQL's 63-byte identifiers, so no derived name
	// is ever truncated into another one.
	maxDBName = 63 - len(previousSuffix) - len(nameTimeLayout)
	// undefinedTable is PostgreSQL's SQLSTATE for a missing relation (a database without Alice's tables).
	undefinedTable = "42P01"
)

var restoreActor = audit.SystemActor("cli")

// restorer is the state of one Restore.
type restorer struct {
	s         *Service
	in        RestoreInput
	name      string          // the live database
	owner     *pgx.ConnConfig // the owner role on the live database
	maint     *pgx.Conn       // the owner role on the maintenance database
	staging   *pgxpool.Pool   // the owner role on <name>_restore
	created   bool            // <name>_restore exists because this restore created it
	staged    bool            // this restore wrote the staging directories
	renaming  bool            // the swap's COMMIT was sent: whether it happened is unknown until swapped is set
	swapped   bool            // the databases were renamed: from here on nothing is undone
	restoreID string          // 32 hex, in the staging database and the staging directories (S-1)
	m         Manifest
	files     map[string][]byte // F frames by name
	master    []byte            // the backup's 32-byte master key
	hwm       []byte            // the time record file to stage (nil: none)
	intact    bool
	warnings  []string
	previous  string // <name>_previous_<ts>, or "" when no live database existed
	safety    string // path of the safety backup
	held      int64  // jobs of the backup held for an Administrator (holdChanges)
}

// Restore restores a backup into a fresh database, verifies it, makes a safety backup of the live installation and
// swaps both at one point (C8, R43 rows 8-9, 41, 42, 45, 46). Until the swap a failure leaves the live database, keys
// and state as they were; after it, FinishInterruptedRestore (the next Restore or the start of serve) completes it.
func Restore(ctx context.Context, cfg Config, in RestoreInput) (res RestoreResult, err error) {
	r := &restorer{s: New(cfg), in: in, files: map[string][]byte{}}
	defer r.clearSecrets()
	if sameDir(cfg.KeysDir, cfg.StateDir) {
		return RestoreResult{}, ErrSameDirectory
	}
	defer func() {
		if err != nil && !r.swapped {
			r.abort(ctx)
		}
		r.close(ctx)
	}()
	if err := r.run(ctx); err != nil {
		return RestoreResult{}, err
	}
	return RestoreResult{Manifest: r.m, SafetyBackup: r.safety, Warnings: r.warnings}, nil
}

func (r *restorer) point(p string) error {
	if r.in.hook != nil {
		return r.in.hook(p)
	}
	return nil
}

func (r *restorer) clearSecrets() {
	clear(r.in.Passphrase)
	clear(r.master)
	clear(r.hwm)
	for _, b := range r.files {
		clear(b)
	}
}

func (r *restorer) close(ctx context.Context) {
	if r.staging != nil {
		r.staging.Close()
		r.staging = nil
	}
	if r.maint != nil {
		_ = r.maint.Close(context.WithoutCancel(ctx))
		r.maint = nil
	}
}

// abort undoes what this restore created before the swap: the staging database and directories. The live
// installation was never touched. Once the swap's COMMIT was sent and its outcome is unknown (a lost reply), abort
// leaves everything: the restore ID decides at the next start or restore whether the staging is applied or stale.
func (r *restorer) abort(ctx context.Context) {
	ctx = context.WithoutCancel(ctx)
	if r.staging != nil {
		r.staging.Close()
		r.staging = nil
	}
	if r.renaming {
		return
	}
	if r.created && r.maint != nil {
		if _, err := r.maint.Exec(ctx, ddl(ddlDrop, r.name+restoreSuffix, "")); err != nil {
			r.s.c.Log.Error("could not drop the staging database; the next restore removes it", "error_type", fmt.Sprintf("%T", err))
		}
	}
	if r.staged {
		for _, d := range []string{r.s.c.KeysDir, r.s.c.StateDir} {
			if err := removeStaging(d); err != nil {
				r.s.c.Log.Error("could not remove a staging directory; the next restore removes it", "error_type", fmt.Sprintf("%T", err))
			}
		}
	}
}

func (r *restorer) run(ctx context.Context) error {
	f, err := os.OpenFile(r.in.Path, os.O_RDONLY|syscall.O_NOFOLLOW, 0) //nolint:gosec // G304: the backup the operator named
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return ErrNotFound
		}
		return fmt.Errorf("backup: open %s: %w", filepath.Base(r.in.Path), err)
	}
	defer func() { _ = f.Close() }()

	// The header first: a foreign or newer file is refused before the passphrase is asked for (F-83).
	h, err := format.ReadHeader(bufio.NewReader(f))
	switch {
	case errors.Is(err, format.ErrNotBackup):
		return err
	case errors.Is(err, format.ErrNewerFormat):
		return &ErrNewer{}
	case err != nil:
		return damaged(err)
	case newerVersion(h.AliceVersion, r.s.c.Version):
		return &ErrNewer{Version: h.AliceVersion}
	}
	if r.in.Passphrase == nil && r.in.AskPassphrase != nil {
		if r.in.Passphrase, err = r.in.AskPassphrase(); err != nil {
			return err
		}
	}
	if _, err := f.Seek(0, io.SeekStart); err != nil {
		return fmt.Errorf("backup: %w", err)
	}
	rd, _, err := format.Open(bufio.NewReader(f), r.in.Passphrase)
	clear(r.in.Passphrase)
	if err != nil {
		return damaged(err)
	}
	gz, err := gzip.NewReader(rd)
	if err != nil {
		return damaged(err)
	}
	dec := dump.NewDecoder(gz)
	if err := r.readManifest(dec); err != nil {
		return err
	}

	if err := r.connect(ctx); err != nil {
		return err
	}
	if err := r.waitForSessions(ctx); err != nil {
		return err
	}
	if err := r.cleanup(ctx); err != nil {
		return err
	}
	if err := r.point("cleaned"); err != nil {
		return err
	}
	if err := r.checkFreeSpace(ctx); err != nil {
		return err
	}
	if err := r.loadStaging(ctx, dec, rd); err != nil {
		return err
	}
	if err := r.point("loaded"); err != nil {
		return err
	}
	if err := r.checkFiles(); err != nil {
		return err
	}
	if err := r.verify(ctx); err != nil {
		return err
	}
	if err := r.point("verified"); err != nil {
		return err
	}
	live, err := r.readLive(ctx)
	if err != nil {
		return err
	}
	if err := r.keepNewerTimeRecord(ctx, live); err != nil {
		return err
	}
	if r.in.Confirm != nil && !r.in.Confirm(r.m) {
		return ErrCancelled
	}
	if err := r.safetyBackup(ctx, live); err != nil {
		return err
	}
	if err := r.point("safety-backup"); err != nil {
		return err
	}
	if err := r.appendRestored(ctx, live); err != nil {
		return err
	}
	if err := r.point("audited"); err != nil {
		return err
	}
	return r.swap(ctx)
}

// readManifest reads the M frame: a newer manifest format or schema is ErrNewer.
func (r *restorer) readManifest(dec *dump.Decoder) error {
	first, err := dec.Next()
	if err != nil {
		return damaged(err)
	}
	if err := json.Unmarshal(first.Data, &r.m); err != nil {
		return damaged(fmt.Errorf("%w: the manifest is not JSON", dump.ErrPayload))
	}
	latest, err := db.LatestVersion(migrations.FS)
	if err != nil {
		return err
	}
	switch {
	case r.m.Format > ManifestFormat || r.m.SchemaVersion > latest:
		return &ErrNewer{Version: r.m.AliceVersion}
	case r.m.Format != ManifestFormat || r.m.SchemaVersion < 1:
		return damaged(fmt.Errorf("%w: manifest format %d, schema %d", dump.ErrPayload, r.m.Format, r.m.SchemaVersion))
	}
	return nil
}

// connect opens the maintenance connection (the owner role on database "postgres"). The live database's name comes
// from OwnerURL: between two renames no database of that name may exist to ask current_database() of.
func (r *restorer) connect(ctx context.Context) error {
	cfg, err := pgx.ParseConfig(r.in.OwnerURL)
	if err != nil {
		return errors.New("backup: the owner database URL is not valid")
	}
	r.name = cfg.Database
	if r.name == "" || len(r.name) > maxDBName || strings.ContainsRune(r.name, 0) || r.name == maintenanceDB {
		return fmt.Errorf("backup: the database name must be 1 to %d bytes and not %q", maxDBName, maintenanceDB)
	}
	r.owner = cfg
	mc := cfg.Copy()
	mc.Database = maintenanceDB
	if r.maint, err = pgx.ConnectConfig(ctx, mc); err != nil {
		return fmt.Errorf("backup: connect to the database server as the owner: %w", db.ErrUnreachable)
	}
	// One restore of a database at a time: a session-level advisory lock on the maintenance connection, held until
	// it closes (or the process dies). A second restore fails here, before its cleanup could touch the first's
	// staging.
	var locked bool
	if err := r.maint.QueryRow(ctx, "SELECT pg_try_advisory_lock(hashtext($1), hashtext($2))", restoreLockKey, r.name).Scan(&locked); err != nil {
		return fmt.Errorf("backup: take the restore lock: %w", err)
	}
	if !locked {
		return ErrRestoreRunning
	}
	return nil
}

// connectTo connects the owner role to database name.
func (r *restorer) connectTo(ctx context.Context, name string) (*pgx.Conn, error) {
	c := r.owner.Copy()
	c.Database = name
	conn, err := pgx.ConnectConfig(ctx, c)
	if err != nil {
		return nil, fmt.Errorf("backup: connect to database %s: %w", name, err)
	}
	return conn, nil
}

func (r *restorer) poolOn(ctx context.Context, name string) (*pgxpool.Pool, error) {
	pc, err := pgxpool.ParseConfig("")
	if err != nil {
		return nil, err
	}
	c := r.owner.Copy()
	c.Database = name
	pc.ConnConfig = c
	pc.MaxConns = 4
	p, err := pgxpool.NewWithConfig(ctx, pc)
	if err != nil {
		return nil, fmt.Errorf("backup: connect to database %s: %w", name, err)
	}
	return p, nil
}

func (r *restorer) exists(ctx context.Context, name string) (bool, error) {
	var ok bool
	if err := r.maint.QueryRow(ctx, "SELECT EXISTS (SELECT 1 FROM pg_database WHERE datname = $1)", name).Scan(&ok); err != nil {
		return false, fmt.Errorf("backup: list databases: %w", err)
	}
	return ok, nil
}

// waitForSessions polls every 2 s for up to WaitForSessions until no other session uses the live database (M-4).
func (r *restorer) waitForSessions(ctx context.Context) error {
	waited := time.Duration(0)
	for {
		var n int
		err := r.maint.QueryRow(ctx, "SELECT count(*) FROM pg_stat_activity WHERE datname = $1 AND pid <> pg_backend_pid()", r.name).Scan(&n)
		if err != nil {
			return fmt.Errorf("backup: count the sessions on the database: %w", err)
		}
		if n == 0 {
			return nil
		}
		if waited >= r.in.WaitForSessions {
			return ErrDatabaseInUse
		}
		step := min(sessionPoll, r.in.WaitForSessions-waited)
		t := time.NewTimer(step)
		select {
		case <-ctx.Done():
			t.Stop()
			return ctx.Err()
		case <-t.C:
		}
		waited += step
	}
}

// checkFreeSpace refuses a restore when the free space the host measured is below 2 × the live database + 1 GiB
// (S-22, R43 row 46).
func (r *restorer) checkFreeSpace(ctx context.Context) error {
	if r.in.FreeBytes <= 0 {
		return nil
	}
	var size int64
	err := r.maint.QueryRow(ctx, "SELECT coalesce((SELECT pg_database_size(datname) FROM pg_database WHERE datname = $1), 0)", r.name).Scan(&size)
	if err != nil {
		return fmt.Errorf("backup: read the database size: %w", err)
	}
	if need := 2*size + minFreeForRestore; r.in.FreeBytes < need {
		return &ErrNoSpace{Free: r.in.FreeBytes, Need: need}
	}
	return nil
}

// loadStaging creates <db>_restore, migrates it to the backup's schema and loads the tables in one transaction that
// also writes the restore ID (S-1). Then it reads the F frames, the Z frame and the container to its end: truncation
// and tag failures surface there, before anything live is touched.
func (r *restorer) loadStaging(ctx context.Context, dec *dump.Decoder, rd io.Reader) error {
	staging := r.name + restoreSuffix
	if _, err := r.maint.Exec(ctx, ddl(ddlCreate, staging, "")); err != nil {
		return fmt.Errorf("backup: create the staging database: %w", err)
	}
	r.created = true
	var err error
	if r.staging, err = r.poolOn(ctx, staging); err != nil {
		return err
	}
	if err := db.MigrateTo(ctx, r.staging, migrations.FS, r.m.SchemaVersion); err != nil {
		return fmt.Errorf("backup: prepare the staging database: %w", err)
	}
	id := make([]byte, 16)
	if _, err := rand.Read(id); err != nil {
		return err
	}
	var next dump.Frame
	err = r.inLoadTx(ctx, func(conn *pgx.Conn, tx pgx.Tx) error {
		first, err := dec.Next()
		if err != nil {
			return err
		}
		load := dump.Load
		if r.in.load != nil {
			load = r.in.load
		}
		st, err := load(ctx, conn, dec, first)
		if err != nil {
			return err
		}
		next = st.Next
		// The row counts are checked before the restore ID adds its row.
		tables, err := dump.Tables(ctx, tx)
		if err != nil {
			return err
		}
		counts, err := dump.Counts(ctx, tx, tables)
		if err != nil {
			return err
		}
		if !maps.Equal(counts, r.m.Tables) {
			return &ErrNotVerified{Reason: "the row counts differ from the manifest"}
		}
		return settings.Set(ctx, tx, keyRestoreID, hex.EncodeToString(id), r.s.c.Clock.Now())
	})
	var nv *ErrNotVerified
	if errors.As(err, &nv) {
		return err
	}
	if err != nil {
		return loadError(err)
	}
	r.restoreID = hex.EncodeToString(id)
	return r.readTail(dec, next, rd)
}

// inLoadTx runs fn on one connection of the staging pool in one transaction with the triggers off.
func (r *restorer) inLoadTx(ctx context.Context, fn func(*pgx.Conn, pgx.Tx) error) error {
	conn, err := r.staging.Acquire(ctx)
	if err != nil {
		return err
	}
	defer conn.Release()
	tx, err := conn.Begin(ctx)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback(context.WithoutCancel(ctx)) }()
	if _, err := tx.Exec(ctx, "SET LOCAL session_replication_role = replica"); err != nil {
		return err
	}
	if err := fn(conn.Conn(), tx); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

// loadError keeps a database error (PostgreSQL's disk_full, a lost connection) as it is and calls everything else
// damage: a payload that decrypted but does not decode or does not fit the schema.
func loadError(err error) error {
	var pe *pgconn.PgError
	if errors.As(err, &pe) && !strings.HasPrefix(pe.Code, "22") && !strings.HasPrefix(pe.Code, "23") {
		return fmt.Errorf("backup: load the staging database: %w", err)
	}
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return err
	}
	return damaged(err)
}

// readTail reads the F frames through the fixed four-entry table (S-14), the Z frame and the end of the container.
func (r *restorer) readTail(dec *dump.Decoder, f dump.Frame, rd io.Reader) error {
	var names []string
	for f.Kind == dump.File {
		if !slices.ContainsFunc(payloadFiles, func(p payloadFile) bool { return p.Name == f.Name }) || slices.Contains(names, f.Name) {
			return damaged(fmt.Errorf("%w: file frame %q", errMismatch, f.Name))
		}
		names = append(names, f.Name)
		r.files[f.Name] = f.Data
		var err error
		if f, err = dec.Next(); err != nil {
			return damaged(err)
		}
	}
	if f.Kind != dump.End {
		return damaged(fmt.Errorf("%w: frame %q where the end was expected", dump.ErrPayload, f.Kind))
	}
	var end endFrame
	if err := json.Unmarshal(f.Data, &end); err != nil {
		return damaged(fmt.Errorf("%w: the end frame is not JSON", dump.ErrPayload))
	}
	if end.Tables != len(r.m.Tables) || end.Files != len(names) || !slices.Equal(names, r.m.Files) {
		return damaged(fmt.Errorf("%w: end frame or files", errMismatch))
	}
	if _, err := dec.Next(); !errors.Is(err, io.EOF) {
		if err == nil {
			err = fmt.Errorf("%w: a frame after the end", dump.ErrPayload)
		}
		return damaged(err)
	}
	if _, err := io.Copy(io.Discard, rd); err != nil {
		return damaged(err)
	}
	return nil
}

// checkFiles checks the staged contents (S-14): master.key decodes to 32 bytes; a TLS pair that does not parse and
// match is dropped with a warning (Alice then creates a temporary certificate); a time record that does not decode
// under the backup's master key is dropped with a warning (the database copy remains).
func (r *restorer) checkFiles() error {
	raw, ok := r.files["keys/master.key"]
	if !ok {
		return &ErrNotVerified{Reason: "the backup holds no master key"}
	}
	var err error
	if r.master, err = decodeMasterKey(raw); err != nil {
		return &ErrNotVerified{Reason: "the master key in the backup is not valid"}
	}
	if r.in.DBOnly {
		// A database-only restore keeps the live keys (the update rollback of this installation): the backup must be
		// of the same master key, or Alice could not open the restored database.
		live, err := readMasterKeyFile(filepath.Join(r.s.c.KeysDir, secrets.MasterKeyFile))
		same := err == nil && hmac.Equal(live, r.master)
		clear(live)
		if !same {
			return &ErrNotVerified{Reason: "the backup was made with another master key; restore it without --db-only"}
		}
	}
	crt, hasCrt := r.files["keys/tls.crt"]
	key, hasKey := r.files["keys/tls.key"]
	if hasCrt || hasKey {
		if _, err := tls.X509KeyPair(crt, key); !hasCrt || !hasKey || err != nil {
			r.dropFile("keys/tls.crt")
			r.dropFile("keys/tls.key")
			r.warn("The HTTPS certificate and key in the backup do not match; Alice creates a temporary certificate.")
		}
	}
	return nil
}

// dropFile clears and forgets a staged file the restore does not apply.
func (r *restorer) dropFile(name string) {
	clear(r.files[name])
	delete(r.files, name)
}

func (r *restorer) warn(msg string) {
	r.warnings = append(r.warnings, msg)
	r.s.c.Log.Warn(msg, "event", "backup.restore_warning")
}

// decodeMasterKey decodes the content of master.key: base64 of 32 bytes and a newline.
func decodeMasterKey(raw []byte) ([]byte, error) {
	trimmed := bytes.TrimSpace(raw)
	key := make([]byte, base64.StdEncoding.DecodedLen(len(trimmed)))
	n, err := base64.StdEncoding.Decode(key, trimmed)
	if err != nil || n != secrets.KeySize {
		clear(key)
		return nil, errors.New("backup: not a master key")
	}
	return key[:n], nil
}

// verify checks the staging database before anything live is touched (R43 row 8; the row counts were checked in the
// load transaction): the audit chain is intact (or AcceptBrokenAudit) and its head equals the manifest's, the backup's master key opens
// the stored key check, and the installation seal verifies with it. Then it migrates forward and ends every session.
func (r *restorer) verify(ctx context.Context) error {
	rep, err := audit.Verify(ctx, r.staging)
	if err != nil {
		return err
	}
	r.intact = rep.Intact
	if !rep.Intact && !r.in.AcceptBrokenAudit {
		return &ErrAuditBroken{Seq: rep.FirstBadSeq}
	}
	head, err := auditHead(ctx, r.staging)
	if err != nil {
		return err
	}
	if head == nil {
		head = &AuditHead{}
	}
	if *head != r.m.AuditHead {
		return &ErrNotVerified{Reason: "the audit log does not end where the manifest says"}
	}
	// The key file holds the current key: the newest version's key check must open with it.
	var version int
	var check []byte
	if err := r.staging.QueryRow(ctx, "SELECT version, key_check FROM master_key_versions ORDER BY version DESC LIMIT 1").Scan(&version, &check); err != nil {
		return &ErrNotVerified{Reason: "the master key does not open the stored key check"}
	}
	k, err := secrets.NewKeyring(version, r.master)
	if err != nil {
		return &ErrNotVerified{Reason: "the master key in the backup is not valid"}
	}
	if k.VerifyKeyCheck(check) != nil {
		return &ErrNotVerified{Reason: "the master key does not open the stored key check"}
	}
	var id string
	var at time.Time
	var seal []byte
	err = r.staging.QueryRow(ctx, "SELECT installation_id, installed_at, installation_seal FROM license WHERE id = 1").Scan(&id, &at, &seal)
	if err != nil || !hmac.Equal(seal, installationSeal(k, id, at)) {
		return &ErrNotVerified{Reason: "the installation seal does not verify"}
	}
	if raw, ok := r.files["state/hwm.dat"]; ok {
		if _, err := license.NewHWMCodec(k).Decode(raw); err != nil {
			r.dropFile("state/hwm.dat")
			r.warn("The time record file in the backup does not verify; the copy in the database is used.")
		}
	}
	if err := db.Migrate(ctx, r.staging, migrations.FS); err != nil {
		return fmt.Errorf("backup: migrate the staging database: %w", err)
	}
	_, err = r.staging.Exec(ctx, "DELETE FROM sessions; DELETE FROM setup_sessions; DELETE FROM oidc_login_states")
	if err != nil {
		return fmt.Errorf("backup: end the sessions of the backup: %w", err)
	}
	return r.holdChanges(ctx)
}

// holdChanges holds the backup's unfinished work that changes servers or Key Vaults (class change, queued or running
// at backup time) for an Administrator, as a confirmed license lock does (blocked_license, L-81): it would otherwise
// start with serve against targets whose state has moved on since the backup (a superseded certificate version
// redeployed, a rotation step on keys rotated later). A running job's cut-off attempt is closed as the reaper closes
// it and its target lock released. Read-only and platform work runs as usual. The count goes into system.restored.
func (r *restorer) holdChanges(ctx context.Context) error {
	return db.InTx(ctx, r.staging, func(tx pgx.Tx) error {
		now := r.s.c.Clock.Now().UTC()
		const running = `SELECT id FROM jobs WHERE status = 'running' AND class = 'change'`
		if _, err := tx.Exec(ctx, `UPDATE job_attempts SET finished_at = $1, error_code = 'job.lease_expired'
WHERE finished_at IS NULL AND job_id IN (`+running+`)`, now); err != nil {
			return fmt.Errorf("backup: close the attempts of the backup's running changes: %w", err)
		}
		if _, err := tx.Exec(ctx, `DELETE FROM target_locks WHERE job_id IN (`+running+`)`); err != nil {
			return fmt.Errorf("backup: release the target locks of the backup's running changes: %w", err)
		}
		tag, err := tx.Exec(ctx, `UPDATE jobs SET status = 'blocked_license', locked_by = NULL, locked_until = NULL
WHERE class = 'change' AND status IN ('queued', 'running')`)
		if err != nil {
			return fmt.Errorf("backup: hold the backup's queued changes: %w", err)
		}
		r.held = tag.RowsAffected()
		if r.held > 0 {
			r.warn(strconv.FormatInt(r.held, 10) + " tasks of the backup that change servers or Key Vaults (queued or running when it" +
				" was made) are held: review them under Waiting for an administrator on Servers, then run or discard each.")
		}
		return nil
	})
}

// installationSeal is the seal of license.(*Service).seal (internal/license/installation.go), which the license
// module does not export: HMAC-SHA256 under the master key's installation subkey. A test pins both to one value.
func installationSeal(k *secrets.Keyring, id string, installedAt time.Time) []byte {
	key := k.Derive(secrets.LabelInstallation)
	defer clear(key)
	m := hmac.New(sha256.New, key)
	m.Write([]byte("alice-installation-v1\n" + id + "\n" + strconv.FormatInt(installedAt.UTC().UnixMicro(), 10)))
	return m.Sum(nil)
}

// auditHead reads the newest audit row; nil on an empty log or a database without Alice's tables.
func auditHead(ctx context.Context, q db.Querier) (*AuditHead, error) {
	var seq int64
	var hash []byte
	err := q.QueryRow(ctx, "SELECT seq, hash FROM audit_log ORDER BY seq DESC LIMIT 1").Scan(&seq, &hash)
	switch {
	case errors.Is(err, pgx.ErrNoRows) || isUndefinedTable(err):
		return nil, nil
	case err != nil:
		return nil, fmt.Errorf("backup: read the audit head: %w", err)
	}
	return &AuditHead{Seq: seq, Hash: hex.EncodeToString(hash)}, nil
}

func isUndefinedTable(err error) bool {
	var pe *pgconn.PgError
	return errors.As(err, &pe) && pe.Code == undefinedTable
}

// liveState is what the restore reads of the live installation before the swap.
type liveState struct {
	exists       bool             // a live database exists
	installation bool             // it holds an installation row
	head         *AuditHead       // its audit head (nil: none)
	keyring      *secrets.Keyring // the live master key (nil: none)
	timeRecord   *license.HWMRecord
	timeSeq      uint64 // the highest sequence of any valid live record
}

// readLive reads the live installation: its database (if any), audit head, master key and time record.
func (r *restorer) readLive(ctx context.Context) (liveState, error) {
	var l liveState
	var err error
	if l.exists, err = r.exists(ctx, r.name); err != nil || !l.exists {
		return l, err
	}
	if raw, err := readMasterKeyFile(filepath.Join(r.s.c.KeysDir, secrets.MasterKeyFile)); err == nil {
		l.keyring, err = secrets.NewKeyring(1, raw)
		clear(raw)
		if err != nil {
			l.keyring = nil
		}
	}
	conn, err := r.connectTo(ctx, r.name)
	if err != nil {
		return l, err
	}
	defer func() { _ = conn.Close(context.WithoutCancel(ctx)) }()
	err = conn.QueryRow(ctx, "SELECT EXISTS (SELECT 1 FROM license WHERE id = 1)").Scan(&l.installation)
	if err != nil && !isUndefinedTable(err) {
		return l, fmt.Errorf("backup: read the live installation: %w", err)
	}
	if l.head, err = auditHead(ctx, conn); err != nil {
		return l, err
	}
	if l.keyring == nil {
		return l, nil
	}
	codec := license.NewHWMCodec(l.keyring)
	var raws [][]byte
	var dbRaw json.RawMessage
	found, err := settings.Get(ctx, conn, license.HWMSettingKey, &dbRaw)
	if err != nil && !isUndefinedTable(err) {
		return l, err
	}
	if found {
		raws = append(raws, dbRaw)
	}
	if b, err := (license.FileHWMStore{Path: filepath.Join(r.s.c.StateDir, license.HWMFileName)}).Load(ctx); err == nil && b != nil {
		raws = append(raws, b)
	}
	l.timeRecord, l.timeSeq, _ = bestRecord(codec, raws)
	return l, nil
}

// bestRecord decodes the records and returns the best (the later time, then the higher sequence), the highest
// sequence of any valid one and the bytes of the best, as the license module reads its two stores (L-55).
func bestRecord(codec license.HWMCodec, raws [][]byte) (*license.HWMRecord, uint64, []byte) {
	var best *license.HWMRecord
	var bestRaw []byte
	var maxSeq uint64
	for _, raw := range raws {
		rec, err := codec.Decode(raw)
		if err != nil {
			continue
		}
		maxSeq = max(maxSeq, rec.Seq)
		if best == nil || rec.At.After(best.At) || (rec.At.Equal(best.At) && rec.Seq > best.Seq) {
			best, bestRaw = &rec, raw
		}
	}
	return best, maxSeq, bestRaw
}

// keepNewerTimeRecord keeps the license time record from going back (S-5, R43 row 42): when the live record is newer
// than the backup's, it is re-sealed under the backup's master key with a higher sequence into the staging database
// and the staged file; otherwise the backup's best record is staged. A fresh host keeps the backup's record.
func (r *restorer) keepNewerTimeRecord(ctx context.Context, live liveState) error {
	k, err := secrets.NewKeyring(1, r.master)
	if err != nil {
		return err
	}
	codec := license.NewHWMCodec(k)
	var dbRaw json.RawMessage
	found, err := settings.Get(ctx, r.staging, license.HWMSettingKey, &dbRaw)
	if err != nil {
		return err
	}
	var raws [][]byte // the file first: on a tie its bytes are staged unchanged
	if b, ok := r.files["state/hwm.dat"]; ok {
		raws = append(raws, b)
	}
	if found {
		raws = append(raws, dbRaw)
	}
	best, maxSeq, bestRaw := bestRecord(codec, raws)
	if live.timeRecord != nil && (best == nil || live.timeRecord.At.After(best.At)) {
		rec := license.HWMRecord{At: live.timeRecord.At, Seq: max(maxSeq, live.timeSeq) + 1}
		if r.hwm, err = codec.Encode(rec); err != nil {
			return err
		}
		return settings.Set(ctx, r.staging, license.HWMSettingKey, json.RawMessage(r.hwm), r.s.c.Clock.Now())
	}
	if best != nil {
		r.hwm = slices.Clone(bestRaw) // the backup's own record; the staged file then equals one of its copies
	}
	return nil
}

// safetyBackup backs up the live installation (kind pre-restore) when its database has an installation row. With
// data but no backup key the restore is refused unless NoSafetyBackup (S-17, R43 row 45). The pool it opens is
// closed before the swap (M-25).
func (r *restorer) safetyBackup(ctx context.Context, live liveState) error {
	if !live.installation {
		return nil
	}
	notConfigured := func() error {
		if r.in.NoSafetyBackup {
			return nil
		}
		return ErrNoSafetyBackup
	}
	if live.keyring == nil {
		return notConfigured()
	}
	pool, err := r.poolOn(ctx, r.name)
	if err != nil {
		return err
	}
	defer pool.Close()
	c := r.s.c
	c.Pool, c.Keyring = pool, live.keyring
	if c.Audit == nil {
		c.Audit = audit.New(c.Clock)
	}
	svc := New(c)
	if _, _, err := svc.keys(ctx); err != nil {
		var f *failure
		if errors.As(err, &f) && f.code == codeNotConfigured {
			return notConfigured()
		}
		return err
	}
	info, err := svc.Create(ctx, CreateInput{Kind: KindPreRestore, Reason: "before restoring " + filepath.Base(r.in.Path), Actor: restoreActor})
	if err != nil {
		return fmt.Errorf("backup: the safety backup of the current installation failed: %w", err)
	}
	r.safety = info.Path
	return nil
}

// appendRestored appends system.restored to the staging database's chain (F-97) with what it replaced (S-17).
func (r *restorer) appendRestored(ctx context.Context, live liveState) error {
	d := map[string]string{
		"backup_name":       filepath.Base(r.in.Path),
		"backup_created_at": r.m.CreatedAt.UTC().Format(time.RFC3339),
		"alice_version":     r.m.AliceVersion,
		"schema_version":    strconv.FormatInt(r.m.SchemaVersion, 10),
		"audit_intact":      strconv.FormatBool(r.intact),
		"safety_backup":     "none",
		"held_jobs":         strconv.FormatInt(r.held, 10),
	}
	if live.head != nil {
		d["previous_audit_seq"] = strconv.FormatInt(live.head.Seq, 10)
		d["previous_audit_hash"] = live.head.Hash
	}
	if r.safety != "" {
		d["safety_backup"] = filepath.Base(r.safety)
	}
	if r.in.NoSafetyBackup {
		d["no_safety_backup"] = "true"
	}
	log := r.s.c.Audit
	if log == nil {
		log = audit.New(r.s.c.Clock)
	}
	return db.InTx(ctx, r.staging, func(tx pgx.Tx) error {
		_, err := log.Append(ctx, tx, audit.Event{Actor: restoreActor, Action: "system.restored", ObjectType: "backup",
			ObjectID: filepath.Base(r.in.Path), Result: audit.Success, Details: d})
		return err
	})
}

// readMasterKeyFile reads a master key file without following a link and without checking its owner or mode (the
// restore only reads it); os.ErrNotExist when there is none.
func readMasterKeyFile(path string) ([]byte, error) {
	b, err := readSmall(path)
	if err != nil {
		return nil, err
	}
	defer clear(b)
	return decodeMasterKey(b)
}

// versionPattern is C7's alice_version.
var versionPattern = regexp.MustCompile(`^([0-9]+)\.([0-9]+)\.([0-9]+)(?:-([0-9A-Za-z.]+))?$`)

// newerVersion reports whether the backup's version v is newer than the running one (semantic-version precedence).
// "dev" on either side is never newer; a version that does not parse is newer than any (it is not one this binary
// wrote), and nothing is newer than a running version that does not parse.
func newerVersion(v, running string) bool {
	if v == "dev" || running == "dev" {
		return false
	}
	a, b := versionPattern.FindStringSubmatch(v), versionPattern.FindStringSubmatch(running)
	switch {
	case b == nil:
		return false
	case a == nil:
		return true
	}
	for i := 1; i <= 3; i++ {
		if c := compareNumeric(a[i], b[i]); c != 0 {
			return c > 0
		}
	}
	switch {
	case a[4] == b[4]:
		return false
	case a[4] == "":
		return true // a release is newer than its pre-releases
	case b[4] == "":
		return false
	}
	pa, pb := strings.Split(a[4], "."), strings.Split(b[4], ".")
	for i := range min(len(pa), len(pb)) {
		if pa[i] == pb[i] {
			continue
		}
		na, ea := strconv.ParseUint(pa[i], 10, 64)
		nb, eb := strconv.ParseUint(pb[i], 10, 64)
		switch {
		case ea == nil && eb == nil:
			return na > nb
		case ea == nil:
			return false // numeric identifiers rank below alphanumeric ones
		case eb == nil:
			return true
		default:
			return pa[i] > pb[i]
		}
	}
	return len(pa) > len(pb)
}

// compareNumeric compares two decimal strings of any length.
func compareNumeric(a, b string) int {
	a, b = strings.TrimLeft(a, "0"), strings.TrimLeft(b, "0")
	if len(a) != len(b) {
		return len(a) - len(b)
	}
	return strings.Compare(a, b)
}
