package backup

import (
	"context"
	"crypto/subtle"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"syscall"

	"github.com/jackc/pgx/v5"

	"alice/internal/platform/db"
	"alice/internal/platform/settings"
)

// ddlOp is one of the restore's three DDL statements.
type ddlOp int

const (
	ddlCreate ddlOp = iota
	ddlRename
	ddlDrop
)

// ddl builds the restore's CREATE DATABASE, ALTER DATABASE … RENAME TO and DROP DATABASE statements: the one place of
// the restore where SQL text carries identifiers (R43 row 48, SEC-060 exception), because PostgreSQL cannot bind
// identifiers in DDL. Every name is the live database's name plus a fixed suffix, quoted by pgx.
func ddl(op ddlOp, name, to string) string {
	q := pgx.Identifier{name}.Sanitize()
	switch op {
	case ddlCreate:
		return "CREATE DATABASE " + q //nolint:gosec // G202: an identifier quoted by pgx.Identifier (R43 row 48)
	case ddlRename:
		return "ALTER DATABASE " + q + " RENAME TO " + pgx.Identifier{to}.Sanitize() //nolint:gosec // G202: identifiers quoted by pgx.Identifier (R43 row 48)
	default:
		return "DROP DATABASE IF EXISTS " + q //nolint:gosec // G202: an identifier quoted by pgx.Identifier (R43 row 48)
	}
}

// swap is the single swap point (S-1, R43 row 8): it writes the staging directories (files, FILES, RESTORE_ID) and
// copies of the live files into previous/, renames both databases in one transaction, applies the staged files
// through FinishInterruptedRestore and only then drops the previous database.
func (r *restorer) swap(ctx context.Context) error {
	if !r.in.DBOnly {
		if err := r.stage(); err != nil {
			return err
		}
	}
	if err := r.point("staged"); err != nil {
		return err
	}
	if !r.in.DBOnly {
		if err := r.copyPrevious(); err != nil {
			return err
		}
	}
	// Nothing of this restore may hold a connection to either database while they are renamed (M-25).
	r.staging.Close()
	r.staging = nil
	if err := r.point("previous"); err != nil {
		return err
	}

	live, err := r.exists(ctx, r.name)
	if err != nil {
		return err
	}
	tx, err := r.maint.Begin(ctx)
	if err != nil {
		return fmt.Errorf("backup: swap the databases: %w", err)
	}
	defer func() { _ = tx.Rollback(context.WithoutCancel(ctx)) }()
	if live {
		r.previous = r.name + previousSuffix + r.s.c.Clock.Now().UTC().Format(nameTimeLayout)
		if _, err := tx.Exec(ctx, ddl(ddlRename, r.name, r.previous)); err != nil {
			return fmt.Errorf("backup: rename the current database: %w", err)
		}
	}
	if _, err := tx.Exec(ctx, ddl(ddlRename, r.name+restoreSuffix, r.name)); err != nil {
		return fmt.Errorf("backup: rename the restored database: %w", err)
	}
	commit := r.in.commit
	if commit == nil {
		commit = func(ctx context.Context, tx pgx.Tx) error { return tx.Commit(ctx) }
	}
	// From here the outcome is unknown until COMMIT answers: a lost reply may hide a swap that happened, so a failure
	// must not remove the staging (abort checks renaming); the restore ID decides at the next start or restore.
	r.renaming = true
	if err := commit(ctx, tx); err != nil {
		return fmt.Errorf("backup: the database swap may not have completed; start Alice or run the restore again to finish or undo it: %w", err)
	}
	r.swapped = true
	r.s.c.Log.Info("the restored database is now live", "event", "backup.restore_swapped")
	if err := r.point("renamed"); err != nil {
		return err
	}

	conn, err := r.connectTo(ctx, r.name)
	if err != nil {
		return err
	}
	applied, err := FinishInterruptedRestore(ctx, conn, r.s.c.KeysDir, r.s.c.StateDir)
	_ = conn.Close(context.WithoutCancel(ctx))
	if err != nil {
		return err
	}
	if !applied && !r.in.DBOnly {
		// The staging vanished between "staged" and the swap: the restored database is live without its keys. The
		// previous database is the way back, so it is kept.
		if r.previous != "" {
			return fmt.Errorf("backup: the restored database is live but its key and state files were not applied; the previous database %s is kept", r.previous)
		}
		return errors.New("backup: the restored database is live but its key and state files were not applied")
	}
	if err := r.point("files"); err != nil {
		return err
	}
	if r.previous != "" {
		if _, err := r.maint.Exec(ctx, ddl(ddlDrop, r.previous, "")); err != nil {
			r.warn("The previous database " + r.previous + " could not be dropped; the next restore drops it.")
		}
	}
	return nil
}

// Names inside a staging directory (C1).
const (
	stagingDir   = ".restore-staging"
	restoreIDTag = "RESTORE_ID"
	filesList    = "FILES"
	previousDir  = "previous"
)

// stagedFile is one file of the fixed table as the staging handles it.
type stagedFile struct {
	name     string // F-frame name
	base     string // file name in its directory
	mode     os.FileMode
	optional bool // absent from the backup: the live file is removed when the restore is applied
}

var (
	keysFiles = []stagedFile{
		{name: "keys/master.key", base: "master.key", mode: 0o400},
		{name: "keys/tls.crt", base: "tls.crt", mode: 0o644, optional: true},
		{name: "keys/tls.key", base: "tls.key", mode: 0o400, optional: true},
	}
	stateFiles = []stagedFile{{name: "state/hwm.dat", base: "hwm.dat", mode: 0o400, optional: true}}
)

// stage writes both staging directories: the staged files (0400, tls.crt 0644; directories 0700, E15), FILES (what
// was staged) and, last, RESTORE_ID. Each file and directory is synced.
func (r *restorer) stage() error {
	r.staged = true
	contents := map[string][]byte{}
	for name, b := range r.files {
		contents[name] = b
	}
	delete(contents, "state/hwm.dat")
	if r.hwm != nil {
		contents["state/hwm.dat"] = r.hwm
	}
	for dir, set := range map[string][]stagedFile{r.s.c.KeysDir: keysFiles, r.s.c.StateDir: stateFiles} {
		s := filepath.Join(dir, stagingDir)
		if err := os.Mkdir(s, 0o700); err != nil {
			return fmt.Errorf("backup: create the staging directory: %w", err)
		}
		var listed []string
		for _, f := range set {
			b, ok := contents[f.name]
			if !ok {
				continue
			}
			if err := writeSynced(filepath.Join(s, f.base), b, f.mode); err != nil {
				return err
			}
			listed = append(listed, f.base)
		}
		if err := writeSynced(filepath.Join(s, filesList), []byte(strings.Join(listed, "\n")+"\n"), 0o400); err != nil {
			return err
		}
		if err := writeSynced(filepath.Join(s, restoreIDTag), []byte(r.restoreID+"\n"), 0o400); err != nil {
			return err
		}
		if err := syncDir(s); err != nil {
			return err
		}
		if err := syncDir(dir); err != nil {
			return err
		}
	}
	return nil
}

// copyPrevious copies the live files into previous/ of each staging directory before the swap (S-1), so an
// operator holds both sides while a restore is being applied.
func (r *restorer) copyPrevious() error {
	for dir, set := range map[string][]stagedFile{r.s.c.KeysDir: keysFiles, r.s.c.StateDir: stateFiles} {
		p := filepath.Join(dir, stagingDir, previousDir)
		if err := os.Mkdir(p, 0o700); err != nil {
			return fmt.Errorf("backup: create the previous directory: %w", err)
		}
		for _, f := range set {
			b, err := readSmall(filepath.Join(dir, f.base))
			if errors.Is(err, os.ErrNotExist) {
				continue
			}
			if err != nil {
				return err
			}
			err = writeSynced(filepath.Join(p, f.base), b, f.mode)
			clear(b)
			if err != nil {
				return err
			}
		}
		if err := syncDir(p); err != nil {
			return err
		}
	}
	return nil
}

func writeSynced(path string, b []byte, mode os.FileMode) error {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY|syscall.O_NOFOLLOW, mode) //nolint:gosec // G304: a fixed name in the staging directory
	if err != nil {
		return fmt.Errorf("backup: write %s: %w", filepath.Base(path), err)
	}
	_, err = f.Write(b)
	if err == nil {
		err = f.Sync()
	}
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		return fmt.Errorf("backup: write %s: %w", filepath.Base(path), err)
	}
	return nil
}

// FinishInterruptedRestore applies staged files only when the live database's backup.restore_id equals the staging's
// RESTORE_ID; otherwise the staging is stale and removed without touching the live files (R43 row 8). q is the app
// pool (serve opens it first) or the restore's connection to the live database. It reports whether files were
// applied.
//
// Applying renames each staged file over the live one and removes a live optional file the restore did not stage (a
// TLS pair the backup lacked, a time record of the old master key); a file listed in FILES but no longer staged was
// renamed by an earlier, interrupted run. The master key is never removed. Each directory is synced.
func FinishInterruptedRestore(ctx context.Context, q db.Querier, keysDir, stateDir string) (bool, error) {
	if sameDir(keysDir, stateDir) {
		return false, ErrSameDirectory
	}
	dirs := map[string][]stagedFile{keysDir: keysFiles, stateDir: stateFiles}
	present := false
	for dir := range dirs {
		if _, err := os.Lstat(filepath.Join(dir, stagingDir)); err == nil {
			present = true
		} else if !errors.Is(err, os.ErrNotExist) {
			return false, fmt.Errorf("backup: read the staging directory: %w", err)
		}
	}
	if !present {
		return false, nil
	}
	var liveID string
	found, err := settings.Get(ctx, q, keyRestoreID, &liveID)
	if err != nil && !isUndefinedTable(err) {
		return false, fmt.Errorf("backup: read the restore ID of the live database: %w", err)
	}
	if !found {
		liveID = ""
	}
	applied := false
	for _, dir := range []string{keysDir, stateDir} {
		ok, err := finishDir(dir, dirs[dir], liveID)
		if err != nil {
			return applied, err
		}
		applied = applied || ok
	}
	return applied, nil
}

// finishDir applies or removes one staging directory.
func finishDir(dir string, set []stagedFile, liveID string) (bool, error) {
	s := filepath.Join(dir, stagingDir)
	fi, err := os.Lstat(s)
	if errors.Is(err, os.ErrNotExist) {
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("backup: read the staging directory: %w", err)
	}
	id, idErr := readSmall(filepath.Join(s, restoreIDTag))
	if !fi.IsDir() || idErr != nil || liveID == "" || len(liveID) != 32 ||
		subtle.ConstantTimeCompare([]byte(strings.TrimSuffix(string(id), "\n")), []byte(liveID)) != 1 {
		return false, removeStaging(dir) // stale: another restore's, an unfinished one's, or not ours at all
	}
	listRaw, err := readSmall(filepath.Join(s, filesList))
	if err != nil {
		return false, fmt.Errorf("backup: read the staged file list: %w", err)
	}
	listed := strings.Fields(string(listRaw))
	for _, f := range set {
		live, staged := filepath.Join(dir, f.base), filepath.Join(s, f.base)
		switch {
		case slices.Contains(listed, f.base):
			if err := os.Rename(staged, live); err != nil && !errors.Is(err, os.ErrNotExist) {
				return false, fmt.Errorf("backup: apply %s: %w", f.base, err)
			}
		case f.optional:
			if err := os.Remove(live); err != nil && !errors.Is(err, os.ErrNotExist) {
				return false, fmt.Errorf("backup: remove %s: %w", f.base, err)
			}
		}
	}
	if err := syncDir(dir); err != nil {
		return false, fmt.Errorf("backup: sync %s: %w", dir, err)
	}
	return true, removeStaging(dir)
}

// removeStaging removes dir's staging directory, if any, and syncs dir.
func removeStaging(dir string) error {
	s := filepath.Join(dir, stagingDir)
	if _, err := os.Lstat(s); errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err := os.RemoveAll(s); err != nil {
		return fmt.Errorf("backup: remove the staging directory: %w", err)
	}
	if err := syncDir(dir); err != nil {
		return fmt.Errorf("backup: sync %s: %w", dir, err)
	}
	return nil
}

// sameDir reports whether a and b name one directory (lexically, after making them absolute): the staging would then
// hold only one of the two file sets.
func sameDir(a, b string) bool {
	aa, errA := filepath.Abs(a)
	bb, errB := filepath.Abs(b)
	if errA != nil || errB != nil {
		return filepath.Clean(a) == filepath.Clean(b)
	}
	return aa == bb
}
