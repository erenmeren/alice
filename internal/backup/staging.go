package backup

import (
	"context"
	"crypto/subtle"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/jackc/pgx/v5"

	"alice/internal/platform/settings"
)

// previousName matches the time suffix of a previous database.
var previousName = regexp.MustCompile(`^[0-9]{8}T[0-9]{6}Z$`)

// cleanup is the start of every Restore (S-1, R43 row 8). It finishes or removes what an interrupted restore left:
//
//   - no <db> but a <db>_restore: it is renamed to <db> only when both staging directories carry its restore ID (the
//     restore reached "staged", so it was verified); otherwise it is unverified and the restore refuses with
//     ErrUnfinishedStaging. It is never dropped (it may be the only copy);
//   - staging directories: FinishInterruptedRestore against the live database applies them when the live database
//     carries their restore ID, else removes them as stale without touching the live files;
//   - <db>_restore while <db> exists: an unfinished staging database, dropped;
//   - <db>_previous_* while <db> exists and no staging remains: the old database of a finished swap, dropped. A
//     previous database that a swap kept because no file was applied is <db>_kept_<ts> and is never dropped here.
func (r *restorer) cleanup(ctx context.Context) error {
	staging := r.name + restoreSuffix
	live, err := r.exists(ctx, r.name)
	if err != nil {
		return err
	}
	restore, err := r.exists(ctx, staging)
	if err != nil {
		return err
	}
	if !live && restore {
		ok, err := r.stagedFor(ctx, staging)
		if err != nil {
			return err
		}
		if !ok {
			return fmt.Errorf("%w: %s exists and %s does not; check it, drop or rename it by hand, then run the restore again",
				ErrUnfinishedStaging, staging, r.name)
		}
		if _, err := r.maint.Exec(ctx, ddl(ddlRename, staging, r.name)); err != nil {
			return fmt.Errorf("backup: finish an interrupted rename: %w", err)
		}
		r.s.c.Log.Warn("an interrupted restore left no live database; its staging database is live again", "event", "backup.restore_recovered")
		live, restore = true, false
	}
	if stagingPresent(r.s.c.KeysDir) || stagingPresent(r.s.c.StateDir) {
		if live {
			if err := r.finishWithLive(ctx); err != nil {
				return err
			}
		} else {
			for _, d := range []string{r.s.c.KeysDir, r.s.c.StateDir} {
				if err := removeStaging(d); err != nil {
					return err
				}
			}
		}
	}
	if !live {
		return nil
	}
	if restore {
		if _, err := r.maint.Exec(ctx, ddl(ddlDrop, staging, "")); err != nil {
			return fmt.Errorf("backup: drop an unfinished staging database: %w", err)
		}
	}
	if stagingPresent(r.s.c.KeysDir) || stagingPresent(r.s.c.StateDir) {
		return nil
	}
	rows, err := r.maint.Query(ctx, "SELECT datname FROM pg_database WHERE starts_with(datname, $1)", r.name+previousSuffix)
	if err != nil {
		return fmt.Errorf("backup: list databases: %w", err)
	}
	names, err := pgx.CollectRows(rows, pgx.RowTo[string])
	if err != nil {
		return fmt.Errorf("backup: list databases: %w", err)
	}
	for _, n := range names {
		if !previousName.MatchString(strings.TrimPrefix(n, r.name+previousSuffix)) {
			continue
		}
		if _, err := r.maint.Exec(ctx, ddl(ddlDrop, n, "")); err != nil {
			return fmt.Errorf("backup: drop the previous database of a finished restore: %w", err)
		}
	}
	return nil
}

func (r *restorer) finishWithLive(ctx context.Context) error {
	conn, err := r.connectTo(ctx, r.name)
	if err != nil {
		return err
	}
	defer func() { _ = conn.Close(context.WithoutCancel(ctx)) }()
	_, err = FinishInterruptedRestore(ctx, conn, r.s.c.KeysDir, r.s.c.StateDir)
	return err
}

// stagedFor reports whether database name carries a restore ID that both staging directories carry too.
func (r *restorer) stagedFor(ctx context.Context, name string) (bool, error) {
	conn, err := r.connectTo(ctx, name)
	if err != nil {
		return false, err
	}
	var id string
	found, err := settings.Get(ctx, conn, keyRestoreID, &id)
	_ = conn.Close(context.WithoutCancel(ctx))
	if err != nil && !isUndefinedTable(err) {
		return false, fmt.Errorf("backup: read the restore ID of %s: %w", name, err)
	}
	if !found || len(id) != 32 {
		return false, nil
	}
	for _, d := range []string{r.s.c.KeysDir, r.s.c.StateDir} {
		b, err := readSmall(filepath.Join(d, stagingDir, restoreIDTag))
		if err != nil || subtle.ConstantTimeCompare([]byte(strings.TrimSuffix(string(b), "\n")), []byte(id)) != 1 {
			return false, nil
		}
	}
	return true, nil
}

func stagingPresent(dir string) bool {
	_, err := os.Lstat(filepath.Join(dir, stagingDir))
	return err == nil
}
