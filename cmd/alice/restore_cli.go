package main

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"math"
	"path/filepath"
	"time"

	"github.com/jackc/pgx/v5"

	"alice/internal/backup"
	"alice/internal/backup/format"
	"alice/internal/platform/config"
)

// restoreFunc is backup.Restore; the tests replace it to see the input the command builds.
var restoreFunc = backup.Restore

// defaultWaitForSessions is how long a restore waits for other sessions on the live database to end (M-4, C6).
const defaultWaitForSessions = 150 * time.Second

// The restore's messages (C7).
const (
	msgRestoreDone      = "Restore finished. Everyone must sign in again. Users and API tokens are as they were when the backup was made; review them."
	msgCancelled        = "Restore cancelled. Nothing was changed."
	msgStillConnected   = "Alice is still connected to the database. Stop it first."
	msgNoSafetyBackup   = "This installation has data but no recovery passphrase, so no safety backup can be made first. Nothing was changed. To restore anyway, run the command again with --no-safety-backup (the current data is then replaced without a copy)."
	msgConfirmPrompt    = "Type RESTORE to replace all current data: "
	confirmWord         = "RESTORE"
	maxConfirmLineBytes = 64
)

const usageRestore = `usage: alice restore FILE [--db-only] [--passphrase-stdin] [--confirm RESTORE] [--accept-broken-audit-log] [--no-safety-backup]
                     [--free-bytes N] [--wait-for-sessions DURATION]`

func runRestore(args []string, cfg config.Config, stdin io.Reader, stdout, stderr io.Writer) int {
	fs := newFlags("restore", usageRestore, stderr)
	dbOnly := fs.Bool("db-only", false, "")
	fromStdin := fs.Bool("passphrase-stdin", false, "")
	confirm := fs.String("confirm", "", "")
	acceptBroken := fs.Bool("accept-broken-audit-log", false, "")
	noSafety := fs.Bool("no-safety-backup", false, "")
	freeBytes := fs.Int64("free-bytes", 0, "")
	wait := fs.Duration("wait-for-sessions", defaultWaitForSessions, "")
	file, ok := parseWithFile(fs, args)
	if !ok {
		return 2
	}
	if (*confirm != "" && *confirm != confirmWord) || *freeBytes < 0 || *wait < 0 {
		fs.Usage()
		return 2
	}
	in := bufio.NewReader(orEmpty(stdin))
	src, ok := newPassphraseSource(*fromStdin, in, stdin, stderr)
	if !ok {
		fmt.Fprintln(stderr, msgPassphraseNeeded)
		return 2
	}
	// MigrationURL falls back to the application's URL, so the owner URL itself is checked (M-1), and then that its
	// role owns the database, before the passphrase is asked for.
	if cfg.MigrateDatabaseURL == "" {
		fmt.Fprintln(stderr, "ALICE_MIGRATE_DATABASE_URL is not set; a restore needs the database owner role. Nothing was changed.")
		return 1
	}
	ctx, stop := commandContext()
	defer stop()
	if err := ownerCheckFunc(ctx, cfg.MigrateDatabaseURL); err != nil {
		var notOwner *errNotOwner
		if errors.As(err, &notOwner) {
			fmt.Fprintf(stderr, "The role in ALICE_MIGRATE_DATABASE_URL (%s) does not own the database %s; a restore needs the "+
				"database owner role. Nothing was changed.\n", notOwner.role, notOwner.database)
			return 1
		}
	}
	rin := backup.RestoreInput{
		Path:              file,
		AskPassphrase:     src.read,
		DBOnly:            *dbOnly,
		AcceptBrokenAudit: *acceptBroken,
		NoSafetyBackup:    *noSafety,
		FreeBytes:         *freeBytes,
		WaitForSessions:   *wait,
		OwnerURL:          cfg.MigrateDatabaseURL,
	}
	if *confirm == "" {
		rin.Confirm = func(m backup.Manifest) bool {
			fmt.Fprintf(stdout, "%s.\n", manifestLine(m))
			fmt.Fprint(stdout, msgConfirmPrompt)
			line, err := readLine(in, maxConfirmLineBytes)
			fmt.Fprintln(stdout)
			return err == nil && string(line) == confirmWord
		}
	}
	res, err := restoreFunc(ctx, backupConfig(cfg, newClock(), slog.New(slog.DiscardHandler)), rin)
	for _, w := range res.Warnings {
		fmt.Fprintln(stderr, "Warning:", w)
	}
	if err != nil {
		msg, code := restoreError(err)
		fmt.Fprintln(stderr, msg)
		return code
	}
	if res.SafetyBackup != "" {
		fmt.Fprintf(stdout, "The replaced data was saved first as %s.\n", filepath.Base(res.SafetyBackup))
	}
	if *dbOnly {
		fmt.Fprintf(stdout, "Database restored from %s.\n", filepath.Base(file))
		return 0
	}
	fmt.Fprintln(stdout, msgRestoreDone)
	return 0
}

// ownerCheckFunc is checkOwnerRole; the tests without a database replace it.
var ownerCheckFunc = checkOwnerRole

// errNotOwner is an owner URL whose role neither owns the live database nor is a superuser.
type errNotOwner struct{ role, database string }

func (e *errNotOwner) Error() string {
	return "role " + e.role + " does not own database " + e.database
}

// checkOwnerRole connects as the owner URL's role to the maintenance database and refuses a role that does not own
// (and is no member of the owner of) the live database. Any other error, including an unreachable server or a live
// database that does not exist (an interrupted restore between its two renames), is left to the restore, which
// reports it in its own words.
func checkOwnerRole(ctx context.Context, ownerURL string) error {
	ctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	cfg, err := pgx.ParseConfig(ownerURL)
	if err != nil {
		return err
	}
	name := cfg.Database
	cfg.Database = "postgres"
	conn, err := pgx.ConnectConfig(ctx, cfg)
	if err != nil {
		return err
	}
	defer func() { _ = conn.Close(context.WithoutCancel(ctx)) }()
	var role string
	var owner bool
	err = conn.QueryRow(ctx, `SELECT current_user::text,
	(SELECT rolsuper FROM pg_roles WHERE rolname = current_user) OR pg_has_role(current_user, d.datdba, 'USAGE')
FROM pg_database d WHERE d.datname = $1`, name).Scan(&role, &owner)
	if err != nil {
		return err
	}
	if !owner {
		return &errNotOwner{role: role, database: name}
	}
	return nil
}

// restoreError maps an error of backup.Restore to its C7 message and exit code.
func restoreError(err error) (string, int) {
	var newer *backup.ErrNewer
	var notVerified *backup.ErrNotVerified
	var broken *backup.ErrAuditBroken
	var noSpace *backup.ErrNoSpace
	switch {
	case errors.Is(err, format.ErrNotBackup):
		return msgNotBackup, 1
	case errors.As(err, &newer):
		if newer.Version == "" {
			return msgNewerUnknown, 1
		}
		return fmt.Sprintf("This backup was created by a newer Alice version (%[1]s). Install Alice %[1]s or newer, then restore.",
			newer.Version), 1
	case errors.Is(err, backup.ErrDamaged):
		return msgDamaged, 1
	case errors.As(err, &notVerified):
		return fmt.Sprintf("The backup could not be verified (%s). Nothing was changed.", notVerified.Reason), 1
	case errors.As(err, &broken):
		return fmt.Sprintf("The audit log in this backup is damaged at entry %d. Nothing was changed. To restore it anyway, "+
			"run the command again with --accept-broken-audit-log (the damage stays visible in Alice).", broken.Seq), 1
	case errors.Is(err, backup.ErrCancelled), errors.Is(err, errPassphraseCancelled):
		return msgCancelled, 1
	case errors.Is(err, backup.ErrNoSafetyBackup):
		return msgNoSafetyBackup, 1
	case errors.As(err, &noSpace):
		return fmt.Sprintf("Not enough free disk space for a restore: %d GB free, %d GB needed.",
			noSpace.Free/1e9, int64(math.Ceil(float64(noSpace.Need)/1e9))), 1
	case errors.Is(err, backup.ErrDatabaseInUse):
		return msgStillConnected, 1
	case errors.Is(err, backup.ErrRestoreRunning):
		return "Another restore is running. Wait for it to finish.", 1
	case errors.Is(err, backup.ErrSameDirectory):
		return "ALICE_KEYS_DIR and ALICE_STATE_DIR must be two different directories. Nothing was changed.", 1
	case errors.Is(err, backup.ErrUnfinishedStaging):
		return "An interrupted restore left an unverified copy of the database (<database>_restore) and no live database. " +
			"Nothing was changed. Drop that copy by hand (see the operator guide), then run the restore again.", 1
	case errors.Is(err, backup.ErrNotFound):
		return "There is no backup file at that path.", 1
	case errors.Is(err, errPassphraseTooLong):
		return msgDamaged, 1
	}
	return "The restore failed: " + err.Error(), 1
}
