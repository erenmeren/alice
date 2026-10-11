package main

import (
	"bufio"
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"text/tabwriter"

	"alice/internal/audit"
	"alice/internal/backup"
	"alice/internal/backup/format"
	"alice/internal/platform/clock"
	"alice/internal/platform/config"
	"alice/internal/version"
)

// The CLI's backup messages (C6, C7).
const (
	msgShallowOK     = "The backup file looks complete (header, size and checksum are correct)."
	msgNotBackup     = "This is not an Alice backup."
	msgDamaged       = "The passphrase is wrong or the file is damaged. Nothing was changed."
	msgNewerUnknown  = "This backup was created by a newer Alice version. Install the newest Alice version, then restore."
	msgNotConfigured = "Backups start after the recovery passphrase is set. Finish the setup wizard first."
	msgRunning       = "Another backup is running. Try again when it has finished."
	preUpgradePrefix = "pre-upgrade-"
)

const usageBackup = `usage: alice backup [--out PATH] [--reason TEXT]
       alice backup list
       alice backup verify FILE [--deep] [--passphrase-stdin]`

// commandContext ends at SIGINT or SIGTERM: a backup or a restore has no fixed time limit.
func commandContext() (context.Context, context.CancelFunc) {
	return signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
}

// backupConfig is the backup service's configuration for a command that needs no database (list, verify, restore).
// The binary's own release version is the one written into and compared with backup headers (C7).
func backupConfig(cfg config.Config, clk clock.Clock, log *slog.Logger) backup.Config {
	return backup.Config{
		Audit:    audit.New(clk),
		Clock:    clk,
		Dir:      cfg.BackupDir,
		KeysDir:  cfg.KeysDir,
		StateDir: cfg.StateDir,
		Version:  version.Get().Version,
		Log:      log,
		Zone:     cfg.TZ,
	}
}

// newFlags is a flag set whose errors go to stderr after the command's usage text.
func newFlags(name, usage string, stderr io.Writer) *flag.FlagSet {
	fs := flag.NewFlagSet(name, flag.ContinueOnError)
	fs.SetOutput(stderr)
	fs.Usage = func() { fmt.Fprintln(stderr, usage) }
	return fs
}

// parseWithFile parses args holding exactly one positional FILE, before or after the flags.
func parseWithFile(fs *flag.FlagSet, args []string) (string, bool) {
	var file string
	if len(args) > 0 && !strings.HasPrefix(args[0], "-") {
		file, args = args[0], args[1:]
	}
	if err := fs.Parse(args); err != nil {
		return "", false
	}
	if file == "" && fs.NArg() == 1 {
		return fs.Arg(0), true
	}
	if file == "" || fs.NArg() != 0 {
		fs.Usage()
		return "", false
	}
	return file, true
}

func runBackup(args []string, cfg config.Config, stdin io.Reader, stdout, stderr io.Writer) int {
	if len(args) > 0 {
		switch args[0] {
		case "list":
			return runBackupList(args[1:], cfg, stdout, stderr)
		case "verify":
			return runBackupVerify(args[1:], cfg, stdin, stdout, stderr)
		}
	}
	fs := newFlags("backup", usageBackup, stderr)
	out := fs.String("out", "", "")
	reason := fs.String("reason", "", "")
	if err := fs.Parse(args); err != nil || fs.NArg() != 0 {
		if err == nil {
			fs.Usage()
		}
		return 2
	}
	in := backup.CreateInput{Kind: backup.KindManual, Reason: *reason, Actor: audit.SystemActor(cliActor)}
	if strings.HasPrefix(*reason, preUpgradePrefix) {
		// §20.1 step 3: the kind names the version that made the backup; the reason (the target version) stays in the
		// manifest. A build without a release version makes a manual backup instead.
		if k := backup.Kind(preUpgradePrefix + version.Get().Version); backup.ValidKind(k) {
			in.Kind = k
		}
	}
	if *out != "" {
		name, ok := outName(*out, cfg.BackupDir)
		if !ok {
			fmt.Fprintf(stderr, "The backup file must be in %s (ALICE_BACKUP_DIR).\n", cfg.BackupDir)
			return 2
		}
		if !backup.ValidName(name) {
			fmt.Fprintln(stderr, "The backup file name must end in .alicebak and must not start with a dot.")
			return 2
		}
		in.Out = name
	}
	ctx, stop := commandContext()
	defer stop()
	return withServicesCtx(ctx, cfg, stderr, func(ctx context.Context, svc *services) int {
		info, err := svc.backup.Create(ctx, in)
		switch {
		case errors.Is(err, backup.ErrRunning):
			fmt.Fprintln(stderr, msgRunning)
			return 1
		case errors.Is(err, backup.ErrNotConfigured):
			fmt.Fprintln(stderr, msgNotConfigured)
			return 1
		case err != nil:
			fmt.Fprintln(stderr, "The backup failed:", err)
			return 1
		}
		fmt.Fprintf(stdout, "Backup written: %s (%s MiB)\n", info.Path, mib(info.Size))
		return 0
	})
}

// outName returns the file name of --out when the path is directly inside dir.
func outName(out, dir string) (string, bool) {
	abs, err := filepath.Abs(out)
	if err != nil {
		return "", false
	}
	d, err := filepath.Abs(dir)
	if err != nil || filepath.Dir(abs) != d {
		return "", false
	}
	return filepath.Base(abs), true
}

// mib formats a size in MiB with one decimal.
func mib(n int64) string { return fmt.Sprintf("%.1f", float64(n)/(1<<20)) }

func runBackupList(args []string, cfg config.Config, stdout, stderr io.Writer) int {
	if len(args) != 0 {
		fmt.Fprintln(stderr, usageBackup)
		return 2
	}
	svc := backup.New(backupConfig(cfg, newClock(), slog.New(slog.DiscardHandler)))
	list, err := svc.List(context.Background())
	if err != nil {
		fmt.Fprintln(stderr, "The backups could not be listed:", err)
		return 1
	}
	tw := tabwriter.NewWriter(stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintln(tw, "NAME\tKIND\tSIZE\tCREATED (UTC)\tALICE\tCHECK")
	for _, b := range list {
		created, kind, alice := "-", string(b.Kind), b.AliceVersion
		if !b.CreatedAt.IsZero() {
			created = b.CreatedAt.UTC().Format("2006-01-02 15:04")
		}
		if kind == "" {
			kind = "-"
		}
		if alice == "" {
			alice = "-"
		}
		check := b.Check
		if b.Code != "" {
			check += " (" + b.Code + ")"
		}
		fmt.Fprintf(tw, "%s\t%s\t%s MiB\t%s\t%s\t%s\n", b.Name, kind, mib(b.Size), created, alice, check)
	}
	if err := tw.Flush(); err != nil {
		return 1
	}
	return 0
}

func runBackupVerify(args []string, cfg config.Config, stdin io.Reader, stdout, stderr io.Writer) int {
	fs := newFlags("backup verify", usageBackup, stderr)
	deep := fs.Bool("deep", false, "")
	fromStdin := fs.Bool("passphrase-stdin", false, "")
	file, ok := parseWithFile(fs, args)
	if !ok {
		return 2
	}
	svc := backup.New(backupConfig(cfg, newClock(), slog.New(slog.DiscardHandler)))
	if !*deep {
		return shallowVerify(svc, file, stdout, stderr)
	}
	src, ok := newPassphraseSource(*fromStdin, bufio.NewReader(orEmpty(stdin)), stdin, stderr)
	if !ok {
		fmt.Fprintln(stderr, msgPassphraseNeeded)
		return 2
	}
	pass, err := src.read()
	if err != nil {
		fmt.Fprintln(stderr, "The passphrase could not be read:", err)
		return 2
	}
	defer clear(pass)
	m, err := svc.VerifyDeep(context.Background(), file, pass)
	switch {
	case errors.Is(err, format.ErrNotBackup):
		fmt.Fprintln(stderr, msgNotBackup)
		return 1
	case errors.Is(err, format.ErrNewerFormat):
		fmt.Fprintln(stderr, msgNewerUnknown)
		return 1
	case errors.Is(err, backup.ErrDamaged):
		fmt.Fprintln(stderr, msgDamaged)
		return 1
	case err != nil:
		fmt.Fprintln(stderr, "The backup file could not be read:", err)
		return 1
	}
	fmt.Fprintf(stdout, "The backup opens with this passphrase and is complete: %s.\n", manifestLine(m))
	return 0
}

// shallowVerify is backup verify without --deep (R43 row 4).
func shallowVerify(svc *backup.Service, file string, stdout, stderr io.Writer) int {
	info, err := svc.Verify(context.Background(), file)
	switch {
	case errors.Is(err, backup.ErrNotFound):
		fmt.Fprintf(stderr, "There is no backup file %s.\n", file)
		return 1
	case err != nil:
		fmt.Fprintln(stderr, "The backup file could not be read:", err)
		return 1
	}
	switch info.Check {
	case backup.CheckOK:
		fmt.Fprintln(stdout, msgShallowOK)
		return 0
	case backup.CheckMissingChecksum:
		fmt.Fprintf(stderr, "The checksum file %s%s is missing, so the file can only be checked with the passphrase (--deep).\n",
			info.Name, backup.ChecksumExt)
	case backup.CheckUnreadableHeader:
		fmt.Fprintln(stderr, headerProblem(file))
	default:
		fmt.Fprintln(stderr, msgDamaged)
	}
	return 1
}

// headerProblem tells a foreign file and a newer format from a damaged backup.
func headerProblem(file string) string {
	f, err := os.Open(file) //nolint:gosec // G304: the backup file the operator named
	if err != nil {
		return msgDamaged
	}
	defer func() { _ = f.Close() }()
	_, err = format.ReadHeader(bufio.NewReader(f))
	switch {
	case errors.Is(err, format.ErrNotBackup):
		return msgNotBackup
	case errors.Is(err, format.ErrNewerFormat):
		return msgNewerUnknown
	}
	return msgDamaged
}

// manifestLine is C7's description of a backup, without the final period.
func manifestLine(m backup.Manifest) string {
	return fmt.Sprintf("Backup from %s UTC, Alice %s, host %s, installation %s", m.CreatedAt.UTC().Format("2006-01-02 15:04"),
		m.AliceVersion, m.Hostname, m.InstallationID)
}

// orEmpty is stdin, or an empty reader when a caller passed none.
func orEmpty(r io.Reader) io.Reader {
	if r == nil {
		return strings.NewReader("")
	}
	return r
}
