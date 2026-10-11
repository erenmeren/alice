package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"alice/internal/backup"
	"alice/internal/backup/format"
	"alice/internal/platform/clock"
	"alice/internal/platform/config"
	"alice/internal/platform/netaddr"
)

// C6: one line of at most 1,024 bytes; exactly one trailing newline is removed and nothing else.
func TestReadLineTakesThePassphraseAsTyped(t *testing.T) {
	for in, want := range map[string]string{
		"secret\n": "secret", "secret": "secret", " secret \n": " secret ", "secret\r\n": "secret\r", "\n": "", "": "",
		"a\nb\n": "a", strings.Repeat("x", 1024) + "\n": strings.Repeat("x", 1024), strings.Repeat("x", 1024): strings.Repeat("x", 1024),
	} {
		got, err := readLine(bufio.NewReaderSize(strings.NewReader(in), 16), maxPassphraseBytes)
		require.NoError(t, err, "%q", in)
		assert.Equal(t, want, string(got), "%q", in)
	}
	for _, in := range []string{strings.Repeat("x", 1025), strings.Repeat("x", 1025) + "\n", strings.Repeat("x", 5000) + "\n"} {
		_, err := readLine(bufio.NewReaderSize(strings.NewReader(in), 16), maxPassphraseBytes)
		assert.ErrorIs(t, err, errPassphraseTooLong)
	}
	// The confirmation line follows the passphrase on the same reader.
	r := bufio.NewReader(strings.NewReader("pass\nRESTORE\n"))
	p, err := readLine(r, maxPassphraseBytes)
	require.NoError(t, err)
	c, err := readLine(r, maxConfirmLineBytes)
	require.NoError(t, err)
	assert.Equal(t, "pass", string(p))
	assert.Equal(t, "RESTORE", string(c))
}

func TestPassphraseSourceNeedsStdinOrATerminal(t *testing.T) {
	_, ok := newPassphraseSource(false, nil, strings.NewReader("x\n"), &bytes.Buffer{})
	assert.False(t, ok, "a pipe without --passphrase-stdin is no source")
	src, ok := newPassphraseSource(true, bufio.NewReader(strings.NewReader("x\n")), nil, &bytes.Buffer{})
	require.True(t, ok)
	p, err := src.read()
	require.NoError(t, err)
	assert.Equal(t, "x", string(p))
}

func TestOutName(t *testing.T) {
	for out, want := range map[string]string{"/opt/alice/backups/a.alicebak": "a.alicebak", "/opt/alice/backups/../backups/b.alicebak": "b.alicebak"} {
		got, ok := outName(out, "/opt/alice/backups")
		assert.True(t, ok, out)
		assert.Equal(t, want, got)
	}
	for _, out := range []string{"/tmp/x.alicebak", "/opt/alice/backups/sub/x.alicebak", "/opt/alice/x.alicebak"} {
		_, ok := outName(out, "/opt/alice/backups")
		assert.False(t, ok, out)
	}
}

func TestMiB(t *testing.T) {
	assert.Equal(t, "0.0", mib(0))
	assert.Equal(t, "1.5", mib(3<<19))
}

// Every restore error has its C7 sentence and exit code 1.
func TestRestoreErrorMessages(t *testing.T) {
	cases := map[string]error{
		"This is not an Alice backup.": format.ErrNotBackup,
		"This backup was created by a newer Alice version (1.2.0). Install Alice 1.2.0 or newer, then restore.": &backup.ErrNewer{Version: "1.2.0"},
		msgNewerUnknown: &backup.ErrNewer{},
		"The passphrase is wrong or the file is damaged. Nothing was changed.":          fmt.Errorf("x: %w", backup.ErrDamaged),
		"The backup could not be verified (the key check failed). Nothing was changed.": &backup.ErrNotVerified{Reason: "the key check failed"},
		"Restore cancelled. Nothing was changed.":                                       backup.ErrCancelled,
		msgNoSafetyBackup: backup.ErrNoSafetyBackup,
		"Not enough free disk space for a restore: 1 GB free, 4 GB needed.": &backup.ErrNoSpace{Free: 1_500_000_000, Need: 3_200_000_000},
		"Alice is still connected to the database. Stop it first.":          backup.ErrDatabaseInUse,
		"There is no backup file at that path.":                             backup.ErrNotFound,
		"The audit log in this backup is damaged at entry 7. Nothing was changed. To restore it anyway, run the command again with --accept-broken-audit-log (the damage stays visible in Alice).": &backup.ErrAuditBroken{Seq: 7},
		"The restore failed: boom":                           errors.New("boom"),
		"Another restore is running. Wait for it to finish.": backup.ErrRestoreRunning,
		"ALICE_KEYS_DIR and ALICE_STATE_DIR must be two different directories. Nothing was changed.":                                                                                                                  backup.ErrSameDirectory,
		"An interrupted restore left an unverified copy of the database (<database>_restore) and no live database. Nothing was changed. Drop that copy by hand (see the operator guide), then run the restore again.": backup.ErrUnfinishedStaging,
	}
	for want, err := range cases {
		msg, code := restoreError(err)
		assert.Equal(t, want, msg)
		assert.Equal(t, 1, code)
	}
}

func TestManifestLineAndCheckLines(t *testing.T) {
	m := backup.Manifest{CreatedAt: time.Date(2026, 10, 10, 2, 30, 59, 0, time.UTC), AliceVersion: "1.0.0", Hostname: "srv1",
		InstallationID: "ALICE-7F3K-92QD-AAAA-BBBB"}
	assert.Equal(t, "Backup from 2026-10-10 02:30 UTC, Alice 1.0.0, host srv1, installation ALICE-7F3K-92QD-AAAA-BBBB", manifestLine(m))
	assert.Equal(t, "[ OK ] Database reachable", checkLine{Label: "Database reachable", OK: true}.String())
	assert.Equal(t, "[FAIL] Database reachable: refused", checkLine{Label: "Database reachable", Reason: "refused"}.String())
}

func TestBackupCommandUsage(t *testing.T) {
	for _, args := range [][]string{{"backup", "extra"}, {"backup", "list", "x"}, {"backup", "verify"}, {"backup", "verify", "a", "b"},
		{"backup", "--nope"}, {"selfcheck", "x"}, {"support-bundle", "x"}} {
		var out, errOut bytes.Buffer
		assert.Equal(t, 2, run(args, env(nil), nil, &out, &errOut), args)
		assert.Contains(t, errOut.String(), "usage: alice", args)
	}
}

// C10: the forwarder dials through netaddr's address rule and names itself after the first ALICE_TLS_HOSTS name.
func TestForwardConfigIsTheProductionOne(t *testing.T) {
	svc := wiringServices(t)
	cfg := forwardConfig(config.Config{TLSHosts: []string{"alice.example.com", "other"}}, svc, clock.Real{}, slog.New(slog.DiscardHandler))
	assert.Equal(t, "alice.example.com", cfg.Hostname)
	assert.Equal(t, "alice", cfg.AppName)
	assert.Nil(t, cfg.RootCAs, "the system roots plus the configured CA")
	require.NotNil(t, cfg.Dial)
	_, err := cfg.Dial(context.Background(), "tcp", "169.254.169.254:6514")
	assert.ErrorIs(t, err, netaddr.ErrNotAllowed, "the metadata address is refused before any packet")
	host, err := os.Hostname()
	require.NoError(t, err)
	assert.Equal(t, host, forwardHostname(config.Config{}))
}

// Without a database, selfcheck fails every database line at once and still checks the listener; the support
// bundle still prints, naming the section it could not read.
func TestSelfcheckAndSupportBundleWithoutADatabase(t *testing.T) {
	vars := env(map[string]string{"ALICE_KEYS_DIR": t.TempDir()})
	var out, errOut bytes.Buffer
	assert.Equal(t, 1, run([]string{"selfcheck"}, vars, nil, &out, &errOut))
	lines := strings.Split(strings.TrimSuffix(out.String(), "\n"), "\n")
	require.Len(t, lines, 7, out.String())
	assert.True(t, strings.HasPrefix(lines[0], "[FAIL] Database reachable: ALICE_DATABASE_URL is not set"), lines[0])
	assert.Equal(t, "[FAIL] Background jobs running: the database is not reachable", lines[6])
	assert.True(t, strings.HasPrefix(lines[5], "[FAIL] HTTPS listener answers with the installed certificate: read tls.crt"), lines[5])

	out.Reset()
	require.Equal(t, 0, run([]string{"support-bundle"}, vars, nil, &out, &errOut), errOut.String())
	var b map[string]any
	require.NoError(t, json.Unmarshal(out.Bytes(), &b))
	assert.Equal(t, []any{"database: the database is not reachable"}, b["errors"])
	assert.Len(t, b["selfcheck"], 7)
}

// The owner check refuses only a role proven not to own the database; anything else is left to the restore (M-1).
func TestCheckOwnerRoleLeavesOtherErrorsToTheRestore(t *testing.T) {
	ctx := context.Background()
	var notOwner *errNotOwner
	err := checkOwnerRole(ctx, "postgres://%zz")
	require.Error(t, err)
	assert.False(t, errors.As(err, &notOwner))
	err = checkOwnerRole(ctx, "postgres://alice_owner:pw@127.0.0.1:1/alice?connect_timeout=2")
	require.Error(t, err, "nothing listens on port 1")
	assert.False(t, errors.As(err, &notOwner))
	assert.Equal(t, "role alice_app does not own database alice", (&errNotOwner{role: "alice_app", database: "alice"}).Error())
}

// A failed owner check that is not a refusal lets the restore run and report the problem in its own words.
func TestRestoreRunsWhenTheOwnerCheckCannotDecide(t *testing.T) {
	old, oldCheck := restoreFunc, ownerCheckFunc
	t.Cleanup(func() { restoreFunc, ownerCheckFunc = old, oldCheck })
	ownerCheckFunc = func(context.Context, string) error { return errors.New("unreachable") }
	restoreFunc = func(context.Context, backup.Config, backup.RestoreInput) (backup.RestoreResult, error) {
		return backup.RestoreResult{}, errors.New("connect: unreachable")
	}
	vars := env(map[string]string{"ALICE_DATABASE_URL": "postgres://alice_app@db/alice", "ALICE_MIGRATE_DATABASE_URL": "postgres://alice_owner@db/alice"})
	var out, errOut bytes.Buffer
	assert.Equal(t, 1, run([]string{"restore", "/b/x.alicebak", "--passphrase-stdin", "--confirm", "RESTORE"}, vars,
		strings.NewReader("p\n"), &out, &errOut))
	assert.Equal(t, "The restore failed: connect: unreachable\n", errOut.String())
}
