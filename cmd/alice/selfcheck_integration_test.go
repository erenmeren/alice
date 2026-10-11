//go:build integration

package main

import (
	"encoding/base64"
	"log/slog"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/stdlib"
	"github.com/pressly/goose/v3"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"alice/internal/platform/db"
	"alice/internal/platform/settings"
	"alice/internal/platform/tlscert"
	"alice/migrations"
)

// selfcheckOK are C9's seven lines of a healthy installation, in order.
var selfcheckOK = []*regexp.Regexp{
	regexp.MustCompile(`^\[ OK \] Database reachable$`),
	regexp.MustCompile(`^\[ OK \] Database schema is current \(version [0-9]+\)$`),
	regexp.MustCompile(`^\[ OK \] Master key opens the stored key check$`),
	regexp.MustCompile(`^\[ OK \] Audit log intact \([0-9]+ entries, head [0-9a-f]{16}\)$`),
	regexp.MustCompile(`^\[ OK \] License readable \(evaluation\)$`),
	regexp.MustCompile(`^\[ OK \] HTTPS listener answers with the installed certificate$`),
	regexp.MustCompile(`^\[ OK \] Background jobs running \(last heartbeat [0-9]{2}:[0-9]{2} UTC\)$`),
}

// listening gives the installation a listener address and a health address of its own.
func (i *cliInstall) listening() {
	i.vars["ALICE_LISTEN_ADDR"] = freeAddr(i.t)
	i.vars["ALICE_HEALTH_ADDR"] = freeAddr(i.t)
}

func (i *cliInstall) serve() func() {
	i.t.Helper()
	_, stop := runServe(i.t, i.config())
	return stop
}

func requireHealthy(t *testing.T, code int, out, errOut string) {
	t.Helper()
	lines := strings.Split(strings.TrimSuffix(out, "\n"), "\n")
	require.Len(t, lines, len(selfcheckOK), out+errOut)
	for n, re := range selfcheckOK {
		assert.Regexp(t, re, lines[n])
	}
	assert.Equal(t, 0, code, out+errOut)
}

func TestSelfcheckOnARunningInstallation(t *testing.T) {
	i := newCLIInstall(t)
	i.listening()
	stop := i.serve()
	defer stop()
	start := time.Now()
	code, out, errOut := i.run("", "selfcheck")
	requireHealthy(t, code, out, errOut)
	assert.Less(t, time.Since(start), 30*time.Second, "no wait for a scheduler tick")
	assert.Zero(t, i.count("SELECT count(*) FROM audit_log WHERE action LIKE 'audit.%'"), "selfcheck writes no audit row")
}

// M-3: a restored database carries an old heartbeat; a process that just started writes its first at once.
func TestSelfcheckPassesRightAfterStartAndAfterRestore(t *testing.T) {
	i := newCLIInstall(t)
	i.listening()
	stale := time.Now().UTC().Add(-2 * time.Hour)
	require.NoError(t, settings.Set(i.ctx, i.d.Owner, heartbeatKey, heartbeat{At: stale}, stale))
	path := i.backup() // the backup carries the stale heartbeat

	stop := i.serve()
	code, out, errOut := i.run("", "selfcheck")
	requireHealthy(t, code, out, errOut)
	stop()

	code, _, errOut = i.restore(cliPassphrase+"\n", path, "--passphrase-stdin", "--confirm", "RESTORE", "--wait-for-sessions", "0s")
	require.Equal(t, 0, code, errOut)
	var hb heartbeat
	_, err := settings.Get(i.ctx, i.d.Owner, heartbeatKey, &hb)
	require.NoError(t, err)
	assert.WithinDuration(t, stale, hb.At, time.Second, "the restored database has the old heartbeat")
	stop = i.serve()
	defer stop()
	code, out, errOut = i.run("", "selfcheck")
	requireHealthy(t, code, out, errOut)
}

func TestSelfcheckReportsEachFailure(t *testing.T) {
	oldWait, oldPoll := heartbeatWait, heartbeatPoll
	heartbeatWait, heartbeatPoll = time.Second, 200*time.Millisecond
	t.Cleanup(func() { heartbeatWait, heartbeatPoll = oldWait, oldPoll })
	failLine := func(t *testing.T, i *cliInstall, prefix string) string {
		t.Helper()
		code, out, _ := i.run("", "selfcheck")
		assert.Equal(t, 1, code, out)
		for _, l := range strings.Split(out, "\n") {
			if strings.HasPrefix(l, prefix) {
				return l
			}
		}
		t.Fatalf("no line %q in:\n%s", prefix, out)
		return ""
	}

	t.Run("database stopped", func(t *testing.T) {
		i := newCLIInstall(t)
		i.listening()
		i.vars["ALICE_DATABASE_URL"] = "postgres://alice_app:x@" + freeAddr(t) + "/alice?connect_timeout=1"
		assert.Regexp(t, `^\[FAIL\] Database reachable: .+`, failLine(t, i, "[FAIL] Database reachable"))
	})
	t.Run("schema one behind", func(t *testing.T) {
		i := newCLIInstall(t)
		i.listening()
		latest, err := db.LatestVersion(migrations.FS)
		require.NoError(t, err)
		// 00012's down migration refuses while a sender key exists.
		_, err = i.d.Owner.Exec(i.ctx, "DELETE FROM setting_secrets WHERE key = 'backup.sender'")
		require.NoError(t, err)
		p, err := goose.NewProvider(goose.DialectPostgres, stdlib.OpenDBFromPool(i.d.Owner), migrations.FS)
		require.NoError(t, err)
		_, err = p.DownTo(i.ctx, latest-1)
		require.NoError(t, err)
		assert.Regexp(t, `^\[FAIL\] Database schema is current \(version [0-9]+\): this Alice needs version [0-9]+$`,
			failLine(t, i, "[FAIL] Database schema is current"))
	})
	t.Run("another master key", func(t *testing.T) {
		i := newCLIInstall(t)
		i.listening()
		key := filepath.Join(i.keys, "master.key")
		require.NoError(t, os.Remove(key))
		require.NoError(t, os.WriteFile(key, []byte(base64.StdEncoding.EncodeToString(make([]byte, 32))+"\n"), 0o400))
		assert.Regexp(t, `^\[FAIL\] Master key opens the stored key check: .*does not match`, failLine(t, i, "[FAIL] Master key"))
		assert.Regexp(t, `^\[FAIL\] License readable: `, failLine(t, i, "[FAIL] License readable"))
	})
	t.Run("audit row changed", func(t *testing.T) {
		i := newCLIInstall(t)
		i.listening()
		conn, err := i.d.Owner.Acquire(i.ctx)
		require.NoError(t, err)
		for _, q := range []string{"SET session_replication_role = replica",
			`UPDATE audit_log SET details = '{"changed":"yes"}' WHERE seq = (SELECT max(seq) FROM audit_log)`, "RESET session_replication_role"} {
			_, err = conn.Exec(i.ctx, q)
			require.NoError(t, err)
		}
		conn.Release()
		assert.Regexp(t, `^\[FAIL\] Audit log intact: damaged at entry [0-9]+`, failLine(t, i, "[FAIL] Audit log intact"))
	})
	t.Run("no listener", func(t *testing.T) {
		i := newCLIInstall(t)
		i.listening()
		_, err := tlscert.EnsureSelfSigned(i.keys, []string{"localhost"}, time.Now())
		require.NoError(t, err)
		assert.Regexp(t, `^\[FAIL\] HTTPS listener answers with the installed certificate: no TLS answer on 127\.0\.0\.1:[0-9]+`,
			failLine(t, i, "[FAIL] HTTPS listener"))
	})
	t.Run("certificate replaced on disk", func(t *testing.T) {
		i := newCLIInstall(t)
		i.listening()
		stop := i.serve()
		defer stop()
		other := t.TempDir()
		_, err := tlscert.EnsureSelfSigned(other, []string{"localhost"}, time.Now())
		require.NoError(t, err)
		crt, err := os.ReadFile(filepath.Join(other, "tls.crt"))
		require.NoError(t, err)
		require.NoError(t, os.WriteFile(filepath.Join(i.keys, "tls.crt"), crt, 0o644))
		assert.Equal(t, "[FAIL] HTTPS listener answers with the installed certificate: the listener presents another certificate than tls.crt",
			failLine(t, i, "[FAIL] HTTPS listener"))
	})
	t.Run("heartbeat too old", func(t *testing.T) {
		i := newCLIInstall(t)
		i.listening()
		old := time.Now().UTC().Add(-6 * time.Minute)
		require.NoError(t, settings.Set(i.ctx, i.d.Owner, heartbeatKey, heartbeat{At: old}, old))
		start := time.Now()
		assert.Equal(t, "[FAIL] Background jobs running: the last heartbeat was at "+old.Format("2006-01-02 15:04")+" UTC",
			failLine(t, i, "[FAIL] Background jobs running"))
		assert.GreaterOrEqual(t, time.Since(start), 800*time.Millisecond, "the heartbeat line waits before it fails")
	})
	t.Run("heartbeat in the future", func(t *testing.T) {
		i := newCLIInstall(t)
		i.listening()
		ahead := time.Now().UTC().Add(10 * time.Minute)
		require.NoError(t, settings.Set(i.ctx, i.d.Owner, heartbeatKey, heartbeat{At: ahead}, ahead))
		assert.Equal(t, "[FAIL] Background jobs running: the last heartbeat is dated in the future ("+ahead.Format("2006-01-02 15:04")+
			" UTC); check the system clock", failLine(t, i, "[FAIL] Background jobs running"))
	})
	t.Run("no heartbeat", func(t *testing.T) {
		i := newCLIInstall(t)
		i.listening()
		assert.Equal(t, "[FAIL] Background jobs running: no heartbeat was recorded", failLine(t, i, "[FAIL] Background jobs running"))
	})
}

// The tls.renew task renews Alice's temporary certificate when it is due and audits it https.temporary_renewed.
func TestRenewCertificateAuditsTheRenewal(t *testing.T) {
	i := newCLIInstall(t)
	svc := i.services()
	now := time.Now()
	clk := func() time.Time { return now }
	store, err := tlscert.NewStore(i.keys, []string{"localhost"}, clk)
	require.NoError(t, err)
	svc.tlsStore = store
	log := slog.New(slog.DiscardHandler)
	require.NoError(t, renewCertificate(i.ctx, svc, log))
	assert.Zero(t, i.count("SELECT count(*) FROM audit_log WHERE action = 'https.temporary_renewed'"), "not due yet")

	before := store.Info()
	now = before.NotAfter.Add(-24 * time.Hour)
	require.NoError(t, renewCertificate(i.ctx, svc, log))
	after := store.Info()
	assert.NotEqual(t, before.FingerprintSHA256, after.FingerprintSHA256)
	assert.Equal(t, 1, i.count(`SELECT count(*) FROM audit_log WHERE action = 'https.temporary_renewed' AND actor_name = 'scheduler'
		AND details->>'fingerprint' = $1`, after.FingerprintSHA256))
}
