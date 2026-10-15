//go:build integration

package main

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"alice/internal/license"
	"alice/internal/license/issuer"
	"alice/internal/platform/clock"
	"alice/internal/platform/db"
	"alice/internal/vconsole/audit"
	"alice/internal/vconsole/vpgtest"
)

// opsEnv is a notifyEnv with one license key, and a run helper that checks that no output ever
// contains a database URL or a password.
type opsEnv struct {
	*notifyEnv
	prefix           string
	keyPath, pubPath string
}

func newOpsEnv(t *testing.T, prefix string) *opsEnv {
	t.Helper()
	e := &opsEnv{notifyEnv: newNotifyEnv(t, prefix), prefix: prefix}
	dir := t.TempDir()
	priv, pub, err := issuer.GenerateKey("vk-2026-01", []byte(words), issuer.KDFParams{MemoryKiB: 64, Time: 1, Threads: 1})
	require.NoError(t, err)
	e.keyPath, e.pubPath = filepath.Join(dir, "key.pem"), filepath.Join(dir, "pub.pem")
	require.NoError(t, os.WriteFile(e.keyPath, priv, 0o600))
	require.NoError(t, os.WriteFile(e.pubPath, pub, 0o600))
	return e
}

func (e *opsEnv) login(kind string) string { return e.prefix + "_" + kind }

// run is do with the secret checks: no URL and no database password in any output.
func (e *opsEnv) run(kind string, args ...string) (string, string, int) {
	e.t.Helper()
	out, errOut, code := e.do(kind, clock.Real{}, args...)
	all := out + errOut
	for _, u := range e.urls {
		assert.NotContains(e.t, all, u, "%q", args)
	}
	assert.NotContains(e.t, all, vpgtest.AsPassword, "%q", args)
	assert.NotContains(e.t, all, "postgres://", "%q", args)
	assert.NotContains(e.t, all, "postgresql://", "%q", args)
	return out, errOut, code
}

// issue issues a license with the env's key as the superuser login and returns its ID.
func (e *opsEnv) issue(customer, installation string) string {
	t := e.t
	t.Helper()
	out, se, code := e.run("super", "customer", "add", "--name", customer)
	require.Equal(t, 0, code, se)
	cust := regexp.MustCompile(`\d+`).FindString(out)
	out, se, code = e.run("super", "request", "add", "--customer", cust, "--installation", installation, "--targets", "5")
	require.Equal(t, 0, code, se)
	reqID := regexp.MustCompile(`\d+`).FindString(out)
	out, se, code = e.run("super", "request", "show", reqID)
	require.Equal(t, 0, code, se)
	hash := regexp.MustCompile(`[0-9a-f]{64}`).FindString(out)
	out, se, code = e.run("super", "issue", "--request", reqID, "--hash", hash, "--key", e.keyPath,
		"--out", filepath.Join(t.TempDir(), "l.alicelic"))
	require.Equal(t, 0, code, se)
	id := regexp.MustCompile(`LIC-\d+-\d+`).FindString(out)
	require.NotEmpty(t, id, out)
	return id
}

// replica runs sql behind the triggers, as a superuser or a damaged restore could.
func (e *opsEnv) replica(sql string, args ...any) {
	e.t.Helper()
	ctx := context.Background()
	require.NoError(e.t, db.InTx(ctx, e.d.Owner, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, `SET LOCAL session_replication_role = replica`); err != nil {
			return err
		}
		_, err := tx.Exec(ctx, sql, args...)
		return err
	}))
}

func lines(s string) []string {
	s = strings.TrimRight(s, "\n")
	if s == "" {
		return nil
	}
	return strings.Split(s, "\n")
}

var hexHash = regexp.MustCompile(`[0-9a-f]{64}`)

func TestAuditHeadAndVerifyHead(t *testing.T) {
	e := newOpsEnv(t, "ah")
	if e.count("audit") == 0 {
		out, se, code := e.run("owner", "audit-head")
		require.Equal(t, 0, code, se)
		assert.Equal(t, "empty\n", out)
	}
	e.issue("Acme", license.NewInstallationID())
	out, se, code := e.run("owner", "audit-head")
	require.Equal(t, 0, code, se)
	old, err := audit.ParseHead(strings.TrimSpace(out))
	require.NoError(t, err, out)

	// The notifier may read the head too (it puts it in the weekly summary); a sales login may not.
	out2, se, code := e.run("notifier", "audit-head")
	require.Equal(t, 0, code, se)
	assert.Equal(t, out, out2)
	_, se, code = e.run("sales", "audit-head")
	assert.Equal(t, 1, code)
	assert.Contains(t, se, "permission denied: audit-head needs the owner login or a login in vendor_notifier")

	// Later rows do not disturb an older checkpoint.
	e.issue("Beta", license.NewInstallationID())
	out, se, code = e.run("owner", "audit-verify", "--head", old.String())
	require.Equal(t, 0, code, se+out)
	assert.Equal(t, fmt.Sprintf("audit chain OK; checkpoint %d found\n", old.Seq), out, "the full hash keeps its line")
	// The sequence with the first 16 or more hex digits passes too and says how many were checked.
	for _, n := range []int{16, 40} {
		out, se, code = e.run("owner", "audit-verify", "--head", fmt.Sprintf("Audit head: %d:%s", old.Seq, old.Hash[:n]))
		require.Equal(t, 0, code, se+out)
		assert.Equal(t, fmt.Sprintf("audit chain OK; checkpoint %d found (first %d hex digits only; the full hash is a stronger check)\n",
			old.Seq, n), out)
	}
	// A prefix that differs is a mismatch, with the same output as a full hash.
	wrong := old.Hash[:15] + map[bool]string{true: "1", false: "0"}[old.Hash[15] == '0']
	out, _, code = e.run("owner", "audit-verify", "--head", fmt.Sprintf("%d:%s", old.Seq, wrong))
	assert.Equal(t, 1, code)
	assert.Equal(t, fmt.Sprintf("audit checkpoint MISMATCH: row %d is missing or is not the row of checkpoint %d:%s; "+
		"audit rows were removed or replaced after the checkpoint was taken\n", old.Seq, old.Seq, wrong), out)
	// Fewer than 16 hex digits are refused before the database.
	_, se, code = e.run("owner", "audit-verify", "--head", fmt.Sprintf("%d:%s", old.Seq, old.Hash[:15]))
	assert.Equal(t, 2, code)
	assert.Contains(t, se, "at least 16 hex digits")
	// Upper case hex is accepted.
	upper := strings.Map(func(r rune) rune {
		if r >= 'a' && r <= 'f' {
			return r - 'a' + 'A'
		}
		return r
	}, old.String())
	_, se, code = e.run("owner", "audit-verify", "--head", upper)
	assert.Equal(t, 0, code, se)

	// A sales login may not verify.
	_, se, code = e.run("sales", "audit-verify", "--head", old.String())
	assert.Equal(t, 1, code)
	assert.Contains(t, se, "permission denied")

	// Remove the checkpoint row and everything after it: the chain still verifies, the checkpoint does not.
	e.replica(`DELETE FROM audit WHERE seq >= $1`, old.Seq)
	_, se, code = e.run("owner", "audit-verify")
	require.Equal(t, 0, code, se, "the shortened chain is intact on its own")
	out, se, code = e.run("owner", "audit-verify", "--head", old.String())
	assert.Equal(t, 1, code)
	assert.Contains(t, out, "MISMATCH")
	for _, h := range hexHash.FindAllString(out+se, -1) {
		assert.Equal(t, old.Hash, h, "no hash but the one given is printed")
	}

	// A head with a seq the chain never reached is a mismatch too.
	_, _, code = e.run("owner", "audit-verify", "--head", "999999:"+old.Hash)
	assert.Equal(t, 1, code)
	out, _, code = e.run("owner", "audit-verify", "--head", fmt.Sprintf("%d:%s", old.Seq, old.Hash[:16]))
	assert.Equal(t, 1, code, "a prefix of a removed row is a mismatch")
	assert.Contains(t, out, "MISMATCH")
	// A malformed head is a usage error.
	_, _, code = e.run("owner", "audit-verify", "--head", "1:xyz")
	assert.Equal(t, 2, code)
}

func TestAuditHeadPrintsEmptyOnAnEmptyAuditTable(t *testing.T) {
	e := newOpsEnv(t, "ae")
	e.issue("Acme", license.NewInstallationID())
	require.NotZero(t, e.count("audit"))
	e.replica(`DELETE FROM audit`)
	require.Zero(t, e.count("audit"))
	for _, kind := range []string{"owner", "notifier"} {
		out, se, code := e.run(kind, "audit-head")
		require.Equal(t, 0, code, se)
		assert.Equal(t, "empty\n", out)
	}
}

func TestAuditShow(t *testing.T) {
	e := newOpsEnv(t, "as")
	inst := license.NewInstallationID()
	lic := e.issue("Acme", inst)
	_, se, code := e.run("owner", "settings", "set", "timezone", "Europe/Berlin")
	require.Equal(t, 0, code, se)
	// A hostile subject, written as a superuser could.
	_, err := e.d.Owner.Exec(context.Background(), `SELECT audit_append('test.evil', E'x\x1b[2Jy\u202ez', '{}'::jsonb)`)
	require.NoError(t, err)
	total := e.count("audit")

	out, se, code := e.run("owner", "audit", "show")
	require.Equal(t, 0, code, se)
	rows := lines(out)
	require.Len(t, rows, min(total, 50))
	var prev int64 = 1 << 62
	lineRE := regexp.MustCompile(`^(\d+) (\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ) (\S+) (\S+) (.*)$`)
	for _, l := range rows {
		m := lineRE.FindStringSubmatch(l)
		require.NotNil(t, m, l)
		seq, err := strconv.ParseInt(m[1], 10, 64)
		require.NoError(t, err)
		assert.Less(t, seq, prev, "newest first")
		prev = seq
	}
	assert.NotContains(t, out, "\x1b")
	assert.NotContains(t, out, "\u202e")
	assert.Contains(t, rows[0], "test.evil x?[2Jyz", "ESC shown as ?, the bidi mark removed (format characters are stripped before the ID scan)")
	assert.NotContains(t, out, inst, "no installation ID without --details")

	// --actor filters.
	out, se, code = e.run("owner", "audit", "show", "--actor", e.login("owner"))
	require.Equal(t, 0, code, se)
	require.Len(t, lines(out), 1, out)
	assert.Contains(t, out, " settings.set timezone")

	// --action is a prefix, and wildcards are literal.
	out, se, code = e.run("owner", "audit", "show", "--action", "license.")
	require.Equal(t, 0, code, se)
	require.Len(t, lines(out), 1, out)
	assert.Contains(t, out, "license.issue "+lic)
	out, _, code = e.run("owner", "audit", "show", "--action", "licen%")
	assert.Equal(t, 0, code)
	assert.Empty(t, out)
	out, _, code = e.run("owner", "audit", "show", "--action", "_icense.")
	assert.Equal(t, 0, code)
	assert.Empty(t, out)

	// --limit is honoured.
	out, se, code = e.run("owner", "audit", "show", "--limit", "2")
	require.Equal(t, 0, code, se)
	assert.Len(t, lines(out), 2)

	// --since: nothing in the future.
	out, se, code = e.run("owner", "audit", "show", "--since", time.Now().UTC().AddDate(0, 0, 2).Format("2006-01-02"))
	require.Equal(t, 0, code, se)
	assert.Empty(t, out)
	out, _, _ = e.run("owner", "audit", "show", "--since", "2000-01-01")
	assert.Len(t, lines(out), min(total, 50))

	// --details shows the details with the installation ID as a fingerprint, no part of it.
	out, se, code = e.run("owner", "audit", "show", "--action", "license.issue", "--details")
	require.Equal(t, 0, code, se)
	assert.NotContains(t, out, inst)
	assert.Contains(t, out, `"installation":"`+installationFingerprint(inst)+`"`)
	all, _, _ := e.run("owner", "audit", "show", "--details", "--limit", "1000")
	assert.NotContains(t, all, inst[:9])
	assert.NotContains(t, all, strings.TrimPrefix(inst, "ALICE-")[:9])
	assert.Contains(t, out, `"targets":5`)

	// Only the owner reads the audit.
	for _, kind := range []string{"sales", "notifier"} {
		out, se, code = e.run(kind, "audit", "show")
		assert.Equal(t, 1, code, kind)
		assert.Contains(t, se, "permission denied", kind)
		assert.Empty(t, out, kind)
	}
}

func TestAuditShowCapsAtTheLimit(t *testing.T) {
	e := newOpsEnv(t, "al")
	_, err := e.d.Owner.Exec(context.Background(),
		`SELECT audit_append('test.bulk', g::text, '{}'::jsonb) FROM generate_series(1, 1005) g`)
	require.NoError(t, err)
	out, se, code := e.run("owner", "audit", "show", "--limit", "1000")
	require.Equal(t, 0, code, se)
	assert.Len(t, lines(out), 1000)
	out, _, _ = e.run("owner", "audit", "show")
	assert.Len(t, lines(out), 50)
	assert.True(t, strings.HasSuffix(lines(out)[0], "test.bulk 1005"), lines(out)[0])
}

func TestVerifyLicensesCommand(t *testing.T) {
	e := newOpsEnv(t, "vl")
	// An empty database may be legitimate: exit 0, with a warning to compare with expectations.
	out, se, code := e.run("owner", "verify-licenses", "--pub", e.pubPath)
	require.Equal(t, 0, code, se+out)
	assert.Equal(t, "checked 0, problems 0\n", out)
	assert.Contains(t, se, "WARNING: no licenses found")

	inst := license.NewInstallationID()
	a := e.issue("Acme", inst)
	e.issue("Beta", license.NewInstallationID())

	out, se, code = e.run("owner", "verify-licenses", "--pub", e.pubPath)
	require.Equal(t, 0, code, se+out)
	assert.Equal(t, "checked 2, problems 0\n", out)
	assert.Empty(t, se)

	// The same keys as a key set file (production.json format).
	pub, err := os.ReadFile(e.pubPath)
	require.NoError(t, err)
	k, err := issuer.ReadPublicKey(pub)
	require.NoError(t, err)
	ks, err := license.EncodeKeySet(k)
	require.NoError(t, err)
	ksPath := filepath.Join(t.TempDir(), "production.json")
	require.NoError(t, os.WriteFile(ksPath, ks, 0o600))
	out, se, code = e.run("sales", "verify-licenses", "--keyset", ksPath)
	require.Equal(t, 0, code, se+out)
	assert.Equal(t, "checked 2, problems 0\n", out)

	// A row that disagrees with its signed file: the license ID and the problem, nothing else.
	e.replica(`UPDATE licenses SET targets = 99 WHERE license_id = $1`, a)
	out, se, code = e.run("owner", "verify-licenses", "--pub", e.pubPath)
	assert.Equal(t, 1, code, se)
	assert.Equal(t, "checked 2, problems 1\n"+a+": the row's targets differs from the signed file\n", out)
	assert.NotContains(t, out+se, inst)

	// A key set that does not hold the signing key: every license is a problem.
	_, otherPub, err := issuer.GenerateKey("vk-2026-02", []byte(words), issuer.KDFParams{MemoryKiB: 64, Time: 1, Threads: 1})
	require.NoError(t, err)
	otherPath := filepath.Join(t.TempDir(), "other.pem")
	require.NoError(t, os.WriteFile(otherPath, otherPub, 0o600))
	out, _, code = e.run("owner", "verify-licenses", "--pub", otherPath)
	assert.Equal(t, 1, code)
	assert.Contains(t, out, "checked 2, problems 2")

	// The notifier may not read license files.
	_, se, code = e.run("notifier", "verify-licenses", "--pub", e.pubPath)
	assert.Equal(t, 1, code)
	assert.Contains(t, se, "permission denied")
}

func TestLicenseRevokeCommand(t *testing.T) {
	e := newOpsEnv(t, "lr")
	a := e.issue("Acme", license.NewInstallationID())

	_, se, code := e.run("sales", "license", "revoke", "--id", a, "--reason", "customer left")
	assert.Equal(t, 1, code)
	assert.Contains(t, se, "permission denied")
	_, se, code = e.run("owner", "license", "revoke", "--id", a, "--reason", "line\nbreak")
	assert.Equal(t, 2, code)
	assert.Contains(t, se, "--reason")
	assert.Zero(t, e.revoked(a))

	out, se, code := e.run("owner", "license", "revoke", "--id", a, "--reason", "customer left")
	require.Equal(t, 0, code, se)
	assert.Contains(t, out, a+" revoked")
	assert.Equal(t, 1, e.revoked(a))

	out, se, code = e.run("owner", "audit", "show", "--action", "license.revoke", "--details")
	require.Equal(t, 0, code, se)
	assert.Contains(t, out, e.login("owner")+" license.revoke "+a)
	assert.Contains(t, out, `"reason":"customer left"`)

	_, se, code = e.run("owner", "license", "revoke", "--id", a, "--reason", "again")
	assert.Equal(t, 1, code)
	assert.Contains(t, se, "already revoked")
	_, se, code = e.run("owner", "license", "revoke", "--id", "LIC-0-0", "--reason", "nope")
	assert.Equal(t, 1, code)
	assert.Contains(t, se, "no license LIC-0-0")
	n, _, _ := e.run("owner", "audit", "show", "--action", "license.revoke")
	assert.Len(t, lines(n), 1, "the refusals changed nothing")
}

func (e *opsEnv) revoked(id string) int {
	var n int
	require.NoError(e.t, e.d.Owner.QueryRow(context.Background(),
		`SELECT count(*) FROM licenses WHERE license_id = $1 AND revoked_at IS NOT NULL`, id).Scan(&n))
	return n
}
