//go:build integration

package store_test

import (
	"context"
	"encoding/base64"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"alice/internal/license"
	"alice/internal/license/issuer"
	"alice/internal/platform/db"
	"alice/internal/vconsole/issue"
	"alice/internal/vconsole/sign"
	"alice/internal/vconsole/store"
	"alice/internal/vconsole/vpgtest"
)

var verifyKDF = issuer.KDFParams{MemoryKiB: 64, Time: 1, Threads: 1}

const verifyWords = "amber canyon violet orbit lantern quiet"

type verifyEnv struct {
	d      *vpgtest.DB
	sales  *pgxpool.Pool
	signer *pgxpool.Pool
	cust   int64
}

func newVerifyEnv(t *testing.T, tag string) verifyEnv {
	t.Helper()
	d := vpgtest.New(t)
	e := verifyEnv{d: d, sales: d.As(t, "vendor_sales", "t_v_sales_"+tag), signer: d.As(t, "vendor_signer", "t_v_signer_"+tag)}
	var err error
	e.cust, err = store.AddCustomer(context.Background(), e.sales, store.NewCustomer{Name: "Acme Ltd"})
	require.NoError(t, err)
	return e
}

func fileSigner(t *testing.T, keyID string) *sign.FileSigner {
	t.Helper()
	priv, _, err := issuer.GenerateKey(keyID, []byte(verifyWords), verifyKDF)
	require.NoError(t, err)
	k, err := issuer.OpenKey(priv, []byte(verifyWords))
	require.NoError(t, err)
	return sign.NewFileSigner(k)
}

func activeSet(signers ...*sign.FileSigner) license.KeySet {
	var keys []license.PublicKey
	for _, s := range signers {
		keys = append(keys, license.PublicKey{ID: s.KeyID(), Key: s.Public(), Status: license.KeyActive})
	}
	return license.NewKeySet(keys...)
}

// issueLicense issues a license through the real issuing path and returns it.
func (e verifyEnv) issueLicense(t *testing.T, s sign.Signer, licenseID, inst string) issue.Result {
	t.Helper()
	ctx := context.Background()
	id, err := store.AddRequest(ctx, e.sales, store.NewRequest{CustomerID: e.cust, Installation: inst, Targets: 5,
		From: "2026-10-15", Months: 12}, now)
	require.NoError(t, err)
	r, err := store.GetRequest(ctx, e.signer, id)
	require.NoError(t, err)
	res, err := issue.Issue(ctx, e.signer, s, issue.Params{RequestID: id, ExpectedHash: store.RequestHash(r), LicenseID: licenseID}, now)
	require.NoError(t, err)
	return res
}

// tamper changes a license row behind the update guard, as someone with database superuser
// rights (or a damaged restore) could: replica mode skips the guard and audit triggers.
func tamper(t *testing.T, d *vpgtest.DB, sql string, args ...any) {
	t.Helper()
	ctx := context.Background()
	require.NoError(t, db.InTx(ctx, d.Owner, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, `SET LOCAL session_replication_role = replica`); err != nil {
			return err
		}
		tag, err := tx.Exec(ctx, sql, args...)
		if err != nil {
			return err
		}
		if tag.RowsAffected() != 1 {
			return fmt.Errorf("tamper changed %d rows", tag.RowsAffected())
		}
		return nil
	}))
}

func problemsFor(ps []store.LicenseProblem, licenseID string) []string {
	var out []string
	for _, p := range ps {
		if p.LicenseID == licenseID {
			out = append(out, p.Problem)
		}
	}
	return out
}

func TestHealthyLicensesPass(t *testing.T) {
	e := newVerifyEnv(t, "a")
	s := fileSigner(t, "vk-2026-01")
	e.issueLicense(t, s, "LIC-2026-000001", license.NewInstallationID())
	e.issueLicense(t, s, "LIC-2026-000002", license.NewInstallationID())

	// The signer and the owner can both read the files.
	for _, q := range []*pgxpool.Pool{e.signer, e.d.Owner} {
		checked, problems, err := store.VerifyLicenses(context.Background(), q, activeSet(s), now)
		require.NoError(t, err)
		assert.Equal(t, 2, checked)
		assert.Empty(t, problems)
	}
}

func TestChangedFileBytesAreFound(t *testing.T) {
	e := newVerifyEnv(t, "b")
	s := fileSigner(t, "vk-2026-01")
	res := e.issueLicense(t, s, "LIC-2026-000001", license.NewInstallationID())
	e.issueLicense(t, s, "LIC-2026-000002", license.NewInstallationID())
	changed := []byte(strings.Replace(string(res.File), "Acme Ltd", "Acme Ltc", 1))
	require.NotEqual(t, res.File, changed)
	tamper(t, e.d, `UPDATE licenses SET file = $1 WHERE license_id = $2`, changed, res.LicenseID)

	checked, problems, err := store.VerifyLicenses(context.Background(), e.signer, activeSet(s), now)
	require.NoError(t, err)
	assert.Equal(t, 2, checked)
	got := problemsFor(problems, res.LicenseID)
	require.NotEmpty(t, got)
	assert.Contains(t, strings.Join(got, "\n"), "file_sha256")
	assert.Empty(t, problemsFor(problems, "LIC-2026-000002"))
}

func TestMissingFileIsFound(t *testing.T) {
	e := newVerifyEnv(t, "m")
	s := fileSigner(t, "vk-2026-01")
	res := e.issueLicense(t, s, "LIC-2026-000001", license.NewInstallationID())
	tamper(t, e.d, `UPDATE licenses SET file = ''::bytea WHERE license_id = $1`, res.LicenseID)

	_, problems, err := store.VerifyLicenses(context.Background(), e.signer, activeSet(s), now)
	require.NoError(t, err)
	assert.Contains(t, strings.Join(problemsFor(problems, res.LicenseID), "\n"), "empty")
}

func TestFileSignedByAnUnknownKeyIsFound(t *testing.T) {
	e := newVerifyEnv(t, "c")
	known, other := fileSigner(t, "vk-2026-01"), fileSigner(t, "vk-2026-02")
	e.issueLicense(t, known, "LIC-2026-000001", license.NewInstallationID())
	e.issueLicense(t, other, "LIC-2026-000002", license.NewInstallationID())

	checked, problems, err := store.VerifyLicenses(context.Background(), e.signer, activeSet(known), now)
	require.NoError(t, err)
	assert.Equal(t, 2, checked)
	assert.Empty(t, problemsFor(problems, "LIC-2026-000001"))
	got := problemsFor(problems, "LIC-2026-000002")
	require.Len(t, got, 1)
	assert.Contains(t, got[0], "not in the key set")
}

func TestFileForADifferentInstallationThanTheRowIsFound(t *testing.T) {
	e := newVerifyEnv(t, "d")
	s := fileSigner(t, "vk-2026-01")
	res := e.issueLicense(t, s, "LIC-2026-000001", license.NewInstallationID())
	tamper(t, e.d, `UPDATE licenses SET installation = $1 WHERE license_id = $2`, license.NewInstallationID(), res.LicenseID)

	_, problems, err := store.VerifyLicenses(context.Background(), e.signer, activeSet(s), now)
	require.NoError(t, err)
	got := problemsFor(problems, res.LicenseID)
	require.Len(t, got, 1)
	assert.Contains(t, got[0], "installation")
}

func TestAnotherLicensesFileInTheRowIsFound(t *testing.T) {
	e := newVerifyEnv(t, "e")
	s := fileSigner(t, "vk-2026-01")
	a := e.issueLicense(t, s, "LIC-2026-000001", license.NewInstallationID())
	b := e.issueLicense(t, s, "LIC-2026-000002", license.NewInstallationID())
	// A consistent swap: the file and its hash both come from license b.
	tamper(t, e.d, `UPDATE licenses SET file = $1, file_sha256 = $2 WHERE license_id = $3`, b.File, b.FileSHA256, a.LicenseID)

	_, problems, err := store.VerifyLicenses(context.Background(), e.signer, activeSet(s), now)
	require.NoError(t, err)
	joined := strings.Join(problemsFor(problems, a.LicenseID), "\n")
	assert.Contains(t, joined, "license ID")
	assert.Contains(t, joined, "installation")
}

func TestRowColumnsThatDisagreeWithThePayloadAreFound(t *testing.T) {
	e := newVerifyEnv(t, "f")
	s := fileSigner(t, "vk-2026-01")
	res := e.issueLicense(t, s, "LIC-2026-000001", license.NewInstallationID())
	tamper(t, e.d, `UPDATE licenses SET targets = 500, valid_until = valid_until + interval '1 year' WHERE license_id = $1`, res.LicenseID)

	_, problems, err := store.VerifyLicenses(context.Background(), e.signer, activeSet(s), now)
	require.NoError(t, err)
	got := problemsFor(problems, res.LicenseID)
	require.Len(t, got, 2)
	joined := strings.Join(got, "\n")
	assert.Contains(t, joined, "targets")
	assert.Contains(t, joined, "valid_until")
}

func TestAllProblemsAreReportedNotOnlyTheFirst(t *testing.T) {
	e := newVerifyEnv(t, "g")
	s, other := fileSigner(t, "vk-2026-01"), fileSigner(t, "vk-2026-02")
	a := e.issueLicense(t, s, "LIC-2026-000001", license.NewInstallationID())
	e.issueLicense(t, s, "LIC-2026-000002", license.NewInstallationID())
	c := e.issueLicense(t, other, "LIC-2026-000003", license.NewInstallationID())
	dd := e.issueLicense(t, s, "LIC-2026-000004", license.NewInstallationID())
	tamper(t, e.d, `UPDATE licenses SET file_sha256 = repeat('0', 64) WHERE license_id = $1`, a.LicenseID)
	tamper(t, e.d, `UPDATE licenses SET valid_from = valid_from - interval '1 day' WHERE license_id = $1`, dd.LicenseID)

	checked, problems, err := store.VerifyLicenses(context.Background(), e.signer, activeSet(s), now)
	require.NoError(t, err)
	assert.Equal(t, 4, checked)
	var ids []string
	for _, p := range problems {
		ids = append(ids, p.LicenseID)
	}
	require.Equal(t, []string{a.LicenseID, c.LicenseID, dd.LicenseID}, ids, "in license order, one each")
	assert.Contains(t, problems[2].Problem, "valid_from")
}

func TestEmptyTableChecksZero(t *testing.T) {
	d := vpgtest.New(t)
	checked, problems, err := store.VerifyLicenses(context.Background(), d.Owner, activeSet(fileSigner(t, "vk-2026-01")), now)
	require.NoError(t, err)
	assert.Zero(t, checked)
	assert.Empty(t, problems)
}

func revokedSet(t *testing.T, s *sign.FileSigner, revokedFrom string) license.KeySet {
	t.Helper()
	entry := fmt.Sprintf(`{"key_id": %q, "public_key": %q, "status": "revoked"`, s.KeyID(), base64.StdEncoding.EncodeToString(s.Public()))
	if revokedFrom != "" {
		entry += fmt.Sprintf(`, "revoked_from": %q`, revokedFrom)
	}
	ks, err := license.ParseKeySet([]byte(`{"keys": [` + entry + `}]}`))
	require.NoError(t, err)
	return ks
}

func TestRevokedKeyForTheIssueDateIsReported(t *testing.T) {
	e := newVerifyEnv(t, "h")
	s := fileSigner(t, "vk-2026-01")
	res := e.issueLicense(t, s, "LIC-2026-000001", license.NewInstallationID()) // issued at now
	ctx := context.Background()
	later := now.Add(30 * 24 * time.Hour) // the check runs a month later, after the revocation

	for name, tc := range map[string]struct {
		revokedFrom string
		problem     bool
	}{
		"revoked before the issue date": {now.Add(-time.Hour).Format(time.RFC3339), true},
		"revoked at the issue date":     {now.Format(time.RFC3339), true},
		"revoked after the issue date":  {now.Add(time.Hour).Format(time.RFC3339), false},
		"revoked with no date":          {"", true},
	} {
		_, problems, err := store.VerifyLicenses(ctx, e.signer, revokedSet(t, s, tc.revokedFrom), later)
		require.NoError(t, err, name)
		got := problemsFor(problems, res.LicenseID)
		if tc.problem {
			require.Len(t, got, 1, name)
			assert.Contains(t, got[0], "revoked", name)
		} else {
			assert.Empty(t, got, name)
		}
	}
}

func TestIssuedAfterTheCheckTimeIsReported(t *testing.T) {
	e := newVerifyEnv(t, "i")
	s := fileSigner(t, "vk-2026-01")
	res := e.issueLicense(t, s, "LIC-2026-000001", license.NewInstallationID())
	_, problems, err := store.VerifyLicenses(context.Background(), e.signer, activeSet(s), now.Add(-time.Hour))
	require.NoError(t, err)
	got := problemsFor(problems, res.LicenseID)
	require.Len(t, got, 1)
	assert.Contains(t, got[0], "after the check time")
}

func TestProblemTextHasNoFileBytesOrInstallationID(t *testing.T) {
	e := newVerifyEnv(t, "j")
	s, other := fileSigner(t, "vk-2026-01"), fileSigner(t, "vk-2026-02")
	insts := []string{license.NewInstallationID(), license.NewInstallationID(), license.NewInstallationID(), license.NewInstallationID()}
	a := e.issueLicense(t, s, "LIC-2026-000001", insts[0])
	b := e.issueLicense(t, s, "LIC-2026-000002", insts[1])
	c := e.issueLicense(t, other, "LIC-2026-000003", insts[2])
	moved := license.NewInstallationID()
	tamper(t, e.d, `UPDATE licenses SET file = $1 WHERE license_id = $2`, append([]byte("garbage "), a.File...), a.LicenseID)
	tamper(t, e.d, `UPDATE licenses SET installation = $1, file = $2, file_sha256 = $3 WHERE license_id = $4`,
		moved, c.File, c.FileSHA256, b.LicenseID)

	_, problems, err := store.VerifyLicenses(context.Background(), e.signer, activeSet(s), now)
	require.NoError(t, err)
	require.GreaterOrEqual(t, len(problems), 4)
	files := [][]byte{a.File, b.File, c.File}
	for _, p := range problems {
		assert.LessOrEqual(t, len(p.Problem), 200, p.Problem)
		for _, inst := range append(insts, moved) {
			assert.NotContains(t, p.Problem, inst)
			assert.NotContains(t, p.Problem, license.IDSuffix(inst))
		}
		for _, f := range files {
			parsed, err := license.ParseFile(f)
			require.NoError(t, err)
			assert.NotContains(t, p.Problem, base64.RawURLEncoding.EncodeToString(parsed.Signature))
			assert.NotContains(t, p.Problem, parsed.Payload.Customer)
		}
		assert.NotContains(t, p.Problem, "{")
	}
}
