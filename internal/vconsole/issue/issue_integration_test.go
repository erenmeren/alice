//go:build integration

package issue_test

import (
	"context"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"alice/internal/license"
	"alice/internal/license/issuer"
	"alice/internal/vconsole/audit"
	"alice/internal/vconsole/issue"
	"alice/internal/vconsole/sign"
	"alice/internal/vconsole/store"
	"alice/internal/vconsole/vpgtest"
)

func TestMain(m *testing.M) { os.Exit(vpgtest.Main(m)) }

var (
	now     = time.Date(2026, 10, 15, 9, 0, 0, 0, time.UTC)
	fastKDF = issuer.KDFParams{MemoryKiB: 64, Time: 1, Threads: 1}
)

const words = "amber canyon violet orbit lantern quiet"

type env struct {
	d      *vpgtest.DB
	sales  *pgxpool.Pool
	signer *pgxpool.Pool
	key    *sign.FileSigner
	cust   int64
}

func setup(t *testing.T, tag string) env {
	t.Helper()
	d := vpgtest.New(t)
	priv, _, err := issuer.GenerateKey("vk-2026-01", []byte(words), fastKDF)
	require.NoError(t, err)
	k, err := issuer.OpenKey(priv, []byte(words))
	require.NoError(t, err)
	e := env{d: d, sales: d.As(t, "vendor_sales", "t_i_sales_"+tag), signer: d.As(t, "vendor_signer", "t_i_signer_"+tag),
		key: sign.NewFileSigner(k)}
	e.cust, err = store.AddCustomer(context.Background(), e.sales, store.NewCustomer{Name: "Acme Ltd"})
	require.NoError(t, err)
	return e
}

func (e env) request(t *testing.T, inst string, targets int, replaces string) (int64, string) {
	t.Helper()
	ctx := context.Background()
	id, err := store.AddRequest(ctx, e.sales, store.NewRequest{CustomerID: e.cust, Installation: inst, Targets: targets,
		From: "2026-10-15", Months: 12, Replaces: replaces}, now)
	require.NoError(t, err)
	r, err := store.GetRequest(ctx, e.signer, id)
	require.NoError(t, err)
	return id, store.RequestHash(r)
}

func TestIssueSignsRecordsAndAudits(t *testing.T) {
	e := setup(t, "a")
	ctx := context.Background()
	inst := license.NewInstallationID()
	id, hash := e.request(t, inst, 5, "")

	res, err := issue.Issue(ctx, e.signer, e.key, issue.Params{RequestID: id, ExpectedHash: hash}, now)
	require.NoError(t, err)
	assert.Regexp(t, `^LIC-2026-\d{6}$`, res.LicenseID)

	f, err := sign.Verify(res.File, e.key)
	require.NoError(t, err)
	assert.Equal(t, inst, f.Payload.InstallationID)
	assert.Equal(t, 5, f.Payload.MaxTargets)
	assert.Equal(t, "Acme Ltd", f.Payload.Customer)

	var status, signedBy, keyID string
	require.NoError(t, e.d.Owner.QueryRow(ctx, `SELECT r.status, l.signed_by, l.key_id FROM license_requests r
		JOIN licenses l ON l.request_id = r.id WHERE r.id = $1`, id).Scan(&status, &signedBy, &keyID))
	assert.Equal(t, "signed", status)
	assert.Equal(t, "t_i_signer_a", signedBy)
	assert.Equal(t, "vk-2026-01", keyID)
	var n int
	require.NoError(t, e.d.Owner.QueryRow(ctx, `SELECT count(*) FROM audit WHERE action = 'license.issue' AND subject = $1`, res.LicenseID).Scan(&n))
	assert.Equal(t, 1, n)
	require.NoError(t, audit.Check(ctx, e.d.Owner))
}

func TestIssueRefusesARequestThatChangedAfterTheSignerLooked(t *testing.T) {
	e := setup(t, "b")
	ctx := context.Background()
	id, hash := e.request(t, license.NewInstallationID(), 5, "")
	// The requester (or anyone with write access) raises the target count after the signer saw it.
	_, err := e.sales.Exec(ctx, `UPDATE license_requests SET targets = 500 WHERE id = $1`, id)
	require.NoError(t, err)

	_, err = issue.Issue(ctx, e.signer, e.key, issue.Params{RequestID: id, ExpectedHash: hash}, now)
	assert.ErrorIs(t, err, issue.ErrRequestChanged)
	var n int
	require.NoError(t, e.d.Owner.QueryRow(ctx, `SELECT count(*) FROM licenses`).Scan(&n))
	assert.Zero(t, n)
}

func TestIssueTwiceFromOneRequestYieldsOneLicense(t *testing.T) {
	e := setup(t, "c")
	ctx := context.Background()
	id, hash := e.request(t, license.NewInstallationID(), 5, "")

	var wg sync.WaitGroup
	errs := make([]error, 2)
	for i := range errs {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, errs[i] = issue.Issue(ctx, e.signer, e.key, issue.Params{RequestID: id, ExpectedHash: hash}, now)
		}()
	}
	wg.Wait()
	ok, notOpen := 0, 0
	for _, err := range errs {
		switch {
		case err == nil:
			ok++
		case assert.ErrorIs(t, err, issue.ErrNotOpen):
			notOpen++
		}
	}
	assert.Equal(t, 1, ok)
	assert.Equal(t, 1, notOpen)
}

func TestIssueRefusesNonOpenAndUnknownRequests(t *testing.T) {
	e := setup(t, "d")
	ctx := context.Background()
	id, hash := e.request(t, license.NewInstallationID(), 5, "")
	_, err := e.sales.Exec(ctx, `UPDATE license_requests SET status = 'cancelled' WHERE id = $1`, id)
	require.NoError(t, err)
	_, err = issue.Issue(ctx, e.signer, e.key, issue.Params{RequestID: id, ExpectedHash: hash}, now)
	assert.ErrorIs(t, err, issue.ErrNotOpen)
	_, err = issue.Issue(ctx, e.signer, e.key, issue.Params{RequestID: 9999, ExpectedHash: hash}, now)
	assert.ErrorIs(t, err, store.ErrNotFound)
}

func TestSalesCannotIssue(t *testing.T) {
	e := setup(t, "e")
	id, hash := e.request(t, license.NewInstallationID(), 5, "")
	_, err := issue.Issue(context.Background(), e.sales, e.key, issue.Params{RequestID: id, ExpectedHash: hash}, now)
	assert.Error(t, err)
	var n int
	require.NoError(t, e.d.Owner.QueryRow(context.Background(), `SELECT count(*) FROM licenses`).Scan(&n))
	assert.Zero(t, n)
}

func TestDuplicateLicenseIDIsRefusedAndTheRequestStaysOpen(t *testing.T) {
	e := setup(t, "f")
	ctx := context.Background()
	id1, h1 := e.request(t, license.NewInstallationID(), 5, "")
	id2, h2 := e.request(t, license.NewInstallationID(), 6, "")
	_, err := issue.Issue(ctx, e.signer, e.key, issue.Params{RequestID: id1, ExpectedHash: h1, LicenseID: "LIC-2026-777777"}, now)
	require.NoError(t, err)
	_, err = issue.Issue(ctx, e.signer, e.key, issue.Params{RequestID: id2, ExpectedHash: h2, LicenseID: "LIC-2026-777777"}, now)
	assert.ErrorIs(t, err, issue.ErrDuplicateLicenseID)
	var status string
	require.NoError(t, e.d.Owner.QueryRow(ctx, `SELECT status FROM license_requests WHERE id = $1`, id2).Scan(&status))
	assert.Equal(t, "open", status)
}

func TestCorrectionRules(t *testing.T) {
	e := setup(t, "g")
	ctx := context.Background()
	inst := license.NewInstallationID()
	id, h := e.request(t, inst, 5, "")
	first, err := issue.Issue(ctx, e.signer, e.key, issue.Params{RequestID: id, ExpectedHash: h}, now)
	require.NoError(t, err)

	// Unknown license.
	idU, hU := e.request(t, inst, 6, "LIC-2026-000000")
	_, err = issue.Issue(ctx, e.signer, e.key, issue.Params{RequestID: idU, ExpectedHash: hU}, now)
	assert.ErrorIs(t, err, issue.ErrUnknownReplaced)

	// Another installation.
	idO, hO := e.request(t, license.NewInstallationID(), 6, first.LicenseID)
	_, err = issue.Issue(ctx, e.signer, e.key, issue.Params{RequestID: idO, ExpectedHash: hO}, now)
	assert.ErrorIs(t, err, issue.ErrOtherInstallation)

	// Ends earlier than the license it replaces: refused unless Shorten is set.
	idS, err := store.AddRequest(ctx, e.sales, store.NewRequest{CustomerID: e.cust, Installation: inst, Targets: 5,
		From: "2026-10-15", Months: 6, Replaces: first.LicenseID}, now)
	require.NoError(t, err)
	rS, err := store.GetRequest(ctx, e.signer, idS)
	require.NoError(t, err)
	_, err = issue.Issue(ctx, e.signer, e.key, issue.Params{RequestID: idS, ExpectedHash: store.RequestHash(rS)}, now)
	assert.ErrorIs(t, err, issue.ErrShortensTerm)
	_, err = issue.Issue(ctx, e.signer, e.key, issue.Params{RequestID: idS, ExpectedHash: store.RequestHash(rS), Shorten: true}, now)
	assert.NoError(t, err)
}
