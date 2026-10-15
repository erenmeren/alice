//go:build integration

package audit_test

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5/pgconn"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"alice/internal/vconsole/audit"
	"alice/internal/vconsole/vpgtest"
)

func TestMain(m *testing.M) { os.Exit(vpgtest.Main(m)) }

func seed(t *testing.T, n int) (*vpgtest.DB, context.Context) {
	t.Helper()
	d := vpgtest.New(t)
	ctx := context.Background()
	sales := d.As(t, "vendor_sales", "t_audit_"+t.Name())
	// Audit rows come from the triggers on the tables, so a customer insert is one audit row.
	for i := 0; i < n; i++ {
		_, err := sales.Exec(ctx, `INSERT INTO customers (name) VALUES ($1)`, fmt.Sprintf("Customer %d", i))
		require.NoError(t, err)
	}
	return d, ctx
}

func TestAppendBuildsAVerifiableChain(t *testing.T) {
	d, ctx := seed(t, 5)
	require.NoError(t, audit.Check(ctx, d.Owner))

	var seqs, actors int
	require.NoError(t, d.Owner.QueryRow(ctx, `SELECT count(DISTINCT seq), count(DISTINCT actor) FROM audit`).Scan(&seqs, &actors))
	assert.Equal(t, 5, seqs)
	assert.Equal(t, 1, actors)
	var actor string
	require.NoError(t, d.Owner.QueryRow(ctx, `SELECT actor FROM audit WHERE seq = 1`).Scan(&actor))
	assert.Equal(t, "t_audit_TestAppendBuildsAVerifiableChain", actor, "the actor is the role the caller acts as")
}

func TestEmptyChainIsIntact(t *testing.T) {
	d := vpgtest.New(t)
	require.NoError(t, audit.Check(context.Background(), d.Owner))
}

func TestEditingAnyFieldIsDetected(t *testing.T) {
	d, ctx := seed(t, 4)
	_, err := d.Owner.Exec(ctx, `ALTER TABLE audit DISABLE TRIGGER audit_append_only`)
	require.NoError(t, err)
	_, err = d.Owner.Exec(ctx, `UPDATE audit SET details = '{"i": 99}' WHERE seq = 2`)
	require.NoError(t, err)
	n, err := audit.Verify(ctx, d.Owner)
	require.NoError(t, err)
	assert.EqualValues(t, 2, n)
	assert.ErrorIs(t, audit.Check(ctx, d.Owner), audit.ErrBroken)
}

func TestDeletingAMiddleRowIsDetected(t *testing.T) {
	d, ctx := seed(t, 4)
	_, err := d.Owner.Exec(ctx, `ALTER TABLE audit DISABLE TRIGGER audit_append_only`)
	require.NoError(t, err)
	_, err = d.Owner.Exec(ctx, `DELETE FROM audit WHERE seq = 2`)
	require.NoError(t, err)
	n, err := audit.Verify(ctx, d.Owner)
	require.NoError(t, err)
	assert.EqualValues(t, 3, n, "the first row that no longer follows its predecessor")
}

func TestTriggersStopEditsAndDeletesForEveryone(t *testing.T) {
	d, ctx := seed(t, 2)
	_, err := d.Owner.Exec(ctx, `UPDATE audit SET actor = 'x' WHERE seq = 1`)
	assert.Error(t, err)
	_, err = d.Owner.Exec(ctx, `DELETE FROM audit`)
	assert.Error(t, err)
	_, err = d.Owner.Exec(ctx, `TRUNCATE audit`)
	assert.Error(t, err)
}

// Known limit (spec section 9, phase 5): the newest rows can be removed without breaking the chain
// from the inside. This test documents it so nobody believes Verify proves completeness.
func TestRemovingTheNewestRowsIsNotDetectable(t *testing.T) {
	d, ctx := seed(t, 3)
	_, err := d.Owner.Exec(ctx, `ALTER TABLE audit DISABLE TRIGGER audit_append_only`)
	require.NoError(t, err)
	_, err = d.Owner.Exec(ctx, `DELETE FROM audit WHERE seq = 3`)
	require.NoError(t, err)
	assert.NoError(t, audit.Check(ctx, d.Owner))
}

func TestConcurrentAppendsKeepASingleChain(t *testing.T) {
	d := vpgtest.New(t)
	ctx := context.Background()
	pool := d.As(t, "vendor_sales", "t_audit_conc")
	errs := make(chan error, 20)
	for i := 0; i < 20; i++ {
		name := fmt.Sprintf("Concurrent %d", i)
		go func() { _, err := pool.Exec(ctx, `INSERT INTO customers (name) VALUES ($1)`, name); errs <- err }()
	}
	for i := 0; i < 20; i++ {
		require.NoError(t, <-errs)
	}
	require.NoError(t, audit.Check(ctx, d.Owner))
	var n int
	require.NoError(t, d.Owner.QueryRow(ctx, `SELECT count(*) FROM audit`).Scan(&n))
	assert.Equal(t, 20, n)
}

func TestAppendIsForTheOwnerOnly(t *testing.T) {
	d := vpgtest.New(t)
	ctx := context.Background()
	_, err := audit.Append(ctx, d.Owner, "tool.run", "x", map[string]any{"k": "v"})
	require.NoError(t, err)
	require.NoError(t, audit.Check(ctx, d.Owner))
	sales := d.As(t, "vendor_sales", "t_audit_append")
	_, err = audit.Append(ctx, sales, "customer.add", "forged", nil)
	assert.Error(t, err, "a sales login cannot write audit rows by hand")
}

// withoutTriggers runs sql as the owner (a superuser in the test container) with the append-only
// triggers off for that transaction. Tests only: no client has this path.
func withoutTriggers(t *testing.T, d *vpgtest.DB, sql string) {
	t.Helper()
	ctx := context.Background()
	tx, err := d.Owner.Begin(ctx)
	require.NoError(t, err)
	defer func() { _ = tx.Rollback(ctx) }()
	_, err = tx.Exec(ctx, `SET LOCAL session_replication_role = replica`)
	require.NoError(t, err)
	_, err = tx.Exec(ctx, sql)
	require.NoError(t, err)
	require.NoError(t, tx.Commit(ctx))
}

func TestCurrentHeadMatchesTheLastRow(t *testing.T) {
	d, ctx := seed(t, 3)
	h, ok, err := audit.CurrentHead(ctx, d.Owner)
	require.NoError(t, err)
	require.True(t, ok)
	var seq int64
	var hash string
	require.NoError(t, d.Owner.QueryRow(ctx, `SELECT seq, hash FROM audit ORDER BY seq DESC LIMIT 1`).Scan(&seq, &hash))
	assert.Equal(t, audit.Head{Seq: seq, Hash: hash}, h)
	assert.EqualValues(t, 3, h.Seq)
	assert.Equal(t, fmt.Sprintf("3:%s", hash), h.String())
}

func TestEmptyChainHasNoHead(t *testing.T) {
	d := vpgtest.New(t)
	_, ok, err := audit.CurrentHead(context.Background(), d.Owner)
	require.NoError(t, err)
	assert.False(t, ok)
}

func TestVerifyHeadPassesWhenRowsWereAddedLater(t *testing.T) {
	d, ctx := seed(t, 3)
	h, _, err := audit.CurrentHead(ctx, d.Owner)
	require.NoError(t, err)
	require.NoError(t, audit.VerifyHead(ctx, d.Owner, h))
	_, err = audit.Append(ctx, d.Owner, "test.later", "x", nil)
	require.NoError(t, err)
	require.NoError(t, audit.VerifyHead(ctx, d.Owner, h))
}

func TestVerifyHeadFailsWhenTheNewestRowsWereDeleted(t *testing.T) {
	d, ctx := seed(t, 5)
	h, _, err := audit.CurrentHead(ctx, d.Owner)
	require.NoError(t, err)
	withoutTriggers(t, d, `DELETE FROM audit WHERE seq >= 4`)
	require.NoError(t, audit.Check(ctx, d.Owner), "the remaining chain is intact: only the checkpoint notices")
	err = audit.VerifyHead(ctx, d.Owner, h)
	assert.ErrorIs(t, err, audit.ErrHeadMismatch)
	// New rows reuse the sequence numbers, with other hashes.
	_, err = audit.Append(ctx, d.Owner, "test.again", "x", nil)
	require.NoError(t, err)
	_, err = audit.Append(ctx, d.Owner, "test.again", "y", nil)
	require.NoError(t, err)
	assert.ErrorIs(t, audit.VerifyHead(ctx, d.Owner, h), audit.ErrHeadMismatch)
}

func TestVerifyHeadFailsWhenARowWasEdited(t *testing.T) {
	d, ctx := seed(t, 4)
	h, _, err := audit.CurrentHead(ctx, d.Owner)
	require.NoError(t, err)
	withoutTriggers(t, d, `UPDATE audit SET details = '{"i": 99}' WHERE seq = 2`)
	assert.ErrorIs(t, audit.VerifyHead(ctx, d.Owner, h), audit.ErrBroken)
}

func TestVerifyHeadFailsWhenTheHashDiffers(t *testing.T) {
	d, ctx := seed(t, 3)
	h, _, err := audit.CurrentHead(ctx, d.Owner)
	require.NoError(t, err)
	h.Hash = strings.Repeat("a", 64)
	assert.ErrorIs(t, audit.VerifyHead(ctx, d.Owner, h), audit.ErrHeadMismatch)
	h.Seq = 99
	assert.ErrorIs(t, audit.VerifyHead(ctx, d.Owner, h), audit.ErrHeadMismatch)
}

func TestParseHeadRefusesJunk(t *testing.T) {
	hex64 := strings.Repeat("ab", 32)
	for _, bad := range []string{"", "5", "5:zz", "-1:" + hex64, "+5:" + hex64, "0:" + hex64, "5:" + hex64[:63],
		"5:" + hex64 + "0", " 5:" + hex64, "5: " + hex64, "5:" + hex64 + " ", "5:" + hex64 + "\n", ":" + hex64,
		"5:" + hex64[:63] + "g", "99999999999999999999:" + hex64, "5:5:" + hex64} {
		_, err := audit.ParseHead(bad)
		assert.Error(t, err, "%q", bad)
	}
	h, err := audit.ParseHead("5:" + hex64)
	require.NoError(t, err)
	assert.Equal(t, audit.Head{Seq: 5, Hash: hex64}, h)
	h, err = audit.ParseHead("12:" + strings.Repeat("AB", 32))
	require.NoError(t, err)
	assert.Equal(t, audit.Head{Seq: 12, Hash: hex64}, h, "upper case hex is normalised")
	again, err := audit.ParseHead(h.String())
	require.NoError(t, err)
	assert.Equal(t, h, again)
}

func TestNotifierAndOwnerCanReadHeadButSalesCannot(t *testing.T) {
	d, ctx := seed(t, 2)
	for group, wantOK := range map[string]bool{"vendor_owner": true, "vendor_notifier": true,
		"vendor_sales": false, "vendor_web": false, "vendor_signer": false} {
		p := d.As(t, group, "t_head_"+group)
		_, _, err := audit.CurrentHead(ctx, p)
		if wantOK {
			assert.NoError(t, err, group)
			continue
		}
		var pe *pgconn.PgError
		if assert.True(t, errors.As(err, &pe), "%s: %v", group, err) {
			assert.Equal(t, "42501", pe.Code, group)
		}
	}
}
