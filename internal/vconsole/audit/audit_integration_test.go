//go:build integration

package audit_test

import (
	"context"
	"fmt"
	"os"
	"testing"

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
