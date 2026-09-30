//go:build integration

package audit_test

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/netip"
	"os"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"alice/internal/audit"
	"alice/internal/platform/clock"
	"alice/internal/platform/db"
	"alice/internal/platform/settings"
	"alice/internal/testutil/pgtest"
)

func TestMain(m *testing.M) { os.Exit(pgtest.Main(m)) }

var start = time.Date(2026, 9, 30, 9, 0, 0, 0, time.UTC)

func userActor() audit.Actor {
	return audit.Actor{Type: audit.ActorUser, ID: uuid.MustParse("0192e0a0-0000-7000-8000-00000000000a"),
		Name: "admin", IP: netip.MustParseAddr("192.0.2.10"), RequestID: "req"}
}

func appendN(t *testing.T, pool *pgxpool.Pool, l *audit.Log, n int) {
	t.Helper()
	for i := range n {
		require.NoError(t, db.InTx(context.Background(), pool, func(tx pgx.Tx) error {
			_, err := l.Append(context.Background(), tx, audit.Event{Actor: userActor(), Action: "test.event",
				ObjectType: "thing", ObjectID: strconv.Itoa(i), Result: audit.Success, Details: map[string]string{"i": strconv.Itoa(i)}})
			return err
		}))
	}
}

// ownerExec runs tampering SQL as the table owner with the append-only triggers disabled,
// simulating an attacker with owner rights.
func ownerExec(t *testing.T, d *pgtest.DB, sql string, args ...any) {
	t.Helper()
	ctx := context.Background()
	require.NoError(t, db.InTx(ctx, d.Owner, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, "ALTER TABLE audit_log DISABLE TRIGGER USER"); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, sql, args...); err != nil {
			return err
		}
		_, err := tx.Exec(ctx, "ALTER TABLE audit_log ENABLE TRIGGER USER")
		return err
	}))
}

func TestAppendBuildsAVerifiableChain(t *testing.T) {
	d := pgtest.New(t)
	l := audit.New(clock.NewFake(start))
	ctx := context.Background()

	rep, err := audit.Verify(ctx, d.App)
	require.NoError(t, err)
	assert.Equal(t, audit.Report{Intact: true}, rep, "an empty log is intact")

	appendN(t, d.App, l, 5)
	rep, err = audit.Verify(ctx, d.App)
	require.NoError(t, err)
	assert.True(t, rep.Intact)
	assert.Equal(t, int64(5), rep.Checked)
	assert.Equal(t, int64(5), rep.HeadSeq)

	var first []byte
	require.NoError(t, d.App.QueryRow(ctx, "SELECT prev_hash FROM audit_log WHERE seq = 1").Scan(&first))
	assert.Equal(t, make([]byte, 32), first, "first link starts from 32 zero bytes")
}

func TestRolledBackAppendLeavesNoGap(t *testing.T) {
	d := pgtest.New(t)
	l := audit.New(clock.NewFake(start))
	ctx := context.Background()
	appendN(t, d.App, l, 1)
	err := db.InTx(ctx, d.App, func(tx pgx.Tx) error {
		if _, err := l.Append(ctx, tx, audit.Event{Actor: userActor(), Action: "test.event", Result: audit.Success}); err != nil {
			return err
		}
		return fmt.Errorf("business change failed")
	})
	require.Error(t, err)
	appendN(t, d.App, l, 1)
	rep, err := audit.Verify(ctx, d.App)
	require.NoError(t, err)
	assert.True(t, rep.Intact)
	assert.Equal(t, int64(2), rep.HeadSeq)
}

// Review Focus #1: values that change shape in PostgreSQL still hash identically after a round trip.
func TestRoundTripOfUnusualValuesStaysIntact(t *testing.T) {
	d := pgtest.New(t)
	fake := clock.NewFake(time.Date(2026, 9, 30, 9, 0, 0, 123456789, time.UTC)) // nanoseconds
	l := audit.New(fake)
	ctx := context.Background()
	details := map[string]string{"city": "İzmir", "district": "ığdır", "note": `quote " and <tag> & ünïcödé`}
	for i := range 20 {
		details[fmt.Sprintf("k%02d", 19-i)] = strconv.Itoa(i)
	}
	actor := audit.Actor{Type: audit.ActorUser, Name: "İsmail", IP: netip.MustParseAddr("::ffff:10.0.0.7"), RequestID: "r"}
	var written audit.Entry
	require.NoError(t, db.InTx(ctx, d.App, func(tx pgx.Tx) error {
		var err error
		written, err = l.Append(ctx, tx, audit.Event{Actor: actor, Action: "user.updated", Result: audit.Success, Details: details})
		return err
	}))
	fake.Advance(1500 * time.Nanosecond)
	require.NoError(t, audit.NewService(l, d.App).Write(ctx, audit.Event{Actor: audit.SystemActor("cli"), Action: "test.event", Result: audit.Failure}))

	items, _, err := audit.List(ctx, d.App, audit.Filter{})
	require.NoError(t, err)
	require.Len(t, items, 2)
	got := items[1]
	assert.Equal(t, "10.0.0.7", got.IP, "IPv4-mapped IPv6 is stored in canonical IPv4 form")
	assert.Equal(t, details, got.Details)
	assert.Equal(t, written.Hash, got.Hash)
	assert.True(t, got.At.Equal(time.Date(2026, 9, 30, 9, 0, 0, 123456000, time.UTC)))

	rep, err := audit.Verify(ctx, d.App)
	require.NoError(t, err)
	assert.True(t, rep.Intact, "%+v", rep)
}

func TestForbiddenDetailKeysAreRejected(t *testing.T) {
	d := pgtest.New(t)
	l := audit.New(clock.NewFake(start))
	ctx := context.Background()
	for _, k := range []string{"password", "secret", "passphrase", "token", "code", "totp_secret", "private_key", "recovery_code", "private_anything"} {
		err := db.InTx(ctx, d.App, func(tx pgx.Tx) error {
			_, err := l.Append(ctx, tx, audit.Event{Actor: userActor(), Action: "x.y", Result: audit.Success, Details: map[string]string{k: "v"}})
			return err
		})
		assert.ErrorIs(t, err, audit.ErrForbiddenDetailKey, k)
	}
	err := db.InTx(ctx, d.App, func(tx pgx.Tx) error {
		_, err := l.Append(ctx, tx, audit.Event{Actor: userActor(), Action: "token.created", Result: audit.Success, Details: map[string]string{"token_id": "t1"}})
		return err
	})
	assert.NoError(t, err, "keys that merely contain a word such as token_id are allowed")
}

// F-90: a modified row is reported at its sequence number.
func TestModifiedRowIsDetected(t *testing.T) {
	d := pgtest.New(t)
	appendN(t, d.App, audit.New(clock.NewFake(start)), 5)
	ownerExec(t, d, "UPDATE audit_log SET actor_name = 'mallory' WHERE seq = 3")
	rep, err := audit.Verify(context.Background(), d.App)
	require.NoError(t, err)
	assert.False(t, rep.Intact)
	assert.Equal(t, int64(3), rep.FirstBadSeq)
	assert.Equal(t, audit.ProblemHashMismatch, rep.Problem)
}

// F-91: a deleted middle row leaves a gap.
func TestDeletedMiddleRowIsDetected(t *testing.T) {
	d := pgtest.New(t)
	appendN(t, d.App, audit.New(clock.NewFake(start)), 5)
	ownerExec(t, d, "DELETE FROM audit_log WHERE seq = 2")
	rep, err := audit.Verify(context.Background(), d.App)
	require.NoError(t, err)
	assert.False(t, rep.Intact)
	assert.Equal(t, int64(2), rep.FirstBadSeq)
	assert.Equal(t, audit.ProblemSequenceGap, rep.Problem)
}

// F-92: deleting the newest rows is detected through the stored checkpoint.
func TestTruncatedTailIsDetectedByCheckpoint(t *testing.T) {
	d := pgtest.New(t)
	l := audit.New(clock.NewFake(start))
	svc := audit.NewService(l, d.App)
	ctx := context.Background()
	appendN(t, d.App, l, 4)
	rep, err := svc.Verify(ctx, audit.SystemActor("cli")) // checkpoint at seq 4, verify event becomes seq 5
	require.NoError(t, err)
	require.True(t, rep.Intact)

	ownerExec(t, d, "DELETE FROM audit_log WHERE seq >= 4")
	rep, err = audit.Verify(ctx, d.App)
	require.NoError(t, err)
	assert.False(t, rep.Intact)
	assert.Equal(t, audit.ProblemTailTruncated, rep.Problem)
	assert.Equal(t, int64(4), rep.FirstBadSeq)
}

func TestCheckpointHashMismatchIsDetected(t *testing.T) {
	d := pgtest.New(t)
	l := audit.New(clock.NewFake(start))
	ctx := context.Background()
	appendN(t, d.App, l, 3)
	require.NoError(t, settings.Set(ctx, d.App, "audit.checkpoint",
		map[string]any{"seq": 2, "hash": hex.EncodeToString(make([]byte, 32)), "at": start.Format(time.RFC3339)}, start))
	rep, err := audit.Verify(ctx, d.App)
	require.NoError(t, err)
	assert.False(t, rep.Intact)
	assert.Equal(t, int64(2), rep.FirstBadSeq)
	assert.Equal(t, audit.ProblemHashMismatch, rep.Problem)
}

// F-93: swapping the contents of two rows is detected.
func TestReorderedRowsAreDetected(t *testing.T) {
	d := pgtest.New(t)
	appendN(t, d.App, audit.New(clock.NewFake(start)), 4)
	ownerExec(t, d, `UPDATE audit_log a SET object_id = b.object_id, details = b.details
		FROM audit_log b WHERE (a.seq, b.seq) IN ((2, 3), (3, 2))`)
	rep, err := audit.Verify(context.Background(), d.App)
	require.NoError(t, err)
	assert.False(t, rep.Intact)
	assert.Equal(t, int64(2), rep.FirstBadSeq)
}

// Append-only triggers hold even for the owner role (F-94's privilege check is in Task 3).
func TestTriggersBlockUpdateDeleteTruncateForOwner(t *testing.T) {
	d := pgtest.New(t)
	appendN(t, d.App, audit.New(clock.NewFake(start)), 1)
	ctx := context.Background()
	for _, sql := range []string{"UPDATE audit_log SET action = 'x'", "DELETE FROM audit_log", "TRUNCATE audit_log"} {
		_, err := d.Owner.Exec(ctx, sql)
		assert.ErrorContains(t, err, "append-only", sql)
	}
}

// F-95: 100 concurrent writers keep the chain contiguous and valid.
func TestConcurrentAppendsStayContiguous(t *testing.T) {
	d := pgtest.New(t)
	svc := audit.NewService(audit.New(clock.NewFake(start)), d.App)
	ctx := context.Background()
	var wg sync.WaitGroup
	errs := make(chan error, 100)
	for i := range 100 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			errs <- svc.Write(ctx, audit.Event{Actor: userActor(), Action: "test.concurrent", ObjectID: strconv.Itoa(i), Result: audit.Success})
		}()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		require.NoError(t, err)
	}
	rep, err := audit.Verify(ctx, d.App)
	require.NoError(t, err)
	assert.True(t, rep.Intact)
	assert.Equal(t, int64(100), rep.HeadSeq)
}

// F-97 style: after verification the chain continues from the verified head.
func TestServiceVerifyRecordsCheckpointAndEventThenChainContinues(t *testing.T) {
	d := pgtest.New(t)
	l := audit.New(clock.NewFake(start))
	svc := audit.NewService(l, d.App)
	ctx := context.Background()
	appendN(t, d.App, l, 3)

	rep, err := svc.Verify(ctx, audit.SystemActor("cli"))
	require.NoError(t, err)
	assert.True(t, rep.Intact)
	assert.Equal(t, int64(3), rep.HeadSeq)

	var cp struct {
		Seq  int64  `json:"seq"`
		Hash string `json:"hash"`
	}
	ok, err := settings.Get(ctx, d.App, "audit.checkpoint", &cp)
	require.NoError(t, err)
	require.True(t, ok)
	assert.Equal(t, int64(3), cp.Seq)
	assert.Equal(t, hex.EncodeToString(rep.HeadHash), cp.Hash)

	items, _, err := svc.List(ctx, audit.Filter{Limit: 1})
	require.NoError(t, err)
	assert.Equal(t, "audit.verified", items[0].Action)
	assert.Equal(t, audit.Success, items[0].Result)
	assert.Equal(t, "3", items[0].Details["checked"])

	appendN(t, d.App, l, 2)
	rep, err = svc.Verify(ctx, audit.SystemActor("cli"))
	require.NoError(t, err)
	assert.True(t, rep.Intact)
	assert.Equal(t, int64(6), rep.HeadSeq)
}

func TestServiceVerifyRecordsFailure(t *testing.T) {
	d := pgtest.New(t)
	l := audit.New(clock.NewFake(start))
	svc := audit.NewService(l, d.App)
	ctx := context.Background()
	appendN(t, d.App, l, 3)
	ownerExec(t, d, "UPDATE audit_log SET result = 'failure' WHERE seq = 2")

	rep, err := svc.Verify(ctx, audit.SystemActor("cli"))
	require.NoError(t, err)
	assert.False(t, rep.Intact)
	items, _, err := svc.List(ctx, audit.Filter{Action: "audit.verified"})
	require.NoError(t, err)
	require.Len(t, items, 1)
	assert.Equal(t, audit.Failure, items[0].Result)
	assert.Equal(t, audit.ProblemHashMismatch, items[0].Details["problem"])
	assert.Equal(t, "2", items[0].Details["first_bad_seq"])
	ok, err := settings.Get(ctx, d.App, "audit.checkpoint", &struct{}{})
	require.NoError(t, err)
	assert.False(t, ok, "no checkpoint is stored for a broken chain")
}

func TestListPagingAndFilters(t *testing.T) {
	d := pgtest.New(t)
	l := audit.New(clock.NewFake(start))
	svc := audit.NewService(l, d.App)
	ctx := context.Background()
	events := []audit.Event{
		{Actor: userActor(), Action: "auth.login", Result: audit.Success},
		{Actor: audit.Actor{Type: audit.ActorUser, Name: "Operator1"}, Action: "auth.login", Result: audit.Failure},
		{Actor: userActor(), Action: "user.created", Result: audit.Success},
		{Actor: userActor(), Action: "auth_login_lookalike", Result: audit.Success},
		{Actor: userActor(), Action: "authz.denied", Result: audit.Denied},
	}
	for _, e := range events {
		require.NoError(t, svc.Write(ctx, e))
	}

	page, next, err := svc.List(ctx, audit.Filter{Limit: 2})
	require.NoError(t, err)
	require.Len(t, page, 2)
	assert.Equal(t, []int64{5, 4}, []int64{page[0].Seq, page[1].Seq}, "newest first")
	assert.Equal(t, int64(4), next)
	page, next, err = svc.List(ctx, audit.Filter{Limit: 2, BeforeSeq: next})
	require.NoError(t, err)
	assert.Equal(t, []int64{3, 2}, []int64{page[0].Seq, page[1].Seq})
	page, next, err = svc.List(ctx, audit.Filter{Limit: 2, BeforeSeq: next})
	require.NoError(t, err)
	assert.Len(t, page, 1)
	assert.Equal(t, int64(0), next, "no further page")

	page, _, err = svc.List(ctx, audit.Filter{Action: "auth."})
	require.NoError(t, err)
	assert.Len(t, page, 2, "prefix match; '_' is not a wildcard")
	page, _, err = svc.List(ctx, audit.Filter{Actor: "operator1"})
	require.NoError(t, err)
	require.Len(t, page, 1)
	assert.Equal(t, "Operator1", page[0].ActorName)
	page, _, err = svc.List(ctx, audit.Filter{Result: audit.Denied})
	require.NoError(t, err)
	require.Len(t, page, 1)
	assert.Equal(t, "authz.denied", page[0].Action)

	page, _, err = svc.List(ctx, audit.Filter{Limit: 1000})
	require.NoError(t, err)
	assert.Len(t, page, 5, "limit is capped at 200, not rejected")
}

func TestIterateIsAscending(t *testing.T) {
	d := pgtest.New(t)
	l := audit.New(clock.NewFake(start))
	appendN(t, d.App, l, 3)
	var seqs []int64
	require.NoError(t, audit.NewService(l, d.App).Iterate(context.Background(), func(e audit.Entry) error {
		seqs = append(seqs, e.Seq)
		return nil
	}))
	assert.Equal(t, []int64{1, 2, 3}, seqs)
}

// Input PostgreSQL cannot store is normalised before hashing, so Append never fails on it.
func TestAppendNormalisesUnstorableInput(t *testing.T) {
	d := pgtest.New(t)
	l := audit.New(clock.NewFake(start))
	ctx := context.Background()
	actor := audit.Actor{Type: audit.ActorUser, Name: "bad\x00name\xff", IP: netip.MustParseAddr("fe80::1%eth0"), RequestID: "r\x00"}
	var written audit.Entry
	require.NoError(t, db.InTx(ctx, d.App, func(tx pgx.Tx) error {
		var err error
		written, err = l.Append(ctx, tx, audit.Event{Actor: actor, Action: "x.y", ObjectID: "o\xc3", Result: audit.Success,
			Details: map[string]string{"note": "a\x00b\xfe", "k\x00": "v"}})
		return err
	}))
	assert.Equal(t, "fe80::1", written.IP)
	items, _, err := audit.List(ctx, d.App, audit.Filter{})
	require.NoError(t, err)
	require.Len(t, items, 1)
	assert.Equal(t, "bad�name�", items[0].ActorName)
	assert.Equal(t, "a�b�", items[0].Details["note"])
	assert.Equal(t, written.Hash, items[0].Hash)
	rep, err := audit.Verify(ctx, d.App)
	require.NoError(t, err)
	assert.True(t, rep.Intact, "%+v", rep)
}

func TestServiceVerifyReadOnlyWritesNothing(t *testing.T) {
	d := pgtest.New(t)
	l := audit.New(clock.NewFake(start))
	svc := audit.NewService(l, d.App)
	ctx := context.Background()
	appendN(t, d.App, l, 3)

	rep, err := svc.VerifyReadOnly(ctx)
	require.NoError(t, err)
	assert.True(t, rep.Intact)
	assert.Equal(t, int64(3), rep.HeadSeq)

	var cp json.RawMessage
	has, err := settings.Get(ctx, d.App, "audit.checkpoint", &cp)
	require.NoError(t, err)
	assert.False(t, has, "a read-only verification never stores a checkpoint")
	var n int
	require.NoError(t, d.App.QueryRow(ctx, "SELECT count(*) FROM audit_log").Scan(&n))
	assert.Equal(t, 3, n, "and never appends an audit.verified row")

	ownerExec(t, d, "UPDATE audit_log SET result = 'failure' WHERE seq = 2")
	rep, err = svc.VerifyReadOnly(ctx)
	require.NoError(t, err)
	assert.False(t, rep.Intact)
	assert.Equal(t, int64(2), rep.FirstBadSeq)
}

// Verify reads and moves the checkpoint only while it holds the chain lock, so two
// verifications that overlap cannot move the checkpoint backwards: the one that saw the
// longer chain always decides last or is seen by the other.
func TestServiceVerifyTakesTheChainLockBeforeTheCheckpoint(t *testing.T) {
	d := pgtest.New(t)
	l := audit.New(clock.NewFake(start))
	svc := audit.NewService(l, d.App)
	ctx := context.Background()
	appendN(t, d.App, l, 3)
	_, err := svc.Verify(ctx, audit.SystemActor("cli")) // stores the checkpoint row (seq 3)
	require.NoError(t, err)

	// Another writer holds the chain lock in an open transaction.
	holder, err := d.App.Begin(ctx)
	require.NoError(t, err)
	defer func() { _ = holder.Rollback(ctx) }()
	_, err = l.Append(ctx, holder, audit.Event{Actor: userActor(), Action: "test.event", Result: audit.Success})
	require.NoError(t, err)

	done := make(chan error, 1)
	go func() {
		_, err := svc.Verify(ctx, audit.SystemActor("cli"))
		done <- err
	}()
	require.Eventually(t, func() bool {
		var waiting int
		err := d.Owner.QueryRow(ctx, `SELECT count(*) FROM pg_locks l JOIN pg_database db ON db.oid = l.database
WHERE l.locktype = 'advisory' AND NOT l.granted AND db.datname = current_database()`).Scan(&waiting)
		return err == nil && waiting == 1
	}, 10*time.Second, 20*time.Millisecond, "the verification waits for the chain lock")

	// While it waits, it has not read-then-written the checkpoint: the row is not locked.
	err = db.InTx(ctx, d.Owner, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, "SELECT 1 FROM settings WHERE key = 'audit.checkpoint' FOR UPDATE NOWAIT")
		return err
	})
	require.NoError(t, err, "the checkpoint must not be touched before the chain lock is held")

	require.NoError(t, holder.Commit(ctx))
	require.NoError(t, <-done)
	rep, err := audit.Verify(ctx, d.App)
	require.NoError(t, err)
	assert.True(t, rep.Intact)
}
