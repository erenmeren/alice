//go:build integration

package forward_test

import (
	"context"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"net"
	"os"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"alice/internal/audit"
	"alice/internal/audit/forward"
	"alice/internal/platform/clock"
	"alice/internal/platform/db"
	"alice/internal/platform/netaddr"
	"alice/internal/platform/settings"
	"alice/internal/platform/validate"
	"alice/internal/testutil/fakesyslog"
	"alice/internal/testutil/pgtest"
)

func TestMain(m *testing.M) { os.Exit(pgtest.Main(m)) }

var admin = audit.Actor{Type: audit.ActorUser, Name: "admin"}

type env struct {
	d   *pgtest.DB
	log *audit.Log
	f   *forward.Forwarder
}

func plainDial(ctx context.Context, network, addr string) (net.Conn, error) {
	return (&net.Dialer{Timeout: 5 * time.Second}).DialContext(ctx, network, addr)
}

func newEnv(t *testing.T, dial func(ctx context.Context, network, addr string) (net.Conn, error)) *env {
	t.Helper()
	d := pgtest.New(t)
	l := audit.New(clock.Real{})
	f := forward.New(forward.Config{Pool: d.App, Audit: l, Clock: clock.Real{}, Dial: dial, Hostname: "alice01", AppName: "alice"})
	return &env{d: d, log: l, f: f}
}

func target(t *testing.T, s *fakesyslog.Server, tr forward.Transport) forward.Settings {
	t.Helper()
	host, port, err := net.SplitHostPort(s.Addr())
	require.NoError(t, err)
	p, err := strconv.Atoi(port)
	require.NoError(t, err)
	return forward.Settings{Enabled: true, Host: host, Port: p, Transport: tr, CAPEM: string(s.CAPEM())}
}

func (e *env) save(t *testing.T, in forward.Settings) forward.Settings {
	t.Helper()
	cur, _, err := e.f.Settings(context.Background())
	require.NoError(t, err)
	out, err := e.f.Save(context.Background(), in, cur.Version, admin)
	require.NoError(t, err)
	return out
}

func (e *env) appendRows(t *testing.T, n int) {
	t.Helper()
	require.NoError(t, db.InTx(context.Background(), e.d.App, func(tx pgx.Tx) error {
		for i := range n {
			if _, err := e.log.Append(context.Background(), tx, audit.Event{Actor: audit.SystemActor("scheduler"),
				Action: "test.row", ObjectType: "row", ObjectID: strconv.Itoa(i), Result: audit.Success,
				Details: map[string]string{"n": strconv.Itoa(i)}}); err != nil {
				return err
			}
		}
		return nil
	}))
}

func (e *env) rows(t *testing.T) []audit.Entry {
	t.Helper()
	var out []audit.Entry
	require.NoError(t, audit.Iterate(context.Background(), e.d.App, func(en audit.Entry) error {
		out = append(out, en)
		return nil
	}))
	return out
}

// received waits until the fake has exactly n messages (they arrive asynchronously) and returns them parsed.
func received(t *testing.T, s *fakesyslog.Server, n int) []parsed {
	t.Helper()
	require.Eventually(t, func() bool { return len(s.Messages()) >= n }, 5*time.Second, 5*time.Millisecond)
	time.Sleep(20 * time.Millisecond) // nothing more arrives
	msgs := s.Messages()
	require.Len(t, msgs, n)
	return parseAll(t, msgs)
}

func (e *env) state(t *testing.T) forward.State {
	t.Helper()
	_, st, err := e.f.Settings(context.Background())
	require.NoError(t, err)
	return st
}

var (
	lineRE  = regexp.MustCompile(`^<(\d+)>1 (\S+) (\S+) (\S+) - (\S+) \[alice@32473 ((?:[^\]\\]|\\.)*)\] (.*)$`)
	paramRE = regexp.MustCompile(`(\w+)="((?:[^"\\]|\\.)*)"`)
)

type parsed struct {
	action string
	params map[string]string
}

func parse(t *testing.T, msg string) parsed {
	t.Helper()
	m := lineRE.FindStringSubmatch(msg)
	require.NotNil(t, m, msg)
	p := parsed{action: m[5], params: map[string]string{}}
	for _, kv := range paramRE.FindAllStringSubmatch(m[6], -1) {
		p.params[kv[1]] = kv[2]
	}
	return p
}

func parseAll(t *testing.T, msgs []string) []parsed {
	t.Helper()
	out := make([]parsed, 0, len(msgs))
	for _, m := range msgs {
		out = append(out, parse(t, m))
	}
	return out
}

// assertDelivered checks that got is exactly the rows with seq in (from, to], in order, each with its hashes.
func assertDelivered(t *testing.T, rows []audit.Entry, got []parsed, from, to int64) {
	t.Helper()
	require.Len(t, got, int(to-from))
	for i, p := range got {
		r := rows[int(from)+i]
		require.Equal(t, strconv.FormatInt(r.Seq, 10), p.params["seq"], "message %d", i)
		require.Equal(t, hex.EncodeToString(r.Hash), p.params["hash"])
		require.Equal(t, hex.EncodeToString(r.PrevHash), p.params["prev_hash"])
		require.Equal(t, r.Action, p.action)
	}
}

func TestForwardsInChainOrderWithHashes(t *testing.T) {
	s := fakesyslog.Start(t, fakesyslog.Options{TLS: true})
	e := newEnv(t, plainDial)
	ctx := context.Background()
	e.save(t, target(t, s, forward.TransportTLS))
	e.appendRows(t, 1200)
	rows := e.rows(t)
	require.Len(t, rows, 1201)

	for i, want := range []int{500, 1000, 1201} {
		require.NoError(t, e.f.Run(ctx), "run %d", i)
		received(t, s, want)
		st := e.state(t)
		assert.Equal(t, int64(want), st.CursorSeq)
		assert.Equal(t, int64(1201-want), st.Backlog)
		assert.Empty(t, st.LastErrorCode)
		assert.False(t, st.LastSentAt.IsZero())
	}
	assertDelivered(t, rows, received(t, s, 1201), 0, 1201)
	require.NoError(t, e.f.Run(ctx))
	received(t, s, 1201) // nothing new, nothing sent
}

func TestF96ReceiverDownNeverBlocksTheLocalWrite(t *testing.T) {
	ctx := context.Background()
	timeAppends := func(e *env) time.Duration {
		start := time.Now()
		for i := range 1000 {
			require.NoError(t, db.InTx(ctx, e.d.App, func(tx pgx.Tx) error {
				_, err := e.log.Append(ctx, tx, audit.Event{Actor: audit.SystemActor("scheduler"), Action: "test.row",
					ObjectType: "row", ObjectID: strconv.Itoa(i), Result: audit.Success})
				return err
			}))
		}
		return time.Since(start)
	}
	baseline := timeAppends(newEnv(t, plainDial)) // forwarding never enabled

	s := fakesyslog.Start(t, fakesyslog.Options{TLS: true})
	e := newEnv(t, plainDial)
	e.save(t, target(t, s, forward.TransportTLS))
	require.NoError(t, e.f.Run(ctx))
	head := e.state(t).CursorSeq
	require.Equal(t, int64(1), head)
	s.Down()

	stop := make(chan struct{})
	var wg sync.WaitGroup
	runs := 0
	wg.Go(func() { // the periodic task (every 15 s in production, every 100 ms here) keeps failing during the appends
		tick := time.NewTicker(100 * time.Millisecond)
		defer tick.Stop()
		for {
			select {
			case <-stop:
				return
			case <-tick.C:
				_ = e.f.Run(ctx)
				runs++
			}
		}
	})
	elapsed := timeAppends(e)
	close(stop)
	wg.Wait()
	require.Positive(t, runs, "the forwarder ran while the receiver was down")
	// ± 50 % of the run without forwarding; 250 ms absorb scheduler noise on short runs.
	assert.Less(t, elapsed, baseline*3/2+250*time.Millisecond, "baseline %v", baseline)

	err := e.f.Run(ctx)
	require.ErrorIs(t, err, forward.ErrUnreachable)
	st := e.state(t)
	assert.Equal(t, "unreachable", st.LastErrorCode)
	assert.False(t, st.LastErrorAt.IsZero())
	assert.Equal(t, head, st.CursorSeq, "the cursor does not move")
	assert.Equal(t, int64(1000), st.Backlog)

	require.NoError(t, s.Up())
	s.Clear()
	require.NoError(t, e.f.Run(ctx))
	require.NoError(t, e.f.Run(ctx))
	require.NoError(t, e.f.Run(ctx))
	assertDelivered(t, e.rows(t), received(t, s, 1000), head, head+1000)
	st = e.state(t)
	assert.Empty(t, st.LastErrorCode)
	assert.Equal(t, int64(0), st.Backlog)
}

func TestF92CheckpointIsForwarded(t *testing.T) {
	s := fakesyslog.Start(t, fakesyslog.Options{TLS: true})
	e := newEnv(t, plainDial)
	ctx := context.Background()
	e.save(t, target(t, s, forward.TransportTLS))
	e.appendRows(t, 3)
	require.NoError(t, e.f.Run(ctx))
	received(t, s, 4)
	s.Clear()

	_, err := audit.NewService(e.log, e.d.App).Verify(ctx, audit.SystemActor("scheduler"))
	require.NoError(t, err)
	cp, ok, err := audit.LastCheckpoint(ctx, e.d.App)
	require.NoError(t, err)
	require.True(t, ok)

	require.NoError(t, e.f.Run(ctx))
	got := received(t, s, 2) // the audit.verified row, then the checkpoint
	assert.Equal(t, "audit.verified", got[0].action)
	assert.Equal(t, "audit.checkpoint", got[1].action)
	assert.Equal(t, strconv.FormatInt(cp.Seq, 10), got[1].params["seq"])
	assert.Equal(t, cp.Hash, got[1].params["hash"])
	assert.Equal(t, cp.Seq, e.state(t).CheckpointSeq)

	require.NoError(t, e.f.Run(ctx))
	received(t, s, 2) // a checkpoint is sent once
}

func TestUntrustedCertificateIsRefused(t *testing.T) {
	s := fakesyslog.Start(t, fakesyslog.Options{TLS: true})
	e := newEnv(t, plainDial)
	ctx := context.Background()
	in := target(t, s, forward.TransportTLS)
	in.CAPEM = ""
	e.save(t, in)
	require.ErrorIs(t, e.f.Run(ctx), forward.ErrUntrusted)
	st := e.state(t)
	assert.Equal(t, "untrusted", st.LastErrorCode)
	assert.Equal(t, int64(0), st.CursorSeq)
	assert.Equal(t, int64(1), st.Backlog)
	assert.Empty(t, s.Messages())
	require.ErrorIs(t, e.f.Test(ctx, in), forward.ErrUntrusted)

	other := fakesyslog.Start(t, fakesyslog.Options{TLS: true})
	wrong := target(t, s, forward.TransportTLS)
	wrong.CAPEM = string(other.CAPEM())
	require.ErrorIs(t, e.f.Test(ctx, wrong), forward.ErrUntrusted, "another CA is no better")
}

func TestAddressRule(t *testing.T) {
	ctx := context.Background()
	e := newEnv(t, plainDial)
	for _, host := range []string{"169.254.169.254", "::ffff:169.254.169.254", "0.0.0.0", "224.0.0.1"} {
		in := forward.Settings{Enabled: true, Host: host, Port: 6514, Transport: forward.TransportTLS}
		_, err := e.f.Save(ctx, in, 0, admin)
		require.ErrorIs(t, err, forward.ErrAddressRefused, host)
		require.ErrorIs(t, e.f.Test(ctx, in), forward.ErrAddressRefused, host)
	}
	cur, _, err := e.f.Settings(ctx)
	require.NoError(t, err)
	assert.Equal(t, 0, cur.Version, "nothing stored")

	t.Run("the dialer refuses a stored link-local address", func(t *testing.T) {
		nd := newEnv(t, func(ctx context.Context, network, addr string) (net.Conn, error) {
			return netaddr.DialContext(ctx, &net.Dialer{Timeout: 2 * time.Second}, network, addr)
		})
		require.NoError(t, settings.Set(ctx, nd.d.App, "audit.forwarding", map[string]any{"enabled": true,
			"host": "169.254.169.254", "port": 6514, "transport": "tcp", "version": 1}, time.Now()))
		nd.appendRows(t, 1)
		require.ErrorIs(t, nd.f.Run(ctx), forward.ErrAddressRefused)
		st := nd.state(t)
		assert.Equal(t, "refused_address", st.LastErrorCode)
		assert.Equal(t, int64(0), st.CursorSeq)
	})
}

func TestUDPAndTCPOnlyWhenChosen(t *testing.T) {
	ctx := context.Background()
	e := newEnv(t, plainDial)
	def, st, err := e.f.Settings(ctx)
	require.NoError(t, err)
	assert.Equal(t, forward.Settings{Port: 6514, Transport: forward.TransportTLS}, def)
	assert.Equal(t, forward.State{}, st)

	s := fakesyslog.Start(t, fakesyslog.Options{UDP: true})
	for _, tr := range []forward.Transport{forward.TransportUDP, forward.TransportTCP} {
		s.Clear()
		in := target(t, s, tr)
		in.CAPEM = ""
		out := e.save(t, in)
		assert.Equal(t, tr, out.Transport)
		require.NoError(t, e.f.Test(ctx, in))
		assert.Equal(t, "audit.forwarding_test", received(t, s, 1)[0].action)
		before := e.state(t).CursorSeq
		require.NoError(t, e.f.Run(ctx), tr)
		rows := e.rows(t)
		after := e.state(t).CursorSeq
		assert.Equal(t, rows[len(rows)-1].Seq, after, tr)
		assertDelivered(t, rows, received(t, s, 1+int(after-before))[1:], before, after)
	}
	// TLS against a plain listener fails: plain TCP is never a fallback.
	in := target(t, s, forward.TransportTLS)
	require.ErrorIs(t, e.f.Test(ctx, in), forward.ErrUnreachable)
}

func TestSettingsAreAuditedAndVersioned(t *testing.T) {
	ctx := context.Background()
	s := fakesyslog.Start(t, fakesyslog.Options{TLS: true})
	e := newEnv(t, plainDial)
	in := target(t, s, forward.TransportTLS)
	out, err := e.f.Save(ctx, in, 0, admin)
	require.NoError(t, err)
	assert.Equal(t, 1, out.Version)
	assert.Empty(t, out.CAPEM)
	assert.True(t, out.CASet)

	rows := e.rows(t)
	require.Len(t, rows, 1)
	assert.Equal(t, "audit.forwarding_changed", rows[0].Action)
	assert.Equal(t, "admin", rows[0].ActorName)
	assert.Equal(t, map[string]string{"enabled": "true", "host": in.Host, "port": strconv.Itoa(in.Port),
		"transport": "tls", "ca_set": "true"}, rows[0].Details)

	_, err = e.f.Save(ctx, in, 0, admin)
	require.ErrorIs(t, err, forward.ErrVersion)

	keep := in
	keep.CAPEM, keep.CASet, keep.Enabled = "", true, false
	out, err = e.f.Save(ctx, keep, 1, admin)
	require.NoError(t, err)
	assert.True(t, out.CASet, "an empty CA with CASet keeps the stored bundle")
	assert.False(t, out.Enabled)
	require.NoError(t, e.f.Run(ctx), "disabled: nothing to do")
	received(t, s, 0)

	keep.Enabled = true
	_, err = e.f.Save(ctx, keep, 2, admin)
	require.NoError(t, err)
	require.NoError(t, e.f.Run(ctx), "the kept CA still trusts the receiver")
	received(t, s, 3)

	clear := keep
	clear.CASet = false
	out, err = e.f.Save(ctx, clear, 3, admin)
	require.NoError(t, err)
	assert.False(t, out.CASet)

	got, _, err := e.f.Settings(ctx)
	require.NoError(t, err)
	assert.Equal(t, out, got)
	pemLine := strings.Split(strings.TrimSpace(in.CAPEM), "\n")[1]
	for _, r := range e.rows(t) {
		for k, v := range r.Details {
			assert.NotContains(t, v, pemLine, "%s", k)
		}
	}

	var verrs validate.Errors
	_, err = e.f.Save(ctx, forward.Settings{Enabled: true, Host: "bad host", Port: 0, Transport: "smtp", CAPEM: "nonsense"}, 4, admin)
	require.True(t, errors.As(err, &verrs), err)
	fields := map[string]string{}
	for _, fe := range verrs {
		fields[fe.Field] = fe.Code
	}
	assert.Equal(t, map[string]string{"host": validate.Pattern, "port": validate.OutOfRange, "transport": validate.OneOf,
		"ca_pem": validate.Pattern}, fields)
	_, err = e.f.Save(ctx, forward.Settings{Enabled: true}, 4, admin)
	require.True(t, errors.As(err, &verrs), err)
	assert.Equal(t, "host", verrs[0].Field)
	off, err := e.f.Save(ctx, forward.Settings{}, 4, admin)
	require.NoError(t, err, "a disabled setting needs no host")
	assert.Equal(t, forward.TransportTLS, off.Transport)
	assert.Equal(t, 6514, off.Port)
}

func TestWriteFailureKeepsTheCursorAtTheLastWrittenRow(t *testing.T) {
	ctx := context.Background()
	s := fakesyslog.Start(t, fakesyslog.Options{UDP: true})
	e := newEnv(t, plainDial)
	in := target(t, s, forward.TransportUDP)
	in.CAPEM = ""
	e.save(t, in)
	e.appendRows(t, 200)
	s.Down() // the port answers ICMP "unreachable": the first datagram goes out, a later send fails
	err := e.f.Run(ctx)
	require.ErrorIs(t, err, forward.ErrUnreachable)
	st := e.state(t)
	assert.Equal(t, "write", st.LastErrorCode)
	assert.Positive(t, st.CursorSeq, "rows written before the failure count as sent (at most once)")
	assert.Less(t, st.CursorSeq, int64(201))
	assert.Equal(t, 201-st.CursorSeq, st.Backlog)
}

func TestTestUsesTheStoredOrConfiguredTrust(t *testing.T) {
	ctx := context.Background()
	s := fakesyslog.Start(t, fakesyslog.Options{TLS: true})
	e := newEnv(t, plainDial)
	in := target(t, s, forward.TransportTLS)
	e.save(t, in)
	kept := in
	kept.CAPEM, kept.CASet = "", true
	require.NoError(t, e.f.Test(ctx, kept), "the stored bundle")
	assert.Equal(t, "audit.forwarding_test", received(t, s, 1)[0].action)

	pool := x509.NewCertPool()
	require.True(t, pool.AppendCertsFromPEM(s.CAPEM()))
	d := pgtest.New(t)
	withRoots := forward.New(forward.Config{Pool: d.App, Audit: audit.New(clock.Real{}), Clock: clock.Real{}, Dial: plainDial,
		RootCAs: pool})
	bare := in
	bare.CAPEM = ""
	require.NoError(t, withRoots.Test(ctx, bare), "the configured roots")

	var verrs validate.Errors
	bare.Port = 70000
	require.True(t, errors.As(withRoots.Test(ctx, bare), &verrs))
}

func TestStorageFailuresAreReported(t *testing.T) {
	ctx := context.Background()
	for _, key := range []string{"audit.forwarding", "audit.forwarding.state"} {
		e := newEnv(t, plainDial)
		if key == "audit.forwarding.state" {
			e.save(t, forward.Settings{Enabled: true, Host: "127.0.0.1", Port: 1, Transport: forward.TransportTCP})
		}
		require.NoError(t, settings.Set(ctx, e.d.App, key, "not an object", time.Now()))
		_, _, err := e.f.Settings(ctx)
		require.Error(t, err, key)
		require.Error(t, e.f.Run(ctx), key)
		if key == "audit.forwarding" {
			_, err = e.f.Save(ctx, forward.Settings{}, 0, admin)
			require.Error(t, err)
			require.Error(t, e.f.Test(ctx, forward.Settings{Enabled: true, Host: "127.0.0.1", Port: 1, CASet: true}))
		}
	}

	e := newEnv(t, plainDial)
	e.save(t, forward.Settings{Enabled: true, Host: "127.0.0.1", Port: 1, Transport: forward.TransportTCP})
	e.d.App.Close()
	_, _, err := e.f.Settings(ctx)
	require.Error(t, err)
	require.Error(t, e.f.Run(ctx))
}
