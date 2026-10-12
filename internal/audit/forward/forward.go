// Package forward sends the audit log to a syslog receiver (SEC-073, R43 row 31): RFC 5424 messages with
// octet-counting frames over TLS (system roots plus an optional CA bundle) by default, plain TCP or UDP only
// when chosen. The outbox is the audit log itself, read in sequence order from a cursor kept in the setting
// audit.forwarding.state; each message carries the row's seq, hash and prev_hash, and every new chain
// checkpoint is forwarded once (F-92). Delivery is at most once: the cursor moves after a write returned (TCP,
// TLS) or a datagram was sent (UDP), and a returned write is only in the kernel's buffer, so a reset can lose
// messages; the collector sees the gap through seq and prev_hash. The audit write path never calls this
// package (F-96): a receiver that is down only grows the backlog.
package forward

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"strconv"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"

	"alice/internal/audit"
	"alice/internal/platform/clock"
	"alice/internal/platform/netaddr"
	"alice/internal/platform/validate"
	"alice/internal/platform/settings"
)

// Transport is how messages reach the receiver.
type Transport string

// Transports. TLS is the default; the others are used only when an Administrator chooses them.
const (
	TransportTLS Transport = "tls"
	TransportTCP Transport = "tcp"
	TransportUDP Transport = "udp"
)

// Settings is the forwarding configuration (setting audit.forwarding). CAPEM is write-only: readers get "" and
// CASet; on Save an empty CAPEM with CASet keeps the stored bundle.
type Settings struct {
	Enabled   bool
	Host      string
	Port      int
	Transport Transport
	CAPEM     string
	CASet     bool
	Version   int
}

// State is the forwarding progress (setting audit.forwarding.state).
type State struct {
	CursorSeq     int64     `json:"cursor_seq"`     // the last row sent
	CheckpointSeq int64     `json:"checkpoint_seq"` // the seq of the last checkpoint sent
	LastSentAt    time.Time `json:"last_sent_at"`
	LastErrorCode string    `json:"last_error_code"` // "", "unreachable", "untrusted", "refused_address", "write"
	LastErrorAt   time.Time `json:"last_error_at"`
	Backlog       int64     `json:"backlog"` // rows not sent yet
}

// Config wires a Forwarder.
type Config struct {
	Pool  *pgxpool.Pool
	Audit *audit.Log
	Clock clock.Clock
	Log   *slog.Logger // nil: discard
	// Dial opens the connection; nil is netaddr.DialContext (the address rule of SEC-065) with a timeout.
	Dial     func(ctx context.Context, network, addr string) (net.Conn, error)
	Hostname string         // the HOSTNAME of every message; "" is "-"
	AppName  string         // "" is "alice"
	RootCAs  *x509.CertPool // nil = system roots
}

// Forwarder reads the audit log from its cursor and sends it.
type Forwarder struct {
	pool     *pgxpool.Pool
	audit    *audit.Log
	clock    clock.Clock
	log      *slog.Logger
	dial     func(ctx context.Context, network, addr string) (net.Conn, error)
	hostname string
	app      string
	roots    *x509.CertPool
	run      sync.Mutex
}

// testMessageAction names the message Test sends. It is a syslog MSGID only, never an audit row.
const testMessageAction = "audit.forwarding_test"

// MaxBatch is the number of rows one Run sends at most.
const MaxBatch = 500

const (
	connectTimeout = 10 * time.Second
	writeTimeout   = 30 * time.Second
)

// Errors. The API maps them to ALC-AUD-0002, ALC-AUD-0003, ALC-AUD-0004 and ALC-SYS-0008.
var (
	ErrAddressRefused = errors.New("forward: the receiver's address is not one Alice connects to")
	ErrUnreachable    = errors.New("forward: the syslog receiver cannot be reached")
	ErrUntrusted      = errors.New("forward: the syslog receiver's certificate is not trusted")
	ErrVersion        = errors.New("forward: the forwarding settings changed since they were read")
)

// Error codes stored in State.LastErrorCode.
const (
	codeUnreachable = "unreachable"
	codeUntrusted   = "untrusted"
	codeRefused     = "refused_address"
	codeWrite       = "write"
)

// New returns a Forwarder.
func New(c Config) *Forwarder {
	f := &Forwarder{pool: c.Pool, audit: c.Audit, clock: c.Clock, log: c.Log, dial: c.Dial, hostname: c.Hostname,
		app: c.AppName, roots: c.RootCAs}
	if f.log == nil {
		f.log = slog.New(slog.DiscardHandler)
	}
	if f.dial == nil {
		f.dial = func(ctx context.Context, network, addr string) (net.Conn, error) {
			return netaddr.DialContext(ctx, &net.Dialer{Timeout: connectTimeout}, network, addr)
		}
	}
	if f.app == "" {
		f.app = "alice"
	}
	return f
}

// Settings returns the configuration (without the CA bundle) and the progress, the backlog counted now.
func (f *Forwarder) Settings(ctx context.Context) (Settings, State, error) {
	rec, err := load(ctx, f.pool)
	if err != nil {
		return Settings{}, State{}, err
	}
	st, err := loadState(ctx, f.pool)
	if err != nil {
		return Settings{}, State{}, err
	}
	head, err := f.head(ctx)
	if err != nil {
		return Settings{}, State{}, err
	}
	st.Backlog = max(head-st.CursorSeq, 0)
	return rec.view(), st, nil
}

// Test sends one test message with in (the stored CA bundle when in.CAPEM is empty and in.CASet is true).
func (f *Forwarder) Test(ctx context.Context, in Settings) error {
	in, err := normalize(in)
	if err != nil {
		return err
	}
	if in.Host == "" {
		// A disabled configuration may leave the host empty, a test may not: ":<port>" dials the local machine.
		var v validate.Errors
		v.Add("host", validate.Required, nil)
		return v.Err()
	}
	rec := record{Host: in.Host, Port: in.Port, Transport: in.Transport, CAPEM: in.CAPEM}
	if in.CAPEM == "" && in.CASet {
		old, err := load(ctx, f.pool)
		if err != nil {
			return err
		}
		rec.CAPEM = old.CAPEM
	}
	conn, _, err := f.connect(ctx, rec)
	if err != nil {
		return err
	}
	defer func() { _ = conn.Close() }()
	msg := message(audit.Entry{At: f.clock.Now(), ActorType: audit.ActorSystem, ActorName: f.app,
		Action: testMessageAction, ObjectType: "setting", ObjectID: settingsKey, Result: audit.Success},
		f.hostname, f.app)
	if err := f.write(conn, rec.Transport, msg); err != nil {
		return fmt.Errorf("%w: %w", ErrUnreachable, err)
	}
	return nil
}

// Run is the audit.forward task: it sends up to MaxBatch rows after the cursor, then a new checkpoint whose rows
// were all sent. Disabled forwarding does nothing. A failure keeps the cursor at the last row written, records
// the error code and is retried at the next tick. Concurrent calls in one process run one at a time.
func (f *Forwarder) Run(ctx context.Context) error {
	if !f.run.TryLock() {
		return nil
	}
	defer f.run.Unlock()
	rec, err := load(ctx, f.pool)
	if err != nil || !rec.Enabled {
		return err
	}
	st, err := loadState(ctx, f.pool)
	if err != nil {
		return err
	}
	head, err := f.head(ctx)
	if err != nil {
		return err
	}
	rows, err := f.after(ctx, st.CursorSeq)
	if err != nil {
		return err
	}
	cp, hasCP, err := audit.LastCheckpoint(ctx, f.pool)
	if err != nil {
		return err
	}
	last := st.CursorSeq
	if len(rows) > 0 {
		last = rows[len(rows)-1].Seq
	}
	sendCP := hasCP && cp.Seq > st.CheckpointSeq && cp.Seq <= last
	if len(rows) == 0 && !sendCP {
		return nil // nothing to send; Settings counts the backlog when it is read
	}

	conn, code, err := f.connect(ctx, rec)
	if err == nil {
		defer func() { _ = conn.Close() }()
		_ = conn.SetWriteDeadline(f.clock.Now().Add(writeTimeout))
		err = f.send(conn, rec.Transport, rows, cp, sendCP, &st)
		if err != nil {
			code, err = codeWrite, fmt.Errorf("%w: %w", ErrUnreachable, err)
		}
	}
	now := f.clock.Now().UTC()
	if err != nil {
		st.LastErrorCode, st.LastErrorAt = code, now
		f.log.Warn("audit forwarding failed", "code", code, "host", rec.Host, "port", rec.Port, "cursor_seq", st.CursorSeq)
	} else {
		st.LastErrorCode, st.LastSentAt = "", now
	}
	st.Backlog = max(head-st.CursorSeq, 0)
	if serr := settings.Set(ctx, f.pool, stateKey, st, now); serr != nil {
		return errors.Join(err, fmt.Errorf("forward: %w", serr))
	}
	return err
}

// send writes the rows, advancing st.CursorSeq after each write, then the checkpoint.
func (f *Forwarder) send(conn net.Conn, tr Transport, rows []audit.Entry, cp audit.Checkpoint, sendCP bool, st *State) error {
	for _, r := range rows {
		if err := f.write(conn, tr, message(r, f.hostname, f.app)); err != nil {
			return err
		}
		st.CursorSeq = r.Seq
	}
	if sendCP {
		if err := f.write(conn, tr, checkpointMessage(cp, f.hostname, f.app)); err != nil {
			return err
		}
		st.CheckpointSeq = cp.Seq
	}
	return nil
}

func (f *Forwarder) write(conn net.Conn, tr Transport, msg []byte) error {
	if tr != TransportUDP {
		msg = octetFrame(msg)
	}
	_, err := conn.Write(msg)
	return err
}

// connect opens the transport. Its error is ErrAddressRefused, ErrUnreachable or ErrUntrusted, with the state code.
func (f *Forwarder) connect(ctx context.Context, rec record) (net.Conn, string, error) {
	ctx, cancel := context.WithTimeout(ctx, connectTimeout)
	defer cancel()
	network := "tcp"
	if rec.Transport == TransportUDP {
		network = "udp"
	}
	conn, err := f.dial(ctx, network, net.JoinHostPort(rec.Host, strconv.Itoa(rec.Port)))
	if err != nil {
		if errors.Is(err, netaddr.ErrNotAllowed) {
			return nil, codeRefused, fmt.Errorf("%w: %w", ErrAddressRefused, err)
		}
		return nil, codeUnreachable, fmt.Errorf("%w: %w", ErrUnreachable, err)
	}
	if rec.Transport != TransportTLS {
		return conn, "", nil
	}
	roots, err := f.rootPool(rec.CAPEM)
	if err != nil {
		_ = conn.Close()
		return nil, codeUntrusted, fmt.Errorf("%w: %w", ErrUntrusted, err)
	}
	tc := tls.Client(conn, &tls.Config{ServerName: rec.Host, RootCAs: roots, MinVersion: tls.VersionTLS12})
	if err := tc.HandshakeContext(ctx); err != nil {
		_ = conn.Close()
		if untrusted(err) {
			return nil, codeUntrusted, fmt.Errorf("%w: %w", ErrUntrusted, err)
		}
		return nil, codeUnreachable, fmt.Errorf("%w: %w", ErrUnreachable, err)
	}
	return tc, "", nil
}

func (f *Forwarder) rootPool(caPEM string) (*x509.CertPool, error) {
	var pool *x509.CertPool
	if f.roots != nil {
		pool = f.roots.Clone()
	} else {
		sys, err := x509.SystemCertPool()
		if err != nil {
			return nil, err
		}
		pool = sys
	}
	if caPEM != "" && !pool.AppendCertsFromPEM([]byte(caPEM)) {
		return nil, errors.New("the stored CA bundle has no certificate")
	}
	return pool, nil
}

// untrusted reports a certificate the client refused (as opposed to a network failure during the handshake).
func untrusted(err error) bool {
	var (
		unknown  x509.UnknownAuthorityError
		hostname x509.HostnameError
		invalid  x509.CertificateInvalidError
		verify   *tls.CertificateVerificationError
	)
	return errors.As(err, &unknown) || errors.As(err, &hostname) || errors.As(err, &invalid) || errors.As(err, &verify)
}

func (f *Forwarder) head(ctx context.Context) (int64, error) {
	var head int64
	if err := f.pool.QueryRow(ctx, `SELECT COALESCE(max(seq), 0) FROM audit_log`).Scan(&head); err != nil {
		return 0, fmt.Errorf("forward: read the chain head: %w", err)
	}
	return head, nil
}

// after reads up to MaxBatch rows with seq > cursor in sequence order: only the columns a message carries.
func (f *Forwarder) after(ctx context.Context, cursor int64) ([]audit.Entry, error) {
	rows, err := f.pool.Query(ctx, `SELECT seq, at, actor_type, actor_name, action, object_type, object_id, result,
		details, prev_hash, hash FROM audit_log WHERE seq > $1 ORDER BY seq LIMIT $2`, cursor, MaxBatch)
	if err != nil {
		return nil, fmt.Errorf("forward: read the audit log: %w", err)
	}
	defer rows.Close()
	var out []audit.Entry
	for rows.Next() {
		var (
			e                 audit.Entry
			actorType, result string
			details           map[string]string
		)
		if err := rows.Scan(&e.Seq, &e.At, &actorType, &e.ActorName, &e.Action, &e.ObjectType, &e.ObjectID, &result,
			&details, &e.PrevHash, &e.Hash); err != nil {
			return nil, fmt.Errorf("forward: read the audit log: %w", err)
		}
		e.ActorType, e.Result, e.Details, e.ActorID = audit.ActorType(actorType), audit.Result(result), details, uuid.Nil
		out = append(out, e)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("forward: read the audit log: %w", err)
	}
	return out, nil
}
