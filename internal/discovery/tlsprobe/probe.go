// Package tlsprobe is the isolated capture path of network certificate discovery (plan
// 2026-10-13-network-discovery, decision 2, amendment A6). CapturePresentedChain opens one connection
// through a dialer the caller supplies, runs a TLS client handshake, records the certificate chain the
// server presented (as DER, in the order presented), the negotiated version and cipher suite, and
// closes the connection. It sends no application byte, not even a close_notify alert.
//
// It is the one place in Alice where a TLS client does not verify the server (InsecureSkipVerify, in
// CapturePresentedChain only): discovery must see expired, self-signed and wrongly chained
// certificates. It therefore trusts nothing: the result holds certificates and never a "verified"
// bit, and the package exports no *tls.Config. guard_test.go enforces this structurally.
//
// The package never dials by itself (no net.Dialer, no proxy): the caller's DialFunc is the only
// way out, so the caller's scan policy (netaddr.ScanDialContext) decides every address.
//
// Errors: a failure is an *Error whose Code is one of the closed set of discovery_endpoints.
// last_error_code (refused, timeout, no_tls, reset, chain_too_large, policy, malformed); Go's error
// text never leaves the package. A cancelled or expired context is returned as the context's own
// error.
package tlsprobe

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"io"
	"net"
	"os"
	"slices"
	"strings"
	"syscall"
	"time"

	"alice/internal/platform/clock"
	"alice/internal/platform/netaddr"
)

// DialFunc opens the TCP connection to address ("host:port"). The scanner passes a function that
// dials through netaddr.ScanDialContext, so its scan policy checks every address at connect time and
// owns the 3 s connect timeout.
type DialFunc func(ctx context.Context, network, address string) (net.Conn, error)

// Code is why a probe produced no certificate chain (discovery_endpoints.last_error_code).
type Code string

// The closed set of probe failure codes (migration 00014, discovery_endpoints.last_error_code).
const (
	CodeRefused       Code = "refused"         // the connection could not be made (refused, or the network or host is unreachable)
	CodeTimeout       Code = "timeout"         // the connection or the handshake did not finish in time
	CodeNoTLS         Code = "no_tls"          // the server does not speak TLS to us (not a TLS record, an alert, any other handshake failure)
	CodeReset         Code = "reset"           // the server reset or closed the connection during the handshake
	CodeChainTooLarge Code = "chain_too_large" // the chain or the handshake is larger than the limits below
	CodePolicy        Code = "policy"          // the scan policy refused the address (never dialed)
	CodeMalformed     Code = "malformed"       // a certificate Go cannot parse (no certificate body is recorded)
)

// Codes lists every code in a stable order.
var Codes = []Code{CodeRefused, CodeTimeout, CodeNoTLS, CodeReset, CodeChainTooLarge, CodePolicy, CodeMalformed}

// Error is a probe or parse failure. Its text is the code only: it carries no Go error string, no
// address and nothing the server sent.
type Error struct{ Code Code }

func (e *Error) Error() string { return "tlsprobe: " + string(e.Code) }

// CodeOf returns the code of an *Error in err's chain.
func CodeOf(err error) (Code, bool) {
	var e *Error
	if errors.As(err, &e) {
		return e.Code, true
	}
	return "", false
}

// Limits (decision 2). A chain may hold at most MaxCertificates certificates, each at most
// MaxCertificateSize bytes of DER and MaxChainSize bytes together; larger chains are chain_too_large.
// MaxHandshakeBytes bounds everything read from the server before the handshake finishes: the chain
// (MaxChainSize) plus 64 KiB for the rest of the server's flight (record headers and TLS 1.3 record
// overhead, ServerHello, key exchange, a CertificateRequest with its CA names, CertificateVerify,
// Finished). A server that sends more is cut off at that byte: chain_too_large. HandshakeTimeout
// bounds the whole handshake from the moment the connection is open (the connect timeout is the
// dialer's).
const (
	MaxCertificates    = 10
	MaxCertificateSize = 16 << 10
	MaxChainSize       = 64 << 10
	MaxHandshakeBytes  = MaxChainSize + 64<<10
	HandshakeTimeout   = 5 * time.Second
)

// handshakeTimeout is HandshakeTimeout; tests shorten it.
var handshakeTimeout = HandshakeTimeout

// wall is the real clock: network deadlines are real time.
var wall clock.Clock = clock.Real{}

// Result is what a server presented. It deliberately has no "verified" or "trusted" field: nothing
// here was verified.
type Result struct {
	Certificates [][]byte // DER, leaf first, in the order the server presented them
	TLSVersion   string   // "TLS 1.0" ... "TLS 1.3"
	CipherSuite  string   // the negotiated suite's IANA name
	SNI          string   // the server name sent ("" when none was sent)
}

// errChainTooLarge is what the byte limit and the chain check return inside the handshake.
var errChainTooLarge = errors.New("tlsprobe: chain too large")

// CapturePresentedChain connects to addr through dial, runs a TLS handshake offering TLS 1.0 to 1.3
// and every cipher suite Go implements, records the chain the server presents and closes the
// connection without sending anything else. sni is sent as the server name unless it is empty or
// an IP literal (then no SNI is sent).
func CapturePresentedChain(ctx context.Context, dial DialFunc, addr string, sni string) (Result, error) {
	if dial == nil {
		return Result{}, &Error{Code: CodePolicy} // no dialer, no connection: fail closed
	}
	if err := ctx.Err(); err != nil {
		return Result{}, err
	}
	conn, err := dial(ctx, "tcp", addr)
	if err != nil {
		return Result{}, failure(ctx, err, false)
	}
	// Closing the TCP connection, never the TLS one: tls.Conn.Close would send a close_notify alert.
	defer func() { _ = conn.Close() }()
	if err := conn.SetDeadline(handshakeDeadline(ctx, wall.Now(), handshakeTimeout)); err != nil {
		return Result{}, failure(ctx, err, true)
	}
	serverName := serverNameFor(sni)
	var presented [][]byte
	suites := make([]uint16, 0, 32)
	for _, s := range tls.CipherSuites() {
		suites = append(suites, s.ID)
	}
	for _, s := range tls.InsecureCipherSuites() {
		suites = append(suites, s.ID)
	}
	cfg := &tls.Config{
		InsecureSkipVerify: true, //nolint:gosec // G402: discovery records the presented chain and trusts nothing
		ServerName:         serverName,
		MinVersion:         tls.VersionTLS10,
		MaxVersion:         tls.VersionTLS13,
		CipherSuites:       suites,
		// NextProtos stays empty: no ALPN, nothing that hints at an application protocol.
		SessionTicketsDisabled: true,
		VerifyPeerCertificate: func(raw [][]byte, _ [][]*x509.Certificate) error {
			if !chainWithinLimits(raw) {
				return errChainTooLarge
			}
			presented = cloneChain(raw)
			return nil
		},
	}
	tc := tls.Client(&limitedConn{Conn: conn, left: MaxHandshakeBytes}, cfg)
	if err := tc.HandshakeContext(ctx); err != nil {
		return Result{}, failure(ctx, err, true)
	}
	state := tc.ConnectionState()
	if len(presented) == 0 {
		return Result{}, &Error{Code: CodeNoTLS}
	}
	return Result{Certificates: presented, TLSVersion: tls.VersionName(state.Version),
		CipherSuite: tls.CipherSuiteName(state.CipherSuite), SNI: serverName}, nil
}

// handshakeDeadline is the earlier of now+limit and the context's deadline.
func handshakeDeadline(ctx context.Context, now time.Time, limit time.Duration) time.Time {
	d := now.Add(limit)
	if cd, ok := ctx.Deadline(); ok && cd.Before(d) {
		return cd
	}
	return d
}

// serverNameFor is the SNI to send: none for an empty name or an IP literal (with or without
// brackets or a zone, the forms crypto/tls itself leaves out), the name without trailing dots
// otherwise (what crypto/tls sends).
func serverNameFor(sni string) string {
	host := sni
	if len(host) > 1 && host[0] == '[' && host[len(host)-1] == ']' {
		host = host[1 : len(host)-1]
	}
	if i := strings.LastIndex(host, "%"); i > 0 {
		host = host[:i]
	}
	if net.ParseIP(host) != nil {
		return ""
	}
	return strings.TrimRight(sni, ".")
}

// chainWithinLimits checks the presented chain against MaxCertificates, MaxCertificateSize and
// MaxChainSize.
func chainWithinLimits(raw [][]byte) bool {
	if len(raw) > MaxCertificates {
		return false
	}
	total := 0
	for _, c := range raw {
		if len(c) > MaxCertificateSize {
			return false
		}
		total += len(c)
	}
	return total <= MaxChainSize
}

func cloneChain(raw [][]byte) [][]byte {
	out := make([][]byte, len(raw))
	for i, c := range raw {
		out[i] = slices.Clone(c)
	}
	return out
}

// limitedConn fails the read once left bytes have been read: the server's whole handshake flight is
// bounded, whatever it claims. It only reads; writes are crypto/tls's own handshake messages.
type limitedConn struct {
	net.Conn
	left int64
}

func (c *limitedConn) Read(p []byte) (int, error) {
	if c.left <= 0 {
		return 0, errChainTooLarge
	}
	if int64(len(p)) > c.left {
		p = p[:c.left]
	}
	n, err := c.Conn.Read(p)
	c.left -= int64(n)
	return n, err
}

// Go's texts for the two failures crypto/tls reports without a typed error (Go 1.27.2,
// crypto/tls handshake_client.go verifyServerCertificate and conn.go readHandshake). They are matched
// exactly from the start and pinned by tests against the fake fleet (TestGoErrorTextsArePinned), so a
// Go upgrade that changes them fails loudly instead of misclassifying.
const (
	goCertificateParseFailure = "tls: failed to parse certificate from server: x509: "
	goHandshakeTooLarge       = "tls: handshake message of length "
	goHandshakeTooLargeMiddle = " exceeds maximum of "
)

// failure maps an error to the closed set. The context's own error wins: a cancelled or expired
// context is returned as it is. A timeout at or after the context's deadline is that deadline (the
// connection's deadline was the context's, and its timer may not have fired yet).
func failure(ctx context.Context, err error, handshake bool) error {
	if cerr := ctx.Err(); cerr != nil {
		return cerr
	}
	code := codeFor(err, handshake)
	if d, ok := ctx.Deadline(); ok && code == CodeTimeout && !wall.Now().Before(d) {
		return context.DeadlineExceeded
	}
	return &Error{Code: code}
}

// codeFor classifies err. handshake is false for a dial failure.
func codeFor(err error, handshake bool) Code {
	text := err.Error()
	var ne net.Error
	switch {
	case errors.Is(err, netaddr.ErrScanRefused):
		return CodePolicy
	case errors.Is(err, errChainTooLarge),
		strings.HasPrefix(text, goHandshakeTooLarge) && strings.Contains(text, goHandshakeTooLargeMiddle):
		return CodeChainTooLarge
	case handshake && strings.HasPrefix(text, goCertificateParseFailure):
		return CodeMalformed
	case errors.Is(err, os.ErrDeadlineExceeded), errors.As(err, &ne) && ne.Timeout():
		return CodeTimeout
	case errors.Is(err, syscall.ECONNREFUSED):
		return CodeRefused
	case errors.Is(err, syscall.ECONNRESET), errors.Is(err, syscall.ECONNABORTED), errors.Is(err, syscall.EPIPE):
		return CodeReset
	case !handshake:
		return CodeRefused // unreachable network or host, or any other failure to connect
	case errors.Is(err, io.EOF), errors.Is(err, io.ErrUnexpectedEOF):
		return CodeReset // the server closed the connection during the handshake
	}
	return CodeNoTLS // not a TLS record, an alert, or any other handshake failure
}
