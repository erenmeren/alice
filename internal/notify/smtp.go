package notify

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"fmt"
	"mime"
	"net"
	"net/mail"
	"net/smtp"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"

	"alice/internal/platform/clock"
	"alice/internal/platform/netaddr"
	"alice/internal/secrets"
)

// Classified SMTP failures. The server's own text is never kept: it may echo addresses
// or, for some servers, parts of the credentials.
var (
	ErrSMTPConnect  = errors.New("notify: cannot connect to the mail server")
	ErrSMTPTLS      = errors.New("notify: the mail server's encryption failed or is not offered")
	ErrSMTPAuth     = errors.New("notify: the mail server rejected the user name or password")
	ErrSMTPRejected = errors.New("notify: the mail server refused the message")

	// Phase 7: a certificate that did not verify (wrapped by CertError together with ErrSMTPTLS) and a host on an
	// address Alice never connects to (netaddr, A-14).
	ErrSMTPUntrusted  = errors.New("notify: the mail server's certificate is not trusted")
	ErrAddressRefused = errors.New("notify: the mail server's address is not one Alice connects to")
)

// ErrorCode is the fixed label of a send failure (notifications_outbox.last_error_code).
func ErrorCode(err error) string {
	switch {
	case errors.Is(err, ErrAddressRefused):
		return "smtp.address_refused"
	case errors.Is(err, ErrSMTPUntrusted):
		return "smtp.untrusted"
	case errors.Is(err, ErrSMTPConnect):
		return "smtp.connect"
	case errors.Is(err, ErrSMTPTLS):
		return "smtp.tls"
	case errors.Is(err, ErrSMTPAuth):
		return "smtp.auth"
	case errors.Is(err, ErrSMTPRejected):
		return "smtp.rejected"
	default:
		return "smtp.error"
	}
}

// SMTPConfig configures the mailer (Phase 2: from ALICE_SMTP_* variables, R36 item 14).
type SMTPConfig struct {
	Host     string
	Port     int
	From     string
	Username string // "" = no authentication
	Password secrets.Plaintext
	TLSMode  string         // "starttls" (default, port 587) or "tls" (implicit TLS, port 465)
	RootCAs  *x509.CertPool // nil = the system's trusted roots
	Pin      string         // lower-case hex SHA-256 of the one accepted leaf; "" = verify the chain (Phase 7)
	// Dial connects; nil = netaddr.DialContext with a net.Dialer (A-14, R42 row 11; Phase 7).
	Dial func(ctx context.Context, network, addr string) (net.Conn, error)
}

// SMTPMailer sends email over an encrypted SMTP connection. There is no plaintext mode.
type SMTPMailer struct {
	cfg   SMTPConfig
	from  *mail.Address
	clock clock.Clock
}

// NewSMTPMailer validates c.
func NewSMTPMailer(c SMTPConfig, clk clock.Clock) (*SMTPMailer, error) {
	if c.Host == "" || strings.ContainsAny(c.Host, " \t\r\n/") {
		return nil, errors.New("notify: the SMTP host is not valid")
	}
	if c.Port < 1 || c.Port > 65535 {
		return nil, errors.New("notify: the SMTP port must be between 1 and 65535")
	}
	if c.TLSMode == "" {
		c.TLSMode = "starttls"
	}
	if c.TLSMode != "starttls" && c.TLSMode != "tls" {
		return nil, errors.New(`notify: the SMTP TLS mode must be "starttls" or "tls"`)
	}
	from, err := mail.ParseAddress(c.From)
	if err != nil {
		return nil, errors.New("notify: the SMTP sender address is not valid")
	}
	return &SMTPMailer{cfg: c, from: from, clock: clk}, nil
}

// Send delivers one message: TCP, TLS (implicit or STARTTLS, required), optional
// AUTH PLAIN, then MAIL/RCPT/DATA. ctx bounds the whole exchange.
func (m *SMTPMailer) Send(ctx context.Context, msg Message) error {
	to, err := mail.ParseAddress(msg.To)
	if err != nil {
		return fmt.Errorf("%w: the recipient address is not valid", ErrSMTPRejected)
	}
	addr := net.JoinHostPort(m.cfg.Host, strconv.Itoa(m.cfg.Port))
	conn, err := m.dial(ctx, "tcp", addr)
	if errors.Is(err, netaddr.ErrNotAllowed) {
		return ErrAddressRefused
	}
	if err != nil {
		return fmt.Errorf("%w (%s)", ErrSMTPConnect, addr)
	}
	defer func() { _ = conn.Close() }()
	if deadline, ok := ctx.Deadline(); ok {
		_ = conn.SetDeadline(deadline)
	}
	tlsCfg := m.tlsConfig()
	if m.cfg.TLSMode == "tls" {
		tc := tls.Client(conn, tlsCfg)
		if err := tc.HandshakeContext(ctx); err != nil {
			return tlsFailure(err)
		}
		conn = tc
	}
	c, err := smtp.NewClient(conn, m.cfg.Host)
	if err != nil {
		return ErrSMTPConnect
	}
	defer func() { _ = c.Close() }()
	if m.cfg.TLSMode == "starttls" {
		if ok, _ := c.Extension("STARTTLS"); !ok {
			return fmt.Errorf("%w: STARTTLS is not offered", ErrSMTPTLS)
		}
		if err := c.StartTLS(tlsCfg); err != nil {
			return tlsFailure(err)
		}
	}
	if m.cfg.Username != "" {
		if err := c.Auth(smtp.PlainAuth("", m.cfg.Username, string(m.cfg.Password.Bytes()), m.cfg.Host)); err != nil {
			return ErrSMTPAuth
		}
	}
	if err := c.Mail(m.from.Address); err != nil {
		return ErrSMTPRejected
	}
	if err := c.Rcpt(to.Address); err != nil {
		return ErrSMTPRejected
	}
	w, err := c.Data()
	if err != nil {
		return ErrSMTPRejected
	}
	if _, err := w.Write(m.compose(to, msg)); err != nil {
		return ErrSMTPRejected
	}
	if err := w.Close(); err != nil {
		return ErrSMTPRejected
	}
	_ = c.Quit() // the message is accepted; a failing QUIT changes nothing
	return nil
}

func (m *SMTPMailer) dial(ctx context.Context, network, addr string) (net.Conn, error) {
	if m.cfg.Dial != nil {
		return m.cfg.Dial(ctx, network, addr)
	}
	return netaddr.DialContext(ctx, &net.Dialer{}, network, addr)
}

func (m *SMTPMailer) tlsConfig() *tls.Config {
	if m.cfg.Pin != "" {
		return pinnedTLS(m.cfg.Host, m.cfg.Pin)
	}
	return &tls.Config{ServerName: m.cfg.Host, MinVersion: tls.VersionTLS12, RootCAs: m.cfg.RootCAs}
}

// tlsFailure keeps a certificate problem's leaf (F-62: the Administrator sees what to trust) and nothing else of the
// server's answer.
func tlsFailure(err error) error {
	var ce *CertError
	if errors.As(err, &ce) {
		return ce
	}
	var ve *tls.CertificateVerificationError
	if errors.As(err, &ve) && len(ve.UnverifiedCertificates) > 0 {
		return &CertError{Cert: infoOf(ve.UnverifiedCertificates[0])}
	}
	return ErrSMTPTLS
}

// compose builds a plain-text UTF-8 message. The subject is one logical line, capped,
// Q-encoded and folded (subjectHeader); the body is base64 so any language and line length is safe.
func (m *SMTPMailer) compose(to *mail.Address, msg Message) []byte {
	var b bytes.Buffer
	header := func(k, v string) { b.WriteString(k + ": " + v + "\r\n") }
	header("From", m.from.String())
	header("To", to.String())
	header("Subject", subjectHeader(msg.Subject))
	header("Date", m.clock.Now().Format(time.RFC1123Z))
	header("Message-ID", "<"+uuid.NewString()+"@alice.invalid>")
	header("MIME-Version", "1.0")
	header("Content-Type", "text/plain; charset=UTF-8")
	header("Content-Transfer-Encoding", "base64")
	b.WriteString("\r\n")
	enc := base64.StdEncoding.EncodeToString([]byte(strings.ReplaceAll(msg.Body, "\n", "\r\n")))
	for len(enc) > 76 {
		b.WriteString(enc[:76] + "\r\n")
		enc = enc[76:]
	}
	b.WriteString(enc + "\r\n")
	return b.Bytes()
}

// MaxSubjectRunes is the longest subject sent; a longer one is cut with an ellipsis (a certificate's name can be 300
// characters long).
const MaxSubjectRunes = 200

// subjectHeader is the Subject value: one line, at most MaxSubjectRunes characters, Q-encoded, and folded between its
// encoded words (each at most 75 octets), so no header line exceeds the 998 octets of RFC 5322 a strict server enforces.
func subjectHeader(subject string) string {
	s := oneLine(subject)
	if r := []rune(s); len(r) > MaxSubjectRunes {
		s = string(r[:MaxSubjectRunes-1]) + "…"
	}
	enc := mime.QEncoding.Encode("utf-8", s)
	if enc == s {
		return s // plain ASCII, at most MaxSubjectRunes octets
	}
	return strings.ReplaceAll(enc, "?= =?", "?=\r\n =?")
}

// oneLine collapses all whitespace, including CR and LF, to single spaces.
func oneLine(s string) string { return strings.Join(strings.Fields(s), " ") }
