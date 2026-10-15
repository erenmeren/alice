// Package mail renders plain-text e-mail that cannot smuggle extra header lines and sends it
// over SMTP with TLS. It exists so the vendor console can notify the owner without a
// third-party dependency; it knows nothing about licenses or the outbox.
package mail

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"mime"
	"mime/quotedprintable"
	"net"
	"net/mail"
	"net/smtp"
	"net/textproto"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"
)

const (
	dialTimeout    = 10 * time.Second
	messageTimeout = 30 * time.Second
	// maxSubjectRunes keeps a subject built from a long customer name readable and far below
	// the 998-byte line limit of RFC 5322 once encoded and folded.
	maxSubjectRunes = 250
	// foldAt is the RFC 5322 recommended line length that header folding aims for.
	foldAt = 78
)

// ErrHeaderInjection is returned when a header value would contain a line break. Such values
// are refused, never stripped: a CR or LF in an address or subject means the input is wrong.
var ErrHeaderInjection = errors.New("mail: header value contains a line break")

// Message is one plain-text e-mail.
type Message struct {
	From    string // RFC 5322 address; empty means the sender's configured From
	To      []string
	Subject string
	Body    string // plain text, UTF-8
}

// Bytes renders the message as RFC 5322 bytes with CRLF line endings, a Date taken from now and
// a Message-ID drawn from rnd. The body is quoted-printable; a non-ASCII subject is Q-encoded.
func (m Message) Bytes(now time.Time, rnd io.Reader) ([]byte, error) {
	from, err := parseAddress("from", m.From)
	if err != nil {
		return nil, err
	}
	if len(m.To) == 0 {
		return nil, errors.New("mail: no recipients")
	}
	to := make([]string, 0, len(m.To))
	for _, t := range m.To {
		a, err := parseAddress("to", t)
		if err != nil {
			return nil, err
		}
		to = append(to, a.String())
	}
	subject, err := headerText("subject", m.Subject)
	if err != nil {
		return nil, err
	}
	if utf8.RuneCountInString(subject) > maxSubjectRunes {
		subject = string([]rune(subject)[:maxSubjectRunes-1]) + "…"
	}
	id := make([]byte, 16)
	if _, err := io.ReadFull(rnd, id); err != nil {
		return nil, fmt.Errorf("mail: message id: %w", err)
	}
	domain := from.Address[strings.LastIndexByte(from.Address, '@')+1:]

	var b bytes.Buffer
	writeHeader(&b, "From", from.String())
	writeHeader(&b, "To", strings.Join(to, ", "))
	writeHeader(&b, "Subject", mime.QEncoding.Encode("utf-8", subject))
	writeHeader(&b, "Date", now.Format(time.RFC1123Z))
	writeHeader(&b, "Message-ID", "<"+hex.EncodeToString(id)+"@"+domain+">")
	writeHeader(&b, "MIME-Version", "1.0")
	writeHeader(&b, "Content-Type", "text/plain; charset=utf-8")
	writeHeader(&b, "Content-Transfer-Encoding", "quoted-printable")
	b.WriteString("\r\n")
	qp := quotedprintable.NewWriter(&b)
	// Text mode: the writer turns LF and CRLF into CRLF and keeps lines under 76 characters.
	if _, err := qp.Write([]byte(m.Body)); err != nil {
		return nil, fmt.Errorf("mail: body: %w", err)
	}
	if err := qp.Close(); err != nil {
		return nil, fmt.Errorf("mail: body: %w", err)
	}
	if !bytes.HasSuffix(b.Bytes(), []byte("\r\n")) {
		b.WriteString("\r\n")
	}
	return b.Bytes(), nil
}

// headerText refuses line breaks and turns every other control or Unicode line/paragraph
// separator into a space: they are not line breaks in RFC 5322 but some clients render them as
// one, which would make a crafted subject look like several lines.
func headerText(field, s string) (string, error) {
	if strings.ContainsAny(s, "\r\n") {
		return "", fmt.Errorf("mail: %s: %w", field, ErrHeaderInjection)
	}
	if !utf8.ValidString(s) {
		return "", fmt.Errorf("mail: %s is not valid utf-8", field)
	}
	return strings.Map(func(r rune) rune {
		if unicode.IsControl(r) || r == ' ' || r == ' ' {
			return ' '
		}
		return r
	}, s), nil
}

// parseAddress accepts exactly one address; a comma-separated list would let one field carry
// recipients the caller did not mean to add.
func parseAddress(field, s string) (*mail.Address, error) {
	if _, err := headerText(field, s); err != nil {
		return nil, err
	}
	a, err := mail.ParseAddress(s)
	if err != nil {
		return nil, fmt.Errorf("mail: %s address: %w", field, err)
	}
	return a, nil
}

// writeHeader writes "Name: value" folded at spaces (RFC 5322 section 2.2.3), so encoded words
// and address lists stay near 78 characters per line. Folding only inserts CRLF before an
// existing space, so unfolding gives the value back unchanged.
func writeHeader(b *bytes.Buffer, name, value string) {
	line := name + ":"
	for i, w := range strings.Split(value, " ") {
		if i > 0 && len(line)+1+len(w) > foldAt {
			b.WriteString(line + "\r\n")
			line = ""
		}
		line += " " + w
	}
	b.WriteString(line + "\r\n")
}

// SMTPConfig says how to reach the SMTP server.
type SMTPConfig struct {
	Addr     string // host:port; port 465 means implicit TLS, anything else STARTTLS
	User     string // empty means no AUTH
	Password string
	From     string
	// RootCAs lets tests trust a throw-away certificate; nil means the system pool.
	RootCAs *x509.CertPool

	// Test hooks: zero means the production value.
	dialTimeout    time.Duration
	messageTimeout time.Duration
	implicitTLS    bool
}

// Sender delivers one message. Send returns nil only when the server accepted the message.
type Sender interface {
	Send(ctx context.Context, m Message, now time.Time) error
}

type smtpSender struct {
	c        SMTPConfig
	host     string
	implicit bool
	from     *mail.Address
}

// NewSMTP checks the configuration and returns a sender. It does not connect.
func NewSMTP(c SMTPConfig) (Sender, error) {
	if c.Addr == "" {
		return nil, errors.New("mail: smtp address is empty")
	}
	host, port, err := net.SplitHostPort(c.Addr)
	if err != nil {
		return nil, fmt.Errorf("mail: smtp address must be host:port: %w", err)
	}
	if host == "" || port == "" {
		return nil, errors.New("mail: smtp address must be host:port")
	}
	if c.From == "" {
		return nil, errors.New("mail: from address is empty")
	}
	from, err := parseAddress("from", c.From)
	if err != nil {
		return nil, err
	}
	if (c.User == "") != (c.Password == "") {
		return nil, errors.New("mail: smtp user and password must be set together")
	}
	// AUTH PLAIN joins identity, user and password with NUL; a NUL or line break inside them
	// would change what the server reads.
	if strings.ContainsAny(c.User, "\x00\r\n") {
		return nil, errors.New("mail: smtp user contains a forbidden character")
	}
	if strings.ContainsAny(c.Password, "\x00\r\n") {
		return nil, errors.New("mail: smtp password contains a forbidden character")
	}
	return &smtpSender{c: c, host: host, implicit: port == "465" || c.implicitTLS, from: from}, nil
}

// Send renders m and delivers it. Errors never contain the password.
func (s *smtpSender) Send(ctx context.Context, m Message, now time.Time) error {
	if m.From == "" {
		m.From = s.c.From
	}
	data, err := m.Bytes(now, rand.Reader)
	if err != nil {
		return err
	}
	rcpts := make([]string, 0, len(m.To))
	for _, t := range m.To {
		a, err := mail.ParseAddress(t) // already validated by Bytes
		if err != nil {
			return fmt.Errorf("mail: to address: %w", err)
		}
		rcpts = append(rcpts, a.Address)
	}
	return s.scrub(s.deliver(ctx, rcpts, data))
}

func (s *smtpSender) deliver(ctx context.Context, rcpts []string, data []byte) error {
	ctx, cancel := context.WithTimeout(ctx, orDefault(s.c.messageTimeout, messageTimeout))
	defer cancel()
	d := net.Dialer{Timeout: orDefault(s.c.dialTimeout, dialTimeout)}
	conn, err := d.DialContext(ctx, "tcp", s.c.Addr)
	if err != nil {
		return fmt.Errorf("mail: connect to smtp server: %w", err)
	}
	defer func() { _ = conn.Close() }()
	// The deadline bounds every read and write of the exchange; closing on cancel also covers a
	// caller cancelling early.
	if dl, ok := ctx.Deadline(); ok {
		if err := conn.SetDeadline(dl); err != nil {
			return fmt.Errorf("mail: set deadline: %w", err)
		}
	}
	stop := context.AfterFunc(ctx, func() { _ = conn.Close() })
	defer stop()

	remote := remoteHost(conn, s.host)
	tlsCfg := &tls.Config{ServerName: s.host, RootCAs: s.c.RootCAs, MinVersion: tls.VersionTLS12}
	encrypted := false
	if s.implicit {
		tc := tls.Client(conn, tlsCfg)
		if err := tc.HandshakeContext(ctx); err != nil {
			return fmt.Errorf("mail: tls handshake: %w", err)
		}
		conn, encrypted = tc, true
	}
	cl, err := smtp.NewClient(conn, s.host)
	if err != nil {
		return fmt.Errorf("mail: smtp greeting: %w", err)
	}
	defer func() { _ = cl.Close() }()
	if !encrypted {
		has, _ := cl.Extension("STARTTLS")
		if err := requireTLS(remote, has); err != nil {
			return err
		}
		if has {
			if err := cl.StartTLS(tlsCfg); err != nil {
				return fmt.Errorf("mail: starttls: %w", err)
			}
			encrypted = true
		}
	}
	// Never AUTH over plain text: on a loopback relay without STARTTLS the credentials are
	// simply not sent.
	if s.c.User != "" && encrypted {
		if err := cl.Auth(smtp.PlainAuth("", s.c.User, s.c.Password, s.host)); err != nil {
			var tp *textproto.Error
			if errors.As(err, &tp) {
				// The reply text is the server's and could repeat what we sent; keep the code only.
				return fmt.Errorf("mail: smtp server refused authentication (code %d)", tp.Code)
			}
			return fmt.Errorf("mail: smtp authentication: %w", err)
		}
	}
	if err := cl.Mail(s.from.Address); err != nil {
		return fmt.Errorf("mail: smtp MAIL FROM: %w", err)
	}
	for _, r := range rcpts {
		if err := cl.Rcpt(r); err != nil {
			return fmt.Errorf("mail: smtp RCPT TO: %w", err)
		}
	}
	w, err := cl.Data()
	if err != nil {
		return fmt.Errorf("mail: smtp DATA: %w", err)
	}
	// The DATA writer does the dot-stuffing (RFC 5321 section 4.5.2).
	if _, err := w.Write(data); err != nil {
		return fmt.Errorf("mail: smtp DATA: %w", err)
	}
	if err := w.Close(); err != nil {
		return fmt.Errorf("mail: smtp DATA: %w", err)
	}
	// The server has accepted the message; a failed QUIT must not make the caller send it again.
	_ = cl.Quit()
	return nil
}

// requireTLS allows a connection without STARTTLS only to a loopback host (a local relay);
// anything else would send the message, and possibly credentials, in clear text.
func requireTLS(host string, hasSTARTTLS bool) error {
	if hasSTARTTLS {
		return nil
	}
	if strings.EqualFold(host, "localhost") {
		return nil
	}
	if ip := net.ParseIP(host); ip != nil && ip.IsLoopback() {
		return nil
	}
	return errors.New("mail: smtp server does not offer STARTTLS; refusing to send in clear text")
}

// remoteHost is the IP actually connected to, so a name that resolves to a public address is
// never treated as loopback.
func remoteHost(c net.Conn, fallback string) string {
	if a, ok := c.RemoteAddr().(*net.TCPAddr); ok {
		return a.IP.String()
	}
	return fallback
}

// scrub is the last line of defence: whatever a server echoes back, the password and its AUTH
// PLAIN encodings never leave in an error.
func (s *smtpSender) scrub(err error) error {
	if err == nil || s.c.Password == "" {
		return err
	}
	msg := err.Error()
	out := msg
	for _, sec := range []string{
		base64.StdEncoding.EncodeToString([]byte("\x00" + s.c.User + "\x00" + s.c.Password)),
		base64.StdEncoding.EncodeToString([]byte(s.c.Password)),
		s.c.Password,
	} {
		out = strings.ReplaceAll(out, sec, "[redacted]")
	}
	if out == msg {
		return err
	}
	// The wrapped error still holds the secret, so the chain is dropped.
	return errors.New(out)
}

func orDefault(d, def time.Duration) time.Duration {
	if d > 0 {
		return d
	}
	return def
}
