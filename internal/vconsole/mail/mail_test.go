package mail

import (
	"bytes"
	"context"
	"encoding/base64"
	"io"
	"mime"
	"mime/quotedprintable"
	"net/mail"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"alice/internal/vconsole/mail/mailtest"
)

var testNow = time.Date(2026, 10, 15, 9, 30, 0, 0, time.FixedZone("TRT", 3*3600))

// parse decodes rendered bytes the way a mail client would.
func parse(t *testing.T, raw []byte) (subject, body string, h mail.Header) {
	t.Helper()
	msg, err := mail.ReadMessage(bytes.NewReader(raw))
	require.NoError(t, err)
	subject, err = new(mime.WordDecoder).DecodeHeader(msg.Header.Get("Subject"))
	require.NoError(t, err)
	require.Equal(t, "quoted-printable", msg.Header.Get("Content-Transfer-Encoding"))
	b, err := io.ReadAll(quotedprintable.NewReader(msg.Body))
	require.NoError(t, err)
	return subject, strings.ReplaceAll(string(b), "\r\n", "\n"), msg.Header
}

func render(t *testing.T, m Message) []byte {
	t.Helper()
	raw, err := m.Bytes(testNow, bytes.NewReader(bytes.Repeat([]byte{0xab}, 16)))
	require.NoError(t, err)
	return raw
}

func TestBytesEncodesNonASCIISubjectAndBody(t *testing.T) {
	m := Message{
		From:    "Lisans Konsolu <licenses@vendor.example>",
		To:      []string{"owner@vendor.example", "Satış Ekibi <sales@vendor.example>"},
		Subject: "Lisans verildi: ç ğ ı ş Ç Ğ İ Ş",
		Body:    "Merhaba,\nMüşteri: Çağrı Işık Şahin\nBitiş: 2027-10-15\n",
	}
	raw := render(t, m)
	subject, body, h := parse(t, raw)
	assert.Equal(t, m.Subject, subject)
	assert.Equal(t, m.Body, body)
	assert.NotContains(t, string(raw), "ç", "non-ASCII must be encoded, not sent raw")

	assert.Equal(t, "1.0", h.Get("MIME-Version"))
	assert.Equal(t, "text/plain; charset=utf-8", h.Get("Content-Type"))
	assert.Equal(t, "<abababababababababababababababab@vendor.example>", h.Get("Message-ID"))
	d, err := h.Date()
	require.NoError(t, err)
	assert.True(t, d.Equal(testNow))

	to, err := h.AddressList("To")
	require.NoError(t, err)
	require.Len(t, to, 2)
	assert.Equal(t, "Satış Ekibi", to[1].Name)
	assert.Equal(t, "sales@vendor.example", to[1].Address)
	from, err := h.AddressList("From")
	require.NoError(t, err)
	assert.Equal(t, "licenses@vendor.example", from[0].Address)
}

func TestBytesRefusesLineBreaksInHeaders(t *testing.T) {
	ok := Message{From: "a@vendor.example", To: []string{"b@vendor.example"}, Subject: "s", Body: "b"}
	cases := map[string]func(m *Message){
		"CR in subject":    func(m *Message) { m.Subject = "renew\rBcc: x@evil.example" },
		"LF in subject":    func(m *Message) { m.Subject = "renew\nBcc: x@evil.example" },
		"CRLF in subject":  func(m *Message) { m.Subject = "renew\r\nBcc: x@evil.example" },
		"LF in from":       func(m *Message) { m.From = "a@vendor.example\nBcc: x@evil.example" },
		"CR in from name":  func(m *Message) { m.From = "Ac\rme <a@vendor.example>" },
		"CRLF in a to":     func(m *Message) { m.To = []string{"b@vendor.example", "c@vendor.example\r\nBcc: x@evil.example"} },
		"LF in a to name":  func(m *Message) { m.To = []string{"Bo\nb <b@vendor.example>"} },
		"CR at the end":    func(m *Message) { m.Subject = "renew\r" },
		"LF at the start":  func(m *Message) { m.Subject = "\nrenew" },
		"long customer LF": func(m *Message) { m.Subject = strings.Repeat("Çok Uzun Müşteri ", 100) + "\nX: y" },
	}
	for name, mut := range cases {
		t.Run(name, func(t *testing.T) {
			m := ok
			m.To = append([]string(nil), ok.To...)
			mut(&m)
			_, err := m.Bytes(testNow, bytes.NewReader(make([]byte, 16)))
			require.ErrorIs(t, err, ErrHeaderInjection)
		})
	}

	// Characters that are not RFC 5322 line breaks are allowed but become a plain space, so no
	// mail client shows them as a new line.
	for _, sep := range []string{"\t", " ", " ", "\u0085", "\v", "\f"} {
		m := ok
		m.Subject = "renew" + sep + "now"
		subject, _, _ := parse(t, render(t, m))
		assert.Equal(t, "renew now", subject, "%q", sep)
	}
}

func TestBytesUsesCRLFAndEndsWithBody(t *testing.T) {
	m := Message{From: "a@vendor.example", To: []string{"b@vendor.example"}, Subject: "Hi", Body: "line one\nline two\r\nlast line"}
	raw := string(render(t, m))
	assert.NotRegexp(t, regexp.MustCompile(`[^\r]\n`), raw, "bare LF")
	assert.NotRegexp(t, regexp.MustCompile("\r[^\n]"), raw, "bare CR")
	head, body, found := strings.Cut(raw, "\r\n\r\n")
	require.True(t, found)
	assert.Contains(t, head, "Subject: Hi\r\n")
	assert.Equal(t, "line one\r\nline two\r\nlast line\r\n", body)
	assert.True(t, strings.HasSuffix(raw, "last line\r\n"))
}

func TestBytesTruncatesAndFoldsLongSubject(t *testing.T) {
	for _, s := range []string{
		strings.Repeat("Çok Uzun Müşteri Adı ", 200),
		strings.Repeat("x", 5000),
		strings.Repeat("Ş", 5000),
	} {
		m := Message{From: "a@vendor.example", To: []string{"b@vendor.example"}, Subject: s, Body: "b"}
		raw := render(t, m)
		head, _, _ := strings.Cut(string(raw), "\r\n\r\n")
		for _, l := range strings.Split(head, "\r\n") {
			assert.LessOrEqual(t, len(l), 998, "RFC 5322 line limit")
			if !strings.HasPrefix(l, "Subject:") && !strings.HasPrefix(l, " ") {
				assert.Contains(t, l, ":", "every non-continuation line is a header")
			}
		}
		subject, _, _ := parse(t, raw)
		assert.True(t, strings.HasSuffix(subject, "…"))
		assert.True(t, strings.HasPrefix(s, strings.TrimSuffix(subject, "…")))
		assert.LessOrEqual(t, len([]rune(subject)), maxSubjectRunes)
	}
}

func TestBytesValidates(t *testing.T) {
	ok := Message{From: "a@vendor.example", To: []string{"b@vendor.example"}, Subject: "s"}
	for name, m := range map[string]Message{
		"no recipients": {From: ok.From, Subject: "s"},
		"bad from":      {From: "not an address", To: ok.To},
		"bad to":        {From: ok.From, To: []string{"nope"}},
		"two in one to": {From: ok.From, To: []string{"b@vendor.example, c@vendor.example"}},
		"invalid utf-8": {From: ok.From, To: ok.To, Subject: "\xff"},
	} {
		_, err := m.Bytes(testNow, bytes.NewReader(make([]byte, 16)))
		assert.Error(t, err, name)
	}
	_, err := ok.Bytes(testNow, bytes.NewReader(nil))
	assert.Error(t, err, "short random source")
}

func newTestSender(t *testing.T, srv *mailtest.Server, mod func(c *SMTPConfig)) Sender {
	t.Helper()
	c := SMTPConfig{
		Addr:     srv.Addr(),
		User:     "notifier",
		Password: "pw-for-tests",
		From:     "Vendor Console <console@vendor.example>",
		RootCAs:  srv.CertPool(),
	}
	if mod != nil {
		mod(&c)
	}
	s, err := NewSMTP(c)
	require.NoError(t, err)
	return s
}

func TestSendWithSTARTTLSAndAuth(t *testing.T) {
	srv := mailtest.Start(t, mailtest.Options{})
	s := newTestSender(t, srv, nil)
	m := Message{To: []string{"Owner <owner@vendor.example>", "sales@vendor.example"}, Subject: "Lisans: ş", Body: "hello"}
	require.NoError(t, s.Send(context.Background(), m, testNow))

	auths := srv.Auths()
	require.Len(t, auths, 1)
	assert.Equal(t, "notifier", auths[0].User)
	assert.Equal(t, "pw-for-tests", auths[0].Password)
	assert.True(t, auths[0].TLS, "AUTH only after STARTTLS")

	msgs := srv.Messages()
	require.Len(t, msgs, 1)
	assert.Equal(t, "console@vendor.example", msgs[0].From)
	assert.Equal(t, []string{"owner@vendor.example", "sales@vendor.example"}, msgs[0].To)
	subject, body, h := parse(t, msgs[0].Data)
	assert.Equal(t, "Lisans: ş", subject)
	assert.Equal(t, "hello\n", body)
	assert.Contains(t, h.Get("From"), "console@vendor.example", "an empty From takes the configured one")
}

func TestSendImplicitTLS(t *testing.T) {
	srv := mailtest.Start(t, mailtest.Options{ImplicitTLS: true})
	s := newTestSender(t, srv, func(c *SMTPConfig) { c.implicitTLS = true })
	require.NoError(t, s.Send(context.Background(), Message{To: []string{"o@vendor.example"}, Subject: "s", Body: "b"}, testNow))
	require.Len(t, srv.Messages(), 1)
	require.Len(t, srv.Auths(), 1)
	assert.True(t, srv.Auths()[0].TLS)
}

func TestSendRefusesAnUntrustedCertificate(t *testing.T) {
	srv := mailtest.Start(t, mailtest.Options{})
	s := newTestSender(t, srv, func(c *SMTPConfig) { c.RootCAs = nil })
	err := s.Send(context.Background(), Message{To: []string{"o@vendor.example"}, Subject: "s", Body: "b"}, testNow)
	require.Error(t, err)
	assert.Empty(t, srv.Auths(), "no credentials to a server we could not verify")
	assert.Empty(t, srv.Messages())
}

func TestBodyDotStuffingIsLeftToTheSMTPLibrary(t *testing.T) {
	srv := mailtest.Start(t, mailtest.Options{})
	s := newTestSender(t, srv, nil)
	body := "first\n.\n..two dots\n.leading\nlast\n"
	require.NoError(t, s.Send(context.Background(), Message{To: []string{"o@vendor.example"}, Subject: "s", Body: body}, testNow))
	msgs := srv.Messages()
	require.Len(t, msgs, 1)
	_, got, _ := parse(t, msgs[0].Data)
	assert.Equal(t, body, got)
}

func TestSendRefusesAuthWithoutTLS(t *testing.T) {
	for _, c := range []struct {
		host string
		tls  bool
		ok   bool
	}{
		{"127.0.0.1", false, true},
		{"127.8.9.10", false, true},
		{"::1", false, true},
		{"localhost", false, true},
		{"LocalHost", false, true},
		{"smtp.example.com", false, false},
		{"192.0.2.10", false, false},
		{"::ffff:192.0.2.10", false, false},
		{"localhost.evil.example", false, false},
		{"", false, false},
		{"smtp.example.com", true, true},
		{"192.0.2.10", true, true},
	} {
		err := requireTLS(c.host, c.tls)
		if c.ok {
			assert.NoError(t, err, "%s tls=%v", c.host, c.tls)
		} else {
			assert.Error(t, err, "%s tls=%v", c.host, c.tls)
		}
	}

	// A loopback server without STARTTLS gets the message, but never the credentials, even
	// though it advertises AUTH PLAIN.
	srv := mailtest.Start(t, mailtest.Options{NoSTARTTLS: true})
	s := newTestSender(t, srv, nil)
	require.NoError(t, s.Send(context.Background(), Message{To: []string{"o@vendor.example"}, Subject: "s", Body: "b"}, testNow))
	assert.Empty(t, srv.Auths())
	assert.Len(t, srv.Messages(), 1)
}

func TestSendTimesOut(t *testing.T) {
	srv := mailtest.Start(t, mailtest.Options{Silent: true})
	s := newTestSender(t, srv, func(c *SMTPConfig) { c.messageTimeout = 300 * time.Millisecond })
	start := time.Now()
	err := s.Send(context.Background(), Message{To: []string{"o@vendor.example"}, Subject: "s", Body: "b"}, testNow)
	require.Error(t, err)
	assert.Less(t, time.Since(start), 2*time.Second)
}

func TestSendHonoursContextCancel(t *testing.T) {
	srv := mailtest.Start(t, mailtest.Options{Silent: true})
	s := newTestSender(t, srv, nil)
	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()
	start := time.Now()
	require.Error(t, s.Send(ctx, Message{To: []string{"o@vendor.example"}, Subject: "s", Body: "b"}, testNow))
	assert.Less(t, time.Since(start), 2*time.Second)
}

func TestSendReportsRejectedRecipient(t *testing.T) {
	srv := mailtest.Start(t, mailtest.Options{RejectRCPT: true})
	s := newTestSender(t, srv, nil)
	err := s.Send(context.Background(), Message{To: []string{"o@vendor.example"}, Subject: "s", Body: "b"}, testNow)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "550")
	assert.Empty(t, srv.Messages())
}

func TestErrorsDoNotContainThePassword(t *testing.T) {
	const pw = "Zq9-distinctive-PASSWORD-7Xv"
	const user = "notifier"
	secrets := []string{
		pw,
		base64.StdEncoding.EncodeToString([]byte(pw)),
		base64.StdEncoding.EncodeToString([]byte("\x00" + user + "\x00" + pw)),
	}
	msg := Message{To: []string{"o@vendor.example"}, Subject: "s", Body: "b"}
	withPW := func(c *SMTPConfig) { c.User, c.Password = user, pw }

	closed := mailtest.Start(t, mailtest.Options{})
	closedAddr := closed.Addr()
	closed.Close()

	cases := map[string]struct {
		opts mailtest.Options
		mod  func(c *SMTPConfig)
	}{
		"auth refused, server echoes": {mailtest.Options{FailAuth: true, Echo: true}, nil},
		"rcpt refused, server echoes": {mailtest.Options{RejectRCPT: true, Echo: true}, nil},
		"untrusted certificate":       {mailtest.Options{Echo: true}, func(c *SMTPConfig) { c.RootCAs = nil }},
		"silent server":               {mailtest.Options{Silent: true}, func(c *SMTPConfig) { c.messageTimeout = 200 * time.Millisecond }},
		"implicit tls to plain":       {mailtest.Options{Echo: true}, func(c *SMTPConfig) { c.implicitTLS = true; c.messageTimeout = time.Second }},
		"connection refused":          {mailtest.Options{}, func(c *SMTPConfig) { c.Addr = closedAddr }},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			srv := mailtest.Start(t, tc.opts)
			s := newTestSender(t, srv, func(c *SMTPConfig) {
				withPW(c)
				if tc.mod != nil {
					tc.mod(c)
				}
			})
			err := s.Send(context.Background(), msg, testNow)
			require.Error(t, err)
			for _, sec := range secrets {
				assert.NotContains(t, err.Error(), sec)
				assert.NotContains(t, strings.ReplaceAll(err.Error(), " ", ""), sec)
			}
		})
	}

	// A server that echoes after a successful AUTH would put the password in the RCPT error:
	// the echo test above must have reached that point.
	srv := mailtest.Start(t, mailtest.Options{RejectRCPT: true, Echo: true})
	s := newTestSender(t, srv, withPW)
	err := s.Send(context.Background(), msg, testNow)
	require.Error(t, err)
	require.Len(t, srv.Auths(), 1)
	assert.Equal(t, pw, srv.Auths()[0].Password)
	assert.Contains(t, err.Error(), "[redacted]")

	// Validation errors too.
	for _, c := range []SMTPConfig{
		{Addr: "nohostport", User: user, Password: pw, From: "a@vendor.example"},
		{Addr: "h:25", User: user, Password: pw, From: "bad"},
		{Addr: "h:25", User: user + "\n", Password: pw, From: "a@vendor.example"},
		{Addr: "h:25", User: user, Password: pw + "\x00", From: "a@vendor.example"},
	} {
		_, err := NewSMTP(c)
		require.Error(t, err)
		assert.NotContains(t, err.Error(), pw)
	}
}

func TestNewSMTPValidates(t *testing.T) {
	good := SMTPConfig{Addr: "smtp.example.com:587", User: "u", Password: "p", From: "a@vendor.example"}
	_, err := NewSMTP(good)
	require.NoError(t, err)
	_, err = NewSMTP(SMTPConfig{Addr: "127.0.0.1:25", From: "a@vendor.example"})
	require.NoError(t, err, "no user means no AUTH")

	for name, mod := range map[string]func(c *SMTPConfig){
		"empty addr":           func(c *SMTPConfig) { c.Addr = "" },
		"no port":              func(c *SMTPConfig) { c.Addr = "smtp.example.com" },
		"empty host":           func(c *SMTPConfig) { c.Addr = ":587" },
		"empty port":           func(c *SMTPConfig) { c.Addr = "smtp.example.com:" },
		"empty from":           func(c *SMTPConfig) { c.From = "" },
		"bad from":             func(c *SMTPConfig) { c.From = "not an address" },
		"two froms":            func(c *SMTPConfig) { c.From = "a@vendor.example, b@vendor.example" },
		"from with LF":         func(c *SMTPConfig) { c.From = "a@vendor.example\nBcc: x@evil.example" },
		"password without usr": func(c *SMTPConfig) { c.User = "" },
		"user without pw":      func(c *SMTPConfig) { c.Password = "" },
		"NUL in password":      func(c *SMTPConfig) { c.Password = "p\x00q" },
		"CR in user":           func(c *SMTPConfig) { c.User = "u\r" },
	} {
		c := good
		mod(&c)
		_, err := NewSMTP(c)
		assert.Error(t, err, name)
	}
}

func TestAddressesRefuseQuotedAndNonASCIILocalParts(t *testing.T) {
	bad := []string{
		`"x@evil.example> NOTIFY=NEVER"@vendor.example`,
		`Eve <"x@evil.example> NOTIFY=NEVER"@vendor.example>`,
		`"a>b"@c.dd`,
		`"a b"@c.dd`,
		`a@b.cc,x@y.zz`,
		`jöhn@example.com`,
		`john@exämple.com`,
		`a\b@c.dd`,
		`.a@c.dd`,
		`a..b@c.dd`,
		`a@-c..dd`,
		`a@c_d.dd`,
	}
	for _, a := range bad {
		m := Message{From: "a@vendor.example", To: []string{a}, Subject: "s", Body: "b"}
		_, err := m.Bytes(testNow, bytes.NewReader(make([]byte, 16)))
		assert.Error(t, err, "to %s", a)
		m = Message{From: a, To: []string{"b@vendor.example"}, Subject: "s", Body: "b"}
		_, err = m.Bytes(testNow, bytes.NewReader(make([]byte, 16)))
		assert.Error(t, err, "from %s", a)
		_, err = NewSMTP(SMTPConfig{Addr: "h:25", From: a})
		assert.Error(t, err, "config from %s", a)
	}

	// A refused recipient never reaches the server.
	srv := mailtest.Start(t, mailtest.Options{})
	s := newTestSender(t, srv, nil)
	err := s.Send(context.Background(), Message{To: []string{bad[0]}, Subject: "s", Body: "b"}, testNow)
	require.Error(t, err)
	assert.Empty(t, srv.Messages())

	// A display name still works; envelope and header carry the same plain address.
	m := Message{To: []string{"Eren <eren@example.com>", `"Altan, Eren" <e.altan+x@sub.example.com>`, "Çağrı Işık <c@example.com>"}, Subject: "s", Body: "b"}
	require.NoError(t, s.Send(context.Background(), m, testNow))
	msgs := srv.Messages()
	require.Len(t, msgs, 1)
	assert.Equal(t, []string{"eren@example.com", "e.altan+x@sub.example.com", "c@example.com"}, msgs[0].To)
	_, _, h := parse(t, msgs[0].Data)
	to, err := h.AddressList("To")
	require.NoError(t, err)
	require.Len(t, to, 3)
	assert.Equal(t, mail.Address{Name: "Eren", Address: "eren@example.com"}, *to[0])
	assert.Equal(t, mail.Address{Name: "Altan, Eren", Address: "e.altan+x@sub.example.com"}, *to[1])
	assert.Equal(t, mail.Address{Name: "Çağrı Işık", Address: "c@example.com"}, *to[2])
}

func TestBytesEncodesEncodedWordLookalikes(t *testing.T) {
	for _, s := range []string{"=?utf-8?b?SGVsbG8=?=", "Renew =?utf-8?q?Hi?= now", "a=?b"} {
		m := Message{From: "a@vendor.example", To: []string{"b@vendor.example"}, Subject: s, Body: "b"}
		raw := render(t, m)
		subject, _, _ := parse(t, raw)
		assert.Equal(t, s, subject)

		// The same for a display name. (net/mail decodes encoded words in its input, so the
		// rendering is tested directly.)
		got, err := mail.ParseAddress(address{name: s, addr: "b@vendor.example"}.header())
		require.NoError(t, err)
		assert.Equal(t, s, got.Name)
	}
}

func TestHeaderFoldingHasNoBlankContinuation(t *testing.T) {
	// "Subject:" + 35 one-letter words ends exactly at column 78; then a trailing space.
	words := strings.TrimSpace(strings.Repeat("a ", 35))
	for _, s := range []string{words + " ", words + "  x", words + "   ", strings.Repeat("ab ", 60)} {
		m := Message{From: "a@vendor.example", To: []string{"b@vendor.example"}, Subject: s, Body: "b"}
		raw := render(t, m)
		head, _, _ := strings.Cut(string(raw), "\r\n\r\n")
		for _, l := range strings.Split(head, "\r\n") {
			assert.NotEmpty(t, strings.TrimSpace(l), "whitespace-only header line in %q", head)
		}
		subject, _, _ := parse(t, raw)
		// net/textproto collapses the whitespace around a fold, so compare words.
		assert.Equal(t, strings.Fields(s), strings.Fields(subject))
	}
	var b bytes.Buffer
	writeHeader(&b, "Subject", strings.Repeat("x", 69)+" ")
	for _, l := range strings.Split(strings.TrimSuffix(b.String(), "\r\n"), "\r\n") {
		assert.NotEmpty(t, strings.TrimSpace(l), "%q", b.String())
	}
}

func TestValidateAddress(t *testing.T) {
	for _, ok := range []string{"a@b.co", "e.altan+x@sub.example.com", "o'brien@example.com", "x_y@a-b.example",
		"!#$%&'*+/=?^_`{|}~-@example.com"} {
		assert.NoError(t, ValidateAddress(ok), ok)
	}
	for _, bad := range []string{"", "a", "a@b", "a@localhost", "@b.co", "a@", "a@@b.co", "a b@c.co", "a@b .co",
		".a@b.co", "a.@b.co", "a..b@c.co", "a@-b.co", "a@b-.co", "a@b..co", "a@.b.co", "a@b.co.", "a@b_c.co",
		"ayşe@example.com", "a@exämple.com", `"a"@b.co`, "Boss <boss@example.com>", "a@b.co\r", "a@b.co\nBcc: x@y.co",
		"a@b.co,c@d.co", strings.Repeat("a", 250) + "@b.co"} {
		err := ValidateAddress(bad)
		assert.Error(t, err, "%q", bad)
		assert.ErrorIs(t, err, ErrInvalidMessage, "%q", bad)
	}
}

func TestLocalValidationErrorsAreInvalidMessage(t *testing.T) {
	rnd := func() io.Reader { return bytes.NewReader(bytes.Repeat([]byte{1}, 16)) }
	for name, m := range map[string]Message{
		"bad to":        {From: "a@b.co", To: []string{"not an address"}, Subject: "s"},
		"no recipients": {From: "a@b.co", Subject: "s"},
		"bad from":      {From: "x", To: []string{"a@b.co"}, Subject: "s"},
		"quoted local":  {From: "a@b.co", To: []string{`"x y"@b.co`}, Subject: "s"},
	} {
		_, err := m.Bytes(testNow, rnd())
		assert.ErrorIs(t, err, ErrInvalidMessage, name)
	}
	_, err := Message{From: "a@b.co", To: []string{"a@b.co"}, Subject: "hi\r\nBcc: x@y.co"}.Bytes(testNow, rnd())
	assert.ErrorIs(t, err, ErrInvalidMessage)
	assert.ErrorIs(t, err, ErrHeaderInjection, "the older sentinel still matches")

	srv := mailtest.Start(t, mailtest.Options{})
	s := newTestSender(t, srv, nil)
	err = s.Send(context.Background(), Message{To: []string{"no at sign"}, Subject: "s", Body: "b"}, testNow)
	assert.ErrorIs(t, err, ErrInvalidMessage)
	assert.Empty(t, srv.Messages())
}

func TestDeliveryErrorsAreNotInvalidMessage(t *testing.T) {
	srv := mailtest.Start(t, mailtest.Options{RejectRCPT: true})
	s := newTestSender(t, srv, nil)
	err := s.Send(context.Background(), Message{To: []string{"a@b.co"}, Subject: "s", Body: "b"}, testNow)
	require.Error(t, err)
	assert.NotErrorIs(t, err, ErrInvalidMessage, "a refusal by the server may be temporary and is retried")
}
