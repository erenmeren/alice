// Package http01 is the HTTP-01 solver: it publishes the key authorization of a challenge as one token file
// on the server the name points at, through a Publisher (the target's alice-helper, protocol 7), checks that
// the file is served at http://<name>/.well-known/acme-challenge/<token> before the CA is asked to validate,
// and removes the file again.
//
// Alice never edits the web server's configuration: the administrator publishes the fixed webroot on port 80
// themselves (docs/nginx-host-preparation.md, "Publishing HTTP-01 challenges"). The solver only asks the
// helper to write and remove one file, for names below the configured allowed suffixes (an empty list refuses
// every name), and never for a wildcard (HTTP-01 cannot validate one).
//
// The check is Alice's own GET on port 80 (plain HTTP is inherent to HTTP-01): every connection through
// netaddr, no proxy, no redirect followed (a redirect is a failure: the answer must come from that URL), a
// short timeout, a 1 KiB answer cap and a bounded number of attempts; the body must equal the key
// authorization exactly. Errors are *acme.Error values with the reasons of internal/acme and never carry a URL
// or an answer body:
//
//	acme.ReasonNameNotAllowed       the name is not below an allowed suffix (nothing is published or fetched)
//	acme.ReasonChallengeUnavailable not an HTTP-01 challenge this solver publishes (wildcard, malformed token
//	                                or key authorization), or the server's helper or sudoers file predates
//	                                the HTTP-01 commands (the publisher's error says "reinstall the helper")
//	acme.ReasonValidationFailedHTTP the publisher failed, or the published file is not served as expected
package http01

import (
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"

	"alice/internal/acme"
	"alice/internal/acme/solver"
	"alice/internal/platform/netaddr"
)

// Limits and defaults.
const (
	DefaultVerifyAttempts = 5
	MaxVerifyAttempts     = 10
	DefaultVerifyInterval = time.Second
	MinVerifyInterval     = 100 * time.Millisecond
	MaxVerifyInterval     = 5 * time.Second
	// FetchTimeout bounds one GET (connect, headers and body).
	FetchTimeout = 5 * time.Second
	// MaxBodyBytes is how much of an answer is read.
	MaxBodyBytes = 1 << 10
	// UserAgent is sent with every check.
	UserAgent = "alice-acme/1"

	// Token and key authorization rules of the helper (helperproto.ValidACMEToken and ValidKeyAuthorization;
	// this package must not import the provider).
	minToken      = 22
	maxToken      = 128
	thumbprintLen = 43

	cleanupTimeout = 30 * time.Second
	httpPort       = 80
)

// Configuration and check errors (fixed text: never a URL or a body).
var (
	ErrNoPublisher = errors.New("http01: no publisher")
	ErrSuffix      = errors.New("http01: an allowed suffix is not a DNS suffix")
	ErrVerify      = errors.New("http01: a verification setting is out of range")
	// ErrNotServed is the cause of a check that never saw the key authorization at the URL.
	ErrNotServed = errors.New("http01: the token is not served at its URL")
	// ErrRedirected is the cause of a check that got a redirect (never followed).
	ErrRedirected = errors.New("http01: the token URL answers with a redirect")
	// ErrPublish is the cause of a publisher failure (the publisher's own error is kept behind it).
	ErrPublish = errors.New("http01: the token file could not be published")
)

// Publisher writes and removes the token file on the server the name points at. *linuxssh.Conn implements it
// (PublishHTTP01Token and RemoveHTTP01Token); a missing file is not an error for RemoveHTTP01Token.
type Publisher interface {
	PublishHTTP01Token(ctx context.Context, token string, keyAuthorization []byte) error
	RemoveHTTP01Token(ctx context.Context, token string) (removed bool, err error)
}

// helperOutdated is implemented by a publisher error that means the server cannot run the HTTP-01 commands
// until its helper is reinstalled (linuxssh.ErrHTTP01HelperOutdated); found with errors.As.
type helperOutdated interface{ HTTP01HelperOutdated() bool }

// Config configures a Solver.
type Config struct {
	// Publisher writes the token file (required).
	Publisher Publisher
	// AllowedSuffixes limits the names: "example.com" admits example.com and every name below it;
	// ".example.com" only the names below it. Empty refuses everything.
	AllowedSuffixes []string
	// VerifyAttempts is how many times the URL is fetched before giving up. 0 means 5; at most 10.
	VerifyAttempts int
	// VerifyInterval is the pause between two fetches. 0 means 1 s; 100 ms to 5 s.
	VerifyInterval time.Duration
}

// Solver implements solver.Solver for HTTP-01.
type Solver struct {
	pub      Publisher
	suffixes []string
	attempts int
	interval time.Duration
	client   *http.Client

	// Test seams (unexported: the dial always goes through netaddr).
	port     int
	resolver *net.Resolver
	sleep    func(context.Context, time.Duration) error
}

var _ solver.Solver = (*Solver)(nil)

// New validates the configuration and builds the solver. It makes no network call.
func New(cfg Config) (*Solver, error) {
	if cfg.Publisher == nil {
		return nil, ErrNoPublisher
	}
	s := &Solver{pub: cfg.Publisher, attempts: cfg.VerifyAttempts, interval: cfg.VerifyInterval, port: httpPort, sleep: sleepCtx}
	if s.attempts == 0 {
		s.attempts = DefaultVerifyAttempts
	}
	if s.interval == 0 {
		s.interval = DefaultVerifyInterval
	}
	if s.attempts < 1 || s.attempts > MaxVerifyAttempts || s.interval < MinVerifyInterval || s.interval > MaxVerifyInterval {
		return nil, ErrVerify
	}
	for _, raw := range cfg.AllowedSuffixes {
		n, ok := normSuffix(raw)
		if !ok {
			return nil, ErrSuffix
		}
		s.suffixes = append(s.suffixes, n)
	}
	s.client = &http.Client{
		Timeout: FetchTimeout,
		Transport: &http.Transport{
			Proxy: nil,
			DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
				return netaddr.DialContext(ctx, &net.Dialer{Timeout: FetchTimeout, Resolver: s.resolver}, network, addr)
			},
			DisableKeepAlives:      true,
			ResponseHeaderTimeout:  FetchTimeout,
			MaxResponseHeaderBytes: 16 << 10,
		},
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
	return s, nil
}

// Types implements solver.Solver.
func (*Solver) Types() []string { return []string{solver.HTTP01} }

// Present publishes the token file and returns once Alice itself fetched the key authorization from the
// token's URL. A cancelled or expired ctx returns ctx.Err().
func (s *Solver) Present(ctx context.Context, ch solver.Challenge) error {
	d, err := s.prepare(ch)
	if err != nil {
		return err
	}
	if err := s.pub.PublishHTTP01Token(ctx, ch.Token, []byte(ch.KeyAuth)); err != nil {
		return s.publishError(ctx, err, d)
	}
	return s.verify(ctx, d, ch)
}

// CleanUp removes the token file. It uses its own bounded context, so it still runs after the order's
// context was cancelled; a file that is not there (Present failed before it wrote it) is success. A challenge
// Present refused before publishing has nothing to remove.
func (s *Solver) CleanUp(ctx context.Context, ch solver.Challenge) error {
	d, err := s.prepare(ch)
	if err != nil {
		return nil //nolint:nilerr // Present refused this challenge before anything was published
	}
	cctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), cleanupTimeout)
	defer cancel()
	if _, err := s.pub.RemoveHTTP01Token(cctx, ch.Token); err != nil {
		return s.publishError(cctx, err, d)
	}
	return nil
}

// prepare checks the challenge and the allow-list before anything is published or fetched and returns the
// normalized name.
func (s *Solver) prepare(ch solver.Challenge) (string, error) {
	if ch.Type != solver.HTTP01 || ch.Wildcard || strings.HasPrefix(ch.Domain, "*.") || !validToken(ch.Token) ||
		!validKeyAuth(ch.Token, ch.KeyAuth) || (ch.HTTPPath != "" && ch.HTTPPath != solver.HTTPPathPrefix+ch.Token) {
		return "", acme.SolverError(acme.ReasonChallengeUnavailable, safeID(ch.Domain), nil)
	}
	d, ok := normDomain(ch.Domain)
	if !ok || !s.allowed(d) {
		return "", &acme.Error{Reason: acme.ReasonNameNotAllowed, Identifier: safeID(ch.Domain)}
	}
	return d, nil
}

func (s *Solver) publishError(ctx context.Context, err error, d string) error {
	if ce := ctx.Err(); ce != nil {
		return ce
	}
	var o helperOutdated
	if errors.As(err, &o) && o.HTTP01HelperOutdated() {
		return acme.SolverError(acme.ReasonChallengeUnavailable, d, err)
	}
	return acme.SolverError(acme.ReasonValidationFailedHTTP, d, errors.Join(ErrPublish, err))
}

// verify fetches the token's URL until it answers 200 with exactly the key authorization.
func (s *Solver) verify(ctx context.Context, d string, ch solver.Challenge) error {
	url := "http://" + net.JoinHostPort(d, strconv.Itoa(s.port)) + solver.HTTPPathPrefix + ch.Token
	cause := ErrNotServed
	for attempt := 1; ; attempt++ {
		ok, redirected := s.fetch(ctx, url, d, ch.KeyAuth)
		if ok {
			return nil
		}
		if ce := ctx.Err(); ce != nil {
			return ce
		}
		if redirected {
			cause = ErrRedirected
		}
		if attempt >= s.attempts {
			return acme.SolverError(acme.ReasonValidationFailedHTTP, d, cause)
		}
		if err := s.sleep(ctx, s.interval); err != nil {
			return err
		}
	}
}

// fetch makes one GET; ok is a 200 whose body is exactly want.
func (s *Solver) fetch(ctx context.Context, url, host, want string) (ok, redirected bool) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return false, false
	}
	req.Host = host
	req.Header.Set("User-Agent", UserAgent)
	req.Header.Set("Accept", "*/*")
	res, err := s.client.Do(req)
	if err != nil {
		return false, false // a *url.Error carries the URL: dropped
	}
	defer res.Body.Close()
	b, err := io.ReadAll(io.LimitReader(res.Body, MaxBodyBytes+1))
	switch {
	case res.StatusCode >= 300 && res.StatusCode < 400:
		return false, true
	case res.StatusCode != http.StatusOK || err != nil || len(b) > MaxBodyBytes:
		return false, false
	}
	return string(b) == want, false
}

func sleepCtx(ctx context.Context, d time.Duration) error {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-t.C:
		return nil
	}
}

func isBase64URL(c byte) bool {
	return c >= 'A' && c <= 'Z' || c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-' || c == '_'
}

// validToken is the helper's token rule: 22 to 128 base64url characters.
func validToken(t string) bool {
	if len(t) < minToken || len(t) > maxToken {
		return false
	}
	for i := 0; i < len(t); i++ {
		if !isBase64URL(t[i]) {
			return false
		}
	}
	return true
}

// validKeyAuth is the helper's key authorization rule: token "." 43 base64url characters, nothing else.
func validKeyAuth(token, ka string) bool {
	rest, ok := strings.CutPrefix(ka, token+".")
	if !ok || len(rest) != thumbprintLen {
		return false
	}
	for i := 0; i < len(rest); i++ {
		if !isBase64URL(rest[i]) {
			return false
		}
	}
	return true
}

func safeID(domain string) string {
	if d, ok := normDomain(domain); ok {
		return d
	}
	return ""
}

// normDomain lower-cases a name, strips a trailing dot and checks its characters (the dns01 rule).
func normDomain(d string) (string, bool) {
	d = strings.TrimSuffix(asciiLower(d), ".")
	if d == "" || len(d) > 253 {
		return "", false
	}
	for _, l := range strings.Split(d, ".") {
		if l == "" || len(l) > 63 || l[0] == '-' || l[len(l)-1] == '-' {
			return "", false
		}
		for i := 0; i < len(l); i++ {
			c := l[i]
			if (c < 'a' || c > 'z') && (c < '0' || c > '9') && c != '-' {
				return "", false
			}
		}
	}
	return d, true
}

// normSuffix keeps a leading dot (subdomains only) and validates the rest (the dns01 rule).
func normSuffix(raw string) (string, bool) {
	raw = strings.TrimSpace(raw)
	dot := strings.HasPrefix(raw, ".")
	d, ok := normDomain(strings.TrimPrefix(raw, "."))
	if !ok || strings.HasPrefix(raw, "*") || strings.HasSuffix(raw, ".") {
		return "", false
	}
	if dot {
		return "." + d, true
	}
	return d, true
}

// allowed matches at label boundaries only: "example.com" admits "a.example.com", never "badexample.com".
func (s *Solver) allowed(d string) bool {
	for _, sf := range s.suffixes {
		if strings.HasPrefix(sf, ".") {
			if strings.HasSuffix(d, sf) {
				return true
			}
		} else if d == sf || strings.HasSuffix(d, "."+sf) {
			return true
		}
	}
	return false
}

func asciiLower(s string) string {
	b := []byte(s)
	for i, c := range b {
		if c >= 'A' && c <= 'Z' {
			b[i] = c + 'a' - 'A'
		}
	}
	return string(b)
}
