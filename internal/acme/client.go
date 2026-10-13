// Package acme is Alice's RFC 8555 client: a thin, swappable wrapper over golang.org/x/crypto/acme that adds
// what the library lacks or does differently from what Alice needs:
//
//   - every call runs under a deadline (Config.CallTimeout per call, Config.OrderTimeout per order);
//   - the library never sleeps on a rate limit or a server error: RetryBackoff answers 0 for both, so a 429
//     surfaces at once as a *RateLimitedError with the CA's Retry-After (capped at 24 h) and a 5xx as
//     ReasonProviderUnreachable; only badNonce is retried (three times, without a real pause);
//   - every error is an *Error with a stable reason of an ALC-ACM code; its text never holds a CA body or
//     header, a URL, the account key or the external account binding key (plan A10);
//   - the directory is read a second time by this package for renewalInfo (RFC 9773), which the library's
//     Directory lacks, and RenewalInfo is hand-written;
//   - orders validate names locally, refuse wildcards without dns-01 before contacting the CA, and clean up
//     every challenge they presented, whatever happens.
//
// The HTTP client must be the guarded one of internal/acme/transport (https only for every URL, including
// the ones a CA returns; dials through netaddr; answers capped).
package acme

import (
	"context"
	"crypto"
	"encoding/base64"
	"errors"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	xacme "golang.org/x/crypto/acme"

	"alice/internal/platform/clock"
)

// Default budgets.
const (
	DefaultCallTimeout    = 2 * time.Minute
	DefaultOrderTimeout   = 10 * time.Minute
	DefaultCleanupTimeout = time.Minute
)

// badNonceRetries is how often a badNonce answer is retried (with a fresh nonce) before it is an error.
const badNonceRetries = 3

// Config builds a Client.
type Config struct {
	// DirectoryURL is the CA's directory (https).
	DirectoryURL string
	// Key is the account key. It may be nil for Discover and RenewalInfo.
	Key crypto.Signer
	// AccountURL is the account's URL (the JWS "kid"), when it is known.
	AccountURL string
	// HTTPClient must come from internal/acme/transport.
	HTTPClient *http.Client
	// Contact is the account's e-mail address (with or without "mailto:"), used by RegisterAccount when it is
	// given no contact.
	Contact string
	// CallTimeout bounds one CA call (default 2 min), OrderTimeout one order (default 10 min), CleanupTimeout
	// the challenge cleanup after an order (default 1 min, on a context that ignores the order's cancellation).
	CallTimeout, OrderTimeout, CleanupTimeout time.Duration
	// Now is the clock (default the real one).
	Now func() time.Time
}

// Client talks to one CA as one account. It is safe for concurrent use except Rollover, which must not run
// beside another call of the same Client.
type Client struct {
	cfg Config
	lib *xacme.Client

	mu  sync.Mutex
	dir *Directory
}

// New checks the configuration and builds the client. It does not contact the CA.
func New(cfg Config) (*Client, error) {
	u, err := url.Parse(cfg.DirectoryURL)
	if err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil {
		return nil, newError(ReasonDirectoryInvalid, errDirectory)
	}
	if cfg.HTTPClient == nil {
		return nil, newError(ReasonProviderUnreachable, errNoHTTPClient)
	}
	if cfg.CallTimeout <= 0 {
		cfg.CallTimeout = DefaultCallTimeout
	}
	if cfg.OrderTimeout <= 0 {
		cfg.OrderTimeout = DefaultOrderTimeout
	}
	if cfg.CleanupTimeout <= 0 {
		cfg.CleanupTimeout = DefaultCleanupTimeout
	}
	if cfg.Now == nil {
		cfg.Now = clock.Real{}.Now
	}
	lib := &xacme.Client{Key: cfg.Key, DirectoryURL: cfg.DirectoryURL, HTTPClient: cfg.HTTPClient,
		RetryBackoff: retryBackoff, UserAgent: "alice"}
	if cfg.AccountURL != "" {
		lib.KID = xacme.KeyID(cfg.AccountURL)
	}
	return &Client{cfg: cfg, lib: lib}, nil
}

var errNoHTTPClient = errors.New("acme: no HTTP client (use internal/acme/transport)")

func (c *Client) now() time.Time { return c.cfg.Now() }

// retryBackoff is the library's RetryBackoff: badNonce (the only 400 that reaches it) is retried at once a few
// times; a rate limit (429), a server error (5xx) or anything else is never retried and never slept on.
func retryBackoff(n int, _ *http.Request, res *http.Response) time.Duration {
	if res != nil && res.StatusCode == http.StatusBadRequest && n <= badNonceRetries {
		return time.Millisecond
	}
	return 0
}

// AccountURL is the account's URL once it is known ("" before registration or lookup).
func (c *Client) AccountURL() string {
	c.mu.Lock()
	defer c.mu.Unlock()
	return string(c.lib.KID)
}

// call runs f under the per-call deadline.
func (c *Client) call(ctx context.Context, f func(context.Context) error) error {
	ctx, cancel := context.WithTimeout(ctx, c.cfg.CallTimeout)
	defer cancel()
	return f(ctx)
}

// EAB is an external account binding as a CA hands it out: a key id and a base64url HMAC key. The caller
// keeps ownership of HMACKey (and zeroes it); the decoded key is zeroed after use.
type EAB struct {
	KID     string
	HMACKey []byte
}

// String never shows the key.
func (e EAB) String() string { return "EAB{KID: " + e.KID + ", HMACKey: redacted}" }

// GoString never shows the key.
func (e EAB) GoString() string { return e.String() }

// decode returns the raw HMAC key.
func (e *EAB) decode() ([]byte, error) {
	if e.KID == "" || len(e.KID) > 256 || strings.ContainsFunc(e.KID, func(r rune) bool { return r < 0x21 || r > 0x7e }) {
		return nil, ErrEABInvalid
	}
	k := e.HMACKey
	for len(k) > 0 && k[len(k)-1] == '=' {
		k = k[:len(k)-1]
	}
	if len(k) == 0 || len(k) > 1024 {
		return nil, ErrEABInvalid
	}
	raw := make([]byte, base64.RawURLEncoding.DecodedLen(len(k)))
	n, err := base64.RawURLEncoding.Decode(raw, k)
	if err != nil || n < 16 {
		clear(raw)
		return nil, ErrEABInvalid
	}
	return raw[:n], nil
}

// Account is a registered account.
type Account struct {
	// URL is the account's URL (store it; it is the JWS "kid").
	URL string
	// TermsOfService is the terms URL that was accepted ("" when the CA has none).
	TermsOfService string
	// UsedEAB says an external account binding was sent.
	UsedEAB bool
	// Existing says the CA already knew this key (the existing account was returned).
	Existing bool
}

// RegisterAccount creates the account of the client's key. tosAccepted must be true (an Admin ticked the box
// showing Discover's TermsOfService); otherwise nothing is sent and the error has ReasonTermsNotAccepted. A
// CA that requires a binding gets none sent without one (ReasonAccountRejected, ErrEABRequired); a malformed
// binding is refused locally (ErrEABInvalid). A key the CA already knows returns its existing account.
func (c *Client) RegisterAccount(ctx context.Context, contact string, eab *EAB, tosAccepted bool) (Account, error) {
	if !tosAccepted {
		return Account{}, newError(ReasonTermsNotAccepted, ErrTermsNotAccepted)
	}
	if c.cfg.Key == nil {
		return Account{}, newError(ReasonAccountRejected, ErrNoKey)
	}
	if contact == "" {
		contact = c.cfg.Contact
	}
	contacts, err := contactURIs(contact)
	if err != nil {
		return Account{}, err
	}
	var bind *xacme.ExternalAccountBinding
	if eab != nil {
		raw, err := eab.decode()
		if err != nil {
			return Account{}, newError(ReasonAccountRejected, err)
		}
		defer clear(raw)
		bind = &xacme.ExternalAccountBinding{KID: eab.KID, Key: raw}
	}
	d, err := c.Discover(ctx)
	if err != nil {
		return Account{}, err
	}
	if d.ExternalAccountRequired && bind == nil {
		return Account{}, newError(ReasonAccountRejected, ErrEABRequired)
	}
	var acct *xacme.Account
	existing := false
	err = c.call(ctx, func(ctx context.Context) error {
		var err error
		acct, err = c.lib.Register(ctx, &xacme.Account{Contact: contacts, ExternalAccountBinding: bind}, func(string) bool { return true })
		if err == xacme.ErrAccountAlreadyExists { //nolint:errorlint // the library returns the sentinel itself
			existing, err = true, nil
		}
		return err
	})
	if err != nil {
		return Account{}, c.classify(err, opAccount, "", "")
	}
	u := c.AccountURL()
	if acct != nil && acct.URI != "" {
		u = acct.URI
	}
	if u == "" {
		return Account{}, newError(ReasonDirectoryInvalid, ErrBadAnswer)
	}
	return Account{URL: u, TermsOfService: d.TermsOfService, UsedEAB: bind != nil, Existing: existing}, nil
}

var errContact = errors.New("acme: the contact is not a plain e-mail address")

// contactURIs turns an e-mail address into the mailto URI list (empty for no contact).
func contactURIs(contact string) ([]string, error) {
	addr := strings.TrimPrefix(contact, "mailto:")
	if addr == "" {
		return nil, nil
	}
	at := strings.IndexByte(addr, '@')
	if len(addr) > 254 || at <= 0 || at != strings.LastIndexByte(addr, '@') || at == len(addr)-1 ||
		strings.ContainsFunc(addr, func(r rune) bool { return r <= 0x20 || r >= 0x7f || strings.ContainsRune(",;<>?&%\"'\\()[]", r) }) {
		return nil, newError(ReasonAccountRejected, errContact)
	}
	return []string{"mailto:" + addr}, nil
}

// Lookup finds the account of the client's key at the CA (onlyReturnExisting) and remembers its URL. It is
// how a rollover whose outcome is unknown is settled: try the new key, then the old one.
func (c *Client) Lookup(ctx context.Context) (string, error) {
	if c.cfg.Key == nil {
		return "", newError(ReasonAccountRejected, ErrNoKey)
	}
	if _, err := c.Discover(ctx); err != nil {
		return "", err
	}
	var a *xacme.Account
	err := c.call(ctx, func(ctx context.Context) error {
		var err error
		a, err = c.lib.GetReg(ctx, "")
		return err
	})
	if err != nil {
		return "", c.classify(err, opAccount, "", "")
	}
	c.mu.Lock()
	c.lib.KID = xacme.KeyID(a.URI)
	c.mu.Unlock()
	return a.URI, nil
}

// RolloverOutcome says whether the CA now holds the new key.
type RolloverOutcome int

const (
	// RolloverNotSwitched: the CA refused or was never asked; the old key is still the account key.
	RolloverNotSwitched RolloverOutcome = iota
	// RolloverSwitched: the CA confirmed; the new key is the account key (and the client now signs with it).
	RolloverSwitched
	// RolloverUnknown: the request may have reached the CA but no answer came; settle it with Lookup.
	RolloverUnknown
)

func (o RolloverOutcome) String() string {
	switch o {
	case RolloverSwitched:
		return "switched"
	case RolloverUnknown:
		return "unknown"
	}
	return "not_switched"
}

// Rollover replaces the account key with newKey (RFC 8555 section 7.3.5), atomically at the CA. The caller
// persists newKey as pending before calling (plan A6) and settles it by the outcome. A CA without keyChange
// gives ReasonRolloverUnsupported without a request.
func (c *Client) Rollover(ctx context.Context, newKey crypto.Signer) (RolloverOutcome, error) {
	if c.cfg.Key == nil || newKey == nil {
		return RolloverNotSwitched, newError(ReasonAccountRejected, ErrNoKey)
	}
	d, err := c.Discover(ctx)
	if err != nil {
		return RolloverNotSwitched, err
	}
	if !d.SupportsRollover() {
		return RolloverNotSwitched, newError(ReasonRolloverUnsupported, ErrRolloverUnsupported)
	}
	err = c.call(ctx, func(ctx context.Context) error { return c.lib.AccountKeyRollover(ctx, newKey) })
	if err == nil {
		c.mu.Lock()
		c.cfg.Key = newKey
		c.mu.Unlock()
		return RolloverSwitched, nil
	}
	ce := c.classify(err, opAccount, "", "")
	var ae *xacme.Error
	if errors.As(err, &ae) && ae.StatusCode >= 400 && ae.StatusCode < 500 && ae.StatusCode != http.StatusTooManyRequests {
		return RolloverNotSwitched, ce
	}
	if ReasonOf(ce) == ReasonCARateLimited || ReasonOf(ce) == ReasonTLSTrustFailed || errors.Is(err, xacme.ErrNoAccount) {
		return RolloverNotSwitched, ce
	}
	return RolloverUnknown, ce
}

// Deactivate permanently deactivates the account (RFC 8555 section 7.3.6).
func (c *Client) Deactivate(ctx context.Context) error {
	if c.cfg.Key == nil {
		return newError(ReasonAccountRejected, ErrNoKey)
	}
	if _, err := c.Discover(ctx); err != nil {
		return err
	}
	err := c.call(ctx, func(ctx context.Context) error { return c.lib.DeactivateReg(ctx) })
	return c.classify(err, opAccount, "", "")
}
