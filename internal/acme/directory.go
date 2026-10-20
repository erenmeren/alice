package acme

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
)

// maxDirectoryBytes bounds the directory document.
const maxDirectoryBytes = 64 << 10

// Directory is what Alice needs from an ACME directory (RFC 8555 section 7.1.1, RFC 9773 section 3).
type Directory struct {
	NewNonce    string
	NewAccount  string
	NewOrder    string
	KeyChange   string // "" when the CA cannot roll account keys over
	RenewalInfo string // "" when the CA has no ARI
	RevokeCert  string // "" when the CA offers no revocation (RFC 8555 section 7.6)
	// TermsOfService is the URL an Admin must accept ("" when the CA has none).
	TermsOfService string
	Website        string
	// ExternalAccountRequired says registration needs an external account binding.
	ExternalAccountRequired bool
}

// SupportsRollover and SupportsARI report the optional resources.
func (d Directory) SupportsRollover() bool { return d.KeyChange != "" }

// SupportsARI reports whether the CA offers renewal information.
func (d Directory) SupportsARI() bool { return d.RenewalInfo != "" }

// SupportsRevocation reports whether the CA offers certificate revocation (revokeCert).
func (d Directory) SupportsRevocation() bool { return d.RevokeCert != "" }

var errDirectory = errors.New("acme: the directory is not an ACME directory")

// ParseDirectory reads a directory document. The three resources an RFC 8555 client needs must be https
// URLs without credentials; the optional ones are dropped when they are not. The terms and website are
// kept only as https or http URLs (they are shown, never fetched).
func ParseDirectory(b []byte) (Directory, error) {
	if len(b) > maxDirectoryBytes {
		return Directory{}, errDirectory
	}
	var v struct {
		NewNonce    any `json:"newNonce"`
		NewAccount  any `json:"newAccount"`
		NewOrder    any `json:"newOrder"`
		KeyChange   any `json:"keyChange"`
		RenewalInfo any `json:"renewalInfo"`
		RevokeCert  any `json:"revokeCert"`
		Meta        struct {
			Terms       any `json:"termsOfService"`
			Website     any `json:"website"`
			EABRequired any `json:"externalAccountRequired"`
		} `json:"meta"`
	}
	if err := json.Unmarshal(b, &v); err != nil {
		return Directory{}, errDirectory
	}
	d := Directory{
		NewNonce: httpsURL(v.NewNonce), NewAccount: httpsURL(v.NewAccount), NewOrder: httpsURL(v.NewOrder),
		KeyChange: httpsURL(v.KeyChange), RenewalInfo: httpsURL(v.RenewalInfo), RevokeCert: httpsURL(v.RevokeCert),
		TermsOfService: webURL(v.Meta.Terms), Website: webURL(v.Meta.Website),
	}
	d.ExternalAccountRequired, _ = v.Meta.EABRequired.(bool)
	if d.NewNonce == "" || d.NewAccount == "" || d.NewOrder == "" {
		return Directory{}, errDirectory
	}
	return d, nil
}

const maxURLLen = 2048

func parseURL(v any) *url.URL {
	s, ok := v.(string)
	if !ok || s == "" || len(s) > maxURLLen {
		return nil
	}
	u, err := url.Parse(s)
	if err != nil || u.Host == "" || u.User != nil || u.Opaque != "" {
		return nil
	}
	return u
}

func httpsURL(v any) string {
	if u := parseURL(v); u != nil && u.Scheme == "https" {
		return u.String()
	}
	return ""
}

func webURL(v any) string {
	if u := parseURL(v); u != nil && (u.Scheme == "https" || u.Scheme == "http") {
		return u.String()
	}
	return ""
}

// Discover fetches the directory (one GET of its own, since the library's Directory has no renewalInfo, then
// the library's own discovery) and caches it for the life of the client.
func (c *Client) Discover(ctx context.Context) (Directory, error) {
	c.mu.Lock()
	if c.dir != nil {
		d := *c.dir
		c.mu.Unlock()
		return d, nil
	}
	c.mu.Unlock()
	ctx, cancel := context.WithTimeout(ctx, c.cfg.CallTimeout)
	defer cancel()
	d, err := c.fetchDirectory(ctx)
	if err != nil {
		return Directory{}, err
	}
	if _, err := c.lib.Discover(ctx); err != nil {
		return Directory{}, c.classify(err, opAccount, "", "")
	}
	c.mu.Lock()
	c.dir = &d
	c.mu.Unlock()
	return d, nil
}

func (c *Client) fetchDirectory(ctx context.Context) (Directory, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.cfg.DirectoryURL, nil)
	if err != nil {
		return Directory{}, newError(ReasonDirectoryInvalid, errDirectory)
	}
	res, err := c.cfg.HTTPClient.Do(req)
	if err != nil {
		return Directory{}, c.classify(err, opAccount, "", "")
	}
	defer res.Body.Close()
	b, rerr := io.ReadAll(io.LimitReader(res.Body, maxDirectoryBytes+1))
	if res.StatusCode != http.StatusOK {
		return Directory{}, c.statusError(res, b)
	}
	if rerr != nil {
		return Directory{}, c.classify(rerr, opAccount, "", "")
	}
	d, err := ParseDirectory(b)
	if err != nil {
		return Directory{}, &Error{Reason: ReasonDirectoryInvalid, Status: res.StatusCode, cause: errDirectory}
	}
	return d, nil
}

// statusError classifies a non-success answer to a request this package made itself.
func (c *Client) statusError(res *http.Response, body []byte) error {
	p := ParseProblem(body)
	e := &Error{Status: res.StatusCode, ProblemType: p.Type}
	switch {
	case res.StatusCode == http.StatusTooManyRequests || shortType(p.Type) == "rateLimited":
		e.Reason = ReasonCARateLimited
		e.cause = &RateLimitedError{RetryAfter: parseRetryAfter(res.Header.Get("Retry-After"), c.now())}
	case res.StatusCode >= 500:
		e.Reason, e.cause = ReasonProviderUnreachable, errUnreachable
	default:
		e.Reason, e.cause = ReasonDirectoryInvalid, ErrBadAnswer
	}
	return e
}
