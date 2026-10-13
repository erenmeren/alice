package acme

import (
	"context"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"
	"time"
)

// maxARIBytes bounds a renewal information answer.
const maxARIBytes = 16 << 10

// RenewalWindow is the CA's suggested renewal window (RFC 9773 section 4.2) and when to ask again.
type RenewalWindow struct {
	Start, End time.Time
	// RetryAfter is the CA's Retry-After, capped at MaxRetryAfter; 0 when it gave none.
	RetryAfter time.Duration
}

var errARI = errors.New("acme: the renewal information is not valid")

// minARIYear is the earliest year a suggested window may start in; a window before it is a CA's bug (or a hostile
// answer that would make every certificate due at once), as is one ending more than MaxARIAhead after now.
const minARIYear = 2000

// MaxARIAhead bounds how far in the future a suggested window may end (RenewalInfo).
const MaxARIAhead = 10 * 365 * 24 * time.Hour

// ParseARI reads a renewal information document tolerantly: unknown fields are ignored; the window must have
// RFC 3339 start and end, start before end, and start in the year 2000 or later.
func ParseARI(b []byte) (start, end time.Time, err error) {
	if len(b) > maxARIBytes {
		return time.Time{}, time.Time{}, errARI
	}
	var v struct {
		Window struct {
			Start any `json:"start"`
			End   any `json:"end"`
		} `json:"suggestedWindow"`
	}
	if json.Unmarshal(b, &v) != nil {
		return time.Time{}, time.Time{}, errARI
	}
	s, ok1 := v.Window.Start.(string)
	e, ok2 := v.Window.End.(string)
	if !ok1 || !ok2 || len(s) > 64 || len(e) > 64 {
		return time.Time{}, time.Time{}, errARI
	}
	start, err1 := time.Parse(time.RFC3339, s)
	end, err2 := time.Parse(time.RFC3339, e)
	if err1 != nil || err2 != nil || !start.Before(end) || start.UTC().Year() < minARIYear {
		return time.Time{}, time.Time{}, errARI
	}
	return start.UTC(), end.UTC(), nil
}

// CertID is the RFC 9773 certificate identifier: base64url(authority key identifier) "." base64url(the DER
// content octets of the serial number).
func CertID(cert *x509.Certificate) (string, error) {
	if len(cert.AuthorityKeyId) == 0 || cert.SerialNumber == nil || cert.SerialNumber.Sign() < 0 {
		return "", errARI
	}
	serial := cert.SerialNumber.Bytes()
	if len(serial) == 0 || serial[0]&0x80 != 0 {
		serial = append([]byte{0}, serial...)
	}
	enc := base64.RawURLEncoding
	return enc.EncodeToString(cert.AuthorityKeyId) + "." + enc.EncodeToString(serial), nil
}

// RenewalInfo asks the CA for the suggested renewal window of a certificate it issued (a window that ends more than
// MaxARIAhead after now is refused like a garbled one). It returns an error
// matching ErrNoARI when the directory has no renewalInfo. The request is an unauthenticated GET bounded by
// the call timeout and maxARIBytes.
func (c *Client) RenewalInfo(ctx context.Context, certDER []byte) (RenewalWindow, error) {
	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		return RenewalWindow{}, newError(ReasonDirectoryInvalid, errARI)
	}
	id, err := CertID(cert)
	if err != nil {
		return RenewalWindow{}, newError(ReasonDirectoryInvalid, errARI)
	}
	d, err := c.Discover(ctx)
	if err != nil {
		return RenewalWindow{}, err
	}
	if !d.SupportsARI() {
		return RenewalWindow{}, ErrNoARI
	}
	ctx, cancel := context.WithTimeout(ctx, c.cfg.CallTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, strings.TrimRight(d.RenewalInfo, "/")+"/"+id, nil)
	if err != nil {
		return RenewalWindow{}, newError(ReasonDirectoryInvalid, errARI)
	}
	res, err := c.cfg.HTTPClient.Do(req)
	if err != nil {
		return RenewalWindow{}, c.classify(err, opAccount, "", "")
	}
	defer res.Body.Close()
	b, rerr := io.ReadAll(io.LimitReader(res.Body, maxARIBytes+1))
	if res.StatusCode != http.StatusOK {
		return RenewalWindow{}, c.statusError(res, b)
	}
	if rerr != nil {
		return RenewalWindow{}, c.classify(rerr, opAccount, "", "")
	}
	start, end, err := ParseARI(b)
	if err == nil && end.After(c.now().Add(MaxARIAhead)) {
		err = errARI
	}
	if err != nil {
		return RenewalWindow{}, &Error{Reason: ReasonDirectoryInvalid, Status: res.StatusCode, cause: errARI}
	}
	return RenewalWindow{Start: start, End: end, RetryAfter: parseRetryAfter(res.Header.Get("Retry-After"), c.now())}, nil
}
