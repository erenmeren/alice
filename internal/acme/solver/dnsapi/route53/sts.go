package route53

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/xml"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"time"

	"alice/internal/acme"
	"alice/internal/acme/solver/dnsapi"
	"alice/internal/secrets"
)

// The role session Alice asks STS for.
const (
	stsVersion = "2011-06-15"
	// SessionDuration is the lifetime Alice asks for (STS's minimum): one order needs minutes, and a short session
	// limits what a leaked temporary credential is worth.
	SessionDuration = 900 * time.Second
	// refreshBefore renews the temporary credentials when less than this remains, so no request is signed with
	// credentials that expire while it travels or while the change is polled.
	refreshBefore = 2 * time.Minute
	// sessionPrefix starts every role session name: CloudTrail shows "alice-acme-<8 hex>" for Alice's calls.
	sessionPrefix = "alice-acme-"
	// maxTokenBytes bounds the session token (STS's are about 1 KiB; it travels in a header).
	maxTokenBytes = 8192
)

type assumeRoleAnswer struct {
	XMLName xml.Name
	// The secret parts are read into byte slices so they can be cleared; strings could not be.
	KeyID      string `xml:"AssumeRoleResult>Credentials>AccessKeyId"`
	Secret     []byte `xml:"AssumeRoleResult>Credentials>SecretAccessKey"`
	Token      []byte `xml:"AssumeRoleResult>Credentials>SessionToken"`
	Expiration string `xml:"AssumeRoleResult>Credentials>Expiration"`
}

// signingCredentials returns the credentials Route 53 calls are signed with: the access key, or (with a role) the
// role's temporary credentials, assumed now when there are none or they are about to expire. The lock is held over
// the STS call, so concurrent calls share one sign-in.
func (p *Provider) signingCredentials(ctx context.Context, d string) (credentials, error) {
	if p.role == "" {
		return credentials{keyID: p.keyID, secret: p.secret}, nil
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.temp != nil && p.now().Add(refreshBefore).Before(p.tempExpires) {
		return *p.temp, nil
	}
	c, exp, err := p.assumeRole(ctx, d)
	if err != nil {
		return credentials{}, err
	}
	// The previous temporary credentials are dropped, not cleared: a request signed a moment ago may still be
	// reading them. Zero clears the current ones.
	p.temp, p.tempExpires = &c, exp
	return c, nil
}

// dropTemporary forgets the temporary credentials after AWS refused them (an expired or revoked session), so the
// next call signs in again.
func (p *Provider) dropTemporary(used credentials) {
	if p.role == "" {
		return
	}
	p.mu.Lock()
	if p.temp != nil && p.temp.keyID == used.keyID {
		p.temp = nil
	}
	p.mu.Unlock()
}

// assumeRole calls STS AssumeRole, signed with the access key. Every failure is acme.DNSSignInError (or the
// transport's unreachable error, or ctx.Err()); STS's answer text is never read.
func (p *Provider) assumeRole(ctx context.Context, d string) (credentials, time.Time, error) {
	var rnd [4]byte
	if _, err := io.ReadFull(p.random, rnd[:]); err != nil {
		return credentials{}, time.Time{}, acme.DNSProviderError(d, 0, false)
	}
	form := url.Values{
		"Action":          {"AssumeRole"},
		"Version":         {stsVersion},
		"RoleArn":         {p.role},
		"RoleSessionName": {sessionPrefix + hex.EncodeToString(rnd[:])},
		"DurationSeconds": {strconv.Itoa(int(SessionDuration / time.Second))},
	}
	if p.externalID != "" {
		form.Set("ExternalId", p.externalID)
	}
	body := []byte(form.Encode())
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, "https://"+STSHost+"/", bytes.NewReader(body))
	if err != nil {
		return credentials{}, time.Time{}, acme.DNSProviderError(d, 0, false)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded; charset=utf-8")
	sign(req, body, credentials{keyID: p.keyID, secret: p.secret}, Region, "sts", p.now())
	status, _, answer, err := dnsapi.Do(ctx, p.client, req, d)
	if err != nil {
		return credentials{}, time.Time{}, err
	}
	defer clear(answer)
	if status != http.StatusOK {
		return credentials{}, time.Time{}, stsError(d, status, errorCode(answer))
	}
	var a assumeRoleAnswer
	if xml.Unmarshal(answer, &a) != nil || a.XMLName.Local != "AssumeRoleResponse" {
		clear(a.Secret)
		clear(a.Token)
		return credentials{}, time.Time{}, acme.DNSProviderError(d, status, false)
	}
	exp, err := time.Parse(time.RFC3339, a.Expiration)
	if err != nil || !accessKeyPattern.MatchString(a.KeyID) || !secretShape(a.Secret) || !tokenShape(a.Token) || !exp.After(p.now()) {
		clear(a.Secret)
		clear(a.Token)
		return credentials{}, time.Time{}, acme.DNSProviderError(d, status, false)
	}
	// Own copies: encoding/xml may hand out slices of its own buffers.
	secret, token := bytes.Clone(a.Secret), bytes.Clone(a.Token)
	clear(a.Secret)
	clear(a.Token)
	return credentials{keyID: a.KeyID, secret: secrets.NewPlaintext(secret), token: secrets.NewPlaintext(token)}, exp, nil
}

// secretShape is a secret access key's shape: 16 to 128 visible ASCII characters.
func secretShape(b []byte) bool { return visibleASCII(b, 16, 128) }

// tokenShape is a session token's shape: visible ASCII (it is sent as a header value), at most maxTokenBytes.
func tokenShape(b []byte) bool { return visibleASCII(b, 16, maxTokenBytes) }

func visibleASCII(b []byte, minLen, maxLen int) bool {
	if len(b) < minLen || len(b) > maxLen {
		return false
	}
	for _, c := range b {
		if c < 0x21 || c > 0x7e {
			return false
		}
	}
	return true
}
