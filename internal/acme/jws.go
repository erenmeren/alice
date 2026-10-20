package acme

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"encoding/asn1"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"math/big"
	"net/http"

	xacme "golang.org/x/crypto/acme"
)

// maxOrderBytes bounds an order document this package parses itself.
const maxOrderBytes = 256 << 10

// errJWSKey is an account key this package cannot sign a request with (never one Alice creates).
var errJWSKey = errors.New("acme: the account key type cannot sign a request")

// jwsAlg is the JWS algorithm of an account key (RFC 7518 section 3): ES256, ES384 or ES512 for ECDSA P-256, P-384 or
// P-521 (size: the length of r and of s), RS256 for RSA (size 0).
func jwsAlg(pub crypto.PublicKey) (alg string, hash crypto.Hash, size int, err error) {
	switch k := pub.(type) {
	case *ecdsa.PublicKey:
		switch k.Curve {
		case elliptic.P256():
			return "ES256", crypto.SHA256, 32, nil
		case elliptic.P384():
			return "ES384", crypto.SHA384, 48, nil
		case elliptic.P521():
			return "ES512", crypto.SHA512, 66, nil
		}
	case *rsa.PublicKey:
		return "RS256", crypto.SHA256, 0, nil
	}
	return "", 0, 0, errJWSKey
}

// signJWS is the flattened JWS of payload for url (RFC 8555 section 6.2), signed with key as the account kid.
func signJWS(key crypto.Signer, kid, nonce, url string, payload []byte) ([]byte, error) {
	alg, hash, size, err := jwsAlg(key.Public())
	if err != nil {
		return nil, err
	}
	hdr, err := json.Marshal(struct {
		Alg   string `json:"alg"`
		KID   string `json:"kid"`
		Nonce string `json:"nonce"`
		URL   string `json:"url"`
	}{alg, kid, nonce, url})
	if err != nil {
		return nil, err
	}
	enc := base64.RawURLEncoding
	protected, body := enc.EncodeToString(hdr), enc.EncodeToString(payload)
	h := hash.New()
	h.Write([]byte(protected + "." + body))
	sig, err := key.Sign(rand.Reader, h.Sum(nil), hash)
	if err != nil {
		return nil, err
	}
	if size > 0 { // ECDSA signs ASN.1; JWS wants r and s, each padded to the curve's size
		var rs struct{ R, S *big.Int }
		if rest, err := asn1.Unmarshal(sig, &rs); err != nil || len(rest) > 0 || rs.R.BitLen() > 8*size || rs.S.BitLen() > 8*size {
			return nil, errJWSKey
		}
		sig = make([]byte, 2*size)
		rs.R.FillBytes(sig[:size])
		rs.S.FillBytes(sig[size:])
	}
	return json.Marshal(map[string]string{"protected": protected, "payload": body, "signature": enc.EncodeToString(sig)})
}

// postNewOrder creates an order whose newOrder carries replaces (RFC 9773 section 5), which golang.org/x/crypto/acme
// cannot send: one POST signed with the account key as its kid, a nonce from newNonce, and badNonce retried with the
// CA's fresh nonce (badNonceRetries times) as the library does. A refusal comes back as the library's *xacme.Error
// (type, status, headers: a Retry-After reaches classify as for any other call); the order as the library's *xacme.Order.
func (c *Client) postNewOrder(ctx context.Context, d Directory, ids []xacme.AuthzID, replaces string) (*xacme.Order, error) {
	c.mu.Lock()
	key, kid := c.cfg.Key, string(c.lib.KID)
	c.mu.Unlock()
	if key == nil {
		return nil, newError(ReasonAccountRejected, ErrNoKey)
	}
	if kid == "" {
		var err error
		if kid, err = c.Lookup(ctx); err != nil {
			return nil, err
		}
	}
	type wireID struct {
		Type  string `json:"type"`
		Value string `json:"value"`
	}
	req := struct {
		Identifiers []wireID `json:"identifiers"`
		Replaces    string   `json:"replaces"`
	}{Replaces: replaces}
	for _, id := range ids {
		req.Identifiers = append(req.Identifiers, wireID{Type: id.Type, Value: id.Value})
	}
	payload, err := json.Marshal(req)
	if err != nil {
		return nil, err
	}
	nonce, err := c.fetchNonce(ctx, d.NewNonce)
	if err != nil {
		return nil, err
	}
	for attempt := 0; ; attempt++ {
		body, err := signJWS(key, kid, nonce, d.NewOrder, payload)
		if err != nil {
			return nil, newError(ReasonAccountRejected, err)
		}
		r, err := http.NewRequestWithContext(ctx, http.MethodPost, d.NewOrder, bytes.NewReader(body))
		if err != nil {
			return nil, newError(ReasonDirectoryInvalid, ErrBadAnswer)
		}
		r.Header.Set("Content-Type", "application/jose+json")
		r.Header.Set("User-Agent", "alice")
		res, err := c.cfg.HTTPClient.Do(r)
		if err != nil {
			return nil, err
		}
		b, rerr := io.ReadAll(io.LimitReader(res.Body, maxOrderBytes+1))
		_ = res.Body.Close()
		if res.StatusCode == http.StatusCreated {
			if rerr != nil {
				return nil, rerr
			}
			return parseOrder(b, res.Header.Get("Location"))
		}
		p := ParseProblem(b)
		if next := res.Header.Get("Replay-Nonce"); shortType(p.Type) == "badNonce" && attempt < badNonceRetries && validNonce(next) {
			nonce = next
			continue
		}
		return nil, &xacme.Error{StatusCode: res.StatusCode, ProblemType: p.Type, Header: res.Header}
	}
}

// fetchNonce asks newNonce for a fresh nonce (RFC 8555 section 7.2).
func (c *Client) fetchNonce(ctx context.Context, url string) (string, error) {
	r, err := http.NewRequestWithContext(ctx, http.MethodHead, url, nil)
	if err != nil {
		return "", newError(ReasonDirectoryInvalid, ErrBadAnswer)
	}
	r.Header.Set("User-Agent", "alice")
	res, err := c.cfg.HTTPClient.Do(r)
	if err != nil {
		return "", err
	}
	_ = res.Body.Close()
	n := res.Header.Get("Replay-Nonce")
	if !validNonce(n) {
		return "", newError(ReasonDirectoryInvalid, ErrBadAnswer)
	}
	return n, nil
}

// validNonce accepts 1..512 base64url characters (RFC 8555 section 6.5.1).
func validNonce(n string) bool {
	if n == "" || len(n) > 512 {
		return false
	}
	_, err := base64.RawURLEncoding.DecodeString(n)
	return err == nil
}

// parseOrder reads an order document (RFC 8555 section 7.1.3) tolerantly into the library's Order; uri is its URL.
func parseOrder(b []byte, uri string) (*xacme.Order, error) {
	if len(b) > maxOrderBytes {
		return nil, newError(ReasonDirectoryInvalid, ErrBadAnswer)
	}
	var v struct {
		Status      string `json:"status"`
		Identifiers []struct {
			Type  string `json:"type"`
			Value string `json:"value"`
		} `json:"identifiers"`
		Authorizations []string `json:"authorizations"`
		Finalize       string   `json:"finalize"`
		Certificate    string   `json:"certificate"`
	}
	if json.Unmarshal(b, &v) != nil {
		return nil, newError(ReasonDirectoryInvalid, ErrBadAnswer)
	}
	o := &xacme.Order{URI: uri, Status: v.Status, AuthzURLs: v.Authorizations, FinalizeURL: v.Finalize, CertURL: v.Certificate}
	for _, id := range v.Identifiers {
		o.Identifiers = append(o.Identifiers, xacme.AuthzID{Type: id.Type, Value: id.Value})
	}
	return o, nil
}
