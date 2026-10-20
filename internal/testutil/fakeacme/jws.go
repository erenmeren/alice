package fakeacme

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/hmac"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"strings"

	"golang.org/x/crypto/acme"
)

const maxBody = 1 << 20

type flatJWS struct {
	Protected string `json:"protected"`
	Payload   string `json:"payload"`
	Signature string `json:"signature"`
}

type jwsHeader struct {
	Alg   string          `json:"alg"`
	JWK   json.RawMessage `json:"jwk"`
	KID   string          `json:"kid"`
	Nonce string          `json:"nonce"`
	URL   string          `json:"url"`
}

// jwsReq is a verified request.
type jwsReq struct {
	header  jwsHeader
	payload []byte // decoded; empty for POST-as-GET
	key     crypto.PublicKey
	acct    *account // a copy; nil for jwk requests
}

// readJWS reads and parses (but does not verify) the flattened JWS of a request.
func readJWS(w http.ResponseWriter, r *http.Request) (flatJWS, jwsHeader, *problem) {
	var j flatJWS
	var h jwsHeader
	if ct := asciiLower(strings.TrimSpace(strings.SplitN(r.Header.Get("Content-Type"), ";", 2)[0])); ct != "application/jose+json" {
		return j, h, malformed(http.StatusUnsupportedMediaType, "the content type must be application/jose+json")
	}
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, maxBody))
	if err != nil {
		return j, h, malformed(http.StatusBadRequest, "the request body could not be read")
	}
	if err := json.Unmarshal(body, &j); err != nil || j.Protected == "" || j.Signature == "" {
		return j, h, malformed(http.StatusBadRequest, "the request is not a flattened JWS")
	}
	ph, err := base64.RawURLEncoding.DecodeString(j.Protected)
	if err != nil || json.Unmarshal(ph, &h) != nil {
		return j, h, malformed(http.StatusBadRequest, "the JWS protected header is not valid")
	}
	return j, h, nil
}

// verifyJWS checks the signature of j with pub.
func verifyJWS(j flatJWS, h jwsHeader, pub crypto.PublicKey) error {
	sig, err := base64.RawURLEncoding.DecodeString(j.Signature)
	if err != nil {
		return errors.New("the signature is not base64url")
	}
	input := []byte(j.Protected + "." + j.Payload)
	switch k := pub.(type) {
	case *rsa.PublicKey:
		if h.Alg != "RS256" || k.N.BitLen() < 2048 {
			return errors.New("an RSA key needs RS256 and at least 2048 bits")
		}
		sum := sha256.Sum256(input)
		return rsa.VerifyPKCS1v15(k, crypto.SHA256, sum[:], sig)
	case *ecdsa.PublicKey:
		var sum []byte
		switch {
		case h.Alg == "ES256" && k.Curve == elliptic.P256():
			d := sha256.Sum256(input)
			sum = d[:]
		case h.Alg == "ES384" && k.Curve == elliptic.P384():
			d := sha512.Sum384(input)
			sum = d[:]
		case h.Alg == "ES512" && k.Curve == elliptic.P521():
			d := sha512.Sum512(input)
			sum = d[:]
		default:
			return errors.New("the algorithm does not match the key")
		}
		n := (k.Curve.Params().BitSize + 7) / 8
		if len(sig) != 2*n {
			return errors.New("the signature has the wrong length")
		}
		if !ecdsa.Verify(k, sum, new(big.Int).SetBytes(sig[:n]), new(big.Int).SetBytes(sig[n:])) {
			return errors.New("the signature is not valid")
		}
		return nil
	}
	return errors.New("unsupported key type")
}

type jwk struct {
	Kty string `json:"kty"`
	Crv string `json:"crv"`
	X   string `json:"x"`
	Y   string `json:"y"`
	N   string `json:"n"`
	E   string `json:"e"`
}

// parseJWK decodes an RSA or EC public key.
func parseJWK(raw []byte) (crypto.PublicKey, error) {
	var k jwk
	if err := json.Unmarshal(raw, &k); err != nil {
		return nil, errors.New("the JWK is not JSON")
	}
	dec := func(s string) (*big.Int, error) {
		b, err := base64.RawURLEncoding.DecodeString(s)
		if err != nil || len(b) == 0 {
			return nil, errors.New("bad JWK number")
		}
		return new(big.Int).SetBytes(b), nil
	}
	switch k.Kty {
	case "EC":
		curves := map[string]elliptic.Curve{"P-256": elliptic.P256(), "P-384": elliptic.P384(), "P-521": elliptic.P521()}
		c, ok := curves[k.Crv]
		if !ok {
			return nil, errors.New("unsupported curve")
		}
		x, err := dec(k.X)
		if err != nil {
			return nil, err
		}
		y, err := dec(k.Y)
		if err != nil {
			return nil, err
		}
		n := (c.Params().BitSize + 7) / 8
		if x.BitLen() > 8*n || y.BitLen() > 8*n {
			return nil, errors.New("the point is not on the curve")
		}
		point := make([]byte, 1+2*n)
		point[0] = 4
		x.FillBytes(point[1 : 1+n])
		y.FillBytes(point[1+n:])
		pub, err := ecdsa.ParseUncompressedPublicKey(c, point) // validates the point is on the curve
		if err != nil {
			return nil, errors.New("the point is not on the curve")
		}
		return pub, nil
	case "RSA":
		n, err := dec(k.N)
		if err != nil {
			return nil, err
		}
		e, err := dec(k.E)
		if err != nil || !e.IsInt64() || e.Int64() < 3 || e.Int64() > 1<<31 {
			return nil, errors.New("bad RSA exponent")
		}
		if n.BitLen() < 2048 {
			return nil, errors.New("the RSA key is too small")
		}
		return &rsa.PublicKey{N: n, E: int(e.Int64())}, nil
	}
	return nil, errors.New("unsupported key type")
}

func thumbprint(pub crypto.PublicKey) string {
	t, err := acme.JWKThumbprint(pub)
	if err != nil {
		return ""
	}
	return t
}

func macOK(key []byte, input string, sig []byte) bool {
	m := hmac.New(sha256.New, key)
	m.Write([]byte(input))
	return hmac.Equal(m.Sum(nil), sig)
}

// jwsMode says how a route identifies its caller.
type jwsMode int

const (
	modeJWK    jwsMode = iota // newAccount: the key is in the header
	modeKID                   // everything else: the account URL is the kid
	modeEither                // revokeCert (RFC 8555 section 7.6): the account's kid or the certificate key's jwk
)

// authenticate reads, checks and consumes a JWS request.
func (s *Server) authenticate(w http.ResponseWriter, r *http.Request, mode jwsMode) (*jwsReq, *problem) {
	j, h, prob := readJWS(w, r)
	if prob != nil {
		return nil, prob
	}
	if h.URL != s.BaseURL()+r.URL.Path {
		return nil, malformed(http.StatusBadRequest, "the url in the JWS protected header does not match the request URL")
	}
	if !s.takeNonce(h.Nonce) {
		return nil, newProblem(http.StatusBadRequest, "badNonce", "the nonce is unknown or was already used")
	}
	out := &jwsReq{header: h}
	switch {
	case (mode == modeJWK || mode == modeEither) && len(h.JWK) > 0 && h.KID == "":
		pub, err := parseJWK(h.JWK)
		if err != nil {
			return nil, malformed(http.StatusBadRequest, "the JWK is not acceptable: "+err.Error())
		}
		out.key = pub
	case (mode == modeKID || mode == modeEither) && h.KID != "" && len(h.JWK) == 0:
		a := s.accountByURL(h.KID)
		if a == nil {
			return nil, newProblem(http.StatusBadRequest, "accountDoesNotExist", "no account for this key id")
		}
		if a.status != "valid" {
			return nil, newProblem(http.StatusForbidden, "unauthorized", "the account is "+a.status)
		}
		out.key, out.acct = a.key, a
	default:
		return nil, malformed(http.StatusBadRequest, "the JWS must carry exactly one of jwk (newAccount) and kid (everything else)")
	}
	if err := verifyJWS(j, h, out.key); err != nil {
		return nil, malformed(http.StatusBadRequest, "the JWS signature failed: "+err.Error())
	}
	if j.Payload != "" {
		p, err := base64.RawURLEncoding.DecodeString(j.Payload)
		if err != nil {
			return nil, malformed(http.StatusBadRequest, "the JWS payload is not base64url")
		}
		out.payload = p
	}
	return out, nil
}

func (s *Server) takeNonce(n string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.st.nonces[n]; !ok || n == "" {
		return false
	}
	delete(s.st.nonces, n)
	return true
}

func (s *Server) newNonce() string {
	n := b64(randBytes(16))
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.st.nonces) > 10000 {
		s.st.nonces = map[string]struct{}{}
	}
	s.st.nonces[n] = struct{}{}
	return n
}

// accountByURL returns a copy of the account a key id names, or nil.
func (s *Server) accountByURL(u string) *account {
	id, ok := strings.CutPrefix(u, s.BaseURL()+"/acme/acct/")
	if !ok {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	a := s.st.accounts[id]
	if a == nil {
		return nil
	}
	c := *a
	return &c
}

// decodeJSON unmarshals a request payload.
func decodeJSON(payload []byte, v any) *problem {
	if err := json.Unmarshal(payload, v); err != nil {
		return malformed(http.StatusBadRequest, fmt.Sprintf("the request payload is not valid: %v", err))
	}
	return nil
}

// requireEmpty enforces POST-as-GET (RFC 8555 section 6.3): the payload must be empty.
func (s *Server) requireEmpty(w http.ResponseWriter, req *jwsReq) bool {
	if len(req.payload) != 0 {
		s.writeProblem(w, malformed(http.StatusBadRequest, "a POST-as-GET request must have an empty payload"))
		return false
	}
	return true
}
