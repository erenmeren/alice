package winhelper

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"io"
	"strconv"
	"unicode/utf8"

	"alice/internal/providers/windows/winproto"
)

// secrets holds every buffer of one call that held key material (the key PEM as decoded from the
// JSON, its DER, the PKCS #8 re-encoding, the PFX and its password), so clear wipes them on every
// path (W2 Ruling 9, Review Focus 5). Go's parsed key objects cannot be wiped (WN-4).
type secrets struct{ bufs [][]byte }

// secretsHook, when set, sees every secrets a call creates (tests check the buffers are zero after
// the call). nil in the helper.
var secretsHook func(*secrets)

func newSecrets() *secrets {
	s := &secrets{}
	if secretsHook != nil {
		secretsHook(s)
	}
	return s
}

// keep registers b and returns it.
func (s *secrets) keep(b []byte) []byte {
	s.bufs = append(s.bufs, b)
	return b
}

// clear wipes every buffer kept, to its capacity.
func (s *secrets) clear() {
	for _, b := range s.bufs {
		clear(b[:cap(b)])
	}
}

// deployRequest is iis-deploy's decoded stdin. keyPEM and chainPEM are buffers of the call's secrets.
type deployRequest struct {
	loc        winproto.Locator
	canonical  string
	expect     string
	chainPEM   []byte
	keyPEM     []byte
	spki, leaf []string
}

// parseDeployInput decodes iis-deploy's stdin, winproto.DeployInput: a JSON object with exactly the six
// members (any order, each once, nothing else). It is a strict hand parser instead of encoding/json so
// that the private key is copied only into buffers of sec (encoding/json keeps copies in strings and
// its own buffers; the Linux helper's parseDeployInput rule). Syntax is BAD_CONTENT; a locator Alice
// does not deploy to, an expected hash or a list that is not valid is INVALID_ARGUMENT (Ruling 5).
func parseDeployInput(raw []byte, sec *secrets) (deployRequest, error) {
	return parseDeployFields(raw, sec, true)
}

// parseRDPDeployInput decodes rdp-deploy's stdin, winproto.RDPDeployInput (W6 Ruling 8): parseDeployInput's
// members without the locator, so exactly five. Any other member (a locator, a store, a SID, a
// listener, a registry path) is BAD_CONTENT: the listener is RDP-Tcp, named in code.
func parseRDPDeployInput(raw []byte, sec *secrets) (deployRequest, error) {
	return parseDeployFields(raw, sec, false)
}

// parseDeployFields is the strict parser of both inputs; withLocator says whether "locator" is a member.
func parseDeployFields(raw []byte, sec *secrets, withLocator bool) (deployRequest, error) {
	var d deployRequest
	badContent := refused(winproto.CodeBadContent, "the input is not a deployment")
	p := jsonScan{b: raw}
	seen := map[string]bool{}
	if !p.lit('{') {
		return d, badContent
	}
	for i := 0; ; i++ {
		if i > 0 && !p.lit(',') {
			break
		}
		name, ok := p.str(make([]byte, 0, 32), 32)
		if !ok || !p.lit(':') || seen[string(name)] {
			return d, badContent
		}
		seen[string(name)] = true
		switch string(name) {
		case "locator":
			if !withLocator {
				return d, badContent
			}
			if d.loc, ok = p.locator(); !ok {
				return d, badContent
			}
		case "expect_sha256":
			var b []byte
			if b, ok = p.str(make([]byte, 0, 64), 64); !ok {
				return d, badContent
			}
			d.expect = string(b)
		case "chain_pem":
			if d.chainPEM, ok = p.str(sec.keep(make([]byte, 0, len(raw))), len(raw)); !ok {
				return d, badContent
			}
		case "key_pem":
			if d.keyPEM, ok = p.str(sec.keep(make([]byte, 0, len(raw))), len(raw)); !ok {
				return d, badContent
			}
		case "forbidden_spki_sha256":
			if d.spki, ok = p.hashList(); !ok {
				return d, badContent
			}
		case "forbidden_leaf_sha256":
			if d.leaf, ok = p.hashList(); !ok {
				return d, badContent
			}
		default:
			return d, badContent
		}
	}
	members := 5
	if withLocator {
		members = 6
	}
	if len(seen) != members || !p.lit('}') {
		return d, badContent
	}
	p.ws()
	if p.i != len(p.b) {
		return d, badContent
	}
	canonical, ok := winproto.RDPCanonical, true
	if withLocator {
		canonical, ok = d.loc.Canonical()
	}
	if !ok || !validSHA256(d.expect) || !winproto.ValidForbidden(d.spki) || !winproto.ValidForbidden(d.leaf) {
		return d, refused(winproto.CodeInvalidArgument, "the binding, the expected hash or a forbidden list is not allowed")
	}
	d.canonical = canonical
	return d, nil
}

// content is the checked new certificate: the leaf, its intermediates and the key as PKCS #8 (a
// buffer of the call's secrets).
type content struct {
	leaf          *x509.Certificate
	intermediates []*x509.Certificate
	pkcs8         []byte
}

// checkContent verifies the new certificate before anything is touched: the chain is only
// CERTIFICATE blocks without headers (a leaf and at most MaxChainCerts intermediates, each at most
// MaxCertDER bytes and an X.509 certificate) and white space; the key is exactly one unencrypted
// RSA or ECDSA private key block (PKCS #8, PKCS #1 or SEC 1) and white space, and it is the leaf's.
// The key is re-encoded as PKCS #8 (Ruling 9). Anything else is BAD_CONTENT.
func checkContent(chainPEM, keyPEM []byte, sec *secrets) (content, error) {
	var c content
	bad := refused(winproto.CodeBadContent, "the input is not a certificate chain and its private key")
	blocks, ok := pemBlocks(chainPEM)
	if !ok || len(blocks) == 0 || len(blocks) > 1+winproto.MaxChainCerts {
		return c, bad
	}
	for i, b := range blocks {
		if b.Type != "CERTIFICATE" || len(b.Headers) != 0 || len(b.Bytes) > winproto.MaxCertDER {
			return c, bad
		}
		cert, err := x509.ParseCertificate(b.Bytes)
		if err != nil {
			return c, bad
		}
		if i == 0 {
			c.leaf = cert
		} else {
			c.intermediates = append(c.intermediates, cert)
		}
	}
	typ, der, ok := decodeKeyPEM(keyPEM, sec)
	if !ok {
		return c, bad
	}
	var priv any
	var err error
	switch typ {
	case "PRIVATE KEY":
		priv, err = x509.ParsePKCS8PrivateKey(der)
	case "RSA PRIVATE KEY":
		priv, err = x509.ParsePKCS1PrivateKey(der)
	case "EC PRIVATE KEY":
		priv, err = x509.ParseECPrivateKey(der)
	default:
		return c, bad
	}
	if err != nil {
		return c, bad
	}
	var pub crypto.PublicKey
	switch k := priv.(type) {
	case *rsa.PrivateKey:
		pub = k.Public()
	case *ecdsa.PrivateKey:
		pub = k.Public()
	default:
		return c, bad
	}
	if eq, ok := pub.(interface{ Equal(crypto.PublicKey) bool }); !ok || !eq.Equal(c.leaf.PublicKey) {
		return c, bad
	}
	p8, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		return c, bad
	}
	c.pkcs8 = sec.keep(p8)
	return c, nil
}

var (
	pemBegin = []byte("-----BEGIN ")
	pemDash  = []byte("-----")
)

// pemBlocks decodes public PEM data as blocks with nothing but white space before, between and after
// them (pem.Decode alone skips text before a block).
func pemBlocks(data []byte) ([]*pem.Block, bool) {
	var out []*pem.Block
	rest := data
	for {
		rest = bytes.TrimLeft(rest, " \t\r\n")
		if len(rest) == 0 {
			return out, true
		}
		if !bytes.HasPrefix(rest, pemBegin) {
			return nil, false
		}
		b, next := pem.Decode(rest)
		if b == nil || bytes.Count(rest[:len(rest)-len(next)], pemBegin) != 1 {
			return nil, false
		}
		out = append(out, b)
		rest = next
	}
}

// decodeKeyPEM decodes exactly one PEM block surrounded by white space without pem.Decode, whose
// copies of the base64 text nobody could clear: the body (no headers) is decoded straight into a
// buffer of sec (base64's decoder skips line ends).
func decodeKeyPEM(data []byte, sec *secrets) (typ string, der []byte, ok bool) {
	rest := bytes.TrimLeft(data, " \t\r\n")
	if !bytes.HasPrefix(rest, pemBegin) {
		return "", nil, false
	}
	rest = rest[len(pemBegin):]
	nl := bytes.IndexByte(rest, '\n')
	if nl < 0 {
		return "", nil, false
	}
	line := bytes.TrimRight(rest[:nl], "\r")
	if !bytes.HasSuffix(line, pemDash) {
		return "", nil, false
	}
	typ = string(line[:len(line)-len(pemDash)])
	rest = rest[nl+1:]
	end := []byte("-----END " + typ + "-----")
	e := bytes.Index(rest, end)
	if e < 0 || len(bytes.TrimLeft(rest[e+len(end):], " \t\r\n")) != 0 {
		return "", nil, false
	}
	body := rest[:e]
	if bytes.IndexByte(body, ':') >= 0 || bytes.Contains(body, pemDash) {
		return "", nil, false
	}
	buf := sec.keep(make([]byte, base64.StdEncoding.DecodedLen(len(body))))
	n, err := base64.StdEncoding.Decode(buf, body)
	if err != nil || n == 0 {
		return "", nil, false
	}
	return typ, buf[:n], true
}

// parseRestoreInput decodes iis-restore's stdin (winproto.RestoreInput, no key material): exactly the
// two lists, both required, and nothing but white space after the object. Syntax is BAD_CONTENT, a list that is not
// ValidForbidden INVALID_ARGUMENT.
func parseRestoreInput(raw []byte) (guard, error) {
	var in struct {
		SPKI *[]string `json:"forbidden_spki_sha256"`
		Leaf *[]string `json:"forbidden_leaf_sha256"`
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&in); err != nil || !atEOF(dec) || in.SPKI == nil || in.Leaf == nil {
		return guard{}, refused(winproto.CodeBadContent, "the input is not the rollback guard")
	}
	if !winproto.ValidForbidden(*in.SPKI) || !winproto.ValidForbidden(*in.Leaf) {
		return guard{}, refused(winproto.CodeInvalidArgument, "a forbidden list is not allowed")
	}
	return guard{SPKI: *in.SPKI, Leaf: *in.Leaf}, nil
}

// atEOF reports whether only white space follows dec's value (dec.More is false before a closing bracket too).
func atEOF(dec *json.Decoder) bool {
	_, err := dec.Token()
	return errors.Is(err, io.EOF)
}

// jsonScan reads the few JSON forms parseDeployInput accepts (cmd/alice-helper/deployinput.go).
type jsonScan struct {
	b []byte
	i int
}

func (p *jsonScan) ws() {
	for p.i < len(p.b) && (p.b[p.i] == ' ' || p.b[p.i] == '\t' || p.b[p.i] == '\n' || p.b[p.i] == '\r') {
		p.i++
	}
}

// lit skips white space and the byte c.
func (p *jsonScan) lit(c byte) bool {
	p.ws()
	if p.i < len(p.b) && p.b[p.i] == c {
		p.i++
		return true
	}
	return false
}

// str skips white space and decodes one JSON string into out, never past its capacity (the content
// is never reallocated and copied), refusing more than maxLen bytes.
func (p *jsonScan) str(out []byte, maxLen int) ([]byte, bool) {
	if !p.lit('"') {
		return out, false
	}
	for p.i < len(p.b) {
		c := p.b[p.i]
		p.i++
		switch {
		case c == '"':
			return out, true
		case c < 0x20:
			return out, false
		case c != '\\':
			if len(out) >= maxLen {
				return out, false
			}
			out = append(out, c)
			continue
		}
		if p.i >= len(p.b) {
			return out, false
		}
		e := p.b[p.i]
		p.i++
		var r rune
		switch e {
		case '"', '\\', '/':
			r = rune(e)
		case 'b':
			r = '\b'
		case 'f':
			r = '\f'
		case 'n':
			r = '\n'
		case 'r':
			r = '\r'
		case 't':
			r = '\t'
		case 'u':
			if p.i+4 > len(p.b) {
				return out, false
			}
			v, err := strconv.ParseUint(string(p.b[p.i:p.i+4]), 16, 16)
			if err != nil {
				return out, false
			}
			p.i += 4
			r = rune(v) //nolint:gosec // G115: at most 0xffff
			if r >= 0xd800 && r < 0xe000 {
				return out, false // surrogates never belong in PEM text or a locator
			}
		default:
			return out, false
		}
		if len(out)+utf8.RuneLen(r) > maxLen {
			return out, false
		}
		out = utf8.AppendRune(out, r)
	}
	return out, false
}

// hashList decodes one JSON array of strings of at most 64 bytes, at most MaxForbidden of them (the
// caller checks ValidForbidden).
func (p *jsonScan) hashList() ([]string, bool) {
	if !p.lit('[') {
		return nil, false
	}
	list := []string{}
	if p.lit(']') {
		return list, true
	}
	for {
		h, ok := p.str(make([]byte, 0, 64), 64)
		if !ok || len(list) >= winproto.MaxForbidden {
			return nil, false
		}
		list = append(list, string(h))
		if p.lit(']') {
			return list, true
		}
		if !p.lit(',') {
			return nil, false
		}
	}
}

// locator decodes the locator object: the members type, ip, host, port and app_id, each at most once,
// nothing else; type, port and app_id required.
func (p *jsonScan) locator() (winproto.Locator, bool) {
	var l winproto.Locator
	if !p.lit('{') {
		return l, false
	}
	seen := map[string]bool{}
	for i := 0; ; i++ {
		if i > 0 && !p.lit(',') {
			break
		}
		name, ok := p.str(make([]byte, 0, 16), 16)
		if !ok || !p.lit(':') || seen[string(name)] {
			return l, false
		}
		seen[string(name)] = true
		if string(name) == "port" {
			if l.Port, ok = p.port(); !ok {
				return l, false
			}
			continue
		}
		v, ok := p.str(make([]byte, 0, winproto.MaxText), winproto.MaxText)
		if !ok {
			return l, false
		}
		switch string(name) {
		case "type":
			l.Type = string(v)
		case "ip":
			l.IP = string(v)
		case "host":
			l.Host = string(v)
		case "app_id":
			l.AppID = string(v)
		default:
			return l, false
		}
	}
	return l, seen["type"] && seen["port"] && seen["app_id"] && p.lit('}')
}

// port decodes a JSON integer of one to five digits.
func (p *jsonScan) port() (int, bool) {
	p.ws()
	start := p.i
	for p.i < len(p.b) && p.b[p.i] >= '0' && p.b[p.i] <= '9' && p.i-start < 6 {
		p.i++
	}
	n := p.i - start
	if n == 0 || n > 5 {
		return 0, false
	}
	v, _ := strconv.Atoi(string(p.b[start:p.i]))
	return v, true
}
