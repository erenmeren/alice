//go:build linux

package main

import (
	"bytes"
	"context"
	"crypto"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"io"
	"unicode/utf8"

	"alice/internal/providers/linuxssh/helperproto"
)

// readInput reads stdin, at most limit+1 bytes (the caller refuses more), into one buffer of that
// size: the input holds a private key, and a growing read would leave copies nobody clears. The
// read ends with the helper's budget: a caller that never closes stdin cannot hold the Nginx lock
// past it (the reading goroutine is abandoned; the process ends right after the answer).
func readInput(ctx context.Context, r io.Reader, limit int) ([]byte, error) {
	buf := make([]byte, limit+1)
	type result struct {
		n   int
		err error
	}
	done := make(chan result, 1)
	go func() {
		n, err := io.ReadFull(r, buf)
		if errors.Is(err, io.ErrUnexpectedEOF) || errors.Is(err, io.EOF) {
			err = nil
		}
		done <- result{n, err}
	}()
	select {
	case res := <-done:
		if res.err != nil {
			clear(buf)
			return nil, res.err
		}
		return buf[:res.n], nil
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

// parsedInput is nginx-deploy's decoded stdin: the new pair (cleared by the caller) and the
// rollback guard (protocol 10).
type parsedInput struct {
	cert, key []byte
	guard     guard
}

// parseDeployInput decodes nginx-deploy's stdin, a JSON object with exactly the two string members
// cert_pem and key_pem and, since protocol 10, the optional array members forbidden_spki_sha256
// and forbidden_leaf_sha256 (helperproto.NginxDeployInput, any order, each once, nothing else; each
// list a helperproto.ValidForbidden one). It is a strict hand parser instead of encoding/json so
// that the private key is copied only into buffers the caller clears (encoding/json keeps copies in
// strings and its own buffers). On error nothing is returned and everything it wrote is cleared.
func parseDeployInput(raw []byte) (in parsedInput, err error) {
	p := jsonScan{b: raw}
	var spki, leaf bool
	fail := func() (parsedInput, error) {
		clear(in.cert)
		clear(in.key)
		return parsedInput{}, errBadContent
	}
	if !p.lit('{') {
		return fail()
	}
	for i := 0; ; i++ {
		if i > 0 && !p.lit(',') {
			break
		}
		name, ok := p.str(make([]byte, 0, 32), 32)
		if !ok || !p.lit(':') {
			return fail()
		}
		switch string(name) {
		case "cert_pem":
			if in.cert != nil {
				return fail()
			}
			if in.cert, ok = p.str(make([]byte, 0, len(raw)), len(raw)); !ok {
				return fail()
			}
		case "key_pem":
			if in.key != nil {
				return fail()
			}
			if in.key, ok = p.str(make([]byte, 0, len(raw)), len(raw)); !ok {
				return fail()
			}
		case "forbidden_spki_sha256":
			if spki {
				return fail()
			}
			spki = true
			if in.guard.SPKI, ok = p.hashList(); !ok {
				return fail()
			}
		case "forbidden_leaf_sha256":
			if leaf {
				return fail()
			}
			leaf = true
			if in.guard.Leaf, ok = p.hashList(); !ok {
				return fail()
			}
		default:
			return fail()
		}
	}
	if in.cert == nil || in.key == nil || !p.lit('}') {
		return fail()
	}
	p.ws()
	if p.i != len(p.b) {
		return fail()
	}
	return in, nil
}

// hashList skips white space and decodes one JSON array of strings that is a
// helperproto.ValidForbidden list.
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
		if !ok || len(list) >= helperproto.MaxForbidden {
			return nil, false
		}
		list = append(list, string(h))
		if p.lit(']') {
			break
		}
		if !p.lit(',') {
			return nil, false
		}
	}
	return list, helperproto.ValidForbidden(list)
}

// jsonScan reads the few JSON forms parseDeployInput accepts.
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

// str skips white space and decodes one JSON string into out (whose capacity is never exceeded:
// the content is never reallocated and copied), refusing more than maxLen bytes.
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
			for _, h := range p.b[p.i : p.i+4] {
				v, ok := hexVal(h)
				if !ok {
					return out, false
				}
				r = r<<4 | v
			}
			p.i += 4
			if r >= 0xd800 && r < 0xe000 {
				return out, false // surrogates never belong in PEM text
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

func hexVal(c byte) (rune, bool) {
	switch {
	case c >= '0' && c <= '9':
		return rune(c - '0'), true
	case c >= 'a' && c <= 'f':
		return rune(c-'a') + 10, true
	case c >= 'A' && c <= 'F':
		return rune(c-'A') + 10, true
	}
	return 0, false
}

// checkDeployContent verifies the new pair before anything is touched: the certificate input is
// only CERTIFICATE blocks (at least one, no headers, each an X.509 certificate) and white space;
// the key input is exactly one unencrypted private key block (PKCS #8, PKCS #1 or SEC 1) and
// white space; and the key is the private key of the first certificate (the leaf).
func checkDeployContent(certPEM, keyPEM []byte) error {
	certs, err := pemBlocks(certPEM)
	if err != nil || len(certs) == 0 {
		return errBadContent
	}
	var leaf *x509.Certificate
	for i, b := range certs {
		if b.Type != "CERTIFICATE" || len(b.Headers) != 0 {
			return errBadContent
		}
		c, err := x509.ParseCertificate(b.Bytes)
		if err != nil {
			return errBadContent
		}
		if i == 0 {
			leaf = c
		}
	}
	keys, err := pemBlocks(keyPEM)
	defer func() {
		for _, b := range keys {
			clear(b.Bytes)
		}
	}()
	if err != nil || len(keys) != 1 || len(keys[0].Headers) != 0 {
		return errBadContent
	}
	var priv any
	switch keys[0].Type {
	case "PRIVATE KEY":
		priv, err = x509.ParsePKCS8PrivateKey(keys[0].Bytes)
	case "RSA PRIVATE KEY":
		priv, err = x509.ParsePKCS1PrivateKey(keys[0].Bytes)
	case "EC PRIVATE KEY":
		priv, err = x509.ParseECPrivateKey(keys[0].Bytes)
	default:
		return errBadContent
	}
	if err != nil {
		return errBadContent
	}
	signer, ok := priv.(crypto.Signer)
	if !ok {
		return errBadContent
	}
	pub, ok := signer.Public().(interface{ Equal(crypto.PublicKey) bool })
	if !ok || !pub.Equal(leaf.PublicKey) {
		return errBadContent
	}
	return nil
}

var pemBegin = []byte("-----BEGIN ")

// pemBlocks decodes data as PEM blocks with nothing but white space before, between and after
// them. pem.Decode alone skips any text before a block, and a malformed block before a good one.
func pemBlocks(data []byte) ([]*pem.Block, error) {
	var out []*pem.Block
	rest := data
	for {
		rest = bytes.TrimLeft(rest, " \t\r\n")
		if len(rest) == 0 {
			return out, nil
		}
		if !bytes.HasPrefix(rest, pemBegin) {
			return out, errBadContent
		}
		b, next := pem.Decode(rest)
		if b == nil || bytes.Count(rest[:len(rest)-len(next)], pemBegin) != 1 {
			return out, errBadContent
		}
		out = append(out, b)
		rest = next
	}
}
