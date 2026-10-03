package certs

import (
	"bytes"
	"crypto/x509"
	"strings"
	"time"
)

// weakSignature reports whether c is signed with a broken or SHA-1 based algorithm.
func weakSignature(c *x509.Certificate) bool {
	switch c.SignatureAlgorithm {
	case x509.MD2WithRSA, x509.MD5WithRSA, x509.SHA1WithRSA, x509.ECDSAWithSHA1, x509.DSAWithSHA1, x509.DSAWithSHA256:
		return true
	}
	return false
}

// orderChain returns the certificates of others that lead from leaf to its
// root, in issuing order. Certificates off that path are dropped; a self-signed
// root at the end is kept.
func orderChain(leaf *x509.Certificate, others []*x509.Certificate) []*x509.Certificate {
	var out []*x509.Certificate
	remaining := append([]*x509.Certificate(nil), others...)
	cur := leaf
	for !selfSigned(cur) {
		next := -1
		for i, cand := range remaining {
			if bytes.Equal(cand.RawSubject, cur.RawIssuer) && cur.CheckSignatureFrom(cand) == nil {
				next = i
				break
			}
		}
		if next < 0 {
			break
		}
		cur = remaining[next]
		out = append(out, cur)
		remaining = append(remaining[:next], remaining[next+1:]...)
	}
	return out
}

// ChainComplete reports whether the chain reaches a root: its last certificate
// is self-signed, or the leaf verifies against roots with the chain as
// intermediates. A leaf that is not valid yet is checked as of its NotBefore, so
// that "not yet valid" is reported on its own and not as a missing chain.
func ChainComplete(p Parsed, roots *x509.CertPool, now time.Time) bool {
	last := p.Leaf
	if n := len(p.Chain); n > 0 {
		last = p.Chain[n-1]
	}
	if selfSigned(last) {
		return true
	}
	if roots == nil {
		roots = x509.NewCertPool()
	}
	inter := x509.NewCertPool()
	for _, c := range p.Chain {
		inter.AddCert(c)
	}
	at := now
	if at.Before(p.Leaf.NotBefore) {
		at = p.Leaf.NotBefore
	}
	_, err := p.Leaf.Verify(x509.VerifyOptions{
		Roots: roots, Intermediates: inter, CurrentTime: at,
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
	})
	return err == nil
}

// SystemRoots returns the operating system's trusted roots, or an empty pool.
func SystemRoots() *x509.CertPool {
	if p, err := x509.SystemCertPool(); err == nil && p != nil {
		return p
	}
	return x509.NewCertPool()
}

// SANMatches reports whether name is covered by one of sans. A SAN "*.rest"
// covers exactly one extra left-most label.
func SANMatches(sans []string, name string) bool {
	if name == "" {
		return false
	}
	for _, san := range sans {
		if rest, ok := strings.CutPrefix(san, "*."); ok {
			if i := strings.IndexByte(name, '.'); i > 0 && strings.EqualFold(name[i+1:], rest) {
				return true
			}
			continue
		}
		if strings.EqualFold(san, name) {
			return true
		}
	}
	return false
}
