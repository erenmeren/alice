package certs

import (
	"bytes"
	"crypto/x509"
	"strings"
	"time"
)

// weakSignature reports whether c is signed with a broken, SHA-1 based or unrecognised algorithm.
func weakSignature(c *x509.Certificate) bool {
	switch c.SignatureAlgorithm {
	case x509.UnknownSignatureAlgorithm, // e.g. SHA-1 under an OID Go does not know: not provably strong
		x509.MD2WithRSA, x509.MD5WithRSA, x509.SHA1WithRSA, x509.ECDSAWithSHA1, x509.DSAWithSHA1, x509.DSAWithSHA256:
		return true
	}
	return false
}

// validAt reports whether c is within its validity period at t.
func validAt(c *x509.Certificate, t time.Time) bool {
	return !t.Before(c.NotBefore) && t.Before(c.NotAfter)
}

// orderChain returns the certificates of others that lead from leaf to its
// root, in issuing order. Certificates off that path are dropped; a self-signed
// root at the end is kept. Where several certificates could issue the current
// one (a cross-sign beside the regular intermediate, or beside the root it
// cross-signs), one that is valid at "at" wins, and among those a self-signed
// root: a still-valid cross-sign listed first must not hide the uploaded root.
func orderChain(leaf *x509.Certificate, others []*x509.Certificate, at time.Time) []*x509.Certificate {
	var out []*x509.Certificate
	remaining := append([]*x509.Certificate(nil), others...)
	rank := func(c *x509.Certificate) int {
		r := 0
		if validAt(c, at) {
			r += 2
		}
		if selfSigned(c) {
			r++
		}
		return r
	}
	cur := leaf
	for !selfSigned(cur) {
		next := -1
		for i, cand := range remaining {
			if !bytes.Equal(cand.RawSubject, cur.RawIssuer) || cur.CheckSignatureFrom(cand) != nil {
				continue
			}
			if next < 0 || rank(cand) > rank(remaining[next]) {
				next = i
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

// ChainComplete reports whether a path from the leaf to a self-signed
// certificate verifies, with every certificate on the path valid at the check
// time. The self-signed certificate is either a root in roots or the last
// uploaded certificate (a root that came with the upload). A leaf that is not
// valid yet is checked as of its NotBefore, so that "not yet valid" is
// reported on its own and not as a missing chain.
func ChainComplete(p Parsed, roots *x509.CertPool, now time.Time) bool {
	pool := x509.NewCertPool()
	if roots != nil {
		pool = roots.Clone()
	}
	last := p.Leaf
	inter := x509.NewCertPool()
	for _, c := range p.Chain {
		inter.AddCert(c)
		last = c
	}
	if selfSigned(last) {
		pool.AddCert(last)
	}
	at := now
	if at.Before(p.Leaf.NotBefore) {
		at = p.Leaf.NotBefore
	}
	_, err := p.Leaf.Verify(x509.VerifyOptions{
		Roots: pool, Intermediates: inter, CurrentTime: at,
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
