package certs

import (
	"bytes"
	"crypto/x509"
	"slices"
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

// maxChainSignatureChecks bounds the signature checks one ordering may make (each issuer candidate
// and each self-signature costs one; a 16384-bit RSA check takes milliseconds). Files with many
// certificates of one name could otherwise cost hundreds of checks; crypto/x509's own chain building
// has the same bound.
const maxChainSignatureChecks = 100

// orderChain returns the certificates of others that lead from leaf to its root, in issuing order.
// Certificates off that path are dropped; a self-signed root at the end is kept. Where several
// certificates could issue the current one (a cross-sign beside the regular intermediate, or beside
// the root it cross-signs, or two issuers with the same name and key), one that is valid at "at"
// is tried first, and among those a self-signed root; when the first choice does not lead to a
// self-signed certificate of the input, the others are tried (a path that ends in an included root
// wins; otherwise the first path found). ok is false when the search needed more than
// maxChainSignatureChecks signature checks: the path is then unknown.
func orderChain(leaf *x509.Certificate, others []*x509.Certificate, at time.Time) (path []*x509.Certificate, ok bool) {
	s := &chainSearch{at: at, self: map[*x509.Certificate]bool{}}
	path, _ = s.extend(leaf, others)
	return path, !s.cut
}

// chainSearch is one orderChain: its signature-check count and the self-signature of each
// certificate, checked once.
type chainSearch struct {
	at     time.Time
	checks int
	cut    bool
	self   map[*x509.Certificate]bool
}

// spend counts one signature check; false (and cut) once the bound is reached.
func (s *chainSearch) spend() bool {
	if s.checks >= maxChainSignatureChecks {
		s.cut = true
		return false
	}
	s.checks++
	return true
}

func (s *chainSearch) selfSigned(c *x509.Certificate) bool {
	if v, ok := s.self[c]; ok {
		return v
	}
	if !s.spend() {
		return false
	}
	v := selfSigned(c)
	s.self[c] = v
	return v
}

func (s *chainSearch) rank(c *x509.Certificate) int {
	r := 0
	if validAt(c, s.at) {
		r += 2
	}
	if s.selfSigned(c) {
		r++
	}
	return r
}

// extend returns a path from cur (cur not included) over remaining, and whether it ends in a
// self-signed certificate (or cur is one).
func (s *chainSearch) extend(cur *x509.Certificate, remaining []*x509.Certificate) ([]*x509.Certificate, bool) {
	if s.selfSigned(cur) || s.cut {
		return nil, !s.cut
	}
	var cands []int
	for i, cand := range remaining {
		if !bytes.Equal(cand.RawSubject, cur.RawIssuer) {
			continue
		}
		if !s.spend() {
			return nil, false
		}
		if cur.CheckSignatureFrom(cand) == nil {
			cands = append(cands, i)
		}
	}
	ranks := make(map[int]int, len(cands))
	for _, i := range cands {
		ranks[i] = s.rank(remaining[i])
	}
	slices.SortStableFunc(cands, func(a, b int) int { return ranks[b] - ranks[a] })
	var first []*x509.Certificate
	for n, i := range cands {
		if s.cut {
			return nil, false
		}
		rest := append(append([]*x509.Certificate(nil), remaining[:i]...), remaining[i+1:]...)
		sub, rooted := s.extend(remaining[i], rest)
		p := append([]*x509.Certificate{remaining[i]}, sub...)
		if rooted {
			return p, true
		}
		if n == 0 {
			first = p
		}
	}
	return first, false
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
