package lestaging

import (
	"bytes"
	"context"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// maxRootBytes bounds one fetched root file.
const maxRootBytes = 64 << 10

// fetchRoots downloads the roots (PEM, self-signed) from urls with client.
func fetchRoots(ctx context.Context, client *http.Client, urls []string) ([]*x509.Certificate, error) {
	var out []*x509.Certificate
	for _, u := range urls {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
		if err != nil {
			return nil, err
		}
		res, err := client.Do(req)
		if err != nil {
			return nil, fmt.Errorf("fetching %s: %w", u, err)
		}
		b, err := io.ReadAll(io.LimitReader(res.Body, maxRootBytes+1))
		_ = res.Body.Close()
		if err != nil || res.StatusCode != http.StatusOK || len(b) > maxRootBytes {
			return nil, fmt.Errorf("fetching %s: status %d", u, res.StatusCode)
		}
		certs, err := parseCerts(b)
		if err != nil || len(certs) != 1 {
			return nil, fmt.Errorf("%s is not one PEM certificate", u)
		}
		if !selfSigned(certs[0]) {
			return nil, fmt.Errorf("%s is not a self-signed root", u)
		}
		out = append(out, certs...)
	}
	return out, nil
}

// parseCerts reads every CERTIFICATE block of PEM text (at least one).
func parseCerts(b []byte) ([]*x509.Certificate, error) {
	var out []*x509.Certificate
	for {
		var blk *pem.Block
		blk, b = pem.Decode(b)
		if blk == nil {
			break
		}
		if blk.Type != "CERTIFICATE" {
			continue
		}
		c, err := x509.ParseCertificate(blk.Bytes)
		if err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	if len(out) == 0 {
		return nil, errors.New("no certificate")
	}
	return out, nil
}

func selfSigned(c *x509.Certificate) bool {
	return bytes.Equal(c.RawIssuer, c.RawSubject) && c.CheckSignatureFrom(c) == nil
}

// chainReport describes a verified chain.
type chainReport struct {
	leaf   *x509.Certificate
	path   []string // common names, leaf first, root last
	issuer string
}

// verifyChain checks the downloaded chain (leaf first, DER, root left out as public CAs do): every certificate
// parses, the leaf holds exactly names, it is valid now for server authentication, and it chains through the given
// intermediates to one of roots and to nothing else. With expectStaging the issuing CA must be a staging CA (its
// name carries "(STAGING)"), so a chain from the production hierarchy is refused.
func verifyChain(chain [][]byte, roots []*x509.Certificate, names []string, expectStaging bool, now time.Time) (chainReport, error) {
	if len(chain) == 0 {
		return chainReport{}, errors.New("the CA sent no certificate")
	}
	certs := make([]*x509.Certificate, 0, len(chain))
	for i, der := range chain {
		c, err := x509.ParseCertificate(der)
		if err != nil {
			return chainReport{}, fmt.Errorf("certificate %d of the chain does not parse", i+1)
		}
		certs = append(certs, c)
	}
	leaf := certs[0]
	if !sameNameSet(leaf.DNSNames, names) {
		return chainReport{}, fmt.Errorf("the leaf names %v, not %v", leaf.DNSNames, names)
	}
	pool, inter := x509.NewCertPool(), x509.NewCertPool()
	for _, r := range roots {
		pool.AddCert(r)
	}
	for _, c := range certs[1:] {
		inter.AddCert(c)
	}
	paths, err := leaf.Verify(x509.VerifyOptions{Roots: pool, Intermediates: inter, CurrentTime: now,
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}})
	if err != nil {
		return chainReport{}, fmt.Errorf("the chain does not lead to the expected roots: %w", err)
	}
	rep := chainReport{leaf: leaf, issuer: leaf.Issuer.CommonName}
	for _, c := range paths[0] {
		rep.path = append(rep.path, c.Subject.CommonName)
	}
	if expectStaging && !strings.Contains(leaf.Issuer.CommonName, "(STAGING)") {
		return rep, fmt.Errorf("the issuing CA %q is not a staging CA", leaf.Issuer.CommonName)
	}
	return rep, nil
}

func sameNameSet(got, want []string) bool {
	if len(got) != len(want) {
		return false
	}
	set := map[string]bool{}
	for _, n := range want {
		set[asciiLower(n)] = true
	}
	for _, n := range got {
		if !set[asciiLower(n)] {
			return false
		}
		delete(set, asciiLower(n))
	}
	return len(set) == 0
}
