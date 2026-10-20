package providers

import (
	"bytes"
	"crypto/x509"
	"errors"
	"time"
)

// Verification levels of a deployment (R51, docs/superpowers/rulings/deployment-trust-verification.md): how much
// Alice proved about the new certificate after it was written. Each level includes the ones below it.
const (
	LevelNone      = 0 // nothing of the new certificate is proven live (a failed or rolled-back deployment)
	LevelInstalled = 1 // the files were written and the web server reloaded; the website was not checked (verification skipped)
	LevelServed    = 2 // every endpoint serves the expected leaf with the deployed chain length
	LevelTrusted   = 3 // and every served chain verifies against the trust store for the endpoint's name at the probe time
	// LevelHealthy (4) is reserved for a check of the service itself after the deployment (an HTTP health URL, a
	// synthetic transaction). Nothing measures it yet: a provider that does will report it through VerifyResult.Level
	// and the record keeps it like the others (R51 item 4).
	LevelHealthy = 4
)

// Trust statuses of a verification (Trust.Status).
const (
	TrustTrusted   = "trusted"   // every served chain verifies
	TrustUntrusted = "untrusted" // a served chain does not verify (Trust.Error says why)
	TrustUnchecked = "unchecked" // the served chain was not available (a helper older than protocol 11 answered)
)

// Why a served chain does not verify (Trust.Error, the trust_error param of deployment.verify_untrusted).
const (
	TrustErrUnknownAuthority  = "unknown_authority"  // the chain leads to no root of the trust store
	TrustErrWrongIntermediate = "wrong_intermediate" // no certificate sent after the leaf issued it
	TrustErrIncompleteChain   = "incomplete_chain"   // an intermediate of the deployed chain is missing
	TrustErrChainOrder        = "chain_order"        // the intermediates are sent out of order
	TrustErrNameMismatch      = "name_mismatch"      // the leaf does not cover the name the endpoint is checked with (never enforced)
	TrustErrExpired           = "expired"            // the leaf or an intermediate on the path has expired
	TrustErrNotYetValid       = "not_yet_valid"      // the leaf or an intermediate on the path is not valid yet
	TrustErrInvalidChain      = "invalid_chain"      // anything else (an unreadable certificate, a constraint violated)
)

// TrustErrors is the closed list of Trust.Error values.
var TrustErrors = []string{TrustErrUnknownAuthority, TrustErrWrongIntermediate, TrustErrIncompleteChain, TrustErrChainOrder,
	TrustErrNameMismatch, TrustErrExpired, TrustErrNotYetValid, TrustErrInvalidChain}

// Trust stores a verification checks against (TrustPolicy.Store, Trust.Store).
const (
	TrustStoreSystem       = "system"        // the operating system's roots (Alice's)
	TrustStoreACME         = "acme_bundle"   // the system roots and the CA bundle of the ACME authority that issued the certificate
	TrustStoreUploadedRoot = "uploaded_root" // the system roots and the self-signed root uploaded with the chain
)

// TrustPolicy is how a verification checks the served chains (VerifyRequest.Trust). Roots is the trust store (nil:
// the system roots), Expected the chain Alice deployed (leaf first; its intermediates tell a missing intermediate from
// an unknown root), Store names the store for the record. Enforce: the anchor is known (the deployed chain verifies
// against Roots itself), so a served chain that does not verify fails the verification; otherwise it is a warning
// and the verification passes at LevelServed. A name mismatch is always a warning (Enforces): the name comes from the
// server's configuration, which the deployment did not change and a rollback would not mend. Build it with
// TrustPolicyFor.
type TrustPolicy struct {
	Roots    *x509.CertPool
	Expected []*x509.Certificate
	Store    string
	Enforce  bool
}

// Trust is what a verification found about the served chains: Status (Trust*; "" when not measured), Error (TrustErr*
// when untrusted), Port (the first endpoint whose chain did not verify, 0 otherwise), and the policy's Store and
// Enforce.
type Trust struct {
	Status   string
	Error    string
	Port     int
	Store    string
	Enforced bool
}

// Enforces reports whether an untrusted chain with reason code fails a verification under p (see TrustPolicy).
func (p TrustPolicy) Enforces(code string) bool {
	return p.Enforce && code != TrustErrNameMismatch
}

// TrustPolicyFor is the policy for deploying chain (leaf first) with roots (nil: the system roots) named store at now.
// A self-signed certificate at the end of the chain (a root uploaded with it, or a self-signed leaf) is added to the
// roots as the anchor, and the store is then TrustStoreUploadedRoot unless it is the ACME authority's. Enforce is
// whether the chain verifies against the roots (any extended key usage, without a name; a leaf that is not valid yet
// is checked as of its NotBefore, as certs.ChainComplete does).
func TrustPolicyFor(chain []*x509.Certificate, roots *x509.CertPool, store string, now time.Time) TrustPolicy {
	p := TrustPolicy{Roots: roots, Expected: chain, Store: store}
	if len(chain) == 0 || chain[0] == nil {
		return p
	}
	if top := chain[len(chain)-1]; selfSigned(top) {
		if p.Roots == nil {
			p.Roots = systemRoots()
		}
		p.Roots = p.Roots.Clone()
		p.Roots.AddCert(top)
		if store != TrustStoreACME {
			p.Store = TrustStoreUploadedRoot
		}
	}
	at := now
	if at.Before(chain[0].NotBefore) {
		at = chain[0].NotBefore
	}
	_, err := chain[0].Verify(x509.VerifyOptions{Roots: p.Roots, Intermediates: poolOf(chain[1:]), CurrentTime: at,
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageAny}})
	p.Enforce = err == nil
	return p
}

// CheckServedChain verifies a served chain (DER, leaf first, as the TLS handshake presented it) with crypto/x509
// against p.Roots for name ("" checks no name: an endpoint without a server name) at now. It returns TrustUnchecked
// for an empty chain, TrustTrusted, or TrustUntrusted with the first reason found, in this order: a certificate that
// cannot be read (invalid_chain); the leaf's validity (expired, not_yet_valid); an intermediate on the path out of
// its validity (expired, not_yet_valid); no certificate after the leaf issued it (wrong_intermediate); the chain
// verifies once the deployed chain's intermediates are added (incomplete_chain); no root (unknown_authority);
// anything else x509 refuses (invalid_chain); intermediates sent in another order than the verified path
// (chain_order); and only for a chain that verifies, the name (name_mismatch), so that a name mismatch never hides a
// chain fault. Only the roots anchor: a self-signed certificate the server sends is an intermediate candidate, never
// a root.
func CheckServedChain(served [][]byte, p TrustPolicy, name string, now time.Time) (status, code string) {
	if len(served) == 0 {
		return TrustUnchecked, ""
	}
	chain := make([]*x509.Certificate, 0, len(served))
	for _, der := range served {
		c, err := x509.ParseCertificate(der)
		if err != nil {
			return TrustUntrusted, TrustErrInvalidChain
		}
		chain = append(chain, c)
	}
	leaf := chain[0]
	if c := validity(leaf, now); c != "" {
		return TrustUntrusted, c
	}
	opts := x509.VerifyOptions{Roots: p.Roots, Intermediates: poolOf(chain[1:]), CurrentTime: now, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageAny}}
	paths, err := leaf.Verify(opts)
	if err == nil {
		switch {
		case !ordered(chain, paths):
			return TrustUntrusted, TrustErrChainOrder
		case name != "" && leaf.VerifyHostname(name) != nil:
			return TrustUntrusted, TrustErrNameMismatch
		}
		return TrustTrusted, ""
	}
	var ua x509.UnknownAuthorityError
	var ci x509.CertificateInvalidError
	expired := errors.As(err, &ci) && ci.Reason == x509.Expired
	if !errors.As(err, &ua) && !expired {
		return TrustUntrusted, TrustErrInvalidChain
	}
	if c := pathValidity(chain, now); c != "" {
		return TrustUntrusted, c
	}
	if len(chain) > 1 && !issuedByAny(leaf, chain[1:]) {
		return TrustUntrusted, TrustErrWrongIntermediate
	}
	if len(p.Expected) > 1 {
		opts.Intermediates = poolOf(append(append([]*x509.Certificate(nil), chain[1:]...), p.Expected[1:]...))
		if _, err := leaf.Verify(opts); err == nil {
			return TrustUntrusted, TrustErrIncompleteChain
		}
	}
	return TrustUntrusted, TrustErrUnknownAuthority
}

// VerificationLevel is the level of a verification by its mode (Verified: "remote", "local", "skipped" or "") and its
// trust status: none without a mode, installed when skipped, trusted when every chain verified, served otherwise.
func VerificationLevel(verified, trust string) int {
	switch verified {
	case "skipped":
		return LevelInstalled
	case "remote", "local":
		if trust == TrustTrusted {
			return LevelTrusted
		}
		return LevelServed
	}
	return LevelNone
}

// StepParams are the params of a verify step for vr: mode, and the trust status when measured (with its reason when
// untrusted) for a passed verification; port and reason (and trust_error) for a failed one.
func (vr VerifyResult) StepParams() map[string]string {
	if !vr.OK {
		p := map[string]string{"port": vr.Params["port"], "reason": vr.Reason}
		if te := vr.Params["trust_error"]; te != "" {
			p["trust_error"] = te
		}
		return p
	}
	p := map[string]string{"mode": vr.Mode}
	if vr.Trust.Status != "" {
		p["trust"] = vr.Trust.Status
	}
	if vr.Trust.Error != "" {
		p["trust_error"] = vr.Trust.Error
	}
	return p
}

// validity is expired or not_yet_valid for a certificate outside its validity at now, "" inside it.
func validity(c *x509.Certificate, now time.Time) string {
	switch {
	case now.After(c.NotAfter):
		return TrustErrExpired
	case now.Before(c.NotBefore):
		return TrustErrNotYetValid
	}
	return ""
}

// pathValidity is the validity reason of the first served intermediate that issued a certificate before it in the
// chain (it is on a path) and is outside its validity at now.
func pathValidity(chain []*x509.Certificate, now time.Time) string {
	for i := 1; i < len(chain); i++ {
		if !issuesAny(chain[i], chain[:i]) {
			continue
		}
		if c := validity(chain[i], now); c != "" {
			return c
		}
	}
	return ""
}

// ordered reports whether one verified path sends its intermediates in the served order: the path's certificates
// after the leaf that the server sent are at positions 1, 2, ... of the chain (a root from the store need not be sent).
func ordered(chain []*x509.Certificate, paths [][]*x509.Certificate) bool {
	for _, path := range paths {
		ok := true
		for j := 1; j < len(path) && ok; j++ {
			pos := indexOf(chain, path[j])
			ok = pos < 0 || pos == j
		}
		if ok {
			return true
		}
	}
	return false
}

func indexOf(chain []*x509.Certificate, c *x509.Certificate) int {
	for i, x := range chain {
		if x.Equal(c) {
			return i
		}
	}
	return -1
}

func issuedByAny(c *x509.Certificate, cands []*x509.Certificate) bool {
	for _, p := range cands {
		if c.CheckSignatureFrom(p) == nil {
			return true
		}
	}
	return false
}

func issuesAny(issuer *x509.Certificate, cs []*x509.Certificate) bool {
	for _, c := range cs {
		if c.CheckSignatureFrom(issuer) == nil {
			return true
		}
	}
	return false
}

// selfSigned is certs' rule: the issuer is the subject and the certificate's own key signed it (a self-signed leaf
// without the CA flag counts too).
func selfSigned(c *x509.Certificate) bool {
	return c != nil && bytes.Equal(c.RawIssuer, c.RawSubject) && c.CheckSignature(c.SignatureAlgorithm, c.RawTBSCertificate, c.Signature) == nil
}

func poolOf(cs []*x509.Certificate) *x509.CertPool {
	p := x509.NewCertPool()
	for _, c := range cs {
		p.AddCert(c)
	}
	return p
}

// systemRoots is the operating system's roots, or an empty pool.
func systemRoots() *x509.CertPool {
	if p, err := x509.SystemCertPool(); err == nil && p != nil {
		return p
	}
	return x509.NewCertPool()
}
