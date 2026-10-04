package fakekv

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1" //nolint:gosec // G505: x5t is the SHA-1 thumbprint by definition (RFC 7515)
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"math/big"
	"regexp"
	"sort"
	"time"

	"software.sslmate.com/src/go-pkcs12"

	"alice/internal/testutil/pki"
)

// CertOptions describes a vault certificate.
type CertOptions struct {
	CommonName string
	SANs       []string
	KeyType    pki.KeyType // default ECDSA256
	Exportable bool        // default false: a non-exportable certificate's secret is refused
	// ContentType is "application/x-pkcs12" (default) or "application/x-pem-file".
	ContentType string
	IncludeRoot bool // the secret's bundle carries the fake root too
	// PEMKeyLast puts the PRIVATE KEY block after the certificates in a PEM secret (default before;
	// GUESS: the order of a real Key Vault PEM secret is unverified).
	PEMKeyLast          bool
	NotBefore, NotAfter time.Time
}

// KeyOptions describes a key (not backed by a certificate).
type KeyOptions struct {
	KeyType string // "RSA" or "EC"
	Size    int    // RSA bits (2048, 3072, 4096)
	Curve   string // EC curve name ("P-256", "P-384", "P-521")
	Enabled bool
	Expires *time.Time
}

type policyState struct {
	exportable  bool
	contentType string
	reuseKey    bool
	issuer      string
	actionType  string
	actionPct   int
}

type version struct {
	id               string
	cert             *x509.Certificate
	chain            []*x509.Certificate // intermediates (and root), leaf excluded
	key              any                 // *rsa.PrivateKey or *ecdsa.PrivateKey; nil never (imports require a key)
	created, updated time.Time
	enabled          bool
	pemKeyLast       bool
	served           map[string]string // secret value served per content type (cached: the same bytes every read)
}

type certEntry struct {
	name     string
	o        CertOptions
	policy   policyState
	versions []*version // creation order
	imported bool
	deleted  bool
	created  time.Time
	updated  time.Time
}

type keyEntry struct {
	name             string
	id               string
	o                KeyOptions
	pub              jwk
	created, updated time.Time
}

type secretEntry struct {
	name        string
	id          string
	contentType string
	value       string
	created     time.Time
}

var nameRE = regexp.MustCompile(`^[0-9a-zA-Z-]+$`)

func newVersionID() string {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

func thumbprint(der []byte) string {
	sum := sha1.Sum(der) //nolint:gosec // G401: x5t is SHA-1 by definition
	return b64url.EncodeToString(sum[:])
}

func checkName(name string) {
	if !nameRE.MatchString(name) {
		panic("fakekv: invalid object name " + name)
	}
}

// issue signs a leaf with the fake CA.
func (s *Server) issue(o CertOptions, now time.Time) (pki.Leaf, []*x509.Certificate) {
	leaf := s.ca.Issue(pki.Opts{CommonName: o.CommonName, SANs: o.SANs, KeyType: o.KeyType, NotBefore: o.NotBefore, NotAfter: o.NotAfter}, now)
	chain := []*x509.Certificate{s.ca.Intermediate}
	if o.IncludeRoot {
		chain = append(chain, s.ca.Root)
	}
	return leaf, chain
}

func (s *Server) newVersion(o CertOptions) *version {
	now := s.o.Now()
	leaf, chain := s.issue(o, now)
	return &version{id: newVersionID(), cert: leaf.Cert, chain: chain, key: leaf.Key, created: now, updated: now,
		enabled: true, pemKeyLast: o.PEMKeyLast, served: map[string]string{}}
}

// AddCertificate creates (or replaces) a certificate with one version and returns the version ID.
// The certificate is self-managed by the fake CA: policy issuer "Self", AutoRenew at 80 %.
func (s *Server) AddCertificate(name string, o CertOptions) string {
	checkName(name)
	if o.ContentType == "" {
		o.ContentType = "application/x-pkcs12"
	}
	v := s.newVersion(o)
	now := s.o.Now()
	e := &certEntry{name: name, o: o, versions: []*version{v}, created: now, updated: now,
		policy: policyState{exportable: o.Exportable, contentType: o.ContentType, issuer: "Self", actionType: "AutoRenew", actionPct: 80}}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.certs[name] = e
	return v.id
}

// AddBulkCertificates creates n exportable certificates named <prefix>-00000 ... that all share ONE
// generated certificate and key (each with its own version ID), so a listing of thousands of
// items costs almost no memory. Their x5t is therefore identical.
func (s *Server) AddBulkCertificates(prefix string, n int) {
	checkName(prefix)
	shared := s.newVersion(CertOptions{CommonName: "bulk.example.test", Exportable: true})
	now := s.o.Now()
	s.mu.Lock()
	defer s.mu.Unlock()
	for i := 0; i < n; i++ {
		v := *shared
		v.id = newVersionID()
		v.created, v.updated = now, now
		v.served = map[string]string{}
		name := fmt.Sprintf("%s-%05d", prefix, i)
		s.certs[name] = &certEntry{name: name, o: CertOptions{CommonName: "bulk.example.test", Exportable: true, ContentType: "application/x-pkcs12"},
			versions: []*version{&v}, created: now, updated: now,
			policy: policyState{exportable: true, contentType: "application/x-pkcs12", issuer: "Self", actionType: "AutoRenew", actionPct: 80}}
	}
}

// Renew adds a version signed by the fake CA with the certificate's names and key type
// (Key Vault auto-renewal) and returns its ID. It panics for an unknown name.
func (s *Server) Renew(name string) string {
	s.mu.Lock()
	e := s.certs[name]
	if e == nil {
		s.mu.Unlock()
		panic("fakekv: Renew of unknown certificate " + name)
	}
	o := e.o
	s.mu.Unlock()
	v := s.newVersion(o)
	s.mu.Lock()
	defer s.mu.Unlock()
	e.versions = append(e.versions, v)
	e.updated = v.updated
	return v.id
}

// SetExportable changes the policy's exportable flag (a Monitor-only certificate).
func (s *Server) SetExportable(name string, exportable bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if e := s.certs[name]; e != nil {
		e.policy.exportable = exportable
		e.updated = s.o.Now()
	}
}

// DisableVersion sets a version's enabled attribute to false (updated moves to now).
func (s *Server) DisableVersion(name, version string) { s.setEnabled(name, version, false) }

// EnableVersion undoes DisableVersion.
func (s *Server) EnableVersion(name, version string) { s.setEnabled(name, version, true) }

func (s *Server) setEnabled(name, ver string, enabled bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, v := s.find(name, ver); v != nil {
		v.enabled = enabled
		v.updated = s.o.Now()
	}
}

// DeleteCertificate soft-deletes a certificate: it leaves every listing and answers 404; its backing
// key and secret go with it. The name cannot be imported into until RecoverCertificate (GUESS: see
// importCertificate).
func (s *Server) DeleteCertificate(name string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if e := s.certs[name]; e != nil {
		e.deleted = true
	}
}

// RecoverCertificate undoes DeleteCertificate.
func (s *Server) RecoverCertificate(name string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if e := s.certs[name]; e != nil {
		e.deleted = false
	}
}

// AddKey adds a key (replacing one of the same name).
func (s *Server) AddKey(name string, o KeyOptions) {
	checkName(name)
	now := s.o.Now()
	pub := s.publicKey(o)
	s.mu.Lock()
	defer s.mu.Unlock()
	s.keys[name] = &keyEntry{name: name, id: newVersionID(), o: o, pub: pub, created: now, updated: now}
}

// publicKey generates (or reuses, per type) a key pair and returns its public JWK without kid.
func (s *Server) publicKey(o KeyOptions) jwk {
	s.mu.Lock()
	defer s.mu.Unlock()
	switch o.KeyType {
	case "EC":
		curve, crv := elliptic.P256(), "P-256"
		switch o.Curve {
		case "P-384":
			curve, crv = elliptic.P384(), o.Curve
		case "P-521":
			curve, crv = elliptic.P521(), o.Curve
		}
		k, ok := s.keyPool[crv].(*ecdsa.PrivateKey)
		if !ok {
			var err error
			if k, err = ecdsa.GenerateKey(curve, rand.Reader); err != nil {
				panic(err)
			}
			s.keyPool[crv] = k
		}
		return jwkOfPublic(&k.PublicKey)
	default:
		size := o.Size
		if size == 0 {
			size = 2048
		}
		id := fmt.Sprintf("rsa-%d", size)
		k, ok := s.keyPool[id].(*rsa.PrivateKey)
		if !ok {
			var err error
			if k, err = rsa.GenerateKey(rand.Reader, size); err != nil {
				panic(err)
			}
			s.keyPool[id] = k
		}
		return jwkOfPublic(&k.PublicKey)
	}
}

func jwkOfPublic(pub any) jwk {
	switch p := pub.(type) {
	case *rsa.PublicKey:
		return jwk{Kty: "RSA", KeyOps: []string{"sign", "verify"}, N: b64url.EncodeToString(p.N.Bytes()),
			E: b64url.EncodeToString(big.NewInt(int64(p.E)).Bytes())}
	case *ecdsa.PublicKey:
		// Bytes is the uncompressed point 0x04 || X || Y with fixed-size coordinates.
		pt, err := p.Bytes()
		if err != nil {
			panic(err)
		}
		size := (len(pt) - 1) / 2
		return jwk{Kty: "EC", KeyOps: []string{"sign", "verify"}, Crv: p.Curve.Params().Name,
			X: b64url.EncodeToString(pt[1 : 1+size]), Y: b64url.EncodeToString(pt[1+size:])}
	}
	panic("fakekv: unsupported public key")
}

// AddSecret adds a plain secret with a generated, obviously fake value (replacing one of the same
// name). It panics if a certificate of that name exists (a certificate owns the name of its secret).
func (s *Server) AddSecret(name, contentType string) {
	checkName(name)
	b := make([]byte, 8)
	_, _ = rand.Read(b)
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.certs[name] != nil {
		panic("fakekv: a certificate named " + name + " owns that secret name")
	}
	s.secrets[name] = &secretEntry{name: name, id: newVersionID(), contentType: contentType,
		value: "fake-secret-value-" + hex.EncodeToString(b), created: s.o.Now()}
}

// Leaf returns a version's certificate ("" = the current version), or nil.
func (s *Server) Leaf(name, version string) *x509.Certificate {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, v := s.find(name, version); v != nil {
		return v.cert
	}
	return nil
}

// SecretValue returns the exact secret value the fake serves for a certificate version ("" = current)
// or a plain secret (the `value` field: base64 PFX text, PEM text or the plain value), or nil.
func (s *Server) SecretValue(name, version string) []byte {
	s.mu.Lock()
	defer s.mu.Unlock()
	if e, v := s.find(name, version); v != nil && !e.deleted {
		return []byte(s.servedLocked(e, v))
	}
	if p := s.secrets[name]; p != nil {
		return []byte(p.value)
	}
	return nil
}

// Versions returns a certificate's version IDs, oldest first.
func (s *Server) Versions(name string) []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	e := s.certs[name]
	if e == nil {
		return nil
	}
	ids := make([]string, len(e.versions))
	for i, v := range e.versions {
		ids[i] = v.id
	}
	return ids
}

// find returns the entry (even soft-deleted) and a version ("" = newest). Callers hold s.mu.
func (s *Server) find(name, ver string) (*certEntry, *version) {
	e := s.certs[name]
	if e == nil || len(e.versions) == 0 {
		return nil, nil
	}
	if ver == "" {
		return e, e.versions[len(e.versions)-1]
	}
	for _, v := range e.versions {
		if v.id == ver {
			return e, v
		}
	}
	return e, nil
}

// servedLocked returns the secret value of a version under the entry's current content type. It is
// computed once per content type, because PFX encoding is randomised and a re-read must serve the same bytes.
func (s *Server) servedLocked(e *certEntry, v *version) string {
	ct := e.policy.contentType
	if val, ok := v.served[ct]; ok {
		return val
	}
	var val string
	if ct == "application/x-pem-file" {
		val = pemSecret(v)
	} else {
		pfx, err := pkcs12.Modern.Encode(v.key, v.cert, v.chain, "")
		if err != nil {
			panic("fakekv: encoding the PFX: " + err.Error())
		}
		val = base64.StdEncoding.EncodeToString(pfx)
	}
	v.served[ct] = val
	return val
}

// pemSecret is the PEM form of a certificate secret: a PKCS #8 PRIVATE KEY block and the certificates,
// leaf first (GUESS: block order unverified).
func pemSecret(v *version) string {
	der, err := x509.MarshalPKCS8PrivateKey(v.key)
	if err != nil {
		panic(err)
	}
	keyBlock := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})
	var certs []byte
	for _, c := range append([]*x509.Certificate{v.cert}, v.chain...) {
		certs = append(certs, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: c.Raw})...)
	}
	if v.pemKeyLast {
		return string(certs) + string(keyBlock)
	}
	return string(keyBlock) + string(certs)
}

// sortedNames returns the names of live certificates sorted. Callers hold s.mu.
func (s *Server) liveCertNames() []string {
	names := make([]string, 0, len(s.certs))
	for n, e := range s.certs {
		if !e.deleted {
			names = append(names, n)
		}
	}
	sort.Strings(names)
	return names
}
