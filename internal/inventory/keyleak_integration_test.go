//go:build integration

package inventory_test

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/stretchr/testify/require"

	"alice/internal/inventory"
	"alice/internal/rbac"
	"alice/internal/testutil/pki"
)

// secretMarkers are forms of 32 bytes of a key's private part (an ECDSA scalar; a slice of an RSA
// private exponent — never public values, which the certificate carries): raw, hex in both cases,
// base64 in the usual alphabets, and, for each encoding a PEM body may show (PKCS#8 and the
// key's own: SEC 1 or PKCS#1), the run of its base64 text that covers only those bytes.
func secretMarkers(t *testing.T, key crypto.Signer) []string {
	t.Helper()
	var secret, native []byte
	switch k := key.(type) {
	case *ecdsa.PrivateKey:
		d, err := k.Bytes()
		require.NoError(t, err)
		secret = d
		native, err = x509.MarshalECPrivateKey(k)
		require.NoError(t, err)
	case *rsa.PrivateKey:
		secret = k.D.Bytes()[16:48]
		native = x509.MarshalPKCS1PrivateKey(k)
	default:
		t.Fatalf("no markers for %T", key)
	}
	pkcs8, err := x509.MarshalPKCS8PrivateKey(key)
	require.NoError(t, err)
	out := []string{string(secret), hex.EncodeToString(secret), fmt.Sprintf("%X", secret), base64.StdEncoding.EncodeToString(secret),
		base64.RawURLEncoding.EncodeToString(secret)}
	for _, der := range [][]byte{pkcs8, native} {
		out = append(out, pemTextRun(t, der, secret))
	}
	return out
}

// pemTextRun is the part of der's base64 text that encodes only bytes of secret.
func pemTextRun(t *testing.T, der, secret []byte) string {
	t.Helper()
	o := bytes.Index(der, secret)
	require.GreaterOrEqual(t, o, 0)
	from, to := (o+2)/3*3, (o+len(secret))/3*3
	return base64.StdEncoding.EncodeToString(der)[from/3*4 : to/3*4]
}

// leakScan collects every value the flows produce and searches all of it for the markers.
type leakScan struct {
	t       *testing.T
	h       *harness
	values  []string
	markers []string
}

func (s *leakScan) add(vs ...any) {
	for _, v := range vs {
		if err, ok := v.(error); ok && err != nil {
			s.values = append(s.values, err.Error(), fmt.Sprintf("%+v %#v", err, err))
			continue
		}
		s.values = append(s.values, fmt.Sprintf("%v %+v %#v", v, v, v))
	}
}

func (s *leakScan) check() {
	t, h := s.t, s.h
	t.Helper()
	haystacks := append([]string{h.logs.String()}, s.values...)
	// Every row of every table, as PostgreSQL renders it (bytea as hex).
	rows, err := h.db.Owner.Query(h.ctx, "SELECT table_name FROM information_schema.tables WHERE table_schema = 'public' AND table_type = 'BASE TABLE'")
	require.NoError(t, err)
	tables, err := pgx.CollectRows(rows, pgx.RowTo[string])
	require.NoError(t, err)
	require.Contains(t, tables, "managed_private_keys")
	for _, name := range tables {
		var dump string
		require.NoError(t, h.db.Owner.QueryRow(h.ctx, "SELECT coalesce(string_agg(t::text, E'\\n'), '') FROM "+pgx.Identifier{name}.Sanitize()+" t").
			Scan(&dump))
		haystacks = append(haystacks, dump)
	}
	require.Greater(t, h.audits("certificate.uploaded")+h.audits("csr.completed"), 0)
	for _, hay := range haystacks {
		flat := strings.NewReplacer("\n", "", "\r", "").Replace(hay)
		for _, m := range s.markers {
			require.NotContains(t, flat, m, "a private key or password leaked")
		}
	}
}

// The binding leak test: every returned value, error, audit row, log line and database row of the
// upload (PEM and PFX) and signing request flows is free of the keys and the PFX passwords.
func TestNoPrivateKeyOrPasswordLeaks(t *testing.T) {
	h := newHarness(t)
	op := h.user("oya", rbac.Operator, "")
	s := &leakScan{t: t, h: h}
	ca := pki.NewCA("Leak", pki.ECDSA256, h.clock.Now())
	issue := func(cn string, o ...pki.Opts) pki.Leaf {
		opts := pki.Opts{CommonName: cn}
		if len(o) > 0 {
			opts = o[0]
			opts.CommonName = cn
		}
		l := ca.Issue(opts, h.clock.Now())
		m := secretMarkers(t, l.Key)
		require.Contains(t, strings.ReplaceAll(string(l.KeyPEM), "\n", ""), m[5], "the text marker is what a PEM shows")
		s.markers = append(s.markers, m...)
		return l
	}
	pem1, pem2, pfx1, pfx2 := issue("pem1.example.test"), issue("pem2.example.test"), issue("pfx1.example.test"), issue("pfx2.example.test")
	const pw1, pw2, wrong = "Correct-Horse-5f1e2d", "Battery-Staple-9a8b7c", "Wrong-Guess-3c4d5e"
	s.markers = append(s.markers, pw1, pw2, wrong)

	c, w, err := h.svc.UploadCertificate(h.ctx, op, pemUpload(pem1))
	require.NoError(t, err)
	s.add(c, w)
	c, w, err = h.svc.UploadCertificate(h.ctx, op, pemUpload(pem1))
	require.ErrorIs(t, err, inventory.ErrCertificateDuplicate)
	s.add(c, w, err)
	c, w, err = h.svc.UploadCertificate(h.ctx, op, inventory.UploadInput{CertificatePEM: string(pem1.FullchainPEM), PrivateKeyPEM: string(pem2.KeyPEM)})
	require.ErrorIs(t, err, inventory.ErrKeyMismatch)
	s.add(c, w, err)
	c, w, err = h.svc.UploadCertificate(h.ctx, op, inventory.UploadInput{PFXBase64: base64.StdEncoding.EncodeToString(pki.PFX(pfx1, ca, pw1)),
		PFXPassword: pw1})
	require.NoError(t, err)
	s.add(c, w)
	c, w, err = h.svc.UploadCertificate(h.ctx, op, inventory.UploadInput{PFXBase64: base64.StdEncoding.EncodeToString(pki.PFX(pfx2, ca, pw2)),
		PFXPassword: wrong})
	require.ErrorIs(t, err, inventory.ErrPFXPassword)
	s.add(c, w, err)
	c, w, err = h.svc.UploadCertificate(h.ctx, op, inventory.UploadInput{CertificatePEM: "x", PFXBase64: "eA==", PFXPassword: pw2})
	require.Error(t, err)
	s.add(c, w, err)

	// Key encodings other than PKCS#8 (their own PEM text forms are markers), and RSA keys.
	now := h.clock.Now()
	rsaLeaf := issue("rsa.example.test", pki.Opts{KeyType: pki.RSA2048})
	pkcs1 := pki.KeyPEMPKCS1(rsaLeaf.Key.(*rsa.PrivateKey))
	require.Contains(t, strings.ReplaceAll(string(pkcs1), "\n", ""), secretMarkers(t, rsaLeaf.Key)[6])
	c, w, err = h.svc.UploadCertificate(h.ctx, op, inventory.UploadInput{CertificatePEM: string(rsaLeaf.FullchainPEM), PrivateKeyPEM: string(pkcs1)})
	require.NoError(t, err)
	s.add(c, w)
	ecLeaf := issue("sec1.example.test")
	sec1 := pki.KeyPEMSEC1(ecLeaf.Key.(*ecdsa.PrivateKey))
	require.Contains(t, strings.ReplaceAll(string(sec1), "\n", ""), secretMarkers(t, ecLeaf.Key)[6])
	c, w, err = h.svc.UploadCertificate(h.ctx, op, inventory.UploadInput{CertificatePEM: string(ecLeaf.FullchainPEM), PrivateKeyPEM: string(sec1)})
	require.NoError(t, err)
	s.add(c, w)
	// Refusals that read the key: expired, weak, a key in the certificate field, an invalid label.
	expired := issue("old.example.test", pki.Opts{NotBefore: now.AddDate(0, -3, 0), NotAfter: now.Add(-time.Minute)})
	c, w, err = h.svc.UploadCertificate(h.ctx, op, pemUpload(expired))
	require.ErrorIs(t, err, inventory.ErrCertificateExpired)
	s.add(c, w, err)
	weak := issue("weak.example.test", pki.Opts{KeyType: pki.RSA1024})
	c, w, err = h.svc.UploadCertificate(h.ctx, op, pemUpload(weak))
	require.ErrorIs(t, err, inventory.ErrWeakCertificate)
	s.add(c, w, err)
	labelled := issue("label.example.test")
	in := pemUpload(labelled)
	in.Label = "bad\x00label"
	c, w, err = h.svc.UploadCertificate(h.ctx, op, in)
	require.Error(t, err)
	s.add(c, w, err)
	pasted := issue("pasted.example.test")
	c, w, err = h.svc.UploadCertificate(h.ctx, op, inventory.UploadInput{CertificatePEM: string(pasted.FullchainPEM) + string(pasted.KeyPEM)})
	require.Error(t, err)
	s.add(c, w, err)
	// A password-protected key: its encrypted body is never shown either.
	encrypted := pki.EncryptedKeyPEM(labelled)
	block, _ := pem.Decode(encrypted)
	require.NotNil(t, block)
	s.markers = append(s.markers, hex.EncodeToString(block.Bytes[32:64]), pemTextRun(t, block.Bytes, block.Bytes[32:64]))
	c, w, err = h.svc.UploadCertificate(h.ctx, op, inventory.UploadInput{CertificatePEM: string(labelled.FullchainPEM), PrivateKeyPEM: string(encrypted)})
	require.ErrorIs(t, err, inventory.ErrKeyEncrypted)
	s.add(c, w, err)

	// Signing requests: the generated keys are read back (test-only) to build their markers.
	csrKeyMarkers := func(id uuid.UUID) {
		var keyID uuid.UUID
		require.NoError(t, h.db.Owner.QueryRow(h.ctx, "SELECT private_key_id FROM csr_requests WHERE id = $1", id).Scan(&keyID))
		pt, err := h.svc.LoadKey(h.ctx, keyID)
		require.NoError(t, err)
		k, err := x509.ParsePKCS8PrivateKey(pt.Bytes())
		pt.Zero()
		require.NoError(t, err)
		s.markers = append(s.markers, secretMarkers(t, k.(crypto.Signer))...)
	}
	csr, err := h.svc.CreateCSR(h.ctx, op, inventory.CSRInput{CommonName: "csr.example.test", KeyType: "ecdsa-p256"})
	require.NoError(t, err)
	s.add(csr)
	csrKeyMarkers(csr.ID)
	signed := ca.IssueForCSR(parseCSR(t, csr), h.clock.Now())
	c, w, err = h.svc.CompleteCSR(h.ctx, op, csr.ID, string(pem2.FullchainPEM), "")
	require.ErrorIs(t, err, inventory.ErrCSRMismatch)
	s.add(c, w, err)
	c, w, err = h.svc.CompleteCSR(h.ctx, op, csr.ID, string(signed.FullchainPEM), "")
	require.NoError(t, err)
	s.add(c, w)
	got, err := h.svc.GetCSR(h.ctx, csr.ID)
	require.NoError(t, err)
	s.add(got)
	cancelled, err := h.svc.CreateCSR(h.ctx, op, inventory.CSRInput{CommonName: "gone.example.test", KeyType: "ecdsa-p256"})
	require.NoError(t, err)
	csrKeyMarkers(cancelled.ID)
	cancelled, err = h.svc.CancelCSR(h.ctx, op, cancelled.ID)
	require.NoError(t, err)
	list, err := h.svc.ListCSRs(h.ctx)
	require.NoError(t, err)
	s.add(cancelled, list)
	page, err := h.svc.ListCertificates(h.ctx, inventory.CertificateFilter{})
	require.NoError(t, err)
	s.add(page)
	for _, item := range page.Items {
		full, err := h.svc.GetCertificate(h.ctx, item.ID)
		require.NoError(t, err)
		s.add(full)
	}
	require.Len(t, s.markers, (10+2)*7+3+2, "10 uploaded keys, 2 generated keys, 3 passwords, 2 of the encrypted key")
	s.check()
}
