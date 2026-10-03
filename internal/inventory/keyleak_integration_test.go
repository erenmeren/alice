//go:build integration

package inventory_test

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/stretchr/testify/require"

	"alice/internal/inventory"
	"alice/internal/rbac"
	"alice/internal/testutil/pki"
)

// secretMarkers are forms of the private part of an ECDSA key (its scalar, never the public point,
// which the certificate carries): raw, hex in both cases, base64 in the usual alphabets, and the
// run of the PKCS#8 base64 text (what a PEM body shows) that covers only scalar bytes.
func secretMarkers(t *testing.T, key crypto.Signer) []string {
	t.Helper()
	k, ok := key.(*ecdsa.PrivateKey)
	require.True(t, ok)
	d, err := k.Bytes()
	require.NoError(t, err)
	der, err := x509.MarshalPKCS8PrivateKey(k)
	require.NoError(t, err)
	o := bytes.Index(der, d)
	require.GreaterOrEqual(t, o, 0)
	from, to := (o+2)/3*3, (o+32)/3*3
	text := base64.StdEncoding.EncodeToString(der)[from/3*4 : to/3*4]
	return []string{string(d), hex.EncodeToString(d), fmt.Sprintf("%X", d), base64.StdEncoding.EncodeToString(d),
		base64.RawURLEncoding.EncodeToString(d), text}
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
	issue := func(cn string) pki.Leaf {
		l := ca.Issue(pki.Opts{CommonName: cn}, h.clock.Now())
		m := secretMarkers(t, l.Key)
		require.Contains(t, strings.ReplaceAll(string(l.KeyPEM), "\n", ""), m[len(m)-1], "the text marker is what a PEM shows")
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
	require.Len(t, s.markers, 6*6+3)
	s.check()
}
