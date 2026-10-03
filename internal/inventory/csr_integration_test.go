//go:build integration

package inventory_test

import (
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"alice/internal/certs"
	"alice/internal/inventory"
	"alice/internal/platform/validate"
	"alice/internal/providers"
	"alice/internal/rbac"
	"alice/internal/testutil/pki"
)

func parseCSR(t *testing.T, csr inventory.CSR) *x509.CertificateRequest {
	t.Helper()
	b, _ := pem.Decode([]byte(csr.CSRPEM))
	require.NotNil(t, b)
	req, err := x509.ParseCertificateRequest(b.Bytes)
	require.NoError(t, err)
	require.NoError(t, req.CheckSignature())
	return req
}

func TestSigningRequestLifecycle(t *testing.T) {
	h := newHarness(t)
	op := h.user("oya", rbac.Operator, "")
	csr, err := h.svc.CreateCSR(h.ctx, op, inventory.CSRInput{CommonName: "WWW.Example.test", SANs: []string{"example.test", "www.example.test"},
		KeyType: "ecdsa-p256"})
	require.NoError(t, err)
	assert.Equal(t, "pending", csr.Status)
	assert.Equal(t, "www.example.test", csr.CommonName, "lower-cased")
	assert.Equal(t, []string{"www.example.test", "example.test"}, csr.SANs, "the names of the request: the common name first, once")
	assert.Equal(t, "ecdsa", csr.KeyAlgorithm)
	assert.Equal(t, 256, csr.KeyBits)
	assert.Nil(t, csr.CertificateID)
	assert.Nil(t, csr.FinishedAt)
	assert.Equal(t, h.clock.Now(), csr.CreatedAt)
	assert.Contains(t, csr.CSRPEM, "BEGIN CERTIFICATE REQUEST")
	req := parseCSR(t, csr)
	assert.Equal(t, "www.example.test", req.Subject.CommonName)
	assert.Equal(t, []string{"www.example.test", "example.test"}, req.DNSNames)
	var owner string
	require.NoError(t, h.db.Owner.QueryRow(h.ctx, "SELECT k.owner_type FROM csr_requests r JOIN managed_private_keys k ON k.id = r.private_key_id WHERE r.id = $1",
		csr.ID).Scan(&owner))
	assert.Equal(t, "csr", owner)
	assert.Equal(t, []map[string]string{{"csr_id": csr.ID.String(), "common_name": "www.example.test", "algorithm": "ecdsa", "bits": "256"}},
		h.auditDetails("csr.created"))

	// The CA signs the request's key.
	ca := pki.NewCA("CSR", pki.ECDSA256, h.clock.Now())
	signed := ca.IssueForCSR(req, h.clock.Now())
	h.clock.Advance(time.Minute)
	c, warnings, err := h.svc.CompleteCSR(h.ctx, op, csr.ID, string(signed.FullchainPEM), "Signed")
	require.NoError(t, err)
	assert.Equal(t, []string{"chain_incomplete"}, warnings)
	assert.Equal(t, "csr", c.Source)
	assert.True(t, c.HasPrivateKey)
	assert.Equal(t, "Signed", c.Label)
	assert.Equal(t, pki.Fingerprint(signed.Cert), c.Fingerprint)
	got, err := h.svc.GetCSR(h.ctx, csr.ID)
	require.NoError(t, err)
	assert.Equal(t, "completed", got.Status)
	require.NotNil(t, got.CertificateID)
	assert.Equal(t, c.ID, *got.CertificateID)
	require.NotNil(t, got.FinishedAt)
	assert.Equal(t, h.clock.Now(), *got.FinishedAt)
	assert.Equal(t, 1, h.count("SELECT count(*) FROM certificates c JOIN csr_requests r ON r.private_key_id = c.private_key_id"),
		"the certificate holds the request's key")
	assert.Equal(t, []map[string]string{{"csr_id": csr.ID.String(), "certificate_id": c.ID.String(), "fingerprint": c.Fingerprint,
		"outcome": "created"}}, h.auditDetails("csr.completed"))
	_, _, err = h.svc.CompleteCSR(h.ctx, op, csr.ID, string(signed.FullchainPEM), "")
	assert.ErrorIs(t, err, inventory.ErrCSRNotPending)

	other, err := h.svc.CreateCSR(h.ctx, op, inventory.CSRInput{CommonName: "b.example.test", KeyType: "rsa-3072"})
	require.NoError(t, err)
	assert.Equal(t, "rsa", other.KeyAlgorithm)
	assert.Equal(t, 3072, other.KeyBits)
	_, _, err = h.svc.CompleteCSR(h.ctx, op, other.ID, string(signed.FullchainPEM), "")
	assert.ErrorIs(t, err, inventory.ErrCSRMismatch)
	_, err = h.svc.CancelCSR(h.ctx, op, other.ID)
	require.NoError(t, err)
	_, err = h.svc.CancelCSR(h.ctx, op, other.ID)
	assert.ErrorIs(t, err, inventory.ErrCSRNotPending)
	_, _, err = h.svc.CompleteCSR(h.ctx, op, other.ID, string(signed.FullchainPEM), "")
	assert.ErrorIs(t, err, inventory.ErrCSRNotPending)
	assert.Equal(t, 1, h.audits("csr.completed"))
	assert.Equal(t, 1, h.audits("csr.cancelled"))
	assert.Equal(t, []map[string]string{{"csr_id": other.ID.String()}}, h.auditDetails("csr.cancelled"))
	assert.Equal(t, []string{"csr_mismatch"}, rejectReasons(h))
	// The key of a cancelled request stays sealed (the table is append-only) and is no certificate's.
	assert.Equal(t, 2, h.count("SELECT count(*) FROM managed_private_keys"))
	assert.Equal(t, 0, h.count("SELECT count(*) FROM certificates c JOIN csr_requests r ON r.private_key_id = c.private_key_id WHERE r.id = $1", other.ID))

	_, err = h.svc.GetCSR(h.ctx, uuid.Must(uuid.NewV7()))
	assert.ErrorIs(t, err, inventory.ErrNotFound)
	_, _, err = h.svc.CompleteCSR(h.ctx, op, uuid.Must(uuid.NewV7()), string(signed.FullchainPEM), "")
	assert.ErrorIs(t, err, inventory.ErrNotFound)
	_, err = h.svc.CancelCSR(h.ctx, op, uuid.Must(uuid.NewV7()))
	assert.ErrorIs(t, err, inventory.ErrNotFound)

	var verrs validate.Errors
	_, err = h.svc.CreateCSR(h.ctx, op, inventory.CSRInput{CommonName: "bad name", KeyType: "ecdsa-p256"})
	require.ErrorAs(t, err, &verrs)
	assert.Equal(t, "common_name", verrs[0].Field)
	_, err = h.svc.CreateCSR(h.ctx, op, inventory.CSRInput{CommonName: "a.example.test", KeyType: "dsa"})
	require.ErrorAs(t, err, &verrs)
	assert.Equal(t, "key_type", verrs[0].Field)
}

func TestSigningRequestValidation(t *testing.T) {
	h := newHarness(t)
	op := h.user("oya", rbac.Operator, "")
	label63 := strings.Repeat("a", 63)
	cn65 := label63 + ".b"
	require.Len(t, cn65, 65)
	many := make([]string, 51)
	for i := range many {
		many[i] = fmt.Sprintf("n%d.example.test", i)
	}
	for _, tc := range []struct {
		in     inventory.CSRInput
		fields map[string]string
	}{
		{inventory.CSRInput{KeyType: "ecdsa-p256"}, map[string]string{"common_name": validate.Required}},
		{inventory.CSRInput{CommonName: "  ", KeyType: "ecdsa-p256"}, map[string]string{"common_name": validate.Required}},
		// D20: the schema's bound of a common name is 64 characters.
		{inventory.CSRInput{CommonName: cn65, KeyType: "ecdsa-p256"}, map[string]string{"common_name": validate.OutOfRange}},
		{inventory.CSRInput{CommonName: "*.com", KeyType: "ecdsa-p256"}, map[string]string{"common_name": validate.Pattern}},
		{inventory.CSRInput{CommonName: "ş.example.test", KeyType: "ecdsa-p256"}, map[string]string{"common_name": validate.Pattern}},
		{inventory.CSRInput{CommonName: "192.0.2.1", KeyType: "ecdsa-p256"}, map[string]string{"common_name": validate.Pattern}},
		{inventory.CSRInput{CommonName: "a.example.test", SANs: []string{"192.0.2.1"}, KeyType: "ecdsa-p256"}, map[string]string{"sans": validate.Pattern}},
		{inventory.CSRInput{CommonName: "a.example.test", SANs: []string{"ok.example.test", "-bad.example.test"}, KeyType: "ecdsa-p256"},
			map[string]string{"sans": validate.Pattern}},
		{inventory.CSRInput{CommonName: "a.example.test", SANs: many, KeyType: "ecdsa-p256"}, map[string]string{"sans": validate.OutOfRange}},
		{inventory.CSRInput{CommonName: "a.example.test", KeyType: ""}, map[string]string{"key_type": validate.OneOf}},
		{inventory.CSRInput{CommonName: "a b", SANs: []string{"*"}, KeyType: "rsa-2048"}, map[string]string{"common_name": validate.Pattern,
			"sans": validate.Pattern, "key_type": validate.OneOf}},
	} {
		_, err := h.svc.CreateCSR(h.ctx, op, tc.in)
		assert.Equal(t, tc.fields, fieldsOf(err), "%+v", tc.in)
	}
	assert.Equal(t, 0, h.count("SELECT count(*) FROM csr_requests"))
	assert.Equal(t, 0, h.count("SELECT count(*) FROM managed_private_keys"))

	// The limits themselves are accepted: a 64-character name, 50 names, a wildcard.
	cn64 := strings.Repeat("a", 61) + ".bc"
	require.Len(t, cn64, 64)
	csr, err := h.svc.CreateCSR(h.ctx, op, inventory.CSRInput{CommonName: cn64, SANs: many[:50], KeyType: "ecdsa-p256"})
	require.NoError(t, err)
	assert.Len(t, csr.SANs, 51)
	_, err = h.svc.CreateCSR(h.ctx, op, inventory.CSRInput{CommonName: "*.example.test", KeyType: "rsa-4096"})
	require.NoError(t, err)
}

// A signed certificate that a server already uses gets the request's key attached; refusals of a
// completion are audited with the request's id.
func TestCompleteSigningRequestForADiscoveredCertificate(t *testing.T) {
	h := newHarness(t)
	admin := h.user("ada", rbac.Admin, "")
	web := nginxTarget(t, h, admin, "web-01")
	csr, err := h.svc.CreateCSR(h.ctx, admin, inventory.CSRInput{CommonName: "www.example.test", KeyType: "ecdsa-p256"})
	require.NoError(t, err)
	req := parseCSR(t, csr)
	ca := pki.NewCA("CSR", pki.ECDSA256, h.clock.Now())
	now := h.clock.Now()
	expired := ca.IssueForCSR(req, now.AddDate(0, 0, -100)) // valid for 90 days from 100 days ago
	_, _, err = h.svc.CompleteCSR(h.ctx, admin, csr.ID, string(expired.FullchainPEM), "")
	require.ErrorIs(t, err, inventory.ErrCertificateExpired)
	_, _, err = h.svc.CompleteCSR(h.ctx, admin, csr.ID, "garbage", "")
	require.ErrorIs(t, err, inventory.ErrCertificateInvalid)
	_, _, err = h.svc.CompleteCSR(h.ctx, admin, csr.ID, " ", "")
	assert.Equal(t, map[string]string{"certificate_pem": validate.Required}, fieldsOf(err))
	_, _, err = h.svc.CompleteCSR(h.ctx, admin, csr.ID, "x", "a\nb")
	assert.Equal(t, map[string]string{"label": validate.Pattern}, fieldsOf(err))
	_, _, err = h.svc.CompleteCSR(h.ctx, admin, csr.ID, strings.Repeat("x", 256<<10+1), "")
	require.ErrorIs(t, err, inventory.ErrCertificateTooLarge)
	assert.Equal(t, []string{"expired", "invalid", "too_large"}, rejectReasons(h))
	for _, d := range h.auditDetails("certificate.upload_rejected") {
		assert.Equal(t, csr.ID.String(), d["csr_id"])
	}

	signed := ca.IssueForCSR(req, now)
	_, err = h.svc.Reconcile(h.ctx, web.ID, providers.DiscoveryResult{Nginx: nginxOK,
		Certificates: []providers.DiscoveredCertificate{dc(cl("/etc/nginx/ssl/www.crt", "/etc/nginx/ssl/www.key"), signed)}})
	require.NoError(t, err)
	page, err := h.svc.ListCertificates(h.ctx, inventory.CertificateFilter{})
	require.NoError(t, err)
	require.Len(t, page.Items, 1)
	c, _, err := h.svc.CompleteCSR(h.ctx, admin, csr.ID, string(signed.FullchainPEM), "")
	require.NoError(t, err)
	assert.Equal(t, page.Items[0].ID, c.ID)
	assert.Equal(t, "discovered", c.Source)
	assert.True(t, c.HasPrivateKey)
	assert.Equal(t, "key_attached", h.auditDetails("csr.completed")[0]["outcome"])

	// Another request whose certificate Alice already holds with a key: refused, the request stays open.
	again, err := h.svc.CreateCSR(h.ctx, admin, inventory.CSRInput{CommonName: "www.example.test", KeyType: "ecdsa-p256"})
	require.NoError(t, err)
	_, err = h.db.Owner.Exec(h.ctx, "UPDATE managed_private_keys SET public_key_sha256 = (SELECT public_key_sha256 FROM certificates) WHERE id = (SELECT private_key_id FROM csr_requests WHERE id = $1)", again.ID)
	require.NoError(t, err)
	_, _, err = h.svc.CompleteCSR(h.ctx, admin, again.ID, string(signed.FullchainPEM), "")
	require.ErrorIs(t, err, inventory.ErrCertificateDuplicate)
	got, err := h.svc.GetCSR(h.ctx, again.ID)
	require.NoError(t, err)
	assert.Equal(t, "pending", got.Status)
}

func TestListSigningRequests(t *testing.T) {
	h := newHarness(t)
	op := h.user("oya", rbac.Operator, "")
	var ids []uuid.UUID
	for i := range 4 {
		csr, err := h.svc.CreateCSR(h.ctx, op, inventory.CSRInput{CommonName: fmt.Sprintf("n%d.example.test", i), KeyType: "ecdsa-p256"})
		require.NoError(t, err)
		ids = append(ids, csr.ID)
		h.clock.Advance(time.Minute)
	}
	_, err := h.svc.CancelCSR(h.ctx, op, ids[0])
	require.NoError(t, err)
	h.clock.Advance(time.Minute)
	_, err = h.svc.CancelCSR(h.ctx, op, ids[2])
	require.NoError(t, err)
	list, err := h.svc.ListCSRs(h.ctx)
	require.NoError(t, err)
	var got []uuid.UUID
	for _, c := range list {
		got = append(got, c.ID)
	}
	assert.Equal(t, []uuid.UUID{ids[3], ids[1], ids[2], ids[0]}, got, "pending newest first, then finished newest first")
	empty := newHarness(t)
	list, err = empty.svc.ListCSRs(empty.ctx)
	require.NoError(t, err)
	assert.Equal(t, []inventory.CSR{}, list)
}

// A cancel that commits while a completion waits for the request's row: the completion sees the
// request no longer pending under the lock and stores nothing (the check before the transaction
// passed).
func TestCompleteSigningRequestLosesToACancel(t *testing.T) {
	h := newHarness(t)
	op := h.user("oya", rbac.Operator, "")
	csr, err := h.svc.CreateCSR(h.ctx, op, inventory.CSRInput{CommonName: "www.example.test", KeyType: "ecdsa-p256"})
	require.NoError(t, err)
	ca := pki.NewCA("CSR", pki.ECDSA256, h.clock.Now())
	signed := ca.IssueForCSR(parseCSR(t, csr), h.clock.Now())

	tx, err := h.db.Owner.Begin(h.ctx)
	require.NoError(t, err)
	defer func() { _ = tx.Rollback(h.ctx) }()
	_, err = tx.Exec(h.ctx, "SELECT id FROM csr_requests WHERE id = $1 FOR UPDATE", csr.ID)
	require.NoError(t, err)
	done := make(chan error, 1)
	go func() {
		_, _, err := h.svc.CompleteCSR(h.ctx, op, csr.ID, string(signed.FullchainPEM), "")
		done <- err
	}()
	select {
	case err := <-done:
		t.Fatalf("the completion did not wait for the request's row: %v", err)
	case <-time.After(300 * time.Millisecond):
	}
	_, err = tx.Exec(h.ctx, "UPDATE csr_requests SET status = 'cancelled', finished_at = $2 WHERE id = $1", csr.ID, h.clock.Now())
	require.NoError(t, err)
	require.NoError(t, tx.Commit(h.ctx))
	require.ErrorIs(t, <-done, inventory.ErrCSRNotPending)
	assert.Equal(t, 0, h.count("SELECT count(*) FROM certificates"))
	assert.Equal(t, 1, h.count("SELECT count(*) FROM managed_private_keys"), "only the request's key")
	got, err := h.svc.GetCSR(h.ctx, csr.ID)
	require.NoError(t, err)
	assert.Equal(t, "cancelled", got.Status)
	assert.Equal(t, 0, h.audits("csr.completed"))
}

// The mirror: a completion that commits while a cancel waits leaves the cancel a not-pending error.
func TestCancelSigningRequestLosesToACompletion(t *testing.T) {
	h := newHarness(t)
	op := h.user("oya", rbac.Operator, "")
	csr, err := h.svc.CreateCSR(h.ctx, op, inventory.CSRInput{CommonName: "www.example.test", KeyType: "ecdsa-p256"})
	require.NoError(t, err)
	ca := pki.NewCA("CSR", pki.ECDSA256, h.clock.Now())
	signed := ca.IssueForCSR(parseCSR(t, csr), h.clock.Now())
	p, err := certs.ParseChainPEM(signed.FullchainPEM)
	require.NoError(t, err)

	tx, err := h.db.Owner.Begin(h.ctx)
	require.NoError(t, err)
	defer func() { _ = tx.Rollback(h.ctx) }()
	_, err = tx.Exec(h.ctx, "SELECT id FROM csr_requests WHERE id = $1 FOR UPDATE", csr.ID)
	require.NoError(t, err)
	done := make(chan error, 1)
	go func() {
		_, err := h.svc.CancelCSR(h.ctx, op, csr.ID)
		done <- err
	}()
	select {
	case err := <-done:
		t.Fatalf("the cancel did not wait for the request's row: %v", err)
	case <-time.After(300 * time.Millisecond):
	}
	certID := uuid.Must(uuid.NewV7())
	_, err = tx.Exec(h.ctx, `INSERT INTO certificates (id, fingerprint_sha256, not_before, not_after, key_algorithm, key_bits, public_key_sha256,
pem_chain, source, private_key_id, first_seen_at, last_seen_at, created_at)
SELECT $1, $2, $3, $4, 'ecdsa', 256, $5, $6, 'csr', private_key_id, $7, $7, $7 FROM csr_requests WHERE id = $8`,
		certID, p.Fingerprint, p.NotBefore, p.NotAfter, p.PublicKeySHA256, p.PEMChain, h.clock.Now(), csr.ID)
	require.NoError(t, err)
	_, err = tx.Exec(h.ctx, "UPDATE csr_requests SET status = 'completed', certificate_id = $2, finished_at = $3 WHERE id = $1",
		csr.ID, certID, h.clock.Now())
	require.NoError(t, err)
	require.NoError(t, tx.Commit(h.ctx))
	require.ErrorIs(t, <-done, inventory.ErrCSRNotPending)
	got, err := h.svc.GetCSR(h.ctx, csr.ID)
	require.NoError(t, err)
	assert.Equal(t, "completed", got.Status)
	assert.Equal(t, 0, h.audits("csr.cancelled"))
}
