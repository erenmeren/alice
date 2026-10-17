//go:build integration

package inventory_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"alice/internal/i18n"
	"alice/internal/inventory"
	"alice/internal/jobs"
	"alice/internal/notify"
	"alice/internal/providers"
	"alice/internal/rbac"
	"alice/internal/testutil/pki"
	"alice/locales"
)

// B1-I1 (and the independent audit of 2026-10-04, AUD-17): a discovery on one server never
// rewrites the chain of a certificate a person uploaded (with its key): a scanned server's file
// that holds the same leaf with an unrelated certificate and the real intermediate leaves the stored
// chain, chain_complete and what a deployment to another server sends unchanged.
func TestDiscoveryNeverRewritesAnUploadedCertificatesChain(t *testing.T) {
	ca := pki.NewCA("Pub", pki.ECDSA256, start)
	roots := x509.NewCertPool()
	roots.AddCert(ca.Root)
	h := newHarness(t, withNginxProvider(), withRoots(roots))
	h.jobs.next = jobs.NewQueue(jobs.QueueConfig{Pool: h.db.App, Keyring: h.keyring, Audit: h.audit, Clock: h.clock, Gate: h.lic})
	admin := h.user("ada", rbac.Admin, "")
	www := pki.Opts{CommonName: "www.example.test", SANs: []string{"www.example.test"}}
	leaf := ca.Issue(www, h.clock.Now())

	c, warnings, err := h.svc.UploadCertificate(h.ctx, admin, inventory.UploadInput{CertificatePEM: string(leaf.CertPEM), PrivateKeyPEM: string(leaf.KeyPEM)})
	require.NoError(t, err)
	require.Contains(t, warnings, "chain_incomplete")
	require.Equal(t, string(leaf.CertPEM), c.PEMChain)

	// A less trusted server holds the public leaf with a certificate of its own choosing and the real
	// intermediate: the file would "complete" the chain.
	junk := pki.SelfSigned("attacker-chosen.example", pki.ECDSA256, h.clock.Now())
	file := append(append(append([]byte{}, leaf.CertPEM...), junk.CertPEM...), ca.IntermediatePEM...)
	hostile := nginxTarget(t, h, admin, "web-hostile")
	_, err = h.svc.Reconcile(h.ctx, hostile.ID, providers.DiscoveryResult{WebServer: nginxOK, Certificates: []providers.DiscoveredCertificate{
		{Location: cl("/etc/nginx/ssl/x.crt", "/etc/nginx/ssl/x.key", "www.example.test"), PEMChain: file, FileSHA256: sha(file)}}})
	require.NoError(t, err)

	got, err := h.svc.GetCertificate(h.ctx, c.ID)
	require.NoError(t, err)
	assert.True(t, got.HasPrivateKey)
	assert.Equal(t, string(leaf.CertPEM), got.PEMChain, "the uploaded chain is what the uploader gave")
	assert.False(t, got.ChainComplete, "a server's file does not lift the incomplete-chain confirmation")
	assert.Equal(t, "uploaded", got.Source)
	assert.Equal(t, 1, got.LocationCount, "the location still points at the certificate")

	// What a deployment of it to another server sends: the uploaded chain, no foreign certificate.
	web := nginxTarget(t, h, admin, "web-02")
	current := ca.Issue(www, h.clock.Now())
	_, err = h.svc.Reconcile(h.ctx, web.ID, providers.DiscoveryResult{WebServer: nginxOK, Certificates: []providers.DiscoveredCertificate{
		dc(cl("/etc/nginx/ssl/www.crt", "/etc/nginx/ssl/www.key", "www.example.test"), current)}})
	require.NoError(t, err)
	reqd, err := h.svc.RequestDeployment(h.ctx, admin, inventory.DeployRequestInput{CertificateID: c.ID,
		LocationIDs: []uuid.UUID{byPath(t, h, web.ID, false)["/etc/nginx/ssl/www.crt"].ID}, ConfirmIncompleteChain: true})
	require.NoError(t, err)
	m, err := h.svc.DeploymentMaterial(h.ctx, reqd[0].ID, false)
	require.NoError(t, err)
	assert.Equal(t, string(leaf.CertPEM), string(m.CertificatePEM))
	assert.NotContains(t, string(m.CertificatePEM), strings.TrimSpace(string(junk.CertPEM)))
}

// A certificate found only on servers is stored as the ordered path from the leaf the server
// serves: the file's other certificates and its order are not kept (B1-I1).
func TestDiscoveredCertificateStoresTheOrderedPathOnly(t *testing.T) {
	ca := pki.NewCA("Inv", pki.ECDSA256, start)
	roots := x509.NewCertPool()
	roots.AddCert(ca.Root)
	h := newHarness(t, withRoots(roots))
	web := nginxTarget(t, h, h.user("ada", rbac.Admin, ""), "web-01")
	leaf := ca.Issue(pki.Opts{CommonName: "www.example.test", SANs: []string{"www.example.test"}}, h.clock.Now())
	junk := pki.SelfSigned("attacker-chosen.example", pki.ECDSA256, h.clock.Now())
	file := append(append(append(append([]byte{}, leaf.CertPEM...), ca.RootPEM...), junk.CertPEM...), ca.IntermediatePEM...)
	_, err := h.svc.Reconcile(h.ctx, web.ID, providers.DiscoveryResult{WebServer: nginxOK, Certificates: []providers.DiscoveredCertificate{
		{Location: cl("/etc/nginx/ssl/www.crt", "/etc/nginx/ssl/www.key", "www.example.test"), PEMChain: file, FileSHA256: sha(file)}}})
	require.NoError(t, err)
	l := byPath(t, h, web.ID, false)["/etc/nginx/ssl/www.crt"]
	require.NotNil(t, l.Certificate)
	got, err := h.svc.GetCertificate(h.ctx, l.Certificate.ID)
	require.NoError(t, err)
	assert.Equal(t, string(leaf.CertPEM)+string(ca.IntermediatePEM)+string(ca.RootPEM), got.PEMChain)
	assert.True(t, got.ChainComplete)
	assert.Equal(t, sha(file), l.CertFileSHA256, "the location's compare-and-swap value is still the file's own hash")
}

// hugeRSACertificate is a certificate whose subject is its issuer and whose RSA key has a
// 753,664-bit modulus with the largest exponent (adapted from the independent audit of 2026-10-04,
// AUD-04): checking its self-signature used to cost about 22 s of CPU.
func hugeRSACertificate(t *testing.T, now time.Time) []byte {
	t.Helper()
	const modBytes = 92 << 10
	signer, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	name := pkix.Name{CommonName: "big.example.test"}
	n := make([]byte, modBytes)
	_, _ = rand.Read(n)
	n[0] |= 0x80
	n[len(n)-1] |= 1
	der, err := x509.CreateCertificate(rand.Reader, &x509.Certificate{SerialNumber: big.NewInt(1), Subject: name, NotBefore: now.Add(-time.Hour),
		NotAfter: now.Add(24 * time.Hour), DNSNames: []string{"big.example.test"}}, &x509.Certificate{SerialNumber: big.NewInt(2), Subject: name},
		&rsa.PublicKey{N: new(big.Int).SetBytes(n), E: 1<<31 - 1}, signer)
	require.NoError(t, err)
	c, err := x509.ParseCertificate(der)
	require.NoError(t, err)
	var outer struct {
		TBS asn1.RawValue
		Alg pkix.AlgorithmIdentifier
		Sig asn1.BitString
	}
	_, err = asn1.Unmarshal(der, &outer)
	require.NoError(t, err)
	sig := make([]byte, modBytes)
	_, _ = rand.Read(sig)
	sig[0] = 0
	out, err := asn1.Marshal(struct {
		TBS asn1.RawValue
		Alg pkix.AlgorithmIdentifier
		Sig asn1.BitString
	}{asn1.RawValue{FullBytes: c.RawTBSCertificate}, outer.Alg, asn1.BitString{Bytes: sig, BitLength: 8 * len(sig)}})
	require.NoError(t, err)
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: out})
}

// AUD-04(b): a certificate file with an oversized RSA key is refused at once (the location shows
// the file as not a certificate it can read), and certificate files are parsed before the scan's
// transaction: the target's row is not locked while they are.
func TestDiscoveryParsesFilesCheaplyAndOutsideTheTransaction(t *testing.T) {
	h := newHarness(t)
	web := nginxTarget(t, h, h.user("ada", rbac.Admin, ""), "web-01")
	huge := hugeRSACertificate(t, h.clock.Now())
	calls := 0
	restore := inventory.SetPrepareHook(func() {
		calls++
		// Another connection can take the target's row lock: no transaction of the scan holds it.
		tx, err := h.db.Owner.Begin(h.ctx)
		require.NoError(t, err)
		defer func() { _ = tx.Rollback(h.ctx) }()
		_, err = tx.Exec(h.ctx, "SELECT 1 FROM targets WHERE id = $1 FOR UPDATE NOWAIT", web.ID)
		require.NoError(t, err, "the scan parses certificate files under the target's row lock")
	})
	defer restore()
	started := time.Now()
	_, err := h.svc.Reconcile(h.ctx, web.ID, providers.DiscoveryResult{WebServer: nginxOK, Certificates: []providers.DiscoveredCertificate{
		{Location: cl("/etc/nginx/ssl/big.crt", "/etc/nginx/ssl/big.key", "big.example.test"), PEMChain: huge, FileSHA256: sha(huge)}}})
	require.NoError(t, err)
	assert.Less(t, time.Since(started), 3*time.Second)
	assert.Equal(t, 1, calls)
	l := byPath(t, h, web.ID, false)["/etc/nginx/ssl/big.crt"]
	assert.False(t, l.Supported)
	assert.Equal(t, providers.CertProblemNotACertificate, l.Problem)
	assert.Nil(t, l.Certificate)
	assert.Zero(t, h.count("SELECT count(*) FROM certificates"))
}

// B1 M1: a discovery run stores its scan only while it holds its job: a run that stalled past its
// lease (the job taken back and claimed again) writes nothing, so an old scan never lands after a
// newer one or after a deployment finished.
func TestReconcileIsFencedToTheDiscoveryJobsClaim(t *testing.T) {
	h := newHarness(t)
	h.jobs.next = jobs.NewQueue(jobs.QueueConfig{Pool: h.db.App, Keyring: h.keyring, Audit: h.audit, Clock: h.clock, Gate: h.lic})
	admin := h.user("ada", rbac.Admin, "")
	web := nginxTarget(t, h, admin, "web-01")
	job, err := h.svc.RequestDiscovery(h.ctx, admin, web.ID)
	require.NoError(t, err)
	_, err = h.db.Owner.Exec(h.ctx, "UPDATE jobs SET status = 'running', attempts = 2 WHERE id = $1", job)
	require.NoError(t, err)
	leaf := pki.NewCA("Inv", pki.ECDSA256, h.clock.Now()).Issue(pki.Opts{CommonName: "www.example.test", SANs: []string{"www.example.test"}}, h.clock.Now())
	res := providers.DiscoveryResult{WebServer: nginxOK, Certificates: []providers.DiscoveredCertificate{
		dc(cl("/etc/nginx/ssl/www.crt", "/etc/nginx/ssl/www.key", "www.example.test"), leaf)}}

	stale := inventory.WithClaim(h.ctx, inventory.Claim{JobID: job, Attempt: 1})
	_, err = h.svc.Reconcile(stale, web.ID, res)
	require.ErrorIs(t, err, inventory.ErrClaimLost)
	assert.Zero(t, h.count("SELECT count(*) FROM certificate_locations"), "the stale run wrote nothing")
	assert.Zero(t, h.audits("target.discovered"))

	live := inventory.WithClaim(h.ctx, inventory.Claim{JobID: job, Attempt: 2})
	_, err = h.svc.Reconcile(live, web.ID, res)
	require.NoError(t, err)
	assert.Equal(t, 1, h.count("SELECT count(*) FROM certificate_locations"))
}

// The changed-outside check through real scans (final review B1 M2, M3 and the Task 13 ledger
// item): after a scan that found the file missing, the certificate Alice deployed is the baseline;
// a rollback whose previous certificate is unknown flags nothing; and every deployment finished
// since the location's last scan counts, not only the latest.
func TestChangedOutsideBaselinesAndDeploymentsSinceTheLastScan(t *testing.T) {
	h := newHarness(t)
	web := nginxTarget(t, h, h.user("ada", rbac.Admin, ""), "web-01")
	ca := pki.NewCA("Inv", pki.ECDSA256, h.clock.Now())
	www := pki.Opts{CommonName: "www.example.test", SANs: []string{"www.example.test"}}
	w, x, y, z := ca.Issue(www, h.clock.Now()), ca.Issue(www, h.clock.Now()), ca.Issue(www, h.clock.Now()), ca.Issue(www, h.clock.Now())
	// scan reads the file at path (nil: missing) and reports whether this scan flagged a change
	// outside Alice (an earlier flag stays on the location until a deployment succeeds).
	scan := func(path string, leaf *pki.Leaf) bool {
		t.Helper()
		before := h.audits("location.changed_outside")
		h.clock.Advance(time.Minute)
		loc := cl(path, path+".key", "www.example.test")
		d := providers.DiscoveredCertificate{Location: loc}
		if leaf != nil {
			d = dc(loc, *leaf)
		} else {
			d.Location.Problem = providers.CertProblemMissing
		}
		_, err := h.svc.Reconcile(h.ctx, web.ID, providers.DiscoveryResult{WebServer: nginxOK, Certificates: []providers.DiscoveredCertificate{d}})
		require.NoError(t, err)
		return h.audits("location.changed_outside") > before
	}
	location := func(path string) inventory.CertificateLocation { return byPath(t, h, web.ID, true)[path] }
	certOf := func(l pki.Leaf) uuid.UUID {
		t.Helper()
		var id uuid.UUID
		require.NoError(t, h.db.Owner.QueryRow(h.ctx, "SELECT id FROM certificates WHERE fingerprint_sha256 = $1", pki.Fingerprint(l.Cert)).Scan(&id))
		return id
	}
	finishedWith := func(l inventory.CertificateLocation, cert pki.Leaf, status, prevFP, code string, sent bool) {
		t.Helper()
		h.clock.Advance(time.Second)
		var op *uuid.UUID
		id := uuid.Must(uuid.NewV7())
		if sent {
			op = &id
		}
		_, err := h.db.Owner.Exec(h.ctx, `INSERT INTO deployments (id, certificate_id, location_id, target_id, trigger, state, status,
new_fingerprint, previous_fingerprint, operation_id, cert_path, key_path, created_at, finished_at, error_code)
VALUES ($1, $2, $3, $4, 'manual', 'done', $5, $6, $7, $8, '/etc/nginx/ssl/d.crt', '/etc/nginx/ssl/d.key', $9, $9, $10)`, id, certOf(cert), l.ID, web.ID,
			status, pki.Fingerprint(cert.Cert), prevFP, op, h.clock.Now(), code)
		require.NoError(t, err)
	}
	finished := func(l inventory.CertificateLocation, cert pki.Leaf, status, prevFP string, sent bool) {
		t.Helper()
		finishedWith(l, cert, status, prevFP, "", sent)
	}

	// M2: Alice deployed X, a scan found the file missing, the next one finds Z.
	scan("/etc/nginx/ssl/m2.crt", &w)
	l := location("/etc/nginx/ssl/m2.crt")
	scan("/etc/nginx/ssl/x.crt", &x) // X is known
	finished(l, x, "succeeded", pki.Fingerprint(w.Cert), true)
	_, err := h.db.Owner.Exec(h.ctx, "UPDATE certificate_locations SET deployed_fingerprint = $2 WHERE id = $1", l.ID, pki.Fingerprint(x.Cert))
	require.NoError(t, err)
	assert.False(t, scan("/etc/nginx/ssl/m2.crt", nil))
	assert.True(t, scan("/etc/nginx/ssl/m2.crt", &z), "a foreign certificate after a scan that read none")

	// M3: a scan saw Y in flight; the deployment rolled back without a recorded previous certificate.
	scan("/etc/nginx/ssl/m3.crt", &w)
	l = location("/etc/nginx/ssl/m3.crt")
	scan("/etc/nginx/ssl/m3.crt", &y)
	finished(l, y, "rolled_back", "", true)
	assert.False(t, scan("/etc/nginx/ssl/m3.crt", &w), "the restored certificate was not recorded: not flagged")

	// Ledger: a scan saw Y in flight; that deployment rolled back to W, then a deployment of X failed
	// in its pre-check (nothing sent) before the next scan.
	scan("/etc/nginx/ssl/seq.crt", &w)
	l = location("/etc/nginx/ssl/seq.crt")
	scan("/etc/nginx/ssl/seq.crt", &y)
	finished(l, y, "rolled_back", pki.Fingerprint(w.Cert), true)
	finished(l, x, "failed", "", false)
	assert.False(t, scan("/etc/nginx/ssl/seq.crt", &w), "the rollback before the latest deployment still counts")
	assert.True(t, scan("/etc/nginx/ssl/seq.crt", &z))

	// W2 review, minor 3: a rollback_failed without a recorded previous certificate makes only the next
	// scan unknown; once a scan saw its effect, a foreign certificate is flagged again.
	scan("/etc/nginx/ssl/rf.crt", &w)
	l = location("/etc/nginx/ssl/rf.crt")
	finished(l, y, "rollback_failed", "", true)
	assert.False(t, scan("/etc/nginx/ssl/rf.crt", &x), "unknown right after the rollback_failed")
	assert.True(t, scan("/etc/nginx/ssl/rf.crt", &z), "a later foreign certificate is flagged")

	// An automatic restore of an unfinished earlier change (ALC-DEP-0024): a discovery saw the earlier
	// change's certificate Y; the new deployment of X put back W (from before Y) and ended
	// rolled_back pending_change_restored. The scan that sees W flags nothing; a later foreign one is.
	scan("/etc/nginx/ssl/pc.crt", &w)
	scan("/etc/nginx/ssl/pc.crt", &y)
	before := h.audits("location.changed_outside")
	l = location("/etc/nginx/ssl/pc.crt")
	_, err = h.db.Owner.Exec(h.ctx, "UPDATE certificate_locations SET changed_outside_at = NULL WHERE id = $1", l.ID)
	require.NoError(t, err)
	finishedWith(l, x, "rolled_back", pki.Fingerprint(y.Cert), "deployment.pending_change_restored", true)
	assert.False(t, scan("/etc/nginx/ssl/pc.crt", &w), "Alice's own restore is not a change outside Alice")
	assert.Nil(t, location("/etc/nginx/ssl/pc.crt").ChangedOutsideAt)
	assert.Equal(t, before, h.audits("location.changed_outside"))
	assert.True(t, scan("/etc/nginx/ssl/pc.crt", &z))
}

// B1 M4: boundParams bounds what PostgreSQL stores, which writes a space after every ':' and ','
// of the object: values whose Go encoding is just under the bound (every allowed key, values of
// quote characters, escaped as two bytes by both) fit the columns' CHECK as PostgreSQL renders them.
func TestBoundParamsFitPostgreSQLsRendering(t *testing.T) {
	h := newHarness(t)
	keys := []string{"port", "failed_step", "profile", "phase", "directory", "backup_dir", "expected", "actual", "mode", "helper_code", "subcommand"}
	in := map[string]string{}
	for _, k := range keys {
		in[k] = ""
	}
	size := func(m map[string]string) int {
		b, err := json.Marshal(m)
		require.NoError(t, err)
		return len(b)
	}
	// Fill the values until Go's encoding is 4095 bytes, at most 256 bytes per value.
	for _, k := range keys {
		for len(in[k]) < 256 && size(in) < 4094 {
			in[k] += `"`
		}
	}
	if size(in) < 4095 {
		in[keys[len(keys)-1]] += "a"
	}
	require.LessOrEqual(t, size(in), 4096, "Go's encoding alone fits the bound")
	require.Greater(t, size(in), 4096-2*len(keys))
	out := inventory.BoundParams(in)
	require.NotEmpty(t, out)
	raw, err := json.Marshal(out)
	require.NoError(t, err)
	var n int
	require.NoError(t, h.db.Owner.QueryRow(h.ctx, "SELECT octet_length($1::jsonb::text)", string(raw)).Scan(&n))
	assert.LessOrEqual(t, n, 4096, "PostgreSQL's rendering fits the CHECK")
}

// finishLocked writes phase and helper_error on every finish, whatever an earlier record left: the
// API's refineReason (ALC-DEP-0019/0020) and the web's rollback_failed headline read them as the
// final answer's, never a stale one (final review, area C).
func TestFinishOverwritesPhaseAndHelperError(t *testing.T) {
	f := newDeployFixture(t)
	for i, tc := range []struct {
		loc               uuid.UUID
		phase, helperErr  string
		wantPhase, wantHE string
	}{
		{f.loc1, "", "", "", ""},
		{f.loc2, providers.PhaseRestoreFailed, "", providers.PhaseRestoreFailed, ""},
		{f.loc5, "", providers.DeployErrFileChanged, "", providers.DeployErrFileChanged},
	} {
		id := f.deploying(tc.loc)
		// A stale value from an earlier answer (written as the owner: no engine path leaves one).
		_, err := f.h.db.Owner.Exec(f.h.ctx, "UPDATE deployments SET phase = 'restored', helper_error = 'syntax' WHERE id = $1", id)
		require.NoError(t, err)
		require.NoError(t, f.h.svc.FinishDeployment(f.h.ctx, id, inventory.DeploymentFinish{Status: inventory.DeployStatusRollbackFailed,
			ErrorCode: "deployment.rollback_failed", Phase: tc.phase, HelperError: tc.helperErr}))
		d := f.get(id)
		assert.Equal(t, tc.wantPhase, d.Phase, i)
		assert.Equal(t, tc.wantHE, d.HelperError, i)
	}
}

// B2-I1 (defence in depth): once an operation id is recorded (a send may have happened), a failed
// finish needs the caller's proof that nothing was written; without it nothing is recorded.
func TestFailedAfterASendNeedsProofThatNothingWasWritten(t *testing.T) {
	f := newDeployFixture(t)
	id := f.deploying(f.loc1)
	err := f.h.svc.FinishDeployment(f.h.ctx, id, inventory.DeploymentFinish{Status: inventory.DeployStatusFailed, ErrorCode: "deployment.interrupted"})
	require.ErrorIs(t, err, inventory.ErrDeploymentState)
	assert.Equal(t, inventory.DeployStateDeploying, f.get(id).State, "nothing recorded")
	require.ErrorIs(t, f.h.svc.RecordOutcome(f.h.ctx, id, inventory.OutcomeRecord{Terminal: true, Finish: inventory.DeploymentFinish{
		Status: inventory.DeployStatusFailed, ErrorCode: "deployment.interrupted"}}, time.Time{}), inventory.ErrDeploymentState)
	require.NoError(t, f.h.svc.FinishDeployment(f.h.ctx, id, inventory.DeploymentFinish{Status: inventory.DeployStatusFailed,
		ErrorCode: "deployment.interrupted", NothingWritten: true}))
	assert.Equal(t, inventory.DeployStatusFailed, f.get(id).Status)
	// Before a send no proof is needed.
	pre := f.request(f.admin, f.cert.ID, f.loc2)
	require.NoError(t, f.h.svc.FinishDeployment(f.h.ctx, pre, inventory.DeploymentFinish{Status: inventory.DeployStatusFailed, ErrorCode: "x.y"}))
}

// forgedIntermediate is a certificate with ca's intermediate subject and public key, issued by a root
// the server made up: the leaf verifies through it, and with the made-up root in the same file the
// server's chain looks complete.
func forgedIntermediate(t *testing.T, ca *pki.CA, now time.Time) (inter, root []byte) {
	t.Helper()
	fake := pki.NewCA("Forger", pki.ECDSA256, now)
	der, err := x509.CreateCertificate(rand.Reader, &x509.Certificate{SerialNumber: big.NewInt(77), Subject: ca.Intermediate.Subject,
		NotBefore: now.Add(-time.Hour), NotAfter: now.AddDate(1, 0, 0), IsCA: true, BasicConstraintsValid: true,
		KeyUsage: x509.KeyUsageCertSign}, fake.Root, ca.IntermediateKey.Public(), fake.RootKey)
	require.NoError(t, err)
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), fake.RootPEM
}

// W2 review, Important 1: attaching a key to a certificate first seen on a server takes the
// uploader's chain and completeness, never the server's (here a "complete" chain forged around the
// real intermediate's key); the benign case stores the upload's chain too.
func TestKeyAttachTakesTheUploadersChain(t *testing.T) {
	ca := pki.NewCA("Pub", pki.ECDSA256, start)
	roots := x509.NewCertPool()
	roots.AddCert(ca.Root)
	h := newHarness(t, withNginxProvider(), withRoots(roots))
	h.jobs.next = jobs.NewQueue(jobs.QueueConfig{Pool: h.db.App, Keyring: h.keyring, Audit: h.audit, Clock: h.clock, Gate: h.lic})
	admin := h.user("ada", rbac.Admin, "")
	www := pki.Opts{CommonName: "www.example.test", SANs: []string{"www.example.test"}}
	leaf, benign := ca.Issue(www, h.clock.Now()), ca.Issue(www, h.clock.Now())
	inter, fakeRoot := forgedIntermediate(t, ca, h.clock.Now())
	forged := append(append(append([]byte{}, leaf.CertPEM...), inter...), fakeRoot...)
	full := append(append([]byte{}, benign.FullchainPEM...), ca.RootPEM...)
	hostile := nginxTarget(t, h, admin, "web-hostile")
	_, err := h.svc.Reconcile(h.ctx, hostile.ID, providers.DiscoveryResult{WebServer: nginxOK, Certificates: []providers.DiscoveredCertificate{
		{Location: cl("/etc/nginx/ssl/x.crt", "/etc/nginx/ssl/x.key", "www.example.test"), PEMChain: forged, FileSHA256: sha(forged)},
		{Location: cl("/etc/nginx/ssl/b.crt", "/etc/nginx/ssl/b.key", "www.example.test"), PEMChain: full, FileSHA256: sha(full)}}})
	require.NoError(t, err)
	var before bool
	require.NoError(t, h.db.Owner.QueryRow(h.ctx, "SELECT chain_complete FROM certificates WHERE fingerprint_sha256 = $1",
		pki.Fingerprint(leaf.Cert)).Scan(&before))
	require.True(t, before, "the forged chain looks complete to a scan")

	c, warnings, err := h.svc.UploadCertificate(h.ctx, admin, inventory.UploadInput{CertificatePEM: string(leaf.CertPEM), PrivateKeyPEM: string(leaf.KeyPEM)})
	require.NoError(t, err)
	assert.Equal(t, []string{"chain_incomplete"}, warnings)
	assert.Equal(t, string(leaf.CertPEM), c.PEMChain, "the uploader's chain: the leaf alone")
	assert.False(t, c.ChainComplete)
	assert.Equal(t, "uploaded", c.Source)

	// A deployment to another server sends no certificate of the scanned server's file.
	web := nginxTarget(t, h, admin, "web-02")
	_, err = h.svc.Reconcile(h.ctx, web.ID, providers.DiscoveryResult{WebServer: nginxOK, Certificates: []providers.DiscoveredCertificate{
		dc(cl("/etc/nginx/ssl/www.crt", "/etc/nginx/ssl/www.key", "www.example.test"), ca.Issue(www, h.clock.Now()))}})
	require.NoError(t, err)
	reqd, err := h.svc.RequestDeployment(h.ctx, admin, inventory.DeployRequestInput{CertificateID: c.ID,
		LocationIDs: []uuid.UUID{byPath(t, h, web.ID, false)["/etc/nginx/ssl/www.crt"].ID}, ConfirmIncompleteChain: true})
	require.NoError(t, err)
	m, err := h.svc.DeploymentMaterial(h.ctx, reqd[0].ID, false)
	require.NoError(t, err)
	assert.Equal(t, string(leaf.CertPEM), string(m.CertificatePEM))

	// A later scan with the forged file changes nothing.
	_, err = h.svc.Reconcile(h.ctx, hostile.ID, providers.DiscoveryResult{WebServer: nginxOK, Certificates: []providers.DiscoveredCertificate{
		{Location: cl("/etc/nginx/ssl/x.crt", "/etc/nginx/ssl/x.key", "www.example.test"), PEMChain: forged, FileSHA256: sha(forged)}}})
	require.NoError(t, err)
	got, err := h.svc.GetCertificate(h.ctx, c.ID)
	require.NoError(t, err)
	assert.Equal(t, string(leaf.CertPEM), got.PEMChain)

	// Benign: the server's file had leaf, intermediate and root; the upload's leaf and intermediate are stored.
	b, warnings, err := h.svc.UploadCertificate(h.ctx, admin, pemUpload(benign))
	require.NoError(t, err)
	assert.Equal(t, []string{}, warnings)
	assert.Equal(t, string(benign.FullchainPEM), b.PEMChain)
	assert.True(t, b.ChainComplete)
}

// W2 review, minor 2: a file whose certificates cannot be ordered within the signature-check bound
// (32 CA certificates of one name with two alternating keys) keeps its leaf alone with the warning
// chain_unresolved; and the parsing stops when the scan's context ends.
func TestDiscoveryBoundsChainOrderingAndFollowsItsContext(t *testing.T) {
	h := newHarness(t)
	web := nginxTarget(t, h, h.user("ada", rbac.Admin, ""), "web-01")
	keys := []*ecdsa.PrivateKey{}
	for range 2 {
		k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		require.NoError(t, err)
		keys = append(keys, k)
	}
	name := pkix.Name{CommonName: "Same"}
	var file []byte
	for i := range 32 {
		der, err := x509.CreateCertificate(rand.Reader, &x509.Certificate{SerialNumber: big.NewInt(int64(i + 10)), Subject: name,
			DNSNames: []string{"www.example.test"}, NotBefore: h.clock.Now().Add(-time.Hour), NotAfter: h.clock.Now().Add(24 * time.Hour),
			IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}, &x509.Certificate{Subject: name}, keys[i%2].Public(), keys[(i+1)%2])
		require.NoError(t, err)
		file = append(file, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})...)
	}
	res := providers.DiscoveryResult{WebServer: nginxOK, Certificates: []providers.DiscoveredCertificate{
		{Location: cl("/etc/nginx/ssl/same.crt", "/etc/nginx/ssl/same.key", "www.example.test"), PEMChain: file, FileSHA256: sha(file)}}}

	gone, cancel := context.WithCancel(h.ctx)
	cancel()
	_, err := h.svc.Reconcile(gone, web.ID, res)
	require.ErrorIs(t, err, context.Canceled)
	assert.Zero(t, h.count("SELECT count(*) FROM certificate_locations"))

	_, err = h.svc.Reconcile(h.ctx, web.ID, res)
	require.NoError(t, err)
	l := byPath(t, h, web.ID, false)["/etc/nginx/ssl/same.crt"]
	assert.Contains(t, l.Warnings, inventory.WarnChainUnresolved)
	require.NotNil(t, l.Certificate)
	c, err := h.svc.GetCertificate(h.ctx, l.Certificate.ID)
	require.NoError(t, err)
	assert.Equal(t, 1, strings.Count(c.PEMChain, "BEGIN CERTIFICATE"), "the leaf alone")
	assert.False(t, c.ChainComplete)
}

// A deployment that ended rolled_back with deployment.pending_change_restored has its own email: the
// website went back to the certificate from before an unfinished earlier change (not "the server
// keeps its previous certificate"), with the earlier change's id (W1 re-review, Important 1).
func TestPendingChangeRestoredHasItsOwnEmail(t *testing.T) {
	f := newDeployFixture(t)
	id := f.deploying(f.loc1)
	op := uuid.New()
	require.NoError(t, f.h.svc.FinishDeployment(f.h.ctx, id, inventory.DeploymentFinish{Status: inventory.DeployStatusRolledBack,
		ErrorCode: "deployment.pending_change_restored", Phase: providers.PhaseRestored, FailedStep: "recover_pending",
		Params: map[string]string{"operation_id": op.String()}}))
	emails := f.emails()
	require.Len(t, emails, 1)
	assert.Equal(t, inventory.TemplateDeploymentPendingChangeRestored, emails[0].Template)
	assert.Equal(t, map[string]string{"target_name": "web-01", "cert_path": "/etc/nginx/ssl/www.crt", "deployment_id": id.String(),
		"operation_id": op.String()}, emails[0].Params)
	cat, err := i18n.Load(locales.FS)
	require.NoError(t, err)
	sender := &notify.Sender{Catalog: cat}
	for lang, want := range map[string][]string{
		"en": {"Alice put back the files from before that earlier change", "The certificate of this deployment was not written", "Discover"},
		"tr": {"Alice o önceki değişiklikten önceki dosyaları geri koydu", "Bu dağıtımın sertifikası yazılmadı", "Keşfet"},
	} {
		m := sender.Render("ada@example.com", emails[0].Template, lang, emails[0].Params)
		assert.NotContains(t, m.Subject+m.Body, "{{", lang)
		assert.NotContains(t, m.Body, "keeps its previous certificate", lang)
		assert.Contains(t, m.Body, op.String(), lang)
		assert.Contains(t, m.Body, id.String(), lang)
		for _, w := range want {
			assert.Contains(t, m.Body, w, lang)
		}
	}
}
