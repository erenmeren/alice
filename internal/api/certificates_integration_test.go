//go:build integration

package api

import (
	"encoding/base64"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"alice/internal/testutil/pki"
)

// Phase 4 API journeys (spec §26.5 owner steps 1-5, F-01..F-19): real services, real PostgreSQL,
// the real job runner and deploy engine, the nginx provider over the emulated Nginx host. Every
// step is an HTTP request of an Administrator or an Operator; the database is read only where the
// API does not expose a fact (audit rows, the outbox), and the emulated server is the customer's.

// Owner steps 1-3 and 5: prepare the server, add it, see its websites, upload a certificate,
// deploy it and see it served.
func TestNginxJourney(t *testing.T) {
	s, admin, adminAcct := installed(t)
	s.stepUp(admin, adminAcct)
	requireStatus(t, admin.do(http.MethodPatch, "/api/v1/users/"+adminAcct.id, map[string]string{"email": "ada@example.com"}), http.StatusOK)
	operator := s.createUser(admin, adminAcct, "otto", "operator", "operator-password-2026")
	oc := s.freshClient()
	s.firstSignIn(oc, operator)

	// Step 1: the preparation guide has a profile for Nginx servers with the five nginx-* commands.
	rec := admin.do(http.MethodGet, "/api/v1/ssh-keys/platform-key", nil)
	requireStatus(t, rec, http.StatusOK)
	profiles := decodeBody[platformKeyDTO](t, rec).Profiles
	require.Contains(t, profiles, "nginx")
	for _, sub := range []string{"nginx-dump", "nginx-test", "nginx-deploy", "nginx-restore", "nginx-status"} {
		assert.Contains(t, profiles["nginx"].Sudoers, sub)
		assert.Contains(t, profiles["nginx"].Script, sub)
	}

	// Step 2: add the server; nothing runs before the host key is confirmed.
	f := s.nginxFixture(wwwSite(), apiSite())
	rec = admin.do(http.MethodPost, "/api/v1/targets", map[string]any{"type": "nginx", "name": "web-01", "host": f.host, "port": f.port, "username": "alice-svc"})
	requireStatus(t, rec, http.StatusCreated)
	target := decodeBody[map[string]any](t, rec)["target"].(map[string]any)
	targetID := target["id"].(string)
	assert.Equal(t, "nginx", target["type"])
	s.pinServer(admin, targetID)

	tg := s.target(admin, targetID)
	nginxFacts := tg["facts"].(map[string]any)["nginx"].(map[string]any)
	assert.Equal(t, true, nginxFacts["config_valid"])
	assert.Equal(t, true, nginxFacts["found"])
	assert.Equal(t, "1.22.1", nginxFacts["version"])

	// Step 3: the scan lists both websites with the certificate they serve.
	locs := s.certificateLocations(admin, targetID, false)
	require.Len(t, locs, 2)
	www := s.location(admin, targetID, wwwCert)
	assert.Equal(t, true, www["supported"])
	assert.Equal(t, wwwKey, www["key_path"])
	cert := www["certificate"].(map[string]any)
	assert.Equal(t, pki.Fingerprint(f.old.Cert), cert["fingerprint"])
	assert.Equal(t, wwwName, cert["subject_cn"])
	assert.NotEmpty(t, cert["not_after"])
	assert.Equal(t, f.old.Cert.NotAfter.UTC().Format("2006-01-02T15:04:05Z"), cert["not_after"])
	assert.Equal(t, "", www["deployed_fingerprint"], "Alice has not deployed anything here yet")
	assert.Nil(t, www["changed_outside_at"])
	servers := www["servers"].([]any)
	require.Len(t, servers, 1)
	assert.Equal(t, []any{wwwName}, servers[0].(map[string]any)["names"])

	// Step 5: an Operator uploads the new certificate with its key and deploys it.
	leaf := s.issue()
	certID := s.uploadCertificate(oc, certBody(leaf, "Renewed"))
	detail := decodeBody[map[string]any](t, oc.do(http.MethodGet, "/api/v1/certificates/"+certID, nil))
	assert.Equal(t, true, detail["has_private_key"])
	assert.Equal(t, true, detail["chain_complete"])
	assert.Equal(t, "uploaded", detail["source"])
	wwwID := www["id"].(string)

	reloads := f.emu.Reloads()
	deps := s.deploy(oc, certID, wwwID)
	d := s.deployment(oc, deps[0].ID)
	assert.Equal(t, "queued", d.State, "accepted, not yet run")
	assert.Equal(t, "pending", d.Status)
	assert.Equal(t, wwwID, d.LocationID)
	assert.Equal(t, targetID, d.TargetID)
	s.runJobs()

	d = s.deployment(oc, deps[0].ID)
	assert.Equal(t, "done", d.State)
	assert.Equal(t, "succeeded", d.Status)
	assert.Equal(t, "remote", d.Verified)
	assert.Nil(t, d.Error)
	assert.Equal(t, []string{"verify_current:started", "verify_current:ok", "backup:ok", "write_key:ok", "write_cert:ok", "config_test:ok",
		"reload:ok", "verify:started", "verify:ok"}, d.stepList())
	assert.Equal(t, pki.Fingerprint(f.old.Cert), d.PreviousFingerprint)
	assert.Equal(t, pki.Fingerprint(leaf.Cert), d.NewFingerprint)
	assert.Equal(t, "succeeded", s.job(oc, deps[0].JobID)["status"])

	f.requirePair(t, wwwCert, wwwKey, wwwName, leaf)
	f.requirePair(t, apiCert, apiKey, apiName, f.old)
	assert.Equal(t, reloads+1, f.emu.Reloads())
	assert.Equal(t, 1, f.emu.DeployCount())

	www = s.location(admin, targetID, wwwCert)
	assert.Equal(t, pki.Fingerprint(leaf.Cert), www["deployed_fingerprint"])
	assert.Equal(t, pki.Fingerprint(leaf.Cert), www["certificate"].(map[string]any)["fingerprint"], "the location shows the deployed certificate")
	assert.Nil(t, www["active_deployment_id"])

	rec = admin.do(http.MethodGet, "/api/v1/deployments?target_id="+targetID, nil)
	requireStatus(t, rec, http.StatusOK)
	listed := decodeBody[struct {
		Items []depView `json:"items"`
	}](t, rec).Items
	require.Len(t, listed, 1)
	assert.Equal(t, deps[0].ID, listed[0].ID)
	assert.Equal(t, "succeeded", listed[0].Status)

	detail = decodeBody[map[string]any](t, admin.do(http.MethodGet, "/api/v1/certificates/"+certID, nil))
	require.Len(t, detail["locations"], 1, "the new certificate is now in use on one website")

	// A second discovery sees the file Alice wrote: no change outside Alice.
	s.discover(admin, targetID)
	www = s.location(admin, targetID, wwwCert)
	assert.Nil(t, www["changed_outside_at"])
	assert.Equal(t, pki.Fingerprint(leaf.Cert), www["certificate"].(map[string]any)["fingerprint"])
	assert.Zero(t, s.auditCount("location.changed_outside"))

	for _, a := range []string{"deployment.requested", "deployment.precheck_started", "deployment.started", "deployment.succeeded", "certificate.uploaded"} {
		assert.Equal(t, 1, s.auditCount(a), a)
	}
	assert.Empty(t, s.deploymentEmails(), "a success sends no email")
}

// An upload as PFX and a batch: one request for two websites of one server is one deployment per
// website, each with its own job, and both end succeeded.
func TestUploadVariantsAndBatchDeploy(t *testing.T) {
	n := newNJ(t, wwwSite(), apiSite())
	leaf := n.issue()
	pfx := pki.PFX(leaf, n.ca, "pfx-password-for-test")
	certID := n.uploadCertificate(n.op, map[string]any{"label": "From PFX", "pfx_base64": base64.StdEncoding.EncodeToString(pfx), "pfx_password": "pfx-password-for-test"})
	cert := decodeBody[map[string]any](t, n.op.do(http.MethodGet, "/api/v1/certificates/"+certID, nil))
	assert.Equal(t, true, cert["has_private_key"])
	assert.Equal(t, true, cert["chain_complete"])

	deps := n.deploy(n.op, certID, n.locs[wwwCert], n.locs[apiCert])
	assert.NotEqual(t, deps[0].JobID, deps[1].JobID, "one job per website")
	n.runJobs()
	for _, ref := range deps {
		d := n.deployment(n.op, ref.ID)
		assert.Equal(t, "succeeded", d.Status, ref.ID)
		assert.Equal(t, "remote", d.Verified)
	}
	n.f.requirePair(t, wwwCert, wwwKey, wwwName, leaf)
	n.f.requirePair(t, apiCert, apiKey, apiName, leaf)
	assert.Equal(t, 2, n.f.emu.DeployCount())
	assert.Empty(t, n.deploymentEmails())

	// A second discovery: both files are what Alice wrote.
	n.discover(n.admin, n.targetID)
	for _, p := range []string{wwwCert, apiCert} {
		assert.Nil(t, n.location(n.admin, n.targetID, p)["changed_outside_at"], p)
	}
	assert.Zero(t, n.auditCount("location.changed_outside"))
	assert.Equal(t, 2, n.countWhere("deployments", "status = 'succeeded'"))
}

// Owner step 1 as the scan shows it: websites Alice cannot manage are listed with the reason,
// and an invalid configuration is shown as such without forgetting the known locations.
func TestDiscoverShowsSupportAndInvalidConfiguration(t *testing.T) {
	s, admin, adminAcct := installed(t)
	f := s.nginxFixture(wwwSite())
	f.emu.AddUnsupported([]string{"vars.example.test"}, 443, "/etc/nginx/ssl/$host.crt", "variable")
	f.emu.AddUnsupported(nil, 8443, "/etc/nginx/ssl/stream.crt", "stream")
	f.emu.AddUnsupported([]string{"pw.example.test"}, 443, "/etc/nginx/ssl/pw.crt", "password_file")
	rec := admin.do(http.MethodPost, "/api/v1/targets", map[string]any{"type": "nginx", "name": "web-01", "host": f.host, "port": f.port, "username": "alice-svc"})
	requireStatus(t, rec, http.StatusCreated)
	targetID := decodeBody[map[string]any](t, rec)["target"].(map[string]any)["id"].(string)
	s.pinServer(admin, targetID)

	locs := s.certificateLocations(admin, targetID, false)
	require.Len(t, locs, 4)
	reasons := map[string]string{}
	for _, l := range locs {
		reasons[l["cert_path"].(string)] = l["unsupported_reason"].(string)
		assert.Equal(t, l["unsupported_reason"] == "", l["supported"], "supported follows the reason: %v", l["cert_path"])
	}
	assert.Equal(t, map[string]string{wwwCert: "", "/etc/nginx/ssl/$host.crt": "variable", "/etc/nginx/ssl/stream.crt": "stream",
		"/etc/nginx/ssl/pw.crt": "password_file"}, reasons)
	assert.Equal(t, true, s.location(admin, targetID, wwwCert)["supported"])
	var warned []string
	for _, w := range s.target(admin, targetID)["facts"].(map[string]any)["warnings"].([]any) {
		warned = append(warned, w.(map[string]any)["code"].(string))
	}
	assert.Contains(t, warned, "stream_tls", "a TLS server in a stream block is flagged")

	// The configuration breaks: the target shows it, the known locations stay (not "missing").
	f.emu.SetConfigInvalid("syntax")
	s.discover(admin, targetID)
	facts := s.target(admin, targetID)["facts"].(map[string]any)["nginx"].(map[string]any)
	assert.Equal(t, false, facts["config_valid"])
	assert.Equal(t, "syntax", facts["config_error"])
	assert.Len(t, s.certificateLocations(admin, targetID, false), 4, "an invalid configuration removes no known location")
	assert.Empty(t, withMissing(s.certificateLocations(admin, targetID, true)))

	// Nothing is deployed to a server whose configuration is invalid (before any change).
	certID := s.uploadCertificate(admin, certBody(s.issue(), "New"))
	requireError(t, s.requestDeploy(admin, certID, s.locationIDs(admin, targetID)[wwwCert]), http.StatusConflict, "ALC-NGX-0002")
	assert.Zero(t, f.emu.DeployCount())
	assert.Equal(t, 1, s.auditCount("deployment.denied"))

	// The configuration is valid again; a deleted server's locations are not listed on the
	// certificate any more.
	f.emu.SetConfigInvalid("")
	s.discover(admin, targetID)
	assert.Equal(t, true, s.target(admin, targetID)["facts"].(map[string]any)["nginx"].(map[string]any)["config_valid"])
	oldCertID := s.location(admin, targetID, wwwCert)["certificate"].(map[string]any)["id"].(string)
	before := decodeBody[map[string]any](t, admin.do(http.MethodGet, "/api/v1/certificates/"+oldCertID, nil))
	require.Len(t, before["locations"], 1)
	s.stepUp(admin, adminAcct)
	requireStatus(t, admin.do(http.MethodDelete, "/api/v1/targets/"+targetID, nil), http.StatusNoContent)
	after := decodeBody[map[string]any](t, admin.do(http.MethodGet, "/api/v1/certificates/"+oldCertID, nil))
	assert.Empty(t, after["locations"], "GET /certificates/{id} excludes the locations of a deleted server")
}

func withMissing(locs []map[string]any) []map[string]any {
	var out []map[string]any
	for _, l := range locs {
		if l["missing_since"] != nil {
			out = append(out, l)
		}
	}
	return out
}

// Review Focus 4, owner step 4: an upload that cannot be used is refused with a code and a text a
// person can act on (English and Turkish), and nothing is stored.
func TestUploadJourneyRefusesWithExactMessages(t *testing.T) {
	s, admin, _ := installed(t)
	now := s.clock.Now()
	good := s.issue(wwwName)
	other := s.issue(apiName)

	// The key of another certificate.
	broken := certBody(good, "Broken")
	broken["private_key_pem"] = string(other.KeyPEM)
	rec := admin.do(http.MethodPost, "/api/v1/certificates/upload", broken)
	requireError(t, rec, http.StatusUnprocessableEntity, "ALC-CRT-0002")
	msg := decodeBody[apiError](t, rec).Error.Message
	assert.Contains(t, msg, "The certificate does not match its private key.")
	assert.Contains(t, msg, "When uploading, use the key that was created together with this certificate.")
	rec = admin.do(http.MethodPost, "/api/v1/certificates/upload", broken, withHeader("Accept-Language", "tr"))
	requireError(t, rec, http.StatusUnprocessableEntity, "ALC-CRT-0002")
	msg = decodeBody[apiError](t, rec).Error.Message
	assert.Contains(t, msg, "Sertifika özel anahtarıyla eşleşmiyor.")
	assert.Contains(t, msg, "Yüklerken bu sertifikayla birlikte oluşturulan anahtarı kullanın.")

	// Expired, encrypted key, wrong PFX password, unreadable certificate.
	expired := s.ca.Issue(pki.Opts{CommonName: wwwName, SANs: []string{wwwName}, NotBefore: now.Add(-72 * time.Hour), NotAfter: now.Add(-time.Hour)}, now)
	requireError(t, admin.do(http.MethodPost, "/api/v1/certificates/upload", certBody(expired, "Old")), http.StatusUnprocessableEntity, "ALC-CRT-0003")
	encrypted := certBody(good, "Locked")
	encrypted["private_key_pem"] = string(pki.EncryptedKeyPEM(good))
	requireError(t, admin.do(http.MethodPost, "/api/v1/certificates/upload", encrypted), http.StatusUnprocessableEntity, "ALC-CRT-0004")
	pfx := base64.StdEncoding.EncodeToString(pki.PFX(good, s.ca, "right-password-for-pfx"))
	requireError(t, admin.do(http.MethodPost, "/api/v1/certificates/upload", map[string]any{"label": "P", "pfx_base64": pfx,
		"pfx_password": "wrong-password-for-pfx"}), http.StatusUnprocessableEntity, "ALC-CRT-0005")
	requireError(t, admin.do(http.MethodPost, "/api/v1/certificates/upload", map[string]any{"label": "X",
		"certificate_pem": "not a certificate", "private_key_pem": string(good.KeyPEM)}), http.StatusUnprocessableEntity, "ALC-CRT-0001")
	assert.Zero(t, s.count("certificates"), "nothing was stored")
	assert.Zero(t, s.count("managed_private_keys"), "no key was stored")
	assert.Equal(t, 6, s.auditCount("certificate.upload_rejected"), "every refusal is audited (the mismatch twice)")
	assert.Zero(t, s.auditCount("certificate.uploaded"))

	// A body over the cap is refused unread.
	requireError(t, admin.do(http.MethodPost, "/api/v1/certificates/upload", strings.Repeat("A", 2<<20)), http.StatusRequestEntityTooLarge, "ALC-SYS-0007")

	// A PEM saved on Windows (BOM, CRLF) is accepted.
	crlf := func(b []byte) string { return "\xef\xbb\xbf" + strings.ReplaceAll(string(b), "\n", "\r\n") }
	rec = admin.do(http.MethodPost, "/api/v1/certificates/upload", map[string]any{"label": "Windows",
		"certificate_pem": crlf(good.FullchainPEM), "private_key_pem": crlf(good.KeyPEM)})
	requireStatus(t, rec, http.StatusCreated)
	assert.Equal(t, 1, s.count("certificates"))
	assert.Equal(t, 1, s.count("managed_private_keys"))
	assert.Equal(t, 1, s.auditCount("certificate.uploaded"))

	// The same certificate again is a duplicate, not a second copy.
	requireError(t, admin.do(http.MethodPost, "/api/v1/certificates/upload", certBody(good, "Again")), http.StatusConflict, "ALC-CRT-0008")
	assert.Equal(t, 1, s.count("certificates"))
}
