//go:build integration

package api

import (
	"net/http"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Role journeys for the Phase 4 routes: an Operator works with certificates but cannot change how a
// website is verified, an Auditor only reads, and an id of one kind never opens a record of another.

func ifMatchOf(version string) reqOpt { return withHeader("If-Match", `"`+version+`"`) }

func TestLocationSettingsAreAdminOnly(t *testing.T) {
	n := newNJ(t, wwwSite())
	loc := n.location(n.admin, n.targetID, wwwCert)
	id, version := loc["id"].(string), loc["version"].(float64)
	assert.Equal(t, float64(1), version)
	body := map[string]any{"verify_port": 8443, "verify_sni": wwwName}
	denied := n.auditCount("authz.denied")

	requireError(t, n.op.do(http.MethodPatch, "/api/v1/locations/"+id, body, ifMatchOf("1")), http.StatusForbidden, "ALC-AUTH-0002")
	assert.Equal(t, denied+1, n.auditCount("authz.denied"))
	assert.Equal(t, 1.0, n.location(n.admin, n.targetID, wwwCert)["version"], "nothing changed")
	assert.Zero(t, n.auditCount("location.updated"))

	n.stepUp(n.admin, n.adminAcct)
	rec := n.admin.do(http.MethodPatch, "/api/v1/locations/"+id, body, ifMatchOf("1"))
	requireStatus(t, rec, http.StatusOK)
	assert.Equal(t, `"2"`, rec.Header().Get("ETag"))
	updated := decodeBody[map[string]any](t, rec)
	assert.Equal(t, float64(8443), updated["verify_port"])
	assert.Equal(t, wwwName, updated["verify_sni"])
	assert.Equal(t, 1, n.auditCount("location.updated"))
	assert.Equal(t, "server_file", updated["kind"], "R59: a certificate file")
	assert.Nil(t, updated["locator"])
	assert.Equal(t, map[string]any{}, updated["details"])
	assert.Equal(t, "", updated["verify_address"])
	// A certificate file takes no probe address (R59 G4): refused, nothing changed.
	requireStatus(t, n.admin.do(http.MethodPatch, "/api/v1/locations/"+id, map[string]any{"verify_address": "10.0.0.9"}, ifMatchOf("2")),
		http.StatusUnprocessableEntity)
	assert.Equal(t, 2.0, n.location(n.admin, n.targetID, wwwCert)["version"])

	requireError(t, n.admin.do(http.MethodPatch, "/api/v1/locations/"+id, body, ifMatchOf("1")), http.StatusPreconditionFailed, "ALC-SYS-0008")
	requireError(t, n.admin.do(http.MethodPatch, "/api/v1/locations/"+id, body), http.StatusPreconditionFailed, "ALC-SYS-0008")
	assert.Equal(t, 1, n.auditCount("location.updated"))
}

func TestAuditorReadsOnly(t *testing.T) {
	n := newNJ(t, wwwSite())
	certID := n.uploadCertificate(n.op, certBody(n.issue(), "New"))
	ref := n.deploy(n.op, certID, n.locs[wwwCert])[0]
	n.runJobs()
	rec := n.op.do(http.MethodPost, "/api/v1/certificates/csr", map[string]any{"common_name": wwwName, "key_type": "ecdsa-p256"})
	requireStatus(t, rec, http.StatusCreated)
	csrID := decodeBody[csrView](t, rec).ID

	auditor := n.createUser(n.admin, n.adminAcct, "audrey", "auditor", "auditor-password-2026")
	ac := n.freshClient()
	n.firstSignIn(ac, auditor)
	for _, path := range []string{"/api/v1/certificates", "/api/v1/certificates/" + certID, "/api/v1/certificates/csr", "/api/v1/certificates/csr/" + csrID,
		"/api/v1/targets/" + n.targetID + "/certificate-locations", "/api/v1/deployments", "/api/v1/deployments/" + ref.ID,
		"/api/v1/deployments?target_id=" + n.targetID, "/api/v1/certificates?target_id=" + n.targetID} {
		requireStatus(t, ac.do(http.MethodGet, path, nil), http.StatusOK)
	}

	before := map[string]int{"certificates": n.count("certificates"), "managed_private_keys": n.count("managed_private_keys"),
		"deployments": n.count("deployments"), "jobs": n.count("jobs")}
	denied := n.auditCount("authz.denied")
	forbidden := []struct {
		method, path string
		body         any
	}{
		{http.MethodPost, "/api/v1/certificates/upload", certBody(n.issue(), "Nope")},
		{http.MethodPost, "/api/v1/certificates/csr", map[string]any{"common_name": wwwName, "key_type": "ecdsa-p256"}},
		{http.MethodPost, "/api/v1/certificates/csr/" + csrID + "/actions/cancel", nil},
		{http.MethodPost, "/api/v1/certificates/csr/" + csrID + "/actions/complete", map[string]any{"certificate_pem": "x"}},
		{http.MethodPost, "/api/v1/certificates/" + certID + "/deploy", map[string]any{"location_ids": []string{n.locs[wwwCert]}}},
	}
	for _, f := range forbidden {
		requireError(t, ac.do(f.method, f.path, f.body), http.StatusForbidden, "ALC-AUTH-0002")
	}
	requireError(t, ac.do(http.MethodPatch, "/api/v1/locations/"+n.locs[wwwCert], map[string]any{"skip_verify": true}, ifMatchOf("1")),
		http.StatusForbidden, "ALC-AUTH-0002")
	assert.Equal(t, denied+len(forbidden)+1, n.auditCount("authz.denied"))
	assert.Equal(t, before, map[string]int{"certificates": n.count("certificates"), "managed_private_keys": n.count("managed_private_keys"),
		"deployments": n.count("deployments"), "jobs": n.count("jobs")}, "an Auditor changes nothing")
}

// An id is only good for the kind of record it names: the id of a location, a certificate or a
// signing request never opens another kind, and an unknown id is the same 404.
func TestObjectIdsOfAnotherKindAre404(t *testing.T) {
	n := newNJ(t, wwwSite())
	certID := n.uploadCertificate(n.op, certBody(n.issue(), "New"))
	rec := n.op.do(http.MethodPost, "/api/v1/certificates/csr", map[string]any{"common_name": wwwName, "key_type": "ecdsa-p256"})
	requireStatus(t, rec, http.StatusCreated)
	csrID := decodeBody[csrView](t, rec).ID
	ref := n.deploy(n.op, certID, n.locs[wwwCert])[0]
	locID := n.locs[wwwCert]

	for _, p := range []string{
		"/api/v1/certificates/" + csrID, "/api/v1/certificates/" + ref.ID, "/api/v1/certificates/" + locID, "/api/v1/certificates/" + uuid.NewString(),
		"/api/v1/certificates/csr/" + certID, "/api/v1/certificates/csr/" + uuid.NewString(),
		"/api/v1/deployments/" + certID, "/api/v1/deployments/" + locID, "/api/v1/deployments/" + uuid.NewString(),
		"/api/v1/targets/" + locID + "/certificate-locations", "/api/v1/targets/" + uuid.NewString() + "/certificate-locations",
	} {
		requireError(t, n.op.do(http.MethodGet, p, nil), http.StatusNotFound, "ALC-SYS-0001")
	}
	requireError(t, n.admin.do(http.MethodPatch, "/api/v1/locations/"+n.targetID, map[string]any{"skip_verify": true}, ifMatchOf("1")),
		http.StatusNotFound, "ALC-SYS-0001")
	requireError(t, n.admin.do(http.MethodPatch, "/api/v1/locations/"+certID, map[string]any{"skip_verify": true}, ifMatchOf("1")),
		http.StatusNotFound, "ALC-SYS-0001")
	requireError(t, n.op.do(http.MethodPost, "/api/v1/certificates/"+csrID+"/deploy", map[string]any{"location_ids": []string{locID}}),
		http.StatusNotFound, "ALC-SYS-0001")
	requireError(t, n.op.do(http.MethodPost, "/api/v1/certificates/csr/"+certID+"/actions/cancel", nil), http.StatusNotFound, "ALC-SYS-0001")
	require.Equal(t, "queued", n.deployment(n.op, ref.ID).State, "nothing happened to the deployment")
}
