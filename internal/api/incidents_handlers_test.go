package api

import (
	"context"
	"net/http"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"alice/internal/acme"
	"alice/internal/inventory"
)

var (
	incidentID = uuid.MustParse("0193a000-0000-7000-8000-0000000000a1")
	incCertID  = uuid.MustParse("0193a000-0000-7000-8000-0000000000a2")
)

// incidentDeps is the API with fake ACME and incident services.
func incidentDeps(t *testing.T) (http.Handler, *fakeACME, *fakeIncidents) {
	t.Helper()
	d := testDeps(t, nil)
	f, inc := &fakeACME{}, &fakeIncidents{}
	d.ACME, d.Incidents = f, inc
	srv := New(d)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		srv.ResetLimits()
		srv.Handler().ServeHTTP(w, r)
	}), f, inc
}

func sampleIncident() inventory.Incident {
	dep := uuid.New()
	acmeID := acmeCertID
	return inventory.Incident{ID: incidentID, CertificateID: incCertID, CertificateName: "www.example.com", Fingerprint: strings.Repeat("ab", 32),
		Source: "acme", PublicKeySHA256: strings.Repeat("cd", 32), ACMECertificateID: &acmeID, State: inventory.IncidentNeedsAttention,
		RevokeMode: inventory.IncidentRevokeAfterVerified, Revocation: inventory.IncidentRevocationPending,
		AttentionCode: inventory.IncidentCodeDeploymentsFailed, CreatedAt: acmeAt, UpdatedAt: acmeAt,
		Counts: map[string]int{"failed": 1, "verified": 1},
		Locations: []inventory.IncidentLocation{
			{LocationID: acmeLocID, TargetID: targetID, TargetName: "web-01", CertPath: "/etc/ssl/www.pem", Status: "failed",
				DeploymentID: &dep, ErrorCode: "deployment.reload_failed", Attempts: 1, UpdatedAt: acmeAt},
		}}
}

func TestRevokeACMEHandler(t *testing.T) {
	h, f, _ := incidentDeps(t)
	var got inventory.ACMERevokeInput
	now := acmeAt
	f.RevokeACMECertificateFn = func(_ context.Context, a inventory.Actor, id uuid.UUID, in inventory.ACMERevokeInput) (inventory.Certificate, error) {
		got = in
		assert.Equal(t, acmeCertID, id)
		return inventory.Certificate{ID: acmeLeafID, Source: "acme", HasPrivateKey: true, RevokedAt: &now, RevocationReason: in.Reason}, nil
	}
	target := "/api/v1/acme/certificates/" + acmeCertID.String() + "/revoke"
	rec := call(h, http.MethodPost, target, "admin-stepup", `{"reason":"keyCompromise","certificate_id":"`+acmeLeafID.String()+`"}`)
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	assert.Equal(t, "keyCompromise", got.Reason)
	require.NotNil(t, got.CertificateID)
	assert.Equal(t, acmeLeafID, *got.CertificateID)
	body := jsonObj(t, rec)
	assert.Equal(t, "keyCompromise", body["revocation_reason"])
	assert.NotContains(t, body["capabilities"], "revoke", "a revoked certificate cannot be revoked again")
	assert.NotContains(t, body["capabilities"], "deploy")

	// The current certificate when none is named; unknown keys and bad ids are refused before the service.
	rec = call(h, http.MethodPost, target, "admin-stepup", `{"reason":"superseded"}`)
	require.Equal(t, http.StatusOK, rec.Code)
	assert.Nil(t, got.CertificateID)
	rec = call(h, http.MethodPost, target, "admin-stepup", `{"reason":"superseded","extra":1}`)
	assert.Equal(t, http.StatusBadRequest, rec.Code)
	rec = call(h, http.MethodPost, target, "admin-stepup", `{"reason":"superseded","certificate_id":"nope"}`)
	assert.Equal(t, http.StatusUnprocessableEntity, rec.Code)

	// The CA's refusals map to their codes.
	for reason, code := range map[string]string{acme.ReasonRevokeUnsupported: "ALC-ACM-0038", acme.ReasonRevokeReasonRefused: "ALC-ACM-0039",
		acme.ReasonRevokeUnauthorized: "ALC-ACM-0040"} {
		f.RevokeACMECertificateFn = func(context.Context, inventory.Actor, uuid.UUID, inventory.ACMERevokeInput) (inventory.Certificate, error) {
			return inventory.Certificate{}, &inventory.ACMEError{Reason: reason}
		}
		rec = call(h, http.MethodPost, target, "admin-stepup", `{"reason":"keyCompromise"}`)
		c, _, _ := errorField(t, rec)
		assert.Equal(t, code, c, reason)
	}
	for err, code := range map[error]string{inventory.ErrCertificateRevoked: "ALC-CRT-0018", inventory.ErrNotACMEVersion: "ALC-ACM-0037"} {
		f.RevokeACMECertificateFn = func(context.Context, inventory.Actor, uuid.UUID, inventory.ACMERevokeInput) (inventory.Certificate, error) {
			return inventory.Certificate{}, err
		}
		rec = call(h, http.MethodPost, target, "admin-stepup", `{"reason":"keyCompromise"}`)
		c, _, _ := errorField(t, rec)
		assert.Equal(t, code, c)
	}
	// An Operator, a token and an Administrator without a fresh step-up never reach it.
	for _, who := range []string{"operator-stepup", "alice_operate_admin", "admin"} {
		rec = call(h, http.MethodPost, target, who, `{"reason":"keyCompromise"}`)
		assert.Equal(t, http.StatusForbidden, rec.Code, who)
	}
}

func TestCertificateCapabilitiesHandler(t *testing.T) {
	h, _, _ := incidentDeps(t)
	rec := call(h, http.MethodGet, "/api/v1/certificates/capabilities", "alice_read_auditor", "")
	require.Equal(t, http.StatusOK, rec.Code)
	body := jsonObj(t, rec)
	assert.Equal(t, []any{"discover", "obtain", "renew", "deploy", "verify", "revoke", "recovery"}, body["capabilities"])
	sources := body["sources"].([]any)
	require.Len(t, sources, 5)
	acmeRow := sources[0].(map[string]any)
	assert.Equal(t, "acme", acmeRow["source"])
	assert.Contains(t, acmeRow["capabilities"], "revoke")
	for _, s := range sources[1:] {
		assert.NotContains(t, s.(map[string]any)["capabilities"], "revoke", s)
	}
}

func TestCertificateImpactHandlerHidesTheNetworkMap(t *testing.T) {
	h, _, inc := incidentDeps(t)
	seen := time.Date(2026, 10, 19, 8, 0, 0, 0, time.UTC)
	inc.CertificateImpactFn = func(context.Context, uuid.UUID) (inventory.CertificateImpact, error) {
		return inventory.CertificateImpact{Certificate: inventory.Certificate{ID: incCertID, Source: "uploaded"},
			Locations: []inventory.ImpactLocation{{LocationID: acmeLocID, TargetID: targetID, TargetName: "web-01", CertPath: "/etc/ssl/www.pem",
				Match: inventory.ImpactMatchKey, Deployable: true}},
			Endpoints: []inventory.ImpactEndpoint{{EndpointID: uuid.New(), ScopeID: uuid.New(), ScopeName: "LAN", Address: netip.MustParseAddr("10.0.0.9"),
				Port: 443, State: "present", LastSeen: &seen, Match: inventory.ImpactMatchCertificate}}}, nil
	}
	target := "/api/v1/certificate-impact/" + incCertID.String()
	rec := call(h, http.MethodGet, target, "auditor", "")
	require.Equal(t, http.StatusOK, rec.Code)
	body := jsonObj(t, rec)
	assert.Len(t, body["endpoints"], 1, "a browser session reads the network map")
	assert.Equal(t, false, body["endpoints_hidden"])
	assert.Len(t, body["locations"], 1)
	rec = call(h, http.MethodGet, target, "alice_read_admin", "")
	require.Equal(t, http.StatusOK, rec.Code)
	body = jsonObj(t, rec)
	assert.Empty(t, body["endpoints"], "a read token never does (D7)")
	assert.Equal(t, true, body["endpoints_hidden"])
	assert.NotContains(t, rec.Body.String(), "10.0.0.9")
}

func TestIncidentHandlers(t *testing.T) {
	h, _, inc := incidentDeps(t)
	var mode string
	inc.StartIncidentFn = func(_ context.Context, _ inventory.Actor, id uuid.UUID, in inventory.IncidentInput) (inventory.Incident, error) {
		mode = in.RevokeMode
		assert.Equal(t, incCertID, id)
		return sampleIncident(), nil
	}
	start := "/api/v1/certificates/" + incCertID.String() + "/incidents"
	rec := call(h, http.MethodPost, start, "admin-stepup", "")
	require.Equal(t, http.StatusCreated, rec.Code, rec.Body.String())
	assert.Equal(t, "/api/v1/incidents/"+incidentID.String(), rec.Header().Get("Location"))
	assert.Empty(t, mode)
	body := jsonObj(t, rec)
	assert.Equal(t, "needs_attention", body["state"])
	assert.Equal(t, "ALC-INC-0010", body["attention"].(map[string]any)["code"])
	locs := body["locations"].([]any)
	require.Len(t, locs, 1)
	assert.Equal(t, "ALC-DEP-0006", locs[0].(map[string]any)["error"].(map[string]any)["code"], "a stored deployment reason keeps its code")
	rec = call(h, http.MethodPost, start, "admin-stepup", `{"revoke_mode":"now"}`)
	require.Equal(t, http.StatusCreated, rec.Code)
	assert.Equal(t, "now", mode)
	rec = call(h, http.MethodPost, start, "operator-stepup", "")
	assert.Equal(t, http.StatusForbidden, rec.Code)
	inc.StartIncidentFn = func(context.Context, inventory.Actor, uuid.UUID, inventory.IncidentInput) (inventory.Incident, error) {
		return inventory.Incident{}, inventory.ErrIncidentOpen
	}
	rec = call(h, http.MethodPost, start, "admin-stepup", "")
	c, _, _ := errorField(t, rec)
	assert.Equal(t, "ALC-INC-0001", c)

	// The list: query validation, then the incidents without their locations.
	var gotOpen bool
	var gotCert *uuid.UUID
	inc.ListIncidentsFn = func(_ context.Context, cert *uuid.UUID, open bool, _ int) ([]inventory.Incident, error) {
		gotOpen, gotCert = open, cert
		return []inventory.Incident{sampleIncident()}, nil
	}
	rec = call(h, http.MethodGet, "/api/v1/incidents?open=true&certificate_id="+incCertID.String(), "alice_read_auditor", "")
	require.Equal(t, http.StatusOK, rec.Code)
	assert.True(t, gotOpen)
	require.NotNil(t, gotCert)
	item := jsonObj(t, rec)["items"].([]any)[0].(map[string]any)
	assert.NotContains(t, item, "locations")
	for _, q := range []string{"open=yes", "limit=0", "limit=201", "certificate_id=x"} {
		rec = call(h, http.MethodGet, "/api/v1/incidents?"+q, "auditor", "")
		assert.Equal(t, http.StatusUnprocessableEntity, rec.Code, q)
	}

	// The actions.
	called := map[string]bool{}
	inc.RetryIncidentFn = func(context.Context, inventory.Actor, uuid.UUID) (inventory.Incident, error) {
		called["retry"] = true
		return sampleIncident(), nil
	}
	inc.RevokeIncidentNowFn = func(context.Context, inventory.Actor, uuid.UUID) (inventory.Incident, error) {
		called["revoke-now"] = true
		return sampleIncident(), nil
	}
	inc.CloseIncidentFn = func(context.Context, inventory.Actor, uuid.UUID) (inventory.Incident, error) {
		called["close"] = true
		return sampleIncident(), nil
	}
	var replacement uuid.UUID
	inc.ChooseIncidentReplacementFn = func(_ context.Context, _ inventory.Actor, _, cert uuid.UUID) (inventory.Incident, error) {
		replacement = cert
		return sampleIncident(), nil
	}
	base := "/api/v1/incidents/" + incidentID.String()
	for _, act := range []string{"retry", "revoke-now", "close"} {
		rec = call(h, http.MethodPost, base+"/"+act, "admin-stepup", "")
		require.Equal(t, http.StatusOK, rec.Code, act)
		assert.True(t, called[act], act)
		rec = call(h, http.MethodPost, base+"/"+act, "admin-stepup", `{"x":1}`)
		assert.Equal(t, http.StatusBadRequest, rec.Code, act)
	}
	rec = call(h, http.MethodPost, base+"/replacement", "admin-stepup", `{"certificate_id":"`+acmeLeafID.String()+`"}`)
	require.Equal(t, http.StatusOK, rec.Code)
	assert.Equal(t, acmeLeafID, replacement)
	rec = call(h, http.MethodPost, base+"/replacement", "admin-stepup", `{"certificate_id":""}`)
	assert.Equal(t, http.StatusUnprocessableEntity, rec.Code)
	inc.ChooseIncidentReplacementFn = func(context.Context, inventory.Actor, uuid.UUID, uuid.UUID) (inventory.Incident, error) {
		return inventory.Incident{}, inventory.ErrIncidentReplacement
	}
	rec = call(h, http.MethodPost, base+"/replacement", "admin-stepup", `{"certificate_id":"`+acmeLeafID.String()+`"}`)
	c, _, _ = errorField(t, rec)
	assert.Equal(t, "ALC-INC-0003", c)
	inc.GetIncidentFn = func(context.Context, uuid.UUID) (inventory.Incident, error) { return sampleIncident(), nil }
	rec = call(h, http.MethodGet, base, "alice_read_auditor", "")
	require.Equal(t, http.StatusOK, rec.Code)
	assert.Contains(t, jsonObj(t, rec), "locations")
}
