package api

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/csv"
	"encoding/json"
	"io"
	"net/http"
	"net/netip"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"alice/internal/audit"
	"alice/internal/discovery"
	"alice/internal/discovery/discoverysvc"
	"alice/internal/platform/csvx"
	"alice/internal/rbac"
	"alice/internal/reports"
)

var (
	dscScopeID = uuid.MustParse("0193d000-0000-7000-8000-000000000001")
	dscScanID  = uuid.MustParse("0193d000-0000-7000-8000-000000000002")
	dscEndID   = uuid.MustParse("0193d000-0000-7000-8000-000000000003")
	dscMgdID   = uuid.MustParse("0193d000-0000-7000-8000-000000000004")
	dscFP      = strings.Repeat("ab", 32)
)

// discoveryDeps is the API with a fake discovery service and fake reports; every request starts with fresh limiters.
func discoveryDeps(t *testing.T) (http.Handler, *fakeDiscovery, *fakeReports) {
	t.Helper()
	d := testDeps(t, nil)
	f, fr := &fakeDiscovery{}, &fakeReports{}
	d.Discovery, d.Reports = f, fr
	srv := New(d)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		srv.ResetLimits()
		srv.Handler().ServeHTTP(w, r)
	}), f, fr
}

func sampleScopeView() discoverysvc.ScopeView {
	scan := sampleScanView()
	scan.State, scan.ErrorCode = discovery.ScanCancelled, discovery.ReasonCancelled
	at := testNow
	return discoverysvc.ScopeView{ID: dscScopeID, Scope: discovery.Scope{Name: "Lab", Entries: []string{"10.0.1.0/24"}, Ports: []int{443},
		SNINames: []string{}, Exclusions: []string{}, Enabled: true, Schedule: discovery.Schedule{Hours: 6, WindowStart: "22:00", WindowEnd: "04:00",
			TimeZone: "UTC"}, RatePerSec: 20, Concurrency: 32}, Version: 3, CreatedBy: uuid.NullUUID{UUID: dscMgdID, Valid: true}, CreatedAt: testNow,
		UpdatedAt: testNow, LastScheduledAt: &at, LastScan: &scan}
}

func sampleScanView() discoverysvc.ScanView {
	return discoverysvc.ScanView{ID: dscScanID, ScopeID: dscScopeID, ScopeName: "Lab", Trigger: "manual", State: discovery.ScanQueued,
		RequestedBy: uuid.NullUUID{UUID: dscMgdID, Valid: true}, QueuedAt: testNow}
}

func sampleCertRow() discovery.CertificateRow {
	return discovery.CertificateRow{Fingerprint: dscFP, SubjectCN: "=cmd|' /C calc'!A0", SANs: []string{"a.example", "b.example"}, IssuerCN: "CA",
		NotBefore: testNow.AddDate(-1, 0, 0), NotAfter: testNow.AddDate(0, 0, 10), KeyAlgorithm: "ecdsa", Status: discovery.StatusManaged,
		ManagedID: uuid.NullUUID{UUID: dscMgdID, Valid: true}, Endpoints: 2, SeenOn: 3, FirstSeen: testNow, LastSeen: testNow}
}

func sampleEndpointRow() discovery.EndpointRow {
	return discovery.EndpointRow{ID: dscEndID, ScopeID: dscScopeID, Address: netip.MustParseAddr("10.0.1.7"), Port: 443, SNI: "a.example",
		Fingerprint: dscFP, PreviousFingerprints: []string{strings.Repeat("cd", 32)}, ChainLen: 2, TLSVersion: "TLS 1.3", Cipher: "TLS_AES_128_GCM_SHA256", State: "present", FirstSeen: testNow,
		LastScannedAt: testNow, TargetID: uuid.NullUUID{UUID: targetID, Valid: true}, TargetName: "web-01"}
}

var snakeKeyRE = regexp.MustCompile(`^[a-z][a-z0-9_]*$`)

// requireSnakeCase fails on any JSON object key of v that is not snake_case.
func requireSnakeCase(t *testing.T, v any, where string) {
	t.Helper()
	switch x := v.(type) {
	case map[string]any:
		for k, c := range x {
			assert.Regexp(t, snakeKeyRE, k, where)
			requireSnakeCase(t, c, where+"."+k)
		}
	case []any:
		for _, c := range x {
			requireSnakeCase(t, c, where)
		}
	}
}

func TestDiscoveryScopeHandlers(t *testing.T) {
	h, f, _ := discoveryDeps(t)
	var got discovery.Scope
	f.CreateScopeFn = func(_ context.Context, in discovery.Scope) (discoverysvc.ScopeView, error) {
		got = in
		return sampleScopeView(), nil
	}
	body := `{"name":"Lab","entries":["10.0.1.0/24","web.example"],"ports":[443,8443],"sni_names":["a.example"],"schedule_hours":6,` +
		`"window_start":"22:00","window_end":"04:00","window_tz":"Europe/Istanbul","rate_per_sec":10}`
	rec := call(h, http.MethodPost, "/api/v1/discovery/scopes", "admin-stepup", body)
	require.Equal(t, http.StatusCreated, rec.Code, rec.Body.String())
	assert.Equal(t, "/api/v1/discovery/scopes/"+dscScopeID.String(), rec.Header().Get("Location"))
	assert.Equal(t, `"3"`, rec.Header().Get("ETag"))
	assert.Equal(t, discovery.Scope{Name: "Lab", Entries: []string{"10.0.1.0/24", "web.example"}, Ports: []int{443, 8443}, SNINames: []string{"a.example"},
		Enabled: true, Schedule: discovery.Schedule{Hours: 6, WindowStart: "22:00", WindowEnd: "04:00", TimeZone: "Europe/Istanbul"}, RatePerSec: 10}, got,
		"enabled unless the body says otherwise; the validator decides everything else")
	assert.Equal(t, rbac.Admin, rbac.Role(f.lastActor().Role))
	assert.NotEqual(t, uuid.Nil, f.lastActor().UserID)
	assert.Equal(t, audit.ActorUser, f.lastActor().Audit.Type)
	v := jsonObj(t, rec)
	requireSnakeCase(t, v, "scope")
	assert.Equal(t, "Lab", v["name"])
	assert.EqualValues(t, 6, v["schedule_hours"])
	assert.Equal(t, "22:00", v["window_start"])
	assert.Nil(t, v["active_scan_id"])
	last := v["last_scan"].(map[string]any)
	assert.Equal(t, "ALC-DSC-0005", last["error_code"])
	assert.Equal(t, "discovery.scan_cancelled", last["error_reason"])

	// Strict keys; a validator refusal answers its DSC code with the field and index, never the value.
	rec = call(h, http.MethodPost, "/api/v1/discovery/scopes", "admin-stepup", `{"name":"x","entries":["10.0.0.1"],"ports":[443],"targets":["x"]}`)
	assert.Equal(t, http.StatusBadRequest, rec.Code)
	f.CreateScopeFn = func(context.Context, discovery.Scope) (discoverysvc.ScopeView, error) {
		return discoverysvc.ScopeView{}, &discovery.Error{Kind: discovery.ErrNotAllowed, Field: "entries", Index: 1, Value: "169.254.169.254"}
	}
	rec = call(h, http.MethodPost, "/api/v1/discovery/scopes", "admin-stepup", `{"name":"x","entries":["10.0.0.1","169.254.169.254"],"ports":[443]}`)
	assert.Equal(t, http.StatusUnprocessableEntity, rec.Code)
	e := jsonObj(t, rec)["error"].(map[string]any)
	assert.Equal(t, "ALC-DSC-0002", e["code"])
	assert.Equal(t, map[string]any{"field": "entries", "index": "1"}, e["params"])
	f.CreateScopeFn = func(context.Context, discovery.Scope) (discoverysvc.ScopeView, error) {
		return discoverysvc.ScopeView{}, &discoverysvc.NameUnresolvedError{Index: 0}
	}
	rec = call(h, http.MethodPost, "/api/v1/discovery/scopes", "admin-stepup", `{"name":"x","entries":["nowhere.example"],"ports":[443]}`)
	assert.Equal(t, "ALC-DSC-0010", decodeErr(t, rec).Error.Code)

	// Get, with its version; an id that is no UUID is the scope's 404.
	f.GetScopeFn = func(_ context.Context, id uuid.UUID) (discoverysvc.ScopeView, error) {
		assert.Equal(t, dscScopeID, id)
		return sampleScopeView(), nil
	}
	rec = call(h, http.MethodGet, "/api/v1/discovery/scopes/"+dscScopeID.String(), "auditor", "")
	require.Equal(t, http.StatusOK, rec.Code)
	assert.Equal(t, `"3"`, rec.Header().Get("ETag"))
	for _, m := range []string{http.MethodGet, http.MethodPatch, http.MethodDelete} {
		rec = call(h, m, "/api/v1/discovery/scopes/not-a-uuid", "admin-stepup", "{}")
		assert.Equal(t, "ALC-DSC-0008", decodeErr(t, rec).Error.Code, m)
	}
	rec = call(h, http.MethodPost, "/api/v1/discovery/scopes/not-a-uuid/scans", "operator", "")
	assert.Equal(t, "ALC-DSC-0008", decodeErr(t, rec).Error.Code)

	// Patch: If-Match is optional but must be one strong validator when sent; the schedule fields are one group.
	var patch discoverysvc.ScopePatch
	var version *int
	f.UpdateScopeFn = func(_ context.Context, _ uuid.UUID, v *int, p discoverysvc.ScopePatch) (discoverysvc.ScopeView, error) {
		patch, version = p, v
		return sampleScopeView(), nil
	}
	req := `{"enabled":false,"schedule_hours":12}`
	rec = callWith(h, http.MethodPatch, "/api/v1/discovery/scopes/"+dscScopeID.String(), "admin-stepup", req, map[string]string{"If-Match": `"3"`})
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	require.NotNil(t, version)
	assert.Equal(t, 3, *version)
	require.NotNil(t, patch.Enabled)
	assert.False(t, *patch.Enabled)
	assert.Equal(t, &discovery.Schedule{Hours: 12}, patch.Schedule, "any schedule field replaces the whole schedule")
	assert.Nil(t, patch.Name)
	rec = callWith(h, http.MethodPatch, "/api/v1/discovery/scopes/"+dscScopeID.String(), "admin-stepup", req, map[string]string{"If-Match": `W/"3"`})
	assert.Equal(t, http.StatusPreconditionFailed, rec.Code)
	rec = call(h, http.MethodPatch, "/api/v1/discovery/scopes/"+dscScopeID.String(), "admin-stepup", `{"name":"y"}`)
	require.Equal(t, http.StatusOK, rec.Code)
	assert.Nil(t, version)
	assert.Nil(t, patch.Schedule)
	f.UpdateScopeFn = func(context.Context, uuid.UUID, *int, discoverysvc.ScopePatch) (discoverysvc.ScopeView, error) {
		return discoverysvc.ScopeView{}, discoverysvc.ErrVersion
	}
	rec = call(h, http.MethodPatch, "/api/v1/discovery/scopes/"+dscScopeID.String(), "admin-stepup", `{"name":"y"}`)
	assert.Equal(t, http.StatusPreconditionFailed, rec.Code)

	// An empty change is refused before the service (Task 9 review 8).
	f.UpdateScopeFn = func(context.Context, uuid.UUID, *int, discoverysvc.ScopePatch) (discoverysvc.ScopeView, error) {
		t.Fatal("an empty change reached the service")
		return discoverysvc.ScopeView{}, nil
	}
	rec = call(h, http.MethodPatch, "/api/v1/discovery/scopes/"+dscScopeID.String(), "admin-stepup", `{}`)
	assert.Equal(t, http.StatusUnprocessableEntity, rec.Code)
	_, _, details := errorField(t, rec)
	assert.Equal(t, []string{"body"}, detailFields(details))

	// Delete.
	f.DeleteScopeFn = func(_ context.Context, id uuid.UUID, v *int) error {
		assert.Equal(t, dscScopeID, id)
		version = v
		return nil
	}
	rec = call(h, http.MethodDelete, "/api/v1/discovery/scopes/"+dscScopeID.String(), "admin-stepup", "")
	assert.Equal(t, http.StatusNoContent, rec.Code)
	rec = callWith(h, http.MethodDelete, "/api/v1/discovery/scopes/"+dscScopeID.String(), "admin-stepup", "", map[string]string{"If-Match": "*"})
	assert.Equal(t, http.StatusPreconditionFailed, rec.Code)

	// The list pages with a cursor of its own.
	var filter discoverysvc.ScopeFilter
	f.ListScopesFn = func(_ context.Context, fl discoverysvc.ScopeFilter) ([]discoverysvc.ScopeView, bool, error) {
		filter = fl
		return []discoverysvc.ScopeView{sampleScopeView()}, true, nil
	}
	rec = call(h, http.MethodGet, "/api/v1/discovery/scopes?limit=1", "operator", "")
	require.Equal(t, http.StatusOK, rec.Code)
	next := jsonObj(t, rec)["next_cursor"].(string)
	rec = call(h, http.MethodGet, "/api/v1/discovery/scopes?cursor="+next, "operator", "")
	require.Equal(t, http.StatusOK, rec.Code)
	require.NotNil(t, filter.After)
	assert.Equal(t, discoverysvc.ScopeCursor{CreatedAt: testNow, ID: dscScopeID}, *filter.After)
	rec = call(h, http.MethodGet, "/api/v1/discovery/scopes?cursor=nope", "operator", "")
	assert.Equal(t, http.StatusUnprocessableEntity, rec.Code)
}

// The preview never stores or resolves: it answers the sizes and the built-in exclusions the ranges overlap; a body
// without a name is previewed under a placeholder.
func TestDiscoveryPreviewHandler(t *testing.T) {
	h, f, _ := discoveryDeps(t)
	var got discovery.Scope
	f.PreviewFn = func(_ context.Context, sc discovery.Scope) (discovery.Preview, error) {
		got = sc
		return discovery.Preview{Addresses: 1024, ExcludedAddresses: 4, Hostnames: 1, Ports: 2, SNINames: 0, Endpoints: 2050,
			BuiltinExclusions: []netip.Prefix{netip.MustParsePrefix("192.0.0.0/24")}}, nil
	}
	rec := call(h, http.MethodPost, "/api/v1/discovery/scopes/preview", "admin-stepup", `{"entries":["192.0.0.0/22","web.example"],"ports":[443,8443]}`)
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	assert.Equal(t, "preview", got.Name)
	v := jsonObj(t, rec)
	requireSnakeCase(t, v, "preview")
	assert.Equal(t, map[string]any{"addresses": 1024.0, "excluded_addresses": 4.0, "hostnames": 1.0, "ports": 2.0, "sni_names": 0.0,
		"endpoints": 2050.0, "builtin_exclusions": []any{"192.0.0.0/24"}}, v)
	assert.Zero(t, f.CreateScopeFn, "nothing is stored")
}

func TestDiscoveryScanHandlers(t *testing.T) {
	h, f, _ := discoveryDeps(t)
	f.StartScanFn = func(_ context.Context, id uuid.UUID) (discoverysvc.ScanView, error) {
		assert.Equal(t, dscScopeID, id)
		return sampleScanView(), nil
	}
	rec := call(h, http.MethodPost, "/api/v1/discovery/scopes/"+dscScopeID.String()+"/scans", "operator", "")
	require.Equal(t, http.StatusAccepted, rec.Code, rec.Body.String())
	assert.Equal(t, "/api/v1/discovery/scans/"+dscScanID.String(), rec.Header().Get("Location"))
	v := jsonObj(t, rec)
	requireSnakeCase(t, v, "scan")
	assert.Equal(t, "queued", v["state"])
	assert.Nil(t, v["error_code"])
	assert.Equal(t, rbac.Operator, rbac.Role(f.lastActor().Role))
	for _, tc := range []struct {
		err  error
		code string
	}{{discovery.ErrScanRunning, "ALC-DSC-0004"}, {discoverysvc.ErrTooManyScans, "ALC-DSC-0007"}, {discovery.ErrScopeNotFound, "ALC-DSC-0008"},
		{discoverysvc.ErrScopeDisabled, "ALC-DSC-0013"}} {
		f.StartScanFn = func(context.Context, uuid.UUID) (discoverysvc.ScanView, error) {
			return discoverysvc.ScanView{}, tc.err
		}
		rec = call(h, http.MethodPost, "/api/v1/discovery/scopes/"+dscScopeID.String()+"/scans", "operator", "")
		assert.Equal(t, tc.code, decodeErr(t, rec).Error.Code)
	}

	f.CancelScanFn = func(_ context.Context, id uuid.UUID) (discoverysvc.ScanView, error) {
		v := sampleScanView()
		v.CancelRequested = true
		return v, nil
	}
	rec = call(h, http.MethodPost, "/api/v1/discovery/scans/"+dscScanID.String()+"/cancel", "alice_operate_operator", "")
	require.Equal(t, http.StatusOK, rec.Code)
	assert.Equal(t, true, jsonObj(t, rec)["cancel_requested"])
	rec = call(h, http.MethodPost, "/api/v1/discovery/scans/nope/cancel", "operator", "")
	assert.Equal(t, http.StatusNotFound, rec.Code)

	f.GetScanFn = func(context.Context, uuid.UUID) (discoverysvc.ScanView, error) {
		return discoverysvc.ScanView{}, discoverysvc.ErrNotFound
	}
	rec = call(h, http.MethodGet, "/api/v1/discovery/scans/"+dscScanID.String(), "auditor", "")
	assert.Equal(t, http.StatusNotFound, rec.Code)
	rec = call(h, http.MethodGet, "/api/v1/discovery/scans/nope", "auditor", "")
	assert.Equal(t, http.StatusNotFound, rec.Code)

	var filter discoverysvc.ScanFilter
	f.ListScansFn = func(_ context.Context, fl discoverysvc.ScanFilter) ([]discoverysvc.ScanView, bool, error) {
		filter = fl
		return []discoverysvc.ScanView{sampleScanView()}, true, nil
	}
	rec = call(h, http.MethodGet, "/api/v1/discovery/scans?scope_id="+dscScopeID.String()+"&state=done&limit=1", "auditor", "")
	require.Equal(t, http.StatusOK, rec.Code)
	assert.Equal(t, discoverysvc.ScanFilter{ScopeID: dscScopeID, State: "done", Limit: 1}, filter)
	next := jsonObj(t, rec)["next_cursor"].(string)
	rec = call(h, http.MethodGet, "/api/v1/discovery/scans?cursor="+next, "auditor", "")
	require.Equal(t, http.StatusOK, rec.Code)
	assert.Equal(t, &discoverysvc.ScanCursor{QueuedAt: testNow, ID: dscScanID}, filter.After)
	for _, q := range []string{"state=paused", "scope_id=x", "limit=0", "cursor=1.x"} {
		rec = call(h, http.MethodGet, "/api/v1/discovery/scans?"+q, "auditor", "")
		assert.Equal(t, http.StatusUnprocessableEntity, rec.Code, q)
	}
}

func TestDiscoveryCertificateAndEndpointHandlers(t *testing.T) {
	h, f, _ := discoveryDeps(t)
	var filter discovery.CertificateFilter
	f.ListCertificatesFn = func(_ context.Context, fl discovery.CertificateFilter) ([]discovery.CertificateRow, bool, error) {
		filter = fl
		return []discovery.CertificateRow{sampleCertRow()}, true, nil
	}
	rec := call(h, http.MethodGet, "/api/v1/discovery/certificates?status=unmanaged&expiring_within_days=30&expired=false&self_signed=true&current=true&q=%20Shop%20&scope_id="+
		dscScopeID.String(), "auditor", "")
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	no, yes := false, true
	assert.Equal(t, discovery.CertificateFilter{Status: "unmanaged", ScopeID: dscScopeID, Query: "Shop", Expired: &no, SelfSigned: &yes, Current: true,
		ExpiringBy: testNow.AddDate(0, 0, 30), Now: testNow, Limit: 50}, filter)
	body := jsonObj(t, rec)
	requireSnakeCase(t, body, "certificates")
	item := body["items"].([]any)[0].(map[string]any)
	assert.Equal(t, dscFP, item["fingerprint_sha256"])
	assert.EqualValues(t, 10, item["days_left"])
	assert.Equal(t, false, item["expired"])
	assert.Equal(t, "managed", item["status"])
	assert.Equal(t, dscMgdID.String(), item["managed_certificate_id"])
	assert.EqualValues(t, 2, item["endpoint_count"])
	assert.NotContains(t, item, "endpoints", "the list carries no endpoint list")
	next := body["next_cursor"].(string)
	rec = call(h, http.MethodGet, "/api/v1/discovery/certificates?status=all&cursor="+next, "auditor", "")
	require.Equal(t, http.StatusOK, rec.Code)
	assert.Equal(t, "", filter.Status, "all is every status")
	assert.False(t, filter.Current, "without current every leaf is listed, those no longer found too")
	assert.Equal(t, &discovery.CertificateCursor{NotAfter: testNow.AddDate(0, 0, 10), Fingerprint: dscFP}, filter.After)
	rec = call(h, http.MethodGet, "/api/v1/discovery/certificates?current=false", "auditor", "")
	require.Equal(t, http.StatusOK, rec.Code)
	assert.False(t, filter.Current)
	for _, q := range []string{"status=gone", "expiring_within_days=0", "expiring_within_days=3651", "expired=maybe", "self_signed=1", "current=yes",
		"q=" + strings.Repeat("x", 201), "cursor=" + strings.Repeat("1", 600), "cursor=12.zz", "scope_id=nope",
		"cursor=9223372036854775807." + dscFP, "cursor=-9223372036854775808." + dscFP, "cursor=253402300800000000." + dscFP} {
		rec = call(h, http.MethodGet, "/api/v1/discovery/certificates?"+q, "auditor", "")
		assert.Equal(t, http.StatusUnprocessableEntity, rec.Code, q)
	}

	f.CertificateFn = func(_ context.Context, fp string) (discovery.CertificateRow, []discovery.EndpointRow, bool, error) {
		assert.Equal(t, dscFP, fp)
		return sampleCertRow(), []discovery.EndpointRow{sampleEndpointRow()}, false, nil
	}
	rec = call(h, http.MethodGet, "/api/v1/discovery/certificates/"+dscFP, "alice_operate_admin", "")
	require.Equal(t, http.StatusOK, rec.Code)
	d := jsonObj(t, rec)
	requireSnakeCase(t, d, "certificate")
	eps := d["endpoints"].([]any)
	require.Len(t, eps, 1)
	ep := eps[0].(map[string]any)
	assert.Equal(t, "10.0.1.7", ep["address"])
	assert.Equal(t, map[string]any{"id": targetID.String(), "name": "web-01"}, ep["target"])
	assert.Equal(t, []any{strings.Repeat("cd", 32)}, ep["previous_fingerprints"], "the rotation ring, newest first")
	assert.Equal(t, false, d["more_endpoints"])
	for _, bad := range []string{strings.Repeat("AB", 32), "abc", dscFP + "00"} {
		rec = call(h, http.MethodGet, "/api/v1/discovery/certificates/"+bad, "auditor", "")
		assert.Equal(t, http.StatusNotFound, rec.Code, bad)
	}

	var ef discovery.EndpointFilter
	f.ListEndpointsFn = func(_ context.Context, fl discovery.EndpointFilter) ([]discovery.EndpointRow, bool, error) {
		ef = fl
		e := sampleEndpointRow()
		e.Fingerprint, e.TargetID, e.PreviousFingerprints = "", uuid.NullUUID{}, nil
		return []discovery.EndpointRow{e}, true, nil
	}
	rec = call(h, http.MethodGet, "/api/v1/discovery/endpoints?scope_id="+dscScopeID.String()+"&fingerprint="+dscFP, "operator", "")
	require.Equal(t, http.StatusOK, rec.Code)
	assert.Equal(t, discovery.EndpointFilter{ScopeID: dscScopeID, Fingerprint: dscFP, Limit: 50}, ef)
	body = jsonObj(t, rec)
	requireSnakeCase(t, body, "endpoints")
	item = body["items"].([]any)[0].(map[string]any)
	assert.Nil(t, item["target"])
	assert.Nil(t, item["fingerprint_sha256"])
	assert.Equal(t, []any{}, item["previous_fingerprints"], "an empty ring is [], never null")
	rec = call(h, http.MethodGet, "/api/v1/discovery/endpoints?cursor="+body["next_cursor"].(string), "operator", "")
	require.Equal(t, http.StatusOK, rec.Code)
	assert.Equal(t, &discovery.EndpointCursor{Address: netip.MustParseAddr("10.0.1.7"), Port: 443, SNI: "a.example", ID: dscEndID}, ef.After)
	for _, q := range []string{"fingerprint=xyz", "cursor=!!!", "cursor=" + b64("10.0.0.1|0|a|"+dscEndID.String()), "cursor=" + b64("x|443||"+dscEndID.String()),
		"cursor=" + b64("10.0.0.1|443|A.example|"+dscEndID.String()), "cursor=" + b64("10.0.0.1|443"), "cursor=" + b64("fe80::1%eth0|443||"+dscEndID.String())} {
		rec = call(h, http.MethodGet, "/api/v1/discovery/endpoints?"+q, "operator", "")
		assert.Equal(t, http.StatusUnprocessableEntity, rec.Code, q)
	}
}

func b64(s string) string { return base64.RawURLEncoding.EncodeToString([]byte(s)) }

// The export runs through the report machinery (reports.ExportRows): the filters as audit details, the action
// discovery.export, the list paged through its own cursor, cells through csvx (a formula CN is neutralised).
func TestDiscoveryExportHandler(t *testing.T) {
	h, f, fr := discoveryDeps(t)
	calls := 0
	f.ListCertificatesFn = func(_ context.Context, fl discovery.CertificateFilter) ([]discovery.CertificateRow, bool, error) {
		calls++
		assert.Equal(t, 200, fl.Limit)
		assert.Equal(t, "unmanaged", fl.Status)
		assert.True(t, fl.Current, "the export takes the list's current filter")
		if fl.After == nil {
			return []discovery.CertificateRow{sampleCertRow()}, true, nil
		}
		c := sampleCertRow()
		c.Fingerprint, c.SubjectCN, c.ManagedID = strings.Repeat("cd", 32), "plain", uuid.NullUUID{}
		return []discovery.CertificateRow{c}, false, nil
	}
	var export reports.RowExport
	fr.ExportRowsFn = func(ctx context.Context, a audit.Actor, x reports.RowExport, w io.Writer) (int, error) {
		export = x
		assert.Equal(t, "auditor", a.Name)
		cw, err := csvx.NewWriter(w)
		require.NoError(t, err)
		require.NoError(t, cw.Write(x.Header))
		n := 0
		for cursor := ""; ; {
			rows, next, err := x.Page(ctx, cursor)
			if err != nil {
				return n, err
			}
			for _, r := range rows {
				require.NoError(t, cw.Write(r))
				n++
			}
			if next == "" {
				break
			}
			cursor = next
		}
		return n, cw.Flush()
	}
	rec := call(h, http.MethodGet, "/api/v1/discovery/certificates/export?status=unmanaged&q=shop&current=true", "auditor", "")
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	assert.Equal(t, "text/csv; charset=utf-8", rec.Header().Get("Content-Type"))
	assert.Equal(t, `attachment; filename="alice-discovered-certificates-2026-09-30.csv"`, rec.Header().Get("Content-Disposition"))
	assert.Equal(t, "discovery.export", export.Action)
	assert.Equal(t, map[string]string{"kind": "discovery_certificates", "format": "csv", "status": "unmanaged", "q": "shop", "current": "true"}, export.Details)
	rows, err := csv.NewReader(bytes.NewReader(bytes.TrimPrefix(rec.Body.Bytes(), []byte("\xEF\xBB\xBF")))).ReadAll()
	require.NoError(t, err)
	require.Len(t, rows, 3)
	assert.Equal(t, discoveryExportColumns, rows[0])
	assert.Equal(t, "'=cmd|' /C calc'!A0", rows[1][1], "csvx neutralises the formula")
	assert.Equal(t, "a.example b.example", rows[1][2])
	assert.Equal(t, dscMgdID.String(), rows[1][10])
	assert.Equal(t, "", rows[2][10])
	assert.Equal(t, 2, calls)

	for _, q := range []string{"cursor=x", "limit=5", "status=nope"} {
		rec = call(h, http.MethodGet, "/api/v1/discovery/certificates/export?"+q, "auditor", "")
		assert.Equal(t, http.StatusUnprocessableEntity, rec.Code, q)
	}
	rec = call(h, http.MethodHead, "/api/v1/discovery/certificates/export", "auditor", "")
	assert.Equal(t, http.StatusMethodNotAllowed, rec.Code, "HEAD never runs an audited export")
	fr.ExportRowsFn = func(context.Context, audit.Actor, reports.RowExport, io.Writer) (int, error) {
		return 0, reports.ErrExportBusy
	}
	rec = call(h, http.MethodGet, "/api/v1/discovery/certificates/export", "auditor", "")
	assert.Equal(t, "ALC-RPT-0004", decodeErr(t, rec).Error.Code, "one export at a time, as the report export")
	assert.Equal(t, "5", rec.Header().Get("Retry-After"))
	// A failing page after the first byte aborts (the export machinery returns the error).
	f.ListCertificatesFn = func(context.Context, discovery.CertificateFilter) ([]discovery.CertificateRow, bool, error) {
		return nil, false, errNotConfigured
	}
	fr.ExportRowsFn = func(ctx context.Context, _ audit.Actor, x reports.RowExport, w io.Writer) (int, error) {
		_, _, err := x.Page(ctx, "")
		return 0, err
	}
	rec = call(h, http.MethodGet, "/api/v1/discovery/certificates/export", "auditor", "")
	assert.Equal(t, http.StatusInternalServerError, rec.Code)
	fr.ExportRowsFn = func(ctx context.Context, _ audit.Actor, x reports.RowExport, w io.Writer) (int, error) {
		_, _, err := x.Page(ctx, "not-a-cursor")
		return 0, err
	}
	rec = call(h, http.MethodGet, "/api/v1/discovery/certificates/export", "auditor", "")
	assert.Equal(t, http.StatusInternalServerError, rec.Code)
}

func TestDiscoverySettingsAndSummaryHandlers(t *testing.T) {
	h, f, _ := discoveryDeps(t)
	f.SettingsFn = func(context.Context) (discoverysvc.SettingsView, error) {
		return discoverysvc.SettingsView{Settings: discoverysvc.Settings{RetentionDays: 90}}, nil
	}
	rec := call(h, http.MethodGet, "/api/v1/discovery/settings", "auditor", "")
	require.Equal(t, http.StatusOK, rec.Code)
	v := jsonObj(t, rec)
	requireSnakeCase(t, v, "settings")
	assert.Equal(t, false, v["scanning_enabled"], "no allowed network: nothing may be scanned, and the answer says so")
	assert.Equal(t, []any{}, v["allowed_networks"])
	assert.Contains(t, v["builtin_exclusions"], "169.254.0.0/16")

	var saved discoverysvc.Settings
	f.SaveSettingsFn = func(_ context.Context, in discoverysvc.Settings) (discoverysvc.SettingsView, error) {
		saved = in
		return discoverysvc.SettingsView{Settings: in, ScanningEnabled: len(in.AllowedNetworks) > 0}, nil
	}
	rec = call(h, http.MethodPut, "/api/v1/discovery/settings", "admin-stepup", `{"allowed_networks":["10.0.0.0/8"],"global_exclusions":[],"retention_days":30}`)
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	assert.Equal(t, discoverysvc.Settings{AllowedNetworks: []string{"10.0.0.0/8"}, GlobalExclusions: []string{}, RetentionDays: 30}, saved)
	assert.Equal(t, true, jsonObj(t, rec)["scanning_enabled"])
	rec = call(h, http.MethodPut, "/api/v1/discovery/settings", "admin-stepup", `{"allowed_networks":[]}`)
	require.Equal(t, http.StatusUnprocessableEntity, rec.Code)
	_, _, details := errorField(t, rec)
	assert.ElementsMatch(t, []string{"global_exclusions", "retention_days"}, detailFields(details))
	f.SaveSettingsFn = func(context.Context, discoverysvc.Settings) (discoverysvc.SettingsView, error) {
		return discoverysvc.SettingsView{}, &discovery.Error{Kind: discovery.ErrInvalid, Field: "retention_days", Index: -1}
	}
	rec = call(h, http.MethodPut, "/api/v1/discovery/settings", "admin-stepup", `{"allowed_networks":[],"global_exclusions":[],"retention_days":3}`)
	assert.Equal(t, "ALC-DSC-0003", decodeErr(t, rec).Error.Code)
	for _, field := range []string{"allowed_networks", "global_exclusions"} {
		long := `["` + strings.Repeat(`10.0.0.1","`, 256) + `10.0.0.2"]`
		body := `{"allowed_networks":[],"global_exclusions":[],"retention_days":30}`
		rec = call(h, http.MethodPut, "/api/v1/discovery/settings", "admin-stepup", strings.Replace(body, `"`+field+`":[]`, `"`+field+`":`+long, 1))
		require.Equal(t, http.StatusUnprocessableEntity, rec.Code, field)
		_, _, details := errorField(t, rec)
		assert.Equal(t, []string{field}, detailFields(details), "more than 256 entries is a validation error, not 'too large to scan'")
	}
	rec = call(h, http.MethodPut, "/api/v1/discovery/settings", "admin", `{"allowed_networks":[],"global_exclusions":[],"retention_days":30}`)
	assert.Equal(t, "auth.stepup_required", decodeErr(t, rec).Error.Reason)

	at := testNow
	f.SummaryFn = func(context.Context) (discoverysvc.Summary, error) {
		return discoverysvc.Summary{UnmanagedTotal: 7, UnmanagedExpiring30d: 2, Scopes: 1, LastScanAt: &at}, nil
	}
	rec = call(h, http.MethodGet, "/api/v1/discovery/summary", "auditor", "")
	require.Equal(t, http.StatusOK, rec.Code)
	assert.Equal(t, map[string]any{"unmanaged_total": 7.0, "unmanaged_expiring_30d": 2.0, "scopes": 1.0, "last_scan_at": testNow.Format(time.RFC3339)},
		jsonObj(t, rec))
}

// No discovery answer of an error carries the service's internal text (an address in a Go error never leaves).
func TestDiscoveryErrorsCarryNoInternals(t *testing.T) {
	h, f, _ := discoveryDeps(t)
	internal := &leakyError{"dial tcp 10.66.77.88:443: connect: connection refused"}
	f.ListCertificatesFn = func(context.Context, discovery.CertificateFilter) ([]discovery.CertificateRow, bool, error) {
		return nil, false, internal
	}
	f.StartScanFn = func(context.Context, uuid.UUID) (discoverysvc.ScanView, error) {
		return discoverysvc.ScanView{}, internal
	}
	f.SummaryFn = func(context.Context) (discoverysvc.Summary, error) { return discoverysvc.Summary{}, internal }
	for _, rq := range []struct{ method, path, id string }{
		{http.MethodGet, "/api/v1/discovery/certificates", "auditor"},
		{http.MethodPost, "/api/v1/discovery/scopes/" + dscScopeID.String() + "/scans", "operator"},
		{http.MethodGet, "/api/v1/discovery/summary", "auditor"},
	} {
		rec := call(h, rq.method, rq.path, rq.id, "")
		assert.Equal(t, http.StatusInternalServerError, rec.Code, rq.path)
		assert.NotContains(t, rec.Body.String(), "10.66.77.88", rq.path)
		assert.NotContains(t, rec.Body.String(), "connection refused", rq.path)
		var m map[string]any
		require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &m))
		assert.Equal(t, "ALC-SYS-0003", m["error"].(map[string]any)["code"])
	}
}

type leakyError struct{ s string }

func (e *leakyError) Error() string { return e.s }

// A leaf valid until 9999-12-31 (the largest date X.509 and PostgreSQL hold) at a page boundary: the cursor is
// microseconds (UnixNano overflows past 2262), so the next page continues after it, in the list and in the export's
// paging alike (Task 9 review 1).
func TestDiscoveryCertificateCursorHoldsYear9999(t *testing.T) {
	h, f, fr := discoveryDeps(t)
	last := time.Date(9999, 12, 31, 23, 59, 59, 999999000, time.UTC)
	far := sampleCertRow()
	far.NotAfter = last
	var afters []*discovery.CertificateCursor
	f.ListCertificatesFn = func(_ context.Context, fl discovery.CertificateFilter) ([]discovery.CertificateRow, bool, error) {
		afters = append(afters, fl.After)
		if fl.After == nil {
			return []discovery.CertificateRow{far}, true, nil
		}
		return nil, false, nil
	}
	rec := call(h, http.MethodGet, "/api/v1/discovery/certificates?limit=1", "auditor", "")
	require.Equal(t, http.StatusOK, rec.Code)
	body := jsonObj(t, rec)
	item := body["items"].([]any)[0].(map[string]any)
	assert.Positive(t, item["days_left"], "no overflow of the days left")
	rec = call(h, http.MethodGet, "/api/v1/discovery/certificates?cursor="+body["next_cursor"].(string), "auditor", "")
	require.Equal(t, http.StatusOK, rec.Code)
	require.Len(t, afters, 2)
	require.NotNil(t, afters[1])
	assert.Equal(t, discovery.CertificateCursor{NotAfter: last, Fingerprint: dscFP}, *afters[1])

	afters = nil
	fr.ExportRowsFn = func(ctx context.Context, _ audit.Actor, x reports.RowExport, w io.Writer) (int, error) {
		n := 0
		for cursor := ""; ; {
			rows, next, err := x.Page(ctx, cursor)
			if err != nil {
				return n, err
			}
			n += len(rows)
			if next == "" {
				break
			}
			cursor = next
		}
		_, err := w.Write([]byte("x\n"))
		return n, err
	}
	rec = call(h, http.MethodGet, "/api/v1/discovery/certificates/export", "auditor", "")
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	require.Len(t, afters, 2, "the export counted both pages")
	assert.Equal(t, discovery.CertificateCursor{NotAfter: last, Fingerprint: dscFP}, *afters[1])
}

// FX-03 (R66 ruling 7): the found certificate's detail carries its last revocation check (null before the first
// check, a failure with its code); the list does not.
func TestDiscoveryCertificateDetailRevocationCheck(t *testing.T) {
	h, f, _ := discoveryDeps(t)
	checked := testNow.Add(-time.Hour)
	row := sampleCertRow()
	row.Revocation = &discovery.RevocationCheck{Status: "unavailable", ErrorCode: "certificate.revocation_unreachable", CheckedAt: checked,
		NextCheckAt: checked.Add(time.Hour)}
	f.CertificateFn = func(context.Context, string) (discovery.CertificateRow, []discovery.EndpointRow, bool, error) {
		return row, nil, false, nil
	}
	rec := call(h, http.MethodGet, "/api/v1/discovery/certificates/"+dscFP, "auditor", "")
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	d := jsonObj(t, rec)
	rc, ok := d["revocation_check"].(map[string]any)
	require.True(t, ok, "%v", d["revocation_check"])
	assert.Equal(t, "unavailable", rc["status"])
	assert.Equal(t, checked.UTC().Format(time.RFC3339), rc["checked_at"])
	assert.Nil(t, rc["revoked_at"])
	e := rc["error"].(map[string]any)
	assert.Equal(t, ErrCertRevocationUnreachable.Code, e["code"])
	assert.Equal(t, "certificate.revocation_unreachable", e["reason"])

	row.Revocation = nil
	rec = call(h, http.MethodGet, "/api/v1/discovery/certificates/"+dscFP, "auditor", "")
	require.Equal(t, http.StatusOK, rec.Code)
	d = jsonObj(t, rec)
	v, present := d["revocation_check"]
	assert.True(t, present, "the detail always names the check")
	assert.Nil(t, v, "null before the first check")

	f.ListCertificatesFn = func(context.Context, discovery.CertificateFilter) ([]discovery.CertificateRow, bool, error) {
		c := sampleCertRow()
		c.Revocation = &discovery.RevocationCheck{Status: "good", CheckedAt: checked, NextCheckAt: checked}
		return []discovery.CertificateRow{c}, false, nil
	}
	rec = call(h, http.MethodGet, "/api/v1/discovery/certificates", "auditor", "")
	require.Equal(t, http.StatusOK, rec.Code)
	item := jsonObj(t, rec)["items"].([]any)[0].(map[string]any)
	assert.NotContains(t, item, "revocation_check", "the list carries no revocation check")
}
