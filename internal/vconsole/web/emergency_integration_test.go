//go:build integration

package web

import (
	"context"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"alice/internal/license"
)

const day = 24 * time.Hour

// seedOn inserts a signed request and its license for inst through the owner pool.
func (e *testEnv) seedOn(cid int64, inst, id string, from, until time.Time, targets int, features []string, emergency bool) {
	e.t.Helper()
	ctx := context.Background()
	if features == nil {
		features = []string{}
	}
	var reqID int64
	if emergency {
		require.NoError(e.t, e.d.Owner.QueryRow(ctx, `INSERT INTO license_requests (customer_id, installation, targets, features,
			status, kind, months, days, reason, extends) VALUES ($1, $2, $3, $4, 'signed', 'emergency', NULL, 14, 'seeded', 'L')
			RETURNING id`, cid, inst, targets, features).Scan(&reqID))
	} else {
		require.NoError(e.t, e.d.Owner.QueryRow(ctx, `INSERT INTO license_requests (customer_id, installation, targets, features, status)
			VALUES ($1, $2, $3, $4, 'signed') RETURNING id`, cid, inst, targets, features).Scan(&reqID))
	}
	_, err := e.d.Owner.Exec(ctx, `INSERT INTO licenses (license_id, request_id, customer_id, installation, key_id, issued_at,
		valid_from, valid_until, targets, file, file_sha256) VALUES ($1, $2, $3, $4, 'key1', $5, $5, $6, $7, 'x', 'sha')`,
		id, reqID, cid, inst, from, until, targets)
	require.NoError(e.t, err)
}

// lapsedInstallation: an old license and the latest one, which ended three days ago.
func (e *testEnv) lapsedInstallation(cid int64) string {
	now := e.clk.Now()
	inst := license.NewInstallationID()
	e.seedOn(cid, inst, "LIC-2024-000001", now.Add(-800*day), now.Add(-400*day), 3, []string{"old"}, false)
	e.seedOn(cid, inst, "LIC-2025-000002", now.Add(-368*day), now.Add(-3*day), 9, []string{"audit", "sso"}, false)
	return inst
}

func TestEmergencyExtensionFromTheLicensesPage(t *testing.T) {
	e := newEnv(t, "https://licenses.example.test")
	ayse := e.signIn("ayse")
	cid := e.addCustomer(ayse, "Lapsed Ltd")
	inst := e.lapsedInstallation(cid)
	now := e.clk.Now()
	e.seedOn(cid, license.NewInstallationID(), "LIC-2026-000003", now.Add(-300*day), now.Add(200*day), 4, nil, false)

	list := e.page("/licenses", ayse)
	assert.Contains(t, list, `href="/requests/emergency?license=LIC-2025-000002"`, "the latest license of a lapsed installation")
	assert.NotContains(t, list, "emergency?license=LIC-2024-000001", "not an older license of the installation")
	assert.NotContains(t, list, "emergency?license=LIC-2026-000003", "not a license that runs for months yet")

	body := e.page("/requests/emergency?license=LIC-2025-000002", ayse)
	assert.Contains(t, body, "Emergency extension")
	assert.Contains(t, body, "Lapsed Ltd")
	assert.Contains(t, body, inst)
	assert.Contains(t, body, "audit, sso")
	assert.Equal(t, "14", inputValue(t, body, "days"))
	assert.Contains(t, body, `max="30"`)
	assert.Equal(t, "LIC-2025-000002", inputValue(t, body, "license"))
	assert.NotContains(t, body, `name="targets"`, "the carried-over content cannot be edited")

	w := e.form("/requests/emergency", url.Values{"license": {"LIC-2025-000002"}, "days": {"21"},
		"reason": {"Renewal PO is delayed by procurement"}}, ayse)
	require.Equal(t, http.StatusSeeOther, w.Code, w.Body.String())
	loc := w.Header().Get("Location")
	require.Regexp(t, requestPath, loc)

	req := e.page(loc, ayse)
	assert.Contains(t, req, "Emergency extension")
	assert.Contains(t, req, "21 days")
	assert.Contains(t, req, "Renewal PO is delayed by procurement")
	assert.Contains(t, req, "LIC-2025-000002")
	assert.NotContains(t, req, "<dt>Months</dt>")

	home := e.page("/", ayse)
	assert.Contains(t, home, "Emergency extension", "the open request is labelled on the home page")

	var kind, by string
	var days, targets int
	require.NoError(t, e.d.Owner.QueryRow(context.Background(), `SELECT kind, days, targets, requested_by FROM license_requests
		WHERE kind = 'emergency' AND status = 'open'`).Scan(&kind, &days, &targets, &by))
	assert.Equal(t, 21, days)
	assert.Equal(t, 9, targets)
	assert.Equal(t, "web:ayse", by)
}

func TestEmergencyExtensionFormRefusals(t *testing.T) {
	e := newEnv(t, "https://licenses.example.test")
	ayse := e.signIn("ayse")
	cid := e.addCustomer(ayse, "Refused Ltd")
	e.lapsedInstallation(cid)
	now := e.clk.Now()
	running := license.NewInstallationID()
	e.seedOn(cid, running, "LIC-2026-000010", now.Add(-300*day), now.Add(60*day), 4, nil, false)
	before := e.countRows("license_requests")

	for name, v := range map[string]url.Values{
		"31 days":       {"license": {"LIC-2025-000002"}, "days": {"31"}, "reason": {"x"}},
		"not a number":  {"license": {"LIC-2025-000002"}, "days": {"two weeks"}, "reason": {"x"}},
		"no reason":     {"license": {"LIC-2025-000002"}, "days": {"14"}, "reason": {" "}},
		"still running": {"license": {"LIC-2026-000010"}, "days": {"30"}, "reason": {"x"}},
	} {
		w := e.form("/requests/emergency", v, ayse)
		assert.Equal(t, http.StatusUnprocessableEntity, w.Code, name)
		assert.Contains(t, w.Body.String(), `class="alert"`, name)
		assert.Contains(t, w.Body.String(), "Refused Ltd", name+": the form is shown again")
	}
	for _, id := range []string{"LIC-2026-999999", "", "a%0Ab", "%3Cscript%3E"} {
		assert.Equal(t, http.StatusNotFound, e.do(http.MethodGet, "/requests/emergency?license="+id, "", ayse).Code, id)
		w := e.form("/requests/emergency", url.Values{"license": {strings.ReplaceAll(id, "%0A", "\n")}, "days": {"14"},
			"reason": {"x"}}, ayse)
		assert.Equal(t, http.StatusNotFound, w.Code, id)
	}
	_, err := e.d.Owner.Exec(context.Background(), `UPDATE licenses SET revoked_at = now() WHERE license_id = 'LIC-2025-000002'`)
	require.NoError(t, err)
	// With its latest license revoked, the installation's older license is carried over; the
	// revoked one itself extends nothing.
	assert.Equal(t, http.StatusNotFound, e.do(http.MethodGet, "/requests/emergency?license=LIC-2025-000002", "", ayse).Code)
	assert.Equal(t, before, e.countRows("license_requests"))

	// Signed out: the sign-in page, nothing else.
	w := e.do(http.MethodGet, "/requests/emergency?license=LIC-2024-000001", "")
	assert.NotEqual(t, http.StatusOK, w.Code)
	assert.NotContains(t, w.Body.String(), "Refused Ltd")
}

func TestEmergencyLicenseIsLabelledInTheList(t *testing.T) {
	e := newEnv(t, "https://licenses.example.test")
	ayse := e.signIn("ayse")
	cid := e.addCustomer(ayse, "Extended Ltd")
	inst := e.lapsedInstallation(cid)
	now := e.clk.Now()
	e.seedOn(cid, inst, "LIC-2026-000020", now.Truncate(day), now.Truncate(day).Add(14*day), 9, nil, true)

	list := e.page("/licenses", ayse)
	row := list[strings.Index(list, "LIC-2026-000020"):]
	row = row[:strings.Index(row, "</tr>")]
	assert.Contains(t, row, "Emergency extension")
	assert.Contains(t, row, "emergency?license=LIC-2026-000020", "a further extension can be asked for from the extension")
	assert.NotContains(t, list, "emergency?license=LIC-2025-000002", "the extension is now the latest")
}
