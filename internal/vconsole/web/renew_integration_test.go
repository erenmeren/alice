//go:build integration

package web

import (
	"context"
	"fmt"
	"html"
	"net/http"
	"net/url"
	"regexp"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"alice/internal/license"
)

// seedRenewable inserts a request with features and the license issued from it, as the signer
// would, and returns the installation ID.
func (e *testEnv) seedRenewable(cid int64, id string, until time.Time, targets int, features []string) string {
	e.t.Helper()
	ctx := context.Background()
	inst := license.NewInstallationID()
	if features == nil {
		features = []string{}
	}
	var reqID int64
	require.NoError(e.t, e.d.Owner.QueryRow(ctx, `INSERT INTO license_requests (customer_id, installation, targets, features, status)
		VALUES ($1, $2, $3, $4, 'signed') RETURNING id`, cid, inst, targets, features).Scan(&reqID))
	_, err := e.d.Owner.Exec(ctx, `INSERT INTO licenses (license_id, request_id, customer_id, installation, key_id, issued_at,
		valid_from, valid_until, targets, file, file_sha256)
		VALUES ($1, $2, $3, $4, 'key1', now() - interval '1 day', now() - interval '1 day', $5, $6, 'x', 'sha')`,
		id, reqID, cid, inst, until, targets)
	require.NoError(e.t, err)
	return inst
}

// inputValue returns the value attribute of the input with the given name.
func inputValue(t *testing.T, body, name string) string {
	t.Helper()
	m := regexp.MustCompile(`name="` + name + `" value="([^"]*)"`).FindStringSubmatch(body)
	require.NotNil(t, m, "input %s", name)
	return html.UnescapeString(m[1])
}

func TestRenewPrefillsFromTheOldLicense(t *testing.T) {
	e := newEnv(t, "https://licenses.example.test")
	ayse := e.signIn("ayse")
	_ = e.addCustomer(ayse, "Other Ltd") // listed first: the prefill must pick the right one
	cid := e.addCustomer(ayse, "Zeta Ltd")
	until := time.Date(2027, 3, 31, 21, 0, 0, 0, time.UTC)
	inst := e.seedRenewable(cid, "LIC-2026-000777", until, 9, []string{"audit", "sso"})

	list := e.do(http.MethodGet, "/licenses", "", ayse)
	require.Equal(t, http.StatusOK, list.Code)
	assert.Contains(t, list.Body.String(), `href="/requests/new?renew=LIC-2026-000777"`)

	w := e.do(http.MethodGet, "/requests/new?renew=LIC-2026-000777", "", ayse)
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())
	body := w.Body.String()
	assert.Contains(t, body, "Renewing LIC-2026-000777")
	assert.Regexp(t, fmt.Sprintf(`<option value="%d" selected>Zeta Ltd</option>`, cid), body)
	assert.Len(t, regexp.MustCompile(` selected>`).FindAllString(body, -1), 1, "one customer selected")
	assert.Equal(t, inst, inputValue(t, body, "installation"))
	assert.Equal(t, "9", inputValue(t, body, "targets"))
	assert.Equal(t, "12", inputValue(t, body, "months"))
	assert.Equal(t, "2027-03-31", inputValue(t, body, "from"), "the new license starts where the old one ends")
	assert.Equal(t, "audit,sso", inputValue(t, body, "features"))
	assert.Empty(t, inputValue(t, body, "replaces"), "a renewal is a new license, not a correction")

	// Submitting the prefilled form as is gives a request with the same content.
	v := url.Values{"customer_id": {fmt.Sprint(cid)}, "installation": {inst}, "targets": {"9"}, "months": {"12"},
		"from": {"2027-03-31"}, "features": {"audit,sso"}}
	sub := e.form("/requests", v, ayse)
	require.Equal(t, http.StatusSeeOther, sub.Code, sub.Body.String())
	var feats []string
	var gotFrom string
	require.NoError(t, e.d.Owner.QueryRow(context.Background(), `SELECT features, valid_from FROM license_requests
		WHERE status = 'open' AND customer_id = $1`, cid).Scan(&feats, &gotFrom))
	assert.Equal(t, []string{"audit", "sso"}, feats)
	assert.Equal(t, "2027-03-31", gotFrom)
}

func TestRenewWithUnknownOrOddIDIs404(t *testing.T) {
	e := newEnv(t, "https://licenses.example.test")
	ayse := e.signIn("ayse")
	cid := e.addCustomer(ayse, "Eta Ltd")
	e.seedRenewable(cid, "LIC-2026-000778", time.Now().Add(40*24*time.Hour), 3, nil)
	for _, q := range []string{"LIC-2026-999999", "", "LIC%2F..%2F1", "x%27%20OR%201%3D1", "%3Cscript%3E", "a%0Ab",
		"LIC-2026-000778%20"} {
		w := e.do(http.MethodGet, "/requests/new?renew="+q, "", ayse)
		assert.Equal(t, http.StatusNotFound, w.Code, q)
		assert.NotContains(t, w.Body.String(), "Eta Ltd", q)
	}
	// Without the parameter the plain form is still there.
	assert.Equal(t, http.StatusOK, e.do(http.MethodGet, "/requests/new", "", ayse).Code)
}

func TestRevokedLicenseHasNoRenewLink(t *testing.T) {
	e := newEnv(t, "https://licenses.example.test")
	ayse := e.signIn("ayse")
	cid := e.addCustomer(ayse, "Theta Ltd")
	e.seedRenewable(cid, "LIC-2026-000781", time.Now().Add(40*24*time.Hour), 3, nil)
	e.seedRenewable(cid, "LIC-2026-000782", time.Now().Add(50*24*time.Hour), 3, nil)
	_, err := e.d.Owner.Exec(context.Background(), `UPDATE licenses SET revoked_at = now() WHERE license_id = 'LIC-2026-000782'`)
	require.NoError(t, err)

	body := e.do(http.MethodGet, "/licenses", "", ayse).Body.String()
	assert.Contains(t, body, "renew=LIC-2026-000781")
	assert.NotContains(t, body, "renew=LIC-2026-000782")
	assert.Equal(t, http.StatusNotFound, e.do(http.MethodGet, "/requests/new?renew=LIC-2026-000782", "", ayse).Code,
		"a revoked license is not renewed by its link either")
}

func TestRenewFormStillValidatesOnSubmit(t *testing.T) {
	e := newEnv(t, "https://licenses.example.test")
	ayse := e.signIn("ayse")
	cid := e.addCustomer(ayse, "Iota Ltd")
	inst := e.seedRenewable(cid, "LIC-2026-000790", time.Now().Add(20*24*time.Hour), 4, []string{"a"})
	require.Equal(t, http.StatusOK, e.do(http.MethodGet, "/requests/new?renew=LIC-2026-000790", "", ayse).Code)
	before := e.countRows("license_requests")
	for name, v := range map[string]url.Values{
		"targets edited to zero": {"targets": {"0"}, "months": {"12"}, "from": {"2030-01-01"}},
		"months edited to 99":    {"targets": {"4"}, "months": {"99"}, "from": {"2030-01-01"}},
		"bad start date":         {"targets": {"4"}, "months": {"12"}, "from": {"31/12/2030"}},
	} {
		v.Set("customer_id", fmt.Sprint(cid))
		v.Set("installation", inst)
		w := e.form("/requests", v, ayse)
		assert.Equal(t, http.StatusUnprocessableEntity, w.Code, name)
		assert.Contains(t, w.Body.String(), `class="alert"`, name)
	}
	assert.Equal(t, before, e.countRows("license_requests"))
}
