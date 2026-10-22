package api

import (
	"context"
	"encoding/json"
	"net/http"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"alice/internal/inventory"
	"alice/internal/providers"
)

// A Windows server is created like any other target: the type and a domain account reach the inventory verbatim
// (R60 Review Focus 1); the target shows its Windows facts; the setup guide carries the windows profile; the target
// list filters by the type; and the key routes refuse it as they refuse any non-server target.
func TestCreateWindowsTarget(t *testing.T) {
	d, inv := inventoryDeps(t)
	var gotIn inventory.NewTarget
	win := sampleTarget()
	win.Type, win.Username, win.Facts = inventory.TypeWindows, `CORP\alice-svc`, inventory.Facts{
		Windows: &providers.WindowsFacts{Build: "10.0.20348.2700", Product: "Windows Server 2022 Datacenter", InstallationType: "Server",
			Elevated: true, IISInstalled: true, IISVersion: "10.0", Stores: []string{"My", "WebHosting"}, OpenSSHVersion: "OpenSSH_for_Windows_8.1"},
	}
	inv.CreateTargetFn = func(_ context.Context, _ inventory.Actor, in inventory.NewTarget) (inventory.Target, uuid.UUID, error) {
		gotIn = in
		return win, jobID, nil
	}
	inv.GetTargetFn = func(context.Context, uuid.UUID) (inventory.Target, error) { return win, nil }
	inv.SetupGuideFn = func(context.Context, string) (inventory.Guide, error) {
		return inventory.Guide{Profiles: map[string]providers.SetupSnippet{"windows": {Profile: "windows", Script: "$AliceUser = 'alice'"}}}, nil
	}
	h := NewHandler(d)

	rec := call(h, http.MethodPost, "/api/v1/targets", "admin",
		`{"name":"iis-01","type":"windows","host":"iis-01.example.com","username":"CORP\\alice-svc"}`)
	require.Equal(t, http.StatusCreated, rec.Code, rec.Body.String())
	assert.Equal(t, inventory.NewTarget{Name: "iis-01", Type: "windows", Host: "iis-01.example.com", Username: `CORP\alice-svc`}, gotIn)
	assert.Equal(t, `CORP\alice-svc`, decodeMap(t, rec.Body.Bytes())["target"].(map[string]any)["username"])

	rec = call(h, http.MethodGet, "/api/v1/targets/"+targetID.String(), "admin", "")
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	facts := decodeMap(t, rec.Body.Bytes())["facts"].(map[string]any)
	raw, err := json.Marshal(facts["windows"])
	require.NoError(t, err)
	assert.JSONEq(t, `{"build":"10.0.20348.2700","product":"Windows Server 2022 Datacenter","installation_type":"Server","elevated":true,
		"iis_installed":true,"iis_version":"10.0","stores":["My","WebHosting"],"openssh_version":"OpenSSH_for_Windows_8.1"}`, string(raw))

	rec = call(h, http.MethodGet, "/api/v1/ssh-keys/platform-key", "admin", "")
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	assert.Equal(t, "$AliceUser = 'alice'", decodeMap(t, rec.Body.Bytes())["profiles"].(map[string]any)["windows"].(map[string]any)["script"])

	inv.ListTargetsFn = func(context.Context) ([]inventory.Target, error) { return []inventory.Target{win, sampleTarget()}, nil }
	rec = call(h, http.MethodGet, "/api/v1/targets?type=windows", "admin", "")
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	assert.Len(t, decodeMap(t, rec.Body.Bytes())["items"], 1)

	assert.Equal(t, http.StatusNotFound, call(h, http.MethodGet, "/api/v1/targets/"+targetID.String()+"/key-files", "admin", "").Code,
		"a Windows server has no SSH key inventory")
}

// A target of another type shows no windows facts.
func TestTargetJSONOmitsWindowsFactsForOtherTypes(t *testing.T) {
	raw, err := json.Marshal(targetJSON(sampleTarget(), serviceRefs{}))
	require.NoError(t, err)
	assert.NotContains(t, string(raw), `"windows"`)
}
