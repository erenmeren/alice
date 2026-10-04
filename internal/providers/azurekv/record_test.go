//go:build azure

package azurekv

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"alice/internal/platform/azureid"
)

// TestRecordShapes rewrites the reference shapes in test/testdata/kv-recordings from a real vault's
// answers when ALICE_AZURE_RECORD=1 and the TestRealAzure variables are set (`make record-azure`;
// `make test-azure` never selects it). The requests go through the provider's own guarded vault
// transport (https, the vault's host only, no proxy, no redirect), never a bare http.Client.
//
// Only the shape is written, with the placeholders of the README of that directory: ids keep their
// form with <vault>, <name> and <version>; <cer>, <x5t>, <value>, <n> and the like replace key
// material; every map with customer-chosen keys (tags) is emptied; strings of free text become
// "<string>"; numbers and booleans stay. The owner reviews the diff and commits it.
func TestRecordShapes(t *testing.T) {
	if os.Getenv("ALICE_AZURE_RECORD") != "1" {
		t.Skip("set ALICE_AZURE_RECORD=1 to record the shapes of a real vault")
	}
	v := realConfig(t)
	vault, err := azureid.ParseVault(v.url)
	require.NoError(t, err)
	sess := v.open(t, v.identity(t))
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	tok, err := sess.api.Token(ctx)
	require.NoError(t, err)
	cert, err := sess.api.GetCertificate(ctx, v.certName, "")
	require.NoError(t, err)
	ver := cert.ID.Version()
	guarded := newGuardedTransport([]string{vault.Host}, nil, nil)
	defer guarded.CloseIdleConnections()

	files := map[string]string{
		"list_certificates.json":         "/certificates?api-version=2025-07-01&maxresults=2",
		"list_certificate_versions.json": "/certificates/" + v.certName + "/versions?api-version=2025-07-01&maxresults=2",
		"get_certificate.json":           "/certificates/" + v.certName + "/" + ver + "?api-version=2025-07-01",
		"get_secret_pkcs12.json":         "/secrets/" + v.certName + "/" + ver + "?api-version=2025-07-01",
		"list_keys.json":                 "/keys?api-version=2025-07-01&maxresults=2",
		"list_secrets.json":              "/secrets?api-version=2025-07-01&maxresults=2",
	}
	dir := filepath.Join(moduleRoot(t), "test", "testdata", "kv-recordings")
	for name, path := range files {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, vault.URL+path, nil)
		require.NoError(t, err)
		req.Header.Set("Authorization", "Bearer "+tok.Token)
		resp, err := guarded.Do(req)
		require.NoError(t, err, name)
		body, err := io.ReadAll(resp.Body)
		_ = resp.Body.Close()
		require.NoError(t, err, name)
		require.Equal(t, http.StatusOK, resp.StatusCode, name)
		var doc any
		require.NoError(t, json.Unmarshal(body, &doc), name)
		out, err := encodeShape(shapeOf("", doc))
		require.NoError(t, err)
		require.NoError(t, os.WriteFile(filepath.Join(dir, name), out, 0o644)) //nolint:gosec // G306: test data in the repository
		t.Logf("recorded %s", name)
	}
}
