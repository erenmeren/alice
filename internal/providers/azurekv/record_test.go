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
)

// TestRecordShapes rewrites the reference shapes in test/testdata/kv-recordings from a real vault's
// answers when ALICE_AZURE_RECORD=1 (and the TestRealAzure variables are set): every string value is
// replaced by a placeholder, numbers, booleans and the keys stay. The owner reviews the diff and
// commits it. Nothing but the shape is written: no key, certificate, secret value or token.
func TestRecordShapes(t *testing.T) {
	if os.Getenv("ALICE_AZURE_RECORD") != "1" {
		t.Skip("set ALICE_AZURE_RECORD=1 to record the shapes of a real vault")
	}
	v := realConfig(t)
	sess := v.open(t, v.identity(t))
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	tok, err := sess.api.Token(ctx)
	require.NoError(t, err)

	cert, err := sess.api.GetCertificate(ctx, v.certName, "")
	require.NoError(t, err)
	ver := cert.ID.Version()
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
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, v.url+path, nil)
		require.NoError(t, err)
		req.Header.Set("Authorization", "Bearer "+tok.Token)
		resp, err := (&http.Client{}).Do(req)
		require.NoError(t, err, name)
		body, err := io.ReadAll(io.LimitReader(resp.Body, MaxBody))
		_ = resp.Body.Close()
		require.NoError(t, err, name)
		require.Equal(t, http.StatusOK, resp.StatusCode, name)
		var doc any
		require.NoError(t, json.Unmarshal(body, &doc), name)
		out, err := json.MarshalIndent(shapeOf(doc), "", "  ")
		require.NoError(t, err)
		require.NoError(t, os.WriteFile(filepath.Join(dir, name), append(out, '\n'), 0o644)) //nolint:gosec // G306: a test data file in the repository
		t.Logf("recorded %s", name)
	}
}

// shapeOf keeps the keys and the JSON types of a document: strings become "<string>".
func shapeOf(v any) any {
	switch x := v.(type) {
	case map[string]any:
		out := make(map[string]any, len(x))
		for k, e := range x {
			out[k] = shapeOf(e)
		}
		return out
	case []any:
		out := make([]any, len(x))
		for i, e := range x {
			out[i] = shapeOf(e)
		}
		return out
	case string:
		return "<string>"
	}
	return v
}
