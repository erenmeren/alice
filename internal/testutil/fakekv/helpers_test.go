package fakekv_test

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"testing"
	"time"

	"software.sslmate.com/src/go-pkcs12"

	"alice/internal/testutil/fakekv"
	"alice/internal/testutil/pki"
)

func ctxTimeout(d time.Duration) (context.Context, context.CancelFunc) {
	return context.WithTimeout(context.Background(), d)
}

// drain sends req and reads the whole body; the error of either step is returned.
func drain(c *fakekv.TestClient, req *http.Request) error {
	resp, err := c.HTTPClient().Do(req)
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()
	_, err = io.ReadAll(resp.Body)
	return err
}

// requireCut requires req to end in an error (its context ended first); an answer instead fails with
// its status and body, so a flake says which path answered. An empty 200 that arrives after the
// context ended is a cut too: the server saw the context end, its handler returned without writing,
// and net/http sent the implicit 200 before the client's transport gave up (seen on a CI runner).
func requireCut(t *testing.T, c *fakekv.TestClient, req *http.Request) {
	t.Helper()
	resp, err := c.HTTPClient().Do(req)
	if err != nil {
		return
	}
	defer func() { _ = resp.Body.Close() }()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return
	}
	if req.Context().Err() != nil && resp.StatusCode == http.StatusOK && len(body) == 0 {
		return
	}
	t.Fatalf("expected the request to be cut by its context, got status %d: %s", resp.StatusCode, body)
}

// importBody is the JSON of an import of the leaf (PFX, empty password).
func importBody(t *testing.T, leaf pki.Leaf) string {
	t.Helper()
	pfx, err := pkcs12.Modern.Encode(leaf.Key, leaf.Cert, nil, "")
	if err != nil {
		t.Fatal(err)
	}
	b, _ := json.Marshal(map[string]any{"value": base64.StdEncoding.EncodeToString(pfx), "pwd": ""})
	return string(b)
}
