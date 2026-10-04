package fakekv

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"
)

// TestClient is an HTTP client wired to one Server (see Server.TestClient).
type TestClient struct {
	s *Server
	c *http.Client
}

// HTTPClient returns the underlying client; it implements the Azure SDK's policy.Transporter.
func (c *TestClient) HTTPClient() *http.Client { return c.c }

// Response is what Do returns.
type Response struct {
	Status int
	Header http.Header
	Body   []byte
}

// JSON decodes the body into any (objects become map[string]any).
func (r Response) JSON(t testing.TB) any {
	t.Helper()
	var v any
	if err := json.Unmarshal(r.Body, &v); err != nil {
		t.Fatalf("response body is not JSON: %v", err)
	}
	return v
}

// Do sends a request to the vault with a valid bearer token ("" body = none). path may carry a query;
// api-version is added when the path has none. A non-vault absolute URL is sent as given.
func (c *TestClient) Do(t testing.TB, method, path, body string) Response {
	t.Helper()
	target := path
	if !strings.HasPrefix(path, "https://") {
		target = c.s.VaultURL() + path
	}
	u, err := url.Parse(target)
	if err != nil {
		t.Fatal(err)
	}
	q := u.Query()
	if !q.Has("api-version") {
		q.Set("api-version", APIVersion)
		u.RawQuery = q.Encode()
	}
	var rd io.Reader
	if body != "" {
		rd = bytes.NewReader([]byte(body))
	}
	req, err := http.NewRequestWithContext(context.Background(), method, u.String(), rd)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Authorization", "Bearer "+c.s.testBearer())
	if body != "" {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := c.c.Do(req)
	if err != nil {
		t.Fatalf("%s %s: %v", method, target, err)
	}
	defer func() { _ = resp.Body.Close() }()
	b, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("reading %s: %v", target, err)
	}
	return Response{Status: resp.StatusCode, Header: resp.Header, Body: b}
}

// Raw sends a request to any absolute URL (https for the vault and the login host, http://169.254.169.254
// for IMDS) through the client, with exactly the given headers: no api-version, no token.
func (c *TestClient) Raw(t testing.TB, method, target string, header http.Header, body string) Response {
	t.Helper()
	var rd io.Reader
	if body != "" {
		rd = bytes.NewReader([]byte(body))
	}
	req, err := http.NewRequestWithContext(context.Background(), method, target, rd)
	if err != nil {
		t.Fatal(err)
	}
	for k, v := range header {
		req.Header[k] = v
	}
	resp, err := c.c.Do(req)
	if err != nil {
		t.Fatalf("%s %s: %v", method, target, err)
	}
	defer func() { _ = resp.Body.Close() }()
	b, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("reading %s: %v", target, err)
	}
	return Response{Status: resp.StatusCode, Header: resp.Header, Body: b}
}

// Get is Do with GET.
func (c *TestClient) Get(t testing.TB, path string) Response {
	return c.Do(t, http.MethodGet, path, "")
}

// GetJSON GETs path, requires 200 and returns the decoded body.
func (c *TestClient) GetJSON(t testing.TB, path string) any {
	t.Helper()
	r := c.Get(t, path)
	if r.Status != http.StatusOK {
		t.Fatalf("GET %s: status %d: %s", path, r.Status, r.Body)
	}
	return r.JSON(t)
}

// TestClientToken returns a valid vault bearer token the fake issued for tests (it is not the one
// LastAccessToken reports).
func (s *Server) TestClientToken() string { return s.testBearer() }
