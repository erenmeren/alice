//go:build integration

package api

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"go.yaml.in/yaml/v3"

	apispec "alice/api"
)

// FuzzOpenAPIInputs (spec §25.6): random JSON bodies against every create and update route of the
// OpenAPI document. One installed stack serves the whole run; the Administrator is signed in and
// stepped up (the session is renewed every fuzzRefreshEvery requests). The fuzz function picks a
// route by an index argument and sends the bytes as the JSON body. The properties: the status is
// never 500 (any 500 is a bug in the handler that owns the route) and the server never panics (the
// recoverer logs "request handler panicked" or "response encoding failed", which the run scans for
// after every request). The seed corpus is one valid body per route, built from the examples of
// its request schema in api/openapi.yaml.
//
// Not fuzzed, by design: the setup routes (the wizard is finished), the four sign-in routes whose
// failures would lock the fuzzing account or change its password (login, mfa/verify, stepup,
// password), and the routes that would dial a host named in the body from the test machine (Key
// Vault registration, the SMTP test and trust, the identity provider routes and the OIDC start), and the directory
// sign-in, step-up and tests (see fuzzExcluded).
// Those are covered by their own negative suites (A-14, F-62, O-12).
const fuzzRefreshEvery = 100

var fuzzExcluded = map[string]bool{
	"POST /api/v1/auth/login": true, "POST /api/v1/auth/mfa/verify": true, "POST /api/v1/auth/stepup": true,
	"POST /api/v1/auth/password": true, "POST /api/v1/key-vaults": true,
	"POST /api/v1/settings/smtp/actions/test": true, "POST /api/v1/settings/smtp/actions/trust": true,
	"POST /api/v1/auth/oidc/{id}/start": true, "POST /api/v1/auth/oidc/stepup": true,
	"POST /api/v1/sso/providers": true, "PATCH /api/v1/sso/providers/{id}": true,
	// Directory sign-in (Task 5): the sign-in and the step-up would spend the per-name limits and wait on the stack's
	// clock (a refusal is held to ldapRefusalFloor); the tests contact the directory. TestDirectory* cover them.
	"POST /api/v1/auth/ldap/{id}/login": true, "POST /api/v1/auth/ldap/stepup": true,
	"POST /api/v1/ldap/directories/{id}/actions/test-connection": true, "POST /api/v1/ldap/directories/{id}/actions/test-signin": true,
}

type fuzzRoute struct {
	method, path string
	seed         []byte
}

func (r fuzzRoute) name() string { return r.method + " " + r.path }

// fuzzRoutes lists the create and update routes of the OpenAPI document that carry a JSON body,
// sorted, with a valid example body each.
func fuzzRoutes(tb testing.TB) []fuzzRoute {
	tb.Helper()
	var doc map[string]any
	require.NoError(tb, yaml.Unmarshal(apispec.YAML, &doc))
	paths, _ := doc["paths"].(map[string]any)
	var out []fuzzRoute
	for path, item := range paths {
		if strings.HasPrefix(path, "/api/v1/setup/") {
			continue
		}
		ops, _ := item.(map[string]any)
		for method, o := range ops {
			op, _ := o.(map[string]any)
			m := map[string]string{"post": http.MethodPost, "put": http.MethodPut, "patch": http.MethodPatch}[method]
			if m == "" || fuzzExcluded[m+" "+path] {
				continue
			}
			rb, _ := op["requestBody"].(map[string]any)
			content, _ := rb["content"].(map[string]any)
			js, _ := content["application/json"].(map[string]any)
			if js == nil {
				continue
			}
			seed, err := json.Marshal(exampleOf(doc, js["schema"], 0))
			require.NoError(tb, err)
			out = append(out, fuzzRoute{method: m, path: path, seed: seed})
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].name() < out[j].name() })
	return out
}

// resolve follows a local $ref.
func resolve(doc map[string]any, schema any) map[string]any {
	s, _ := schema.(map[string]any)
	for i := 0; i < 10 && s != nil; i++ {
		ref, ok := s["$ref"].(string)
		if !ok {
			return s
		}
		var cur any = doc
		for _, part := range strings.Split(strings.TrimPrefix(ref, "#/"), "/") {
			m, _ := cur.(map[string]any)
			cur = m[part]
		}
		s, _ = cur.(map[string]any)
	}
	return s
}

// exampleOf builds a body from a schema: an example, a default or the first enum value of each
// property, else the smallest value of its type.
func exampleOf(doc map[string]any, schema any, depth int) any {
	s := resolve(doc, schema)
	if s == nil || depth > 6 {
		return nil
	}
	if v, ok := s["example"]; ok {
		return v
	}
	if l, ok := s["examples"].([]any); ok && len(l) > 0 {
		return l[0]
	}
	if v, ok := s["default"]; ok {
		return v
	}
	if l, ok := s["enum"].([]any); ok && len(l) > 0 {
		return l[0]
	}
	for _, key := range []string{"oneOf", "anyOf"} {
		if l, ok := s[key].([]any); ok && len(l) > 0 {
			return exampleOf(doc, l[0], depth+1)
		}
	}
	if l, ok := s["allOf"].([]any); ok {
		merged := map[string]any{}
		for _, part := range l {
			if m, ok := exampleOf(doc, part, depth+1).(map[string]any); ok {
				for k, v := range m {
					merged[k] = v
				}
			}
		}
		return merged
	}
	typ, _ := s["type"].(string)
	if l, ok := s["type"].([]any); ok {
		for _, t := range l {
			if ts, _ := t.(string); ts != "null" {
				typ = ts
				break
			}
		}
	}
	switch typ {
	case "object":
		obj := map[string]any{}
		props, _ := s["properties"].(map[string]any)
		for name, p := range props {
			obj[name] = exampleOf(doc, p, depth+1)
		}
		return obj
	case "array":
		if item := exampleOf(doc, s["items"], depth+1); item != nil {
			return []any{item}
		}
		return []any{}
	case "integer", "number":
		if v, ok := s["minimum"]; ok {
			return v
		}
		return 1
	case "boolean":
		return false
	default:
		n, _ := s["minLength"].(int)
		return strings.Repeat("a", max(n, 1))
	}
}

func FuzzOpenAPIInputs(f *testing.F) {
	routes := fuzzRoutes(f)
	require.NotEmpty(f, routes)
	s, c, admin := installed(f)
	operator := s.createUser(c, admin, "olga", "operator", operatorPassword)
	s.stepUp(c, admin)
	for i, r := range routes {
		f.Add(uint8(i), r.seed)
	}

	n := 0
	f.Fuzz(func(t *testing.T, idx uint8, body []byte) {
		// A *testing.F may not be used inside the fuzz target (f.Helper panics): the harness
		// reports through the iteration's own t. Iterations of one process run one at a time.
		s.t = t
		r := routes[int(idx)%len(routes)]
		n++
		s.clock.Advance(250 * time.Millisecond) // the general limit is 300 requests a minute
		if n%fuzzRefreshEvery == 0 {
			fuzzRefreshSession(t, s, c, admin)
		}
		path := fuzzPath(r.path, operator.id)
		rec := fuzzSend(s, c, r.method, path, body)

		s.logs.mu.Lock()
		logged := s.logs.b.String()
		s.logs.b.Reset() // bounded memory over a long run
		s.logs.mu.Unlock()
		if strings.Contains(logged, "request handler panicked") || strings.Contains(logged, "response encoding failed") {
			t.Fatalf("%s %s: the handler panicked (request body %q)", r.method, path, body)
		}
		if rec.Code == http.StatusInternalServerError {
			t.Fatalf("%s %s: 500 for body %q: %s", r.method, path, body, rec.Body.String())
		}
	})
}

// fuzzPath fills the path parameters: the operator's id for a user, a fixed identifier otherwise.
func fuzzPath(path, operatorID string) string {
	if strings.HasPrefix(path, "/api/v1/users/{id}") {
		path = strings.Replace(path, "{id}", operatorID, 1)
	}
	for _, p := range []string{"{id}", "{key_id}", "{certificate_id}", "{version_id}"} {
		path = strings.ReplaceAll(path, p, "3f2b8c1e-5d4a-4b7e-9a10-0c1d2e3f4a5b")
	}
	return path
}

// fuzzSend sends one request as the browser of c does, without recording it (the stack's exchange
// log would grow without bound over a long run).
func fuzzSend(s *stack, c *client, method, path string, body []byte) *httptest.ResponseRecorder {
	ifMatch := `"1"`
	if method == http.MethodPut && (strings.HasPrefix(path, "/api/v1/settings/") || path == "/api/v1/sso/settings") {
		// Settings carry a version: read it, or every request would end at the precondition (412)
		// before its body is looked at.
		if tag := fuzzSend(s, c, http.MethodGet, path, nil).Header().Get("ETag"); tag != "" {
			ifMatch = tag
		}
	}
	req := httptest.NewRequest(method, "https://alice.test"+path, bytes.NewReader(body))
	req.RemoteAddr = c.ip + ":40000"
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Origin", "https://alice.test")
	req.Header.Set("Sec-Fetch-Site", "same-origin")
	req.Header.Set(activityHeader, "1")
	req.Header.Set("If-Match", ifMatch)
	if c.csrf != "" {
		req.Header.Set("X-CSRF-Token", c.csrf)
	}
	for name, value := range c.cookies {
		req.AddCookie(&http.Cookie{Name: name, Value: value})
	}
	rec := httptest.NewRecorder()
	s.handler.ServeHTTP(rec, req)
	// Keep the cookies the server sets or clears, as c.do does.
	for _, ck := range responseCookies(rec) {
		if ck.MaxAge < 0 || ck.Value == "" {
			delete(c.cookies, ck.Name)
		} else {
			c.cookies[ck.Name] = ck.Value
		}
	}
	return rec
}

// fuzzRefreshSession signs the Administrator in again and steps up, so a long run keeps its
// authority however far the fake clock has moved.
func fuzzRefreshSession(t *testing.T, s *stack, c *client, admin *account) {
	t.Helper()
	s.clock.Advance(31 * time.Second)
	rec := c.do(http.MethodPost, "/api/v1/auth/login", map[string]string{"username": admin.username, "password": admin.password})
	requireStatus(t, rec, http.StatusOK)
	requireStatus(t, c.do(http.MethodPost, "/api/v1/auth/mfa/verify", map[string]string{"code": s.totpNow(admin.secret)}), http.StatusOK)
	s.stepUp(c, admin)
	s.mu.Lock()
	s.exchanges = nil // the requests above were recorded
	s.mu.Unlock()
}

// The seeds are meant to be understood by the handlers: as the stepped-up Administrator none of
// them is turned away for want of a session (401), CSRF or authority (403 other than the license).
// Without this the fuzz target could run for hours against a locked door.
func TestFuzzOpenAPISeedsReachTheHandlers(t *testing.T) {
	s, c, admin := installed(t)
	operator := s.createUser(c, admin, "olga", "operator", operatorPassword)
	s.stepUp(c, admin)
	routes := fuzzRoutes(t)
	require.GreaterOrEqual(t, len(routes), 35, "create and update routes with a JSON body")
	counts := map[int]int{}
	for _, r := range routes {
		rec := fuzzSend(s, c, r.method, fuzzPath(r.path, operator.id), r.seed)
		counts[rec.Code]++
		t.Logf("%-3d %s", rec.Code, r.name())
		require.NotEqual(t, http.StatusInternalServerError, rec.Code, r.name())
		require.NotEqual(t, http.StatusUnauthorized, rec.Code, "%s: the session works", r.name())
		require.NotEqual(t, http.StatusTooManyRequests, rec.Code, "%s: the pace stays under the limits", r.name())
		s.clock.Advance(250 * time.Millisecond)
	}
	require.Positive(t, counts[http.StatusNotFound]+counts[http.StatusUnprocessableEntity]+counts[http.StatusConflict]+counts[http.StatusBadRequest],
		"some seeds are answered by the handlers' own validation")
}
