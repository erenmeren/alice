package api

import (
	"context"
	"go/ast"
	"go/parser"
	"go/token"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"alice/internal/audit"
	"alice/internal/license"
)

// edgeIdentity is a test identity the route's permission lets through (expectedMatrix), so the
// request reaches the handler when nothing else refuses it.
func edgeIdentity(t *testing.T, rt route) string {
	t.Helper()
	want := expectedMatrix[rt.perm]
	for _, id := range identities {
		if want[id] == allw {
			return id
		}
	}
	t.Fatalf("no identity may call %s %s", rt.method, rt.pattern)
	return ""
}

// AUD-13: every route in the table, now and any added later, refuses a query key or value that is
// not valid UTF-8 or holds NUL with 400 ALC-SYS-0004 before its handler runs, naming the parameter
// and never echoing the value; legitimate query text reaches the handler. Every route passes guard
// (TestNoRouteBypassesTable), so a new route cannot escape the check.
func TestEveryRouteRefusesUnstorableQueryText(t *testing.T) {
	d := testDeps(t, nil)
	s := newServer(d)
	routes := s.apiRoutes()
	require.NotEmpty(t, routes)
	var called bool
	for i := range routes {
		routes[i].handler = func(w http.ResponseWriter, _ *http.Request) {
			called = true
			w.WriteHeader(http.StatusOK)
		}
	}
	h := s.handler(routes)
	for _, rt := range routes {
		target := pathParamRE.ReplaceAllString(rt.pattern, uuid.NewString())
		id := edgeIdentity(t, rt)
		for _, tc := range []struct{ query, field string }{
			{"q=a%00b", "q"}, {"os_user=%ff", "os_user"}, {"actor=%C3%28", "actor"}, {"%ff=1", "query"}, {"a%00=1", "query"},
			{"limit=10&cursor=x%00", "cursor"}, {"q=%zz", "query"}, {"a=1;b=2", "query"}, {"from=192.0.2.1%zz", "query"},
		} {
			(&Server{s: s}).ResetLimits()
			called = false
			rec := call(h, rt.method, target+"?"+tc.query, id, "")
			name := rt.method + " " + rt.pattern + "?" + tc.query
			assert.True(t, unstorableRefusal(t, rec.Code, rec.Body.Bytes(), tc.field), "%s: %d %s", name, rec.Code, rec.Body)
			assert.False(t, called, "the handler must not run: %s", name)
			assert.NotContains(t, rec.Body.String(), "\\u0000", name)
			assert.NotContains(t, rec.Body.String(), "\\ufffd", name)
		}
		(&Server{s: s}).ResetLimits()
		called = false
		rec := call(h, rt.method, target+"?q=%2F+a%20b%2B&os_user=d%C4%B1&x=%F0%9F%94%91e%CC%81", id, "")
		assert.Equal(t, http.StatusOK, rec.Code, "%s %s with legitimate query text", rt.method, rt.pattern)
		assert.True(t, called, "%s %s with legitimate query text", rt.method, rt.pattern)
	}
}

// AUD-13: every documented operation with a request body refuses a body whose JSON text decodes to
// NUL with the edge's answer (400 ALC-SYS-0004, details [{field: body, code: validation.pattern}]),
// which only the shared decode helpers produce; an operation documented without a body either never
// reads it or answers the same way. A new route with a body must be documented
// (TestRouteTableMatchesSpec) and must decode through the helpers
// (TestOnlyTheDecodeHelpersReadRequests), or this test fails.
func TestEveryRouteWithABodyRefusesNULText(t *testing.T) {
	withBody := map[string]bool{}
	for _, op := range specOps() {
		withBody[op.key()] = op.has("requestBody:")
	}
	d := testDeps(t, nil)
	s := newServer(d)
	h := s.handler(s.apiRoutes())
	checked := 0
	for _, rt := range s.apiRoutes() {
		if safeMethod(rt.method) {
			continue
		}
		key := rt.method + " " + rt.pattern
		target := pathParamRE.ReplaceAllString(rt.pattern, uuid.NewString())
		(&Server{s: s}).ResetLimits()
		body := &readCounter{r: strings.NewReader(`"\u0000"`)}
		req := as(httptest.NewRequest(rt.method, target, body), edgeIdentity(t, rt))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("If-Match", `"1"`)
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		refused := unstorableRefusal(t, rec.Code, rec.Body.Bytes(), "body")
		if withBody[key] {
			checked++
			assert.True(t, refused, "%s: %d %s", key, rec.Code, rec.Body)
		} else {
			// The fakes answer most of these with errors; what matters is that the body was not read.
			assert.True(t, refused || body.n == 0, "%s reads a body it does not document: %d %s", key, rec.Code, rec.Body)
		}
	}
	assert.Positive(t, checked)
}

// readCounter counts the bytes read from a request body.
type readCounter struct {
	r io.Reader
	n int
}

func (c *readCounter) Read(p []byte) (int, error) {
	n, err := c.r.Read(p)
	c.n += n
	return n, err
}

// TestOnlyTheDecodeHelpersReadRequests: request bodies are read only by the decode helpers (which
// run the text check) and path values only by pathUUID (which parses them); no handler reads form
// values. The scan parses the package's non-test sources.
func TestOnlyTheDecodeHelpersReadRequests(t *testing.T) {
	allowed := map[string]map[string]bool{
		// downloadedFile reads the Body of an sshkeys.Download (the file the service built), not a request.
		"Body":      {"readJSON": true, "decodeExact": true, "decodeExactBody": true, "downloadedFile": true},
		"PathValue": {"pathUUID": true},
	}
	forbidden := map[string]bool{"Form": true, "PostForm": true, "FormValue": true, "PostFormValue": true, "ParseForm": true,
		"ParseMultipartForm": true, "MultipartReader": true, "MultipartForm": true, "FormFile": true, "GetBody": true}
	files, err := filepath.Glob("*.go")
	require.NoError(t, err)
	fset := token.NewFileSet()
	seen := map[string]int{}
	for _, name := range files {
		if strings.HasSuffix(name, "_test.go") {
			continue
		}
		f, err := parser.ParseFile(fset, name, nil, 0)
		require.NoError(t, err)
		for _, decl := range f.Decls {
			fn, ok := decl.(*ast.FuncDecl)
			if !ok || fn.Body == nil {
				continue
			}
			ast.Inspect(fn.Body, func(n ast.Node) bool {
				sel, ok := n.(*ast.SelectorExpr)
				if !ok {
					return true
				}
				pos := fset.Position(sel.Pos())
				switch field := sel.Sel.Name; {
				case forbidden[field]:
					t.Errorf("%s: %s reads %s; request text must go through the decode helpers", pos, fn.Name.Name, field)
				case allowed[field] != nil:
					seen[field]++
					if !allowed[field][fn.Name.Name] {
						t.Errorf("%s: %s reads %s; only %v may", pos, fn.Name.Name, field, allowed[field])
					}
				}
				return true
			})
		}
	}
	assert.Positive(t, seen["Body"], "the scan found no body read at all; is it looking at the right files?")
	assert.Positive(t, seen["PathValue"])
}

// S9: a license upload refused at the edge for NUL text still writes license.upload.invalid (as the
// license module does for any file it cannot read), without the file's content; a preview stores
// and audits nothing, and a body refused for another reason is not a license upload.
func TestLicenseUploadWithNULTextIsAudited(t *testing.T) {
	d := testDeps(t, nil)
	h := NewHandler(d)
	fa := d.Audit.(*fakeAudit)
	installs := 0
	d.License.(*fakeLicense).InstallFn = func(context.Context, []byte, audit.Actor, uuid.UUID) (license.UploadResult, error) {
		installs++
		return license.UploadResult{}, nil
	}

	rec := call(h, http.MethodPost, "/api/v1/license", "admin-stepup", `{"license":"{\"a\":\"\u0000\"}"}`)
	require.True(t, unstorableRefusal(t, rec.Code, rec.Body.Bytes(), "body"), "%d %s", rec.Code, rec.Body)
	require.Equal(t, 1, fa.Count("license.upload.invalid"))
	var ev audit.Event
	for _, e := range fa.Events() {
		if e.Action == "license.upload.invalid" {
			ev = e
		}
	}
	assert.Equal(t, audit.Failure, ev.Result)
	assert.Equal(t, "license", ev.ObjectType)
	assert.Equal(t, map[string]string{"reason": "invalid", "problem": "not_json"}, ev.Details)
	// M3: the label is the one the license module itself gives such a file.
	for _, file := range []string{"\x00", "{\"format\":1\x00}", "{\"format\":1,\"payload\":\"\x00\"}", "\uFEFF{\"a\x00\":1}"} {
		_, err := license.ParseFile([]byte(file))
		var inv *license.InvalidError
		require.ErrorAs(t, err, &inv, "%q", file)
		assert.Equal(t, "not_json", inv.Problem, "%q", file)
		assert.Equal(t, "invalid", license.RejectReason(err), "%q", file)
	}
	assert.Equal(t, "admin", ev.Actor.Name)
	assert.Zero(t, installs, "the license module never sees the file")

	rec = call(h, http.MethodPost, "/api/v1/license/preview", "admin-stepup", `{"license":"\u0000"}`)
	require.True(t, unstorableRefusal(t, rec.Code, rec.Body.Bytes(), "body"), "%d %s", rec.Code, rec.Body)
	rec = call(h, http.MethodPost, "/api/v1/license", "admin-stepup", `{"license":1}`)
	require.Equal(t, http.StatusBadRequest, rec.Code)
	assert.Equal(t, 1, fa.Count("license.upload.invalid"), "only the NUL refusal of an upload is audited")
}
