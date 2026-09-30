package api

import (
	"flag"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"alice/internal/rbac"
)

var update = flag.Bool("update", false, "rewrite docs/authz-matrix.md from the route table")

// Matrix identities (see as() and identityAuth).
var identities = []string{
	"", "expired", "disabled", "pending", "setup",
	"admin", "operator", "auditor",
	"admin-stepup", "operator-stepup", "auditor-stepup",
	"alice_read_admin", "alice_operate_operator", "alice_read_auditor",
}

const (
	allw = http.StatusOK
	unau = http.StatusUnauthorized
	forb = http.StatusForbidden
	step = 4031 // 403 with auth.stepup_required
)

// expectedMatrix is the documented role table (spec §15.4, decisions R3,
// §25.1) written out by hand. It is deliberately NOT computed from
// rbac.Decide: a wrong policy must make this test fail.
var expectedMatrix = map[rbac.Permission]map[string]int{
	// columns: anonymous, expired, disabled, pending, setup, admin, operator, auditor,
	// admin+step-up, operator+step-up, auditor+step-up, token read (admin),
	// token operate (operator), token read (auditor)
	rbac.Public:         row(allw, allw, allw, allw, allw, allw, allw, allw, allw, allw, allw, allw, allw, allw),
	rbac.Setup:          row(unau, unau, unau, forb, allw, forb, forb, forb, forb, forb, forb, forb, forb, forb),
	rbac.MFAPending:     row(unau, unau, unau, allw, forb, forb, forb, forb, forb, forb, forb, forb, forb, forb),
	rbac.Session:        row(unau, unau, unau, unau, unau, allw, allw, allw, allw, allw, allw, forb, forb, forb),
	rbac.SessionStepUp:  row(unau, unau, unau, unau, unau, step, step, step, allw, allw, allw, forb, forb, forb),
	rbac.Read:           row(unau, unau, unau, unau, unau, allw, allw, allw, allw, allw, allw, allw, allw, allw),
	rbac.AuditRead:      row(unau, unau, unau, unau, unau, allw, forb, allw, allw, forb, allw, allw, forb, allw),
	rbac.UsersRead:      row(unau, unau, unau, unau, unau, allw, forb, forb, allw, forb, forb, allw, forb, forb),
	rbac.UsersManage:    row(unau, unau, unau, unau, unau, step, forb, forb, allw, forb, forb, forb, forb, forb),
	rbac.SettingsManage: row(unau, unau, unau, unau, unau, step, forb, forb, allw, forb, forb, forb, forb, forb),
	rbac.SetupFinish:    row(unau, unau, unau, unau, unau, allw, forb, forb, allw, forb, forb, forb, forb, forb),
}

func row(codes ...int) map[string]int {
	m := map[string]int{}
	for i, c := range codes {
		m[identities[i]] = c
	}
	return m
}

// authenticatedUser reports whether a denial for this identity must be audited.
func authenticatedUser(id string) bool {
	return id != "" && id != "expired" && id != "disabled" && id != "pending" && id != "setup"
}

// TestAuthzMatrix sends every route in the table as every identity and checks
// the status, that forbidden requests never reach the handler, and that
// authenticated denials are audited (spec §25.1, SEC-016).
func TestAuthzMatrix(t *testing.T) {
	d := testDeps(t, nil)
	s := newServer(d)
	routes := s.apiRoutes()
	var called bool
	for i := range routes {
		routes[i].handler = func(w http.ResponseWriter, _ *http.Request) {
			called = true
			w.WriteHeader(http.StatusOK)
		}
	}
	h := s.handler(routes)
	fa := d.Audit.(*fakeAudit)

	for _, rt := range routes {
		want, known := expectedMatrix[rt.perm]
		require.True(t, known, "permission %q of %s %s has no row in expectedMatrix", rt.perm, rt.method, rt.pattern)
		target := pathParamRE.ReplaceAllString(rt.pattern, uuid.NewString())
		for _, id := range identities {
			(&Server{s: s}).ResetLimits()
			called = false
			before := fa.Count("authz.denied")
			rec := call(h, rt.method, target, id, "")
			name := fmt.Sprintf("%s %s as %q", rt.method, rt.pattern, id)

			switch w := want[id]; w {
			case allw:
				assert.Equal(t, http.StatusOK, rec.Code, name)
				assert.True(t, called, name)
			case step:
				assert.Equal(t, http.StatusForbidden, rec.Code, name)
				assert.Equal(t, "auth.stepup_required", decodeErr(t, rec).Error.Reason, name)
			default:
				assert.Equal(t, w, rec.Code, name)
			}
			if want[id] != allw {
				assert.False(t, called, "handler must not run: %s", name)
				assert.NotContains(t, rec.Body.String(), "\"items\"", name)
			}
			denied := want[id] == forb || want[id] == step
			if denied && authenticatedUser(id) {
				assert.Equal(t, before+1, fa.Count("authz.denied"), "denial must be audited: %s", name)
			} else {
				assert.Equal(t, before, fa.Count("authz.denied"), "no audit expected: %s", name)
			}
		}
	}
}

// Every permission rbac knows is covered by the hand-written table.
func TestExpectedMatrixCoversEveryPermission(t *testing.T) {
	for _, p := range rbac.Permissions() {
		_, ok := expectedMatrix[p]
		assert.True(t, ok, "expectedMatrix lacks %q", p)
	}
}

func yesNo(b bool) string {
	if b {
		return "yes"
	}
	return "no"
}

// authzMatrixDoc renders docs/authz-matrix.md from the route table and policies.
func authzMatrixDoc() string {
	var b strings.Builder
	b.WriteString("# Authorization matrix\n\n")
	b.WriteString("Generated by `make authz-doc` from the route table in `internal/api` and the policies in\n")
	b.WriteString("`internal/rbac`. Do not edit by hand; CI fails when this file is out of date.\n\n")
	b.WriteString("Anonymous: no sign-in needed. Wizard: only with a setup-wizard session. Pending: only between\n")
	b.WriteString("password and verification code. Token columns: minimum API token access (the token owner's role\n")
	b.WriteString("must also allow the route). Step-up: a fresh verification code (5 minutes) is required.\n\n")
	b.WriteString("| Method | Path | Permission | Anonymous | Admin | Operator | Auditor | API token | Step-up |\n")
	b.WriteString("|---|---|---|---|---|---|---|---|---|\n")
	for _, rt := range newServer(Deps{}).apiRoutes() {
		pol, _ := rbac.PolicyFor(rt.perm)
		anon := yesNo(pol.Anonymous)
		switch {
		case pol.Setup:
			anon = "wizard"
		case pol.Pending:
			anon = "pending"
		}
		role := func(r rbac.Role) string { return yesNo(pol.Anonymous || slices.Contains(pol.Roles, r)) }
		token := "no"
		if pol.Anonymous {
			token = "yes"
		} else if pol.TokenScope != "" {
			token = string(pol.TokenScope)
		}
		fmt.Fprintf(&b, "| %s | `%s` | `%s` | %s | %s | %s | %s | %s | %s |\n",
			rt.method, rt.pattern, rt.perm, anon, role(rbac.Admin), role(rbac.Operator), role(rbac.Auditor), token, yesNo(pol.StepUp))
	}
	return b.String()
}

func TestAuthzMatrixDocIsCurrent(t *testing.T) {
	path := filepath.Join("..", "..", "docs", "authz-matrix.md")
	want := authzMatrixDoc()
	if *update {
		require.NoError(t, os.WriteFile(path, []byte(want), 0o644))
	}
	got, err := os.ReadFile(path)
	require.NoError(t, err, "run: make authz-doc")
	assert.Equal(t, want, string(got), "docs/authz-matrix.md is stale; run: make authz-doc")
}

// TestNoRouteBypassesTable parses the package's non-test sources and allows
// Handle/HandleFunc calls only inside register (the guarded route table) and
// for the documented catch-alls "/api/", "/test/" and "/" (spec §25.1).
func TestNoRouteBypassesTable(t *testing.T) {
	files, err := filepath.Glob("*.go")
	require.NoError(t, err)
	allowedLiterals := map[string]bool{`"/api/"`: true, `"/test/"`: true, `"/"`: true}
	fset := token.NewFileSet()
	checked := 0
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
				call, ok := n.(*ast.CallExpr)
				if !ok {
					return true
				}
				sel, ok := call.Fun.(*ast.SelectorExpr)
				if !ok || (sel.Sel.Name != "Handle" && sel.Sel.Name != "HandleFunc") || len(call.Args) == 0 {
					return true
				}
				checked++
				pos := fset.Position(call.Pos())
				if lit, ok := call.Args[0].(*ast.BasicLit); ok && allowedLiterals[lit.Value] {
					return true
				}
				if fn.Name.Name == "register" {
					return true
				}
				t.Errorf("%s: %s.%s registers a route outside the route table", pos, fn.Name.Name, sel.Sel.Name)
				return true
			})
		}
	}
	assert.Positive(t, checked, "the scan found no registrations at all; is it looking at the right files?")
}

// under reports whether pattern is prefix or a path below it.
func under(pattern, prefix string) bool {
	return pattern == prefix || strings.HasPrefix(pattern, prefix+"/")
}

// routeRuleViolations checks the permissions the specification fixes for
// sensitive route groups: user administration and settings need an
// administrator's browser session with step-up (SEC-009), token routes are
// for browser sessions only and creating a token needs step-up (SEC-009,
// SEC-025), and the audit log needs audit.read. No permission may accept API
// tokens and require step-up at once (tokens can never step up).
func routeRuleViolations(routes []route) []string {
	var out []string
	for _, rt := range routes {
		var want rbac.Permission
		switch p := rt.pattern; {
		case under(p, "/api/v1/users") && !safeMethod(rt.method):
			want = rbac.UsersManage
		case under(p, "/api/v1/users"):
			want = rbac.UsersRead
		case p == "/api/v1/tokens" && rt.method == http.MethodPost:
			want = rbac.SessionStepUp
		case under(p, "/api/v1/tokens"):
			want = rbac.Session
		case under(p, "/api/v1/settings"), p == "/api/v1/setup/recovery-passphrase":
			want = rbac.SettingsManage
		case under(p, "/api/v1/audit"):
			want = rbac.AuditRead
		}
		key := rt.method + " " + rt.pattern
		if want != "" && rt.perm != want {
			out = append(out, fmt.Sprintf("%s: permission %q, want %q", key, rt.perm, want))
		}
		if pol, ok := rbac.PolicyFor(rt.perm); ok && pol.StepUp && pol.TokenScope != "" {
			out = append(out, fmt.Sprintf("%s: permission %q accepts API tokens but requires step-up", key, rt.perm))
		}
	}
	return out
}

func TestSensitiveRoutesHaveTheirFixedPermissions(t *testing.T) {
	assert.Empty(t, routeRuleViolations(newServer(Deps{}).apiRoutes()))
}

func TestRouteRuleViolationsCatchesWeakPermissions(t *testing.T) {
	bad := []route{
		{method: http.MethodPatch, pattern: "/api/v1/users/{id}", perm: rbac.UsersRead},
		{method: http.MethodGet, pattern: "/api/v1/users", perm: rbac.Read},
		{method: http.MethodPost, pattern: "/api/v1/tokens", perm: rbac.Session},
		{method: http.MethodDelete, pattern: "/api/v1/tokens/{id}", perm: rbac.Read},
		{method: http.MethodPut, pattern: "/api/v1/settings/locale", perm: rbac.Session},
		{method: http.MethodPost, pattern: "/api/v1/setup/recovery-passphrase", perm: rbac.SetupFinish},
		{method: http.MethodGet, pattern: "/api/v1/audit/export", perm: rbac.Read},
	}
	assert.Len(t, routeRuleViolations(bad), len(bad))
	good := []route{
		{method: http.MethodPatch, pattern: "/api/v1/users/{id}", perm: rbac.UsersManage},
		{method: http.MethodGet, pattern: "/api/v1/users/{id}", perm: rbac.UsersRead},
		{method: http.MethodPost, pattern: "/api/v1/tokens", perm: rbac.SessionStepUp},
		{method: http.MethodGet, pattern: "/api/v1/tokens", perm: rbac.Session},
		{method: http.MethodPost, pattern: "/api/v1/setup/recovery-passphrase", perm: rbac.SettingsManage},
		{method: http.MethodPost, pattern: "/api/v1/audit/verify", perm: rbac.AuditRead},
		{method: http.MethodGet, pattern: "/api/v1/usersettings", perm: rbac.Session},
	}
	assert.Empty(t, routeRuleViolations(good))
}
