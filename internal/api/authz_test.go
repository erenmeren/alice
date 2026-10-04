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

	"alice/internal/license"
	"alice/internal/rbac"
)

var update = flag.Bool("update", false, "rewrite docs/authz-matrix.md from the route table")

// Matrix identities (see as() and identityAuth).
var identities = []string{
	"", "expired", "disabled", "pending", "setup",
	"admin", "operator", "auditor",
	"admin-stepup", "operator-stepup", "auditor-stepup",
	"alice_read_admin", "alice_operate_operator", "alice_read_auditor",
	"alice_operate_admin",
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
	// token operate (operator), token read (auditor), token operate (admin)
	rbac.Public:         row(allw, allw, allw, allw, allw, allw, allw, allw, allw, allw, allw, allw, allw, allw, allw),
	rbac.Setup:          row(unau, unau, unau, forb, allw, forb, forb, forb, forb, forb, forb, forb, forb, forb, forb),
	rbac.MFAPending:     row(unau, unau, unau, allw, forb, forb, forb, forb, forb, forb, forb, forb, forb, forb, forb),
	rbac.Session:        row(unau, unau, unau, unau, unau, allw, allw, allw, allw, allw, allw, forb, forb, forb, forb),
	rbac.SessionStepUp:  row(unau, unau, unau, unau, unau, step, step, step, allw, allw, allw, forb, forb, forb, forb),
	rbac.Read:           row(unau, unau, unau, unau, unau, allw, allw, allw, allw, allw, allw, allw, allw, allw, allw),
	rbac.AuditRead:      row(unau, unau, unau, unau, unau, allw, forb, allw, allw, forb, allw, allw, forb, allw, allw),
	rbac.UsersRead:      row(unau, unau, unau, unau, unau, allw, forb, forb, allw, forb, forb, allw, forb, forb, allw),
	rbac.UsersManage:    row(unau, unau, unau, unau, unau, step, forb, forb, allw, forb, forb, forb, forb, forb, forb),
	rbac.SettingsManage: row(unau, unau, unau, unau, unau, step, forb, forb, allw, forb, forb, forb, forb, forb, forb),
	rbac.LicenseRead:    row(unau, unau, unau, unau, unau, allw, forb, allw, allw, forb, allw, allw, forb, allw, allw),
	rbac.LicenseManage:  row(unau, unau, unau, unau, unau, step, forb, forb, allw, forb, forb, forb, forb, forb, forb),

	rbac.TargetsManage:    row(unau, unau, unau, unau, unau, allw, forb, forb, allw, forb, forb, forb, forb, forb, allw),
	rbac.HostKeysConfirm:  row(unau, unau, unau, unau, unau, allw, forb, forb, allw, forb, forb, forb, forb, forb, forb),
	rbac.HostKeysRepin:    row(unau, unau, unau, unau, unau, step, forb, forb, allw, forb, forb, forb, forb, forb, forb),
	rbac.InventoryOperate: row(unau, unau, unau, unau, unau, allw, allw, forb, allw, allw, forb, forb, allw, forb, allw),
	rbac.JobsConfirm:      row(unau, unau, unau, unau, unau, allw, forb, forb, allw, forb, forb, forb, forb, forb, forb),

	rbac.CertificatesOperate: row(unau, unau, unau, unau, unau, allw, allw, forb, allw, allw, forb, forb, allw, forb, allw),
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
	b.WriteString("In lock: whether the operation still works after the license (or the evaluation) has expired;\n")
	b.WriteString("changes to managed systems are refused with ALC-LIC-0001 (spec R9).\n\n")
	b.WriteString("| Method | Path | Permission | Anonymous | Admin | Operator | Auditor | API token | Step-up | In lock |\n")
	b.WriteString("|---|---|---|---|---|---|---|---|---|---|\n")
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
		inLock := "yes"
		if gated(rt.lic) {
			inLock = "no"
		}
		fmt.Fprintf(&b, "| %s | `%s` | `%s` | %s | %s | %s | %s | %s | %s | %s |\n",
			rt.method, rt.pattern, rt.perm, anon, role(rbac.Admin), role(rbac.Operator), role(rbac.Auditor), token, yesNo(pol.StepUp), inLock)
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
// SEC-025), settings and the setup steps after the administrator exists
// (recovery passphrase, completion) need settings.manage, and the audit log
// needs audit.read. Servers need targets.manage to change, host-key confirmation and re-pinning
// have their own permissions, test/discovery/key removal need inventory.operate, confirming or
// discarding paused jobs needs jobs.confirm, and every other read of these groups is read. No
// permission may accept API tokens and require step-up at once (tokens can never step up).
func routeRuleViolations(routes []route) []string {
	var out []string
	for _, rt := range routes {
		var want rbac.Permission
		switch p := rt.pattern; {
		case p == "/api/v1/license/status":
			want = rbac.Read
		case under(p, "/api/v1/license") && !safeMethod(rt.method):
			want = rbac.LicenseManage
		case under(p, "/api/v1/license"):
			want = rbac.LicenseRead
		case strings.HasSuffix(p, "/host-keys/{key_id}/actions/confirm"):
			want = rbac.HostKeysConfirm
		case strings.HasSuffix(p, "/host-keys/{key_id}/actions/repin"):
			want = rbac.HostKeysRepin
		case under(p, "/api/v1/targets") && (strings.HasSuffix(p, "/actions/test") || strings.HasSuffix(p, "/actions/discover")):
			want = rbac.InventoryOperate
		case under(p, "/api/v1/targets") && !safeMethod(rt.method):
			want = rbac.TargetsManage
		case p == "/api/v1/ssh-keys/platform-key":
			want = rbac.TargetsManage
		case under(p, "/api/v1/ssh-keys") && !safeMethod(rt.method):
			want = rbac.InventoryOperate
		case under(p, "/api/v1/jobs") && !safeMethod(rt.method):
			want = rbac.JobsConfirm
		case under(p, "/api/v1/certificates") && !safeMethod(rt.method):
			want = rbac.CertificatesOperate
		case under(p, "/api/v1/locations") && !safeMethod(rt.method):
			want = rbac.TargetsManage
		case under(p, "/api/v1/deployments") && !safeMethod(rt.method):
			want = rbac.CertificatesOperate
		case under(p, "/api/v1/targets"), under(p, "/api/v1/ssh-keys"), under(p, "/api/v1/jobs"), under(p, "/api/v1/providers"),
			under(p, "/api/v1/certificates"), under(p, "/api/v1/locations"), under(p, "/api/v1/deployments"):
			want = rbac.Read
		case under(p, "/api/v1/users") && !safeMethod(rt.method):
			want = rbac.UsersManage
		case under(p, "/api/v1/users"):
			want = rbac.UsersRead
		case p == "/api/v1/tokens" && rt.method == http.MethodPost:
			want = rbac.SessionStepUp
		case under(p, "/api/v1/tokens"):
			want = rbac.Session
		case under(p, "/api/v1/settings"), p == "/api/v1/setup/recovery-passphrase", p == "/api/v1/setup/complete", p == "/api/v1/setup/evaluation":
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
	routes := newServer(Deps{}).apiRoutes()
	assert.Empty(t, routeRuleViolations(routes))
	// The rules must not pass vacuously: the sensitive routes that exist so far are in the table.
	var table []string
	for _, rt := range routes {
		table = append(table, rt.method+" "+rt.pattern)
	}
	for _, k := range []string{
		"POST /api/v1/setup/recovery-passphrase",
		"POST /api/v1/setup/complete",
		"POST /api/v1/setup/evaluation",
		"POST /api/v1/auth/recovery-codes",
		"GET /api/v1/users",
		"POST /api/v1/users",
		"GET /api/v1/users/{id}",
		"PATCH /api/v1/users/{id}",
		"POST /api/v1/users/{id}/actions/reset-mfa",
		"POST /api/v1/users/{id}/actions/reset-password",
		"POST /api/v1/users/{id}/actions/revoke-sessions",
		"GET /api/v1/tokens",
		"POST /api/v1/tokens",
		"DELETE /api/v1/tokens/{id}",
		"GET /api/v1/audit",
		"GET /api/v1/audit/export",
		"POST /api/v1/audit/verify",
		"GET /api/v1/license/status",
		"GET /api/v1/license",
		"POST /api/v1/license/preview",
		"POST /api/v1/license",
		"GET /api/v1/providers",
		"GET /api/v1/targets",
		"POST /api/v1/targets",
		"GET /api/v1/targets/{id}",
		"PATCH /api/v1/targets/{id}",
		"DELETE /api/v1/targets/{id}",
		"POST /api/v1/targets/{id}/actions/test",
		"POST /api/v1/targets/{id}/actions/discover",
		"GET /api/v1/targets/{id}/host-keys",
		"POST /api/v1/targets/{id}/host-keys/{key_id}/actions/confirm",
		"POST /api/v1/targets/{id}/host-keys/{key_id}/actions/repin",
		"GET /api/v1/targets/{id}/ssh-keys",
		"GET /api/v1/ssh-keys",
		"GET /api/v1/ssh-keys/platform-key",
		"GET /api/v1/ssh-keys/{id}",
		"POST /api/v1/ssh-keys/locations/{id}/actions/remove",
		"GET /api/v1/jobs",
		"GET /api/v1/jobs/{id}",
		"POST /api/v1/jobs/{id}/actions/confirm",
		"POST /api/v1/jobs/{id}/actions/discard",
		"GET /api/v1/certificates",
		"GET /api/v1/certificates/{id}",
		"POST /api/v1/certificates/upload",
		"POST /api/v1/certificates/{id}/deploy",
		"GET /api/v1/certificates/csr",
		"POST /api/v1/certificates/csr",
		"GET /api/v1/certificates/csr/{id}",
		"POST /api/v1/certificates/csr/{id}/actions/complete",
		"POST /api/v1/certificates/csr/{id}/actions/cancel",
		"GET /api/v1/targets/{id}/certificate-locations",
		"PATCH /api/v1/locations/{id}",
		"GET /api/v1/deployments",
		"GET /api/v1/deployments/{id}",
	} {
		assert.Contains(t, table, k)
	}
}

func TestRouteRuleViolationsCatchesWeakPermissions(t *testing.T) {
	bad := []route{
		{method: http.MethodPatch, pattern: "/api/v1/users/{id}", perm: rbac.UsersRead},
		{method: http.MethodGet, pattern: "/api/v1/users", perm: rbac.Read},
		{method: http.MethodPost, pattern: "/api/v1/tokens", perm: rbac.Session},
		{method: http.MethodDelete, pattern: "/api/v1/tokens/{id}", perm: rbac.Read},
		{method: http.MethodPut, pattern: "/api/v1/settings/locale", perm: rbac.Session},
		{method: http.MethodPost, pattern: "/api/v1/setup/recovery-passphrase", perm: rbac.Session},
		{method: http.MethodPost, pattern: "/api/v1/setup/complete", perm: rbac.Session},
		{method: http.MethodPost, pattern: "/api/v1/setup/evaluation", perm: rbac.Session},
		{method: http.MethodGet, pattern: "/api/v1/audit/export", perm: rbac.Read},
		{method: http.MethodGet, pattern: "/api/v1/license/status", perm: rbac.LicenseRead},
		{method: http.MethodGet, pattern: "/api/v1/license", perm: rbac.Read},
		{method: http.MethodPost, pattern: "/api/v1/license/preview", perm: rbac.LicenseRead},
		{method: http.MethodPost, pattern: "/api/v1/targets", perm: rbac.InventoryOperate},
		{method: http.MethodDelete, pattern: "/api/v1/targets/{id}", perm: rbac.Read},
		{method: http.MethodPost, pattern: "/api/v1/targets/{id}/actions/test", perm: rbac.TargetsManage},
		{method: http.MethodPost, pattern: "/api/v1/targets/{id}/host-keys/{key_id}/actions/confirm", perm: rbac.TargetsManage},
		{method: http.MethodPost, pattern: "/api/v1/targets/{id}/host-keys/{key_id}/actions/repin", perm: rbac.HostKeysConfirm},
		{method: http.MethodGet, pattern: "/api/v1/targets/{id}/host-keys", perm: rbac.TargetsManage},
		{method: http.MethodGet, pattern: "/api/v1/ssh-keys/platform-key", perm: rbac.Read},
		{method: http.MethodPost, pattern: "/api/v1/ssh-keys/locations/{id}/actions/remove", perm: rbac.Read},
		{method: http.MethodPost, pattern: "/api/v1/jobs/{id}/actions/confirm", perm: rbac.InventoryOperate},
		{method: http.MethodPost, pattern: "/api/v1/jobs/{id}/actions/discard", perm: rbac.InventoryOperate},
		{method: http.MethodGet, pattern: "/api/v1/jobs", perm: rbac.JobsConfirm},
		{method: http.MethodGet, pattern: "/api/v1/providers", perm: rbac.Session},
		{method: http.MethodPost, pattern: "/api/v1/certificates/upload", perm: rbac.InventoryOperate},
		{method: http.MethodPost, pattern: "/api/v1/certificates/{id}/deploy", perm: rbac.Read},
		{method: http.MethodPost, pattern: "/api/v1/certificates/csr/{id}/actions/cancel", perm: rbac.TargetsManage},
		{method: http.MethodPatch, pattern: "/api/v1/locations/{id}", perm: rbac.CertificatesOperate},
		{method: http.MethodGet, pattern: "/api/v1/deployments", perm: rbac.CertificatesOperate},
		{method: http.MethodGet, pattern: "/api/v1/certificates/{id}", perm: rbac.CertificatesOperate},
		{method: http.MethodGet, pattern: "/api/v1/targets/{id}/certificate-locations", perm: rbac.TargetsManage},
	}
	assert.Len(t, routeRuleViolations(bad), len(bad))
	good := []route{
		{method: http.MethodPatch, pattern: "/api/v1/users/{id}", perm: rbac.UsersManage},
		{method: http.MethodGet, pattern: "/api/v1/users/{id}", perm: rbac.UsersRead},
		{method: http.MethodPost, pattern: "/api/v1/tokens", perm: rbac.SessionStepUp},
		{method: http.MethodGet, pattern: "/api/v1/tokens", perm: rbac.Session},
		{method: http.MethodPost, pattern: "/api/v1/setup/recovery-passphrase", perm: rbac.SettingsManage},
		{method: http.MethodPost, pattern: "/api/v1/setup/complete", perm: rbac.SettingsManage},
		{method: http.MethodPost, pattern: "/api/v1/setup/evaluation", perm: rbac.SettingsManage},
		{method: http.MethodPost, pattern: "/api/v1/audit/verify", perm: rbac.AuditRead},
		{method: http.MethodGet, pattern: "/api/v1/usersettings", perm: rbac.Session},
		{method: http.MethodGet, pattern: "/api/v1/license/status", perm: rbac.Read},
		{method: http.MethodGet, pattern: "/api/v1/license", perm: rbac.LicenseRead},
		{method: http.MethodPost, pattern: "/api/v1/license", perm: rbac.LicenseManage},
		{method: http.MethodPost, pattern: "/api/v1/targets", perm: rbac.TargetsManage},
		{method: http.MethodPost, pattern: "/api/v1/targets/{id}/actions/discover", perm: rbac.InventoryOperate},
		{method: http.MethodPost, pattern: "/api/v1/targets/{id}/host-keys/{key_id}/actions/repin", perm: rbac.HostKeysRepin},
		{method: http.MethodGet, pattern: "/api/v1/ssh-keys/{id}", perm: rbac.Read},
		{method: http.MethodGet, pattern: "/api/v1/ssh-keys/platform-key", perm: rbac.TargetsManage},
		{method: http.MethodPost, pattern: "/api/v1/jobs/{id}/actions/discard", perm: rbac.JobsConfirm},
		{method: http.MethodPost, pattern: "/api/v1/certificates/upload", perm: rbac.CertificatesOperate},
		{method: http.MethodPost, pattern: "/api/v1/certificates/{id}/deploy", perm: rbac.CertificatesOperate},
		{method: http.MethodPost, pattern: "/api/v1/certificates/csr/{id}/actions/cancel", perm: rbac.CertificatesOperate},
		{method: http.MethodPatch, pattern: "/api/v1/locations/{id}", perm: rbac.TargetsManage},
		{method: http.MethodGet, pattern: "/api/v1/deployments", perm: rbac.Read},
		{method: http.MethodGet, pattern: "/api/v1/certificates/{id}", perm: rbac.Read},
		{method: http.MethodGet, pattern: "/api/v1/targets/{id}/certificate-locations", perm: rbac.Read},
	}
	assert.Empty(t, routeRuleViolations(good))
}

// Route groups and how lock mode treats their state-changing operations (R9, R36 item 6).
var (
	lockAvailable = []string{"/api/v1/auth", "/api/v1/setup", "/api/v1/license", "/api/v1/users", "/api/v1/tokens",
		"/api/v1/audit", "/api/v1/backup", "/api/v1/backups", "/api/v1/settings"}
	lockRefused = []string{"/api/v1/targets", "/api/v1/certificates", "/api/v1/locations", "/api/v1/deployments",
		"/api/v1/ssh-keys", "/api/v1/rotation", "/api/v1/keyvault", "/api/v1/jobs"}
)

func underAny(pattern string, prefixes []string) bool {
	for _, p := range prefixes {
		if under(pattern, p) {
			return true
		}
	}
	return false
}

// lockRuleViolations: reads are never refused in lock; every state-changing route declares a
// license class and belongs to exactly one of the two lock lists; infrastructure routes are
// gated (ClassChange or ClassReadOnly); platform administration is ClassAlways; a route that
// has no signed-in user (public, setup session, pending sign-in) is never gated, because the
// gate's refusal is audited per user and would lock everyone out of it.
func lockRuleViolations(routes []route) []string {
	var out []string
	for _, rt := range routes {
		key := rt.method + " " + rt.pattern
		pol, known := rbac.PolicyFor(rt.perm)
		if !known {
			// An unknown permission would also skip the signed-in-user rule below.
			out = append(out, key+": unknown permission")
			continue
		}
		if safeMethod(rt.method) {
			if rt.lic != license.ClassUnset && rt.lic != license.ClassAlways {
				out = append(out, key+": reads stay available in lock")
			}
			continue
		}
		if (pol.Anonymous || pol.Setup || pol.Pending) && gated(rt.lic) {
			out = append(out, key+": a route without a signed-in user is never refused by the license gate")
		}
		refused, available := underAny(rt.pattern, lockRefused), underAny(rt.pattern, lockAvailable)
		switch {
		case !rt.lic.Valid():
			out = append(out, key+": declares no license class")
		case refused && available:
			out = append(out, key+": route group is in both lock lists")
		case refused && !gated(rt.lic):
			out = append(out, key+": infrastructure work must be refused in lock (ClassChange or ClassReadOnly)")
		case available && rt.lic != license.ClassAlways:
			out = append(out, key+": platform administration must stay available (ClassAlways)")
		case !refused && !available:
			out = append(out, key+": route group is in neither lock list")
		}
	}
	return out
}

func TestEveryStateChangingRouteDeclaresALicenseClass(t *testing.T) {
	assert.Empty(t, lockRuleViolations(newServer(Deps{}).apiRoutes()))
}

func TestLockRuleViolationsCatchesMistakes(t *testing.T) {
	bad := []route{
		{method: http.MethodPost, pattern: "/api/v1/users", perm: rbac.UsersManage},
		{method: http.MethodPost, pattern: "/api/v1/targets", perm: rbac.Read, lic: license.ClassAlways},
		{method: http.MethodDelete, pattern: "/api/v1/ssh-keys/{id}", perm: rbac.Read, lic: license.ClassAlways},
		{method: http.MethodPost, pattern: "/api/v1/license", perm: rbac.LicenseManage, lic: license.ClassChange},
		{method: http.MethodGet, pattern: "/api/v1/targets", perm: rbac.Read, lic: license.ClassChange},
		// Carry 1: a group in neither list, a gated public route, an ungated infrastructure route.
		{method: http.MethodPost, pattern: "/api/v1/widgets", perm: rbac.Read, lic: license.ClassAlways},
		{method: http.MethodPost, pattern: "/api/v1/targets", perm: rbac.Public, lic: license.ClassChange},
		{method: http.MethodPost, pattern: "/api/v1/jobs/{id}/actions/confirm", perm: rbac.Read, lic: license.ClassAlways},
		{method: http.MethodPost, pattern: "/api/v1/targets/{id}/actions/test", perm: rbac.Setup, lic: license.ClassReadOnly},
		// Fix wave C-9: a gated route of a pending sign-in, and permissions the policy table does
		// not know (otherwise valid routes, so the unknown permission is their only violation).
		{method: http.MethodPost, pattern: "/api/v1/targets", perm: rbac.MFAPending, lic: license.ClassChange},
		{method: http.MethodPost, pattern: "/api/v1/targets", perm: "targets.nonexistent", lic: license.ClassChange},
		{method: http.MethodGet, pattern: "/api/v1/targets", perm: "targets.nonexistent"},
	}
	for _, rt := range bad {
		assert.Len(t, lockRuleViolations([]route{rt}), 1, "%s %s", rt.method, rt.pattern)
	}
	// A route group in both lock lists is a mistake in the lists themselves.
	saved := lockAvailable
	lockAvailable = append(append([]string{}, saved...), "/api/v1/targets")
	both := lockRuleViolations([]route{{method: http.MethodPost, pattern: "/api/v1/targets", perm: rbac.Read, lic: license.ClassChange}})
	lockAvailable = saved
	assert.Equal(t, []string{"POST /api/v1/targets: route group is in both lock lists"}, both)
	good := []route{
		{method: http.MethodPost, pattern: "/api/v1/targets", perm: rbac.Read, lic: license.ClassChange},
		{method: http.MethodPost, pattern: "/api/v1/targets/{id}/actions/test", perm: rbac.Read, lic: license.ClassReadOnly},
		{method: http.MethodPost, pattern: "/api/v1/users", perm: rbac.UsersManage, lic: license.ClassAlways},
		{method: http.MethodPost, pattern: "/api/v1/setup/session", perm: rbac.Public, lic: license.ClassAlways},
		{method: http.MethodGet, pattern: "/api/v1/targets", perm: rbac.Read},
		{method: http.MethodGet, pattern: "/api/v1/widgets", perm: rbac.Read},
	}
	assert.Empty(t, lockRuleViolations(good))
}

// TestRouteTableInLock sends every route in the table while the license is locked, as the
// first matrix identity that is allowed to use it: platform administration, sign-in and all
// reads still reach their handler (R9, R36 item 6); only ClassChange/ClassReadOnly routes are
// refused with license.locked.
func TestRouteTableInLock(t *testing.T) {
	d := testDeps(t, nil)
	d.License.(*fakeLicense).set(license.ErrLocked)
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
	for _, rt := range routes {
		id := ""
		for _, candidate := range identities {
			if expectedMatrix[rt.perm][candidate] == allw {
				id = candidate
				break
			}
		}
		name := fmt.Sprintf("%s %s as %q", rt.method, rt.pattern, id)
		(&Server{s: s}).ResetLimits()
		called = false
		rec := call(h, rt.method, pathParamRE.ReplaceAllString(rt.pattern, uuid.NewString()), id, "")
		if gated(rt.lic) {
			assert.Equal(t, http.StatusForbidden, rec.Code, name)
			assert.Equal(t, "license.locked", decodeErr(t, rec).Error.Reason, name)
			assert.False(t, called, name)
			continue
		}
		assert.Equal(t, http.StatusOK, rec.Code, name)
		assert.True(t, called, name)
	}
}
