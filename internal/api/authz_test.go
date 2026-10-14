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

	// Phase 5: Administrator with a fresh step-up only, never an API token (S6).
	rbac.CredentialsManage: row(unau, unau, unau, unau, unau, step, forb, forb, allw, forb, forb, forb, forb, forb, forb),

	// Phase 6 (R41 rows 5, 24, 25; S2): the private key download and every rotation action that starts or decides
	// changes on servers are an Administrator's browser session with step-up, never a token; preparing, previewing,
	// switching off, deleting policies and stopping a run (Stop and undo) is an Administrator's, operate tokens included.
	rbac.SSHKeysDownload: row(unau, unau, unau, unau, unau, step, forb, forb, allw, forb, forb, forb, forb, forb, forb),
	rbac.RotationManage:  row(unau, unau, unau, unau, unau, allw, forb, forb, allw, forb, forb, forb, forb, forb, allw),
	rbac.RotationOperate: row(unau, unau, unau, unau, unau, step, forb, forb, allw, forb, forb, forb, forb, forb, forb),

	// Phase 7 (SEC-009, R42 row 24): single sign-on configuration is an Administrator's browser session with step-up.
	rbac.SSOManage: row(unau, unau, unau, unau, unau, step, forb, forb, allw, forb, forb, forb, forb, forb, forb),
	// Phase 8: backups (C12).
	rbac.BackupManage: row(unau, unau, unau, unau, unau, step, forb, forb, allw, forb, forb, forb, forb, forb, forb),

	// ACME issuance (A9): everyone reads; Operators may order, test, deploy and bind existing certificates (operate
	// tokens too); only an Administrator with step-up creates certificates, providers, accounts and hooks (no token).
	rbac.AcmeView:    row(unau, unau, unau, unau, unau, allw, allw, allw, allw, allw, allw, allw, allw, allw, allw),
	rbac.AcmeOperate: row(unau, unau, unau, unau, unau, allw, allw, forb, allw, allw, forb, forb, allw, forb, allw),
	rbac.AcmeManage:  row(unau, unau, unau, unau, unau, step, forb, forb, allw, forb, forb, forb, forb, forb, forb),
	// Reading a CA's directory before registration (fix round 2): an Administrator's browser session, no step-up, no token.
	rbac.AcmePreview: row(unau, unau, unau, unau, unau, allw, forb, forb, allw, forb, forb, forb, forb, forb, forb),

	// Network discovery (A5, D7): every role reads the results in a browser, but a token needs the operate scope (read
	// tokens never read the internal network map; an Auditor holds read tokens only); Admin and Operator start and cancel
	// scans (operate tokens too); only an Administrator with step-up defines scopes, exclusions, allowed networks and
	// retention (no token). No route uses them before Task 9; TestExpectedMatrixCoversEveryPermission needs the rows.
	rbac.DiscoveryView:    row(unau, unau, unau, unau, unau, allw, allw, allw, allw, allw, allw, forb, allw, forb, allw),
	rbac.DiscoveryOperate: row(unau, unau, unau, unau, unau, allw, allw, forb, allw, allw, forb, forb, allw, forb, allw),
	rbac.DiscoveryManage:  row(unau, unau, unau, unau, unau, step, forb, forb, allw, forb, forb, forb, forb, forb, forb),
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
	b.WriteString(authzNotes)
	return b.String()
}

// conditionalRules are the operations whose route permission is weaker than what the request needs in one case:
// the handler then asks for credentials.manage's strength (an Administrator's browser session with a fresh
// step-up, never an API token), and the inventory repeats the check inside its transaction.
var conditionalRules = []struct{ method, path string }{
	{http.MethodDelete, "/api/v1/targets/{id}"},
	{http.MethodPatch, "/api/v1/bindings/{id}"},
	{http.MethodPost, "/api/v1/bindings/{id}/actions/deploy"},
	{http.MethodPut, "/api/v1/acme/certificates/{id}/bindings/{location_id}"},
}

const authzNotes = `
## Notes

**Conditional rules.** These routes are listed above with the permission that every request needs. In the cases below the
request also needs what ` + "`credentials.manage`" + ` needs: an Administrator's browser session with a fresh step-up, and never an
API token (403 ALC-AUTH-0003 without the step-up, 403 ALC-AUTH-0002 for a token or another role).

- ` + "`DELETE /api/v1/targets/{id}?remove_bindings=true`" + `: removing a Key Vault together with its connected websites. Without
  ` + "`remove_bindings`" + ` the route is ` + "`targets.manage`" + ` as listed. The step-up here is a convenience guard, not a boundary: an
  Administrator without a step-up can remove each connection (` + "`DELETE /api/v1/bindings/{id}`" + `) and then the vault.
- ` + "`PATCH /api/v1/bindings/{id}`" + `: when it adds websites to a connection that deploys automatically. Releasing websites, or any
  change to a connection that does not deploy automatically, is ` + "`certificates.operate`" + ` as listed.
- ` + "`POST /api/v1/bindings/{id}/actions/deploy`" + `: when the version is held (found while the license was not available, or with an
  incomplete certificate chain). An Operator is refused with ALC-AKV-0022.
- ` + "`PUT /api/v1/acme/certificates/{id}/bindings/{location_id}`" + `: when it switches unattended deployment on (` + "`auto_deploy: true`" + ` for a
  new binding, or for a binding whose automatic deployment is off). Then it needs what ` + "`acme.manage`" + ` needs (an Administrator's
  browser session with a fresh step-up, never an API token); binding with automatic deployment off, keeping it on and switching it
  off are ` + "`acme.operate`" + ` as listed. The inventory decides inside its transaction with the strength of the session, so a binding
  switched off by another request in the meantime is not switched on again without the step-up (403 ALC-AUTH-0003).

**` + "`credentials.manage`" + `** is Administrator with step-up and no API token. Besides adding a Key Vault and replacing its credentials
it gates switching automatic deployment on or off, releasing a held version and importing a certificate into a vault (a
private key leaves Alice).

**In lock.** ` + "`PUT /api/v1/bindings/{id}/auto-deploy`" + ` and ` + "`DELETE /api/v1/bindings/{id}`" + ` are open while the license is expired
(switching automatic deployment off and removing a connection only reduce what Alice does); switching it on is refused then by
the inventory with ALC-LIC-0001. ` + "`POST /api/v1/ssh-keys/{id}/actions/download-private-key`" + ` is open too: it changes nothing outside
Alice, and a lock must not hold the keys of the customer's own servers hostage.

**ACME certificates.** Every ` + "`/api/v1/acme/...`" + ` read is ` + "`acme.view`" + ` (every role, read tokens). Certificate authorities,
their accounts, DNS hooks and the certificate definitions (with their name lists), re-arming automatic renewal and releasing a held
certificate are ` + "`acme.manage`" + `: an Administrator's browser session with step-up, never an API token. Ordering a renewal, a test
run, binding locations and Deploy now are ` + "`acme.operate`" + ` (Operators and operate tokens). The routes that contact a certificate
authority or start work (account registration, key change and its check, deactivation, order, test run, re-arm, a change of a
certificate definition (switching automatic renewal on re-arms it), Deploy now) are
limited to 10 a minute per user or token. In lock every ACME change is refused with ALC-LIC-0001 (no certificate authority is
contacted) except ` + "`DELETE /api/v1/acme/certificates/{id}`" + ` and ` + "`DELETE /api/v1/acme/certificates/{id}/bindings/{location_id}`" + `,
which only reduce what Alice does (no renewal, no deployment), like removing a Key Vault connection.
` + "`POST /api/v1/acme/providers/{id}/preview`" + ` reads the certificate authority's directory before the account is registered (its
terms of service, whether an external account binding is required) for the registration form: ` + "`acme.preview`" + `, an
Administrator's browser session without a step-up (nothing is changed, no secret is read) and never an API token; it contacts the
certificate authority, so it is refused in lock and limited to 10 a minute per user like the other ACME actions.

**Network discovery.** Every ` + "`/api/v1/discovery/...`" + ` read is ` + "`discovery.view`" + `: every role in a browser, but an API token
needs the operate scope (read tokens never read the internal network map; an Auditor holds read tokens only). Starting and
cancelling a scan are ` + "`discovery.operate`" + ` (Administrators, Operators and operate tokens), together at most 10 a minute per user or
token; a scan is started only for a scope, never for addresses given in the request. Scan scopes, the allowed scan networks,
the global exclusions and the retention are ` + "`discovery.manage`" + `: an Administrator's browser session with a fresh step-up, never an
API token. Creating or changing a scope looks up the host names it adds (each at most 5 seconds; a refusal names the entry,
never an address) and is limited to 30 a minute per user; the size preview of the scope form (no look-up, nothing dialed) has
its own 60 a minute per user. In lock only starting a scan is refused with
ALC-LIC-0001; cancelling a scan and changing scopes and settings keep working. The CSV export is a read (it works in lock), at
most 10 a minute per user or token and one export of any kind at a time per person; ` + "`discovery.export`" + ` is recorded in the
audit log before the first byte.

**SSH keys and rotation (Phase 6).** The private key download is an Administrator's browser session with a fresh step-up,
never an API token, at most 5 per minute per user; its audit row is written before the file is sent. A rotation policy
is created switched off. ` + "`PATCH /api/v1/rotation/policies/{id}`" + ` is ` + "`rotation.manage`" + ` (operate tokens allowed), but a
change to the interval, the overlap, the notice time or the new key type of a policy that is on switches it off in the same step;
switching it on again (` + "`POST /api/v1/rotation/policies/{id}/actions/enable`" + `) needs ` + "`rotation.operate`" + `, an
Administrator's browser session with step-up. A scheduled run starts only after its notice email was delivered; Run now
(` + "`rotation.operate`" + `) needs the digest of the preview the Administrator saw. Stop and undo
(` + "`POST /api/v1/rotation/runs/{id}/actions/abort`" + `) is ` + "`rotation.manage`" + `: automation may stop a run.

**Dashboard, exports and settings (Phase 7).** The Dashboard's reads are ` + "`read`" + ` and filtered by role inside the service:
` + "`GET /api/v1/notifications/status`" + ` answers the delivery state to Administrators only (everyone else gets ` + "`{\"failing\": false}`" + `),
the summary's audit head is for Administrators and Auditors. The CSV exports are reads (they work in lock), at most 10 a
minute per user or token and one at a time per person; each is recorded in the audit log before the first byte. Saved views
are a signed-in person's own (` + "`session`" + `, no API token). Every ` + "`/api/v1/settings/...`" + ` route is ` + "`settings.manage`" + `;
` + "`POST /api/v1/settings/smtp/actions/test`" + ` is limited to 5 a minute per user.

**Single sign-on (Phase 7).** Every ` + "`/api/v1/sso/...`" + ` route is ` + "`sso.manage`" + `: an Administrator's browser session with
step-up, never an API token. The sign-in at an identity provider is public: the start is limited like the sign-in form (10 a
minute per address); ` + "`GET /api/v1/auth/oidc/{id}/callback`" + ` is the only GET that changes state (it consumes the sign-in
state and creates or steps up a session), is always answered with a 303 redirect (HEAD is 405) and is limited per binding
cookie (10 a minute) and per address (the anonymous 60 a minute). An SSO
user's step-up (` + "`POST /api/v1/auth/oidc/stepup`" + `) needs the user's own session.
`

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
		// Phase 5 (R40 row 11, S6): everything that adds a vault, replaces its credentials, switches automatic
		// deployment, releases a held version or moves a private key into a vault is credentials.manage.
		case p == "/api/v1/key-vaults" && !safeMethod(rt.method), strings.HasSuffix(p, "/vault-credentials"),
			strings.HasSuffix(p, "/auto-deploy"), strings.HasSuffix(p, "/actions/import-to-key-vault"),
			strings.HasSuffix(p, "/versions/{version_id}/actions/release"):
			want = rbac.CredentialsManage
		case under(p, "/api/v1/bindings") && !safeMethod(rt.method):
			want = rbac.CertificatesOperate
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
		// Phase 6 (R41 rows 5, 24, 25; S2): a private key leaves Alice only through the download; switching a policy on,
		// Run now, Continue, Finish now and Keep old need an Administrator's step-up; the rest of the policy work and Stop
		// and undo are rotation.manage.
		case strings.HasSuffix(p, "/actions/download-private-key"):
			want = rbac.SSHKeysDownload
		case under(p, "/api/v1/rotation") && !safeMethod(rt.method) && rotationOperateAction(p):
			want = rbac.RotationOperate
		case under(p, "/api/v1/rotation") && !safeMethod(rt.method):
			want = rbac.RotationManage
		case under(p, "/api/v1/rotation"):
			want = rbac.Read
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
			under(p, "/api/v1/certificates"), under(p, "/api/v1/locations"), under(p, "/api/v1/deployments"),
			under(p, "/api/v1/bindings"), under(p, "/api/v1/certificate-locations"), under(p, "/api/v1/key-vaults"):
			want = rbac.Read
		// ACME (D6, A9): reads are acme.view; ordering, test runs, bindings and Deploy now acme.operate; everything else
		// (providers, accounts, hooks, definitions, re-arm, release) acme.manage.
		case under(p, "/api/v1/acme") && safeMethod(rt.method):
			want = rbac.AcmeView
		case under(p, "/api/v1/acme/certificates") && acmeOperateAction(rt.method, p):
			want = rbac.AcmeOperate
		case under(p, "/api/v1/acme/providers") && strings.HasSuffix(p, "/preview"):
			want = rbac.AcmePreview
		case under(p, "/api/v1/acme"):
			want = rbac.AcmeManage
		// Network discovery (D1, D7, A5): reads are discovery.view; starting and cancelling a scan discovery.operate;
		// scopes and the settings discovery.manage.
		case under(p, "/api/v1/discovery") && safeMethod(rt.method):
			want = rbac.DiscoveryView
		case under(p, "/api/v1/discovery") && rt.method == http.MethodPost && (strings.HasSuffix(p, "/scans") || strings.HasSuffix(p, "/cancel")):
			want = rbac.DiscoveryOperate
		case under(p, "/api/v1/discovery"):
			want = rbac.DiscoveryManage
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
		// Phase 7 (C13): the Dashboard's reads are read (the service filters by role); saved views are a person's own.
		case under(p, "/api/v1/dashboard"), under(p, "/api/v1/alerts"), under(p, "/api/v1/notifications"):
			want = rbac.Read
		case under(p, "/api/v1/views"):
			want = rbac.Session
		// Phase 7 (C13): single sign-on configuration; the sign-in at an identity provider is public, its step-up a session's.
		case under(p, "/api/v1/sso"):
			want = rbac.SSOManage
		case p == "/api/v1/auth/oidc/providers", p == "/api/v1/auth/oidc/{id}/start", p == "/api/v1/auth/oidc/{id}/callback":
			want = rbac.Public
		case p == "/api/v1/auth/oidc/stepup":
			want = rbac.Session
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

// acmeOperateAction: the ACME actions an Operator may take on an existing certificate (A9).
func acmeOperateAction(method, p string) bool {
	return (method == http.MethodPost && (strings.HasSuffix(p, "/order") || strings.HasSuffix(p, "/test") || strings.HasSuffix(p, "/deploy"))) ||
		strings.HasSuffix(p, "/bindings/{location_id}")
}

// rotationOperateAction: the rotation actions that start or decide changes on servers (rotation.operate).
func rotationOperateAction(p string) bool {
	for _, a := range []string{"/actions/enable", "/actions/run", "/actions/continue", "/actions/finish-now", "/actions/keep-old"} {
		if strings.HasSuffix(p, a) {
			return true
		}
	}
	return false
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
		"POST /api/v1/key-vaults",
		"PUT /api/v1/targets/{id}/vault-credentials",
		"GET /api/v1/targets/{id}/kv/certificates",
		"GET /api/v1/targets/{id}/kv/certificates/{certificate_id}",
		"POST /api/v1/targets/{id}/kv/certificates/{certificate_id}/versions/{version_id}/actions/release",
		"GET /api/v1/targets/{id}/kv/keys",
		"GET /api/v1/targets/{id}/kv/secrets",
		"GET /api/v1/targets/{id}/kv/imports",
		"GET /api/v1/targets/{id}/kv/imports/{import_id}",
		"GET /api/v1/certificate-locations",
		"POST /api/v1/bindings",
		"GET /api/v1/bindings/{id}",
		"PATCH /api/v1/bindings/{id}",
		"PUT /api/v1/bindings/{id}/auto-deploy",
		"DELETE /api/v1/bindings/{id}",
		"POST /api/v1/bindings/{id}/actions/deploy",
		"POST /api/v1/certificates/{id}/actions/import-to-key-vault",
		"POST /api/v1/ssh-keys/generate",
		"POST /api/v1/ssh-keys/{id}/actions/deploy",
		"POST /api/v1/ssh-keys/{id}/actions/download-private-key",
		"GET /api/v1/targets/{id}/key-files",
		"GET /api/v1/rotation/policies",
		"POST /api/v1/rotation/policies",
		"GET /api/v1/rotation/policies/{id}",
		"PATCH /api/v1/rotation/policies/{id}",
		"DELETE /api/v1/rotation/policies/{id}",
		"POST /api/v1/rotation/policies/{id}/actions/enable",
		"POST /api/v1/rotation/policies/{id}/actions/disable",
		"POST /api/v1/rotation/policies/{id}/actions/preview",
		"POST /api/v1/rotation/policies/{id}/actions/run",
		"GET /api/v1/rotation/runs",
		"GET /api/v1/rotation/runs/{id}",
		"POST /api/v1/rotation/runs/{id}/actions/continue",
		"POST /api/v1/rotation/runs/{id}/actions/finish-now",
		"POST /api/v1/rotation/runs/{id}/actions/keep-old",
		"POST /api/v1/rotation/runs/{id}/actions/abort",
		"GET /api/v1/dashboard/summary",
		"GET /api/v1/dashboard/expiring",
		"GET /api/v1/alerts",
		"GET /api/v1/notifications/status",
		"GET /api/v1/certificates/export",
		"GET /api/v1/ssh-keys/export",
		"GET /api/v1/views",
		"POST /api/v1/views",
		"DELETE /api/v1/views/{id}",
		"GET /api/v1/settings/smtp",
		"PUT /api/v1/settings/smtp",
		"DELETE /api/v1/settings/smtp",
		"POST /api/v1/settings/smtp/actions/test",
		"POST /api/v1/settings/smtp/actions/trust",
		"POST /api/v1/settings/smtp/actions/untrust",
		"GET /api/v1/settings/notifications",
		"PUT /api/v1/settings/notifications",
		"GET /api/v1/settings/alerts",
		"PUT /api/v1/settings/alerts",
		"GET /api/v1/settings/general",
		"PUT /api/v1/settings/general",
		"GET /api/v1/sso/providers",
		"POST /api/v1/sso/providers",
		"GET /api/v1/sso/providers/{id}",
		"PATCH /api/v1/sso/providers/{id}",
		"DELETE /api/v1/sso/providers/{id}",
		"POST /api/v1/sso/providers/{id}/actions/refresh",
		"GET /api/v1/sso/group-mappings",
		"POST /api/v1/sso/group-mappings",
		"DELETE /api/v1/sso/group-mappings/{id}",
		"GET /api/v1/sso/settings",
		"PUT /api/v1/sso/settings",
		"GET /api/v1/auth/oidc/providers",
		"POST /api/v1/auth/oidc/{id}/start",
		"GET /api/v1/auth/oidc/{id}/callback",
		"POST /api/v1/auth/oidc/stepup",
		"GET /api/v1/acme/providers",
		"POST /api/v1/acme/providers",
		"GET /api/v1/acme/providers/{id}",
		"PATCH /api/v1/acme/providers/{id}",
		"DELETE /api/v1/acme/providers/{id}",
		"POST /api/v1/acme/providers/{id}/account",
		"POST /api/v1/acme/providers/{id}/preview",
		"POST /api/v1/acme/accounts/{id}/rollover",
		"POST /api/v1/acme/accounts/{id}/rollover/recover",
		"POST /api/v1/acme/accounts/{id}/deactivate",
		"GET /api/v1/acme/hooks",
		"POST /api/v1/acme/hooks",
		"GET /api/v1/acme/hooks/{id}",
		"PATCH /api/v1/acme/hooks/{id}",
		"DELETE /api/v1/acme/hooks/{id}",
		"GET /api/v1/acme/certificates",
		"POST /api/v1/acme/certificates",
		"GET /api/v1/acme/certificates/{id}",
		"PATCH /api/v1/acme/certificates/{id}",
		"DELETE /api/v1/acme/certificates/{id}",
		"POST /api/v1/acme/certificates/{id}/order",
		"POST /api/v1/acme/certificates/{id}/test",
		"GET /api/v1/acme/certificates/{id}/orders",
		"POST /api/v1/acme/certificates/{id}/rearm",
		"POST /api/v1/acme/certificates/{id}/release-hold",
		"GET /api/v1/acme/certificates/{id}/bindings",
		"PUT /api/v1/acme/certificates/{id}/bindings/{location_id}",
		"DELETE /api/v1/acme/certificates/{id}/bindings/{location_id}",
		"POST /api/v1/acme/certificates/{id}/deploy",
		"GET /api/v1/discovery/summary",
		"GET /api/v1/discovery/scopes",
		"POST /api/v1/discovery/scopes",
		"POST /api/v1/discovery/scopes/preview",
		"GET /api/v1/discovery/scopes/{id}",
		"PATCH /api/v1/discovery/scopes/{id}",
		"DELETE /api/v1/discovery/scopes/{id}",
		"POST /api/v1/discovery/scopes/{id}/scans",
		"GET /api/v1/discovery/scans",
		"GET /api/v1/discovery/scans/{id}",
		"POST /api/v1/discovery/scans/{id}/cancel",
		"GET /api/v1/discovery/certificates",
		"GET /api/v1/discovery/certificates/export",
		"GET /api/v1/discovery/certificates/{fingerprint}",
		"GET /api/v1/discovery/endpoints",
		"GET /api/v1/discovery/settings",
		"PUT /api/v1/discovery/settings",
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
		// Phase 5: a weaker permission on what moves a key or switches automatic deployment.
		{method: http.MethodPost, pattern: "/api/v1/key-vaults", perm: rbac.TargetsManage},
		{method: http.MethodPut, pattern: "/api/v1/targets/{id}/vault-credentials", perm: rbac.TargetsManage},
		{method: http.MethodPut, pattern: "/api/v1/bindings/{id}/auto-deploy", perm: rbac.CertificatesOperate},
		{method: http.MethodPost, pattern: "/api/v1/certificates/{id}/actions/import-to-key-vault", perm: rbac.CertificatesOperate},
		{method: http.MethodPost, pattern: "/api/v1/targets/{id}/kv/certificates/{certificate_id}/versions/{version_id}/actions/release", perm: rbac.CertificatesOperate},
		{method: http.MethodPost, pattern: "/api/v1/bindings", perm: rbac.CredentialsManage},
		{method: http.MethodGet, pattern: "/api/v1/bindings/{id}", perm: rbac.CertificatesOperate},
		// Phase 6: a private key or a change on servers behind a weaker permission.
		{method: http.MethodPost, pattern: "/api/v1/ssh-keys/{id}/actions/download-private-key", perm: rbac.InventoryOperate},
		{method: http.MethodPost, pattern: "/api/v1/rotation/policies/{id}/actions/enable", perm: rbac.RotationManage},
		{method: http.MethodPost, pattern: "/api/v1/rotation/policies/{id}/actions/run", perm: rbac.RotationManage},
		{method: http.MethodPost, pattern: "/api/v1/rotation/runs/{id}/actions/keep-old", perm: rbac.RotationManage},
		{method: http.MethodPost, pattern: "/api/v1/rotation/runs/{id}/actions/abort", perm: rbac.RotationOperate},
		{method: http.MethodPatch, pattern: "/api/v1/rotation/policies/{id}", perm: rbac.InventoryOperate},
		{method: http.MethodGet, pattern: "/api/v1/rotation/runs", perm: rbac.RotationManage},
		{method: http.MethodPost, pattern: "/api/v1/ssh-keys/generate", perm: rbac.Read},
		// Phase 7: settings behind less than settings.manage, the dashboard behind more than read, views for tokens.
		{method: http.MethodPost, pattern: "/api/v1/settings/smtp/actions/test", perm: rbac.Session},
		{method: http.MethodGet, pattern: "/api/v1/settings/smtp", perm: rbac.Read},
		{method: http.MethodGet, pattern: "/api/v1/dashboard/summary", perm: rbac.AuditRead},
		{method: http.MethodGet, pattern: "/api/v1/notifications/status", perm: rbac.SettingsManage},
		{method: http.MethodGet, pattern: "/api/v1/alerts", perm: rbac.Session},
		{method: http.MethodPost, pattern: "/api/v1/views", perm: rbac.Read},
		{method: http.MethodGet, pattern: "/api/v1/certificates/export", perm: rbac.AuditRead},
		{method: http.MethodPost, pattern: "/api/v1/sso/providers", perm: rbac.SettingsManage},
		{method: http.MethodGet, pattern: "/api/v1/sso/settings", perm: rbac.UsersRead},
		{method: http.MethodPost, pattern: "/api/v1/auth/oidc/stepup", perm: rbac.SessionStepUp},
		{method: http.MethodGet, pattern: "/api/v1/auth/oidc/{id}/callback", perm: rbac.Session},
		// ACME: a definition, provider, hook or account behind acme.operate, an order behind acme.manage, a read behind more.
		{method: http.MethodPost, pattern: "/api/v1/acme/certificates", perm: rbac.AcmeOperate},
		{method: http.MethodPatch, pattern: "/api/v1/acme/certificates/{id}", perm: rbac.AcmeOperate},
		{method: http.MethodPost, pattern: "/api/v1/acme/providers", perm: rbac.AcmeOperate},
		{method: http.MethodPost, pattern: "/api/v1/acme/accounts/{id}/rollover", perm: rbac.AcmeOperate},
		{method: http.MethodPost, pattern: "/api/v1/acme/certificates/{id}/rearm", perm: rbac.AcmeOperate},
		{method: http.MethodPost, pattern: "/api/v1/acme/certificates/{id}/order", perm: rbac.AcmeManage},
		{method: http.MethodPut, pattern: "/api/v1/acme/certificates/{id}/bindings/{location_id}", perm: rbac.Read},
		{method: http.MethodGet, pattern: "/api/v1/acme/certificates", perm: rbac.AcmeOperate},
		{method: http.MethodPost, pattern: "/api/v1/acme/providers/{id}/preview", perm: rbac.AcmeView},
		{method: http.MethodPost, pattern: "/api/v1/acme/providers/{id}/account", perm: rbac.AcmePreview},
		// Network discovery: a scope behind operate, a scan start behind view, a read behind manage, the settings behind operate.
		{method: http.MethodPost, pattern: "/api/v1/discovery/scopes", perm: rbac.DiscoveryOperate},
		{method: http.MethodPost, pattern: "/api/v1/discovery/scopes/{id}/scans", perm: rbac.DiscoveryView},
		{method: http.MethodGet, pattern: "/api/v1/discovery/certificates", perm: rbac.DiscoveryManage},
		{method: http.MethodGet, pattern: "/api/v1/discovery/endpoints", perm: rbac.Read},
		{method: http.MethodPut, pattern: "/api/v1/discovery/settings", perm: rbac.DiscoveryOperate},
		{method: http.MethodPost, pattern: "/api/v1/discovery/scans/{id}/cancel", perm: rbac.DiscoveryManage},
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
		{method: http.MethodPost, pattern: "/api/v1/key-vaults", perm: rbac.CredentialsManage},
		{method: http.MethodPut, pattern: "/api/v1/bindings/{id}/auto-deploy", perm: rbac.CredentialsManage},
		{method: http.MethodPost, pattern: "/api/v1/bindings", perm: rbac.CertificatesOperate},
		{method: http.MethodGet, pattern: "/api/v1/certificate-locations", perm: rbac.Read},
		{method: http.MethodPost, pattern: "/api/v1/ssh-keys/{id}/actions/download-private-key", perm: rbac.SSHKeysDownload},
		{method: http.MethodPost, pattern: "/api/v1/rotation/policies/{id}/actions/enable", perm: rbac.RotationOperate},
		{method: http.MethodPost, pattern: "/api/v1/rotation/policies/{id}/actions/disable", perm: rbac.RotationManage},
		{method: http.MethodPatch, pattern: "/api/v1/rotation/policies/{id}", perm: rbac.RotationManage},
		{method: http.MethodGet, pattern: "/api/v1/rotation/runs/{id}", perm: rbac.Read},
		{method: http.MethodPost, pattern: "/api/v1/rotation/runs/{id}/actions/abort", perm: rbac.RotationManage},
		{method: http.MethodPut, pattern: "/api/v1/settings/general", perm: rbac.SettingsManage},
		{method: http.MethodGet, pattern: "/api/v1/dashboard/expiring", perm: rbac.Read},
		{method: http.MethodDelete, pattern: "/api/v1/views/{id}", perm: rbac.Session},
		{method: http.MethodGet, pattern: "/api/v1/ssh-keys/export", perm: rbac.Read},
		{method: http.MethodDelete, pattern: "/api/v1/sso/group-mappings/{id}", perm: rbac.SSOManage},
		{method: http.MethodPost, pattern: "/api/v1/auth/oidc/{id}/start", perm: rbac.Public},
		{method: http.MethodPost, pattern: "/api/v1/acme/certificates/{id}/test", perm: rbac.AcmeOperate},
		{method: http.MethodDelete, pattern: "/api/v1/acme/certificates/{id}/bindings/{location_id}", perm: rbac.AcmeOperate},
		{method: http.MethodDelete, pattern: "/api/v1/acme/hooks/{id}", perm: rbac.AcmeManage},
		{method: http.MethodGet, pattern: "/api/v1/acme/hooks/{id}", perm: rbac.AcmeView},
		{method: http.MethodPost, pattern: "/api/v1/discovery/scopes/preview", perm: rbac.DiscoveryManage},
		{method: http.MethodPost, pattern: "/api/v1/discovery/scans/{id}/cancel", perm: rbac.DiscoveryOperate},
		{method: http.MethodGet, pattern: "/api/v1/discovery/settings", perm: rbac.DiscoveryView},
	}
	assert.Empty(t, routeRuleViolations(good))
}

// Route groups and how lock mode treats their state-changing operations (R9, R36 item 6).
var (
	lockAvailable = []string{"/api/v1/auth", "/api/v1/setup", "/api/v1/license", "/api/v1/users", "/api/v1/tokens",
		"/api/v1/audit", "/api/v1/backup", "/api/v1/backups", "/api/v1/settings",
		// Phase 7 (C13): the Dashboard, its conditions and the delivery state are reads; saved views change nothing outside Alice.
		"/api/v1/dashboard", "/api/v1/alerts", "/api/v1/views", "/api/v1/notifications", "/api/v1/sso"}
	lockRefused = []string{"/api/v1/targets", "/api/v1/certificates", "/api/v1/locations", "/api/v1/deployments",
		"/api/v1/ssh-keys", "/api/v1/rotation", "/api/v1/keyvault", "/api/v1/jobs", "/api/v1/key-vaults", "/api/v1/bindings",
		// ACME (A13): user routes that contact a CA or a target are ClassChange and answer 403 license.locked.
		"/api/v1/acme",
		// Network discovery (A5): starting a scan is ClassReadOnly (the scan itself is paused in lock).
		"/api/v1/discovery"}
	// lockAvailableRoutes are routes of a refused group that work in every license state because
	// they only reduce what Alice will do (ClassAlways).
	//
	// Phase 5: switching automatic deployment (the inventory refuses switching it ON in lock, switching it off is a
	// safety action) and removing a binding amend R40 row 22.
	//
	// Phase 6: the private key download changes nothing outside Alice; a lock must not hold the customer's own access
	// keys hostage (R41 row 5).
	lockAvailableRoutes = map[string]bool{"POST /api/v1/jobs/{id}/actions/discard": true,
		"PUT /api/v1/bindings/{id}/auto-deploy": true, "DELETE /api/v1/bindings/{id}": true,
		"POST /api/v1/ssh-keys/{id}/actions/download-private-key": true,
		// Stop and undo takes back what a run added; its undo runs in lock (L-86).
		"POST /api/v1/rotation/runs/{id}/actions/abort": true,
		// ACME: deleting a certificate definition (no more renewals, its bindings go) and removing a binding only reduce
		// what Alice does, like removing a Key Vault connection; neither contacts a certificate authority or a server.
		"DELETE /api/v1/acme/certificates/{id}": true, "DELETE /api/v1/acme/certificates/{id}/bindings/{location_id}": true,
		// Network discovery (A5): a locked installation can still stop a scan, change or remove its scopes and the settings;
		// none of them contacts a server (the preview resolves nothing; a scope's save looks its new names up only).
		"POST /api/v1/discovery/scans/{id}/cancel": true, "POST /api/v1/discovery/scopes": true, "POST /api/v1/discovery/scopes/preview": true,
		"PATCH /api/v1/discovery/scopes/{id}": true, "DELETE /api/v1/discovery/scopes/{id}": true, "PUT /api/v1/discovery/settings": true}
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
		if lockAvailableRoutes[key] {
			refused, available = false, true
		}
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

// The notes name routes that exist and say what the matrix rows cannot.
func TestAuthzNotesNameRealRoutesAndTheirConditions(t *testing.T) {
	var table []string
	for _, rt := range newServer(Deps{}).apiRoutes() {
		table = append(table, rt.method+" "+rt.pattern)
	}
	for _, c := range conditionalRules {
		assert.Contains(t, table, c.method+" "+c.path)
		assert.Contains(t, authzNotes, c.method+" "+c.path, "the notes must name "+c.path)
	}
	for _, phrase := range []string{"remove_bindings=true", "adds websites to a connection that deploys automatically", "the version is held",
		"not a boundary", "gates switching automatic deployment", "releasing a held version", "importing a certificate",
		"switches unattended deployment on", "only reduce what Alice does (no renewal, no deployment)", "10 a minute per user or token",
		"read tokens never read the internal network map", "never for addresses given in the request", "never an address",
		"In lock only starting a scan is refused"} {
		assert.Contains(t, authzNotes, phrase)
	}
}
