package rbac_test

import (
	"fmt"
	"sort"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"alice/internal/rbac"
)

// subject names used in the expected table below.
var subjects = map[string]rbac.Subject{
	"anon":                   {Kind: rbac.Anonymous},
	"setup":                  {Kind: rbac.SetupSession},
	"pending":                {Kind: rbac.PendingSession, Role: rbac.Admin},
	"admin":                  {Kind: rbac.UserSession, Role: rbac.Admin},
	"admin+stepup":           {Kind: rbac.UserSession, Role: rbac.Admin, StepUp: true},
	"operator":               {Kind: rbac.UserSession, Role: rbac.Operator},
	"operator+stepup":        {Kind: rbac.UserSession, Role: rbac.Operator, StepUp: true},
	"auditor":                {Kind: rbac.UserSession, Role: rbac.Auditor},
	"auditor+stepup":         {Kind: rbac.UserSession, Role: rbac.Auditor, StepUp: true},
	"token-read-admin":       {Kind: rbac.APIToken, Role: rbac.Admin, Scope: rbac.ScopeRead},
	"token-operate-admin":    {Kind: rbac.APIToken, Role: rbac.Admin, Scope: rbac.ScopeOperate},
	"token-read-operator":    {Kind: rbac.APIToken, Role: rbac.Operator, Scope: rbac.ScopeRead},
	"token-operate-operator": {Kind: rbac.APIToken, Role: rbac.Operator, Scope: rbac.ScopeOperate},
	"token-read-auditor":     {Kind: rbac.APIToken, Role: rbac.Auditor, Scope: rbac.ScopeRead},
	"token-noscope-admin":    {Kind: rbac.APIToken, Role: rbac.Admin},
	"session-unknown-role":   {Kind: rbac.UserSession, Role: "root", StepUp: true},
}

const (
	A = rbac.Allow
	U = rbac.DenyUnauthenticated
	F = rbac.DenyForbidden
	S = rbac.DenyStepUp
)

// expected is written by hand from the spec role table (§15.4, R3) — it is the
// oracle and must not be derived from the policy map.
var expected = map[rbac.Permission]map[string]rbac.Decision{
	rbac.Public: {"anon": A, "setup": A, "pending": A, "admin": A, "admin+stepup": A, "operator": A, "operator+stepup": A,
		"auditor": A, "auditor+stepup": A, "token-read-admin": A, "token-operate-admin": A, "token-read-operator": A,
		"token-operate-operator": A, "token-read-auditor": A, "token-noscope-admin": A, "session-unknown-role": A},
	rbac.Setup: {"anon": U, "setup": A, "pending": F, "admin": F, "admin+stepup": F, "operator": F, "operator+stepup": F,
		"auditor": F, "auditor+stepup": F, "token-read-admin": F, "token-operate-admin": F, "token-read-operator": F,
		"token-operate-operator": F, "token-read-auditor": F, "token-noscope-admin": F, "session-unknown-role": F},
	rbac.MFAPending: {"anon": U, "setup": F, "pending": A, "admin": F, "admin+stepup": F, "operator": F, "operator+stepup": F,
		"auditor": F, "auditor+stepup": F, "token-read-admin": F, "token-operate-admin": F, "token-read-operator": F,
		"token-operate-operator": F, "token-read-auditor": F, "token-noscope-admin": F, "session-unknown-role": F},
	rbac.Session: {"anon": U, "setup": U, "pending": U, "admin": A, "admin+stepup": A, "operator": A, "operator+stepup": A,
		"auditor": A, "auditor+stepup": A, "token-read-admin": F, "token-operate-admin": F, "token-read-operator": F,
		"token-operate-operator": F, "token-read-auditor": F, "token-noscope-admin": F, "session-unknown-role": F},
	rbac.SessionStepUp: {"anon": U, "setup": U, "pending": U, "admin": S, "admin+stepup": A, "operator": S, "operator+stepup": A,
		"auditor": S, "auditor+stepup": A, "token-read-admin": F, "token-operate-admin": F, "token-read-operator": F,
		"token-operate-operator": F, "token-read-auditor": F, "token-noscope-admin": F, "session-unknown-role": F},
	rbac.Read: {"anon": U, "setup": U, "pending": U, "admin": A, "admin+stepup": A, "operator": A, "operator+stepup": A,
		"auditor": A, "auditor+stepup": A, "token-read-admin": A, "token-operate-admin": A, "token-read-operator": A,
		"token-operate-operator": A, "token-read-auditor": A, "token-noscope-admin": F, "session-unknown-role": F},
	rbac.AuditRead: {"anon": U, "setup": U, "pending": U, "admin": A, "admin+stepup": A, "operator": F, "operator+stepup": F,
		"auditor": A, "auditor+stepup": A, "token-read-admin": A, "token-operate-admin": A, "token-read-operator": F,
		"token-operate-operator": F, "token-read-auditor": A, "token-noscope-admin": F, "session-unknown-role": F},
	rbac.UsersRead: {"anon": U, "setup": U, "pending": U, "admin": A, "admin+stepup": A, "operator": F, "operator+stepup": F,
		"auditor": F, "auditor+stepup": F, "token-read-admin": A, "token-operate-admin": A, "token-read-operator": F,
		"token-operate-operator": F, "token-read-auditor": F, "token-noscope-admin": F, "session-unknown-role": F},
	rbac.UsersManage: {"anon": U, "setup": U, "pending": U, "admin": S, "admin+stepup": A, "operator": F, "operator+stepup": F,
		"auditor": F, "auditor+stepup": F, "token-read-admin": F, "token-operate-admin": F, "token-read-operator": F,
		"token-operate-operator": F, "token-read-auditor": F, "token-noscope-admin": F, "session-unknown-role": F},
	rbac.SettingsManage: {"anon": U, "setup": U, "pending": U, "admin": S, "admin+stepup": A, "operator": F, "operator+stepup": F,
		"auditor": F, "auditor+stepup": F, "token-read-admin": F, "token-operate-admin": F, "token-read-operator": F,
		"token-operate-operator": F, "token-read-auditor": F, "token-noscope-admin": F, "session-unknown-role": F},
	rbac.LicenseRead: {"anon": U, "setup": U, "pending": U, "admin": A, "admin+stepup": A, "operator": F, "operator+stepup": F,
		"auditor": A, "auditor+stepup": A, "token-read-admin": A, "token-operate-admin": A, "token-read-operator": F,
		"token-operate-operator": F, "token-read-auditor": A, "token-noscope-admin": F, "session-unknown-role": F},
	rbac.LicenseManage: {"anon": U, "setup": U, "pending": U, "admin": S, "admin+stepup": A, "operator": F, "operator+stepup": F,
		"auditor": F, "auditor+stepup": F, "token-read-admin": F, "token-operate-admin": F, "token-read-operator": F,
		"token-operate-operator": F, "token-read-auditor": F, "token-noscope-admin": F, "session-unknown-role": F},
	rbac.TargetsManage: {"anon": U, "setup": U, "pending": U, "admin": A, "admin+stepup": A, "operator": F, "operator+stepup": F,
		"auditor": F, "auditor+stepup": F, "token-read-admin": F, "token-operate-admin": A, "token-read-operator": F,
		"token-operate-operator": F, "token-read-auditor": F, "token-noscope-admin": F, "session-unknown-role": F},
	rbac.HostKeysConfirm: {"anon": U, "setup": U, "pending": U, "admin": A, "admin+stepup": A, "operator": F, "operator+stepup": F,
		"auditor": F, "auditor+stepup": F, "token-read-admin": F, "token-operate-admin": F, "token-read-operator": F,
		"token-operate-operator": F, "token-read-auditor": F, "token-noscope-admin": F, "session-unknown-role": F},
	rbac.HostKeysRepin: {"anon": U, "setup": U, "pending": U, "admin": S, "admin+stepup": A, "operator": F, "operator+stepup": F,
		"auditor": F, "auditor+stepup": F, "token-read-admin": F, "token-operate-admin": F, "token-read-operator": F,
		"token-operate-operator": F, "token-read-auditor": F, "token-noscope-admin": F, "session-unknown-role": F},
	rbac.InventoryOperate: {"anon": U, "setup": U, "pending": U, "admin": A, "admin+stepup": A, "operator": A, "operator+stepup": A,
		"auditor": F, "auditor+stepup": F, "token-read-admin": F, "token-operate-admin": A, "token-read-operator": F,
		"token-operate-operator": A, "token-read-auditor": F, "token-noscope-admin": F, "session-unknown-role": F},
	rbac.CertificatesOperate: {"anon": U, "setup": U, "pending": U, "admin": A, "admin+stepup": A, "operator": A, "operator+stepup": A,
		"auditor": F, "auditor+stepup": F, "token-read-admin": F, "token-operate-admin": A, "token-read-operator": F,
		"token-operate-operator": A, "token-read-auditor": F, "token-noscope-admin": F, "session-unknown-role": F},
	rbac.JobsConfirm: {"anon": U, "setup": U, "pending": U, "admin": A, "admin+stepup": A, "operator": F, "operator+stepup": F,
		"auditor": F, "auditor+stepup": F, "token-read-admin": F, "token-operate-admin": F, "token-read-operator": F,
		"token-operate-operator": F, "token-read-auditor": F, "token-noscope-admin": F, "session-unknown-role": F},
}

func TestDecideMatchesDocumentedMatrix(t *testing.T) {
	for _, p := range rbac.Permissions() {
		row, ok := expected[p]
		require.True(t, ok, "permission %q has no row in the expected matrix", p)
		require.Len(t, row, len(subjects), "row %q must cover every subject", p)
		for name, s := range subjects {
			want, ok := row[name]
			require.True(t, ok, "row %q misses subject %q", p, name)
			assert.Equal(t, want, rbac.Decide(p, s), fmt.Sprintf("%s as %s", p, name))
		}
	}
	assert.Len(t, expected, len(rbac.Permissions()), "expected matrix lists a permission that does not exist")
}

func TestUnknownPermissionIsDenied(t *testing.T) {
	for name, s := range subjects {
		assert.Equal(t, rbac.DenyForbidden, rbac.Decide("nope", s), name)
		assert.Equal(t, rbac.DenyForbidden, rbac.Decide("", s), name)
	}
}

func TestPermissionsAreSortedAndHavePolicies(t *testing.T) {
	ps := rbac.Permissions()
	assert.Len(t, ps, 18)
	assert.True(t, sort.SliceIsSorted(ps, func(i, j int) bool { return ps[i] < ps[j] }))
	for _, p := range ps {
		_, ok := rbac.PolicyFor(p)
		assert.True(t, ok, string(p))
	}
	_, ok := rbac.PolicyFor("nope")
	assert.False(t, ok)
}

func TestPolicyForReturnsACopy(t *testing.T) {
	p, ok := rbac.PolicyFor(rbac.Read)
	require.True(t, ok)
	p.Roles[0] = "root"
	again, _ := rbac.PolicyFor(rbac.Read)
	assert.Equal(t, rbac.Admin, again.Roles[0])
}

func TestRolesAndParsing(t *testing.T) {
	assert.Equal(t, []rbac.Role{rbac.Admin, rbac.Operator, rbac.Auditor}, rbac.Roles())
	for _, r := range rbac.Roles() {
		got, ok := rbac.ParseRole(string(r))
		assert.True(t, ok)
		assert.Equal(t, r, got)
	}
	for _, bad := range []string{"", "Admin", "ADMIN", "root", " admin"} {
		_, ok := rbac.ParseRole(bad)
		assert.False(t, ok, bad)
	}
	for _, s := range []rbac.Scope{rbac.ScopeRead, rbac.ScopeOperate} {
		got, ok := rbac.ParseScope(string(s))
		assert.True(t, ok)
		assert.Equal(t, s, got)
	}
	for _, bad := range []string{"", "Read", "write", "admin"} {
		_, ok := rbac.ParseScope(bad)
		assert.False(t, ok, bad)
	}
}

func TestAllowsScope(t *testing.T) {
	assert.True(t, rbac.Admin.AllowsScope(rbac.ScopeRead))
	assert.True(t, rbac.Admin.AllowsScope(rbac.ScopeOperate))
	assert.True(t, rbac.Operator.AllowsScope(rbac.ScopeRead))
	assert.True(t, rbac.Operator.AllowsScope(rbac.ScopeOperate))
	assert.True(t, rbac.Auditor.AllowsScope(rbac.ScopeRead))
	assert.False(t, rbac.Auditor.AllowsScope(rbac.ScopeOperate), "auditors are read-only")
	assert.False(t, rbac.Admin.AllowsScope("write"))
	assert.False(t, rbac.Role("root").AllowsScope(rbac.ScopeRead))
}
