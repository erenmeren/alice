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
	rbac.BackupManage: {"anon": U, "setup": U, "pending": U, "admin": S, "admin+stepup": A, "operator": F, "operator+stepup": F,
		"auditor": F, "auditor+stepup": F, "token-read-admin": F, "token-operate-admin": F, "token-read-operator": F,
		"token-operate-operator": F, "token-read-auditor": F, "token-noscope-admin": F, "session-unknown-role": F},
	// ACME issuance (A9): written out by hand.
	rbac.AcmeView: {"anon": U, "setup": U, "pending": U, "admin": A, "admin+stepup": A, "operator": A, "operator+stepup": A,
		"auditor": A, "auditor+stepup": A, "token-read-admin": A, "token-operate-admin": A, "token-read-operator": A,
		"token-operate-operator": A, "token-read-auditor": A, "token-noscope-admin": F, "session-unknown-role": F},
	rbac.AcmeOperate: {"anon": U, "setup": U, "pending": U, "admin": A, "admin+stepup": A, "operator": A, "operator+stepup": A,
		"auditor": F, "auditor+stepup": F, "token-read-admin": F, "token-operate-admin": A, "token-read-operator": F,
		"token-operate-operator": A, "token-read-auditor": F, "token-noscope-admin": F, "session-unknown-role": F},
	rbac.AcmeManage: {"anon": U, "setup": U, "pending": U, "admin": S, "admin+stepup": A, "operator": F, "operator+stepup": F,
		"auditor": F, "auditor+stepup": F, "token-read-admin": F, "token-operate-admin": F, "token-read-operator": F,
		"token-operate-operator": F, "token-read-auditor": F, "token-noscope-admin": F, "session-unknown-role": F},
	rbac.AcmePreview: {"anon": U, "setup": U, "pending": U, "admin": A, "admin+stepup": A, "operator": F, "operator+stepup": F,
		"auditor": F, "auditor+stepup": F, "token-read-admin": F, "token-operate-admin": F, "token-read-operator": F,
		"token-operate-operator": F, "token-read-auditor": F, "token-noscope-admin": F, "session-unknown-role": F},
	// Network discovery (plan contract, A5, D7): written out by hand. The results are the internal network map: every
	// role reads them in a browser, but an API token needs the operate scope (read tokens do not get it, D7), so an
	// Auditor's token (read only, AllowsScope) never does. Starting and cancelling a scan: Admin and Operator, operate
	// tokens, like acme.operate. Scopes, global exclusions, allowed networks and retention: Admin with step-up, no token.
	rbac.DiscoveryView: {"anon": U, "setup": U, "pending": U, "admin": A, "admin+stepup": A, "operator": A, "operator+stepup": A,
		"auditor": A, "auditor+stepup": A, "token-read-admin": F, "token-operate-admin": A, "token-read-operator": F,
		"token-operate-operator": A, "token-read-auditor": F, "token-noscope-admin": F, "session-unknown-role": F},
	rbac.DiscoveryOperate: {"anon": U, "setup": U, "pending": U, "admin": A, "admin+stepup": A, "operator": A, "operator+stepup": A,
		"auditor": F, "auditor+stepup": F, "token-read-admin": F, "token-operate-admin": A, "token-read-operator": F,
		"token-operate-operator": A, "token-read-auditor": F, "token-noscope-admin": F, "session-unknown-role": F},
	rbac.DiscoveryManage: {"anon": U, "setup": U, "pending": U, "admin": S, "admin+stepup": A, "operator": F, "operator+stepup": F,
		"auditor": F, "auditor+stepup": F, "token-read-admin": F, "token-operate-admin": F, "token-read-operator": F,
		"token-operate-operator": F, "token-read-auditor": F, "token-noscope-admin": F, "session-unknown-role": F},
	rbac.SSOManage: {"anon": U, "setup": U, "pending": U, "admin": S, "admin+stepup": A, "operator": F, "operator+stepup": F,
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
	rbac.CredentialsManage: {"anon": U, "setup": U, "pending": U, "admin": S, "admin+stepup": A, "operator": F, "operator+stepup": F,
		"auditor": F, "auditor+stepup": F, "token-read-admin": F, "token-operate-admin": F, "token-read-operator": F,
		"token-operate-operator": F, "token-read-auditor": F, "token-noscope-admin": F, "session-unknown-role": F},
	rbac.JobsConfirm: {"anon": U, "setup": U, "pending": U, "admin": A, "admin+stepup": A, "operator": F, "operator+stepup": F,
		"auditor": F, "auditor+stepup": F, "token-read-admin": F, "token-operate-admin": F, "token-read-operator": F,
		"token-operate-operator": F, "token-read-auditor": F, "token-noscope-admin": F, "session-unknown-role": F},
	// Phase 6 (R41 rows 5, 7, 24, 25; S2): the private key download and the rotation actions that start changes on servers
	// are an Administrator's with step-up, never a token; preparing and stopping policies allows operate tokens.
	rbac.SSHKeysDownload: {"anon": U, "setup": U, "pending": U, "admin": S, "admin+stepup": A, "operator": F, "operator+stepup": F,
		"auditor": F, "auditor+stepup": F, "token-read-admin": F, "token-operate-admin": F, "token-read-operator": F,
		"token-operate-operator": F, "token-read-auditor": F, "token-noscope-admin": F, "session-unknown-role": F},
	rbac.RotationManage: {"anon": U, "setup": U, "pending": U, "admin": A, "admin+stepup": A, "operator": F, "operator+stepup": F,
		"auditor": F, "auditor+stepup": F, "token-read-admin": F, "token-operate-admin": A, "token-read-operator": F,
		"token-operate-operator": F, "token-read-auditor": F, "token-noscope-admin": F, "session-unknown-role": F},
	rbac.RotationOperate: {"anon": U, "setup": U, "pending": U, "admin": S, "admin+stepup": A, "operator": F, "operator+stepup": F,
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
	assert.Len(t, ps, 31)
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

func TestPhase6Policies(t *testing.T) {
	admin := rbac.Subject{Kind: rbac.UserSession, Role: rbac.Admin}
	adminUp := rbac.Subject{Kind: rbac.UserSession, Role: rbac.Admin, StepUp: true}
	op := rbac.Subject{Kind: rbac.UserSession, Role: rbac.Operator, StepUp: true}
	aud := rbac.Subject{Kind: rbac.UserSession, Role: rbac.Auditor, StepUp: true}
	adminTok := rbac.Subject{Kind: rbac.APIToken, Role: rbac.Admin, Scope: rbac.ScopeOperate}
	adminRead := rbac.Subject{Kind: rbac.APIToken, Role: rbac.Admin, Scope: rbac.ScopeRead}
	cases := []struct {
		p    rbac.Permission
		s    rbac.Subject
		want rbac.Decision
	}{
		{rbac.SSHKeysDownload, adminUp, rbac.Allow},
		{rbac.SSHKeysDownload, admin, rbac.DenyStepUp},
		{rbac.SSHKeysDownload, op, rbac.DenyForbidden},
		{rbac.SSHKeysDownload, adminTok, rbac.DenyForbidden}, // R23, A-09: no token retrieves a private key
		{rbac.RotationManage, admin, rbac.Allow},
		{rbac.RotationManage, adminTok, rbac.Allow},
		{rbac.RotationManage, adminRead, rbac.DenyForbidden},
		{rbac.RotationManage, op, rbac.DenyForbidden},
		{rbac.RotationManage, aud, rbac.DenyForbidden},
		{rbac.RotationOperate, adminUp, rbac.Allow},
		{rbac.RotationOperate, admin, rbac.DenyStepUp},
		{rbac.RotationOperate, adminTok, rbac.DenyForbidden},
		{rbac.RotationOperate, op, rbac.DenyForbidden},
		{rbac.InventoryOperate, op, rbac.Allow}, // generate and deploy
		{rbac.InventoryOperate, aud, rbac.DenyForbidden},
	}
	for _, c := range cases {
		assert.Equal(t, c.want, rbac.Decide(c.p, c.s), "%s %+v", c.p, c.s)
	}
}

func TestPhase7Policies(t *testing.T) {
	adminUp := rbac.Subject{Kind: rbac.UserSession, Role: rbac.Admin, StepUp: true}
	admin := rbac.Subject{Kind: rbac.UserSession, Role: rbac.Admin}
	tok := rbac.Subject{Kind: rbac.APIToken, Role: rbac.Admin, Scope: rbac.ScopeOperate}
	op := rbac.Subject{Kind: rbac.UserSession, Role: rbac.Operator, StepUp: true}
	assert.Equal(t, rbac.Allow, rbac.Decide(rbac.SSOManage, adminUp))
	assert.Equal(t, rbac.DenyStepUp, rbac.Decide(rbac.SSOManage, admin))
	assert.Equal(t, rbac.DenyForbidden, rbac.Decide(rbac.SSOManage, tok), "no token configures SSO")
	assert.Equal(t, rbac.DenyForbidden, rbac.Decide(rbac.SSOManage, op))
}

// Phase 8: backups are an Administrator's, with step-up, never an API token's.
func TestBackupManagePolicy(t *testing.T) {
	assert.Equal(t, rbac.Permission("backup.manage"), rbac.BackupManage)
	adminUp := rbac.Subject{Kind: rbac.UserSession, Role: rbac.Admin, StepUp: true}
	admin := rbac.Subject{Kind: rbac.UserSession, Role: rbac.Admin}
	tok := rbac.Subject{Kind: rbac.APIToken, Role: rbac.Admin, Scope: rbac.ScopeOperate}
	op := rbac.Subject{Kind: rbac.UserSession, Role: rbac.Operator, StepUp: true}
	aud := rbac.Subject{Kind: rbac.UserSession, Role: rbac.Auditor, StepUp: true}
	assert.Equal(t, rbac.Allow, rbac.Decide(rbac.BackupManage, adminUp))
	assert.Equal(t, rbac.DenyStepUp, rbac.Decide(rbac.BackupManage, admin))
	assert.Equal(t, rbac.DenyForbidden, rbac.Decide(rbac.BackupManage, tok), "no token reads or makes backups")
	assert.Equal(t, rbac.DenyForbidden, rbac.Decide(rbac.BackupManage, op))
	assert.Equal(t, rbac.DenyForbidden, rbac.Decide(rbac.BackupManage, aud))
	pol, ok := rbac.PolicyFor(rbac.BackupManage)
	require.True(t, ok)
	assert.Empty(t, pol.TokenScope)
}

// Network discovery (A5, D7): the permission names are fixed (OpenAPI x-permission), a read token never reads the
// network map, and the definitions of what may be scanned are never a token's.
func TestDiscoveryPolicies(t *testing.T) {
	assert.Equal(t, rbac.Permission("discovery.view"), rbac.DiscoveryView)
	assert.Equal(t, rbac.Permission("discovery.operate"), rbac.DiscoveryOperate)
	assert.Equal(t, rbac.Permission("discovery.manage"), rbac.DiscoveryManage)

	view, ok := rbac.PolicyFor(rbac.DiscoveryView)
	require.True(t, ok)
	assert.Equal(t, rbac.ScopeOperate, view.TokenScope, "D7: read API tokens do not get the network map")
	assert.False(t, view.StepUp)
	for _, r := range rbac.Roles() {
		assert.Equal(t, rbac.Allow, rbac.Decide(rbac.DiscoveryView, rbac.Subject{Kind: rbac.UserSession, Role: r}), r)
		if r.AllowsScope(rbac.ScopeOperate) {
			continue
		}
		assert.Equal(t, rbac.DenyForbidden, rbac.Decide(rbac.DiscoveryView, rbac.Subject{Kind: rbac.APIToken, Role: r, Scope: rbac.ScopeRead}),
			"%s can only hold read tokens, so no token of theirs reads the network map", r)
	}

	op, ok := rbac.PolicyFor(rbac.DiscoveryOperate)
	require.True(t, ok)
	assert.Equal(t, []rbac.Role{rbac.Admin, rbac.Operator}, op.Roles, "D1: Operators start and cancel scans")
	assert.Equal(t, rbac.ScopeOperate, op.TokenScope)
	assert.False(t, op.StepUp)

	manage, ok := rbac.PolicyFor(rbac.DiscoveryManage)
	require.True(t, ok)
	assert.Equal(t, []rbac.Role{rbac.Admin}, manage.Roles, "D1: defining what is scanned is the SSRF-relevant act")
	assert.True(t, manage.StepUp)
	assert.Empty(t, manage.TokenScope, "no token defines scopes, exclusions or allowed networks")
}
