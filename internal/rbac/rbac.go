// Package rbac holds Alice's role and permission model. It is pure: no I/O,
// no clock, no database. Every HTTP route declares one Permission; Decide
// turns (permission, subject) into an authorization decision.
package rbac

import "sort"

// Role is a user's role. Roles are stored lowercase in the database.
type Role string

// The three v1 roles (spec §15.4).
const (
	Admin    Role = "admin"
	Operator Role = "operator"
	Auditor  Role = "auditor"
)

// Roles returns every role, most privileged first.
func Roles() []Role { return []Role{Admin, Operator, Auditor} }

// ParseRole accepts only the exact lowercase role names.
func ParseRole(s string) (Role, bool) {
	for _, r := range Roles() {
		if string(r) == s {
			return r, true
		}
	}
	return "", false
}

// Scope is an API token scope. ScopeOperate includes everything ScopeRead allows.
type Scope string

// API token scopes (SEC-026).
const (
	ScopeRead    Scope = "read"
	ScopeOperate Scope = "operate"
)

// ParseScope accepts only the exact lowercase scope names.
func ParseScope(s string) (Scope, bool) {
	switch Scope(s) {
	case ScopeRead, ScopeOperate:
		return Scope(s), true
	default:
		return "", false
	}
}

// AllowsScope reports whether a user with role r may hold a token with scope s.
// Auditors are read-only; admins and operators may hold either scope.
func (r Role) AllowsScope(s Scope) bool {
	switch r {
	case Admin, Operator:
		return s == ScopeRead || s == ScopeOperate
	case Auditor:
		return s == ScopeRead
	default:
		return false
	}
}

// satisfies reports whether a token with scope have meets the minimum scope want.
func (have Scope) satisfies(want Scope) bool {
	switch want {
	case ScopeRead:
		return have == ScopeRead || have == ScopeOperate
	case ScopeOperate:
		return have == ScopeOperate
	default:
		return false
	}
}

// Permission is the value of a route's x-permission.
type Permission string

// Every permission used by the route table.
const (
	Public         Permission = "public"
	Setup          Permission = "setup"
	MFAPending     Permission = "mfa_pending"
	Session        Permission = "session"
	SessionStepUp  Permission = "session.stepup"
	Read           Permission = "read"
	AuditRead      Permission = "audit.read"
	UsersRead      Permission = "users.read"
	UsersManage    Permission = "users.manage"
	SettingsManage Permission = "settings.manage"
	LicenseRead    Permission = "license.read"   // license status and history: Admin and Auditor (R3)
	LicenseManage  Permission = "license.manage" // license upload: Admin with step-up (§25.1)

	// Phase 3 (R37 item 12, §15.4).
	TargetsManage    Permission = "targets.manage"    // add, change and remove servers; the platform key and setup snippets: Admin
	HostKeysConfirm  Permission = "hostkeys.confirm"  // pin a server's first fingerprint: Admin in a browser session
	HostKeysRepin    Permission = "hostkeys.repin"    // accept a changed fingerprint: Admin with step-up (SEC-080, F-32)
	InventoryOperate Permission = "inventory.operate" // test connection, discovery, key removal: Admin and Operator
	JobsConfirm      Permission = "jobs.confirm"      // run or discard work paused by the license: Admin (R29)

	// Phase 4 (R38 item 12, §15.4).
	CertificatesOperate Permission = "certificates.operate" // upload, signing requests, deploy: Admin and Operator

	// Phase 5 (R40 row 11, S6). What can hand Azure a way into Alice or move a private key out of it:
	// adding a Key Vault and replacing its sign-in credentials, switching automatic deployment,
	// releasing a held version and importing a certificate into a vault. Admin with step-up, never an
	// API token. (Not only credentials: the one policy keeps every such action in one place.)
	CredentialsManage Permission = "credentials.manage"

	// Phase 6 (R41 rows 5, 24, 25; §15.4, SEC-009, SEC-045, R23, S2). The private key download: Administrator in a
	// browser session with step-up, never an API token. Rotation policies: Administrators prepare, change,
	// preview, switch off and stop them (operate tokens allowed); starting changes on servers — switching a policy
	// on, Run now, Continue after a renewal, Finish now, Keep the old key — needs a step-up session. Any change to
	// an enabled policy's schedule switches it off (S2), so a token can never re-shape a policy that is on.
	SSHKeysDownload Permission = "sshkeys.download"
	RotationManage  Permission = "rotation.manage"
	RotationOperate Permission = "rotation.operate"

	// Phase 7 (SEC-009 "SSO configuration", §25.1, R42 row 24): identity providers, group mappings and the
	// "SSO users may be Admin" switch — an Administrator in a browser session with step-up; never an API token.
	SSOManage Permission = "sso.manage"

	// Phase 8 (contract C1, C12): list, make and download backups — an Administrator in a browser session with
	// step-up, never an API token. A backup holds every secret of the installation (encrypted).
	BackupManage Permission = "backup.manage"

	// ACME certificate issuance (decision D6, amendment A9). AcmeView: every role and read tokens. AcmeOperate: order a
	// renewal, run a test run, request a deployment and edit bindings of existing ACME certificates (Admin, Operator;
	// operate tokens). AcmeManage: create, edit and delete certificates, providers, accounts and hooks, with their name
	// allow-lists (Admin in a browser session with step-up, never an API token).
	AcmeView    Permission = "acme.view"
	AcmeOperate Permission = "acme.operate"
	AcmeManage  Permission = "acme.manage"
)

// Policy describes who may use a permission.
type Policy struct {
	Anonymous  bool   // anyone, authenticated or not
	Setup      bool   // setup (wizard) session only
	Pending    bool   // pending login session only (password verified, MFA not done)
	Roles      []Role // roles allowed for user sessions and API tokens
	TokenScope Scope  // "" = API tokens rejected; otherwise the minimum scope (operate ⊇ read)
	StepUp     bool   // user sessions must have an active step-up window
}

var allRoles = []Role{Admin, Operator, Auditor}

var policies = map[Permission]Policy{
	Public:         {Anonymous: true},
	Setup:          {Setup: true},
	MFAPending:     {Pending: true},
	Session:        {Roles: allRoles},
	SessionStepUp:  {Roles: allRoles, StepUp: true},
	Read:           {Roles: allRoles, TokenScope: ScopeRead},
	AuditRead:      {Roles: []Role{Admin, Auditor}, TokenScope: ScopeRead},
	UsersRead:      {Roles: []Role{Admin}, TokenScope: ScopeRead},
	UsersManage:    {Roles: []Role{Admin}, StepUp: true},
	SettingsManage: {Roles: []Role{Admin}, StepUp: true},
	LicenseRead:    {Roles: []Role{Admin, Auditor}, TokenScope: ScopeRead},
	LicenseManage:  {Roles: []Role{Admin}, StepUp: true},

	TargetsManage:    {Roles: []Role{Admin}, TokenScope: ScopeOperate},
	HostKeysConfirm:  {Roles: []Role{Admin}},
	HostKeysRepin:    {Roles: []Role{Admin}, StepUp: true},
	InventoryOperate: {Roles: []Role{Admin, Operator}, TokenScope: ScopeOperate},
	JobsConfirm:      {Roles: []Role{Admin}},

	CertificatesOperate: {Roles: []Role{Admin, Operator}, TokenScope: ScopeOperate},

	CredentialsManage: {Roles: []Role{Admin}, StepUp: true},

	SSHKeysDownload: {Roles: []Role{Admin}, StepUp: true},
	RotationManage:  {Roles: []Role{Admin}, TokenScope: ScopeOperate},
	RotationOperate: {Roles: []Role{Admin}, StepUp: true},

	SSOManage: {Roles: []Role{Admin}, StepUp: true},

	BackupManage: {Roles: []Role{Admin}, StepUp: true},

	AcmeView:    {Roles: allRoles, TokenScope: ScopeRead},
	AcmeOperate: {Roles: []Role{Admin, Operator}, TokenScope: ScopeOperate},
	AcmeManage:  {Roles: []Role{Admin}, StepUp: true},
}

// PolicyFor returns the policy of p. The returned Roles slice is a copy.
func PolicyFor(p Permission) (Policy, bool) {
	pol, ok := policies[p]
	if !ok {
		return Policy{}, false
	}
	pol.Roles = append([]Role(nil), pol.Roles...)
	return pol, true
}

// Permissions returns every known permission, sorted.
func Permissions() []Permission {
	out := make([]Permission, 0, len(policies))
	for p := range policies {
		out = append(out, p)
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out
}

// SubjectKind is how the caller authenticated.
type SubjectKind int

// Subject kinds, from least to most authenticated.
const (
	Anonymous SubjectKind = iota
	SetupSession
	PendingSession
	UserSession
	APIToken
)

// Subject is the caller as seen by the authorization check.
type Subject struct {
	Kind   SubjectKind
	Role   Role
	Scope  Scope // API tokens only
	StepUp bool  // user sessions only: step-up window is active
}

// Decision is the outcome of Decide.
type Decision int

// Decisions. DenyUnauthenticated maps to HTTP 401, the others to 403.
const (
	Allow Decision = iota
	DenyUnauthenticated
	DenyForbidden
	DenyStepUp
)

// Decide is the single authorization function (deny by default).
func Decide(p Permission, s Subject) Decision {
	pol, ok := policies[p]
	switch {
	case !ok:
		return DenyForbidden
	case pol.Anonymous:
		return Allow
	case pol.Setup:
		return exact(s.Kind, SetupSession)
	case pol.Pending:
		return exact(s.Kind, PendingSession)
	}
	switch s.Kind {
	case UserSession:
		if !hasRole(pol.Roles, s.Role) {
			return DenyForbidden
		}
		if pol.StepUp && !s.StepUp {
			return DenyStepUp
		}
		return Allow
	case APIToken:
		if pol.TokenScope == "" || !s.Scope.satisfies(pol.TokenScope) || !hasRole(pol.Roles, s.Role) {
			return DenyForbidden
		}
		return Allow
	default: // Anonymous, SetupSession, PendingSession are not fully authenticated users
		return DenyUnauthenticated
	}
}

func exact(have, want SubjectKind) Decision {
	switch have {
	case want:
		return Allow
	case Anonymous:
		return DenyUnauthenticated
	default:
		return DenyForbidden
	}
}

func hasRole(roles []Role, r Role) bool {
	for _, x := range roles {
		if x == r {
			return true
		}
	}
	return false
}
