// Package rbac holds Alice's role and permission model. It is pure: no I/O,
// no clock, no database. Every HTTP route declares one Permission; Decide
// turns (permission, subject) into an authorization decision.
package rbac

import (
	"slices"
	"sort"

	"github.com/google/uuid"
)

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
	// AcmePreview: read a certificate authority's directory before registering its account (terms of service, whether
	// an external account binding is needed) — an Administrator's browser session, never an API token, no step-up:
	// nothing is changed and no secret is read (Task 13 fix round 2).
	AcmePreview Permission = "acme.preview"

	// Network certificate discovery (plan contract, amendment A5, decisions D1 and D7). DiscoveryView: read the results,
	// scopes and scans — the internal network map — every role in a browser session, but an API token needs the operate
	// scope (D7: read tokens do not get it; an Auditor can hold read tokens only, so no Auditor token reads it).
	// DiscoveryOperate: start and cancel a scan of an existing scope (Admin, Operator; operate tokens, like
	// AcmeOperate). DiscoveryManage: create, edit and delete scopes, global exclusions, allowed scan networks and
	// retention — what may be dialed is the SSRF-relevant act (D1), so an Administrator in a browser session with
	// step-up, never an API token.
	DiscoveryView    Permission = "discovery.view"
	DiscoveryOperate Permission = "discovery.operate"
	DiscoveryManage  Permission = "discovery.manage"

	// Key-compromise incidents (owner decision 2026-10-20, docs/superpowers/rulings/certificate-revocation.md): starting
	// one marks every certificate with the key compromised for good and replaces it on every server, acting on the
	// incident (retry, revoke now regardless, choose the replacement, close) — an Administrator in a browser session with
	// step-up, never an API token. Reading incidents and the impact of a certificate is Read.
	CertificatesIncident Permission = "certificates.incident"

	// Scoped access and service ownership (R49, docs/superpowers/specs/2026-10-21-scoped-rbac-and-service-ownership-design.md
	// §5.2): ServicesManage creates, changes and deletes services and environments; ServicesAssign moves resources
	// between services; ServicesTrust lets one service accept another's certificates and SSH keys. They decide who may
	// reach what: a global Administrator's browser session with step-up, never an API token.
	ServicesManage Permission = "services.manage"
	ServicesAssign Permission = "services.assign"
	ServicesTrust  Permission = "services.trust"
	// AccessManage adds and removes role bindings (R49 Phase 2, design §5.2): who holds which role on which service or
	// environment. A global Administrator's browser session with step-up, never an API token, like the services.
	AccessManage Permission = "access.manage"
	// ServicesPolicy changes a service's policy (R55, design §5.2, §7.3): an Administrator of that service with step-up,
	// never an API token. The policy's domains need a global grant besides (the API checks it): a service
	// Administrator widening their own service's names would defeat the rule.
	ServicesPolicy Permission = "services.policy"
)

// Policy describes who may use a permission.
type Policy struct {
	Anonymous bool // anyone, authenticated or not
	Setup     bool // setup (wizard) session only
	Pending   bool // pending login session only (password verified, MFA not done)
	// SignedIn: every signed-in person, whatever their grants, a person without any role included (R49 Phase 2: a
	// person whose only rights are role bindings, or who has none yet, still reads and ends their own session, changes
	// their password and language). Roles is not consulted for a user session then; API tokens follow TokenScope.
	SignedIn   bool
	Roles      []Role // roles allowed for user sessions and API tokens
	TokenScope Scope  // "" = API tokens rejected; otherwise the minimum scope (operate ⊇ read)
	StepUp     bool   // user sessions must have an active step-up window
}

var allRoles = []Role{Admin, Operator, Auditor}

var policies = map[Permission]Policy{
	Public:         {Anonymous: true},
	Setup:          {Setup: true},
	MFAPending:     {Pending: true},
	Session:        {SignedIn: true, Roles: allRoles},
	SessionStepUp:  {SignedIn: true, Roles: allRoles, StepUp: true},
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
	AcmePreview: {Roles: []Role{Admin}},

	DiscoveryView:    {Roles: allRoles, TokenScope: ScopeOperate},
	DiscoveryOperate: {Roles: []Role{Admin, Operator}, TokenScope: ScopeOperate},
	DiscoveryManage:  {Roles: []Role{Admin}, StepUp: true},

	CertificatesIncident: {Roles: []Role{Admin}, StepUp: true},

	ServicesManage: {Roles: []Role{Admin}, StepUp: true},
	ServicesAssign: {Roles: []Role{Admin}, StepUp: true},
	ServicesTrust:  {Roles: []Role{Admin}, StepUp: true},
	AccessManage:   {Roles: []Role{Admin}, StepUp: true},
	ServicesPolicy: {Roles: []Role{Admin}, StepUp: true},
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
	Kind SubjectKind
	// Role is the global role (users.role; "" for a person without one, R49 Phase 2): it holds on every service.
	Role   Role
	Scope  Scope // API tokens only
	StepUp bool  // user sessions only: step-up window is active
	// Grants are the roles held on services only (role bindings, design §5.1), each with the services it covers now
	// (an environment binding expanded to the services that carry the environment at this request).
	Grants []ScopedGrant
}

// ScopedGrant is a role held on a set of services: a role binding on one service, or on an environment expanded to the
// services that carry it (design §5.1). A grant with no services allows nothing.
type ScopedGrant struct {
	Role     Role
	Services []uuid.UUID
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

// Decide is the authorization function of a global grant (deny by default): the subject's global role, or, for a
// SignedIn permission, any signed-in person. Scoped grants never satisfy it: it is the check of every platform route
// (design §5.3) and of every route before scoped access existed.
func Decide(p Permission, s Subject) Decision {
	return decide(p, s, func(roles []Role) bool { return hasRole(roles, s.Role) })
}

// DecideAnywhere is Decide where a scoped grant on any service counts as well (design §5.3, the route-level check of
// the resource, list, create, cross and "any" routes): the caller may use the permission somewhere. What it may reach
// is Reach; the resource of a route is checked against it afterwards.
func DecideAnywhere(p Permission, s Subject) Decision {
	return decide(p, s, func(roles []Role) bool {
		if hasRole(roles, s.Role) {
			return true
		}
		for _, g := range s.Grants {
			if len(g.Services) > 0 && hasRole(roles, g.Role) {
				return true
			}
		}
		return false
	})
}

// DecideIn is the decision on one service: the global role, or a scoped grant whose services include service.
func DecideIn(p Permission, s Subject, service uuid.UUID) Decision {
	return decide(p, s, func(roles []Role) bool {
		if hasRole(roles, s.Role) {
			return true
		}
		for _, g := range s.Grants {
			if hasRole(roles, g.Role) && slices.Contains(g.Services, service) {
				return true
			}
		}
		return false
	})
}

// Reach is where the subject may use permission p (design §5.1): all is true when its global role allows p;
// otherwise services are the services of its scoped grants whose role allows p (sorted, without repeats; nil when
// none). The token scope applies as in Decide (a read token reaches nothing with an operate permission); the step-up
// window does not (Decide asks for it). A subject that is not a signed-in person or a token reaches nothing, and so
// does a permission that is not a role's (public, the wizard, a pending sign-in).
func Reach(p Permission, s Subject) (all bool, services []uuid.UUID) {
	pol, ok := policies[p]
	if !ok || pol.Anonymous || pol.Setup || pol.Pending {
		return false, nil
	}
	switch s.Kind {
	case UserSession:
	case APIToken:
		if pol.TokenScope == "" || !s.Scope.satisfies(pol.TokenScope) {
			return false, nil
		}
	default:
		return false, nil
	}
	if hasRole(pol.Roles, s.Role) {
		return true, nil
	}
	for _, g := range s.Grants {
		if hasRole(pol.Roles, g.Role) {
			services = append(services, g.Services...)
		}
	}
	if len(services) == 0 {
		return false, nil
	}
	slices.SortFunc(services, compareUUID)
	return false, slices.Compact(services)
}

// HasAnyGrant reports whether the subject holds a role anywhere: a global role or a scoped grant on some service. A
// signed-in person without one sees only the "no access yet" page (design §9).
func (s Subject) HasAnyGrant() bool {
	if _, ok := ParseRole(string(s.Role)); ok {
		return true
	}
	for _, g := range s.Grants {
		if len(g.Services) > 0 {
			return true
		}
	}
	return false
}

// AllowsScopeAnywhere reports whether some grant of the subject (its global role, or a scoped grant on some service)
// may hold an API token of scope sc (design §6.3: the token scope check at creation and at every use).
func (s Subject) AllowsScopeAnywhere(sc Scope) bool {
	if s.Role.AllowsScope(sc) {
		return true
	}
	for _, g := range s.Grants {
		if len(g.Services) > 0 && g.Role.AllowsScope(sc) {
			return true
		}
	}
	return false
}

// Within narrows the subject to services (an API token limited to services, design §6.3, R54): its global role becomes
// a grant on those services and every scoped grant keeps only those of its services; grants left without a service go.
// The result never holds a global role, so no platform permission (Decide) allows it, whatever the owner's role.
// Narrowing only: nothing outside the subject's own grants is ever added.
func (s Subject) Within(services []uuid.UUID) Subject {
	limit := slices.Clone(services)
	slices.SortFunc(limit, compareUUID)
	limit = slices.Compact(limit)
	out := s
	out.Role, out.Grants = "", nil
	if _, ok := ParseRole(string(s.Role)); ok && len(limit) > 0 {
		out.Grants = append(out.Grants, ScopedGrant{Role: s.Role, Services: limit})
	}
	for _, g := range s.Grants {
		var kept []uuid.UUID
		for _, sv := range g.Services {
			if _, found := slices.BinarySearchFunc(limit, sv, compareUUID); found {
				kept = append(kept, sv)
			}
		}
		if len(kept) > 0 {
			out.Grants = append(out.Grants, ScopedGrant{Role: g.Role, Services: kept})
		}
	}
	return out
}

func compareUUID(a, b uuid.UUID) int {
	for i := range a {
		switch {
		case a[i] < b[i]:
			return -1
		case a[i] > b[i]:
			return 1
		}
	}
	return 0
}

func decide(p Permission, s Subject, roleOK func([]Role) bool) Decision {
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
		signedIn := pol.SignedIn && (s.Role == "" || hasRole(allRoles, s.Role))
		if !signedIn && !roleOK(pol.Roles) {
			return DenyForbidden
		}
		if pol.StepUp && !s.StepUp {
			return DenyStepUp
		}
		return Allow
	case APIToken:
		if pol.TokenScope == "" || !s.Scope.satisfies(pol.TokenScope) || !roleOK(pol.Roles) {
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
