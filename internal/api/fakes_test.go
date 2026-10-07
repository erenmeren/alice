package api

import (
	"context"
	"errors"
	"io"
	"sync"
	"time"

	"github.com/google/uuid"

	"alice/internal/alerts"
	"alice/internal/audit"
	"alice/internal/auth"
	"alice/internal/inventory"
	"alice/internal/jobs"
	"alice/internal/license"
	"alice/internal/notify"
	"alice/internal/platform/settings"
	"alice/internal/providers"
	"alice/internal/rbac"
	"alice/internal/reports"
	"alice/internal/setup"
	"alice/internal/sshkeys"
)

// errNotConfigured is returned by fake methods whose function field is nil.
var errNotConfigured = errors.New("fake: method not configured")

// fakeAuth implements AuthService. Each method calls its function field when
// set; otherwise it returns zero values and errNotConfigured (AuthenticatePassive
// and AuthenticateToken return auth.ErrUnauthenticated; RecordActivity returns nil;
// CSRFToken and CheckCSRF use the "csrf-<token>" convention). AuthenticateFn answers
// AuthenticatePassive, the guard's session lookup.
type fakeAuth struct {
	AuthenticateFn            func(ctx context.Context, sessionToken string) (auth.Principal, error)
	RecordActivityFn          func(ctx context.Context, p auth.Principal) error
	AuthenticateTokenFn       func(ctx context.Context, bearer string) (auth.Principal, error)
	LoginFn                   func(ctx context.Context, username, password string, m auth.Meta) (auth.LoginResult, error)
	EnrollMFAFn               func(ctx context.Context, p auth.Principal, m auth.Meta) (auth.TOTPEnrollment, error)
	VerifyMFAFn               func(ctx context.Context, p auth.Principal, in auth.MFAInput, m auth.Meta) (auth.SessionResult, error)
	SessionInfoFn             func(ctx context.Context, p auth.Principal, sessionToken string) (auth.SessionInfo, error)
	StepUpFn                  func(ctx context.Context, p auth.Principal, code string, m auth.Meta) (auth.SessionResult, error)
	LogoutFn                  func(ctx context.Context, p auth.Principal, m auth.Meta) error
	ChangePasswordFn          func(ctx context.Context, p auth.Principal, current, next string, m auth.Meta) (auth.SessionResult, error)
	RegenerateRecoveryCodesFn func(ctx context.Context, p auth.Principal, m auth.Meta) ([]string, error)
	SetLocaleFn               func(ctx context.Context, p auth.Principal, locale string) error
	ListUsersFn               func(ctx context.Context) ([]auth.User, error)
	GetUserFn                 func(ctx context.Context, id uuid.UUID) (auth.User, error)
	CreateUserFn              func(ctx context.Context, p auth.Principal, m auth.Meta, in auth.NewUser) (auth.User, error)
	UpdateUserFn              func(ctx context.Context, p auth.Principal, m auth.Meta, id uuid.UUID, in auth.UserUpdate) (auth.User, error)
	ResetMFAFn                func(ctx context.Context, p auth.Principal, m auth.Meta, id uuid.UUID) error
	ResetPasswordFn           func(ctx context.Context, p auth.Principal, m auth.Meta, id uuid.UUID, password string) error
	RevokeSessionsFn          func(ctx context.Context, p auth.Principal, m auth.Meta, id uuid.UUID) error
	CreateTokenFn             func(ctx context.Context, p auth.Principal, m auth.Meta, in auth.NewToken) (string, auth.Token, error)
	ListTokensFn              func(ctx context.Context, p auth.Principal, m auth.Meta, userID uuid.UUID) ([]auth.Token, error)
	RevokeTokenFn             func(ctx context.Context, p auth.Principal, m auth.Meta, id uuid.UUID) error
}

func (f *fakeAuth) AuthenticatePassive(ctx context.Context, t string) (auth.Principal, error) {
	if f.AuthenticateFn != nil {
		return f.AuthenticateFn(ctx, t)
	}
	return auth.Principal{}, auth.ErrUnauthenticated
}

func (f *fakeAuth) RecordActivity(ctx context.Context, p auth.Principal) error {
	if f.RecordActivityFn != nil {
		return f.RecordActivityFn(ctx, p)
	}
	return nil
}

func (f *fakeAuth) AuthenticateToken(ctx context.Context, b string) (auth.Principal, error) {
	if f.AuthenticateTokenFn != nil {
		return f.AuthenticateTokenFn(ctx, b)
	}
	return auth.Principal{}, auth.ErrUnauthenticated
}

func (f *fakeAuth) CSRFToken(t string) string       { return "csrf-" + t }
func (f *fakeAuth) CheckCSRF(t, header string) bool { return header == "csrf-"+t }

func (f *fakeAuth) Login(ctx context.Context, u, pw string, m auth.Meta) (auth.LoginResult, error) {
	if f.LoginFn != nil {
		return f.LoginFn(ctx, u, pw, m)
	}
	return auth.LoginResult{}, errNotConfigured
}

func (f *fakeAuth) EnrollMFA(ctx context.Context, p auth.Principal, m auth.Meta) (auth.TOTPEnrollment, error) {
	if f.EnrollMFAFn != nil {
		return f.EnrollMFAFn(ctx, p, m)
	}
	return auth.TOTPEnrollment{}, errNotConfigured
}

func (f *fakeAuth) VerifyMFA(ctx context.Context, p auth.Principal, in auth.MFAInput, m auth.Meta) (auth.SessionResult, error) {
	if f.VerifyMFAFn != nil {
		return f.VerifyMFAFn(ctx, p, in, m)
	}
	return auth.SessionResult{}, errNotConfigured
}

func (f *fakeAuth) SessionInfo(ctx context.Context, p auth.Principal, t string) (auth.SessionInfo, error) {
	if f.SessionInfoFn != nil {
		return f.SessionInfoFn(ctx, p, t)
	}
	return auth.SessionInfo{}, errNotConfigured
}

func (f *fakeAuth) StepUp(ctx context.Context, p auth.Principal, code string, m auth.Meta) (auth.SessionResult, error) {
	if f.StepUpFn != nil {
		return f.StepUpFn(ctx, p, code, m)
	}
	return auth.SessionResult{}, errNotConfigured
}

func (f *fakeAuth) Logout(ctx context.Context, p auth.Principal, m auth.Meta) error {
	if f.LogoutFn != nil {
		return f.LogoutFn(ctx, p, m)
	}
	return errNotConfigured
}

func (f *fakeAuth) ChangePassword(ctx context.Context, p auth.Principal, cur, next string, m auth.Meta) (auth.SessionResult, error) {
	if f.ChangePasswordFn != nil {
		return f.ChangePasswordFn(ctx, p, cur, next, m)
	}
	return auth.SessionResult{}, errNotConfigured
}

func (f *fakeAuth) RegenerateRecoveryCodes(ctx context.Context, p auth.Principal, m auth.Meta) ([]string, error) {
	if f.RegenerateRecoveryCodesFn != nil {
		return f.RegenerateRecoveryCodesFn(ctx, p, m)
	}
	return nil, errNotConfigured
}

func (f *fakeAuth) SetLocale(ctx context.Context, p auth.Principal, l string) error {
	if f.SetLocaleFn != nil {
		return f.SetLocaleFn(ctx, p, l)
	}
	return errNotConfigured
}

func (f *fakeAuth) ListUsers(ctx context.Context) ([]auth.User, error) {
	if f.ListUsersFn != nil {
		return f.ListUsersFn(ctx)
	}
	return nil, errNotConfigured
}

func (f *fakeAuth) GetUser(ctx context.Context, id uuid.UUID) (auth.User, error) {
	if f.GetUserFn != nil {
		return f.GetUserFn(ctx, id)
	}
	return auth.User{}, errNotConfigured
}

func (f *fakeAuth) CreateUser(ctx context.Context, p auth.Principal, m auth.Meta, in auth.NewUser) (auth.User, error) {
	if f.CreateUserFn != nil {
		return f.CreateUserFn(ctx, p, m, in)
	}
	return auth.User{}, errNotConfigured
}

func (f *fakeAuth) UpdateUser(ctx context.Context, p auth.Principal, m auth.Meta, id uuid.UUID, in auth.UserUpdate) (auth.User, error) {
	if f.UpdateUserFn != nil {
		return f.UpdateUserFn(ctx, p, m, id, in)
	}
	return auth.User{}, errNotConfigured
}

func (f *fakeAuth) ResetMFA(ctx context.Context, p auth.Principal, m auth.Meta, id uuid.UUID) error {
	if f.ResetMFAFn != nil {
		return f.ResetMFAFn(ctx, p, m, id)
	}
	return errNotConfigured
}

func (f *fakeAuth) ResetPassword(ctx context.Context, p auth.Principal, m auth.Meta, id uuid.UUID, pw string) error {
	if f.ResetPasswordFn != nil {
		return f.ResetPasswordFn(ctx, p, m, id, pw)
	}
	return errNotConfigured
}

func (f *fakeAuth) RevokeSessions(ctx context.Context, p auth.Principal, m auth.Meta, id uuid.UUID) error {
	if f.RevokeSessionsFn != nil {
		return f.RevokeSessionsFn(ctx, p, m, id)
	}
	return errNotConfigured
}

func (f *fakeAuth) CreateToken(ctx context.Context, p auth.Principal, m auth.Meta, in auth.NewToken) (string, auth.Token, error) {
	if f.CreateTokenFn != nil {
		return f.CreateTokenFn(ctx, p, m, in)
	}
	return "", auth.Token{}, errNotConfigured
}

func (f *fakeAuth) ListTokens(ctx context.Context, p auth.Principal, m auth.Meta, userID uuid.UUID) ([]auth.Token, error) {
	if f.ListTokensFn != nil {
		return f.ListTokensFn(ctx, p, m, userID)
	}
	return nil, errNotConfigured
}

func (f *fakeAuth) RevokeToken(ctx context.Context, p auth.Principal, m auth.Meta, id uuid.UUID) error {
	if f.RevokeTokenFn != nil {
		return f.RevokeTokenFn(ctx, p, m, id)
	}
	return errNotConfigured
}

// fakeSetup implements SetupService with the same conventions as fakeAuth.
// Authenticate accepts only the token "setup-ok" unless AuthenticateFn is set.
type fakeSetup struct {
	StatusFn                func(ctx context.Context) (setup.Status, error)
	StartSessionFn          func(ctx context.Context, code string, m auth.Meta) (string, error)
	AuthenticateFn          func(ctx context.Context, token string) error
	SetLanguageFn           func(ctx context.Context, token, language string) error
	BeginAdminEnrollmentFn  func(ctx context.Context, token string, in setup.AdminInput) (auth.TOTPEnrollment, error)
	CreateAdminFn           func(ctx context.Context, token, code string, m auth.Meta) (auth.SessionResult, error)
	SetRecoveryPassphraseFn func(ctx context.Context, p auth.Principal, m auth.Meta, passphrase, confirm string) error
	CompleteFn              func(ctx context.Context, p auth.Principal, m auth.Meta) (setup.Status, error)
	ChooseEvaluationFn      func(ctx context.Context, p auth.Principal, m auth.Meta) (setup.Status, error)
}

func (f *fakeSetup) Status(ctx context.Context) (setup.Status, error) {
	if f.StatusFn != nil {
		return f.StatusFn(ctx)
	}
	return setup.Status{}, errNotConfigured
}

func (f *fakeSetup) StartSession(ctx context.Context, code string, m auth.Meta) (string, error) {
	if f.StartSessionFn != nil {
		return f.StartSessionFn(ctx, code, m)
	}
	return "", errNotConfigured
}

func (f *fakeSetup) Authenticate(ctx context.Context, token string) error {
	if f.AuthenticateFn != nil {
		return f.AuthenticateFn(ctx, token)
	}
	if token == "setup-ok" {
		return nil
	}
	return setup.ErrSessionInvalid
}

func (f *fakeSetup) SetLanguage(ctx context.Context, token, lang string) error {
	if f.SetLanguageFn != nil {
		return f.SetLanguageFn(ctx, token, lang)
	}
	return errNotConfigured
}

func (f *fakeSetup) BeginAdminEnrollment(ctx context.Context, token string, in setup.AdminInput) (auth.TOTPEnrollment, error) {
	if f.BeginAdminEnrollmentFn != nil {
		return f.BeginAdminEnrollmentFn(ctx, token, in)
	}
	return auth.TOTPEnrollment{}, errNotConfigured
}

func (f *fakeSetup) CreateAdmin(ctx context.Context, token, code string, m auth.Meta) (auth.SessionResult, error) {
	if f.CreateAdminFn != nil {
		return f.CreateAdminFn(ctx, token, code, m)
	}
	return auth.SessionResult{}, errNotConfigured
}

func (f *fakeSetup) SetRecoveryPassphrase(ctx context.Context, p auth.Principal, m auth.Meta, pass, confirm string) error {
	if f.SetRecoveryPassphraseFn != nil {
		return f.SetRecoveryPassphraseFn(ctx, p, m, pass, confirm)
	}
	return errNotConfigured
}

func (f *fakeSetup) Complete(ctx context.Context, p auth.Principal, m auth.Meta) (setup.Status, error) {
	if f.CompleteFn != nil {
		return f.CompleteFn(ctx, p, m)
	}
	return setup.Status{}, errNotConfigured
}

func (f *fakeSetup) ChooseEvaluation(ctx context.Context, p auth.Principal, m auth.Meta) (setup.Status, error) {
	if f.ChooseEvaluationFn != nil {
		return f.ChooseEvaluationFn(ctx, p, m)
	}
	return setup.Status{}, errNotConfigured
}

// fakeAudit implements AuditService and records written events.
type fakeAudit struct {
	mu        sync.Mutex
	events    []audit.Event
	ListFn    func(ctx context.Context, f audit.Filter) ([]audit.Entry, int64, error)
	IterateFn func(ctx context.Context, fn func(audit.Entry) error) error
	VerifyFn  func(ctx context.Context, actor audit.Actor) (audit.Report, error)
	// WriteFn, when set, sees every write first; an error it returns is the write's error and
	// nothing is recorded.
	WriteFn func(ctx context.Context, e audit.Event) error

	VerifyReadOnlyFn func(ctx context.Context) (audit.Report, error)
}

func (f *fakeAudit) Write(ctx context.Context, e audit.Event) error {
	if f.WriteFn != nil {
		if err := f.WriteFn(ctx, e); err != nil {
			return err
		}
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	f.events = append(f.events, e)
	return nil
}

// Events returns a copy of the recorded events.
func (f *fakeAudit) Events() []audit.Event {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]audit.Event(nil), f.events...)
}

// Count returns how many recorded events have the given action.
func (f *fakeAudit) Count(action string) int {
	n := 0
	for _, e := range f.Events() {
		if e.Action == action {
			n++
		}
	}
	return n
}

func (f *fakeAudit) List(ctx context.Context, fl audit.Filter) ([]audit.Entry, int64, error) {
	if f.ListFn != nil {
		return f.ListFn(ctx, fl)
	}
	return nil, 0, errNotConfigured
}

func (f *fakeAudit) Iterate(ctx context.Context, fn func(audit.Entry) error) error {
	if f.IterateFn != nil {
		return f.IterateFn(ctx, fn)
	}
	return errNotConfigured
}

func (f *fakeAudit) Verify(ctx context.Context, a audit.Actor) (audit.Report, error) {
	if f.VerifyFn != nil {
		return f.VerifyFn(ctx, a)
	}
	return audit.Report{}, errNotConfigured
}

// Test identities. Session cookie values and bearer tokens map to principals
// in identityAuth; the setup cookie "setup-ok" is accepted by fakeSetup.
var (
	adminID    = uuid.MustParse("0190f5a0-0000-7000-8000-000000000001")
	operatorID = uuid.MustParse("0190f5a0-0000-7000-8000-000000000002")
	auditorID  = uuid.MustParse("0190f5a0-0000-7000-8000-000000000003")
	admin2ID   = uuid.MustParse("0190f5a0-0000-7000-8000-000000000004")
)

// identityAuth returns a fakeAuth that recognises the matrix identities.
// now is the fake clock time used for step-up windows.
func identityAuth(now time.Time) *fakeAuth {
	session := func(id uuid.UUID, name string, role rbac.Role, stepUp bool) auth.Principal {
		p := auth.Principal{Kind: rbac.UserSession, UserID: id, Username: name, DisplayName: name, Role: role, Locale: "en", SessionHash: []byte(name)}
		if stepUp {
			p.StepUpUntil = now.Add(5 * time.Minute)
		}
		return p
	}
	sessions := map[string]auth.Principal{
		"admin":           session(adminID, "admin", rbac.Admin, false),
		"operator":        session(operatorID, "operator", rbac.Operator, false),
		"auditor":         session(auditorID, "auditor", rbac.Auditor, false),
		"admin-stepup":    session(adminID, "admin", rbac.Admin, true),
		"admin2-stepup":   session(admin2ID, "admin2", rbac.Admin, true), // a second Administrator (per-user limits)
		"operator-stepup": session(operatorID, "operator", rbac.Operator, true),
		"auditor-stepup":  session(auditorID, "auditor", rbac.Auditor, true),
		"pending":         {Kind: rbac.PendingSession, UserID: operatorID, Username: "operator", Role: rbac.Operator, SessionHash: []byte("pending")},
		"admin-pending":   {Kind: rbac.PendingSession, UserID: adminID, Username: "admin", Role: rbac.Admin, SessionHash: []byte("admin-pending")},
	}
	token := func(id uuid.UUID, name string, role rbac.Role, scope rbac.Scope) auth.Principal {
		return auth.Principal{Kind: rbac.APIToken, UserID: id, Username: name, Role: role, TokenID: uuid.NewSHA1(uuid.NameSpaceOID, []byte(name+string(scope))), Scope: scope}
	}
	tokens := map[string]auth.Principal{
		"alice_read_admin":       token(adminID, "admin", rbac.Admin, rbac.ScopeRead),
		"alice_operate_operator": token(operatorID, "operator", rbac.Operator, rbac.ScopeOperate),
		"alice_read_auditor":     token(auditorID, "auditor", rbac.Auditor, rbac.ScopeRead),
		"alice_operate_admin":    token(adminID, "admin", rbac.Admin, rbac.ScopeOperate),
	}
	return &fakeAuth{
		AuthenticateFn: func(_ context.Context, t string) (auth.Principal, error) {
			if p, ok := sessions[t]; ok {
				return p, nil
			}
			return auth.Principal{}, auth.ErrUnauthenticated // includes "expired" and "disabled"
		},
		AuthenticateTokenFn: func(_ context.Context, b string) (auth.Principal, error) {
			if p, ok := tokens[b]; ok {
				return p, nil
			}
			return auth.Principal{}, auth.ErrUnauthenticated
		},
	}
}

func (f *fakeAudit) VerifyReadOnly(ctx context.Context) (audit.Report, error) {
	if f.VerifyReadOnlyFn != nil {
		return f.VerifyReadOnlyFn(ctx)
	}
	return audit.Report{}, errNotConfigured
}

// fakeLicense implements LicenseService. Allow returns err and counts calls; the other
// methods call their function fields (errNotConfigured when nil).
type fakeLicense struct {
	mu        sync.Mutex
	err       error
	calls     int
	snap      license.Snapshot
	DetailFn  func(ctx context.Context) (license.Detail, error)
	PreviewFn func(ctx context.Context, raw []byte) (license.UploadResult, error)
	InstallFn func(ctx context.Context, raw []byte, actor audit.Actor, by uuid.UUID) (license.UploadResult, error)
}

func (f *fakeLicense) Allow(license.Class) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls++
	return f.err
}

func (f *fakeLicense) Snapshot() license.Snapshot {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.snap
}

func (f *fakeLicense) Detail(ctx context.Context) (license.Detail, error) {
	if f.DetailFn != nil {
		return f.DetailFn(ctx)
	}
	return license.Detail{}, errNotConfigured
}

func (f *fakeLicense) Preview(ctx context.Context, raw []byte) (license.UploadResult, error) {
	if f.PreviewFn != nil {
		return f.PreviewFn(ctx, raw)
	}
	return license.UploadResult{}, errNotConfigured
}

func (f *fakeLicense) Install(ctx context.Context, raw []byte, actor audit.Actor, by uuid.UUID) (license.UploadResult, error) {
	if f.InstallFn != nil {
		return f.InstallFn(ctx, raw, actor, by)
	}
	return license.UploadResult{}, errNotConfigured
}

func (f *fakeLicense) set(err error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.err = err
}

func (f *fakeLicense) count() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.calls
}

// fakeInventory implements InventoryService. Each method calls its function field when set;
// otherwise it returns zero values and errNotConfigured.
type fakeInventory struct {
	ListTargetsFn       func(ctx context.Context) ([]inventory.Target, error)
	GetTargetFn         func(ctx context.Context, id uuid.UUID) (inventory.Target, error)
	CreateTargetFn      func(ctx context.Context, a inventory.Actor, in inventory.NewTarget) (inventory.Target, uuid.UUID, error)
	UpdateTargetFn      func(ctx context.Context, a inventory.Actor, id uuid.UUID, ifVersion int, p inventory.TargetPatch) (inventory.Target, error)
	DeleteTargetFn      func(ctx context.Context, a inventory.Actor, id uuid.UUID) error
	RequestTestFn       func(ctx context.Context, a inventory.Actor, id uuid.UUID) (uuid.UUID, error)
	RequestDiscoveryFn  func(ctx context.Context, a inventory.Actor, id uuid.UUID) (uuid.UUID, error)
	ListHostKeysFn      func(ctx context.Context, targetID uuid.UUID) ([]inventory.HostKeyRecord, error)
	ConfirmHostKeyFn    func(ctx context.Context, a inventory.Actor, targetID, keyID uuid.UUID, fingerprint string) (uuid.UUID, error)
	RepinHostKeyFn      func(ctx context.Context, a inventory.Actor, targetID, keyID uuid.UUID, fingerprint, reason string) (uuid.UUID, error)
	ListTargetKeysFn    func(ctx context.Context, targetID uuid.UUID, includeMissing bool) ([]inventory.KeyLocation, error)
	ListSSHKeysFn       func(ctx context.Context, f inventory.KeyFilter) (inventory.KeyPage, error)
	GetSSHKeyFn         func(ctx context.Context, id uuid.UUID) (inventory.SSHKey, error)
	SetupGuideFn        func(ctx context.Context, from string) (inventory.Guide, error)
	RequestKeyRemovalFn func(ctx context.Context, a inventory.Actor, locationID uuid.UUID, confirmLastRootKey bool) (uuid.UUID, error)

	ListCertificatesFn  func(ctx context.Context, f inventory.CertificateFilter) (inventory.CertificatePage, error)
	GetCertificateFn    func(ctx context.Context, id uuid.UUID) (inventory.Certificate, error)
	UploadCertificateFn func(ctx context.Context, a inventory.Actor, in inventory.UploadInput) (inventory.Certificate, []string, error)
	CreateCSRFn         func(ctx context.Context, a inventory.Actor, in inventory.CSRInput) (inventory.CSR, error)
	ListCSRsFn          func(ctx context.Context) ([]inventory.CSR, error)
	GetCSRFn            func(ctx context.Context, id uuid.UUID) (inventory.CSR, error)
	CompleteCSRFn       func(ctx context.Context, a inventory.Actor, id uuid.UUID, certificatePEM, label string) (inventory.Certificate, []string, error)
	CancelCSRFn         func(ctx context.Context, a inventory.Actor, id uuid.UUID) (inventory.CSR, error)
	ListLocationsFn     func(ctx context.Context, targetID uuid.UUID, includeMissing bool) (inventory.LocationList, error)
	UpdateLocationFn    func(ctx context.Context, a inventory.Actor, id uuid.UUID, ifVersion int, p inventory.LocationPatch) (inventory.CertificateLocation, error)
	RequestDeploymentFn func(ctx context.Context, a inventory.Actor, in inventory.DeployRequestInput) ([]inventory.RequestedDeployment, error)
	ListDeploymentsFn   func(ctx context.Context, f inventory.DeploymentFilter) (inventory.DeploymentPage, error)
	DeploymentFn        func(ctx context.Context, id uuid.UUID) (inventory.Deployment, error)

	CreateVaultFn                  func(ctx context.Context, a inventory.Actor, in inventory.NewVault) (inventory.Target, providers.ConnectionReport, uuid.UUID, error)
	ReplaceVaultCredentialsFn      func(ctx context.Context, a inventory.Actor, id uuid.UUID, ifVersion int, in inventory.VaultCredentialInput) (inventory.Target, providers.ConnectionReport, uuid.UUID, error)
	DeleteVaultFn                  func(ctx context.Context, a inventory.Actor, id uuid.UUID, removeBindings bool) error
	RequestAccessCheckFn           func(ctx context.Context, a inventory.Actor, vaultID, readSecretOf uuid.UUID) (uuid.UUID, error)
	ListKVCertificatesFn           func(ctx context.Context, vault uuid.UUID, f inventory.KVFilter) (inventory.KVCertificatePage, error)
	KVCertificateFn                func(ctx context.Context, vault, id uuid.UUID) (inventory.KVCertificateDetail, error)
	ListKVKeysFn                   func(ctx context.Context, vault uuid.UUID, f inventory.KVFilter) ([]inventory.KVKey, string, error)
	ListKVSecretsFn                func(ctx context.Context, vault uuid.UUID, f inventory.KVFilter) ([]inventory.KVSecret, string, error)
	ListDeployableLocationsFn      func(ctx context.Context, f inventory.LocationFilter) (inventory.DeployableLocationPage, error)
	CreateBindingFn                func(ctx context.Context, a inventory.Actor, in inventory.BindingInput) (inventory.Binding, error)
	UpdateBindingLocationsStrictFn func(ctx context.Context, a inventory.Actor, id uuid.UUID, ifVersion int, locations []uuid.UUID, strict bool) (inventory.Binding, error)
	SetAutoDeployFn                func(ctx context.Context, a inventory.Actor, id uuid.UUID, ifVersion int, enabled bool) (inventory.Binding, error)
	DeleteBindingFn                func(ctx context.Context, a inventory.Actor, id uuid.UUID) error
	BindingFn                      func(ctx context.Context, id uuid.UUID) (inventory.Binding, error)
	RequestKVDeploymentFn          func(ctx context.Context, a inventory.Actor, in inventory.KVDeployInput) ([]inventory.RequestedDeployment, error)
	ReleaseVersionFn               func(ctx context.Context, a inventory.Actor, in inventory.ReleaseInput) (inventory.KVVersion, error)
	RequestImportFn                func(ctx context.Context, a inventory.Actor, in inventory.ImportInput) (inventory.KVImport, error)
	ImportFn                       func(ctx context.Context, vault, id uuid.UUID) (inventory.KVImport, error)
	ListImportsPageFn              func(ctx context.Context, vault uuid.UUID, f inventory.ImportFilter) (inventory.ImportPage, error)
}

func (f *fakeInventory) ListCertificates(ctx context.Context, fl inventory.CertificateFilter) (inventory.CertificatePage, error) {
	if f.ListCertificatesFn != nil {
		return f.ListCertificatesFn(ctx, fl)
	}
	return inventory.CertificatePage{}, errNotConfigured
}

func (f *fakeInventory) GetCertificate(ctx context.Context, id uuid.UUID) (inventory.Certificate, error) {
	if f.GetCertificateFn != nil {
		return f.GetCertificateFn(ctx, id)
	}
	return inventory.Certificate{}, errNotConfigured
}

func (f *fakeInventory) UploadCertificate(ctx context.Context, a inventory.Actor, in inventory.UploadInput) (inventory.Certificate, []string, error) {
	if f.UploadCertificateFn != nil {
		return f.UploadCertificateFn(ctx, a, in)
	}
	return inventory.Certificate{}, nil, errNotConfigured
}

func (f *fakeInventory) CreateCSR(ctx context.Context, a inventory.Actor, in inventory.CSRInput) (inventory.CSR, error) {
	if f.CreateCSRFn != nil {
		return f.CreateCSRFn(ctx, a, in)
	}
	return inventory.CSR{}, errNotConfigured
}

func (f *fakeInventory) ListCSRs(ctx context.Context) ([]inventory.CSR, error) {
	if f.ListCSRsFn != nil {
		return f.ListCSRsFn(ctx)
	}
	return nil, errNotConfigured
}

func (f *fakeInventory) GetCSR(ctx context.Context, id uuid.UUID) (inventory.CSR, error) {
	if f.GetCSRFn != nil {
		return f.GetCSRFn(ctx, id)
	}
	return inventory.CSR{}, errNotConfigured
}

func (f *fakeInventory) CompleteCSR(ctx context.Context, a inventory.Actor, id uuid.UUID, pemText, label string) (inventory.Certificate, []string, error) {
	if f.CompleteCSRFn != nil {
		return f.CompleteCSRFn(ctx, a, id, pemText, label)
	}
	return inventory.Certificate{}, nil, errNotConfigured
}

func (f *fakeInventory) CancelCSR(ctx context.Context, a inventory.Actor, id uuid.UUID) (inventory.CSR, error) {
	if f.CancelCSRFn != nil {
		return f.CancelCSRFn(ctx, a, id)
	}
	return inventory.CSR{}, errNotConfigured
}

func (f *fakeInventory) ListLocations(ctx context.Context, targetID uuid.UUID, includeMissing bool) (inventory.LocationList, error) {
	if f.ListLocationsFn != nil {
		return f.ListLocationsFn(ctx, targetID, includeMissing)
	}
	return inventory.LocationList{}, errNotConfigured
}

func (f *fakeInventory) UpdateLocation(ctx context.Context, a inventory.Actor, id uuid.UUID, v int, p inventory.LocationPatch) (inventory.CertificateLocation, error) {
	if f.UpdateLocationFn != nil {
		return f.UpdateLocationFn(ctx, a, id, v, p)
	}
	return inventory.CertificateLocation{}, errNotConfigured
}

func (f *fakeInventory) RequestDeployment(ctx context.Context, a inventory.Actor, in inventory.DeployRequestInput) ([]inventory.RequestedDeployment, error) {
	if f.RequestDeploymentFn != nil {
		return f.RequestDeploymentFn(ctx, a, in)
	}
	return nil, errNotConfigured
}

func (f *fakeInventory) ListDeployments(ctx context.Context, fl inventory.DeploymentFilter) (inventory.DeploymentPage, error) {
	if f.ListDeploymentsFn != nil {
		return f.ListDeploymentsFn(ctx, fl)
	}
	return inventory.DeploymentPage{}, errNotConfigured
}

func (f *fakeInventory) Deployment(ctx context.Context, id uuid.UUID) (inventory.Deployment, error) {
	if f.DeploymentFn != nil {
		return f.DeploymentFn(ctx, id)
	}
	return inventory.Deployment{}, errNotConfigured
}

func (f *fakeInventory) ListTargets(ctx context.Context) ([]inventory.Target, error) {
	if f.ListTargetsFn != nil {
		return f.ListTargetsFn(ctx)
	}
	return nil, errNotConfigured
}

func (f *fakeInventory) GetTarget(ctx context.Context, id uuid.UUID) (inventory.Target, error) {
	if f.GetTargetFn != nil {
		return f.GetTargetFn(ctx, id)
	}
	return inventory.Target{}, errNotConfigured
}

func (f *fakeInventory) CreateTarget(ctx context.Context, a inventory.Actor, in inventory.NewTarget) (inventory.Target, uuid.UUID, error) {
	if f.CreateTargetFn != nil {
		return f.CreateTargetFn(ctx, a, in)
	}
	return inventory.Target{}, uuid.Nil, errNotConfigured
}

func (f *fakeInventory) UpdateTarget(ctx context.Context, a inventory.Actor, id uuid.UUID, v int, p inventory.TargetPatch) (inventory.Target, error) {
	if f.UpdateTargetFn != nil {
		return f.UpdateTargetFn(ctx, a, id, v, p)
	}
	return inventory.Target{}, errNotConfigured
}

func (f *fakeInventory) DeleteTarget(ctx context.Context, a inventory.Actor, id uuid.UUID) error {
	if f.DeleteTargetFn != nil {
		return f.DeleteTargetFn(ctx, a, id)
	}
	return errNotConfigured
}

func (f *fakeInventory) RequestTest(ctx context.Context, a inventory.Actor, id uuid.UUID) (uuid.UUID, error) {
	if f.RequestTestFn != nil {
		return f.RequestTestFn(ctx, a, id)
	}
	return uuid.Nil, errNotConfigured
}

func (f *fakeInventory) RequestDiscovery(ctx context.Context, a inventory.Actor, id uuid.UUID) (uuid.UUID, error) {
	if f.RequestDiscoveryFn != nil {
		return f.RequestDiscoveryFn(ctx, a, id)
	}
	return uuid.Nil, errNotConfigured
}

func (f *fakeInventory) ListHostKeys(ctx context.Context, targetID uuid.UUID) ([]inventory.HostKeyRecord, error) {
	if f.ListHostKeysFn != nil {
		return f.ListHostKeysFn(ctx, targetID)
	}
	return nil, errNotConfigured
}

func (f *fakeInventory) ConfirmHostKey(ctx context.Context, a inventory.Actor, targetID, keyID uuid.UUID, fp string) (uuid.UUID, error) {
	if f.ConfirmHostKeyFn != nil {
		return f.ConfirmHostKeyFn(ctx, a, targetID, keyID, fp)
	}
	return uuid.Nil, errNotConfigured
}

func (f *fakeInventory) RepinHostKey(ctx context.Context, a inventory.Actor, targetID, keyID uuid.UUID, fp, reason string) (uuid.UUID, error) {
	if f.RepinHostKeyFn != nil {
		return f.RepinHostKeyFn(ctx, a, targetID, keyID, fp, reason)
	}
	return uuid.Nil, errNotConfigured
}

func (f *fakeInventory) ListTargetKeys(ctx context.Context, targetID uuid.UUID, includeMissing bool) ([]inventory.KeyLocation, error) {
	if f.ListTargetKeysFn != nil {
		return f.ListTargetKeysFn(ctx, targetID, includeMissing)
	}
	return nil, errNotConfigured
}

func (f *fakeInventory) ListSSHKeys(ctx context.Context, fl inventory.KeyFilter) (inventory.KeyPage, error) {
	if f.ListSSHKeysFn != nil {
		return f.ListSSHKeysFn(ctx, fl)
	}
	return inventory.KeyPage{}, errNotConfigured
}

func (f *fakeInventory) GetSSHKey(ctx context.Context, id uuid.UUID) (inventory.SSHKey, error) {
	if f.GetSSHKeyFn != nil {
		return f.GetSSHKeyFn(ctx, id)
	}
	return inventory.SSHKey{}, errNotConfigured
}

func (f *fakeInventory) SetupGuide(ctx context.Context, from string) (inventory.Guide, error) {
	if f.SetupGuideFn != nil {
		return f.SetupGuideFn(ctx, from)
	}
	return inventory.Guide{}, errNotConfigured
}

func (f *fakeInventory) RequestKeyRemoval(ctx context.Context, a inventory.Actor, id uuid.UUID, confirm bool) (uuid.UUID, error) {
	if f.RequestKeyRemovalFn != nil {
		return f.RequestKeyRemovalFn(ctx, a, id, confirm)
	}
	return uuid.Nil, errNotConfigured
}

func (f *fakeInventory) CreateVault(ctx context.Context, a inventory.Actor, in inventory.NewVault) (inventory.Target, providers.ConnectionReport, uuid.UUID, error) {
	if f.CreateVaultFn != nil {
		return f.CreateVaultFn(ctx, a, in)
	}
	return inventory.Target{}, providers.ConnectionReport{}, uuid.Nil, errNotConfigured
}

func (f *fakeInventory) ReplaceVaultCredentials(ctx context.Context, a inventory.Actor, id uuid.UUID, v int, in inventory.VaultCredentialInput) (inventory.Target, providers.ConnectionReport, uuid.UUID, error) {
	if f.ReplaceVaultCredentialsFn != nil {
		return f.ReplaceVaultCredentialsFn(ctx, a, id, v, in)
	}
	return inventory.Target{}, providers.ConnectionReport{}, uuid.Nil, errNotConfigured
}

func (f *fakeInventory) DeleteVault(ctx context.Context, a inventory.Actor, id uuid.UUID, remove bool) error {
	if f.DeleteVaultFn != nil {
		return f.DeleteVaultFn(ctx, a, id, remove)
	}
	return errNotConfigured
}

func (f *fakeInventory) RequestAccessCheck(ctx context.Context, a inventory.Actor, vaultID, readSecretOf uuid.UUID) (uuid.UUID, error) {
	if f.RequestAccessCheckFn != nil {
		return f.RequestAccessCheckFn(ctx, a, vaultID, readSecretOf)
	}
	return uuid.Nil, errNotConfigured
}

func (f *fakeInventory) ListKVCertificates(ctx context.Context, vault uuid.UUID, fl inventory.KVFilter) (inventory.KVCertificatePage, error) {
	if f.ListKVCertificatesFn != nil {
		return f.ListKVCertificatesFn(ctx, vault, fl)
	}
	return inventory.KVCertificatePage{}, errNotConfigured
}

func (f *fakeInventory) KVCertificate(ctx context.Context, vault, id uuid.UUID) (inventory.KVCertificateDetail, error) {
	if f.KVCertificateFn != nil {
		return f.KVCertificateFn(ctx, vault, id)
	}
	return inventory.KVCertificateDetail{}, errNotConfigured
}

func (f *fakeInventory) ListKVKeys(ctx context.Context, vault uuid.UUID, fl inventory.KVFilter) ([]inventory.KVKey, string, error) {
	if f.ListKVKeysFn != nil {
		return f.ListKVKeysFn(ctx, vault, fl)
	}
	return nil, "", errNotConfigured
}

func (f *fakeInventory) ListKVSecrets(ctx context.Context, vault uuid.UUID, fl inventory.KVFilter) ([]inventory.KVSecret, string, error) {
	if f.ListKVSecretsFn != nil {
		return f.ListKVSecretsFn(ctx, vault, fl)
	}
	return nil, "", errNotConfigured
}

func (f *fakeInventory) ListDeployableLocations(ctx context.Context, fl inventory.LocationFilter) (inventory.DeployableLocationPage, error) {
	if f.ListDeployableLocationsFn != nil {
		return f.ListDeployableLocationsFn(ctx, fl)
	}
	return inventory.DeployableLocationPage{}, errNotConfigured
}

func (f *fakeInventory) CreateBinding(ctx context.Context, a inventory.Actor, in inventory.BindingInput) (inventory.Binding, error) {
	if f.CreateBindingFn != nil {
		return f.CreateBindingFn(ctx, a, in)
	}
	return inventory.Binding{}, errNotConfigured
}

func (f *fakeInventory) UpdateBindingLocationsStrict(ctx context.Context, a inventory.Actor, id uuid.UUID, v int, l []uuid.UUID, strict bool) (inventory.Binding, error) {
	if f.UpdateBindingLocationsStrictFn != nil {
		return f.UpdateBindingLocationsStrictFn(ctx, a, id, v, l, strict)
	}
	return inventory.Binding{}, errNotConfigured
}

func (f *fakeInventory) SetAutoDeploy(ctx context.Context, a inventory.Actor, id uuid.UUID, v int, enabled bool) (inventory.Binding, error) {
	if f.SetAutoDeployFn != nil {
		return f.SetAutoDeployFn(ctx, a, id, v, enabled)
	}
	return inventory.Binding{}, errNotConfigured
}

func (f *fakeInventory) DeleteBinding(ctx context.Context, a inventory.Actor, id uuid.UUID) error {
	if f.DeleteBindingFn != nil {
		return f.DeleteBindingFn(ctx, a, id)
	}
	return errNotConfigured
}

func (f *fakeInventory) Binding(ctx context.Context, id uuid.UUID) (inventory.Binding, error) {
	if f.BindingFn != nil {
		return f.BindingFn(ctx, id)
	}
	return inventory.Binding{}, errNotConfigured
}

func (f *fakeInventory) RequestKVDeployment(ctx context.Context, a inventory.Actor, in inventory.KVDeployInput) ([]inventory.RequestedDeployment, error) {
	if f.RequestKVDeploymentFn != nil {
		return f.RequestKVDeploymentFn(ctx, a, in)
	}
	return nil, errNotConfigured
}

func (f *fakeInventory) ReleaseVersion(ctx context.Context, a inventory.Actor, in inventory.ReleaseInput) (inventory.KVVersion, error) {
	if f.ReleaseVersionFn != nil {
		return f.ReleaseVersionFn(ctx, a, in)
	}
	return inventory.KVVersion{}, errNotConfigured
}

func (f *fakeInventory) RequestImport(ctx context.Context, a inventory.Actor, in inventory.ImportInput) (inventory.KVImport, error) {
	if f.RequestImportFn != nil {
		return f.RequestImportFn(ctx, a, in)
	}
	return inventory.KVImport{}, errNotConfigured
}

func (f *fakeInventory) Import(ctx context.Context, vault, id uuid.UUID) (inventory.KVImport, error) {
	if f.ImportFn != nil {
		return f.ImportFn(ctx, vault, id)
	}
	return inventory.KVImport{}, errNotConfigured
}

func (f *fakeInventory) ListImportsPage(ctx context.Context, vault uuid.UUID, fl inventory.ImportFilter) (inventory.ImportPage, error) {
	if f.ListImportsPageFn != nil {
		return f.ListImportsPageFn(ctx, vault, fl)
	}
	return inventory.ImportPage{}, errNotConfigured
}

// fakeJobs implements JobsService with the same conventions.
type fakeJobs struct {
	GetFn     func(ctx context.Context, id uuid.UUID) (jobs.View, error)
	ListFn    func(ctx context.Context, f jobs.ListFilter) ([]jobs.View, string, error)
	ConfirmFn func(ctx context.Context, actor audit.Actor, by, id uuid.UUID) error
	DiscardFn func(ctx context.Context, actor audit.Actor, by, id uuid.UUID) error
}

func (f *fakeJobs) Get(ctx context.Context, id uuid.UUID) (jobs.View, error) {
	if f.GetFn != nil {
		return f.GetFn(ctx, id)
	}
	return jobs.View{}, errNotConfigured
}

func (f *fakeJobs) List(ctx context.Context, fl jobs.ListFilter) ([]jobs.View, string, error) {
	if f.ListFn != nil {
		return f.ListFn(ctx, fl)
	}
	return nil, "", errNotConfigured
}

func (f *fakeJobs) Confirm(ctx context.Context, actor audit.Actor, by, id uuid.UUID) error {
	if f.ConfirmFn != nil {
		return f.ConfirmFn(ctx, actor, by, id)
	}
	return errNotConfigured
}

func (f *fakeJobs) Discard(ctx context.Context, actor audit.Actor, by, id uuid.UUID) error {
	if f.DiscardFn != nil {
		return f.DiscardFn(ctx, actor, by, id)
	}
	return errNotConfigured
}

// fakeProviders implements ProviderCatalog.
type fakeProviders struct{ items []providers.Descriptor }

func (f fakeProviders) List() []providers.Descriptor { return f.items }

// fakeSSHKeys implements SSHKeysService. Each method records its name in calls and calls its function field when
// set; otherwise it answers zero values and errNotConfigured.
type fakeSSHKeys struct {
	mu    sync.Mutex
	calls []string

	GenerateFn           func(ctx context.Context, a inventory.Actor, in sshkeys.GenerateInput) (sshkeys.ManagedKey, error)
	ManagedKeyFn         func(ctx context.Context, id uuid.UUID) (sshkeys.ManagedKey, error)
	RequestDeployFn      func(ctx context.Context, a inventory.Actor, in sshkeys.DeployInput) (uuid.UUID, error)
	DownloadPrivateKeyFn func(ctx context.Context, a inventory.Actor, in sshkeys.DownloadInput) (sshkeys.Download, error)
	CreatePolicyFn       func(ctx context.Context, a inventory.Actor, in sshkeys.PolicyInput) (sshkeys.Policy, error)
	UpdatePolicyFn       func(ctx context.Context, a inventory.Actor, id uuid.UUID, version int, p sshkeys.PolicyPatch) (sshkeys.Policy, error)
	SetPolicyEnabledFn   func(ctx context.Context, a inventory.Actor, id uuid.UUID, version int, enabled bool) (sshkeys.Policy, error)
	DeletePolicyFn       func(ctx context.Context, a inventory.Actor, id uuid.UUID, version int) error
	PolicyFn             func(ctx context.Context, id uuid.UUID) (sshkeys.Policy, error)
	PoliciesFn           func(ctx context.Context) ([]sshkeys.Policy, error)
	PreviewFn            func(ctx context.Context, a inventory.Actor, id uuid.UUID) (sshkeys.Preview, error)
	RunNowFn             func(ctx context.Context, a inventory.Actor, id uuid.UUID, digest string) (sshkeys.Rotation, error)
	RotationFn           func(ctx context.Context, id uuid.UUID) (sshkeys.Rotation, error)
	RotationSummariesFn  func(ctx context.Context, f sshkeys.RotationFilter) ([]sshkeys.RotationSummary, string, error)
	ContinueFn           func(ctx context.Context, a inventory.Actor, id uuid.UUID) error
	FinishNowFn          func(ctx context.Context, a inventory.Actor, id uuid.UUID) error
	KeepOldFn            func(ctx context.Context, a inventory.Actor, id uuid.UUID, locations []uuid.UUID) error
	AbortFn              func(ctx context.Context, a inventory.Actor, id uuid.UUID) error
}

func (f *fakeSSHKeys) record(name string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls = append(f.calls, name)
}

// Calls returns the names of the methods called so far.
func (f *fakeSSHKeys) Calls() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.calls...)
}

func (f *fakeSSHKeys) reset() {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls = nil
}

func (f *fakeSSHKeys) Generate(ctx context.Context, a inventory.Actor, in sshkeys.GenerateInput) (sshkeys.ManagedKey, error) {
	f.record("Generate")
	if f.GenerateFn != nil {
		return f.GenerateFn(ctx, a, in)
	}
	return sshkeys.ManagedKey{}, errNotConfigured
}

func (f *fakeSSHKeys) ManagedKey(ctx context.Context, id uuid.UUID) (sshkeys.ManagedKey, error) {
	f.record("ManagedKey")
	if f.ManagedKeyFn != nil {
		return f.ManagedKeyFn(ctx, id)
	}
	return sshkeys.ManagedKey{}, errNotConfigured
}

func (f *fakeSSHKeys) RequestDeploy(ctx context.Context, a inventory.Actor, in sshkeys.DeployInput) (uuid.UUID, error) {
	f.record("RequestDeploy")
	if f.RequestDeployFn != nil {
		return f.RequestDeployFn(ctx, a, in)
	}
	return uuid.Nil, errNotConfigured
}

func (f *fakeSSHKeys) DownloadPrivateKey(ctx context.Context, a inventory.Actor, in sshkeys.DownloadInput) (sshkeys.Download, error) {
	f.record("DownloadPrivateKey")
	if f.DownloadPrivateKeyFn != nil {
		return f.DownloadPrivateKeyFn(ctx, a, in)
	}
	return sshkeys.Download{}, errNotConfigured
}

func (f *fakeSSHKeys) CreatePolicy(ctx context.Context, a inventory.Actor, in sshkeys.PolicyInput) (sshkeys.Policy, error) {
	f.record("CreatePolicy")
	if f.CreatePolicyFn != nil {
		return f.CreatePolicyFn(ctx, a, in)
	}
	return sshkeys.Policy{}, errNotConfigured
}

func (f *fakeSSHKeys) UpdatePolicy(ctx context.Context, a inventory.Actor, id uuid.UUID, version int, p sshkeys.PolicyPatch) (sshkeys.Policy, error) {
	f.record("UpdatePolicy")
	if f.UpdatePolicyFn != nil {
		return f.UpdatePolicyFn(ctx, a, id, version, p)
	}
	return sshkeys.Policy{}, errNotConfigured
}

func (f *fakeSSHKeys) SetPolicyEnabled(ctx context.Context, a inventory.Actor, id uuid.UUID, version int, enabled bool) (sshkeys.Policy, error) {
	f.record("SetPolicyEnabled")
	if f.SetPolicyEnabledFn != nil {
		return f.SetPolicyEnabledFn(ctx, a, id, version, enabled)
	}
	return sshkeys.Policy{}, errNotConfigured
}

func (f *fakeSSHKeys) DeletePolicy(ctx context.Context, a inventory.Actor, id uuid.UUID, version int) error {
	f.record("DeletePolicy")
	if f.DeletePolicyFn != nil {
		return f.DeletePolicyFn(ctx, a, id, version)
	}
	return errNotConfigured
}

func (f *fakeSSHKeys) Policy(ctx context.Context, id uuid.UUID) (sshkeys.Policy, error) {
	f.record("Policy")
	if f.PolicyFn != nil {
		return f.PolicyFn(ctx, id)
	}
	return sshkeys.Policy{}, errNotConfigured
}

func (f *fakeSSHKeys) Policies(ctx context.Context) ([]sshkeys.Policy, error) {
	f.record("Policies")
	if f.PoliciesFn != nil {
		return f.PoliciesFn(ctx)
	}
	return nil, errNotConfigured
}

func (f *fakeSSHKeys) Preview(ctx context.Context, a inventory.Actor, id uuid.UUID) (sshkeys.Preview, error) {
	f.record("Preview")
	if f.PreviewFn != nil {
		return f.PreviewFn(ctx, a, id)
	}
	return sshkeys.Preview{}, errNotConfigured
}

func (f *fakeSSHKeys) RunNow(ctx context.Context, a inventory.Actor, id uuid.UUID, digest string) (sshkeys.Rotation, error) {
	f.record("RunNow")
	if f.RunNowFn != nil {
		return f.RunNowFn(ctx, a, id, digest)
	}
	return sshkeys.Rotation{}, errNotConfigured
}

func (f *fakeSSHKeys) Rotation(ctx context.Context, id uuid.UUID) (sshkeys.Rotation, error) {
	f.record("Rotation")
	if f.RotationFn != nil {
		return f.RotationFn(ctx, id)
	}
	return sshkeys.Rotation{}, errNotConfigured
}

func (f *fakeSSHKeys) RotationSummaries(ctx context.Context, fl sshkeys.RotationFilter) ([]sshkeys.RotationSummary, string, error) {
	f.record("RotationSummaries")
	if f.RotationSummariesFn != nil {
		return f.RotationSummariesFn(ctx, fl)
	}
	return nil, "", errNotConfigured
}

func (f *fakeSSHKeys) Continue(ctx context.Context, a inventory.Actor, id uuid.UUID) error {
	f.record("Continue")
	if f.ContinueFn != nil {
		return f.ContinueFn(ctx, a, id)
	}
	return errNotConfigured
}

func (f *fakeSSHKeys) FinishNow(ctx context.Context, a inventory.Actor, id uuid.UUID) error {
	f.record("FinishNow")
	if f.FinishNowFn != nil {
		return f.FinishNowFn(ctx, a, id)
	}
	return errNotConfigured
}

func (f *fakeSSHKeys) KeepOld(ctx context.Context, a inventory.Actor, id uuid.UUID, locations []uuid.UUID) error {
	f.record("KeepOld")
	if f.KeepOldFn != nil {
		return f.KeepOldFn(ctx, a, id, locations)
	}
	return errNotConfigured
}

func (f *fakeSSHKeys) Abort(ctx context.Context, a inventory.Actor, id uuid.UUID) error {
	f.record("Abort")
	if f.AbortFn != nil {
		return f.AbortFn(ctx, a, id)
	}
	return errNotConfigured
}

// phase7Fake counts the calls of a Phase 7 fake service (fakeMail, fakeAlerts, fakeReports).
type phase7Fake struct {
	mu sync.Mutex
	n  int
}

func (f *phase7Fake) record() {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.n++
}

func (f *phase7Fake) calls() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.n
}

func (f *phase7Fake) reset() {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.n = 0
}

// fakeMail implements MailService: one function field per method (errNotConfigured when nil), a call counter.
type fakeMail struct {
	phase7Fake
	SMTPFn           func(ctx context.Context) (notify.SMTPSettings, bool, error)
	SaveSMTPFn       func(ctx context.Context, a audit.Actor, version int, in notify.SMTPInput) (notify.SMTPSettings, error)
	DeleteSMTPFn     func(ctx context.Context, a audit.Actor, version int) error
	TestMailFn       func(ctx context.Context, a audit.Actor, to, locale string) error
	TrustFn          func(ctx context.Context, a audit.Actor, version int, fingerprint string) (notify.SMTPSettings, error)
	UntrustFn        func(ctx context.Context, a audit.Actor, version int) (notify.SMTPSettings, error)
	RecipientsFn     func(ctx context.Context) (notify.Recipients, error)
	SaveRecipientsFn func(ctx context.Context, a audit.Actor, version int, r notify.Recipients) (notify.Recipients, error)
	GeneralFn        func(ctx context.Context) (settings.General, error)
	SaveGeneralFn    func(ctx context.Context, a audit.Actor, version int, g settings.General) (settings.General, error)
	DeliveryFn       func(ctx context.Context) (notify.Delivery, error)
}

// succeed makes every method answer a harmless success.
func (f *fakeMail) succeed() {
	smtp := notify.SMTPSettings{Host: "smtp.example.com", Port: 587, TLSMode: "starttls", From: "alice@example.com", Version: 2}
	f.SMTPFn = func(context.Context) (notify.SMTPSettings, bool, error) { return smtp, true, nil }
	f.SaveSMTPFn = func(context.Context, audit.Actor, int, notify.SMTPInput) (notify.SMTPSettings, error) {
		return smtp, nil
	}
	f.DeleteSMTPFn = func(context.Context, audit.Actor, int) error { return nil }
	f.TestMailFn = func(context.Context, audit.Actor, string, string) error { return nil }
	f.TrustFn = func(context.Context, audit.Actor, int, string) (notify.SMTPSettings, error) { return smtp, nil }
	f.UntrustFn = func(context.Context, audit.Actor, int) (notify.SMTPSettings, error) { return smtp, nil }
	f.RecipientsFn = func(context.Context) (notify.Recipients, error) { return notify.Recipients{Administrators: true}, nil }
	f.SaveRecipientsFn = func(_ context.Context, _ audit.Actor, _ int, r notify.Recipients) (notify.Recipients, error) {
		r.Version = 1
		return r, nil
	}
	f.GeneralFn = func(context.Context) (settings.General, error) {
		return settings.General{RetiredKeyRetentionDays: 30}, nil
	}
	f.SaveGeneralFn = func(_ context.Context, _ audit.Actor, _ int, g settings.General) (settings.General, error) {
		g.Version = 1
		return g, nil
	}
	f.DeliveryFn = func(context.Context) (notify.Delivery, error) { return notify.Delivery{}, nil }
}

func (f *fakeMail) SMTP(ctx context.Context) (notify.SMTPSettings, bool, error) {
	f.record()
	if f.SMTPFn != nil {
		return f.SMTPFn(ctx)
	}
	return notify.SMTPSettings{}, false, errNotConfigured
}

func (f *fakeMail) SaveSMTP(ctx context.Context, a audit.Actor, version int, in notify.SMTPInput) (notify.SMTPSettings, error) {
	f.record()
	if f.SaveSMTPFn != nil {
		return f.SaveSMTPFn(ctx, a, version, in)
	}
	return notify.SMTPSettings{}, errNotConfigured
}

func (f *fakeMail) DeleteSMTP(ctx context.Context, a audit.Actor, version int) error {
	f.record()
	if f.DeleteSMTPFn != nil {
		return f.DeleteSMTPFn(ctx, a, version)
	}
	return errNotConfigured
}

func (f *fakeMail) TestMail(ctx context.Context, a audit.Actor, to, locale string) error {
	f.record()
	if f.TestMailFn != nil {
		return f.TestMailFn(ctx, a, to, locale)
	}
	return errNotConfigured
}

func (f *fakeMail) Trust(ctx context.Context, a audit.Actor, version int, fingerprint string) (notify.SMTPSettings, error) {
	f.record()
	if f.TrustFn != nil {
		return f.TrustFn(ctx, a, version, fingerprint)
	}
	return notify.SMTPSettings{}, errNotConfigured
}

func (f *fakeMail) Untrust(ctx context.Context, a audit.Actor, version int) (notify.SMTPSettings, error) {
	f.record()
	if f.UntrustFn != nil {
		return f.UntrustFn(ctx, a, version)
	}
	return notify.SMTPSettings{}, errNotConfigured
}

func (f *fakeMail) Recipients(ctx context.Context) (notify.Recipients, error) {
	f.record()
	if f.RecipientsFn != nil {
		return f.RecipientsFn(ctx)
	}
	return notify.Recipients{}, errNotConfigured
}

func (f *fakeMail) SaveRecipients(ctx context.Context, a audit.Actor, version int, r notify.Recipients) (notify.Recipients, error) {
	f.record()
	if f.SaveRecipientsFn != nil {
		return f.SaveRecipientsFn(ctx, a, version, r)
	}
	return notify.Recipients{}, errNotConfigured
}

func (f *fakeMail) General(ctx context.Context) (settings.General, error) {
	f.record()
	if f.GeneralFn != nil {
		return f.GeneralFn(ctx)
	}
	return settings.General{}, errNotConfigured
}

func (f *fakeMail) SaveGeneral(ctx context.Context, a audit.Actor, version int, g settings.General) (settings.General, error) {
	f.record()
	if f.SaveGeneralFn != nil {
		return f.SaveGeneralFn(ctx, a, version, g)
	}
	return settings.General{}, errNotConfigured
}

func (f *fakeMail) Delivery(ctx context.Context) (notify.Delivery, error) {
	f.record()
	if f.DeliveryFn != nil {
		return f.DeliveryFn(ctx)
	}
	return notify.Delivery{}, errNotConfigured
}

// fakeAlerts implements AlertsService.
type fakeAlerts struct {
	phase7Fake
	ThresholdsFn     func(ctx context.Context) (alerts.ThresholdSettings, error)
	SaveThresholdsFn func(ctx context.Context, a audit.Actor, version int, days []int) (alerts.ThresholdSettings, error)
}

func (f *fakeAlerts) succeed() {
	f.ThresholdsFn = func(context.Context) (alerts.ThresholdSettings, error) {
		return alerts.ThresholdSettings{Days: []int{60, 30, 14, 7, 1}}, nil
	}
	f.SaveThresholdsFn = func(_ context.Context, _ audit.Actor, version int, days []int) (alerts.ThresholdSettings, error) {
		return alerts.ThresholdSettings{Days: days, Version: version + 1}, nil
	}
}

func (f *fakeAlerts) Thresholds(ctx context.Context) (alerts.ThresholdSettings, error) {
	f.record()
	if f.ThresholdsFn != nil {
		return f.ThresholdsFn(ctx)
	}
	return alerts.ThresholdSettings{}, errNotConfigured
}

func (f *fakeAlerts) SaveThresholds(ctx context.Context, a audit.Actor, version int, days []int) (alerts.ThresholdSettings, error) {
	f.record()
	if f.SaveThresholdsFn != nil {
		return f.SaveThresholdsFn(ctx, a, version, days)
	}
	return alerts.ThresholdSettings{}, errNotConfigured
}

// fakeReports implements ReportsService; lastViewer is the viewer of the last Summary or Attention call.
type fakeReports struct {
	phase7Fake
	lastViewer           reports.Viewer
	SummaryFn            func(ctx context.Context, v reports.Viewer) (reports.Summary, error)
	ExpiringFn           func(ctx context.Context, days, limit int) ([]alerts.Item, error)
	AttentionFn          func(ctx context.Context, v reports.Viewer) ([]reports.Condition, error)
	ExportCertificatesFn func(ctx context.Context, a audit.Actor, f inventory.CertificateFilter, w io.Writer) (int, error)
	ExportSSHKeysFn      func(ctx context.Context, a audit.Actor, f inventory.KeyFilter, w io.Writer) (int, error)
	ViewsFn              func(ctx context.Context, userID uuid.UUID, page string) ([]reports.View, error)
	CreateViewFn         func(ctx context.Context, userID uuid.UUID, page, name string, query map[string]string) (reports.View, error)
	DeleteViewFn         func(ctx context.Context, userID, id uuid.UUID) error
}

func (f *fakeReports) succeed() {
	f.SummaryFn = func(context.Context, reports.Viewer) (reports.Summary, error) { return reports.Summary{}, nil }
	f.ExpiringFn = func(context.Context, int, int) ([]alerts.Item, error) { return nil, nil }
	f.AttentionFn = func(context.Context, reports.Viewer) ([]reports.Condition, error) { return nil, nil }
	f.ExportCertificatesFn = func(_ context.Context, _ audit.Actor, _ inventory.CertificateFilter, w io.Writer) (int, error) {
		_, err := w.Write([]byte("\xEF\xBB\xBFid\n"))
		return 0, err
	}
	f.ExportSSHKeysFn = func(_ context.Context, _ audit.Actor, _ inventory.KeyFilter, w io.Writer) (int, error) {
		_, err := w.Write([]byte("\xEF\xBB\xBFid\n"))
		return 0, err
	}
	f.ViewsFn = func(context.Context, uuid.UUID, string) ([]reports.View, error) { return nil, nil }
	f.CreateViewFn = func(_ context.Context, _ uuid.UUID, page, name string, query map[string]string) (reports.View, error) {
		return reports.View{ID: uuid.New(), Page: page, Name: name, Query: query}, nil
	}
	f.DeleteViewFn = func(context.Context, uuid.UUID, uuid.UUID) error { return nil }
}

func (f *fakeReports) Summary(ctx context.Context, v reports.Viewer) (reports.Summary, error) {
	f.record()
	f.mu.Lock()
	f.lastViewer = v
	f.mu.Unlock()
	if f.SummaryFn != nil {
		return f.SummaryFn(ctx, v)
	}
	return reports.Summary{}, errNotConfigured
}

func (f *fakeReports) Expiring(ctx context.Context, days, limit int) ([]alerts.Item, error) {
	f.record()
	if f.ExpiringFn != nil {
		return f.ExpiringFn(ctx, days, limit)
	}
	return nil, errNotConfigured
}

func (f *fakeReports) Attention(ctx context.Context, v reports.Viewer) ([]reports.Condition, error) {
	f.record()
	f.mu.Lock()
	f.lastViewer = v
	f.mu.Unlock()
	if f.AttentionFn != nil {
		return f.AttentionFn(ctx, v)
	}
	return nil, errNotConfigured
}

func (f *fakeReports) ExportCertificates(ctx context.Context, a audit.Actor, fl inventory.CertificateFilter, w io.Writer) (int, error) {
	f.record()
	if f.ExportCertificatesFn != nil {
		return f.ExportCertificatesFn(ctx, a, fl, w)
	}
	return 0, errNotConfigured
}

func (f *fakeReports) ExportSSHKeys(ctx context.Context, a audit.Actor, fl inventory.KeyFilter, w io.Writer) (int, error) {
	f.record()
	if f.ExportSSHKeysFn != nil {
		return f.ExportSSHKeysFn(ctx, a, fl, w)
	}
	return 0, errNotConfigured
}

func (f *fakeReports) Views(ctx context.Context, userID uuid.UUID, page string) ([]reports.View, error) {
	f.record()
	if f.ViewsFn != nil {
		return f.ViewsFn(ctx, userID, page)
	}
	return nil, errNotConfigured
}

func (f *fakeReports) CreateView(ctx context.Context, userID uuid.UUID, page, name string, query map[string]string) (reports.View, error) {
	f.record()
	if f.CreateViewFn != nil {
		return f.CreateViewFn(ctx, userID, page, name, query)
	}
	return reports.View{}, errNotConfigured
}

func (f *fakeReports) DeleteView(ctx context.Context, userID, id uuid.UUID) error {
	f.record()
	if f.DeleteViewFn != nil {
		return f.DeleteViewFn(ctx, userID, id)
	}
	return errNotConfigured
}
