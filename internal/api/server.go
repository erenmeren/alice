// Package api is Alice's HTTP layer. It holds no business logic and no SQL.
package api

import (
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"log/slog"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"

	"alice/internal/alerts"
	"alice/internal/audit"
	"alice/internal/audit/forward"
	"alice/internal/auth"
	"alice/internal/auth/ldap"
	"alice/internal/auth/oidc"
	"alice/internal/auth/ratelimit"
	"alice/internal/backup"
	"alice/internal/discovery"
	"alice/internal/discovery/discoverysvc"
	"alice/internal/i18n"
	"alice/internal/inventory"
	"alice/internal/jobs"
	"alice/internal/license"
	"alice/internal/notify"
	"alice/internal/platform/clock"
	"alice/internal/platform/db"
	"alice/internal/platform/settings"
	"alice/internal/platform/tlscert"
	"alice/internal/providers"
	"alice/internal/rbac"
	"alice/internal/reports"
	"alice/internal/secrets"
	"alice/internal/setup"
	"alice/internal/sshkeys"
	"alice/internal/version"
)

// HealthChecker reports whether dependencies (the database) are ready.
type HealthChecker interface {
	Check(ctx context.Context) error
}

// AuthService is the part of auth.Service the HTTP layer uses.
type AuthService interface {
	// AuthenticatePassive resolves a session cookie without sliding its idle timeout;
	// RecordActivity slides it once the guard has accepted the request as a person's action (AUD-01).
	AuthenticatePassive(ctx context.Context, sessionToken string) (auth.Principal, error)
	RecordActivity(ctx context.Context, p auth.Principal) error
	AuthenticateToken(ctx context.Context, bearer string) (auth.Principal, error)
	CSRFToken(sessionToken string) string
	CheckCSRF(sessionToken, header string) bool
	Login(ctx context.Context, username, password string, m auth.Meta) (auth.LoginResult, error)
	EnrollMFA(ctx context.Context, p auth.Principal, m auth.Meta) (auth.TOTPEnrollment, error)
	VerifyMFA(ctx context.Context, p auth.Principal, in auth.MFAInput, m auth.Meta) (auth.SessionResult, error)
	SessionInfo(ctx context.Context, p auth.Principal, sessionToken string) (auth.SessionInfo, error)
	StepUp(ctx context.Context, p auth.Principal, code string, m auth.Meta) (auth.SessionResult, error)
	Logout(ctx context.Context, p auth.Principal, m auth.Meta) error
	ChangePassword(ctx context.Context, p auth.Principal, current, next string, m auth.Meta) (auth.SessionResult, error)
	RegenerateRecoveryCodes(ctx context.Context, p auth.Principal, m auth.Meta) ([]string, error)
	SetLocale(ctx context.Context, p auth.Principal, locale string) error
	ListUsers(ctx context.Context) ([]auth.User, error)
	GetUser(ctx context.Context, id uuid.UUID) (auth.User, error)
	CreateUser(ctx context.Context, p auth.Principal, m auth.Meta, in auth.NewUser) (auth.User, error)
	UpdateUser(ctx context.Context, p auth.Principal, m auth.Meta, id uuid.UUID, in auth.UserUpdate) (auth.User, error)
	ResetMFA(ctx context.Context, p auth.Principal, m auth.Meta, id uuid.UUID) error
	ResetPassword(ctx context.Context, p auth.Principal, m auth.Meta, id uuid.UUID, password string) error
	RevokeSessions(ctx context.Context, p auth.Principal, m auth.Meta, id uuid.UUID) error
	CreateToken(ctx context.Context, p auth.Principal, m auth.Meta, in auth.NewToken) (string, auth.Token, error)
	ListTokens(ctx context.Context, p auth.Principal, m auth.Meta, userID uuid.UUID) ([]auth.Token, error)
	RevokeToken(ctx context.Context, p auth.Principal, m auth.Meta, id uuid.UUID) error
	// Directory sign-in (LDAP, Task 5): the handlers talk to the directory first (LDAPService.Verify), then these hold
	// the transaction.
	SignInLDAP(ctx context.Context, id auth.LDAPIdentity, role rbac.Role, mfaRequired bool, m auth.Meta) (auth.LoginResult, error)
	StepUpLDAP(ctx context.Context, p auth.Principal, id auth.LDAPIdentity, role rbac.Role, mfaCode string, mfaRequired bool,
		m auth.Meta) (auth.SessionResult, error)
	RefuseLDAP(ctx context.Context, id auth.LDAPIdentity, reason string, m auth.Meta) error
}

// SetupService is the part of setup.Service the HTTP layer uses.
type SetupService interface {
	Status(ctx context.Context) (setup.Status, error)
	StartSession(ctx context.Context, code string, m auth.Meta) (string, error)
	Authenticate(ctx context.Context, token string) error
	SetLanguage(ctx context.Context, token, language string) error
	BeginAdminEnrollment(ctx context.Context, token string, in setup.AdminInput) (auth.TOTPEnrollment, error)
	CreateAdmin(ctx context.Context, token, code string, m auth.Meta) (auth.SessionResult, error)
	SetRecoveryPassphrase(ctx context.Context, p auth.Principal, m auth.Meta, passphrase, confirm string) error
	ChooseEvaluation(ctx context.Context, p auth.Principal, m auth.Meta) (setup.Status, error)
	Complete(ctx context.Context, p auth.Principal, m auth.Meta) (setup.Status, error)
	// Phase 8 (C11): the wizard's HTTPS and mail steps.
	KeepTemporaryCertificate(ctx context.Context, p auth.Principal, m auth.Meta) (setup.Status, error)
	SkipMail(ctx context.Context, p auth.Principal, m auth.Meta) (setup.Status, error)
}

// AuditService is the part of audit.Service the HTTP layer uses.
type AuditService interface {
	Write(ctx context.Context, e audit.Event) error
	List(ctx context.Context, f audit.Filter) ([]audit.Entry, int64, error)
	Iterate(ctx context.Context, fn func(audit.Entry) error) error
	Verify(ctx context.Context, actor audit.Actor) (audit.Report, error)
	// VerifyReadOnly checks the chain without writing a checkpoint or an audit row (used by the export).
	VerifyReadOnly(ctx context.Context) (audit.Report, error)
}

// LicenseService is the part of license.Service the HTTP layer uses.
type LicenseService interface {
	// Allow is the single lock-mode gate (spec §8.6, R9).
	Allow(c license.Class) error
	Snapshot() license.Snapshot
	Detail(ctx context.Context) (license.Detail, error)
	Preview(ctx context.Context, raw []byte) (license.UploadResult, error)
	Install(ctx context.Context, raw []byte, actor audit.Actor, by uuid.UUID) (license.UploadResult, error)
}

// InventoryService is the part of inventory.Service the HTTP layer uses.
type InventoryService interface {
	ListTargets(ctx context.Context) ([]inventory.Target, error)
	GetTarget(ctx context.Context, id uuid.UUID) (inventory.Target, error)
	CreateTarget(ctx context.Context, a inventory.Actor, in inventory.NewTarget) (inventory.Target, uuid.UUID, error)
	UpdateTarget(ctx context.Context, a inventory.Actor, id uuid.UUID, ifVersion int, p inventory.TargetPatch) (inventory.Target, error)
	DeleteTarget(ctx context.Context, a inventory.Actor, id uuid.UUID) error
	RequestTest(ctx context.Context, a inventory.Actor, id uuid.UUID) (uuid.UUID, error)
	RequestDiscovery(ctx context.Context, a inventory.Actor, id uuid.UUID) (uuid.UUID, error)
	ListHostKeys(ctx context.Context, targetID uuid.UUID) ([]inventory.HostKeyRecord, error)
	ConfirmHostKey(ctx context.Context, a inventory.Actor, targetID, keyID uuid.UUID, fingerprint string) (uuid.UUID, error)
	RepinHostKey(ctx context.Context, a inventory.Actor, targetID, keyID uuid.UUID, fingerprint, reason string) (uuid.UUID, error)
	ListTargetKeys(ctx context.Context, targetID uuid.UUID, includeMissing bool) ([]inventory.KeyLocation, error)
	ListSSHKeys(ctx context.Context, f inventory.KeyFilter) (inventory.KeyPage, error)
	GetSSHKey(ctx context.Context, id uuid.UUID) (inventory.SSHKey, error)
	SetupGuide(ctx context.Context, from string) (inventory.Guide, error)
	RequestKeyRemoval(ctx context.Context, a inventory.Actor, locationID uuid.UUID, confirmLastRootKey bool) (uuid.UUID, error)

	// Phase 4: certificates, signing requests, locations and deployments.
	ListCertificates(ctx context.Context, f inventory.CertificateFilter) (inventory.CertificatePage, error)
	GetCertificate(ctx context.Context, id uuid.UUID) (inventory.Certificate, error)
	UploadCertificate(ctx context.Context, a inventory.Actor, in inventory.UploadInput) (inventory.Certificate, []string, error)
	CreateCSR(ctx context.Context, a inventory.Actor, in inventory.CSRInput) (inventory.CSR, error)
	ListCSRs(ctx context.Context) ([]inventory.CSR, error)
	GetCSR(ctx context.Context, id uuid.UUID) (inventory.CSR, error)
	CompleteCSR(ctx context.Context, a inventory.Actor, id uuid.UUID, certificatePEM, label string) (inventory.Certificate, []string, error)
	CancelCSR(ctx context.Context, a inventory.Actor, id uuid.UUID) (inventory.CSR, error)
	ListLocations(ctx context.Context, targetID uuid.UUID, includeMissing bool) (inventory.LocationList, error)
	UpdateLocation(ctx context.Context, a inventory.Actor, id uuid.UUID, ifVersion int, p inventory.LocationPatch) (inventory.CertificateLocation, error)
	RequestDeployment(ctx context.Context, a inventory.Actor, in inventory.DeployRequestInput) ([]inventory.RequestedDeployment, error)
	ListDeployments(ctx context.Context, f inventory.DeploymentFilter) (inventory.DeploymentPage, error)
	Deployment(ctx context.Context, id uuid.UUID) (inventory.Deployment, error)

	// Phase 5: Key Vault vaults, their inventory, bindings, deployments of vault versions and imports.
	CreateVault(ctx context.Context, a inventory.Actor, in inventory.NewVault) (inventory.Target, providers.ConnectionReport, uuid.UUID, error)
	ReplaceVaultCredentials(ctx context.Context, a inventory.Actor, id uuid.UUID, ifVersion int, in inventory.VaultCredentialInput) (inventory.Target, providers.ConnectionReport, uuid.UUID, error)
	DeleteVault(ctx context.Context, a inventory.Actor, id uuid.UUID, removeBindings bool) error
	RequestAccessCheck(ctx context.Context, a inventory.Actor, vaultID, readSecretOf uuid.UUID) (uuid.UUID, error)
	ListKVCertificates(ctx context.Context, vault uuid.UUID, f inventory.KVFilter) (inventory.KVCertificatePage, error)
	KVCertificate(ctx context.Context, vault, id uuid.UUID) (inventory.KVCertificateDetail, error)
	ListKVKeys(ctx context.Context, vault uuid.UUID, f inventory.KVFilter) ([]inventory.KVKey, string, error)
	ListKVSecrets(ctx context.Context, vault uuid.UUID, f inventory.KVFilter) ([]inventory.KVSecret, string, error)
	ListDeployableLocations(ctx context.Context, f inventory.LocationFilter) (inventory.DeployableLocationPage, error)
	CreateBinding(ctx context.Context, a inventory.Actor, in inventory.BindingInput) (inventory.Binding, error)
	UpdateBindingLocationsStrict(ctx context.Context, a inventory.Actor, id uuid.UUID, ifVersion int, locations []uuid.UUID, strictSession bool) (inventory.Binding, error)
	SetAutoDeploy(ctx context.Context, a inventory.Actor, id uuid.UUID, ifVersion int, enabled bool) (inventory.Binding, error)
	DeleteBinding(ctx context.Context, a inventory.Actor, id uuid.UUID) error
	Binding(ctx context.Context, id uuid.UUID) (inventory.Binding, error)
	RequestKVDeployment(ctx context.Context, a inventory.Actor, in inventory.KVDeployInput) ([]inventory.RequestedDeployment, error)
	ReleaseVersion(ctx context.Context, a inventory.Actor, in inventory.ReleaseInput) (inventory.KVVersion, error)
	RequestImport(ctx context.Context, a inventory.Actor, in inventory.ImportInput) (inventory.KVImport, error)
	Import(ctx context.Context, vault, id uuid.UUID) (inventory.KVImport, error)
	ListImportsPage(ctx context.Context, vault uuid.UUID, f inventory.ImportFilter) (inventory.ImportPage, error)
}

// ACMEService is the part of inventory.Service the ACME routes use (plan 2026-10-13 Task 13): certificate authorities
// (providers) and their accounts, DNS hooks, ACME certificate definitions, their orders, bindings and Deploy now. Every
// view it returns is secret-free (the EAB HMAC key, the account key and the hook secret are write-only).
type ACMEService interface {
	ListACMEProviders(ctx context.Context) ([]inventory.ACMEProvider, error)
	GetACMEProvider(ctx context.Context, id uuid.UUID) (inventory.ACMEProvider, error)
	CreateACMEProvider(ctx context.Context, a inventory.Actor, in inventory.ACMEProviderInput) (inventory.ACMEProvider, error)
	UpdateACMEProvider(ctx context.Context, a inventory.Actor, id uuid.UUID, p inventory.ACMEProviderPatch) (inventory.ACMEProvider, error)
	DeleteACMEProvider(ctx context.Context, a inventory.Actor, id uuid.UUID) error
	ListACMEAccounts(ctx context.Context, providerID uuid.UUID) ([]inventory.ACMEAccount, error)
	RegisterACMEAccountTerms(ctx context.Context, a inventory.Actor, providerID uuid.UUID, contactEmail string, tosAccepted bool,
		acceptedTermsURL string) (inventory.ACMEAccount, error)
	PreviewACMEProvider(ctx context.Context, providerID uuid.UUID) (inventory.ACMEProviderPreview, error)
	RolloverACMEAccount(ctx context.Context, a inventory.Actor, accountID uuid.UUID) (inventory.ACMEAccount, error)
	RecoverACMERollover(ctx context.Context, a inventory.Actor, accountID uuid.UUID) (inventory.ACMEAccount, error)
	DeactivateACMEAccount(ctx context.Context, a inventory.Actor, accountID uuid.UUID) (inventory.ACMEAccount, error)
	ListACMEHooks(ctx context.Context) ([]inventory.ACMEHook, error)
	GetACMEHook(ctx context.Context, id uuid.UUID) (inventory.ACMEHook, error)
	CreateACMEHook(ctx context.Context, a inventory.Actor, in inventory.ACMEHookInput) (inventory.ACMEHook, error)
	UpdateACMEHook(ctx context.Context, a inventory.Actor, id uuid.UUID, p inventory.ACMEHookPatch) (inventory.ACMEHook, error)
	DeleteACMEHook(ctx context.Context, a inventory.Actor, id uuid.UUID) error
	ListACMECertificates(ctx context.Context) ([]inventory.ACMECertificate, error)
	GetACMECertificate(ctx context.Context, id uuid.UUID) (inventory.ACMECertificate, error)
	CreateACMECertificate(ctx context.Context, a inventory.Actor, in inventory.ACMECertificateInput) (inventory.ACMECertificate, error)
	UpdateACMECertificate(ctx context.Context, a inventory.Actor, id uuid.UUID, p inventory.ACMECertificatePatch) (inventory.ACMECertificate, error)
	DeleteACMECertificate(ctx context.Context, a inventory.Actor, id uuid.UUID) error
	RequestOrder(ctx context.Context, a inventory.Actor, acmeCertificateID uuid.UUID, kind string) (inventory.ACMEOrder, error)
	ListACMEOrders(ctx context.Context, acmeCertificateID uuid.UUID, limit int) ([]inventory.ACMEOrder, error)
	ReArmACMEAutoRenew(ctx context.Context, a inventory.Actor, id uuid.UUID) (inventory.ACMECertificate, error)
	ReleaseACMEDeployHold(ctx context.Context, a inventory.Actor, id uuid.UUID) error
	ListACMEBindings(ctx context.Context, id uuid.UUID) ([]inventory.ACMEBinding, error)
	AddACMEBindingStrict(ctx context.Context, a inventory.Actor, id, location uuid.UUID, autoDeploy, strictSession bool) (inventory.ACMEBinding, error)
	RemoveACMEBinding(ctx context.Context, a inventory.Actor, id, location uuid.UUID) error
	DeployACMENow(ctx context.Context, a inventory.Actor, id uuid.UUID, in inventory.ACMEDeployInput) ([]inventory.RequestedDeployment, error)
}

// JobsService is the part of jobs.Queue the HTTP layer uses.
type JobsService interface {
	Get(ctx context.Context, id uuid.UUID) (jobs.View, error)
	List(ctx context.Context, f jobs.ListFilter) ([]jobs.View, string, error)
	Confirm(ctx context.Context, actor audit.Actor, by uuid.UUID, id uuid.UUID) error
	Discard(ctx context.Context, actor audit.Actor, by uuid.UUID, id uuid.UUID) error
}

// SSHKeysService is the part of *sshkeys.Service the HTTP layer uses (C7, Phase 6): generated keys, their deploy
// and download, rotation policies, previews, runs and the Administrator's decisions on them.
type SSHKeysService interface {
	Generate(ctx context.Context, a inventory.Actor, in sshkeys.GenerateInput) (sshkeys.ManagedKey, error)
	ManagedKey(ctx context.Context, id uuid.UUID) (sshkeys.ManagedKey, error)
	RequestDeploy(ctx context.Context, a inventory.Actor, in sshkeys.DeployInput) (uuid.UUID, error)
	DownloadPrivateKey(ctx context.Context, a inventory.Actor, in sshkeys.DownloadInput) (sshkeys.Download, error)
	CreatePolicy(ctx context.Context, a inventory.Actor, in sshkeys.PolicyInput) (sshkeys.Policy, error)
	UpdatePolicy(ctx context.Context, a inventory.Actor, id uuid.UUID, version int, p sshkeys.PolicyPatch) (sshkeys.Policy, error)
	SetPolicyEnabled(ctx context.Context, a inventory.Actor, id uuid.UUID, version int, enabled bool) (sshkeys.Policy, error)
	DeletePolicy(ctx context.Context, a inventory.Actor, id uuid.UUID, version int) error
	Policy(ctx context.Context, id uuid.UUID) (sshkeys.Policy, error)
	Policies(ctx context.Context) ([]sshkeys.Policy, error)
	Preview(ctx context.Context, a inventory.Actor, id uuid.UUID) (sshkeys.Preview, error)
	RunNow(ctx context.Context, a inventory.Actor, id uuid.UUID, digest string) (sshkeys.Rotation, error)
	Rotation(ctx context.Context, id uuid.UUID) (sshkeys.Rotation, error)
	RotationSummaries(ctx context.Context, f sshkeys.RotationFilter) ([]sshkeys.RotationSummary, string, error)
	Continue(ctx context.Context, a inventory.Actor, id uuid.UUID) error
	FinishNow(ctx context.Context, a inventory.Actor, id uuid.UUID) error
	KeepOld(ctx context.Context, a inventory.Actor, id uuid.UUID, locations []uuid.UUID) error
	Abort(ctx context.Context, a inventory.Actor, id uuid.UUID) error
}

// MailService is the part of *notify.Settings the HTTP layer uses (C7, Phase 7): the mail server, the test e-mail and
// the certificate trust, the recipients of every e-mail, the general settings and the delivery state.
type MailService interface {
	SMTP(ctx context.Context) (notify.SMTPSettings, bool, error)
	SaveSMTP(ctx context.Context, a audit.Actor, version int, in notify.SMTPInput) (notify.SMTPSettings, error)
	DeleteSMTP(ctx context.Context, a audit.Actor, version int) error
	TestMail(ctx context.Context, a audit.Actor, to, locale string) error
	Trust(ctx context.Context, a audit.Actor, version int, fingerprint string) (notify.SMTPSettings, error)
	Untrust(ctx context.Context, a audit.Actor, version int) (notify.SMTPSettings, error)
	Recipients(ctx context.Context) (notify.Recipients, error)
	SaveRecipients(ctx context.Context, a audit.Actor, version int, r notify.Recipients) (notify.Recipients, error)
	General(ctx context.Context) (settings.General, error)
	SaveGeneral(ctx context.Context, a audit.Actor, version int, g settings.General) (settings.General, error)
	Delivery(ctx context.Context) (notify.Delivery, error)
}

// AlertsService is the part of *alerts.Service the HTTP layer uses (C8): the expiry thresholds setting.
type AlertsService interface {
	Thresholds(ctx context.Context) (alerts.ThresholdSettings, error)
	SaveThresholds(ctx context.Context, a audit.Actor, version int, days []int) (alerts.ThresholdSettings, error)
}

// ReportsService is the part of *reports.Service the HTTP layer uses (C9): the dashboard, the CSV exports and the
// saved views.
type ReportsService interface {
	Summary(ctx context.Context, v reports.Viewer) (reports.Summary, error)
	Expiring(ctx context.Context, days, limit int) ([]alerts.Item, error)
	Attention(ctx context.Context, v reports.Viewer) ([]reports.Condition, error)
	ExportCertificates(ctx context.Context, a audit.Actor, f inventory.CertificateFilter, w io.Writer) (int, error)
	ExportSSHKeys(ctx context.Context, a audit.Actor, f inventory.KeyFilter, w io.Writer) (int, error)
	// ExportRows is the same machinery for another module's list (network discovery's certificates).
	ExportRows(ctx context.Context, a audit.Actor, x reports.RowExport, w io.Writer) (int, error)
	Views(ctx context.Context, userID uuid.UUID, page string) ([]reports.View, error)
	CreateView(ctx context.Context, userID uuid.UUID, page, name string, query map[string]string) (reports.View, error)
	DeleteView(ctx context.Context, userID, id uuid.UUID) error
}

// SSOService is the part of *oidc.Service the HTTP layer uses (C11, Phase 7): identity providers, group mappings, the
// "SSO users may be Admin" switch, and the sign-in and step-up at an identity provider.
type SSOService interface {
	Providers(ctx context.Context) ([]oidc.Provider, error)
	Provider(ctx context.Context, id uuid.UUID) (oidc.Provider, error)
	PublicProviders(ctx context.Context) ([]oidc.PublicProvider, error)
	CreateProvider(ctx context.Context, a audit.Actor, in oidc.ProviderInput) (oidc.Provider, error)
	UpdateProvider(ctx context.Context, a audit.Actor, id uuid.UUID, version int, p oidc.ProviderPatch) (oidc.Provider, error)
	RefreshProvider(ctx context.Context, a audit.Actor, id uuid.UUID, version int) (oidc.Provider, error)
	DeleteProvider(ctx context.Context, a audit.Actor, id uuid.UUID, version int) error
	Mappings(ctx context.Context, providerID uuid.UUID) ([]oidc.Mapping, error)
	CreateMapping(ctx context.Context, a audit.Actor, providerID uuid.UUID, group string, role rbac.Role) (oidc.Mapping, error)
	DeleteMapping(ctx context.Context, a audit.Actor, id uuid.UUID) error
	Settings(ctx context.Context) (oidc.SSOSettings, error)
	SaveSettings(ctx context.Context, a audit.Actor, version int, allowAdmin bool) (oidc.SSOSettings, error)
	Begin(ctx context.Context, in oidc.BeginInput) (oidc.Begin, error)
	Complete(ctx context.Context, providerID uuid.UUID, q url.Values, binding string, m auth.Meta) (oidc.Completion, error)
}

// LDAPService is the part of *ldap.Service the HTTP layer uses (directory sign-in, Task 5): directories, their group
// mappings, Test connection and Test sign-in, the sign-in page's list and the password check of a sign-in or step-up.
// A Directory never carries the service account password.
type LDAPService interface {
	Directories(ctx context.Context) ([]ldap.Directory, error)
	Directory(ctx context.Context, id uuid.UUID) (ldap.Directory, error)
	PublicDirectories(ctx context.Context) ([]ldap.PublicDirectory, error)
	CreateDirectory(ctx context.Context, a audit.Actor, in ldap.DirectoryInput) (ldap.Directory, error)
	UpdateDirectory(ctx context.Context, a audit.Actor, id uuid.UUID, version int, p ldap.DirectoryPatch) (ldap.Directory, error)
	DeleteDirectory(ctx context.Context, a audit.Actor, id uuid.UUID, version int) error
	Mappings(ctx context.Context, directoryID uuid.UUID) ([]ldap.Mapping, error)
	CreateMapping(ctx context.Context, a audit.Actor, directoryID uuid.UUID, group string, role rbac.Role) (ldap.Mapping, error)
	DeleteMapping(ctx context.Context, a audit.Actor, id uuid.UUID) error
	TestConnection(ctx context.Context, a audit.Actor, id uuid.UUID) error
	TestSignInGated(ctx context.Context, a audit.Actor, id uuid.UUID, login string, password secrets.Plaintext, gate ldap.Gate) (ldap.TestResult, error)
	VerifyGated(ctx context.Context, directoryID uuid.UUID, login string, password secrets.Plaintext, gate ldap.Gate) (ldap.Identity, ldap.Directory, error)
	ResolveRole(ctx context.Context, directoryID uuid.UUID, groups []string) (rbac.Role, bool, error)
}

var _ LDAPService = (*ldap.Service)(nil)

// BackupService is the part of *backup.Service the HTTP layer uses (C8, Phase 8): the list, a backup made now, the
// download, the free space, the schedule and the state.
type BackupService interface {
	Create(ctx context.Context, in backup.CreateInput) (backup.Info, error)
	List(ctx context.Context) ([]backup.Info, error)
	Open(ctx context.Context, name string) (*os.File, backup.Info, error)
	FreeBytes() (uint64, error)
	Schedule(ctx context.Context) (backup.Schedule, error)
	SaveSchedule(ctx context.Context, a audit.Actor, version int, in backup.Schedule) (backup.Schedule, error)
	State(ctx context.Context) (backup.State, error)
}

// ForwardService is the part of *forward.Forwarder the HTTP layer uses (C10, Phase 8).
type ForwardService interface {
	Settings(ctx context.Context) (forward.Settings, forward.State, error)
	Save(ctx context.Context, in forward.Settings, version int, actor audit.Actor) (forward.Settings, error)
	Test(ctx context.Context, in forward.Settings) error
}

// HTTPSService is Alice's HTTPS certificate (C11, Phase 8): what the listener serves, and the installation of an
// uploaded pair. Install puts the pair in use (tlscert.Store.Install) and only then records it: the wizard's HTTPS
// choice and the https.certificate_replaced audit row, in one transaction, retried once and logged when it fails
// (setup.CertificateInstaller, which cmd/alice and the integration stack both wire; the HTTP layer holds no pool).
type HTTPSService interface {
	Info() tlscert.Info
	Install(ctx context.Context, p auth.Principal, m auth.Meta, u tlscert.Upload) (tlscert.Info, error)
}

// DiscoveryService is the part of *discoverysvc.Service the HTTP layer uses (network discovery, Task 9): scopes,
// settings, scans and the read side. Every change writes its audit row in its own transaction.
type DiscoveryService interface {
	ListScopes(ctx context.Context, f discoverysvc.ScopeFilter) ([]discoverysvc.ScopeView, bool, error)
	GetScope(ctx context.Context, id uuid.UUID) (discoverysvc.ScopeView, error)
	CreateScope(ctx context.Context, a discoverysvc.Actor, in discovery.Scope) (discoverysvc.ScopeView, error)
	UpdateScope(ctx context.Context, a discoverysvc.Actor, id uuid.UUID, ifVersion *int, p discoverysvc.ScopePatch) (discoverysvc.ScopeView, error)
	DeleteScope(ctx context.Context, a discoverysvc.Actor, id uuid.UUID, ifVersion *int) error
	Preview(ctx context.Context, sc discovery.Scope) (discovery.Preview, error)
	StartScan(ctx context.Context, a discoverysvc.Actor, scopeID uuid.UUID) (discoverysvc.ScanView, error)
	CancelScan(ctx context.Context, a discoverysvc.Actor, id uuid.UUID) (discoverysvc.ScanView, error)
	GetScan(ctx context.Context, id uuid.UUID) (discoverysvc.ScanView, error)
	ListScans(ctx context.Context, f discoverysvc.ScanFilter) ([]discoverysvc.ScanView, bool, error)
	ListCertificates(ctx context.Context, f discovery.CertificateFilter) ([]discovery.CertificateRow, bool, error)
	Certificate(ctx context.Context, fingerprint string) (discovery.CertificateRow, []discovery.EndpointRow, bool, error)
	ListEndpoints(ctx context.Context, f discovery.EndpointFilter) ([]discovery.EndpointRow, bool, error)
	Settings(ctx context.Context) (discoverysvc.SettingsView, error)
	SaveSettings(ctx context.Context, a discoverysvc.Actor, in discoverysvc.Settings) (discoverysvc.SettingsView, error)
	Summary(ctx context.Context) (discoverysvc.Summary, error)
}

var _ DiscoveryService = (*discoverysvc.Service)(nil)

// ProviderCatalog lists the compiled-in providers (providers.Registry).
type ProviderCatalog interface {
	List() []providers.Descriptor
}

// Deps are the handler's dependencies, wired in cmd/alice.
type Deps struct {
	Health         HealthChecker
	Catalog        *i18n.Catalog
	Version        version.Info
	UI             fs.FS
	Log            *slog.Logger
	Clock          clock.Clock
	Auth           AuthService
	Setup          SetupService
	Audit          AuditService
	License        LicenseService
	Inventory      InventoryService
	Jobs           JobsService
	Providers      ProviderCatalog
	SSHKeys        SSHKeysService
	Mail           MailService
	Alerts         AlertsService
	Reports        ReportsService
	SSO            SSOService
	LDAP           LDAPService      // directory (LDAP and Active Directory) sign-in
	Backup         BackupService    // Phase 8: nil leaves the backup routes and the dashboard's backup section unavailable
	Forward        ForwardService   // Phase 8: audit forwarding
	ACME           ACMEService      // ACME issuance (inventory.Service)
	Discovery      DiscoveryService // network certificate discovery (discoverysvc.Service)
	TLSStore       HTTPSService     // Phase 8: the HTTPS certificate
	TrustedProxies []netip.Prefix
	TestHandler    http.Handler // nil in release builds; mounted at "/test/" by the e2e build
}

// limitClass selects the rate limits applied to a route in addition to the general limit.
type limitClass int

const (
	limitDefault      limitClass = iota // general limit only
	limitNone                           // no limit (health probes)
	limitLogin                          // 10 per minute per IP (password and setup-code guessing)
	limitMFA                            // 5 per minute per IP (verification codes)
	limitHealth                         // 60 per minute per IP in a bucket of its own (public /healthz, AUD-16)
	limitDownload                       // 5 per minute per user: private key and backup downloads (SEC-022, R41 row 5)
	limitTestMail                       // 5 per minute per user: test e-mails (C13)
	limitExport                         // 10 per minute per user or token: CSV exports (C13)
	limitOIDCCallback                   // 10 per minute per binding cookie: the identity provider's redirect back (S-11)
	// C12's limitDownload (5 per minute per user) for the Phase 8 actions that send no file, each in a bucket of its own
	// so that one never blocks another or a download (Task 9 review M-4).
	limitBackupNow   // a backup made now
	limitHTTPSUpload // an HTTPS certificate upload
	limitForwardTest // a test message to the audit forwarding server
	limitACME        // 10 per minute per user or token: ACME orders and test runs (A5), keyed like limitExport
	// Network discovery (plan contract, A3), keyed like limitACME, each in a bucket of its own.
	limitDiscovery        // 10 per minute per user or token: starting and cancelling scans, one budget for both
	limitDiscoveryResolve // 30 per minute per user or token: the save-time check that a listed name resolves (ALC-DSC-0010)
	limitDiscoveryPreview // 60 per minute per user or token: the scope form's live size check (no look-up, nothing dialed)
	limitDirectoryTest    // 5 per minute per user: a directory's Test connection and Test sign-in, one budget for both
)

// Directory sign-in lockout (replaces plan ruling 5, Task 5 fix rounds). Two lockouts with the same numbers: one per
// sign-in name at a directory (ldapLockout, checked before any directory traffic, unknown names counted exactly like
// known ones) and one per account, the entry's unique id at a directory (ldapAccountLockout, checked by a gate between
// the user search and the user bind, so aliases and spellings of one account share it). After ldapLockoutFailures
// failed directory passwords within ldapLockoutWindow the key is locked for ldapLockoutFor, whatever the address and
// even with the right password; attempts in flight count (each reserves a slot), so parallel attempts cannot pass
// the limit. Active Directory's default lockout policy
// counts failures in a 30-minute observation window, so a lock longer than that window lets the directory's own
// counter reset before Alice sends the name again: a stream of guesses through Alice can never keep a directory
// account's failure counter climbing (a token bucket that refills every few minutes could). A successful sign-in clears
// the name's failures. The table holds ldapLockoutKeys names and never forgets one that is locked or still counting
// (ratelimit.BoundedLockout: when it is full of such names, new names are refused until one expires; the DoS trade-off
// is documented there). The per-address limit of the sign-in form (limitLogin) applies as well.
const (
	ldapLockoutFailures = 3
	ldapLockoutWindow   = 30 * time.Minute
	ldapLockoutFor      = 45 * time.Minute
	ldapLockoutKeys     = 100_000
)

// route is one documented operation. The route table is the single source of
// truth for what the muxes serve and which permission each operation needs;
// openapi.yaml must list exactly these operations with the same x-permission.
type route struct {
	method  string
	pattern string
	perm    rbac.Permission
	limit   limitClass
	// lic is how lock mode treats this operation. Every non-GET route declares it: ClassAlways
	// for platform administration, ClassChange for changes to managed systems or inventory
	// (refused while the license is expired, R9). GET routes leave it unset (reads stay available).
	lic license.Class
	// getOnly refuses HEAD (which the mux sends to a GET pattern) with 405: an audited export must never run, nor write
	// its audit row, for a request that discards the body (Task 14 review M6).
	getOnly bool
	handler http.HandlerFunc
}

type server struct {
	deps    Deps
	general *ratelimit.Limiter // authenticated subjects, per session or token: 300/min
	anon    *ratelimit.Limiter // anonymous and setup subjects, per IP: 60/min
	login   *ratelimit.Limiter // per IP: 10/min
	mfa     *ratelimit.Limiter // per IP: 5/min
	// badCreds: per IP, lookups of credentials that did not resolve: 60/min (AUD-16).
	badCreds *ratelimit.Limiter
	// recent: credentials validated or issued in the last recentLifetime; they skip badCreds.
	recent *ratelimit.Recent
	// rotated: session cookies replaced by a rotation in the last rotatedLifetime; a 401 for
	// them never deletes the cookie (it would delete the new one in a response race).
	rotated *ratelimit.Recent
	healthz *ratelimit.Limiter // public /healthz, per IP: 60/min
	// download: private key downloads per user: 5/min, besides the general limit (R41 row 5).
	download *ratelimit.Limiter
	// testMails: test e-mails per user: 5/min; export: CSV exports per user or token: 10/min (C13).
	testMails *ratelimit.Limiter
	export    *ratelimit.Limiter
	// actions: the Phase 8 actions of C12's limitDownload that send no file (5/min per user each), limitACME and
	// limitDiscovery (10/min per user or token), limitDiscoveryResolve (30/min per user or token) and
	// limitDiscoveryPreview (60/min per user or token).
	actions map[limitClass]*ratelimit.Limiter
	// oidcCallbacks: identity provider callbacks per binding cookie: 10/min (S-11: not per address, so a company
	// behind one address is not limited to a few sign-ins a minute).
	oidcCallbacks *ratelimit.Limiter
	// ldapLockout: failed directory passwords per (directory, normalised sign-in name), sign-in and step-up alike.
	ldapLockout        *ratelimit.BoundedLockout
	ldapAccountLockout *ratelimit.BoundedLockout // per (directory, unique id)
	// ldapFullLogged: when each full lockout table ("name", "account") was last logged (each at most once per
	// ldapFullLogEvery).
	ldapFullMu     sync.Mutex
	ldapFullLogged map[string]time.Time
	// ldapRefusalFloor: the least time a refused directory sign-in takes (ldapRefusalFloor const).
	ldapRefusalFloor time.Duration
	// denials coalesces the guard's denial audit rows (AUD-06).
	denials *denialCoalescer
	// chainScan is the one slot for reading the whole audit chain (verification, export) in this
	// process (AUD-06): a second scan is refused with ErrAuditBusy instead of running beside it.
	chainScan chan struct{}
	// scanCtx ends every chain scan when stopScans is called (shutdown, I3).
	scanCtx   context.Context
	stopScans context.CancelFunc
}

const (
	// recentLifetime is the session idle timeout (ruling on S2): every session this process
	// validated and that has not idled out passes the block; each successful lookup slides it.
	recentLifetime  = auth.SessionIdle
	recentMax       = 16384 // entries; each is a 32-byte keyed hash and a time (Recent)
	rotatedLifetime = time.Minute
	rotatedMax      = 4096
)

func newServer(d Deps) *server {
	if d.Clock == nil {
		d.Clock = clock.Real{}
	}
	scanCtx, stopScans := context.WithCancel(context.Background())
	s := &server{
		deps:    d,
		general: ratelimit.New(d.Clock, 300, time.Minute),
		anon:    ratelimit.New(d.Clock, 60, time.Minute),
		login:   ratelimit.New(d.Clock, 10, time.Minute),
		mfa:     ratelimit.New(d.Clock, 5, time.Minute),

		badCreds:  ratelimit.New(d.Clock, 60, time.Minute),
		recent:    ratelimit.NewRecent(d.Clock, recentLifetime, recentMax),
		rotated:   ratelimit.NewRecent(d.Clock, rotatedLifetime, rotatedMax),
		healthz:   ratelimit.New(d.Clock, 60, time.Minute),
		download:  ratelimit.New(d.Clock, 5, time.Minute),
		testMails: ratelimit.New(d.Clock, 5, time.Minute),
		export:    ratelimit.New(d.Clock, 10, time.Minute),

		oidcCallbacks:      ratelimit.New(d.Clock, 10, time.Minute),
		ldapLockout:        ratelimit.NewBoundedLockout(d.Clock, ldapLockoutFailures, ldapLockoutWindow, ldapLockoutFor, ldapLockoutKeys),
		ldapAccountLockout: ratelimit.NewBoundedLockout(d.Clock, ldapLockoutFailures, ldapLockoutWindow, ldapLockoutFor, ldapLockoutKeys),
		ldapRefusalFloor:   ldapRefusalFloor,
		actions: map[limitClass]*ratelimit.Limiter{
			limitBackupNow:   ratelimit.New(d.Clock, 5, time.Minute),
			limitHTTPSUpload: ratelimit.New(d.Clock, 5, time.Minute),
			limitForwardTest: ratelimit.New(d.Clock, 5, time.Minute),
			limitACME:        ratelimit.New(d.Clock, 10, time.Minute),

			limitDiscovery:        ratelimit.New(d.Clock, 10, time.Minute),
			limitDiscoveryResolve: ratelimit.New(d.Clock, 30, time.Minute),
			limitDiscoveryPreview: ratelimit.New(d.Clock, 60, time.Minute),
			limitDirectoryTest:    ratelimit.New(d.Clock, 5, time.Minute),
		},

		denials:   newDenialCoalescer(d.Clock),
		chainScan: make(chan struct{}, 1),
		scanCtx:   scanCtx,
		stopScans: stopScans,
	}
	s.ldapLockout.OnFull = func() { s.logLockoutFull("name") }
	s.ldapAccountLockout.OnFull = func() { s.logLockoutFull("account") }
	return s
}

// ldapFullLogEvery is how often a full directory lockout table is logged.
const ldapFullLogEvery = 10 * time.Minute

// logLockoutFull warns, at most once per ldapFullLogEvery, that a directory lockout table refused a new key because
// it is full of live keys (ratelimit.BoundedLockout fails closed), once per table per interval. Nothing of the key is
// logged.
func (s *server) logLockoutFull(table string) {
	now := s.deps.Clock.Now()
	s.ldapFullMu.Lock()
	if last, ok := s.ldapFullLogged[table]; ok && now.Sub(last) < ldapFullLogEvery {
		s.ldapFullMu.Unlock()
		return
	}
	if s.ldapFullLogged == nil {
		s.ldapFullLogged = map[string]time.Time{}
	}
	s.ldapFullLogged[table] = now
	s.ldapFullMu.Unlock()
	if s.deps.Log != nil {
		s.deps.Log.Warn("directory sign-in lockout table is full; new sign-in names are refused until entries expire",
			"table", table, "capacity", ldapLockoutKeys)
	}
}

// Server is the public HTTPS handler plus the controls the e2e build needs.
type Server struct {
	s *server
	h http.Handler
}

// New builds the public HTTPS handler. It panics if a route declares an
// unknown permission or a state-changing route declares no license class, so a
// misconfigured route table never starts (SEC-016, R9).
func New(d Deps) *Server {
	s := newServer(d)
	return &Server{s: s, h: s.handler(s.apiRoutes())}
}

// Handler returns the HTTP handler.
func (s *Server) Handler() http.Handler { return s.h }

// ResetLimits clears all in-memory rate limiters and the open denial windows, without writing
// their summaries (used by the e2e reset endpoint).
func (s *Server) ResetLimits() {
	s.s.general.Reset()
	s.s.anon.Reset()
	s.s.login.Reset()
	s.s.mfa.Reset()
	s.s.badCreds.Reset()
	s.s.recent.Reset()
	s.s.rotated.Reset()
	s.s.healthz.Reset()
	s.s.download.Reset()
	s.s.testMails.Reset()
	s.s.export.Reset()
	s.s.oidcCallbacks.Reset()
	s.s.ldapLockout.Reset()
	s.s.ldapAccountLockout.Reset()
	for _, l := range s.s.actions {
		l.Reset()
	}
	s.s.denials.reset()
}

// NewHandler returns the public HTTPS handler.
func NewHandler(d Deps) http.Handler { return New(d).Handler() }

// NewHealthHandler returns the handler for the internal, container-local health listener.
func NewHealthHandler(d Deps) http.Handler {
	s := newServer(d)
	mux := http.NewServeMux()
	s.register(mux, s.probeRoutes(false))
	return s.requestID(securityHeaders(s.recoverer(mux)))
}

func (s *server) handler(routes []route) http.Handler {
	mux := http.NewServeMux()
	s.register(mux, routes)
	notFound := func(w http.ResponseWriter, r *http.Request) { s.writeError(w, r, ErrNotFound) }
	mux.HandleFunc("/api/", s.apiFallback(mux, routes))
	if s.deps.TestHandler != nil {
		mux.Handle("/test/", s.deps.TestHandler)
	} else {
		mux.HandleFunc("/test/", notFound) // reserved for test-only routes; never the SPA
	}
	mux.Handle("/", s.spa())
	return s.requestID(securityHeaders(s.recoverer(mux)))
}

// apiFallback answers an /api/ request no route took: 405 with Allow when a route serves the path with
// another method (the "/api/" catch-all matches every method, so the mux's own 405 never runs;
// review-fixes I-1), else the JSON 404. It asks mux which pattern each route method would match and
// runs no handler.
func (s *server) apiFallback(mux *http.ServeMux, routes []route) http.HandlerFunc {
	var methods []string
	for _, r := range routes {
		methods = append(methods, r.method)
	}
	slices.Sort(methods)
	methods = slices.Compact(methods)
	return func(w http.ResponseWriter, r *http.Request) {
		var allow []string
		for _, m := range methods {
			probe := r.Clone(r.Context())
			probe.Method = m
			if _, pattern := mux.Handler(probe); strings.HasPrefix(pattern, m+" ") {
				allow = append(allow, m)
				if m == http.MethodGet {
					allow = append(allow, http.MethodHead) // the mux serves HEAD with GET
				}
			}
		}
		if len(allow) > 0 {
			slices.Sort(allow)
			w.Header().Set("Allow", strings.Join(allow, ", "))
			s.writeError(w, r, ErrMethodNotAllowed)
			return
		}
		s.writeError(w, r, ErrNotFound)
	}
}

// register is the only place routes reach a mux; every route passes through guard.
func (s *server) register(mux *http.ServeMux, routes []route) {
	for _, r := range routes {
		if _, ok := rbac.PolicyFor(r.perm); !ok {
			panic(fmt.Sprintf("api: route %s %s has unknown permission %q", r.method, r.pattern, r.perm))
		}
		if !safeMethod(r.method) && !r.lic.Valid() {
			panic(fmt.Sprintf("api: state-changing route %s %s declares no license class", r.method, r.pattern))
		}
		mux.HandleFunc(r.method+" "+r.pattern, s.guard(r))
	}
}

// probeRoutes are served on both the public and the internal health listener. /healthz asks the
// database, so on the public listener it has a per-address limit of its own (AUD-16); the
// internal listener (container healthcheck, orchestrators) and /livez stay unlimited.
func (s *server) probeRoutes(public bool) []route {
	health := limitNone
	if public {
		health = limitHealth
	}
	return []route{
		{method: http.MethodGet, pattern: "/livez", perm: rbac.Public, limit: limitNone, handler: func(w http.ResponseWriter, _ *http.Request) {
			writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
		}},
		{method: http.MethodGet, pattern: "/healthz", perm: rbac.Public, limit: health, handler: func(w http.ResponseWriter, r *http.Request) {
			if err := s.deps.Health.Check(r.Context()); err != nil {
				s.deps.Log.Warn("health check failed", "request_id", RequestID(r.Context()), "reason", healthReason(err))
				s.writeError(w, r, ErrUnavailable)
				return
			}
			writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
		}},
	}
}

// systemRoutes are small informational endpoints.
func (s *server) systemRoutes() []route {
	return []route{
		{method: http.MethodGet, pattern: "/api/v1/version", perm: rbac.Read, handler: func(w http.ResponseWriter, _ *http.Request) {
			writeJSON(w, http.StatusOK, s.deps.Version)
		}},
		{method: http.MethodGet, pattern: "/api/v1/i18n/locales", perm: rbac.Public, handler: func(w http.ResponseWriter, _ *http.Request) {
			writeJSON(w, http.StatusOK, map[string]any{"default": s.deps.Catalog.Default(), "locales": s.deps.Catalog.Locales()})
		}},
	}
}

// apiRoutes are the documented operations on the public listener.
// Undocumented catch-alls (the /api/ and /test/ JSON 404s and the SPA
// fallback) are registered separately in handler and are not operations.
func (s *server) apiRoutes() []route {
	var routes []route
	routes = append(routes, s.probeRoutes(true)...)
	routes = append(routes, s.systemRoutes()...)
	routes = append(routes, s.setupRoutes()...)
	routes = append(routes, s.authRoutes()...)
	routes = append(routes, s.oidcRoutes()...)
	routes = append(routes, s.ldapSignInRoutes()...)
	routes = append(routes, s.userRoutes()...)
	routes = append(routes, s.tokenRoutes()...)
	routes = append(routes, s.auditRoutes()...)
	routes = append(routes, s.licenseRoutes()...)
	routes = append(routes, s.providerRoutes()...)
	routes = append(routes, s.targetRoutes()...)
	routes = append(routes, s.sshKeyRoutes()...)
	routes = append(routes, s.rotationRoutes()...)
	routes = append(routes, s.jobRoutes()...)
	routes = append(routes, s.certificateRoutes()...)
	routes = append(routes, s.locationRoutes()...)
	routes = append(routes, s.deploymentRoutes()...)
	routes = append(routes, s.vaultRoutes()...)
	routes = append(routes, s.bindingRoutes()...)
	routes = append(routes, s.importRoutes()...)
	routes = append(routes, s.settingsRoutes()...)
	routes = append(routes, s.dashboardRoutes()...)
	routes = append(routes, s.viewRoutes()...)
	routes = append(routes, s.ssoRoutes()...)
	routes = append(routes, s.ldapRoutes()...)
	routes = append(routes, s.backupRoutes()...)
	routes = append(routes, s.httpsRoutes()...)
	routes = append(routes, s.forwardingRoutes()...)
	routes = append(routes, s.acmeRoutes()...)
	routes = append(routes, s.discoveryRoutes()...)
	return routes
}

// healthReason maps an error to a fixed label so no driver text (which could
// include connection details) ever reaches the logs.
func healthReason(err error) string {
	switch {
	case errors.Is(err, db.ErrUnreachable):
		return "database_unreachable"
	case errors.Is(err, db.ErrMigrationsPending):
		return "migrations_pending"
	default:
		return "unknown"
	}
}
