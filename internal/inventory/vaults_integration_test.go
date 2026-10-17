//go:build integration

package inventory_test

import (
	"context"
	"crypto/rsa"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"alice/internal/certs"
	"alice/internal/inventory"
	"alice/internal/jobs"
	"alice/internal/license"
	"alice/internal/platform/azureid"
	"alice/internal/platform/validate"
	"alice/internal/providers"
	"alice/internal/providers/fake"
	"alice/internal/rbac"
	"alice/internal/secrets"
	"alice/internal/testutil/fakekv"
	"alice/internal/testutil/pki"
)

const (
	kvTenant      = "1111aaaa-2222-bbbb-3333-cccc4444dddd"
	kvTenantUpper = "1111AAAA-2222-BBBB-3333-CCCC4444DDDD"
	kvClient      = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"
	kvObject      = "99999999-8888-7777-6666-555555555555"
)

// azureCaps are the capabilities of the azurekv provider (Task 8).
var azureCaps = []providers.Capability{providers.CapTestConnection, providers.CapDiscoverCerts, providers.CapDiscoverKVKeys,
	providers.CapDiscoverKVSecrets, providers.CapReadCertificateSecret, providers.CapImportCertificate}

// withAzureProvider replaces the registry with one holding the harness's linuxssh fake and p as the
// azurekv provider.
func withAzureProvider(p providers.Provider) harnessOption {
	return func(c *inventory.Config) {
		ssh, _ := c.Registry.Get(providers.KindLinuxSSH)
		reg := providers.NewRegistry()
		reg.Register(ssh)
		reg.Register(p)
		reg.Freeze()
		c.Registry = reg
	}
}

// withAzureAndNginx registers the scripted azurekv fake and the fake nginx provider next to linuxssh.
func withAzureAndNginx() harnessOption {
	return func(c *inventory.Config) {
		ssh, _ := c.Registry.Get(providers.KindLinuxSSH)
		reg := providers.NewRegistry()
		reg.Register(ssh)
		reg.Register(fake.New(providers.KindNginx, nginxCaps...))
		reg.Register(fake.New(providers.KindAzureKV, azureCaps...))
		reg.Freeze()
		c.Registry = reg
	}
}

// withAzure registers the scripted azurekv fake; the harness exposes it as h.azure.
func withAzure() harnessOption {
	return withAzureProvider(fake.New(providers.KindAzureKV, azureCaps...))
}

// spyAzure is the fake azurekv provider that also records the identity each Open was handed.
type spyAzure struct {
	*fake.Provider
	mu        sync.Mutex
	seen      []seenIdentity
	refs      []uuid.UUID
	forgotten []uuid.UUID
}

// ForgetTarget makes the spy a providers.ConnectionCache and records what was forgotten.
func (s *spyAzure) ForgetTarget(id uuid.UUID) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.forgotten = append(s.forgotten, id)
}

func (s *spyAzure) refIDs() []uuid.UUID {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]uuid.UUID(nil), s.refs...)
}

func (s *spyAzure) forgottenIDs() []uuid.UUID {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]uuid.UUID(nil), s.forgotten...)
}

type seenIdentity struct {
	Auth, Tenant, Client, Secret string
	CertificateDER, Key          []byte
}

func newSpyAzure() *spyAzure {
	return &spyAzure{Provider: fake.New(providers.KindAzureKV, azureCaps...)}
}

func (s *spyAzure) Open(ctx context.Context, t providers.TargetRef, cred providers.CredentialSource, env providers.Env) (providers.Session, error) {
	s.mu.Lock()
	s.refs = append(s.refs, t.ID)
	s.mu.Unlock()
	if az, ok := cred.(providers.AzureCredentialSource); ok {
		if id, release, err := az.AzureIdentity(ctx); err == nil {
			s.mu.Lock()
			s.seen = append(s.seen, seenIdentity{Auth: id.Auth, Tenant: id.TenantID, Client: id.ClientID,
				Secret: string(id.ClientSecret.Bytes()), CertificateDER: append([]byte(nil), id.CertificateDER...),
				Key: append([]byte(nil), id.PrivateKeyDER.Bytes()...)})
			s.mu.Unlock()
			release()
		}
	}
	return s.Provider.Open(ctx, t, cred, env)
}

func (s *spyAzure) identities() []seenIdentity {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]seenIdentity(nil), s.seen...)
}

func okChecks() []providers.AzureCheck {
	return []providers.AzureCheck{
		{Name: providers.AzureCheckSignIn, Result: providers.AzureResultOK},
		{Name: providers.AzureCheckListCertificates, Result: providers.AzureResultOK},
		{Name: providers.AzureCheckListKeys, Result: providers.AzureResultOK},
		{Name: providers.AzureCheckListSecrets, Result: providers.AzureResultOK},
		{Name: providers.AzureCheckReadSecret, Result: providers.AzureResultNotChecked},
		{Name: providers.AzureCheckImport, Result: providers.AzureResultNotChecked},
	}
}

func azureReport(checks []providers.AzureCheck) providers.ConnectionReport {
	return providers.ConnectionReport{Azure: &providers.AzureFacts{ObjectID: kvObject, TenantID: kvTenant, PermissionModel: "rbac",
		Checks: checks, CheckedAt: start}}
}

// script sets what the fake azurekv provider answers to the next test connections.
func (h *harness) script(fn func(c *fake.Config)) { h.azure.Configure(fn) }

func (h *harness) azureOK() {
	h.script(func(c *fake.Config) { c.Report, c.TestErr, c.OpenErr = azureReport(okChecks()), nil, nil })
}

func (h *harness) failWith(code string) {
	h.script(func(c *fake.Config) {
		c.Report, c.TestErr = providers.ConnectionReport{}, providers.NewError(code, false, nil, nil)
	})
}

func (h *harness) rawBytes(t *testing.T, sql string, args ...any) []byte {
	t.Helper()
	var b []byte
	require.NoError(t, h.db.Owner.QueryRow(h.ctx, sql, args...).Scan(&b))
	return b
}

// dump is every row of the tables a secret could leak into, as JSON text.
func (h *harness) dump(t *testing.T) string {
	t.Helper()
	var sb strings.Builder
	for _, table := range []string{"targets", "credentials", "audit_log", "jobs"} {
		rows, err := h.db.Owner.Query(h.ctx, "SELECT row_to_json(x)::text FROM "+table+" x")
		require.NoError(t, err)
		for rows.Next() {
			var s string
			require.NoError(t, rows.Scan(&s))
			sb.WriteString(s)
		}
		require.NoError(t, rows.Err())
		rows.Close()
	}
	return sb.String()
}

func (h *harness) vaultCredentials() int {
	return h.count("SELECT count(*) FROM credentials WHERE purpose = 'azure_vault'")
}

func (h *harness) vaultCount() int {
	return h.count("SELECT count(*) FROM targets WHERE type = 'azure_key_vault'")
}

func secretVault(name, url string) inventory.NewVault {
	return inventory.NewVault{Name: name, VaultURL: url, Auth: providers.AzureAuthClientSecret, TenantID: kvTenant, ClientID: kvClient,
		ClientSecret: secrets.NewPlaintext([]byte(fakekv.NewClientSecret()))}
}

func (h *harness) newVault(a inventory.Actor, name, url string) inventory.Target {
	h.t.Helper()
	tgt, _, _, err := h.svc.CreateVault(h.ctx, a, secretVault(name, url))
	require.NoError(h.t, err)
	return tgt
}

func TestCreateVaultRunsThePreflightAndStoresTheCredentialSealed(t *testing.T) {
	spy := newSpyAzure()
	h := newHarness(t, withAzureProvider(spy))
	h.azure = spy.Provider
	h.azureOK()
	admin := h.user("ada", rbac.Admin, "")
	secret := fakekv.NewClientSecret()
	tgt, rep, jobID, err := h.svc.CreateVault(h.ctx, admin, inventory.NewVault{Name: "Prod vault", VaultURL: "https://Prod-Vault.vault.azure.net/",
		Auth: providers.AzureAuthClientSecret, TenantID: kvTenantUpper, ClientID: kvClient,
		ClientSecret: secrets.NewPlaintext([]byte(secret)), SecretExpiresOn: ptr(start.Add(180 * 24 * time.Hour))})
	require.NoError(t, err)
	assert.Equal(t, inventory.TypeAzureKeyVault, tgt.Type)
	assert.Equal(t, inventory.StatusOK, tgt.Status)
	assert.Empty(t, tgt.LastErrorCode)
	assert.Equal(t, "Prod vault", tgt.Name)
	require.NotNil(t, tgt.Vault)
	assert.Equal(t, "https://prod-vault.vault.azure.net", tgt.Vault.URL)
	assert.Equal(t, "prod-vault.vault.azure.net", tgt.Vault.Host)
	assert.Equal(t, providers.AzureAuthClientSecret, tgt.Vault.Auth)
	assert.Equal(t, kvTenant, tgt.Vault.TenantID)
	assert.Equal(t, kvClient, tgt.Vault.ClientID)
	assert.Equal(t, start.Add(180*24*time.Hour), *tgt.Vault.SecretExpiresOn)
	assert.Equal(t, 15*time.Minute, tgt.Vault.PollInterval)
	assert.Equal(t, 15*time.Minute, tgt.DiscoveryInterval)
	assert.Equal(t, providers.AzureResultOK, rep.Azure.Checks[1].Result)
	require.NotNil(t, tgt.Vault.Access)
	assert.Equal(t, rep.Azure.Checks, tgt.Vault.Access.Checks)
	assert.Equal(t, tgt.Facts.Azure, tgt.Vault.Access)
	assert.Equal(t, kvObject, tgt.Vault.Access.ObjectID)
	require.NotNil(t, tgt.LastSuccessAt)
	assert.Contains(t, tgt.Capabilities, "discover_certificates")

	reqs := h.jobs.requests()
	require.Len(t, reqs, 1)
	assert.Equal(t, inventory.JobKVPoll, reqs[0].Type, "the first poll is queued at once")
	assert.Equal(t, "kv.poll:"+tgt.ID.String(), reqs[0].DedupeKey)
	assert.Equal(t, tgt.ID, reqs[0].TargetID)
	assert.NotEqual(t, uuid.Nil, jobID)

	// The pre-flight signed in with exactly what is stored, and asked the vault by its canonical URL.
	seen := spy.identities()
	require.Len(t, seen, 1)
	assert.Equal(t, seenIdentity{Auth: providers.AzureAuthClientSecret, Tenant: kvTenant, Client: kvClient, Secret: secret,
		CertificateDER: nil, Key: nil}, seen[0])
	assert.Equal(t, 1, h.azure.Count("TestConnection"))
	assert.Equal(t, 1, h.azure.Count("Close"), "the pre-flight session is closed")

	// The credential row: purpose azure_vault, kind azure_sp_secret, target_id the vault, public_info
	// without the secret; the ciphertext does not contain the secret and opens with the AAD of its row only.
	var credID, owner uuid.UUID
	var kind, purpose string
	var info []byte
	require.NoError(t, h.db.Owner.QueryRow(h.ctx, `SELECT c.id, c.kind, c.purpose, c.target_id, c.public_info FROM targets t JOIN credentials c ON c.id = t.credential_id WHERE t.id = $1`,
		tgt.ID).Scan(&credID, &kind, &purpose, &owner, &info))
	assert.Equal(t, "azure_sp_secret", kind)
	assert.Equal(t, "azure_vault", purpose)
	assert.Equal(t, tgt.ID, owner)
	assert.NotContains(t, string(info), secret)
	assert.JSONEq(t, fmt.Sprintf(`{"auth":"client_secret","tenant_id":%q,"client_id":%q,"secret_expires_on":%q}`,
		kvTenant, kvClient, start.Add(180*24*time.Hour).Format(time.RFC3339)), string(info))
	raw := h.rawBytes(t, "SELECT ciphertext FROM credentials WHERE target_id = $1", tgt.ID)
	assert.NotContains(t, string(raw), secret)
	var env secrets.Envelope
	require.NoError(t, h.db.Owner.QueryRow(h.ctx, "SELECT ciphertext, nonce, wrapped_dek, key_version FROM credentials WHERE id = $1", credID).
		Scan(&env.Ciphertext, &env.Nonce, &env.WrappedDEK, &env.KeyVersion))
	pt, err := h.keyring.Open(secrets.Location{Table: "credentials", RowID: credID.String(), Column: "ciphertext"}, env)
	require.NoError(t, err)
	assert.Equal(t, secret, string(pt.Bytes()))
	pt.Zero()
	_, err = h.keyring.Open(secrets.Location{Table: "credentials", RowID: uuid.NewString(), Column: "ciphertext"}, env)
	assert.Error(t, err, "the envelope is bound to its own row")

	assert.Equal(t, 1, h.audits("target.created"))
	d := h.auditDetails("target.created")[0]
	assert.Equal(t, map[string]string{"name": "Prod vault", "type": "azure_key_vault", "vault_url": "https://prod-vault.vault.azure.net",
		"auth": "client_secret", "tenant_id": kvTenant, "client_id": kvClient, "credential_id": credID.String(), "status": "ok"}, d)

	// Canary: nowhere else.
	assert.NotContains(t, h.dump(t), secret)
	assert.NotContains(t, h.dump(t), hex.EncodeToString([]byte(secret)))
	assert.NotContains(t, h.logs.String(), secret)

	got, err := h.svc.GetTarget(h.ctx, tgt.ID)
	require.NoError(t, err)
	assert.Equal(t, tgt, got)
	list, err := h.svc.ListTargets(h.ctx)
	require.NoError(t, err)
	assert.Equal(t, []inventory.Target{tgt}, list)
}

func TestCreateVaultRefusalsCreateNothing(t *testing.T) {
	h := newHarness(t, withAzure())
	admin := h.user("ada", rbac.Admin, "")
	refusals := []string{"azure.vault_not_found", "azure.auth_failed", "azure.credentials_expired", "azure.unreachable",
		"azure.tls_untrusted", "azure.address_not_allowed", "azure.clock_skew", "azure.throttled", "azure.unexpected_response"}
	for i, code := range refusals {
		h.failWith(code)
		_, _, jobID, err := h.svc.CreateVault(h.ctx, admin, secretVault("v", "https://oops.vault.azure.net"))
		var pe *providers.Error
		require.ErrorAs(t, err, &pe, code)
		assert.Equal(t, code, pe.Code)
		assert.Equal(t, uuid.Nil, jobID)
		assert.Equal(t, 0, h.vaultCount(), code)
		assert.Equal(t, 0, h.vaultCredentials(), code)
		assert.Empty(t, h.jobs.requests(), code)
		assert.Equal(t, 0, h.audits("target.created"))
		assert.Equal(t, i+1, h.audits("vault.add_refused"))
	}
	assert.Equal(t, 0, h.count("SELECT count(*) FROM targets"))
	got := h.auditDetails("vault.add_refused")
	for i, code := range refusals {
		assert.Equal(t, map[string]string{"vault_url": "https://oops.vault.azure.net", "auth": "client_secret", "reason": code}, got[i])
	}
	n, err := inventory.Counter{}.CountTargets(h.ctx, h.db.Owner)
	require.NoError(t, err)
	assert.Equal(t, 0, n, "no license slot is used")

	// The sign-in itself refused at Open.
	h.script(func(c *fake.Config) {
		c.TestErr, c.OpenErr = nil, providers.NewError("azure.auth_failed", false, nil, nil)
	})
	_, _, _, err = h.svc.CreateVault(h.ctx, admin, secretVault("v", "https://oops.vault.azure.net"))
	var pe *providers.Error
	require.ErrorAs(t, err, &pe)
	assert.Equal(t, "azure.auth_failed", pe.Code)
	assert.Equal(t, 0, h.vaultCredentials())

	// A provider that reports the first failure as rows instead of an error is refused the same way.
	h.script(func(c *fake.Config) {
		c.OpenErr = nil
		c.Report = azureReport([]providers.AzureCheck{{Name: providers.AzureCheckSignIn, Result: providers.AzureResultOK},
			{Name: providers.AzureCheckListCertificates, Result: providers.AzureResultFailed, Reason: "azure.vault_not_found"}})
	})
	_, _, _, err = h.svc.CreateVault(h.ctx, admin, secretVault("v", "https://oops.vault.azure.net"))
	require.ErrorAs(t, err, &pe)
	assert.Equal(t, "azure.vault_not_found", pe.Code)
	assert.Equal(t, 0, h.vaultCount())

	// A failure that is not a provider error is refused too, with a stable reason; its text is not stored.
	h.script(func(c *fake.Config) {
		c.Report, c.TestErr = providers.ConnectionReport{}, fmt.Errorf("dial tcp 10.1.2.3:443: secret-ish text")
	})
	_, _, _, err = h.svc.CreateVault(h.ctx, admin, secretVault("v", "https://oops.vault.azure.net"))
	require.Error(t, err)
	last := h.auditDetails("vault.add_refused")
	assert.Equal(t, "internal.unexpected", last[len(last)-1]["reason"])
	assert.NotContains(t, h.dump(t), "secret-ish")
}

func TestCreateVaultRefusesInvalidInputBeforeAnyCall(t *testing.T) {
	h := newHarness(t, withAzure())
	admin := h.user("ada", rbac.Admin, "")
	in := secretVault("v", "https://contoso.vault.azure.net:8443")
	in.TenantID = "contoso.onmicrosoft.com"
	_, _, _, err := h.svc.CreateVault(h.ctx, admin, in)
	var verrs validate.Errors
	require.ErrorAs(t, err, &verrs)
	assert.Equal(t, []string{"vault_url", "tenant_id"}, []string{verrs[0].Field, verrs[1].Field})
	assert.Equal(t, 0, h.azure.Count("Open"))
	assert.Equal(t, 0, h.vaultCount())
	assert.Empty(t, h.jobs.requests())
}

func TestCreateVaultDuplicatesAreRefused(t *testing.T) {
	h := newHarness(t, withAzure())
	h.azureOK()
	admin := h.user("ada", rbac.Admin, "")
	first := h.newVault(admin, "Prod", "https://prod.vault.azure.net")
	for _, url := range []string{"https://prod.vault.azure.net", "https://PROD.vault.azure.net/", "prod", "  Prod.Vault.Azure.Net  "} {
		_, _, _, err := h.svc.CreateVault(h.ctx, admin, secretVault("Other "+url, url))
		require.ErrorIs(t, err, inventory.ErrDuplicateTarget, url)
	}
	_, _, _, err := h.svc.CreateVault(h.ctx, admin, secretVault("PROD", "https://other.vault.azure.net"))
	require.ErrorIs(t, err, inventory.ErrDuplicateTarget, "names are unique without regard to case")
	assert.Equal(t, 1, h.vaultCount())
	assert.Equal(t, 1, h.vaultCredentials(), "a refused add leaves no credential row")
	assert.Len(t, h.jobs.requests(), 1)
	assert.Equal(t, 1, h.audits("target.created"))

	// A deleted vault frees its address and name.
	require.NoError(t, h.svc.DeleteVault(h.ctx, admin, first.ID, false))
	again := h.newVault(admin, "Prod", "https://prod.vault.azure.net")
	assert.NotEqual(t, first.ID, again.ID)
}

func TestCreateVaultLicense(t *testing.T) {
	h := newHarness(t, withAzure())
	h.azureOK()
	admin := h.user("ada", rbac.Admin, "")
	addN(h, admin, 1, 4)
	h.newVault(admin, "Fifth", "https://fifth.vault.azure.net")
	opens := h.azure.Count("Open")
	_, _, _, err := h.svc.CreateVault(h.ctx, admin, secretVault("Sixth", "https://sixth.vault.azure.net"))
	var limit *license.TargetLimitError
	require.ErrorAs(t, err, &limit)
	assert.Equal(t, 5, limit.Max)
	assert.Equal(t, opens, h.azure.Count("Open"), "a vault the license cannot hold is refused before Azure is called")
	assert.Equal(t, 1, h.vaultCredentials())
	assert.Equal(t, []map[string]string{{"reason": "target_limit", "used": "5", "max": "5", "name": "Sixth"}},
		h.auditDetails("target.add.denied_license"))

	// Deleting a vault frees its slot at once (L-79).
	require.NoError(t, h.svc.DeleteVault(h.ctx, admin, mustList(t, h)[4].ID, false))
	h.newVault(admin, "Sixth", "https://sixth.vault.azure.net")
}

func TestCreateVaultIsRefusedInLock(t *testing.T) {
	h := newHarness(t, withAzure())
	h.azureOK()
	admin := h.user("ada", rbac.Admin, "")
	h.clock.Advance(31 * 24 * time.Hour)
	require.NoError(t, h.lic.Tick(h.ctx))
	_, _, _, err := h.svc.CreateVault(h.ctx, admin, secretVault("Prod", "https://prod.vault.azure.net"))
	require.ErrorIs(t, err, license.ErrLocked)
	assert.Equal(t, 0, h.azure.Count("Open"), "nothing is sent to Azure in lock")
	assert.Equal(t, 0, h.vaultCount())
	require.Len(t, h.auditDetails("target.add.denied_license"), 1)
	assert.Equal(t, "locked", h.auditDetails("target.add.denied_license")[0]["reason"])
}

func TestCreateVaultWithMissingRolesIsDegraded(t *testing.T) {
	h := newHarness(t, withAzure())
	admin := h.user("ada", rbac.Admin, "")
	checks := okChecks()
	checks[1] = providers.AzureCheck{Name: providers.AzureCheckListCertificates, Result: providers.AzureResultForbidden,
		Reason: "azure.forbidden", Role: providers.RoleKeyVaultReader}
	h.script(func(c *fake.Config) { c.Report = azureReport(checks) })
	tgt, rep, _, err := h.svc.CreateVault(h.ctx, admin, secretVault("Prod", "https://prod.vault.azure.net"))
	require.NoError(t, err)
	assert.Equal(t, inventory.StatusDegraded, tgt.Status)
	assert.Equal(t, "azure.forbidden", tgt.LastErrorCode)
	require.NotNil(t, tgt.Facts.Azure)
	assert.Equal(t, providers.AzureResultForbidden, tgt.Facts.Azure.Checks[1].Result)
	assert.Equal(t, providers.RoleKeyVaultReader, tgt.Facts.Azure.Checks[1].Role)
	assert.Equal(t, tgt.Facts.Azure, rep.Azure)
	assert.Equal(t, inventory.JobKVPoll, h.jobs.requests()[0].Type)
	assert.Equal(t, "degraded", h.auditDetails("target.created")[0]["status"])

	// A forbidden or firewall answer to the first call, reported as an error, adds the vault as well.
	for i, code := range []string{"azure.forbidden", "azure.firewall"} {
		h.script(func(c *fake.Config) {
			c.Report, c.TestErr = providers.ConnectionReport{}, providers.NewError(code, false, nil, map[string]string{"client_address": "203.0.113.7"})
		})
		name := fmt.Sprintf("v%d", i)
		tgt, rep, _, err := h.svc.CreateVault(h.ctx, admin, secretVault(name, "https://"+name+"-vault.vault.azure.net"))
		require.NoError(t, err, code)
		assert.Equal(t, inventory.StatusDegraded, tgt.Status, code)
		assert.Equal(t, code, tgt.LastErrorCode)
		require.NotNil(t, rep.Azure, code)
		assert.Equal(t, providers.AzureResultOK, rep.Azure.Checks[0].Result, "the sign-in worked")
	}

	// A firewall reported as a row.
	checks = okChecks()
	checks[1] = providers.AzureCheck{Name: providers.AzureCheckListCertificates, Result: providers.AzureResultFailed, Reason: "azure.firewall"}
	h.script(func(c *fake.Config) { c.Report, c.TestErr = azureReport(checks), nil })
	tgt, _, _, err = h.svc.CreateVault(h.ctx, admin, secretVault("fw", "https://fw-vault.vault.azure.net"))
	require.NoError(t, err)
	assert.Equal(t, inventory.StatusDegraded, tgt.Status)
	assert.Equal(t, "azure.firewall", tgt.LastErrorCode)
	assert.Equal(t, 4, h.count("SELECT count(*) FROM targets WHERE status = 'degraded'"))
	assert.Equal(t, 0, h.audits("vault.add_refused"))
}

func TestCreateVaultStoresOnlyCleanAccessChecks(t *testing.T) {
	h := newHarness(t, withAzure())
	admin := h.user("ada", rbac.Admin, "")
	checks := append(okChecks(), providers.AzureCheck{Name: "<script>", Result: "ok"})
	checks[2] = providers.AzureCheck{Name: providers.AzureCheckListKeys, Result: providers.AzureResultFailed,
		Reason: "AADSTS7000215: Invalid client secret provided", Role: "Owner of everything"}
	rep := azureReport(checks)
	rep.Azure.ObjectID, rep.Azure.TenantID, rep.Azure.PermissionModel = "not a guid", "contoso.onmicrosoft.com", "<b>weird</b>"
	h.script(func(c *fake.Config) { c.Report = rep })
	tgt, _, _, err := h.svc.CreateVault(h.ctx, admin, secretVault("Prod", "https://prod.vault.azure.net"))
	require.NoError(t, err)
	a := tgt.Facts.Azure
	require.NotNil(t, a)
	assert.Empty(t, a.ObjectID)
	assert.Empty(t, a.TenantID)
	assert.Equal(t, "unknown", a.PermissionModel)
	assert.Len(t, a.Checks, 6, "a row with an unknown name is dropped")
	assert.Equal(t, "internal.unexpected", a.Checks[2].Reason)
	assert.Empty(t, a.Checks[2].Role)
	assert.Equal(t, "internal.unexpected", tgt.LastErrorCode)
	assert.NotContains(t, h.dump(t), "AADSTS")
}

func TestCreateVaultWithCertificateAndManagedIdentity(t *testing.T) {
	spy := newSpyAzure()
	h := newHarness(t, withAzureProvider(spy))
	h.azure = spy.Provider
	h.azureOK()
	admin := h.user("ada", rbac.Admin, "")

	leaf := pki.SelfSigned("sp.example.test", pki.RSA2048, h.clock.Now())
	markers := secretMarkers(t, leaf.Key)
	tgt, _, _, err := h.svc.CreateVault(h.ctx, admin, inventory.NewVault{Name: "Cert vault", VaultURL: "certvault", Auth: providers.AzureAuthCertificate,
		TenantID: kvTenant, ClientID: kvClient, Certificate: certs.Upload{CertificatePEM: leaf.CertPEM, PrivateKeyPEM: leaf.KeyPEM}})
	require.NoError(t, err)
	assert.Equal(t, inventory.StatusOK, tgt.Status)
	require.NotNil(t, tgt.Vault)
	assert.Equal(t, providers.AzureAuthCertificate, tgt.Vault.Auth)
	assert.Equal(t, azureid.ThumbprintOf(leaf.Cert.Raw), tgt.Vault.CertThumbprint)
	assert.Equal(t, leaf.Cert.NotAfter.UTC(), *tgt.Vault.CertNotAfter)
	assert.Nil(t, tgt.Vault.SecretExpiresOn)
	seen := spy.identities()
	require.Len(t, seen, 1)
	assert.Equal(t, providers.AzureAuthCertificate, seen[0].Auth)
	assert.Equal(t, leaf.Cert.Raw, seen[0].CertificateDER)
	parsed, err := x509.ParsePKCS8PrivateKey(seen[0].Key)
	require.NoError(t, err)
	assert.True(t, leaf.Key.(*rsa.PrivateKey).Equal(parsed), "the pre-flight signed in with the uploaded key")

	// The stored credential: kind azure_sp_cert, public_info with the certificate and thumbprint, the sealed
	// payload is the PKCS #8 key and opens through the vault's source.
	var kind string
	var info []byte
	require.NoError(t, h.db.Owner.QueryRow(h.ctx, "SELECT kind, public_info FROM credentials WHERE target_id = $1", tgt.ID).Scan(&kind, &info))
	assert.Equal(t, "azure_sp_cert", kind)
	assert.Contains(t, string(info), azureid.ThumbprintOf(leaf.Cert.Raw))
	id, release, err := h.svc.VaultCredentials(tgt.ID).AzureIdentity(h.ctx)
	require.NoError(t, err)
	assert.Equal(t, seen[0].Key, id.PrivateKeyDER.Bytes())
	assert.Equal(t, leaf.Cert.Raw, id.CertificateDER)
	release()
	dump := h.dump(t)
	for _, m := range markers {
		assert.NotContains(t, dump, m, "no form of the private key is in a column, an audit detail or a job")
		assert.NotContains(t, h.logs.String(), m)
	}

	// An ECDSA key is not accepted (MSAL signs with RSA), and nothing is sent to Azure for it.
	opens := h.azure.Count("Open")
	ec := pki.SelfSigned("ec.example.test", pki.ECDSA256, h.clock.Now())
	_, _, _, err = h.svc.CreateVault(h.ctx, admin, inventory.NewVault{Name: "EC", VaultURL: "ecvault", Auth: providers.AzureAuthCertificate,
		TenantID: kvTenant, ClientID: kvClient, Certificate: certs.Upload{CertificatePEM: ec.CertPEM, PrivateKeyPEM: ec.KeyPEM}})
	require.ErrorIs(t, err, inventory.ErrClientCertificateInvalid)
	assert.Equal(t, opens, h.azure.Count("Open"))

	// An expired certificate and one that is not valid yet are refused before Azure is called.
	expired := pki.NewCA("c", pki.ECDSA256, h.clock.Now()).Issue(pki.Opts{CommonName: "old", KeyType: pki.RSA2048,
		NotBefore: h.clock.Now().Add(-48 * time.Hour), NotAfter: h.clock.Now().Add(-time.Hour)}, h.clock.Now())
	_, _, _, err = h.svc.CreateVault(h.ctx, admin, inventory.NewVault{Name: "Old", VaultURL: "oldvault", Auth: providers.AzureAuthCertificate,
		TenantID: kvTenant, ClientID: kvClient, Certificate: certs.Upload{CertificatePEM: expired.CertPEM, PrivateKeyPEM: expired.KeyPEM}})
	require.ErrorIs(t, err, inventory.ErrCertificateExpired)
	future := pki.NewCA("c", pki.ECDSA256, h.clock.Now()).Issue(pki.Opts{CommonName: "new", KeyType: pki.RSA2048,
		NotBefore: h.clock.Now().Add(time.Hour), NotAfter: h.clock.Now().Add(48 * time.Hour)}, h.clock.Now())
	_, _, _, err = h.svc.CreateVault(h.ctx, admin, inventory.NewVault{Name: "New", VaultURL: "newvault", Auth: providers.AzureAuthCertificate,
		TenantID: kvTenant, ClientID: kvClient, Certificate: certs.Upload{CertificatePEM: future.CertPEM, PrivateKeyPEM: future.KeyPEM}})
	require.ErrorIs(t, err, inventory.ErrCertificateNotYetValid)
	assert.Equal(t, opens, h.azure.Count("Open"))
	assert.Equal(t, 1, h.vaultCount())

	// A managed identity: nothing secret, the sealed payload is empty, the user-assigned client ID is optional.
	mi, _, _, err := h.svc.CreateVault(h.ctx, admin, inventory.NewVault{Name: "MI vault", VaultURL: "mivault", Auth: providers.AzureAuthManagedIdentity})
	require.NoError(t, err)
	assert.Equal(t, providers.AzureAuthManagedIdentity, mi.Vault.Auth)
	assert.Empty(t, mi.Vault.TenantID)
	assert.Empty(t, mi.Vault.ClientID)
	var miCred uuid.UUID
	var env secrets.Envelope
	require.NoError(t, h.db.Owner.QueryRow(h.ctx, "SELECT id, kind, ciphertext, nonce, wrapped_dek, key_version FROM credentials WHERE target_id = $1", mi.ID).
		Scan(&miCred, &kind, &env.Ciphertext, &env.Nonce, &env.WrappedDEK, &env.KeyVersion))
	assert.Equal(t, "azure_managed_identity", kind)
	pt, err := h.keyring.Open(secrets.Location{Table: "credentials", RowID: miCred.String(), Column: "ciphertext"}, env)
	require.NoError(t, err)
	assert.Empty(t, pt.Bytes())
	mid, release, err := h.svc.VaultCredentials(mi.ID).AzureIdentity(h.ctx)
	require.NoError(t, err)
	assert.Equal(t, providers.AzureAuthManagedIdentity, mid.Auth)
	release()
	mi2, _, _, err := h.svc.CreateVault(h.ctx, admin, inventory.NewVault{Name: "MI user", VaultURL: "miuser", Auth: providers.AzureAuthManagedIdentity, ClientID: kvClient})
	require.NoError(t, err)
	assert.Equal(t, kvClient, mi2.Vault.ClientID)
}

func TestVaultCredentialSource(t *testing.T) {
	h := newHarness(t, withAzure())
	h.azureOK()
	admin := h.user("ada", rbac.Admin, "")
	secret := fakekv.NewClientSecret()
	in := secretVault("Prod", "https://prod.vault.azure.net")
	in.ClientSecret = secrets.NewPlaintext([]byte(secret))
	a, _, _, err := h.svc.CreateVault(h.ctx, admin, in)
	require.NoError(t, err)
	b := h.newVault(admin, "Other", "https://other.vault.azure.net")

	src := h.svc.VaultCredentials(a.ID)
	id, release, err := src.AzureIdentity(h.ctx)
	require.NoError(t, err)
	assert.Equal(t, providers.AzureAuthClientSecret, id.Auth)
	assert.Equal(t, kvTenant, id.TenantID)
	assert.Equal(t, kvClient, id.ClientID)
	assert.Equal(t, secret, string(id.ClientSecret.Bytes()))
	assert.NotContains(t, fmt.Sprintf("%v %+v %#v", id, id, id), secret)
	held := id.ClientSecret.Bytes()
	release()
	assert.Equal(t, make([]byte, len(secret)), held, "release zeroes the decrypted secret")

	_, _, err = src.SSHSigner(h.ctx)
	require.Error(t, err, "a vault source has no SSH key")
	_, isVaultSource := h.svc.Credentials().(providers.AzureCredentialSource)
	assert.False(t, isVaultSource, "and the platform key's source is no vault source")

	// A credential row that names another vault (moved by the owner role) is refused, never used.
	_, err = h.db.Owner.Exec(h.ctx, "UPDATE credentials SET target_id = $2 WHERE id = (SELECT credential_id FROM targets WHERE id = $1)", a.ID, b.ID)
	require.NoError(t, err)
	_, _, err = src.AzureIdentity(h.ctx)
	require.Error(t, err)
	assert.NotContains(t, err.Error(), secret)

	// An unknown or deleted vault, and a server, have no vault credential.
	_, _, err = h.svc.VaultCredentials(uuid.New()).AzureIdentity(h.ctx)
	require.ErrorIs(t, err, inventory.ErrNotFound)
	web := h.add(admin, "web", "web.example.com")
	_, _, err = h.svc.VaultCredentials(web.ID).AzureIdentity(h.ctx)
	require.ErrorIs(t, err, inventory.ErrNotFound)

	// A row that was tampered with is refused: a certificate credential whose kind says secret.
	_, err = h.db.Owner.Exec(h.ctx, "UPDATE credentials SET public_info = '{\"auth\":\"certificate\"}' WHERE target_id = $1 AND id = (SELECT credential_id FROM targets WHERE id = $1)", b.ID)
	require.NoError(t, err)
	_, _, err = h.svc.VaultCredentials(b.ID).AzureIdentity(h.ctx)
	require.Error(t, err)

	// A sealed secret this master key cannot open (another key, a damaged row) is a closed refusal the
	// deployment engine can name: replace the vault's credentials.
	c := h.newVault(admin, "Third", "https://third.vault.azure.net")
	_, err = h.db.Owner.Exec(h.ctx, "UPDATE credentials SET ciphertext = ciphertext || '\\x00'::bytea WHERE id = (SELECT credential_id FROM targets WHERE id = $1)", c.ID)
	require.NoError(t, err)
	_, _, err = h.svc.VaultCredentials(c.ID).AzureIdentity(h.ctx)
	require.ErrorIs(t, err, inventory.ErrVaultCredentialUnreadable)
	require.ErrorIs(t, err, secrets.ErrDecrypt)
}

func TestVaultInputIsConsumedByTheCall(t *testing.T) {
	h := newHarness(t, withAzure())
	admin := h.user("ada", rbac.Admin, "")
	leaf := pki.SelfSigned("sp.example.test", pki.RSA2048, h.clock.Now())
	key := append([]byte(nil), leaf.KeyPEM...)
	in := inventory.NewVault{Name: "Cert", VaultURL: "certvault", Auth: providers.AzureAuthCertificate, TenantID: kvTenant, ClientID: kvClient,
		Certificate: certs.Upload{CertificatePEM: leaf.CertPEM, PrivateKeyPEM: key}}
	h.azureOK()
	_, _, _, err := h.svc.CreateVault(h.ctx, admin, in)
	require.NoError(t, err)
	assert.Equal(t, make([]byte, len(key)), key, "the private key PEM is zeroed after use")

	secret := secrets.NewPlaintext([]byte(fakekv.NewClientSecret()))
	bad := secretVault("Bad", "https://bad.vault.azure.net:99")
	bad.ClientSecret = secret
	_, _, _, err = h.svc.CreateVault(h.ctx, admin, bad)
	require.Error(t, err)
	assert.Equal(t, make([]byte, len(secret.Bytes())), secret.Bytes(), "even a refused request's secret is zeroed")
}

func TestReplaceVaultCredentials(t *testing.T) {
	spy := newSpyAzure()
	h := newHarness(t, withAzureProvider(spy))
	h.azure = spy.Provider
	h.azureOK()
	admin := h.user("ada", rbac.Admin, "")
	oldSecret := fakekv.NewClientSecret()
	in := secretVault("Prod", "https://prod.vault.azure.net")
	in.ClientSecret = secrets.NewPlaintext([]byte(oldSecret))
	tgt, _, _, err := h.svc.CreateVault(h.ctx, admin, in)
	require.NoError(t, err)
	var oldCred uuid.UUID
	require.NoError(t, h.db.Owner.QueryRow(h.ctx, "SELECT credential_id FROM targets WHERE id = $1", tgt.ID).Scan(&oldCred))
	_, err = h.db.Owner.Exec(h.ctx, `UPDATE targets SET status = 'auth_failed', last_error_code = 'azure.auth_failed', poll_failures = 5,
facts = facts || '{"kv_auth_failures": 3, "kv_throttled_cycles": 2}' WHERE id = $1`, tgt.ID)
	require.NoError(t, err)
	cur, err := h.svc.GetTarget(h.ctx, tgt.ID)
	require.NoError(t, err)

	newSecret := fakekv.NewClientSecret()
	newBytes := []byte(newSecret)
	h.clock.Advance(time.Hour)
	got, rep, jobID, err := h.svc.ReplaceVaultCredentials(h.ctx, admin, tgt.ID, cur.Version, inventory.VaultCredentialInput{
		Auth: providers.AzureAuthClientSecret, TenantID: kvTenant, ClientID: kvClient, ClientSecret: secrets.NewPlaintext(newBytes)})
	require.NoError(t, err)
	assert.Equal(t, make([]byte, len(newSecret)), newBytes, "the replacement's secret is zeroed after a success")
	assert.NotEqual(t, uuid.Nil, jobID)
	assert.Equal(t, cur.Version+1, got.Version)
	assert.Equal(t, inventory.StatusOK, got.Status)
	assert.Empty(t, got.LastErrorCode)
	assert.Equal(t, rep.Azure, got.Vault.Access)
	assert.Zero(t, got.Facts.KVAuthFailures)
	assert.Zero(t, got.Facts.KVThrottledCycles)
	assert.Equal(t, 0, h.count("SELECT poll_failures FROM targets WHERE id = $1", tgt.ID))
	var newCred uuid.UUID
	require.NoError(t, h.db.Owner.QueryRow(h.ctx, "SELECT credential_id FROM targets WHERE id = $1", tgt.ID).Scan(&newCred))
	assert.NotEqual(t, oldCred, newCred)
	assert.Equal(t, 2, h.vaultCredentials(), "the old row remains: credentials are append-only, superseded not erased")
	assert.Equal(t, 2, h.count("SELECT count(*) FROM credentials WHERE target_id = $1", tgt.ID))

	id, release, err := h.svc.VaultCredentials(tgt.ID).AzureIdentity(h.ctx)
	require.NoError(t, err)
	assert.Equal(t, newSecret, string(id.ClientSecret.Bytes()))
	release()
	seen := spy.identities()
	assert.Equal(t, newSecret, seen[len(seen)-1].Secret, "the pre-flight used the new secret against the stored vault URL")
	assert.Equal(t, 1+1, h.azure.Count("TestConnection"))
	require.Len(t, h.jobs.requests(), 2)
	assert.Equal(t, inventory.JobKVPoll, h.jobs.requests()[1].Type, "a poll is queued")

	details := h.auditDetails("vault.credentials_replaced")
	require.Len(t, details, 1)
	assert.Equal(t, map[string]string{"name": "Prod", "vault_url": "https://prod.vault.azure.net", "auth": "client_secret",
		"tenant_id": kvTenant, "client_id": kvClient, "credential_id": newCred.String(), "previous_credential_id": oldCred.String(), "status": "ok"}, details[0])
	assert.NotContains(t, h.dump(t), newSecret)
	assert.NotContains(t, h.dump(t), oldSecret)
	assert.NotContains(t, h.logs.String(), newSecret)

	// A wrong secret is refused by the pre-flight and nothing changes.
	h.failWith("azure.auth_failed")
	wrong := []byte(fakekv.NewClientSecret())
	_, _, _, err = h.svc.ReplaceVaultCredentials(h.ctx, admin, tgt.ID, got.Version, inventory.VaultCredentialInput{
		Auth: providers.AzureAuthClientSecret, TenantID: kvTenant, ClientID: kvClient, ClientSecret: secrets.NewPlaintext(wrong)})
	var pe *providers.Error
	require.ErrorAs(t, err, &pe)
	assert.Equal(t, "azure.auth_failed", pe.Code)
	assert.Equal(t, make([]byte, len(wrong)), wrong, "the secret of a refused replacement is zeroed too")
	// The refusal is audited (SEC-070): one row, a closed reason, no Azure text.
	refused := h.auditDetails("vault.credentials_refused")
	require.Len(t, refused, 1)
	assert.Equal(t, map[string]string{"vault_url": "https://prod.vault.azure.net", "auth": "client_secret", "reason": "azure.auth_failed"}, refused[0])
	var refusedObject uuid.UUID
	var refusedResult string
	require.NoError(t, h.db.Owner.QueryRow(h.ctx, "SELECT object_id::uuid, result FROM audit_log WHERE action = 'vault.credentials_refused'").Scan(&refusedObject, &refusedResult))
	assert.Equal(t, tgt.ID, refusedObject)
	assert.Equal(t, "failure", refusedResult)
	assert.Equal(t, 2, h.vaultCredentials())
	now, err := h.svc.GetTarget(h.ctx, tgt.ID)
	require.NoError(t, err)
	assert.Equal(t, got, now)
	assert.Equal(t, 1, h.audits("vault.credentials_replaced"))

	// A stale version is refused before Azure is asked.
	h.azureOK()
	opens := h.azure.Count("Open")
	_, _, _, err = h.svc.ReplaceVaultCredentials(h.ctx, admin, tgt.ID, cur.Version, inventory.VaultCredentialInput{
		Auth: providers.AzureAuthManagedIdentity})
	require.ErrorIs(t, err, inventory.ErrVersionMismatch)
	assert.Equal(t, opens, h.azure.Count("Open"))

	// Invalid input, a server and an unknown vault.
	_, _, _, err = h.svc.ReplaceVaultCredentials(h.ctx, admin, tgt.ID, got.Version, inventory.VaultCredentialInput{Auth: "password"})
	var verrs validate.Errors
	require.ErrorAs(t, err, &verrs)
	web := h.add(admin, "web", "web.example.com")
	_, _, _, err = h.svc.ReplaceVaultCredentials(h.ctx, admin, web.ID, web.Version, inventory.VaultCredentialInput{Auth: providers.AzureAuthManagedIdentity})
	require.ErrorIs(t, err, inventory.ErrNotAVault)
	_, _, _, err = h.svc.ReplaceVaultCredentials(h.ctx, admin, uuid.New(), 1, inventory.VaultCredentialInput{Auth: providers.AzureAuthManagedIdentity})
	require.ErrorIs(t, err, inventory.ErrNotFound)

	// The method can change; a degraded check degrades the vault; a disabled vault stays disabled.
	checks := okChecks()
	checks[2] = providers.AzureCheck{Name: providers.AzureCheckListKeys, Result: providers.AzureResultForbidden, Reason: "azure.forbidden", Role: providers.RoleKeyVaultReader}
	h.script(func(c *fake.Config) { c.Report = azureReport(checks) })
	mi, _, _, err := h.svc.ReplaceVaultCredentials(h.ctx, admin, tgt.ID, got.Version, inventory.VaultCredentialInput{Auth: providers.AzureAuthManagedIdentity})
	require.NoError(t, err)
	assert.Equal(t, inventory.StatusDegraded, mi.Status)
	assert.Equal(t, providers.AzureAuthManagedIdentity, mi.Vault.Auth)
	assert.Empty(t, mi.Vault.TenantID)
	_, err = h.db.Owner.Exec(h.ctx, "UPDATE targets SET status = 'disabled' WHERE id = $1", tgt.ID)
	require.NoError(t, err)
	off, err := h.svc.GetTarget(h.ctx, tgt.ID)
	require.NoError(t, err)
	h.azureOK()
	again, _, _, err := h.svc.ReplaceVaultCredentials(h.ctx, admin, tgt.ID, off.Version, inventory.VaultCredentialInput{
		Auth: providers.AzureAuthClientSecret, TenantID: kvTenant, ClientID: kvClient, ClientSecret: secrets.NewPlaintext([]byte(fakekv.NewClientSecret()))})
	require.NoError(t, err)
	assert.Equal(t, inventory.StatusDisabled, again.Status)
}

func TestReplaceVaultCredentialsIsRefusedInLock(t *testing.T) {
	h := newHarness(t, withAzure())
	h.azureOK()
	admin := h.user("ada", rbac.Admin, "")
	tgt := h.newVault(admin, "Prod", "https://prod.vault.azure.net")
	h.clock.Advance(31 * 24 * time.Hour)
	require.NoError(t, h.lic.Tick(h.ctx))
	_, _, _, err := h.svc.ReplaceVaultCredentials(h.ctx, admin, tgt.ID, tgt.Version, inventory.VaultCredentialInput{Auth: providers.AzureAuthManagedIdentity})
	require.ErrorIs(t, err, license.ErrLocked)
	assert.Equal(t, 1, h.vaultCredentials())
}

func TestTheDatabaseRefusalsAreClosedErrors(t *testing.T) {
	h := newHarness(t, withAzure())
	h.azureOK()
	admin := h.user("ada", rbac.Admin, "")
	a := h.newVault(admin, "A", "https://a-vault.vault.azure.net")
	b := h.newVault(admin, "B", "https://b-vault.vault.azure.net")
	web := h.add(admin, "web", "web.example.com")
	pk, err := h.svc.PlatformKey(h.ctx)
	require.NoError(t, err)
	var bCred uuid.UUID
	require.NoError(t, h.db.Owner.QueryRow(h.ctx, "SELECT credential_id FROM targets WHERE id = $1", b.ID).Scan(&bCred))

	// Z1006: a vault moved to the platform key, or to another vault's credential.
	for _, cred := range []uuid.UUID{pk.ID, bCred} {
		err := h.svc.MoveVaultCredentialTo(h.ctx, a.ID, cred, a.Version)
		require.ErrorIs(t, err, inventory.ErrCredentialNotTheTargets)
		assert.NotContains(t, err.Error(), "Z1006")
		assert.NotContains(t, err.Error(), "SQLSTATE")
	}
	// Z1005: the application changing the credential of a server.
	err = h.svc.MoveVaultCredentialTo(h.ctx, web.ID, pk.ID, web.Version)
	require.ErrorIs(t, err, inventory.ErrNotAVault)
	assert.NotContains(t, err.Error(), "Z1005")
	// Z1006 on insert: a vault row that uses the platform key.
	err = h.svc.InsertVaultRowWith(h.ctx, pk.ID)
	require.ErrorIs(t, err, inventory.ErrCredentialNotTheTargets)
	cur, err := h.svc.GetTarget(h.ctx, a.ID)
	require.NoError(t, err)
	assert.Equal(t, a, cur, "nothing changed")
}

func TestVaultPollIntervalAndDeletion(t *testing.T) {
	h := newHarness(t, withAzureAndNginx())
	h.azureOK()
	admin := h.user("ada", rbac.Admin, "")
	tgt := h.newVault(admin, "Prod", "https://prod.vault.azure.net")
	web := nginxTarget(t, h, admin, "web-01")

	for _, ok := range []int{5, 1440} {
		cur, err := h.svc.GetTarget(h.ctx, tgt.ID)
		require.NoError(t, err)
		m := ok
		got, err := h.svc.UpdateTarget(h.ctx, admin, tgt.ID, cur.Version, inventory.TargetPatch{PollIntervalMinutes: &m})
		require.NoError(t, err)
		assert.Equal(t, time.Duration(ok)*time.Minute, got.Vault.PollInterval)
		assert.Equal(t, got.Vault.PollInterval, got.DiscoveryInterval)
	}
	assert.Equal(t, 1440*60, h.count("SELECT discovery_interval_seconds FROM targets WHERE id = $1", tgt.ID))
	assert.Equal(t, "poll_interval", h.auditDetails("target.updated")[0]["fields"])
	cur, err := h.svc.GetTarget(h.ctx, tgt.ID)
	require.NoError(t, err)
	for _, bad := range []int{4, 1441, 0, -1} {
		m := bad
		_, err := h.svc.UpdateTarget(h.ctx, admin, tgt.ID, cur.Version, inventory.TargetPatch{PollIntervalMinutes: &m})
		var verrs validate.Errors
		require.ErrorAs(t, err, &verrs, bad)
		assert.Equal(t, "poll_interval_minutes", verrs[0].Field)
		assert.Equal(t, validate.OutOfRange, verrs[0].Code)
	}
	// Each interval belongs to one kind of target.
	hours, minutes := 24, 30
	_, err = h.svc.UpdateTarget(h.ctx, admin, web.ID, web.Version, inventory.TargetPatch{PollIntervalMinutes: &minutes})
	var verrs validate.Errors
	require.ErrorAs(t, err, &verrs)
	assert.Equal(t, []string{"poll_interval_minutes"}, []string{verrs[0].Field})
	assert.Equal(t, validate.Pattern, verrs[0].Code)
	_, err = h.svc.UpdateTarget(h.ctx, admin, tgt.ID, cur.Version, inventory.TargetPatch{DiscoveryIntervalHours: &hours})
	require.ErrorAs(t, err, &verrs)
	assert.Equal(t, "discovery_interval_hours", verrs[0].Field)
	assert.Equal(t, validate.Pattern, verrs[0].Code)
	renamed := "Production vault"
	got, err := h.svc.UpdateTarget(h.ctx, admin, tgt.ID, cur.Version, inventory.TargetPatch{Name: &renamed})
	require.NoError(t, err)
	assert.Equal(t, renamed, got.Name)
	assert.Equal(t, 1440*time.Minute, got.Vault.PollInterval)

	// Bindings: a live one blocks the deletion.
	bindingID := h.seedBinding(t, tgt.ID, web.ID)
	err = h.svc.DeleteVault(h.ctx, admin, tgt.ID, false)
	require.ErrorIs(t, err, inventory.ErrVaultHasBindings)
	assert.Equal(t, 0, h.count("SELECT count(*) FROM targets WHERE deleted_at IS NOT NULL"))
	assert.Equal(t, 1, h.count("SELECT count(*) FROM bindings WHERE deleted_at IS NULL"))
	assert.Equal(t, 0, h.audits("target.deleted"))

	require.NoError(t, h.svc.DeleteVault(h.ctx, admin, tgt.ID, true))
	assert.Equal(t, 0, h.count("SELECT count(*) FROM bindings WHERE deleted_at IS NULL"))
	assert.Equal(t, 1, h.count("SELECT count(*) FROM bindings WHERE id = $1 AND deleted_at IS NOT NULL", bindingID), "soft-deleted, not removed")
	assert.Equal(t, 0, h.count("SELECT count(*) FROM certificate_locations WHERE binding_id IS NOT NULL"), "its locations are released")
	bd := h.auditDetails("binding.deleted")
	require.Len(t, bd, 1)
	assert.Equal(t, map[string]string{"binding_id": bindingID.String(), "vault_url": "https://prod.vault.azure.net", "reason": "vault_deleted", "location_count": "1"}, bd[0])
	td := h.auditDetails("target.deleted")
	require.Len(t, td, 1)
	assert.Equal(t, map[string]string{"name": "Production vault", "type": "azure_key_vault", "vault_url": "https://prod.vault.azure.net", "binding_count": "1"}, td[0])
	_, err = h.svc.GetTarget(h.ctx, tgt.ID)
	require.ErrorIs(t, err, inventory.ErrNotFound)
	assert.Equal(t, 1, h.vaultCount(), "the row is kept as history")
	n, err := inventory.Counter{}.CountTargets(h.ctx, h.db.Owner)
	require.NoError(t, err)
	assert.Equal(t, 1, n, "the license slot is free (only the Nginx server counts)")
	require.ErrorIs(t, h.svc.DeleteVault(h.ctx, admin, tgt.ID, true), inventory.ErrNotFound)

	// Without bindings a vault is deleted outright, and a server is not a vault.
	other := h.newVault(admin, "Other", "https://other.vault.azure.net")
	require.NoError(t, h.svc.DeleteVault(h.ctx, admin, other.ID, false))
	require.ErrorIs(t, h.svc.DeleteVault(h.ctx, admin, web.ID, false), inventory.ErrNotAVault)
	assert.Equal(t, 2, h.audits("target.deleted"))
}

// seedBinding gives the vault a certificate, binds it and attaches the Nginx server's first location.
func (h *harness) seedBinding(t *testing.T, vault, web uuid.UUID) uuid.UUID {
	t.Helper()
	ca := pki.NewCA("Bind", pki.ECDSA256, h.clock.Now())
	l := ca.Issue(pki.Opts{CommonName: "www.example.test"}, h.clock.Now())
	_, err := h.svc.Reconcile(h.ctx, web, providers.DiscoveryResult{WebServer: nginxOK,
		Certificates: []providers.DiscoveredCertificate{dc(cl("/etc/nginx/ssl/www.crt", "/etc/nginx/ssl/www.key"), l)}})
	require.NoError(t, err)
	loc := byPath(t, h, web, false)["/etc/nginx/ssl/www.crt"]
	cert, binding := uuid.Must(uuid.NewV7()), uuid.Must(uuid.NewV7())
	_, err = h.db.Owner.Exec(h.ctx, `INSERT INTO kv_certificates (id, target_id, name, listed_thumbprint, enabled, first_seen_at, last_seen_at)
VALUES ($1, $2, 'web-cert', repeat('a', 40), true, $3, $3)`, cert, vault, h.clock.Now())
	require.NoError(t, err)
	_, err = h.db.Owner.Exec(h.ctx, "INSERT INTO bindings (id, kv_certificate_id, kv_target_id, created_at) VALUES ($1, $2, $3, $4)", binding, cert, vault, h.clock.Now())
	require.NoError(t, err)
	_, err = h.db.Owner.Exec(h.ctx, "UPDATE certificate_locations SET binding_id = $2 WHERE id = $1", loc.ID, binding)
	require.NoError(t, err)
	return binding
}

func TestVaultJobsAndScheduling(t *testing.T) {
	h := newHarness(t, withAzure())
	h.azureOK()
	admin := h.user("ada", rbac.Admin, "")
	vault := h.newVault(admin, "Prod", "https://prod.vault.azure.net")
	web := h.add(admin, "web", "web.example.com")
	h.pinnedKey(web.ID)
	_, err := h.db.Owner.Exec(h.ctx, "UPDATE targets SET status = 'ok' WHERE id = $1", web.ID)
	require.NoError(t, err)
	before := len(h.jobs.requests())

	jobID, err := h.svc.RequestTest(h.ctx, admin, vault.ID)
	require.NoError(t, err)
	assert.NotEqual(t, uuid.Nil, jobID)
	jobID, err = h.svc.RequestDiscovery(h.ctx, admin, vault.ID)
	require.NoError(t, err)
	assert.NotEqual(t, uuid.Nil, jobID)
	reqs := h.jobs.requests()[before:]
	require.Len(t, reqs, 2)
	assert.Equal(t, inventory.JobRequest{Type: inventory.JobKVTest, TargetID: vault.ID, Payload: map[string]string{}, Kind: "user",
		CreatedBy: admin.UserID, CreatedByRole: "admin", DedupeKey: "kv.test_connection:" + vault.ID.String()}, reqs[0])
	assert.Equal(t, inventory.JobRequest{Type: inventory.JobKVPoll, TargetID: vault.ID, Payload: map[string]string{}, Kind: "user",
		CreatedBy: admin.UserID, CreatedByRole: "admin", DedupeKey: "kv.poll:" + vault.ID.String()}, reqs[1])
	// A server is unchanged.
	_, err = h.svc.RequestTest(h.ctx, admin, web.ID)
	require.NoError(t, err)
	_, err = h.svc.RequestDiscovery(h.ctx, admin, web.ID)
	require.NoError(t, err)
	reqs = h.jobs.requests()[before+2:]
	assert.Equal(t, inventory.JobTestConnection, reqs[0].Type)
	assert.Equal(t, inventory.JobDiscover, reqs[1].Type)

	// A disabled vault runs nothing.
	_, err = h.db.Owner.Exec(h.ctx, "UPDATE targets SET status = 'disabled' WHERE id = $1", vault.ID)
	require.NoError(t, err)
	_, err = h.svc.RequestTest(h.ctx, admin, vault.ID)
	require.ErrorIs(t, err, inventory.ErrTargetNotReady)
	_, err = h.svc.RequestDiscovery(h.ctx, admin, vault.ID)
	require.ErrorIs(t, err, inventory.ErrTargetNotReady)
	_, err = h.db.Owner.Exec(h.ctx, "UPDATE targets SET status = 'ok' WHERE id = $1", vault.ID)
	require.NoError(t, err)

	// The SSH scheduler never queues a scan or a connection test for a vault.
	h.clock.Advance(25 * time.Hour)
	n := len(h.jobs.requests())
	scheduled, err := h.svc.ScheduleDiscovery(h.ctx)
	require.NoError(t, err)
	assert.Equal(t, 1, scheduled, "only the server is due")
	for _, r := range h.jobs.requests()[n:] {
		assert.NotEqual(t, vault.ID, r.TargetID)
		assert.Equal(t, inventory.JobDiscover, r.Type)
	}
	_, err = h.db.Owner.Exec(h.ctx, "UPDATE targets SET status = 'unreachable' WHERE id = $1", vault.ID)
	require.NoError(t, err)
	h.clock.Advance(25 * time.Hour)
	n = len(h.jobs.requests())
	_, err = h.svc.ScheduleDiscovery(h.ctx)
	require.NoError(t, err)
	for _, r := range h.jobs.requests()[n:] {
		assert.NotEqual(t, vault.ID, r.TargetID, "an unreachable vault is not tested by the SSH scheduler either")
	}

	// TargetRef addresses a vault by its URL.
	ref, tt, err := h.svc.TargetRef(h.ctx, vault.ID)
	require.NoError(t, err)
	assert.Equal(t, providers.KindAzureKV, ref.Kind)
	assert.Equal(t, providers.TargetConfig{"vault_url": "https://prod.vault.azure.net"}, ref.Config)
	assert.Equal(t, vault.ID, tt.ID)
}

func TestRequestAccessCheckWithASecretRead(t *testing.T) {
	h := newHarness(t, withAzure())
	h.azureOK()
	admin := h.user("ada", rbac.Admin, "")
	vault := h.newVault(admin, "Prod", "https://prod.vault.azure.net")
	other := h.newVault(admin, "Other", "https://other.vault.azure.net")
	web := h.add(admin, "web", "web.example.com")
	cert := func(owner uuid.UUID, name string, exportable *bool, version string) uuid.UUID {
		id := uuid.Must(uuid.NewV7())
		_, err := h.db.Owner.Exec(h.ctx, `INSERT INTO kv_certificates (id, target_id, name, listed_thumbprint, enabled, exportable, current_version, first_seen_at, last_seen_at)
VALUES ($1, $2, $3, repeat('a', 40), true, $4, $5, $6, $6)`, id, owner, name, exportable, version, h.clock.Now())
		require.NoError(t, err)
		return id
	}
	yes, no := true, false
	version := strings.Repeat("ab", 16)
	good := cert(vault.ID, "web-cert", &yes, version)
	closedOne := cert(vault.ID, "closed", &no, version)
	unknownPolicy := cert(vault.ID, "unknown", nil, version)
	noVersion := cert(vault.ID, "fresh", &yes, "")
	foreign := cert(other.ID, "foreign", &yes, version)
	gone := cert(vault.ID, "gone", &yes, version)
	_, err := h.db.Owner.Exec(h.ctx, "UPDATE kv_certificates SET missing_since = $2 WHERE id = $1", gone, h.clock.Now())
	require.NoError(t, err)

	n := len(h.jobs.requests())
	jobID, err := h.svc.RequestAccessCheck(h.ctx, admin, vault.ID, good)
	require.NoError(t, err)
	assert.NotEqual(t, uuid.Nil, jobID)
	req := h.jobs.requests()[n]
	assert.Equal(t, inventory.JobKVTest, req.Type)
	assert.Equal(t, vault.ID, req.TargetID)
	assert.Equal(t, map[string]string{"read_secret_of": good.String()}, req.Payload)
	assert.Equal(t, "kv.test_connection:"+vault.ID.String()+":"+good.String(), req.DedupeKey, "it never collides with a plain check's payload")

	_, err = h.svc.RequestAccessCheck(h.ctx, admin, vault.ID, uuid.Nil)
	require.NoError(t, err)
	assert.Empty(t, h.jobs.requests()[n+1].Payload)
	assert.Equal(t, "kv.test_connection:"+vault.ID.String(), h.jobs.requests()[n+1].DedupeKey)

	for _, tc := range []struct {
		name string
		id   uuid.UUID
		want error
	}{
		{"not exportable", closedOne, inventory.ErrNotExportable},
		{"policy never read", unknownPolicy, inventory.ErrNotExportable},
		{"no current version", noVersion, inventory.ErrVersionNotDeployable},
		{"another vault's certificate", foreign, inventory.ErrNotFound},
		{"unknown", uuid.New(), inventory.ErrNotFound},
		{"removed from the vault", gone, inventory.ErrNotFound},
	} {
		_, err := h.svc.RequestAccessCheck(h.ctx, admin, vault.ID, tc.id)
		require.ErrorIs(t, err, tc.want, tc.name)
	}
	assert.Len(t, h.jobs.requests(), n+2, "refusals queue nothing")
	_, err = h.svc.RequestAccessCheck(h.ctx, admin, web.ID, uuid.Nil)
	require.ErrorIs(t, err, inventory.ErrNotAVault)
	_, err = h.svc.RequestAccessCheck(h.ctx, admin, uuid.New(), uuid.Nil)
	require.ErrorIs(t, err, inventory.ErrNotFound)
	_, err = h.db.Owner.Exec(h.ctx, "UPDATE targets SET status = 'disabled' WHERE id = $1", vault.ID)
	require.NoError(t, err)
	_, err = h.svc.RequestAccessCheck(h.ctx, admin, vault.ID, good)
	require.ErrorIs(t, err, inventory.ErrTargetNotReady)
}

func TestRecordKVConnection(t *testing.T) {
	h := newHarness(t, withAzure())
	h.azureOK()
	admin := h.user("ada", rbac.Admin, "")
	tgt := h.newVault(admin, "Prod", "https://prod.vault.azure.net")
	h.clock.Advance(time.Minute)

	checks := okChecks()
	checks[3] = providers.AzureCheck{Name: providers.AzureCheckListSecrets, Result: providers.AzureResultForbidden, Reason: "azure.forbidden", Role: providers.RoleKeyVaultReader}
	require.NoError(t, h.svc.RecordKVConnection(h.ctx, tgt.ID, azureReport(checks)))
	got, err := h.svc.GetTarget(h.ctx, tgt.ID)
	require.NoError(t, err)
	assert.Equal(t, inventory.StatusDegraded, got.Status)
	assert.Equal(t, "azure.forbidden", got.LastErrorCode)
	assert.Equal(t, providers.AzureResultForbidden, got.Vault.Access.Checks[3].Result)
	assert.Equal(t, h.clock.Now(), *got.LastSuccessAt)
	assert.Equal(t, []map[string]string{{"from_status": "ok", "to_status": "degraded", "reason": "azure.forbidden"}}, h.auditDetails("target.status_changed"))

	require.NoError(t, h.svc.RecordKVConnection(h.ctx, tgt.ID, azureReport(checks)))
	assert.Equal(t, 1, h.audits("target.status_changed"), "no audit row without a change")

	require.NoError(t, h.svc.RecordKVConnection(h.ctx, tgt.ID, azureReport(okChecks())))
	got, err = h.svc.GetTarget(h.ctx, tgt.ID)
	require.NoError(t, err)
	assert.Equal(t, inventory.StatusOK, got.Status)
	assert.Empty(t, got.LastErrorCode)
	assert.Equal(t, "kv_check_ok", h.auditDetails("target.status_changed")[1]["reason"])

	// Other facts survive; a disabled vault stays disabled; a report without a check is refused.
	_, err = h.db.Owner.Exec(h.ctx, "UPDATE targets SET status = 'disabled', facts = facts || '{\"kv_auth_failures\": 2}' WHERE id = $1", tgt.ID)
	require.NoError(t, err)
	require.NoError(t, h.svc.RecordKVConnection(h.ctx, tgt.ID, azureReport(checks)))
	got, err = h.svc.GetTarget(h.ctx, tgt.ID)
	require.NoError(t, err)
	assert.Equal(t, inventory.StatusDisabled, got.Status)
	assert.Equal(t, 2, got.Facts.KVAuthFailures)
	require.Error(t, h.svc.RecordKVConnection(h.ctx, tgt.ID, providers.ConnectionReport{}))
	require.ErrorIs(t, h.svc.RecordKVConnection(h.ctx, uuid.New(), azureReport(checks)), inventory.ErrNotFound)
	web := h.add(admin, "web", "web.example.com")
	require.ErrorIs(t, h.svc.RecordKVConnection(h.ctx, web.ID, azureReport(checks)), inventory.ErrNotAVault)
}

func TestAVaultIsNeverAServerAndTheOtherWayRound(t *testing.T) {
	h := newHarness(t, withAzure())
	h.azureOK()
	admin := h.user("ada", rbac.Admin, "")
	_, _, err := h.svc.CreateTarget(h.ctx, admin, inventory.NewTarget{Name: "v", Type: inventory.TypeAzureKeyVault, Host: "prod.vault.azure.net"})
	var verrs validate.Errors
	require.ErrorAs(t, err, &verrs)
	assert.Equal(t, "type", verrs[0].Field)
	assert.Equal(t, 0, h.count("SELECT count(*) FROM targets"))

	vault := h.newVault(admin, "Prod", "https://prod.vault.azure.net")
	web := h.add(admin, "web", "web.example.com")
	require.ErrorIs(t, h.svc.DeleteTarget(h.ctx, admin, vault.ID), inventory.ErrNotAServer)
	require.ErrorIs(t, h.svc.DeleteVault(h.ctx, admin, web.ID, false), inventory.ErrNotAVault)
	assert.Equal(t, 2, len(mustList(t, h)))
	assert.Nil(t, mustList(t, h)[1].Vault, "a server has no vault half")
	assert.NotNil(t, mustList(t, h)[0].Vault)

	// The platform key's source is a server's: a vault never signs in with it, and the database says so.
	pk, err := h.svc.PlatformKey(h.ctx)
	require.NoError(t, err)
	_, err = h.db.App.Exec(h.ctx, "UPDATE targets SET credential_id = $2 WHERE id = $1", vault.ID, pk.ID)
	require.Error(t, err)
	_, err = h.db.App.Exec(h.ctx, "UPDATE targets SET credential_id = credential_id WHERE id = $1", web.ID)
	require.Error(t, err)
	_, err = h.db.Owner.Exec(h.ctx, "UPDATE targets SET credential_id = $2 WHERE id = $1", vault.ID, pk.ID)
	require.Error(t, err)
}

func TestVaultJobTypesAreAcceptedByTheQueue(t *testing.T) {
	h := newHarness(t, withAzure())
	h.azureOK()
	q := jobs.NewQueue(jobs.QueueConfig{Pool: h.db.App, Keyring: h.keyring, Audit: h.audit, Clock: h.clock, Gate: h.lic})
	h.jobs.next = q
	admin := h.user("ada", rbac.Admin, "")
	tgt := h.newVault(admin, "Prod", "https://prod.vault.azure.net")
	assert.Equal(t, 1, h.count("SELECT count(*) FROM jobs WHERE type = 'kv.poll' AND target_id = $1", tgt.ID))
	_, err := h.svc.RequestTest(h.ctx, admin, tgt.ID)
	require.NoError(t, err)
	_, err = h.svc.RequestDiscovery(h.ctx, admin, tgt.ID)
	require.NoError(t, err)
	assert.Equal(t, 1, h.count("SELECT count(*) FROM jobs WHERE type = 'kv.test_connection'"))
	assert.Equal(t, 1, h.count("SELECT count(*) FROM jobs WHERE type = 'kv.poll'"), "a manual poll coalesces with the one that is queued")
	require.NoError(t, pgxTx(h, func(tx pgx.Tx) error {
		_, err := q.EnqueueTx(h.ctx, tx, inventory.JobRequest{Type: inventory.JobKVImport, TargetID: tgt.ID, Payload: map[string]string{}, Kind: "user",
			CreatedBy: admin.UserID, CreatedByRole: "admin", DedupeKey: "kv.import:x"})
		return err
	}))
	for _, typ := range []string{jobs.KVTestConnection.Name, jobs.KVPoll.Name, jobs.KVImport.Name} {
		assert.NotEmpty(t, typ)
	}
	assert.Equal(t, license.ClassChange, jobs.KVImport.Class, "an import changes the vault: refused in lock")
	assert.Equal(t, license.ClassReadOnly, jobs.KVPoll.Class)
	assert.Equal(t, license.ClassReadOnly, jobs.KVTestConnection.Class)
}

func pgxTx(h *harness, fn func(tx pgx.Tx) error) error {
	tx, err := h.db.App.Begin(h.ctx)
	if err != nil {
		return err
	}
	if err := fn(tx); err != nil {
		_ = tx.Rollback(h.ctx)
		return err
	}
	return tx.Commit(h.ctx)
}

func TestReplaceVaultCredentialsClearsCertificateInput(t *testing.T) {
	h := newHarness(t, withAzure())
	h.azureOK()
	admin := h.user("ada", rbac.Admin, "")
	tgt := h.newVault(admin, "Prod", "https://prod.vault.azure.net")
	leaf := pki.SelfSigned("sp.example.test", pki.RSA2048, h.clock.Now())
	key := append([]byte(nil), leaf.KeyPEM...)
	_, _, _, err := h.svc.ReplaceVaultCredentials(h.ctx, admin, tgt.ID, tgt.Version, inventory.VaultCredentialInput{Auth: providers.AzureAuthCertificate,
		TenantID: kvTenant, ClientID: kvClient, Certificate: certs.Upload{CertificatePEM: leaf.CertPEM, PrivateKeyPEM: key}})
	require.NoError(t, err)
	assert.Equal(t, make([]byte, len(key)), key, "the key PEM is zeroed after a success")
	cur, err := h.svc.GetTarget(h.ctx, tgt.ID)
	require.NoError(t, err)
	h.failWith("azure.auth_failed")
	key = append([]byte(nil), leaf.KeyPEM...)
	_, _, _, err = h.svc.ReplaceVaultCredentials(h.ctx, admin, tgt.ID, cur.Version, inventory.VaultCredentialInput{Auth: providers.AzureAuthCertificate,
		TenantID: kvTenant, ClientID: kvClient, Certificate: certs.Upload{CertificatePEM: leaf.CertPEM, PrivateKeyPEM: key}})
	require.Error(t, err)
	assert.Equal(t, make([]byte, len(key)), key, "and after a refusal")
}

// I2: the SSH record paths never accept a vault.
func TestSSHPathsRefuseAVault(t *testing.T) {
	h := newHarness(t, withAzure())
	h.azureOK()
	admin := h.user("ada", rbac.Admin, "")
	vault := h.newVault(admin, "Prod", "https://prod.vault.azure.net")
	hk := ed25519HostKey(t)
	calls := map[string]func() error{
		"RecordConnectionOK":      func() error { return h.svc.RecordConnectionOK(h.ctx, vault.ID, providers.ConnectionReport{}) },
		"RecordConnectionFailure": func() error { return h.svc.RecordConnectionFailure(h.ctx, vault.ID, "ssh.unreachable") },
		"HostKeyStore.Observed":   func() error { return h.svc.HostKeyStore().Observed(h.ctx, vault.ID, hk, false) },
		"Reconcile":               func() error { _, err := h.svc.Reconcile(h.ctx, vault.ID, providers.DiscoveryResult{}); return err },
		"ConfirmHostKey": func() error {
			_, err := h.svc.ConfirmHostKey(h.ctx, admin, vault.ID, uuid.New(), hk.Fingerprint)
			return err
		},
		"RepinHostKey": func() error {
			_, err := h.svc.RepinHostKey(h.ctx, admin, vault.ID, uuid.New(), hk.Fingerprint, "The server was rebuilt on purpose")
			return err
		},
	}
	for name, call := range calls {
		before, err := h.svc.GetTarget(h.ctx, vault.ID)
		require.NoError(t, err)
		require.ErrorIs(t, call(), inventory.ErrNotAServer, name)
		after, err := h.svc.GetTarget(h.ctx, vault.ID)
		require.NoError(t, err)
		assert.Equal(t, before, after, name+": the vault row is unchanged")
	}
	assert.Equal(t, 0, h.count("SELECT count(*) FROM host_keys"))
	assert.Equal(t, 0, h.count("SELECT count(*) FROM audit_log WHERE action = 'target.status_changed'"))
}

// m1: an incomplete report never creates a vault.
func TestCreateVaultRefusesAnIncompleteReport(t *testing.T) {
	h := newHarness(t, withAzure())
	admin := h.user("ada", rbac.Admin, "")
	for name, checks := range map[string][]providers.AzureCheck{
		"only a sign-in row": {{Name: providers.AzureCheckSignIn, Result: providers.AzureResultOK}},
		"listing failed without a reason": {{Name: providers.AzureCheckSignIn, Result: providers.AzureResultOK},
			{Name: providers.AzureCheckListCertificates, Result: providers.AzureResultFailed}},
	} {
		h.script(func(c *fake.Config) { c.Report = azureReport(checks) })
		_, _, _, err := h.svc.CreateVault(h.ctx, admin, secretVault("v", "https://oops.vault.azure.net"))
		var pe *providers.Error
		require.ErrorAs(t, err, &pe, name)
		assert.Equal(t, "internal.unexpected", pe.Code, name)
		assert.Equal(t, 0, h.vaultCount(), name)
		assert.Equal(t, 0, h.vaultCredentials(), name)
	}
	assert.Equal(t, 2, h.audits("vault.add_refused"))
}

// m2, m7: a provider that fails with foreign text or panics gives a closed error and an audit row.
func TestPreflightFailuresAreClosedErrors(t *testing.T) {
	h := newHarness(t, withAzure())
	h.azureOK()
	admin := h.user("ada", rbac.Admin, "")
	tgt := h.newVault(admin, "Prod", "https://prod.vault.azure.net")
	canary := "AADSTS70011 CANARY-" + fakekv.NewClientSecret()
	render := func(err error) string { return fmt.Sprintf("%v|%+v|%#v|%s", err, err, err, err.Error()) }
	for _, replace := range []bool{false, true} {
		h.script(func(c *fake.Config) { c.Report, c.TestErr = providers.ConnectionReport{}, errors.New(canary) })
		var err error
		if replace {
			_, _, _, err = h.svc.ReplaceVaultCredentials(h.ctx, admin, tgt.ID, tgt.Version, inventory.VaultCredentialInput{Auth: providers.AzureAuthManagedIdentity})
		} else {
			_, _, _, err = h.svc.CreateVault(h.ctx, admin, secretVault("v", "https://oops.vault.azure.net"))
		}
		var pe *providers.Error
		require.ErrorAs(t, err, &pe, replace)
		assert.Equal(t, "internal.unexpected", pe.Code)
		assert.NotContains(t, render(err), "CANARY")
		assert.Nil(t, errors.Unwrap(err), "no cause is reachable")
	}
	assert.NotContains(t, h.dump(t), "CANARY")
	assert.NotContains(t, h.logs.String(), "CANARY")

	// A panic in the provider is recovered, audited and logged by type only.
	panicking := &panicAzure{Provider: fake.New(providers.KindAzureKV, azureCaps...), on: true}
	h2 := newHarness(t, withAzureProvider(panicking))
	admin2 := h2.user("ada", rbac.Admin, "")
	_, _, _, err := h2.svc.CreateVault(h2.ctx, admin2, secretVault("v", "https://oops.vault.azure.net"))
	var pe *providers.Error
	require.ErrorAs(t, err, &pe)
	assert.Equal(t, "internal.unexpected", pe.Code)
	assert.NotContains(t, render(err), "CANARY")
	assert.Equal(t, 0, h2.vaultCount())
	assert.Equal(t, 0, h2.vaultCredentials())
	require.Len(t, h2.auditDetails("vault.add_refused"), 1)
	assert.Equal(t, "internal.unexpected", h2.auditDetails("vault.add_refused")[0]["reason"])
	assert.NotContains(t, h2.logs.String(), "CANARY")
	// The same for a replacement.
	h2.azure = panicking.Provider
	h2.azureOK()
	panicking.on = false
	good := h2.newVault(admin2, "Good", "https://good.vault.azure.net")
	panicking.on = true
	_, _, _, err = h2.svc.ReplaceVaultCredentials(h2.ctx, admin2, good.ID, good.Version, inventory.VaultCredentialInput{Auth: providers.AzureAuthManagedIdentity})
	require.ErrorAs(t, err, &pe)
	assert.Equal(t, "internal.unexpected", pe.Code)
	require.Len(t, h2.auditDetails("vault.credentials_refused"), 1)
	cur, err := h2.svc.GetTarget(h2.ctx, good.ID)
	require.NoError(t, err)
	assert.Equal(t, good, cur)
}

// panicAzure panics in Open while on.
type panicAzure struct {
	*fake.Provider
	on bool
}

func (p *panicAzure) Open(ctx context.Context, t providers.TargetRef, c providers.CredentialSource, env providers.Env) (providers.Session, error) {
	if p.on {
		panic("AADSTS CANARY panic text")
	}
	return p.Provider.Open(ctx, t, c, env)
}

// m3: last_success_at means the vault answered a listing.
func TestLastSuccessIsSetOnlyByAnAnsweredListing(t *testing.T) {
	h := newHarness(t, withAzure())
	admin := h.user("ada", rbac.Admin, "")
	checks := okChecks()
	checks[1] = providers.AzureCheck{Name: providers.AzureCheckListCertificates, Result: providers.AzureResultForbidden, Reason: "azure.forbidden", Role: providers.RoleKeyVaultReader}
	h.script(func(c *fake.Config) { c.Report = azureReport(checks) })
	deg, _, _, err := h.svc.CreateVault(h.ctx, admin, secretVault("Deg", "https://deg-vault.vault.azure.net"))
	require.NoError(t, err)
	assert.Equal(t, inventory.StatusDegraded, deg.Status)
	assert.Nil(t, deg.LastSuccessAt, "a vault that never listed has no last success")
	h.script(func(c *fake.Config) {
		c.Report, c.TestErr = providers.ConnectionReport{}, providers.NewError("azure.firewall", false, nil, nil)
	})
	fw, _, _, err := h.svc.CreateVault(h.ctx, admin, secretVault("Fw", "https://fw-vault.vault.azure.net"))
	require.NoError(t, err)
	assert.Nil(t, fw.LastSuccessAt)

	// A listing that works sets it; a replacement that ends degraded leaves it as it was.
	h.azureOK()
	h.clock.Advance(time.Minute)
	good := h.newVault(admin, "Good", "https://good-vault.vault.azure.net")
	require.NotNil(t, good.LastSuccessAt)
	first := *good.LastSuccessAt
	h.clock.Advance(time.Hour)
	h.script(func(c *fake.Config) { c.Report = azureReport(checks) })
	rep, _, _, err := h.svc.ReplaceVaultCredentials(h.ctx, admin, good.ID, good.Version, inventory.VaultCredentialInput{Auth: providers.AzureAuthManagedIdentity})
	require.NoError(t, err)
	assert.Equal(t, inventory.StatusDegraded, rep.Status)
	assert.Equal(t, first, *rep.LastSuccessAt)
	// RecordKVConnection follows the same rule.
	h.clock.Advance(time.Hour)
	require.NoError(t, h.svc.RecordKVConnection(h.ctx, good.ID, azureReport(checks)))
	again, err := h.svc.GetTarget(h.ctx, good.ID)
	require.NoError(t, err)
	assert.Equal(t, first, *again.LastSuccessAt)
	require.NoError(t, h.svc.RecordKVConnection(h.ctx, good.ID, azureReport(okChecks())))
	again, err = h.svc.GetTarget(h.ctx, good.ID)
	require.NoError(t, err)
	assert.Equal(t, h.clock.Now(), *again.LastSuccessAt)
}

// m5: the pre-flight names the vault; nothing per-target stays in the provider after a refusal.
func TestPreflightNamesTheVaultAndForgetsIt(t *testing.T) {
	spy := newSpyAzure()
	h := newHarness(t, withAzureProvider(spy))
	h.azure = spy.Provider
	admin := h.user("ada", rbac.Admin, "")
	h.failWith("azure.auth_failed")
	_, _, _, err := h.svc.CreateVault(h.ctx, admin, secretVault("v", "https://oops.vault.azure.net"))
	require.Error(t, err)
	refs := spy.refIDs()
	require.Len(t, refs, 1)
	assert.NotEqual(t, uuid.Nil, refs[0], "a new vault is opened under the id it would get")
	assert.Equal(t, refs, spy.forgottenIDs(), "a refused add leaves nothing per-target in the provider")

	// N1: a failure AFTER a successful pre-flight (here the queue refuses the first poll, so the
	// transaction rolls back) leaves no target, so the opened id is forgotten too.
	h.azureOK()
	h.jobs.fail = errors.New("queue is down")
	_, _, _, err = h.svc.CreateVault(h.ctx, admin, secretVault("w", "https://late.vault.azure.net"))
	require.Error(t, err)
	refs = spy.refIDs()
	require.Len(t, refs, 2)
	assert.Contains(t, spy.forgottenIDs(), refs[1], "the id of an add that failed after the pre-flight is forgotten")
	assert.Zero(t, h.count("SELECT count(*) FROM targets WHERE type = 'azure_key_vault'"))

	// A committed add keeps its id: the vault exists and uses the limiter claim.
	tgt := h.newVault(admin, "Prod", "https://prod.vault.azure.net")
	assert.NotContains(t, spy.forgottenIDs(), tgt.ID)

	// N2: neither a refused nor a successful replacement drops the live vault's limiter claim (the
	// credential is read at every Open, nothing is cached per credential).
	h.failWith("azure.auth_failed")
	_, _, _, err = h.svc.ReplaceVaultCredentials(h.ctx, admin, tgt.ID, tgt.Version, inventory.VaultCredentialInput{Auth: providers.AzureAuthManagedIdentity})
	require.Error(t, err)
	assert.NotContains(t, spy.forgottenIDs(), tgt.ID, "a refused replacement changes nothing and forgets nothing")
	h.azureOK()
	_, _, _, err = h.svc.ReplaceVaultCredentials(h.ctx, admin, tgt.ID, tgt.Version, inventory.VaultCredentialInput{Auth: providers.AzureAuthManagedIdentity})
	require.NoError(t, err)
	refs = spy.refIDs()
	assert.Equal(t, tgt.ID, refs[len(refs)-1], "a replacement is opened under the vault's own id")
	assert.NotContains(t, spy.forgottenIDs(), tgt.ID, "the new credential is read at the next Open: no forget needed")
}

// m6: a disabled vault is not polled by a replacement.
func TestReplaceOnADisabledVaultQueuesNoPoll(t *testing.T) {
	h := newHarness(t, withAzure())
	h.azureOK()
	admin := h.user("ada", rbac.Admin, "")
	tgt := h.newVault(admin, "Prod", "https://prod.vault.azure.net")
	_, err := h.db.Owner.Exec(h.ctx, "UPDATE targets SET status = 'disabled' WHERE id = $1", tgt.ID)
	require.NoError(t, err)
	cur, err := h.svc.GetTarget(h.ctx, tgt.ID)
	require.NoError(t, err)
	n := len(h.jobs.requests())
	got, _, jobID, err := h.svc.ReplaceVaultCredentials(h.ctx, admin, tgt.ID, cur.Version, inventory.VaultCredentialInput{Auth: providers.AzureAuthManagedIdentity})
	require.NoError(t, err)
	assert.Equal(t, inventory.StatusDisabled, got.Status)
	assert.Equal(t, uuid.Nil, jobID)
	assert.Len(t, h.jobs.requests(), n)
}

// A duplicate is found before the pre-flight: no sign-in happens for it.
func TestDuplicateVaultIsFoundBeforeThePreflight(t *testing.T) {
	h := newHarness(t, withAzure())
	h.azureOK()
	admin := h.user("ada", rbac.Admin, "")
	h.newVault(admin, "Prod", "https://prod.vault.azure.net")
	opens := h.azure.Count("Open")
	for _, in := range []inventory.NewVault{secretVault("Other", "PROD"), secretVault("prod", "https://another.vault.azure.net")} {
		_, _, _, err := h.svc.CreateVault(h.ctx, admin, in)
		require.ErrorIs(t, err, inventory.ErrDuplicateTarget)
	}
	assert.Equal(t, opens, h.azure.Count("Open"), "no call to Azure for a vault that is already there")
}
