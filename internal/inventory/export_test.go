package inventory

import (
	"context"
	"crypto/x509"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"alice/internal/acme"
	"alice/internal/certs"
	"alice/internal/platform/db"
	"alice/internal/providers"
	"alice/internal/secrets"
)

// AuditLicenseDenial exposes auditLicenseDenial to the integration tests.
func (s *Service) AuditLicenseDenial(ctx context.Context, a Actor, name string, cause error) {
	s.auditLicenseDenial(ctx, a, name, cause)
}

// ServersTextBound exposes the size bound of boundServers to the integration tests, which compare
// it with PostgreSQL's rendering.
func ServersTextBound(servers []providers.CertServer) int {
	total := 2
	for i, s := range servers {
		total += serverTextSize(s)
		if i > 0 {
			total += 2
		}
	}
	return total
}

// LoadKey exposes loadKey to the integration tests (the round trip of a sealed key and the leak
// test's markers of generated keys).
func (s *Service) LoadKey(ctx context.Context, id uuid.UUID) (secrets.Plaintext, error) {
	return s.loadKey(ctx, s.pool, id)
}

// HoldPFXSlots takes n PFX decode slots without waiting; ok is false (and nothing is held) when
// they are not all free. release gives them back.
func HoldPFXSlots(n int) (release func(), ok bool) {
	var held []func()
	release = func() {
		for _, r := range held {
			r()
		}
	}
	for range n {
		r, ok := acquirePFXSlot()
		if !ok {
			release()
			return func() {}, false
		}
		held = append(held, r)
	}
	return release, true
}

// ValidSNI exposes validSNI to the test that compares it with helperproto.ValidSNI.
func ValidSNI(s string) bool { return validSNI(s) }

// SetValidateUpload replaces the upload decoder (a panicking one in tests); restore puts it back.
func SetValidateUpload(f func(certs.Upload, time.Time, *x509.CertPool) (certs.Validated, error)) (restore func()) {
	old := validateUpload
	validateUpload = f
	return func() { validateUpload = old }
}

// SetPrepareHook installs a function that runs while a scan's certificate files are parsed
// (prepareScan); restore removes it.
func SetPrepareHook(f func()) (restore func()) {
	old := prepareHook
	prepareHook = f
	return func() { prepareHook = old }
}

// BoundParams exposes boundParams with the error params' allowlist to the test that measures
// PostgreSQL's rendering of the result.
func BoundParams(in map[string]string) map[string]string { return boundParams(in, errorParamKeys) }

// HoldCSRSlots takes every signing-request key generation slot; release gives them back.
func HoldCSRSlots() (release func()) {
	var held []func()
	for range maxCSRKeygens {
		if r, ok := acquireCSRSlot(); ok {
			held = append(held, r)
		}
	}
	return func() {
		for _, r := range held {
			r()
		}
	}
}

// SetMaxPendingCSRs changes the bound of open signing requests; restore puts it back.
func SetMaxPendingCSRs(n int) (restore func()) {
	old := maxPendingCSRs
	maxPendingCSRs = n
	return func() { maxPendingCSRs = old }
}

// MoveVaultCredentialTo exposes moveVaultCredential to the integration tests: it points a target's
// credential_id at any credential row, as a bug (or the owner role) could, to see how the
// database's refusal reaches the caller.
func (s *Service) MoveVaultCredentialTo(ctx context.Context, id, credential uuid.UUID, version int) error {
	return db.InTx(ctx, s.pool, func(tx pgx.Tx) error {
		return s.moveVaultCredential(ctx, tx, id, credential, StatusOK, "", &providers.AzureFacts{}, s.clock.Now().UTC(), version, false)
	})
}

// InsertVaultRowWith exposes insertTarget with a vault row that uses any credential row.
func (s *Service) InsertVaultRowWith(ctx context.Context, credential uuid.UUID) error {
	return db.InTx(ctx, s.pool, func(tx pgx.Tx) error {
		return s.insertTarget(ctx, tx, targetRow{ID: uuid.Must(uuid.NewV7()), Name: "forged", Type: TypeAzureKeyVault,
			Config:       targetConfig{Host: "forged.vault.azure.net", Port: 443, VaultURL: "https://forged.vault.azure.net"},
			CredentialID: credential, Status: StatusOK, IntervalSeconds: 900})
	})
}

// SetKVBatchSizes makes the batches of a stored poll small (tests); restore puts the old sizes back.
func SetKVBatchSizes(certs, keys, secrets int) (restore func()) {
	oc, ok, os := kvBatchCerts, kvBatchKeys, kvBatchSecrets
	kvBatchCerts, kvBatchKeys, kvBatchSecrets = certs, keys, secrets
	return func() { kvBatchCerts, kvBatchKeys, kvBatchSecrets = oc, ok, os }
}

// SetKVBatchHook sets the function that runs after each committed batch of a stored poll.
func SetKVBatchHook(f func(kind string, batch int)) (restore func()) {
	old := kvBatchHook
	kvBatchHook = f
	return func() { kvBatchHook = old }
}

// MaxPFXDecodes is how many PFX files the process decodes at once.
func MaxPFXDecodes() int { return maxPFXDecodes }

// SetKVMaterialHook installs the observer of KVDeployMaterial's buffers and returns its restore.
func SetKVMaterialHook(f func(stage string, b []byte)) (restore func()) {
	old := kvMaterialHook
	kvMaterialHook = f
	return func() { kvMaterialHook = old }
}

// SetAutoDeployBatch lowers the number of deployments one planner run creates.
func SetAutoDeployBatch(n int) (restore func()) {
	old := autoDeployBatch
	autoDeployBatch = n
	return func() { autoDeployBatch = old }
}

// SetImportMaterialHook installs the observer of ImportMaterial's buffers and returns its restore.
func SetImportMaterialHook(f func(stage string, b []byte)) (restore func()) {
	old := importMaterialHook
	importMaterialHook = f
	return func() { importMaterialHook = old }
}

// SetAutoDeployPage sets how many candidate bindings the planner reads per page.
func SetAutoDeployPage(n int) (restore func()) {
	old := autoDeployBindings
	autoDeployBindings = n
	return func() { autoDeployBindings = old }
}

// SetPlanMailLimit sets how many individual mails the planner sends per vault and kind in one run.
func SetPlanMailLimit(n int) (restore func()) {
	old := planMailLimit
	planMailLimit = n
	return func() { planMailLimit = old }
}

// SetPlanPageHook installs the hook that runs after the planner read a page of candidates.
func SetPlanPageHook(f func()) (restore func()) {
	old := planPageHook
	planPageHook = f
	return func() { planPageHook = old }
}

// SetSweepBatch bounds the imports one SweepImports call changes.
func SetSweepBatch(n int) (restore func()) {
	old := importSweepBatch
	importSweepBatch = n
	return func() { importSweepBatch = old }
}

// SetPlanInsertHook installs the hook that runs before the planner inserts a website's deployment.
func SetPlanInsertHook(f func(location uuid.UUID)) (restore func()) {
	old := planInsertHook
	planInsertHook = f
	return func() { planInsertHook = old }
}

// CredentialLocation exposes credentialLocation to the integration tests, which seal a damaged
// platform key at the place the real one lives.
func CredentialLocation(id uuid.UUID) secrets.Location { return credentialLocation(id) }

// SetACMERolloverSeam replaces the CA's answer to an account key change (the integration tests' crash simulation).
func (s *Service) SetACMERolloverSeam(f func(acme.RolloverOutcome) acme.RolloverOutcome) {
	s.rolloverSeam = f
}

// OpenACMEEAB exposes openEAB to the integration tests (the sealed EAB round trip).
func (s *Service) OpenACMEEAB(ctx context.Context, id uuid.UUID) (string, secrets.Plaintext, error) {
	return s.openEAB(ctx, s.pool, id)
}

// SetKeygenSeam runs f inside a keygen slot before an ACME order's key is generated (tests only).
func SetKeygenSeam(s *Service, f func()) { s.keygenSeam = f }

// SetACMERenewHook sets the hook that runs between a candidate's read and its transaction (nil removes it).
func SetACMERenewHook(f func(id uuid.UUID)) { acmeRenewHook = f }

// SetACMEDeployHook installs a function that runs after an ACME certificate's candidate was read and before its
// transaction (the automatic deployment planner); restore removes it.
func SetACMEDeployHook(f func(id uuid.UUID)) (restore func()) {
	old := acmeDeployHook
	acmeDeployHook = f
	return func() { acmeDeployHook = old }
}

// SetACMEDeployInsertHook installs a function that runs before the ACME planner inserts a location's deployment.
func SetACMEDeployInsertHook(f func(location uuid.UUID)) (restore func()) {
	old := acmeDeployInsertHook
	acmeDeployInsertHook = f
	return func() { acmeDeployInsertHook = old }
}

// SetACMEDeployPage sets the size of a page of the ACME planner's candidates; restore puts it back.
func SetACMEDeployPage(n int) (restore func()) {
	old := acmeDeployPage
	acmeDeployPage = n
	return func() { acmeDeployPage = old }
}

// Registry is the service's provider registry (tests build a second service on the same registry).
func (s *Service) Registry() *providers.Registry { return s.registry }

// SafeACMEWebURL is safeACMEWebURL (the preview's rule for a URL shown as a link).
var SafeACMEWebURL = safeACMEWebURL

// AddAPITarget stores a target of an API type (R59: the BIG-IP and Kubernetes phases add the API path) with its own
// credential sealed from sec, as the owner role, and returns its id.
func (s *Service) AddAPITarget(ctx context.Context, owner *pgxpool.Pool, typ, name, host string, sec providers.TargetSecret) (uuid.UUID, error) {
	c, err := s.sealTargetCredential(typ, sec)
	if err != nil {
		return uuid.Nil, err
	}
	target := uuid.Must(uuid.NewV7())
	err = db.InTx(ctx, owner, func(tx pgx.Tx) error {
		if err := insertTargetCredential(ctx, tx, c, target, time.Now()); err != nil {
			return err
		}
		_, err := tx.Exec(ctx, `INSERT INTO targets (id, name, type, config, credential_id, status, created_at, updated_at)
VALUES ($1, $2, $3, jsonb_build_object('host', $4::text, 'port', 443), $5, 'ok', now(), now())`, target, name, typ, host, c.ID)
		return err
	})
	return target, err
}

// ValidWindowsUser exposes windowsUserRE to the test that compares it with windows.ValidUser.
func ValidWindowsUser(s string) bool { return windowsUserRE.MatchString(s) }

// ConfigUsable exposes configUsable.
func ConfigUsable(n *providers.WebServerFacts) bool { return configUsable(n) }

// WindowsDefaultUser is the Windows default account the inventory stores.
const WindowsDefaultUser = windowsDefaultUser

// ProblemCertMissing is the Windows problem whose location has no certificate.
const ProblemCertMissing = problemCertMissing

// WindowsAuthorizedKeysLine exposes windowsAuthorizedKeysLine to the equality test with the Windows provider's line.
func WindowsAuthorizedKeysLine(publicKey, from string) string {
	return windowsAuthorizedKeysLine(publicKey, from)
}

// DeployTypes exposes deployTypes: the target types whose registered provider deploys (W2 Ruling 20).
func (s *Service) DeployTypes() []string { return s.deployTypes() }

// ValidBackupStore and ValidBackupSHA1 expose the rules of a Windows rollback_info's store and thumbprint (winproto's).
func ValidBackupStore(s string) bool { return backupStoreRE.MatchString(s) }

func ValidBackupSHA1(s string) bool { return backupSHA1RE.MatchString(s) }

// NewCertSHA256 exposes newCertSHA256: the location's compare-and-swap token once a deployment wrote certPEM.
func NewCertSHA256(kind providers.LocationKind, certPEM []byte) string {
	return newCertSHA256(kind, certPEM)
}
