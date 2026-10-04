package inventory

import (
	"context"
	"crypto/x509"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

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
