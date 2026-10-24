//go:build integration

package inventory_test

import (
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"alice/internal/authz"
	"alice/internal/inventory"
	"alice/internal/providers"
	"alice/internal/rbac"
)

// Every other path of the service (servers, locations, deployments, Key Vault, bindings, keys, drift, the planners)
// reports a database that cannot be reached as an error of its own: never as not found, a state, nothing to do, or
// success. A planner that ran against a dead database must not say it found no work.
func TestServicePathsReportADatabaseFailure(t *testing.T) {
	h := newHarness(t, withClosedPool())
	h.installLicense("LIC-DEAD-DB-2", 5, 365)
	require.NoError(t, h.lic.Tick(h.ctx))
	a := h.user("ada", rbac.Admin, "")
	id, other := uuid.New(), uuid.New()
	ctx, svc := h.ctx, h.svc
	for name, call := range map[string]func() error{
		// servers and their locations
		"GetTarget":               func() error { _, err := svc.GetTarget(ctx, id); return err },
		"ListTargets":             func() error { _, err := svc.ListTargets(ctx); return err },
		"TargetRef":               func() error { _, _, err := svc.TargetRef(ctx, id); return err },
		"DeleteTarget":            func() error { return svc.DeleteTarget(ctx, a, id) },
		"RequestTest":             func() error { _, err := svc.RequestTest(ctx, a, id); return err },
		"RequestDiscovery":        func() error { _, err := svc.RequestDiscovery(ctx, a, id); return err },
		"RecordConnectionFailure": func() error { return svc.RecordConnectionFailure(ctx, id, "ssh.unreachable") },
		"ScheduleDiscovery":       func() error { _, err := svc.ScheduleDiscovery(ctx); return err },
		"SweepDeployments":        func() error { _, err := svc.SweepDeployments(ctx); return err },
		"ListLocations":           func() error { _, err := svc.ListLocations(ctx, id, true); return err },
		"GetLocation":             func() error { _, err := svc.GetLocation(ctx, id); return err },
		"ListDeployableLocations": func() error { _, err := svc.ListDeployableLocations(ctx, inventory.LocationFilter{}); return err },
		"ListHostKeys":            func() error { _, err := svc.ListHostKeys(ctx, id); return err },
		"ConfirmHostKey":          func() error { _, err := svc.ConfirmHostKey(ctx, a, id, other, "SHA256:x"); return err },
		"RepinHostKey":            func() error { _, err := svc.RepinHostKey(ctx, a, id, other, "SHA256:x", "rebuilt"); return err },
		"Reconcile":               func() error { _, err := svc.Reconcile(ctx, id, providers.DiscoveryResult{}); return err },
		// certificates and deployments
		"ListCertificates":     func() error { _, err := svc.ListCertificates(ctx, inventory.CertificateFilter{}); return err },
		"GetCertificate":       func() error { _, err := svc.GetCertificate(ctx, id); return err },
		"ListCSRs":             func() error { _, err := svc.ListCSRs(ctx); return err },
		"GetCSR":               func() error { _, err := svc.GetCSR(ctx, id); return err },
		"CancelCSR":            func() error { _, err := svc.CancelCSR(ctx, a, id); return err },
		"Deployment":           func() error { _, err := svc.Deployment(ctx, id); return err },
		"ListDeployments":      func() error { _, err := svc.ListDeployments(ctx, inventory.DeploymentFilter{}); return err },
		"DeploymentMaterial":   func() error { _, err := svc.DeploymentMaterial(ctx, id, true); return err },
		"BeginDeployment":      func() error { _, err := svc.BeginDeployment(ctx, id); return err },
		"CheckRecoveryPending": func() error { return svc.CheckRecoveryPending(ctx, id) },
		"OperationDeployment":  func() error { _, _, err := svc.OperationDeployment(ctx, id); return err },
		"RequestRecovery":      func() error { _, err := svc.RequestRecovery(ctx, id); return err },
		"MarkRecovering":       func() error { return svc.MarkRecovering(ctx, id, time.Now(), false) },
		"RollbackGuard":        func() error { _, err := svc.RollbackGuard(ctx, id); return err },
		"ListIncidentsIn": func() error {
			_, err := svc.ListIncidentsIn(ctx, inventory.IncidentFilter{}, authz.Reach{})
			return err
		},
		// drift
		"LocationObservation":       func() error { _, err := svc.LocationObservation(ctx, id); return err },
		"SetDriftMode":              func() error { _, err := svc.SetDriftMode(ctx, a, id, inventory.DriftModeObserve, false); return err },
		"RepairDrift":               func() error { _, err := svc.RepairDrift(ctx, a, id, false); return err },
		"ScheduleDriftObservations": func() error { _, err := svc.ScheduleDriftObservations(ctx); return err },
		"DriftProbes":               func() error { _, err := svc.DriftProbes(ctx, id); return err },
		"RecordDriftObservations": func() error {
			_, err := svc.RecordDriftObservations(ctx, id, []inventory.DriftResult{{LocationID: other, At: time.Now(), Skipped: true}})
			return err
		},
		"PlanDriftRepairs": func() error { _, err := svc.PlanDriftRepairs(ctx); return err },
		// Key Vault, bindings and imports
		"ListKVCertificates": func() error { _, err := svc.ListKVCertificates(ctx, id, inventory.KVFilter{}); return err },
		"KVCertificate":      func() error { _, err := svc.KVCertificate(ctx, id, other); return err },
		"ListKVKeys":         func() error { _, _, err := svc.ListKVKeys(ctx, id, inventory.KVFilter{}); return err },
		"ListKVSecrets":      func() error { _, _, err := svc.ListKVSecrets(ctx, id, inventory.KVFilter{}); return err },
		"ScheduleKVPolls":    func() error { _, err := svc.ScheduleKVPolls(ctx); return err },
		"KVPollRequest":      func() error { _, err := svc.KVPollRequest(ctx, id); return err },
		"PlanKVAutoDeploy":   func() error { _, err := svc.PlanKVAutoDeploy(ctx); return err },
		"KVDeployPrecheck":   func() error { return svc.KVDeployPrecheck(ctx, id) },
		"Binding":            func() error { _, err := svc.Binding(ctx, id); return err },
		"ListBindings":       func() error { _, err := svc.ListBindings(ctx, inventory.BindingFilter{}); return err },
		"DeleteBinding":      func() error { return svc.DeleteBinding(ctx, a, id) },
		"Import":             func() error { _, err := svc.Import(ctx, id, other); return err },
		"ListImports":        func() error { _, err := svc.ListImports(ctx, id, 10); return err },
		"ListImportsPage":    func() error { _, err := svc.ListImportsPage(ctx, id, inventory.ImportFilter{}); return err },
		"ImportMaterial":     func() error { _, err := svc.ImportMaterial(ctx, id); return err },
		"MarkImportSent":     func() error { return svc.MarkImportSent(ctx, id) },
		"SweepImports":       func() error { _, err := svc.SweepImports(ctx); return err },
		"DeleteVault":        func() error { return svc.DeleteVault(ctx, a, id, false) },
		"RequestAccessCheck": func() error { _, err := svc.RequestAccessCheck(ctx, a, id, other); return err },
		// SSH keys
		"KeyLocation":           func() error { _, err := svc.KeyLocation(ctx, id); return err },
		"ListTargetKeys":        func() error { _, err := svc.ListTargetKeys(ctx, id, true); return err },
		"ListSSHKeys":           func() error { _, err := svc.ListSSHKeys(ctx, inventory.KeyFilter{}); return err },
		"GetSSHKey":             func() error { _, err := svc.GetSSHKey(ctx, id); return err },
		"RequestKeyRemoval":     func() error { _, err := svc.RequestKeyRemoval(ctx, a, id, false); return err },
		"ProtectedFingerprints": func() error { _, err := svc.ProtectedFingerprints(ctx); return err },
		// ACME paths the other table leaves out
		"ListACMECertificatesIn": func() error { _, err := svc.ListACMECertificatesIn(ctx, authz.Reach{}); return err },
		"DeleteACMECertificate":  func() error { return svc.DeleteACMECertificate(ctx, a, id) },
		"ReArmACMEAutoRenew":     func() error { _, err := svc.ReArmACMEAutoRenew(ctx, a, id); return err },
		"RemoveACMEBinding":      func() error { return svc.RemoveACMEBinding(ctx, a, id, other) },
		"ReleaseACMEDeployHold":  func() error { return svc.ReleaseACMEDeployHold(ctx, a, id) },
		"ACMEOrderWork":          func() error { _, err := svc.ACMEOrderWork(ctx, id); return err },
		"GetACMEHook":            func() error { _, err := svc.GetACMEHook(ctx, id); return err },
		"DeleteACMEHook":         func() error { return svc.DeleteACMEHook(ctx, a, id) },
		"DeleteACMEProvider":     func() error { return svc.DeleteACMEProvider(ctx, a, id) },
		"PreviewACMEProvider":    func() error { _, err := svc.PreviewACMEProvider(ctx, id); return err },
		"SyncCapabilities":       func() error { _, err := svc.SyncCapabilities(ctx); return err },
	} {
		err := call()
		require.Error(t, err, name)
		for _, refusal := range []error{inventory.ErrNotFound, inventory.ErrIncidentState, inventory.ErrDriftNotBound, inventory.ErrDriftNotDrifted} {
			assert.NotErrorIs(t, err, refusal, name)
		}
	}
}
