//go:build integration

package inventory_test

import (
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"alice/internal/audit"
	"alice/internal/inventory"
	"alice/internal/platform/validate"
	"alice/internal/providers"
	"alice/internal/rbac"
	"alice/internal/secrets"
	"alice/internal/testutil/fakekv"
	"alice/internal/testutil/pki"
)

// refuseWrites makes the database refuse the given statement kind on a table, standing in for a
// storage failure in the middle of an operation.
func (h *harness) refuseWrites(table, event string) {
	h.t.Helper()
	_, err := h.db.Owner.Exec(h.ctx, `CREATE OR REPLACE FUNCTION test_refuse() RETURNS trigger LANGUAGE plpgsql AS
		$$ BEGIN RAISE EXCEPTION 'storage refused'; END $$`)
	require.NoError(h.t, err)
	_, err = h.db.Owner.Exec(h.ctx, "CREATE TRIGGER test_refuse_"+table+" BEFORE "+event+" ON "+table+" FOR EACH ROW EXECUTE FUNCTION test_refuse()")
	require.NoError(h.t, err)
}

func TestVaultOperationsSurviveStorageFailures(t *testing.T) {
	h := newHarness(t, withAzureAndNginx())
	h.azureOK()
	admin := h.user("ada", rbac.Admin, "")
	tgt := h.newVault(admin, "Prod", "https://prod.vault.azure.net")
	cur, err := h.svc.GetTarget(h.ctx, tgt.ID)
	require.NoError(t, err)
	replacement := func() inventory.VaultCredentialInput {
		return inventory.VaultCredentialInput{Auth: providers.AzureAuthClientSecret, TenantID: kvTenant, ClientID: kvClient,
			ClientSecret: secrets.NewPlaintext([]byte(fakekv.NewClientSecret()))}
	}
	credentials := h.count("SELECT count(*) FROM credentials")

	// The new credential cannot be stored: nothing changes.
	h.refuseWrites("credentials", "INSERT")
	_, _, _, err = h.svc.ReplaceVaultCredentials(h.ctx, admin, tgt.ID, cur.Version, replacement())
	require.Error(t, err)
	assert.Equal(t, credentials, h.count("SELECT count(*) FROM credentials"))
	_, err = h.db.Owner.Exec(h.ctx, "DROP TRIGGER test_refuse_credentials ON credentials")
	require.NoError(t, err)

	// The vault row cannot be updated: replacing, recording an access check and deleting all fail whole.
	h.refuseWrites("targets", "UPDATE")
	_, _, _, err = h.svc.ReplaceVaultCredentials(h.ctx, admin, tgt.ID, cur.Version, replacement())
	require.Error(t, err)
	assert.Equal(t, credentials, h.count("SELECT count(*) FROM credentials"), "the half-made replacement is rolled back")
	require.Error(t, h.svc.RecordKVConnection(h.ctx, tgt.ID, azureReport(okChecks())))
	require.Error(t, h.svc.DeleteVault(h.ctx, admin, tgt.ID, false))
	again, err := h.svc.GetTarget(h.ctx, tgt.ID)
	require.NoError(t, err)
	assert.Equal(t, cur.Version, again.Version)
	assert.Equal(t, 0, h.count("SELECT count(*) FROM targets WHERE deleted_at IS NOT NULL"))
}

func TestRecordAccessCheckReadRefusesMalformedRecords(t *testing.T) {
	h := newHarness(t, withAzure())
	h.azureOK()
	admin := h.user("ada", rbac.Admin, "")
	tgt := h.newVault(admin, "Prod", "https://prod.vault.azure.net")
	good := ver(1)
	cases := []struct {
		field, name, version, reason string
		result                       audit.Result
	}{
		{"certificate_name", "not a name!", good, "", audit.Success},
		{"version", "web-cert", "short", "", audit.Success},
		{"result", "web-cert", good, "", audit.Result("maybe")},
		{"reason", "web-cert", good, "free text, not a code", audit.Failure},
	}
	for _, c := range cases {
		err := h.svc.RecordAccessCheckRead(h.ctx, tgt.ID, c.name, c.version, c.result, c.reason)
		var errs validate.Errors
		require.ErrorAs(t, err, &errs, c.field)
		assert.Equal(t, c.field, errs[0].Field)
	}
	assert.Zero(t, h.audits("kv.secret_read"), "a refused record writes nothing")
}

func TestCreateTargetRefusesUnusableNamesAndAddresses(t *testing.T) {
	h := newHarness(t)
	admin := h.user("ada", rbac.Admin, "")
	cases := []struct{ field, name, host string }{
		{"name", "bad\xffname", "10.0.0.5"},
		{"host", "web", "fe80::1%eth0"},
		{"host", "web", "[fe80::1%eth0]"},
	}
	for _, c := range cases {
		_, _, err := h.svc.CreateTarget(h.ctx, admin, inventory.NewTarget{Name: c.name, Type: "linux", Host: c.host})
		var errs validate.Errors
		require.ErrorAs(t, err, &errs, c.host)
		assert.Equal(t, c.field, errs[0].Field, c.host)
	}
	assert.Zero(t, h.count("SELECT count(*) FROM targets"))
}

func TestStoredTargetRowsThatCannotBeDecodedAreReported(t *testing.T) {
	h := newHarness(t)
	admin := h.user("ada", rbac.Admin, "")
	tgt := h.add(admin, "web-01", "10.0.0.5")

	_, err := h.db.Owner.Exec(h.ctx, "UPDATE targets SET facts = '[]'::jsonb WHERE id = $1", tgt.ID)
	require.NoError(t, err)
	_, err = h.svc.GetTarget(h.ctx, tgt.ID)
	require.Error(t, err)
	assert.ErrorContains(t, err, "decode target facts")

	_, err = h.db.Owner.Exec(h.ctx, `UPDATE targets SET facts = '{}'::jsonb, config = '{"host":"10.0.0.5","port":22,"username":5}'::jsonb WHERE id = $1`, tgt.ID)
	require.NoError(t, err)
	_, err = h.svc.GetTarget(h.ctx, tgt.ID)
	require.Error(t, err)
	assert.ErrorContains(t, err, "decode target config")
}

func TestUpdateTargetStorageFailureChangesNothing(t *testing.T) {
	h := newHarness(t)
	admin := h.user("ada", rbac.Admin, "")
	tgt := h.add(admin, "web-01", "10.0.0.5")
	h.refuseWrites("targets", "UPDATE")
	name := "renamed"
	_, err := h.svc.UpdateTarget(h.ctx, admin, tgt.ID, tgt.Version, inventory.TargetPatch{Name: &name})
	require.Error(t, err)
	got, err := h.svc.GetTarget(h.ctx, tgt.ID)
	require.NoError(t, err)
	assert.Equal(t, "web-01", got.Name)
	assert.Zero(t, h.audits("target.updated"))
}

func TestUploadStorageFailuresStoreNothing(t *testing.T) {
	h := newHarness(t)
	op := h.user("oya", rbac.Operator, "")
	ca := pki.NewCA("Inv", pki.ECDSA256, h.clock.Now())
	leaf := ca.Issue(pki.Opts{CommonName: "up.example.test", SANs: []string{"up.example.test"}}, h.clock.Now())
	drop := func(table string) {
		_, err := h.db.Owner.Exec(h.ctx, "DROP TRIGGER test_refuse_"+table+" ON "+table)
		require.NoError(t, err)
	}

	// The private key cannot be stored.
	h.refuseWrites("managed_private_keys", "INSERT")
	_, _, err := h.svc.UploadCertificate(h.ctx, op, pemUpload(leaf))
	require.Error(t, err)
	drop("managed_private_keys")
	assert.Zero(t, h.count("SELECT count(*) FROM certificates"))

	// The certificate row cannot be stored.
	h.refuseWrites("certificates", "INSERT")
	_, _, err = h.svc.UploadCertificate(h.ctx, op, pemUpload(leaf))
	require.Error(t, err)
	drop("certificates")
	assert.Zero(t, h.count("SELECT count(*) FROM certificates"))
	assert.Zero(t, h.count("SELECT count(*) FROM managed_private_keys"), "the key is rolled back with the certificate")
}

func TestTargetWritesReportStorageFailures(t *testing.T) {
	h := newHarness(t)
	admin := h.user("ada", rbac.Admin, "")
	tg := h.add(admin, "web-01", "10.0.0.5")

	// A damaged row fails the whole listing instead of being skipped.
	_, err := h.db.Owner.Exec(h.ctx, "UPDATE targets SET facts = '[]'::jsonb WHERE id = $1", tg.ID)
	require.NoError(t, err)
	_, err = h.svc.ListTargets(h.ctx)
	require.Error(t, err)
	_, err = h.db.Owner.Exec(h.ctx, "UPDATE targets SET facts = '{}'::jsonb WHERE id = $1", tg.ID)
	require.NoError(t, err)

	// Recording a connection outcome, and deleting the target, fail whole when the row cannot be updated.
	h.refuseWrites("targets", "UPDATE")
	require.Error(t, h.svc.RecordConnectionFailure(h.ctx, tg.ID, "ssh.timeout"))
	require.Error(t, h.svc.RecordConnectionOK(h.ctx, tg.ID, providers.ConnectionReport{}))
	require.Error(t, h.svc.DeleteTarget(h.ctx, admin, tg.ID))
	got, err := h.svc.GetTarget(h.ctx, tg.ID)
	require.NoError(t, err)
	assert.Equal(t, tg.Status, got.Status)
	assert.Zero(t, h.audits("target.deleted"))
	_, err = h.db.Owner.Exec(h.ctx, "DROP TRIGGER test_refuse_targets ON targets")
	require.NoError(t, err)

	// A new target that cannot be stored leaves nothing behind.
	h.refuseWrites("targets", "INSERT")
	_, _, err = h.svc.CreateTarget(h.ctx, admin, inventory.NewTarget{Name: "web-02", Type: "linux", Host: "10.0.0.6"})
	require.Error(t, err)
	assert.Equal(t, 1, h.count("SELECT count(*) FROM targets"))
}

func TestTargetOperationsOnAnUnknownTargetAreNotFound(t *testing.T) {
	h := newHarness(t)
	admin := h.user("ada", rbac.Admin, "")
	id := uuid.New()
	name := "x"
	require.ErrorIs(t, h.svc.RecordConnectionFailure(h.ctx, id, "ssh.timeout"), inventory.ErrNotFound)
	require.ErrorIs(t, h.svc.RecordConnectionOK(h.ctx, id, providers.ConnectionReport{}), inventory.ErrNotFound)
	_, err := h.svc.UpdateTarget(h.ctx, admin, id, 1, inventory.TargetPatch{Name: &name})
	require.ErrorIs(t, err, inventory.ErrNotFound)
	require.ErrorIs(t, h.svc.DeleteTarget(h.ctx, admin, id), inventory.ErrNotFound)
	_, _, err = h.svc.TargetRef(h.ctx, id)
	require.ErrorIs(t, err, inventory.ErrNotFound)
}
