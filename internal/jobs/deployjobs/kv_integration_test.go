//go:build integration

package deployjobs

import (
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"alice/internal/certs"
	"alice/internal/inventory"
	"alice/internal/jobs"
	"alice/internal/platform/azureid"
	"alice/internal/providers"
	"alice/internal/providers/fake"
	"alice/internal/providers/linuxssh/helperproto"
	"alice/internal/secrets"
	"alice/internal/testutil/fakekv"
	"alice/internal/testutil/pki"
)

const (
	kvTenantID = "1111aaaa-2222-bbbb-3333-cccc4444dddd"
	kvClientID = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"
)

// kvWorld is the Phase 4 world (the old certificate served by the servers) plus a vault "prod" that
// holds one certificate "web-cert" whose only version is the new leaf (e.nw): the vault's secret
// is that leaf's key and chain. The vault is the scripted azurekv fake (the real provider and the
// fake Azure service join the integration harness with Task 18's seam).
type kvWorld struct {
	*env
	vault     uuid.UUID
	ver       string
	kvCert    uuid.UUID
	versionID uuid.UUID
}

func newKVWorld(t *testing.T) *kvWorld {
	t.Helper()
	e := newEnv(t)
	w := &kvWorld{env: e, ver: fmt.Sprintf("%032x", 1)}
	checks := []providers.AzureCheck{
		{Name: providers.AzureCheckSignIn, Result: providers.AzureResultOK},
		{Name: providers.AzureCheckListCertificates, Result: providers.AzureResultOK},
		{Name: providers.AzureCheckListKeys, Result: providers.AzureResultOK},
		{Name: providers.AzureCheckListSecrets, Result: providers.AzureResultOK},
		{Name: providers.AzureCheckReadSecret, Result: providers.AzureResultNotChecked},
		{Name: providers.AzureCheckImport, Result: providers.AzureResultNotChecked},
	}
	e.az.Configure(func(c *fake.Config) {
		c.OpenErr, c.TestErr = nil, nil
		c.Report = providers.ConnectionReport{Azure: &providers.AzureFacts{ObjectID: "99999999-8888-7777-6666-555555555555", TenantID: kvTenantID,
			PermissionModel: "rbac", Checks: checks, CheckedAt: e.clock.Now()}}
	})
	e.evaluate()
	v, _, _, err := e.inv.CreateVault(e.ctx, e.admin, inventory.NewVault{Name: "prod", VaultURL: "https://prod.vault.azure.net",
		Auth: providers.AzureAuthClientSecret, TenantID: kvTenantID, ClientID: kvClientID,
		ClientSecret: secrets.NewPlaintext([]byte(fakekv.NewClientSecret()))})
	require.NoError(t, err)
	w.vault = v.ID
	now, l := e.clock.Now(), e.nw
	th, nb, exp := azureid.ThumbprintOf(l.Cert.Raw), l.Cert.NotBefore.UTC(), l.Cert.NotAfter.UTC()
	cert := providers.KVCertificate{Name: "web-cert", Thumbprint: th, Enabled: true, NotBefore: &nb, Expires: &exp, Created: &now, Updated: &now,
		Details: &providers.KVCertificateDetails{Version: w.ver, Thumbprint: th, Updated: &now, CER: l.Cert.Raw, Exportable: ptr(true), KeyType: "ecdsa",
			KeySize: 256, ContentType: "pkcs12", IssuerName: "Unknown", AutoRenew: true},
		Versions: []providers.KVCertificateVersion{{Version: w.ver, Thumbprint: th, Enabled: true, NotBefore: &nb, Expires: &exp, Created: &now}}}
	_, err = e.inv.ReconcileKV(e.ctx, w.vault, providers.DiscoveryResult{KV: &providers.KVInventory{Certificates: []providers.KVCertificate{cert}}})
	require.NoError(t, err)
	require.NoError(t, e.db.Owner.QueryRow(e.ctx, "SELECT id FROM kv_certificates WHERE target_id = $1 AND name = 'web-cert'", w.vault).Scan(&w.kvCert))
	require.NoError(t, e.db.Owner.QueryRow(e.ctx, "SELECT id FROM kv_certificate_versions WHERE kv_certificate_id = $1 AND version = $2",
		w.kvCert, w.ver).Scan(&w.versionID))
	w.serve(append(append([]byte(nil), l.KeyPEM...), l.FullchainPEM...))
	return w
}

func ptr[T any](v T) *T { return &v }

// serve makes the vault answer the secret read with this PEM text (the key and the chain).
func (w *kvWorld) serve(pemText []byte) {
	w.az.Configure(func(c *fake.Config) {
		c.SecretErr = nil
		c.Secret = providers.CertificateSecret{ContentType: certs.ContentTypePEM, Value: providers.NewSecret(pemText)}
	})
}

// refuse makes the vault refuse the secret read with err.
func (w *kvWorld) refuse(err error) { w.az.Configure(func(c *fake.Config) { c.SecretErr = err }) }

func (w *kvWorld) bind(locs ...uuid.UUID) inventory.Binding {
	w.t.Helper()
	b, err := w.inv.CreateBinding(w.ctx, w.admin, inventory.BindingInput{KVCertificateID: w.kvCert, LocationIDs: locs})
	require.NoError(w.t, err)
	return b
}

// deploy asks for the vault version on the binding's locations (Deploy now) and returns the deployments.
func (w *kvWorld) deploy(b inventory.Binding, confirmChain bool, locs ...uuid.UUID) []uuid.UUID {
	w.t.Helper()
	w.evaluate()
	got, err := w.inv.RequestKVDeployment(w.ctx, w.admin, inventory.KVDeployInput{BindingID: b.ID, VersionID: w.versionID, LocationIDs: locs,
		ConfirmIncompleteChain: confirmChain})
	require.NoError(w.t, err)
	out := make([]uuid.UUID, 0, len(got))
	for _, g := range got {
		out = append(out, g.ID)
	}
	return out
}

func (w *kvWorld) reads() int { return w.az.Count("ReadCertificateSecret") }

func (w *kvWorld) stepsOf(id uuid.UUID) map[string]string {
	w.t.Helper()
	out := map[string]string{}
	for _, s := range w.deployment(id).Steps {
		out[s.Name+":"+s.Status] = s.Params["reason"]
	}
	return out
}

// untouched asserts the server was not spoken to since commands: no command, and its website serves
// the old certificate.
func (w *kvWorld) untouched(s *server, commands int) {
	w.t.Helper()
	assert.Equal(w.t, commands, len(s.srv.Commands()), "the server received no command")
	assert.Zero(w.t, s.emu.DeployCount())
	w.assertPair(s, wwwCert, wwwKey, wwwName, w.old)
}

func TestKVDeploymentEndToEnd(t *testing.T) {
	w := newKVWorld(t)
	s1, s2 := w.addServer("web-01", wwwSite()), w.addServer("web-02", wwwSite())
	b := w.bind(s1.locs[wwwCert], s2.locs[wwwCert])
	keys := w.count("SELECT count(*) FROM managed_private_keys")
	ids := w.deploy(b, false)
	require.Len(t, ids, 2)
	for _, id := range ids {
		d := w.settle(id)
		assert.Equal(t, inventory.DeployStatusSucceeded, d.Status)
		assert.Equal(t, "key_vault", d.Source)
		require.NotNil(t, d.BindingID)
		assert.Equal(t, w.ver, d.KVVersion)
		steps := w.stepsOf(id)
		assert.Contains(t, steps, stepKVSecret+":ok")
		assert.NotContains(t, steps, stepKVSecret+":failed")
	}
	for _, s := range []*server{s1, s2} {
		w.assertPair(s, wwwCert, wwwKey, wwwName, w.nw)
		assert.Equal(t, w.nw.FullchainPEM, s.emu.NginxFile(wwwCert), "the vault's leaf with its intermediate is what the website serves")
		assert.Equal(t, w.nw.KeyPEM, s.emu.NginxFile(wwwKey))
	}
	assert.Equal(t, 2, w.reads(), "one secret read per deployment")
	assert.Equal(t, 2, w.audits("kv.secret_read"))
	assert.Equal(t, keys, w.count("SELECT count(*) FROM managed_private_keys"), "the vault's key was never sealed or stored")
	assert.Equal(t, 2, w.audits("deployment.succeeded"))
}

// F-41: the vault refuses the secret because the role Key Vault Secrets User is missing. The
// deployment ends failed with the role named, before anything was sent: the servers received no
// command and still serve the old certificate.
func TestF41MissingSecretsRoleChangesNothing(t *testing.T) {
	w := newKVWorld(t)
	s1, s2 := w.addServer("web-01", wwwSite()), w.addServer("web-02", wwwSite())
	b := w.bind(s1.locs[wwwCert], s2.locs[wwwCert])
	c1, c2 := len(s1.srv.Commands()), len(s2.srv.Commands())
	w.refuse(providers.NewError("azure.forbidden", false, nil, map[string]string{"role": "Key Vault Secrets User", "model": "rbac",
		"azure_code": "Forbidden", "azure_request_id": "00000000-0000-0000-0000-000000000001", "stderr": "remote text"}))
	for _, id := range w.deploy(b, false) {
		d := w.settle(id)
		assert.Equal(t, inventory.DeployStatusFailed, d.Status)
		assert.Equal(t, "azure.forbidden", d.ErrorCode)
		assert.Equal(t, stepKVSecret, d.FailedStep)
		assert.Equal(t, map[string]string{"role": "Key Vault Secrets User", "model": "rbac", "azure_code": "Forbidden",
			"azure_request_id": "00000000-0000-0000-0000-000000000001"}, d.ErrorParams, "the role reaches the record (D5), remote text does not")
		assert.Equal(t, "azure.forbidden", w.stepsOf(id)[stepKVSecret+":failed"])
		v := w.jobOf(id)
		assert.Equal(t, string(jobs.StatusFailed), string(v.Status))
		assert.Equal(t, "azure.forbidden", v.LastErrorCode)
	}
	w.untouched(s1, c1)
	w.untouched(s2, c2)
	assert.Zero(t, w.audits("kv.secret_read"), "no secret was read")
	assert.Equal(t, 2, w.audits("deployment.failed"))
}

// F-45 at run time: the certificate was made non-exportable after the request. Either the vault
// refuses the secret (403) or it answers 200 with a secret that holds no private key; both end the
// deployment before anything is sent.
func TestF45NonExportableAtRunTime(t *testing.T) {
	for _, tc := range []struct {
		name   string
		setup  func(w *kvWorld)
		reason string
	}{
		{"the vault refuses the secret", func(w *kvWorld) {
			w.refuse(providers.NewError("azure.forbidden", false, nil, map[string]string{"role": "Key Vault Secrets User", "model": "rbac"}))
		}, "azure.forbidden"},
		{"the secret has no private key", func(w *kvWorld) { w.serve(w.nw.FullchainPEM) }, "kv.secret_unreadable"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			w := newKVWorld(t)
			s := w.addServer("web-01", wwwSite())
			b := w.bind(s.locs[wwwCert])
			cmds := len(s.srv.Commands())
			id := w.deploy(b, false)[0]
			tc.setup(w)
			d := w.settle(id)
			assert.Equal(t, inventory.DeployStatusFailed, d.Status)
			assert.Equal(t, tc.reason, d.ErrorCode)
			w.untouched(s, cmds)
		})
	}
}

// F-17: an incomplete chain is refused unless an Administrator confirmed it when requesting; the
// confirmed deployment goes through and its step says so.
func TestKVIncompleteChainNeedsTheConfirmation(t *testing.T) {
	w := newKVWorld(t)
	s := w.addServer("web-01", wwwSite())
	b := w.bind(s.locs[wwwCert])
	w.serve(append(append([]byte(nil), w.nw.KeyPEM...), w.nw.CertPEM...)) // the leaf alone
	cmds := len(s.srv.Commands())
	d := w.settle(w.deploy(b, false)[0])
	assert.Equal(t, inventory.DeployStatusFailed, d.Status)
	assert.Equal(t, "certificate.chain_unconfirmed", d.ErrorCode)
	w.untouched(s, cmds)

	id := w.deploy(b, true)[0]
	d = w.settle(id)
	assert.Equal(t, inventory.DeployStatusSucceeded, d.Status)
	assert.Equal(t, "chain_incomplete", w.stepsOf(id)[stepKVSecret+":ok"])
	assert.Equal(t, w.nw.CertPEM, s.emu.NginxFile(wwwCert), "the chain as the vault delivered it")
	assert.Equal(t, pki.Fingerprint(w.nw.Cert), s.emu.Served(443, wwwName))
}

// The vault is deleted (with its bindings) while a deployment is queued: the deployment ends failed
// with the closed reason, nothing was sent.
func TestKVDeploymentOfADeletedVault(t *testing.T) {
	w := newKVWorld(t)
	s := w.addServer("web-01", wwwSite())
	b := w.bind(s.locs[wwwCert])
	cmds := len(s.srv.Commands())
	id := w.deploy(b, false)[0]
	require.NoError(t, w.inv.DeleteVault(w.ctx, w.admin, w.vault, true))
	d := w.settle(id)
	assert.Equal(t, inventory.DeployStatusFailed, d.Status)
	assert.Equal(t, "kv.certificate_not_found", d.ErrorCode)
	assert.Zero(t, w.reads())
	w.untouched(s, cmds)
}

// L-80 and L-82 with a vault deployment. L-80: the license locks while the send is in flight; the
// deployment completes and is recorded. L-82: its reload fails as the lock begins; the recovery
// (ClassAlways) rolls back without any vault access.
func TestL80L82WithAKeyVaultDeployment(t *testing.T) {
	t.Run("L-80", func(t *testing.T) {
		w := newKVWorld(t)
		s := w.addServer("web-01", wwwSite())
		id := w.deploy(w.bind(s.locs[wwwCert]), false)[0]
		w.setWrap(func(_ providers.TargetRef, sess providers.Session) providers.Session {
			return lockingSession{Session: sess, gate: w.gate}
		})
		ran, err := w.runner.RunOnce(w.ctx)
		require.NoError(t, err)
		require.True(t, ran)
		require.True(t, w.gate.locked.Load())
		w.setWrap(nil)
		d := w.deployment(id)
		assert.Equal(t, inventory.DeployStateDone, d.State)
		assert.Equal(t, inventory.DeployStatusSucceeded, d.Status, "the in-flight deployment finished in lock")
		assert.Equal(t, 1, w.reads())
		assert.Equal(t, 1, w.audits("kv.secret_read"))
	})
	t.Run("L-82", func(t *testing.T) {
		w := newKVWorld(t)
		s := w.addServer("web-01", wwwSite())
		id := w.deploy(w.bind(s.locs[wwwCert]), false)[0]
		s.emu.NoopReload(true)
		s.emu.HangupAfter(helperproto.StepReload)
		w.drain()
		require.Equal(t, inventory.DeployStateRecovering, w.deployment(id).State)
		require.Equal(t, 1, w.reads())
		w.gate.locked.Store(true)
		d := w.settle(id)
		assert.Equal(t, inventory.DeployStatusRolledBack, d.Status)
		w.assertPair(s, wwwCert, wwwKey, wwwName, w.old)
		assert.Equal(t, 1, w.audits("deployment.failed"))
		assert.Equal(t, 1, w.audits("deployment.rolled_back"))
		assert.Equal(t, 1, w.reads(), "the recovery read nothing from the vault")
	})
}

// L-81: a vault deployment queued before the lock is held; a renewal alone does not start it; an
// Administrator's confirmation does, and it then reads the secret and deploys.
func TestL81KVDeploymentHeldThenConfirmed(t *testing.T) {
	w := newKVWorld(t)
	s := w.addServer("web-01", wwwSite())
	id := w.deploy(w.bind(s.locs[wwwCert]), false)[0]
	w.gate.locked.Store(true)
	w.drain()
	d := w.deployment(id)
	require.Equal(t, inventory.DeployStateQueued, d.State)
	assert.Equal(t, string(jobs.StatusBlocked), d.JobStatus)
	assert.Zero(t, w.reads(), "a held deployment reads nothing")

	w.gate.locked.Store(false)
	w.drain()
	assert.Equal(t, string(jobs.StatusBlocked), w.deployment(id).JobStatus, "a renewal alone starts nothing")
	assert.Zero(t, w.reads())
	require.NoError(t, w.queue.Confirm(w.ctx, w.admin.Audit, w.admin.UserID, *d.JobID))
	w.drain()
	assert.Equal(t, inventory.DeployStatusSucceeded, w.deployment(id).Status)
	assert.Equal(t, 1, w.reads())
	w.assertPair(s, wwwCert, wwwKey, wwwName, w.nw)
}

// A crash between the steps of a vault deployment. Nothing of the secret was stored, so a run
// before the start record reads the vault again; a run after it recovers from the journal and never
// asks the vault; a vault that refuses the second read ends the deployment failed with the closed
// reason and the website unchanged.
func TestKVResumeAfterACrash(t *testing.T) {
	for _, tc := range []struct {
		name   string
		point  string
		before func(w *kvWorld) // what changes in the vault while the process is dead
		status string
		reason string
		reads  int
		sends  int
		want   func(e *env) pki.Leaf
	}{
		{name: "after the vault read, before the pre-check", point: "step:kv_secret:ok", status: inventory.DeployStatusSucceeded, reads: 2, sends: 1, want: newLeaf},
		{name: "after the pre-check, before the start record", point: "before:StartDeployment", status: inventory.DeployStatusSucceeded, reads: 2, sends: 1,
			want: newLeaf},
		{name: "the role was removed meanwhile", point: "before:StartDeployment", status: inventory.DeployStatusFailed, reason: "azure.forbidden", reads: 2,
			before: func(w *kvWorld) {
				w.refuse(providers.NewError("azure.forbidden", false, nil, map[string]string{"role": "Key Vault Secrets User", "model": "rbac"}))
			}, want: oldLeaf},
		{name: "the version was disabled meanwhile", point: "step:kv_secret:ok", status: inventory.DeployStatusFailed, reason: "kv.version_disabled", reads: 2,
			before: func(w *kvWorld) { w.refuse(providers.NewError("kv.version_disabled", false, nil, nil)) }, want: oldLeaf},
		{name: "the certificate was deleted meanwhile", point: "before:StartDeployment", status: inventory.DeployStatusFailed, reason: "kv.certificate_not_found",
			reads: 2, before: func(w *kvWorld) { w.refuse(providers.NewError("kv.certificate_not_found", false, nil, nil)) }, want: oldLeaf},
		{name: "after the start record, before the send", point: "after:StartDeployment", status: inventory.DeployStatusFailed,
			reason: "deployment.interrupted", reads: 1, want: oldLeaf},
		{name: "after the send, before the outcome is recorded", point: "session:after:DeployCertificate", status: inventory.DeployStatusSucceeded, reads: 1,
			sends: 1, want: newLeaf},
		{name: "after the send, the vault refuses now: recovery needs no vault", point: "session:after:DeployCertificate", status: inventory.DeployStatusSucceeded,
			reads: 1, sends: 1, want: newLeaf,
			before: func(w *kvWorld) {
				w.refuse(providers.NewError("azure.forbidden", false, nil, map[string]string{"role": "Key Vault Secrets User"}))
			}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			w := newKVWorld(t)
			s := w.addServer("web-01", wwwSite())
			id := w.deploy(w.bind(s.locs[wwwCert]), false)[0]
			k := newKiller(tc.point)
			w.runDying(k)
			require.Equal(t, tc.point, k.firedAt())
			require.NotEqual(t, inventory.DeployStateDone, w.deployment(id).State)
			if tc.before != nil {
				tc.before(w)
			}
			w.restart()
			d := w.settle(id)
			assert.Equal(t, tc.status, d.Status)
			assert.Equal(t, tc.reason, d.ErrorCode)
			assert.Equal(t, tc.reads, w.reads(), "the vault is read again only by a run before the start record")
			assert.Equal(t, tc.sends, s.emu.DeployCount(), "the certificate is sent at most once")
			w.assertPair(s, wwwCert, wwwKey, wwwName, tc.want(w.env))
		})
	}
}

// Nothing of the vault secret (its key, its PEM text) reaches a job row, a deployment record, a step,
// an audit row, the outbox, a stored certificate row or a log line, over a success, a refusal by
// the vault, and a secret that is not the recorded version.
func TestKVSecretLeavesNothingBehind(t *testing.T) {
	w := newKVWorld(t)
	s := w.addServer("web-01", wwwSite(), apiSite())
	b := w.bind(s.locs[wwwCert], s.locs[apiCert])
	ids := w.deploy(b, false, s.locs[wwwCert])
	w.settle(ids[0])
	// A refusal that carries a canary in its cause, and a secret for another certificate.
	canary := "VAULT-CANARY-" + uuid.NewString()
	w.refuse(providers.NewError("azure.forbidden", false, fmt.Errorf("body %s", canary), map[string]string{"role": "Key Vault Secrets User"}))
	ids = append(ids, w.deploy(b, false, s.locs[apiCert])...)
	w.settle(ids[1])
	other := w.ca.Issue(pki.Opts{CommonName: wwwName, SANs: []string{wwwName}}, w.clock.Now())
	w.serve(append(append([]byte(nil), other.KeyPEM...), other.FullchainPEM...))
	w.clock.Advance(time.Second)
	// the api location is free again (the refusal finished it): a third request meets the other secret
	ids = append(ids, w.deploy(b, false, s.locs[apiCert])...)
	d := w.settle(ids[2])
	assert.Equal(t, "kv.secret_mismatch", d.ErrorCode)

	var dump strings.Builder
	for _, table := range []string{"jobs", "job_attempts", "deployments", "deployment_steps", "audit_log", "notifications_outbox", "targets", "credentials",
		"certificates", "certificate_locations", "kv_certificates", "kv_certificate_versions", "bindings"} {
		rows, err := w.db.Owner.Query(w.ctx, "SELECT t::text FROM "+table+" t")
		require.NoError(t, err)
		for rows.Next() {
			var line string
			require.NoError(t, rows.Scan(&line))
			dump.WriteString(line + "\n")
		}
		require.NoError(t, rows.Err())
		rows.Close()
	}
	dump.WriteString(w.logs.String())
	text := dump.String()
	require.Contains(t, text, "certificate.deploy", "the dump holds the jobs")
	for i, needle := range append(keyMarkers(t, w.nw.KeyPEM), keyMarkers(t, other.KeyPEM)...) {
		assert.False(t, strings.Contains(text, needle), "key marker %d leaked", i)
	}
	assert.False(t, strings.Contains(text, canary), "the text of a refusal's cause leaked")
	assert.Zero(t, w.count("SELECT count(*) FROM managed_private_keys"), "no key of the vault was sealed")
}
