//go:build integration

package inventory_test

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"alice/internal/inventory"
	"alice/internal/providers"
	"alice/internal/testutil/pki"
)

// The Remote Desktop listener of a Windows server (R69, W6 Rulings 3, 4, 19-21): one win_rdp location per server, the
// RDP-Tcp listener, handled at the inventory sites as an http.sys binding.

// rdpFixture is winDeployFixture plus a second Windows server iis-02 whose RDP-Tcp listener serves old as its self-signed
// certificate (the value SSLCertificateSHA1Hash absent: store Remote Desktop).
type rdpFixture struct {
	*winDeployFixture
	server, rdp uuid.UUID
}

func newRDPFixture(t *testing.T) *rdpFixture {
	t.Helper()
	f := &rdpFixture{winDeployFixture: newWinDeployFixture(t)}
	h := f.h
	f.server = winTarget(t, h, f.admin, "iis-02").ID
	f.scan(3389)
	l := byPath(t, h, f.server, false)["rdp/RDP-Tcp"]
	require.True(t, l.Supported)
	require.Equal(t, providers.LocationWinRDP, l.Kind)
	f.rdp = l.ID
	return f
}

// scan reconciles iis-02's discovery: its listener on port, serving old as its self-signed certificate.
func (f *rdpFixture) scan(port int) inventory.ReconcileSummary {
	f.h.t.Helper()
	loc := providers.CertLocation{Kind: providers.LocationWinRDP, CertPath: "rdp/RDP-Tcp", Supported: true,
		Locator: providers.Locator{"type": "rdp", "listener": "RDP-Tcp"},
		Details: map[string]any{"port": port, "store": "Remote Desktop", "cert_sha1": thumbprint(f.old), "self_signed": true,
			"enabled": true, "security_layer": 2, "nla": true, "cert_template": ""},
		Servers: []providers.CertServer{}}
	sum, err := f.h.svc.Reconcile(f.h.ctx, f.server, providers.DiscoveryResult{WebServer: iisOK,
		Certificates: []providers.DiscoveredCertificate{{Location: loc, PEMChain: f.old.FullchainPEM, FileSHA256: derSHA(f.old)}}})
	require.NoError(f.h.t, err)
	return sum
}

func (f *rdpFixture) details() map[string]any {
	f.h.t.Helper()
	var raw []byte
	require.NoError(f.h.t, f.h.db.Owner.QueryRow(f.h.ctx, "SELECT details FROM certificate_locations WHERE id = $1", f.rdp).Scan(&raw))
	out := map[string]any{}
	require.NoError(f.h.t, json.Unmarshal(raw, &out))
	return out
}

func (f *rdpFixture) succeed(id uuid.UUID, leaf pki.Leaf) {
	f.h.t.Helper()
	require.NoError(f.h.t, f.h.svc.FinishDeployment(f.h.ctx, id, inventory.DeploymentFinish{Status: inventory.DeployStatusSucceeded,
		Result: "deployed", CertFileSHA256: derSHA(leaf), Verified: "remote"}))
}

// Ruling 4: the token of the RDP listener is the SHA-256 of the leaf's DER, as for an http.sys binding.
func TestNewCertSHA256ForRDP(t *testing.T) {
	now := time.Now()
	leaf := pki.NewCA("Token", pki.ECDSA256, now).Issue(pki.Opts{CommonName: "rdp.example.test", SANs: []string{"rdp.example.test"}}, now)
	assert.Equal(t, pki.Fingerprint(leaf.Cert), inventory.NewCertSHA256(providers.LocationWinRDP, leaf.FullchainPEM))
	assert.Empty(t, inventory.NewCertSHA256(providers.LocationWinRDP, []byte("not PEM")))
}

// Ruling 19: the start record of an RDP deployment is a binding's: the store and thumbprint the discovery read (the
// self-signed certificate's Remote Desktop before the first deployment), then what Alice deployed (My).
func TestStartBackupRefForRDP(t *testing.T) {
	f := newRDPFixture(t)
	r := f.request(f.rdp)
	f.start(r.ID, nil)
	var got map[string]any
	require.NoError(t, json.Unmarshal([]byte(f.rollbackInfo(r.ID)), &got))
	assert.Equal(t, map[string]any{"operation_id": r.ID.String(), "store": "Remote Desktop", "previous_sha1": thumbprint(f.old),
		"previous_sha256": derSHA(f.old)}, got)
	f.succeed(r.ID, f.nw)

	// The next deployment replaces what Alice deployed, in My.
	other := f.ca.Issue(pki.Opts{CommonName: "www.example.test", SANs: []string{"www.example.test"}}, f.h.clock.Now())
	c, _, err := f.h.svc.UploadCertificate(f.h.ctx, f.admin, pemUpload(other))
	require.NoError(t, err)
	got2, err := f.h.svc.RequestDeployment(f.h.ctx, f.admin, inventory.DeployRequestInput{CertificateID: c.ID, LocationIDs: []uuid.UUID{f.rdp}})
	require.NoError(t, err)
	require.Len(t, got2, 1)
	_, err = f.h.svc.BeginDeployment(f.h.ctx, got2[0].ID)
	require.NoError(t, err)
	m, err := f.h.svc.DeploymentMaterial(f.h.ctx, got2[0].ID, true)
	require.NoError(t, err)
	m.PrivateKeyPEM.Zero()
	require.NoError(t, f.h.svc.StartDeployment(f.h.ctx, got2[0].ID, m.SendValues(pki.Fingerprint(f.nw.Cert), 2)))
	got = nil
	require.NoError(t, json.Unmarshal([]byte(f.rollbackInfo(got2[0].ID)), &got))
	assert.Equal(t, map[string]any{"operation_id": got2[0].ID.String(), "store": "MY", "previous_sha1": thumbprint(f.nw),
		"previous_sha256": derSHA(f.nw)}, got)
}

// Ruling 19: after a deployment the listener names the deployed certificate in My: store MY, self_signed false and the
// deployed thumbprint, the other details kept.
func TestRDPDetailsAfterDeployment(t *testing.T) {
	f := newRDPFixture(t)
	r := f.request(f.rdp)
	f.start(r.ID, nil)
	f.succeed(r.ID, f.nw)
	d := f.details()
	assert.Equal(t, "MY", d["store"])
	assert.Equal(t, false, d["self_signed"])
	assert.Equal(t, thumbprint(f.nw), d["cert_sha1"])
	assert.Equal(t, true, d["nla"], "the listener's other details are kept")
}

// Ruling 19: an RDP deployment whose Windows session ended without an answer lost its connection, as a binding's.
func TestWindowsLostIncludesRDP(t *testing.T) {
	f := newRDPFixture(t)
	h := f.h
	r := f.request(f.rdp)
	f.start(r.ID, nil)
	_, err := h.db.Owner.Exec(h.ctx, "UPDATE deployments SET error_code = 'deployment.interrupted' WHERE id = $1", r.ID)
	require.NoError(t, err)
	require.NoError(t, h.svc.MarkRecovering(h.ctx, r.ID, time.Time{}, true))
	mails := f.deploymentMails(r.ID)
	require.Len(t, mails, 1)
	assert.Equal(t, inventory.WindowsTemplate(inventory.TemplateDeploymentNeedsAttention), mails[0].Template,
		"the lost-connection text, not the unconfirmed one")
	assert.Equal(t, "rdp", mails[0].Params["windows_note"])
}

// Ruling 20: an RDP listener's rollback_failed, outcome_unknown and restored_unverified e-mails are its RDP texts, naming
// the previous certificate in place of backup_dir; every other deployment e-mail is the Windows text with windows_note
// rdp. A restore that left NETWORK SERVICE's read access to the key in place says so (Ruling 10, rdp_key_acl_left).
func TestRDPDeploymentMail(t *testing.T) {
	f := newRDPFixture(t)
	h := f.h
	base := func(id uuid.UUID) map[string]string {
		return map[string]string{"target_name": "iis-02", "cert_path": "rdp/RDP-Tcp", "deployment_id": id.String()}
	}
	prev := thumbprint(f.old) // the Remote Desktop store is not one the e-mail names (the API's store rule)
	for _, tc := range []struct {
		finish   inventory.DeploymentFinish
		template string
	}{
		{inventory.DeploymentFinish{Status: inventory.DeployStatusRollbackFailed, Result: "rollback_failed", FailedStep: "restore",
			ErrorCode: "windows.backup_missing"}, inventory.TemplateDeploymentRollbackFailed},
		{inventory.DeploymentFinish{Status: inventory.DeployStatusRollbackFailed, ErrorCode: "deployment.outcome_unknown"},
			inventory.TemplateDeploymentOutcomeUnknown},
		{inventory.DeploymentFinish{Status: inventory.DeployStatusRollbackFailed, Result: "rollback_failed", Phase: providers.PhaseRestored,
			FailedStep: "verify_old", ErrorCode: "deployment.rollback_failed"}, inventory.TemplateDeploymentRestoredUnverified},
	} {
		r := f.request(f.rdp)
		f.start(r.ID, nil)
		require.NoError(t, h.svc.FinishDeployment(h.ctx, r.ID, tc.finish))
		want := base(r.ID)
		want["previous_certificate"] = prev
		mails := f.deploymentMails(r.ID)
		assert.Equal(t, []queuedMail{{inventory.WindowsRDPTemplate(tc.template), want}}, mails, tc.template)
	}

	r := f.request(f.rdp)
	require.NoError(t, h.svc.FinishDeployment(h.ctx, r.ID, inventory.DeploymentFinish{Status: inventory.DeployStatusFailed,
		ErrorCode: "windows.rdp_disabled"}))
	want := base(r.ID)
	want["windows_note"] = "rdp"
	assert.Equal(t, []queuedMail{{inventory.WindowsTemplate(inventory.TemplateDeploymentFailed), want}}, f.deploymentMails(r.ID))

	// A restore whose revoke of the NETWORK SERVICE ACE failed (the restore step's param).
	r2 := f.request(f.rdp)
	f.start(r2.ID, nil)
	require.NoError(t, h.svc.RecordDeploymentStep(h.ctx, r2.ID, providers.StepNameRestore, providers.StepOK,
		map[string]string{"rdp_key_acl_left": "true"}))
	require.NoError(t, h.svc.FinishDeployment(h.ctx, r2.ID, inventory.DeploymentFinish{Status: inventory.DeployStatusRollbackFailed,
		Result: "rollback_failed", Phase: providers.PhaseRestored, FailedStep: "verify_old", ErrorCode: "deployment.rollback_failed"}))
	want = base(r2.ID)
	want["previous_certificate"] = prev
	want["rdp_key_acl_left"] = "true"
	assert.Equal(t, []queuedMail{{inventory.WindowsRDPTemplate(inventory.TemplateDeploymentRestoredUnverified), want}},
		f.deploymentMails(r2.ID))
	d, err := h.svc.Deployment(h.ctx, r2.ID)
	require.NoError(t, err)
	var kept map[string]string
	for _, st := range d.Steps {
		if st.Name == providers.StepNameRestore {
			kept = st.Params
		}
	}
	assert.Equal(t, "true", kept["rdp_key_acl_left"], "the step param is kept")
}

// Ruling 7 (Q7): an incident's place on the RDP listener queues the incident cleanup of its server once it settles.
func TestRDPIncidentQueuesCleanup(t *testing.T) {
	f := newRDPFixture(t)
	h := f.h
	h.installLicense("LIC-INCIDENT-RDP", 5, 365)
	require.NoError(t, h.lic.Tick(h.ctx))
	_, _, err := h.svc.UploadCertificate(h.ctx, f.admin, pemUpload(f.old))
	require.NoError(t, err)
	var old uuid.UUID
	require.NoError(t, h.db.Owner.QueryRow(h.ctx, "SELECT id FROM certificates WHERE fingerprint_sha256 = $1", pki.Fingerprint(f.old.Cert)).Scan(&old))
	i, err := h.svc.StartIncident(h.ctx, f.admin, old, inventory.IncidentInput{})
	require.NoError(t, err)
	require.Equal(t, "pending", locationStatus(i)[f.rdp], "the RDP listener is a place Alice replaces")
	key := "windows.cleanup:" + f.server.String() + ":incident:" + i.ID.String() + ":" + f.rdp.String()
	queued := func() bool {
		for _, r := range h.jobs.requests() {
			if r.Type == inventory.JobWindowsCleanup && r.DedupeKey == key {
				return true
			}
		}
		return false
	}
	_, err = h.svc.ChooseIncidentReplacement(h.ctx, f.admin, i.ID, f.cert.ID)
	require.NoError(t, err)
	_, err = h.svc.AdvanceIncidents(h.ctx)
	require.NoError(t, err)
	i, err = h.svc.GetIncident(h.ctx, i.ID)
	require.NoError(t, err)
	dep := incidentLocation(t, i, f.rdp).DeploymentID
	require.NotNil(t, dep)
	assert.False(t, queued(), "nothing before the place settles")
	_, err = h.db.Owner.Exec(h.ctx, `UPDATE deployments SET state = 'done', status = 'succeeded', verified = 'remote', finished_at = $2 WHERE id = $1`,
		*dep, h.clock.Now())
	require.NoError(t, err)
	_, err = h.svc.AdvanceIncidents(h.ctx)
	require.NoError(t, err)
	assert.True(t, queued(), "the settled RDP place queues its server's cleanup")
}

// Ruling 20: the observation of the RDP listener reads its warning win_rdp_autoenroll (the drift e-mail's note).
func TestRDPObservationReadsAutoenroll(t *testing.T) {
	f := newRDPFixture(t)
	h := f.h
	o, err := h.svc.LocationObservation(h.ctx, f.rdp)
	require.NoError(t, err)
	assert.False(t, o.RDPAutoenroll())
	assert.False(t, o.AutoCertRebind)
	_, err = h.db.Owner.Exec(h.ctx, "UPDATE certificate_locations SET warnings = ARRAY['win_rdp_autoenroll'] WHERE id = $1", f.rdp)
	require.NoError(t, err)
	o, err = h.svc.LocationObservation(h.ctx, f.rdp)
	require.NoError(t, err)
	assert.True(t, o.RDPAutoenroll())
}

// Final review I1 (Rulings 3 and 16 amended): the listener's port is a detail, not its identity. A scan that reports
// another port updates the same row's details; it is never skipped as a locator conflict.
func TestRDPPortChangeUpdatesTheLocation(t *testing.T) {
	f := newRDPFixture(t)
	assert.InDelta(t, 3389, f.details()["port"], 0)
	sum := f.scan(13389)
	assert.Zero(t, sum.SkippedLocations)
	assert.Equal(t, 1, sum.Locations)
	assert.Zero(t, sum.NewLocations)
	locs := byPath(t, f.h, f.server, false)
	require.Len(t, locs, 1)
	assert.Equal(t, f.rdp, locs["rdp/RDP-Tcp"].ID, "the same row")
	assert.InDelta(t, 13389, f.details()["port"], 0)
	var locator []byte
	require.NoError(t, f.h.db.Owner.QueryRow(f.h.ctx, "SELECT locator FROM certificate_locations WHERE id = $1", f.rdp).Scan(&locator))
	assert.JSONEq(t, `{"type":"rdp","listener":"RDP-Tcp"}`, string(locator))
}
