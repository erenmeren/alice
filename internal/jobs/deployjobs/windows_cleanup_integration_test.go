//go:build integration

package deployjobs

import (
	"context"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"alice/internal/inventory"
	"alice/internal/providers"
	"alice/internal/providers/windows/winproto"
	"alice/internal/providers/windows/wintest"
	"alice/internal/testutil/pki"
)

// R62 W3 (Rulings 4-13): the certificate cleanup of a Windows server through the real job engine (windows.cleanup on the
// runner, Alice's judgement in inventory on PostgreSQL) against the emulated server (the helper's own code on wintest's
// modelled host). Alice's clock is the fake clock every service reads (the rollback window compares a deployment's
// finished_at with it); the helper's clock is the model's (SetNow, Advance). Each test moves both, or one of them.

// advanceBoth moves Alice's clock and the helper's by d.
func (e *env) advanceBoth(s *winServer, d time.Duration) {
	e.clock.Advance(d)
	s.model.Advance(d)
}

// ACCEPTANCE item 2. A renewal deploys C3 over C2. The day it is replaced the helper starts counting; six days later
// nothing is removed: the helper's age is not reached (too_young), and with the helper's clock two days ahead Alice's
// rollback window still holds it (rollback_window). Eight days after the renewal, on both clocks, the cleanup removes C2
// and its key from the store and audits it; C3 still serves and C1 (not Alice's) stays.
func TestWindowsCleanupAfterRenewal(t *testing.T) {
	w := newWinDriftWorld(t)
	_, c3 := w.renewEarly()
	c3SHA1 := w.win.bound()
	require.NotEqual(t, w.c2SHA1, c3SHA1)
	require.True(t, w.win.model.HasCertificate("My", w.c2SHA1), "the replaced certificate is still in the store")

	status, res := w.cleanupNow(w.win)
	require.Equal(t, "succeeded", status, "%v", res)
	assert.EqualValues(t, 1, res["candidates"], "C2: Alice imported it and nothing uses it")
	assert.EqualValues(t, 0, res["removed"], "the helper counts from today")

	w.advanceBoth(w.win, 6*24*time.Hour)
	status, res = w.cleanupNow(w.win)
	require.Equal(t, "succeeded", status, "%v", res)
	assert.EqualValues(t, 1, res["candidates"])
	assert.EqualValues(t, 0, res["removed"], "%v", res)
	assert.Empty(t, keptReasons(res), "the helper's wait: Alice is not asked")
	v := w.helperVerdict(w.win, "My", w.c2SHA1, w.c2)
	assert.Equal(t, providers.CleanupItemResult{SHA256: w.c2, Result: providers.CleanupKept, Reason: winproto.KeptTooYoung}, v)

	w.win.model.Advance(2 * 24 * time.Hour) // the helper's clock alone: its age is reached, Alice's window is not over
	status, res = w.cleanupNow(w.win)
	require.Equal(t, "succeeded", status, "%v", res)
	assert.EqualValues(t, 0, res["removed"], "%v", res)
	assert.Equal(t, map[string]string{w.c2: inventory.CleanupKeptRollbackWindow}, keptReasons(res))
	assert.True(t, w.win.model.HasCertificate("My", w.c2SHA1))
	assert.Zero(t, w.audits("windows.certificate_removed"))

	w.clock.Advance(2 * 24 * time.Hour) // Alice's clock: eight days after the renewal
	status, res = w.cleanupNow(w.win)
	require.Equal(t, "succeeded", status, "%v", res)
	assert.EqualValues(t, 1, res["removed"], "%v", res)
	assert.Empty(t, keptReasons(res))
	assert.False(t, w.win.model.HasCertificate("My", w.c2SHA1), "C2 is removed")
	assert.False(t, w.win.model.HasKey("My", w.c2SHA1), "with its key")
	assert.True(t, w.win.model.HasCertificate("My", w.win.oldSHA1), "C1 was not imported by Alice")
	assert.Equal(t, c3SHA1, w.win.bound(), "the binding names C3")
	assert.Equal(t, c3, w.win.served(), "C3 still serves")
	var details map[string]string
	require.NoError(t, w.db.Owner.QueryRow(w.ctx, "SELECT details FROM audit_log WHERE action = 'windows.certificate_removed'").Scan(&details))
	delete(details, "service_id")
	assert.Equal(t, map[string]string{"store": "My", "sha1": w.c2SHA1, "sha256": w.c2, "reason": winproto.CleanupAged}, details)
	assert.Equal(t, 1, w.audits("windows.certificate_removed"))
}

// cleanWith runs before right before every ApplyCleanup of the sessions opened from now on: what changes on the server
// between the plan and the apply.
type cleanWith struct {
	providers.Session
	before func()
}

func (s cleanWith) PlanCleanup(ctx context.Context, watch []providers.CleanupRef) (providers.CleanupPlan, error) {
	return s.Session.(providers.CertificateCleaner).PlanCleanup(ctx, watch)
}

func (s cleanWith) ApplyCleanup(ctx context.Context, items []providers.CleanupItem) (providers.CleanupApplyResult, error) {
	s.before()
	return s.Session.(providers.CertificateCleaner).ApplyCleanup(ctx, items)
}

// Review Focus 1, ACCEPTANCE item 2. C2, which Alice imported and replaced with C3 eight days ago (both clocks), would
// be removed; but while anything on the server uses it, or a third party's copy is what the store holds, the cleanup
// removes nothing and the helper keeps it with the matching reason: an http.sys record of another application binds it,
// the RDP listener or a WinRM HTTPS listener names it, a writing journal names it (a deployment killed at deploy.writing
// and not recovered yet), a third party imported its own copy, or another application binds it between the plan and the
// apply (the helper judges again under its lock).
func TestWindowsCleanupKeepsRows(t *testing.T) {
	foreign := func(s *winServer, sha1 string) {
		s.model.AddBinding(winproto.SSLBinding{Type: winproto.BindingIPPort, IP: "0.0.0.0", Port: 8443, AppID: "{afebb9ad-9b97-4a91-9ab5-daf4d59122f6}",
			CertSHA1: sha1, Store: "My"})
	}
	for _, tc := range []struct {
		name   string
		setup  func(e *env, s *winServer, c2SHA1 string)
		race   bool // setup runs between the plan and the apply
		reason string
	}{
		{"bound by another application's record", func(_ *env, s *winServer, c2 string) { foreign(s, c2) }, false, winproto.KeptBound},
		{"named by the RDP listener", func(_ *env, s *winServer, c2 string) {
			s.model.SetRDP(wintest.RDPConfig{Present: true, Enabled: true, NLA: true, Port: 3389, SecurityLayer: 2})
			s.model.SetRDPThumbprint(c2)
		}, false, winproto.KeptRDP},
		{"named by a WinRM listener", func(_ *env, s *winServer, c2 string) { s.model.SetWinRMThumbprints(c2) }, false, winproto.KeptWinRM},
		{"named by a writing journal", func(e *env, s *winServer, _ string) {
			s.model.KillAt("deploy.writing")
			id := e.request(s.loc)[0] // C2 again, over C3
			e.drain()
			require.Equal(e.t, inventory.DeployStateRecovering, e.deployment(id).State, "killed, not recovered")
			require.Equal(e.t, winproto.PhaseWriting, s.phase(e.t, id))
		}, false, winproto.KeptJournal},
		{"imported by a third party", func(e *env, s *winServer, c2 string) {
			s.model.RemoveCertificate("My", c2)
			require.Equal(e.t, c2, s.model.AddCertificate("My", e.nw.CertPEM, e.nw.KeyPEM, wintest.CertOptions{FriendlyName: "someone else"}))
		}, false, winproto.KeptNotAlice},
		{"bound by another application between the plan and the apply", func(_ *env, s *winServer, c2 string) { foreign(s, c2) }, true,
			winproto.KeptBound},
	} {
		t.Run(tc.name, func(t *testing.T) {
			e, s := newWinCleanupEnv(t)
			c2 := pki.Fingerprint(e.nw.Cert)
			require.Equal(t, inventory.DeployStatusSucceeded, e.settle(e.request(s.loc)[0]).Status)
			c2SHA1 := s.bound()
			c3 := e.ca.Issue(pki.Opts{CommonName: wwwName, SANs: []string{wwwName}}, e.clock.Now())
			e.deployLeaf(s, c3)
			status, res := e.cleanupNow(s)
			require.Equal(t, "succeeded", status, "%v", res)
			require.EqualValues(t, 1, res["candidates"], "C2 is unbound from today")

			e.advanceBoth(s, 8*24*time.Hour)
			if tc.race {
				e.setWrap(func(_ providers.TargetRef, sess providers.Session) providers.Session {
					return cleanWith{Session: sess, before: func() { tc.setup(e, s, c2SHA1) }}
				})
			} else {
				tc.setup(e, s, c2SHA1)
			}
			status, res = e.cleanupNow(s)
			e.setWrap(nil)
			require.Equal(t, "succeeded", status, "%v", res)
			assert.EqualValues(t, 0, res["removed"], "%v", res)
			if tc.race {
				assert.EqualValues(t, 1, res["candidates"], "unused when planned")
				assert.Equal(t, map[string]string{c2: tc.reason}, keptReasons(res), "the helper's apply kept it")
			} else {
				assert.EqualValues(t, 0, res["candidates"], "%v", res)
			}
			assert.True(t, s.model.HasCertificate("My", c2SHA1), "still in the store")
			assert.True(t, s.model.HasKey("My", c2SHA1), "with its key")
			assert.Zero(t, e.audits("windows.certificate_removed"))
			assert.Equal(t, providers.CleanupItemResult{SHA256: c2, Result: providers.CleanupKept, Reason: tc.reason},
				e.helperVerdict(s, "My", c2SHA1, c2), "the helper's reason")
		})
	}
}

// R62 W3 Ruling 9 (§15 Q7). Alice deployed C2; its key is compromised and the incident replaces it with C3 on the
// binding. Once the replacement verified, the cleanup the incident queued removes Alice's C2 at once (no age, no
// rollback window: nothing may roll back to it), key first, audited with the incident. A copy of C2 the test imported
// into another store without Alice's name is not hers: it stays, and the services are told once.
func TestWindowsIncidentRemovesTheCompromisedCertificate(t *testing.T) {
	e, s := newWinCleanupEnv(t)
	c2 := e.upload()
	require.Equal(t, inventory.DeployStatusSucceeded, e.settle(e.request(s.loc)[0]).Status)
	c2SHA1 := s.bound()
	require.Equal(t, c2SHA1, s.model.AddCertificate("WebHosting", e.nw.CertPEM, e.nw.KeyPEM, wintest.CertOptions{FriendlyName: "someone else"}))
	l3 := e.ca.Issue(pki.Opts{CommonName: wwwName, SANs: []string{wwwName, apiName}}, e.clock.Now())
	c3, _, err := e.inv.UploadCertificate(e.ctx, e.admin, inventory.UploadInput{CertificatePEM: string(l3.FullchainPEM), PrivateKeyPEM: string(l3.KeyPEM)})
	require.NoError(t, err)

	i := e.windowsIncident(s, c2, c3, nil)
	assert.Equal(t, thumbprintOf(l3.Cert.Raw), s.bound(), "C3 is bound")
	assert.Equal(t, pki.Fingerprint(l3.Cert), s.served())
	assert.False(t, s.model.HasCertificate("My", c2SHA1), "Alice's C2 is removed at once")
	assert.False(t, s.model.HasKey("My", c2SHA1), "with its key")
	assert.True(t, s.model.HasCertificate("WebHosting", c2SHA1), "the copy Alice did not import stays")
	assert.True(t, s.model.HasKey("WebHosting", c2SHA1))
	assert.True(t, s.model.HasCertificate("My", s.oldSHA1), "C1 is neither compromised nor Alice's")
	var details map[string]string
	require.NoError(t, e.db.Owner.QueryRow(e.ctx, "SELECT details FROM audit_log WHERE action = 'windows.certificate_removed'").Scan(&details))
	delete(details, "service_id")
	assert.Equal(t, map[string]string{"store": "My", "sha1": c2SHA1, "sha256": c2.Fingerprint, "reason": winproto.CleanupIncident,
		"incident_id": i.ID.String()}, details)
	assert.Equal(t, 1, e.audits("windows.certificate_removed"))

	var store string
	require.NoError(t, e.db.Owner.QueryRow(e.ctx, `SELECT params->>'store' FROM notifications_outbox WHERE template_key = $1
    AND params->>'thumbprint' = $2 AND params->>'incident_id' = $3`, inventory.TemplateWindowsCompromisedInStore, c2SHA1, i.ID.String()).Scan(&store))
	assert.Equal(t, "WebHosting", store, "one notice, naming the store that still holds it")
	assert.Equal(t, 1, e.count("SELECT count(*) FROM notifications_outbox WHERE template_key = $1", inventory.TemplateWindowsCompromisedInStore))

	// A later run (the next day's) removes nothing more and tells nobody again.
	e.advanceBoth(s, 24*time.Hour)
	status, res := e.cleanupNow(s)
	require.Equal(t, "succeeded", status, "%v", res)
	assert.EqualValues(t, 0, res["removed"], "%v", res)
	assert.True(t, s.model.HasCertificate("WebHosting", c2SHA1))
	assert.Equal(t, 1, e.count("SELECT count(*) FROM notifications_outbox WHERE template_key = $1", inventory.TemplateWindowsCompromisedInStore))
}

// deployLeaf uploads l with its key and deploys it to the server's binding through the deployment engine.
func (e *env) deployLeaf(s *winServer, l pki.Leaf) inventory.Deployment {
	e.t.Helper()
	c, _, err := e.inv.UploadCertificate(e.ctx, e.admin, inventory.UploadInput{CertificatePEM: string(l.FullchainPEM), PrivateKeyPEM: string(l.KeyPEM)})
	require.NoError(e.t, err)
	e.evaluate()
	got, err := e.inv.RequestDeployment(e.ctx, e.admin, inventory.DeployRequestInput{CertificateID: c.ID, LocationIDs: []uuid.UUID{s.loc}})
	require.NoError(e.t, err)
	require.Len(e.t, got, 1)
	d := e.settle(got[0].ID)
	require.Equal(e.t, inventory.DeployStatusSucceeded, d.Status, "%s %v", d.ErrorCode, d.ErrorParams)
	assert.Equal(e.t, thumbprintOf(l.Cert.Raw), s.bound())
	return d
}
