//go:build integration

package inventory_test

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"alice/internal/inventory"
	"alice/internal/platform/validate"
	"alice/internal/providers"
	"alice/internal/testutil/pki"
)

// driftFixture is the ACME deployment world with one ACME certificate issued and bound to web-01's www.crt (loc1),
// deployed there once (a person's Deploy now, finished succeeded): the location's desired certificate is cur, and what
// another tool puts back is the old certificate the fixture's servers held before (oldFP).
type driftFixture struct {
	*acmeDeployWorld
	acme         inventory.ACMECertificate
	cur          uuid.UUID
	curFP, oldFP string
}

// newDriftFixture binds with automatic deployment on (the default repair mode is then auto) or off (observe).
func newDriftFixture(t *testing.T, auto bool) *driftFixture {
	t.Helper()
	w := newACMEDeployWorld(t)
	c, cur := w.issued("www.example.test")
	w.bind(c, auto, w.loc1)
	f := &driftFixture{acmeDeployWorld: w, acme: c, cur: cur, oldFP: pki.Fingerprint(w.old.Cert)}
	require.NoError(t, w.h.db.Owner.QueryRow(w.h.ctx, "SELECT fingerprint_sha256 FROM certificates WHERE id = $1", cur).Scan(&f.curFP))
	got, err := w.h.svc.DeployACMENow(w.h.ctx, w.operator, c.ID, inventory.ACMEDeployInput{LocationIDs: []uuid.UUID{w.loc1}})
	require.NoError(t, err)
	require.Len(t, got, 1)
	w.finish(got[0].ID, inventory.DeployStatusSucceeded, "")
	w.h.clock.Advance(time.Minute)
	return f
}

// served is a probe of loc1 that completed a handshake and found fp, now.
func (f *driftFixture) served(fp string) inventory.DriftResult {
	return inventory.DriftResult{LocationID: f.loc1, At: f.h.clock.Now(), Reached: true, Served: fp, Probe: inventory.DriftProbeAlice,
		Level: 2, Trust: providers.TrustTrusted}
}

// record stores the results as web-01's observation job and returns how many locations drifted.
func (f *driftFixture) record(results ...inventory.DriftResult) int {
	f.h.t.Helper()
	n, err := f.h.svc.RecordDriftObservations(f.h.ctx, f.target1, results)
	require.NoError(f.h.t, err)
	return n
}

func (f *driftFixture) observation() inventory.LocationObservation {
	f.h.t.Helper()
	o, err := f.h.svc.LocationObservation(f.h.ctx, f.loc1)
	require.NoError(f.h.t, err)
	return o
}

// scanFile is a discovery of web-01 that reads leaf in www.crt (b.crt keeps the old certificate).
func (f *driftFixture) scanFile(leaf pki.Leaf) {
	f.h.t.Helper()
	_, err := f.h.svc.Reconcile(f.h.ctx, f.target1, providers.DiscoveryResult{WebServer: nginxOK, Certificates: []providers.DiscoveredCertificate{
		dc(cl("/etc/nginx/ssl/www.crt", "/etc/nginx/ssl/www.key", "www.example.test"), leaf),
		dc(cl("/etc/nginx/ssl/b.crt", "/etc/nginx/ssl/b.key", "www.example.test"), f.old)}})
	require.NoError(f.h.t, err)
}

func (f *driftFixture) setMode(mode string) inventory.LocationObservation {
	f.h.t.Helper()
	require.NoError(f.h.t, f.h.lic.Tick(f.h.ctx))
	o, err := f.h.svc.SetDriftMode(f.h.ctx, f.admin, f.loc1, mode, true)
	require.NoError(f.h.t, err)
	return o
}

// outboxParams are the params of the e-mails of template, oldest first.
func (f *driftFixture) outboxParams(template string) []map[string]string {
	f.h.t.Helper()
	rows, err := f.h.db.Owner.Query(f.h.ctx, "SELECT params FROM notifications_outbox WHERE template_key = $1 ORDER BY created_at, id", template)
	require.NoError(f.h.t, err)
	defer rows.Close()
	var out []map[string]string
	for rows.Next() {
		var raw []byte
		require.NoError(f.h.t, rows.Scan(&raw))
		var p map[string]string
		require.NoError(f.h.t, json.Unmarshal(raw, &p))
		out = append(out, p)
	}
	require.NoError(f.h.t, rows.Err())
	return out
}

// R52 item 3: the schedule queues one observation per server whose bound locations are due, stamps the next one a full
// interval later, never observes an unbound location and removes the rows of locations no longer bound; the probes of
// a server are its bound locations' verification requests of the desired certificate with the ACME authority's trust.
func TestDriftScheduleAndProbes(t *testing.T) {
	f := newDriftFixture(t, true)
	h := f.h
	_, err := h.db.Owner.Exec(h.ctx, "INSERT INTO location_observations (location_id, updated_at) VALUES ($1, $2)", f.loc5, h.clock.Now())
	require.NoError(t, err)

	before := len(h.jobs.requests())
	n, err := h.svc.ScheduleDriftObservations(h.ctx)
	require.NoError(t, err)
	assert.Equal(t, 1, n, "one job for web-01, none for web-02 (no bound location)")
	reqs := h.jobs.requests()[before:]
	require.Len(t, reqs, 1)
	assert.Equal(t, inventory.JobRequest{Type: inventory.JobDriftObserve, TargetID: f.target1, Payload: map[string]string{}, Kind: "scheduled",
		DedupeKey: inventory.JobDriftObserve + ":" + f.target1.String()}, reqs[0])
	assert.Zero(t, h.count("SELECT count(*) FROM location_observations WHERE location_id = $1", f.loc5), "an unbound location's row is removed")
	var next time.Time
	require.NoError(t, h.db.Owner.QueryRow(h.ctx, "SELECT next_observe_at FROM location_observations WHERE location_id = $1", f.loc1).Scan(&next))
	assert.False(t, next.Before(h.clock.Now().Add(inventory.DriftObserveInterval)))
	assert.True(t, next.Before(h.clock.Now().Add(inventory.DriftObserveInterval+inventory.DriftObserveInterval/10)), "spread within a tenth")
	o := f.observation()
	require.NotNil(t, o.NextObserveAt)
	assert.Equal(t, next.UTC(), *o.NextObserveAt)

	_, err = h.db.Owner.Exec(h.ctx, "UPDATE jobs SET status = 'succeeded', finished_at = $1 WHERE type = $2", h.clock.Now(), inventory.JobDriftObserve)
	require.NoError(t, err)
	n, err = h.svc.ScheduleDriftObservations(h.ctx)
	require.NoError(t, err)
	assert.Zero(t, n, "not due yet")
	h.clock.Advance(inventory.DriftObserveInterval + time.Hour)
	n, err = h.svc.ScheduleDriftObservations(h.ctx)
	require.NoError(t, err)
	assert.Equal(t, 1, n, "due again")

	_, err = h.db.Owner.Exec(h.ctx, "UPDATE certificate_locations SET verify_port = 8443, verify_sni = 'check.example.test' WHERE id = $1", f.loc1)
	require.NoError(t, err)
	probes, err := h.svc.DriftProbes(h.ctx, f.target1)
	require.NoError(t, err)
	require.Len(t, probes, 1)
	p := probes[0]
	assert.Equal(t, 8443, p.Request.Verify.Port, "the location's verification settings")
	assert.Equal(t, "check.example.test", p.Request.Verify.SNI)
	assert.Equal(t, f.loc1, p.LocationID)
	assert.Equal(t, f.curFP, p.Request.Fingerprint, "the desired leaf is expected")
	assert.Equal(t, "/etc/nginx/ssl/www.crt", p.Request.Location.CertPath)
	assert.True(t, p.Request.Location.Supported)
	assert.NotEmpty(t, p.Request.Location.Servers)
	assert.Equal(t, "ecdsa", p.Request.KeyType)
	assert.Equal(t, []string{"www.example.test"}, p.Request.SANs)
	require.NotNil(t, p.Request.Trust)
	assert.Equal(t, providers.TrustStoreACME, p.Request.Trust.Store, "the issuing authority's bundle")
	assert.True(t, p.Request.Trust.Enforce, "the provider's bundle holds the issuing root")

	probes, err = h.svc.DriftProbes(h.ctx, f.target2)
	require.NoError(t, err)
	assert.Empty(t, probes, "web-02 has no bound location")
}

// R52 items 1-3, mode observe: a skipped verification and a probe that completed no handshake are stored without a drift
// (an unreachable website, its reason closed); a result of another server's location or of an unbound location is
// dropped; another leaf served starts one drift episode with its audit row and one notice naming both certificates; a
// person's repair (Deploy now) that the next probe confirms ends it without the "repaired" notice.
func TestDriftObservedInModeObserve(t *testing.T) {
	f := newDriftFixture(t, true)
	h := f.h
	o := f.observation()
	assert.Equal(t, inventory.DriftModeAuto, o.Mode, "automatic deployment on: auto by default")
	assert.Equal(t, inventory.DriftModeAuto, o.DefaultMode)
	assert.Equal(t, inventory.DriftSourceACME, o.Source)
	require.NotNil(t, o.SourceID)
	assert.Equal(t, f.acme.ID, *o.SourceID)
	require.NotNil(t, o.Desired)
	assert.Equal(t, f.curFP, o.Desired.Fingerprint)
	require.NotNil(t, o.LastDeployment)
	assert.Equal(t, providers.LevelServed, o.LastDeployment.Level, "verified remote, trust not recorded")
	assert.Equal(t, inventory.HealthInSync, o.Health, "deployed a minute ago")

	o = f.setMode(inventory.DriftModeObserve)
	assert.Equal(t, inventory.DriftModeObserve, o.Mode)
	assert.Equal(t, inventory.DriftModeObserve, o.ModeSetting)
	changed := h.auditDetails("location.drift_mode_changed")
	require.Len(t, changed, 1)
	assert.Equal(t, map[string]string{"location_id": f.loc1.String(), "cert_path": "/etc/nginx/ssl/www.crt", "mode": "observe",
		"effective_mode": "observe", "previous_mode": "auto"}, changed[0])

	h.clock.Advance(time.Minute)
	assert.Zero(t, f.record(inventory.DriftResult{LocationID: f.loc1, At: h.clock.Now(), Skipped: true}))
	o = f.observation()
	require.NotNil(t, o.TLSAttemptAt)
	assert.Equal(t, h.clock.Now(), *o.TLSAttemptAt)
	assert.Empty(t, o.TLSError)
	assert.Nil(t, o.TLS, "a skipped verification says nothing of the website")

	h.clock.Advance(time.Minute)
	assert.Zero(t, f.record(inventory.DriftResult{LocationID: f.loc1, At: h.clock.Now(), Error: "Not A Code!"}))
	o = f.observation()
	assert.Equal(t, inventory.HealthUnreachable, o.Health)
	assert.Equal(t, "internal.unexpected", o.TLSError, "a reason outside the closed shape is stored as unexpected")

	// Dropped: loc1 reported by web-02's job, an unbound location of web-01, a location that does not exist.
	h.clock.Advance(time.Minute)
	n, err := h.svc.RecordDriftObservations(h.ctx, f.target2, []inventory.DriftResult{f.served(f.oldFP)})
	require.NoError(t, err)
	assert.Zero(t, n)
	unbound := f.served(f.oldFP)
	unbound.LocationID = f.loc5
	missing := f.served(f.oldFP)
	missing.LocationID = uuid.New()
	assert.Zero(t, f.record(unbound, missing))
	assert.Nil(t, f.observation().TLS, "nothing was stored for loc1")
	assert.Zero(t, h.count("SELECT count(*) FROM location_observations WHERE location_id = $1", f.loc5))

	// Another leaf served: the drift starts.
	h.clock.Advance(time.Minute)
	drift := f.served(f.oldFP)
	drift.Trust, drift.TrustError = providers.TrustUntrusted, providers.TrustErrUnknownAuthority
	assert.Equal(t, 1, f.record(drift))
	o = f.observation()
	assert.Equal(t, inventory.HealthDrifted, o.Health)
	require.NotNil(t, o.DriftSince)
	assert.Equal(t, h.clock.Now(), *o.DriftSince)
	assert.Equal(t, "tls", o.DriftSource)
	assert.Equal(t, f.oldFP, o.DriftFingerprint)
	require.NotNil(t, o.TLS)
	assert.Equal(t, f.oldFP, o.TLS.Fingerprint)
	assert.Equal(t, providers.TrustUntrusted, o.TLS.Trust)
	assert.Equal(t, providers.TrustErrUnknownAuthority, o.TLS.TrustError)
	require.NotNil(t, o.TLS.CertificateID, "Alice holds the old certificate (discovered)")
	detected := h.auditDetails("location.drift_detected")
	require.Len(t, detected, 1)
	assert.Equal(t, map[string]string{"location_id": f.loc1.String(), "target_id": f.target1.String(), "cert_path": "/etc/nginx/ssl/www.crt",
		"desired_fingerprint": f.curFP, "observed_fingerprint": f.oldFP, "observed_by": "tls", "mode": "observe"}, detected[0])
	mails := f.outboxParams(inventory.TemplateDriftDetected)
	require.NotEmpty(t, mails)
	assert.Equal(t, "web-01", mails[0]["target_name"])
	assert.Equal(t, "/etc/nginx/ssl/www.crt", mails[0]["cert_path"])
	assert.Equal(t, "www.example.test", mails[0]["certificate_name"])
	assert.Equal(t, "www.example.test", mails[0]["observed_name"], "the old certificate's subject name")
	sent := len(mails)
	assert.Equal(t, 1, h.count("SELECT count(*) FROM alerts WHERE kind = 'location_drift' AND object_id = $1", f.loc1))

	h.clock.Advance(2 * time.Hour)
	assert.Equal(t, 1, f.record(f.served(f.oldFP)), "still drifted")
	assert.Len(t, f.outboxParams(inventory.TemplateDriftDetected), sent, "one notice per episode")
	assert.Equal(t, 1, h.audits("location.drift_detected"))

	// A person repairs it; the next probe finds the desired certificate.
	got, err := h.svc.RepairDrift(h.ctx, f.operator, f.loc1, true)
	require.NoError(t, err)
	require.Len(t, got, 1)
	assert.Equal(t, f.cur, f.deps(f.cur)[1].Certificate)
	assert.Equal(t, "manual", f.deps(f.cur)[1].Trigger, "the request path of the source: Deploy now")
	f.finish(got[0].ID, inventory.DeployStatusSucceeded, "")
	h.clock.Advance(time.Minute)
	assert.Zero(t, f.record(f.served(f.curFP)))
	o = f.observation()
	assert.Equal(t, inventory.HealthInSync, o.Health)
	assert.Nil(t, o.DriftSince)
	assert.Empty(t, o.DriftFingerprint)
	resolved := h.auditDetails("location.drift_resolved")
	require.Len(t, resolved, 1)
	assert.Equal(t, "false", resolved[0]["repaired_automatically"])
	assert.Zero(t, h.emails(inventory.TemplateDriftRepaired), "no automatic repair ended it")
	_, err = h.svc.RepairDrift(h.ctx, f.operator, f.loc1, true)
	assert.ErrorIs(t, err, inventory.ErrDriftNotDrifted)
	_, err = h.svc.RepairDrift(h.ctx, f.operator, uuid.New(), true)
	assert.ErrorIs(t, err, inventory.ErrNotFound)
}

// R52 item 4: the repair mode. An unknown mode is a validation error and an unknown location not found; observe and
// approve are anyone's who may change the location, a mode that becomes auto is an Administrator's with a fresh
// step-up; setting the mode a location already has changes nothing; default goes back to the binding's default. In mode
// approve a drift is mailed with the repair ready, naming a certificate Alice does not hold by its fingerprint.
func TestDriftModesAndTheApproveNotice(t *testing.T) {
	f := newDriftFixture(t, false)
	h := f.h
	_, err := h.svc.SetDriftMode(h.ctx, f.admin, f.loc1, "sometimes", true)
	var ve validate.Errors
	require.ErrorAs(t, err, &ve)
	assert.Equal(t, "mode", ve[0].Field)
	assert.Equal(t, "observe, approve, auto, default", ve[0].Params["values"])
	_, err = h.svc.SetDriftMode(h.ctx, f.admin, uuid.New(), inventory.DriftModeObserve, true)
	assert.ErrorIs(t, err, inventory.ErrNotFound)

	o := f.observation()
	assert.Equal(t, inventory.DriftModeObserve, o.Mode, "automatic deployment off: observe by default")
	assert.Empty(t, o.ModeSetting)
	o, err = h.svc.SetDriftMode(h.ctx, f.operator, f.loc1, inventory.DriftModeApprove, false)
	require.NoError(t, err)
	assert.Equal(t, inventory.DriftModeApprove, o.Mode)
	_, err = h.svc.SetDriftMode(h.ctx, f.operator, f.loc1, inventory.DriftModeApprove, false)
	require.NoError(t, err)
	assert.Equal(t, 1, h.audits("location.drift_mode_changed"), "nothing changed: no audit row")

	_, err = h.svc.SetDriftMode(h.ctx, f.operator, f.loc1, inventory.DriftModeAuto, true)
	assert.ErrorIs(t, err, inventory.ErrAdminRequired)
	_, err = h.svc.SetDriftMode(h.ctx, f.admin, f.loc1, inventory.DriftModeAuto, false)
	assert.ErrorIs(t, err, inventory.ErrAutoDeployNeedsStepUp)
	assert.Equal(t, inventory.DriftModeAuto, f.setMode(inventory.DriftModeAuto).Mode)
	o = f.setMode(inventory.DriftModeDefault)
	assert.Empty(t, o.ModeSetting)
	assert.Equal(t, inventory.DriftModeObserve, o.Mode)
	last := h.auditDetails("location.drift_mode_changed")
	assert.Equal(t, "default", last[len(last)-1]["mode"])
	assert.Equal(t, "observe", last[len(last)-1]["effective_mode"])
	f.setMode(inventory.DriftModeApprove)

	unknown := strings.Repeat("ab", 32)
	h.clock.Advance(time.Minute)
	assert.Equal(t, 1, f.record(f.served(unknown)))
	o = f.observation()
	assert.Equal(t, inventory.HealthDrifted, o.Health)
	require.NotNil(t, o.TLS)
	assert.Nil(t, o.TLS.CertificateID, "Alice does not hold it")
	mails := f.outboxParams(inventory.TemplateDriftRepairReady)
	require.NotEmpty(t, mails)
	assert.Equal(t, unknown[:16], mails[0]["observed_name"], "named by its fingerprint")
	assert.Zero(t, h.emails(inventory.TemplateDriftDetected))
	assert.Equal(t, "approve", h.auditDetails("location.drift_detected")[0]["mode"])

	assert.ElementsMatch(t, []string{inventory.TemplateDriftDetected, inventory.TemplateDriftRepairReady, inventory.TemplateDriftRepaired,
		inventory.TemplateDriftFlapping, inventory.TemplateDriftRepairFailing}, inventory.DriftTemplates())
}

// One observation job probes at most 20 locations of a server: the schedule stamps the 20 it took and leaves the
// others due for its next run.
func TestDriftScheduleTakesTwentyLocationsOfAServer(t *testing.T) {
	f := newDriftFixture(t, true)
	h := f.h
	f.bind(f.acme, true, f.moreLocations(20)...)
	n, err := h.svc.ScheduleDriftObservations(h.ctx)
	require.NoError(t, err)
	assert.Equal(t, 1, n)
	assert.Equal(t, 20, h.count("SELECT count(*) FROM location_observations WHERE next_observe_at IS NOT NULL"), "one bound location waits")
	probes, err := h.svc.DriftProbes(h.ctx, f.target1)
	require.NoError(t, err)
	assert.Len(t, probes, 20)
}

// A website that served a leaf Alice cannot name (no fingerprint the observation can hold) drifted: the notice says
// "-" for what it found. Lists of locations carry the observation of a bound location only, and an empty list none.
func TestDriftOfAnUnreadableLeafAndTheLists(t *testing.T) {
	f := newDriftFixture(t, false)
	h := f.h
	h.clock.Advance(time.Minute)
	assert.Equal(t, 1, f.record(f.served("not-a-fingerprint")))
	o := f.observation()
	assert.Equal(t, inventory.HealthDrifted, o.Health)
	require.NotNil(t, o.TLS)
	assert.Empty(t, o.TLS.Fingerprint)
	assert.Empty(t, o.DriftFingerprint)
	mails := f.outboxParams(inventory.TemplateDriftDetected)
	require.NotEmpty(t, mails)
	assert.Equal(t, "-", mails[0]["observed_name"])

	locs := byPath(t, h, f.target1, false)
	require.NotNil(t, locs["/etc/nginx/ssl/www.crt"].Observation)
	assert.Equal(t, inventory.HealthDrifted, locs["/etc/nginx/ssl/www.crt"].Observation.Health)
	assert.Nil(t, locs["/etc/nginx/ssl/b.crt"].Observation, "an unbound location has none")
	l, err := h.svc.GetLocation(h.ctx, f.loc1)
	require.NoError(t, err)
	require.NotNil(t, l.Observation)
	empty := nginxTarget(t, h, f.admin, "web-03")
	list, err := h.svc.ListLocations(h.ctx, empty.ID, true)
	require.NoError(t, err)
	assert.Empty(t, list.Items)
}
