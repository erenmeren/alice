//go:build integration

package inventory_test

import (
	"crypto/x509"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"alice/internal/inventory"
	"alice/internal/jobs"
	"alice/internal/providers"
	"alice/internal/providers/windows/winproto"
	"alice/internal/rbac"
	"alice/internal/testutil/pki"
)

// R62 W3 Task 7: Alice's half of the Windows certificate cleanup (Rulings 8, 9, 12, 13): the judgement of a plan, the
// watch list of compromised certificates, the daily schedule and the record of what was removed.

// cleanupFixture: two connected Windows servers (iis-01 with the bindings 443 and 8443 holding cur and 9443 holding held,
// a binding 10443 that went missing; iis-02 with 443 holding cur), the real queue behind the recorder.
type cleanupFixture struct {
	h                      *harness
	admin                  inventory.Actor
	ca                     *pki.CA
	cur                    pki.Leaf
	curCert                inventory.Certificate
	win, win2              uuid.UUID
	loc1, loc2, loc3, loc4 uuid.UUID
}

func newCleanupFixture(t *testing.T, held, missing pki.Leaf) *cleanupFixture {
	t.Helper()
	ca := pki.NewCA("Cleanup", pki.ECDSA256, start)
	roots := x509.NewCertPool()
	roots.AddCert(ca.Root)
	h := newHarness(t, withWindowsProvider(), withRoots(roots))
	h.jobs.next = jobs.NewQueue(jobs.QueueConfig{Pool: h.db.App, Keyring: h.keyring, Audit: h.audit, Clock: h.clock, Gate: h.lic})
	f := &cleanupFixture{h: h, ca: ca, admin: h.user("ada", rbac.Admin, "ada@example.com")}
	f.cur = f.issue("cur")
	f.win, f.win2 = winTarget(t, h, f.admin, "iis-01").ID, winTarget(t, h, f.admin, "iis-02").ID
	_, err := h.svc.Reconcile(h.ctx, f.win, providers.DiscoveryResult{WebServer: iisOK, Certificates: []providers.DiscoveredCertificate{
		winBinding(443, "A", &f.cur), winBinding(8443, "B", &f.cur), winBinding(9443, "C", &held), winBinding(10443, "D", &missing)}})
	require.NoError(t, err)
	_, err = h.svc.Reconcile(h.ctx, f.win, providers.DiscoveryResult{WebServer: iisOK, Certificates: []providers.DiscoveredCertificate{
		winBinding(443, "A", &f.cur), winBinding(8443, "B", &f.cur), winBinding(9443, "C", &held)}})
	require.NoError(t, err)
	locs := byPath(t, h, f.win, false)
	require.Len(t, locs, 3, "10443 is missing")
	f.loc1, f.loc2, f.loc3 = locs["http.sys/ipport/0.0.0.0:443"].ID, locs["http.sys/ipport/0.0.0.0:8443"].ID, locs["http.sys/ipport/0.0.0.0:9443"].ID
	_, err = h.svc.Reconcile(h.ctx, f.win2, providers.DiscoveryResult{WebServer: iisOK, Certificates: []providers.DiscoveredCertificate{
		winBinding(443, "A", &f.cur)}})
	require.NoError(t, err)
	f.loc4 = byPath(t, h, f.win2, false)["http.sys/ipport/0.0.0.0:443"].ID
	f.curCert = f.certOf(f.cur)
	return f
}

// issue is a new leaf of the fixture's CA, stored in Alice with its key.
func (f *cleanupFixture) issue(name string) pki.Leaf {
	f.h.t.Helper()
	l := f.ca.Issue(pki.Opts{CommonName: name + ".example.test", SANs: []string{name + ".example.test"}}, f.h.clock.Now())
	_, _, err := f.h.svc.UploadCertificate(f.h.ctx, f.admin, pemUpload(l))
	require.NoError(f.h.t, err)
	return l
}

func (f *cleanupFixture) certOf(l pki.Leaf) inventory.Certificate {
	f.h.t.Helper()
	var id uuid.UUID
	require.NoError(f.h.t, f.h.db.Owner.QueryRow(f.h.ctx, "SELECT id FROM certificates WHERE fingerprint_sha256 = $1", derSHA(l)).Scan(&id))
	c, err := f.h.svc.GetCertificate(f.h.ctx, id)
	require.NoError(f.h.t, err)
	return c
}

// deployment inserts, as the owner, a Windows deployment of target at loc replacing prev with nw: finished at the given
// instant, or unfinished (deploying) when finished is zero.
func (f *cleanupFixture) deployment(target, loc uuid.UUID, nw, prev string, finished time.Time) {
	f.h.t.Helper()
	state, status, created := "deploying", "running", f.h.clock.Now()
	var fin *time.Time
	if !finished.IsZero() {
		state, status, created, fin = "done", "succeeded", finished, &finished
	}
	_, err := f.h.db.Owner.Exec(f.h.ctx, `INSERT INTO deployments (id, certificate_id, location_id, target_id, trigger, state, status,
    new_fingerprint, previous_fingerprint, cert_path, key_path, location_kind, created_at, finished_at)
VALUES ($1, $2, $3, $4, 'manual', $5, $6, $7, $8, 'http.sys/ipport/0.0.0.0:443', '', 'win_sslbinding', $9, $10)`,
		uuid.Must(uuid.NewV7()), f.curCert.ID, loc, target, state, status, nw, prev, created, fin)
	require.NoError(f.h.t, err)
}

func (f *cleanupFixture) compromise(l pki.Leaf) {
	f.h.t.Helper()
	_, err := f.h.db.Owner.Exec(f.h.ctx, "UPDATE certificates SET compromised_at = $2 WHERE fingerprint_sha256 = $1", derSHA(l), f.h.clock.Now())
	require.NoError(f.h.t, err)
}

// incident inserts, as the owner, a closed incident of l's certificate (its key) and returns its id.
func (f *cleanupFixture) incident(l pki.Leaf) uuid.UUID {
	f.h.t.Helper()
	id := uuid.Must(uuid.NewV7())
	_, err := f.h.db.Owner.Exec(f.h.ctx, `INSERT INTO certificate_incidents (id, certificate_id, public_key_sha256, state, revocation, created_at,
    updated_at, finished_at) SELECT $1, id, public_key_sha256, 'closed', 'not_possible', $3, $3, $3 FROM certificates WHERE fingerprint_sha256 = $2`,
		id, derSHA(l), f.h.clock.Now())
	require.NoError(f.h.t, err)
	return id
}

func candidate(l pki.Leaf, eligible string) providers.CleanupCertificate {
	return providers.CleanupCertificate{Store: "My", SHA1: thumbprint(l), SHA256: derSHA(l), Eligible: eligible, FriendlyName: "Alice x 01234567",
		NotAfter: l.Cert.NotAfter, UnboundSince: start}
}

func watched(l pki.Leaf, state, reason string) providers.CleanupWatched {
	return providers.CleanupWatched{Store: "My", SHA1: thumbprint(l), SHA256: derSHA(l), State: state, Reason: reason}
}

func removeItem(l pki.Leaf, reason string) providers.CleanupItem {
	return providers.CleanupItem{Store: "My", SHA1: thumbprint(l), SHA256: derSHA(l), Reason: reason}
}

// Review Focus 3, Rulings 8 and 9: Alice removes a candidate the helper finds eligible only when no deployment of the
// server finished less than 7 days ago with it, no unfinished deployment names it and no location still there holds it;
// a compromised certificate goes at once (incident: no age, no rollback window) unless a deployment is running with it;
// another server's deployments do not count; the switch off keeps every candidate.
func TestJudgeCleanupRules(t *testing.T) {
	ca := pki.NewCA("Cleanup held", pki.ECDSA256, start)
	held := ca.Issue(pki.Opts{CommonName: "held.example.test", SANs: []string{"held.example.test"}}, start)
	missing := ca.Issue(pki.Opts{CommonName: "missing.example.test", SANs: []string{"missing.example.test"}}, start)
	f := newCleanupFixture(t, held, missing)
	h := f.h
	now := h.clock.Now()
	day := 24 * time.Hour
	c6, c8, crun, cdep, ccomp, ccompRun, cother, cexp, cwait := f.issue("c6"), f.issue("c8"), f.issue("crun"), f.issue("cdep"),
		f.issue("ccomp"), f.issue("ccomprun"), f.issue("cother"), f.issue("cexp"), f.issue("cwait")
	cw, cwKept, cnc := f.issue("cw"), f.issue("cwkept"), f.issue("cnc")
	cur := derSHA(f.cur)

	f.deployment(f.win, f.loc1, cur, derSHA(c6), now.Add(-6*day))
	f.deployment(f.win, f.loc1, cur, derSHA(c8), now.Add(-8*day))
	f.deployment(f.win, f.loc1, cur, derSHA(ccomp), now.Add(-day))
	f.deployment(f.win, f.loc2, derSHA(crun), cur, time.Time{})
	f.deployment(f.win, f.loc3, cur, derSHA(ccompRun), time.Time{})
	f.deployment(f.win2, f.loc4, cur, derSHA(cother), now.Add(-day))
	_, err := h.db.Owner.Exec(h.ctx, "UPDATE certificate_locations SET deployed_fingerprint = $2 WHERE id = $1", f.loc1, derSHA(cdep))
	require.NoError(t, err)
	for _, l := range []pki.Leaf{ccomp, ccompRun, cw, cwKept} {
		f.compromise(l)
	}

	plan := providers.CleanupPlan{
		Candidates: []providers.CleanupCertificate{candidate(c6, providers.CleanupAged), candidate(c8, providers.CleanupAged),
			candidate(crun, providers.CleanupAged), candidate(held, providers.CleanupAged), candidate(cdep, providers.CleanupAged),
			candidate(ccomp, ""), candidate(ccompRun, providers.CleanupAged), candidate(cother, providers.CleanupAged),
			candidate(cexp, providers.CleanupExpired), candidate(missing, providers.CleanupAged), candidate(cwait, "")},
		Watched: []providers.CleanupWatched{watched(ccomp, providers.WatchRemovable, ""), watched(cw, providers.WatchRemovable, ""),
			watched(cwKept, providers.WatchKept, "bound"), watched(cnc, providers.WatchRemovable, "")},
	}
	d, err := h.svc.JudgeCleanup(h.ctx, f.win, plan)
	require.NoError(t, err)
	assert.Equal(t, []providers.CleanupItem{removeItem(ccomp, providers.CleanupIncident), removeItem(cw, providers.CleanupIncident),
		removeItem(c8, providers.CleanupAged), removeItem(cother, providers.CleanupAged), removeItem(cexp, providers.CleanupExpired),
		removeItem(missing, providers.CleanupAged)}, d.Remove,
		"compromised first (replaced a day ago, not yet aged; a watched one); then 8 days after its replacement, another server's deployment, expired, a missing location's")
	assert.Equal(t, []inventory.CleanupKept{{SHA256: derSHA(c6), Reason: inventory.CleanupKeptRollbackWindow},
		{SHA256: derSHA(crun), Reason: inventory.CleanupKeptDeploymentRunning}, {SHA256: derSHA(held), Reason: inventory.CleanupKeptLocationHolds},
		{SHA256: derSHA(cdep), Reason: inventory.CleanupKeptLocationHolds}, {SHA256: derSHA(ccompRun), Reason: inventory.CleanupKeptDeploymentRunning}},
		d.Kept, "a candidate the helper does not find eligible yet is neither removed nor kept by Alice")

	// The rollback window ends 7 days after the deployment: a day later c6 goes too.
	h.clock.Advance(day + time.Minute)
	d, err = h.svc.JudgeCleanup(h.ctx, f.win, providers.CleanupPlan{Candidates: []providers.CleanupCertificate{candidate(c6, providers.CleanupAged)}})
	require.NoError(t, err)
	assert.Equal(t, []providers.CleanupItem{removeItem(c6, providers.CleanupAged)}, d.Remove)
	assert.Empty(t, d.Kept)

	// The switch off: every candidate and every compromised watched certificate stays.
	off := false
	swt, err := h.svc.GetTarget(h.ctx, f.win)
	require.NoError(t, err)
	assert.True(t, swt.CertificateCleanup, "on by default")
	swt, err = h.svc.UpdateTarget(h.ctx, f.admin, f.win, swt.Version, inventory.TargetPatch{CertificateCleanup: &off})
	require.NoError(t, err)
	assert.False(t, swt.CertificateCleanup)
	d, err = h.svc.JudgeCleanup(h.ctx, f.win, plan)
	require.NoError(t, err)
	assert.Empty(t, d.Remove)
	want := []inventory.CleanupKept{}
	for _, c := range plan.Candidates {
		want = append(want, inventory.CleanupKept{SHA256: c.SHA256, Reason: inventory.CleanupKeptSwitchOff})
	}
	want = append(want, inventory.CleanupKept{SHA256: derSHA(cw), Reason: inventory.CleanupKeptSwitchOff})
	assert.Equal(t, want, d.Kept)

	_, err = h.svc.JudgeCleanup(h.ctx, uuid.New(), plan)
	require.ErrorIs(t, err, inventory.ErrNotFound)
}

// An apply never takes more items than the helper accepts (winproto.MaxCleanupItems); compromised ones first, the next
// day takes the rest.
func TestJudgeCleanupBoundsTheItems(t *testing.T) {
	require.Equal(t, winproto.MaxCleanupItems, inventory.CleanupMaxItems)
	ca := pki.NewCA("Cleanup held", pki.ECDSA256, start)
	held := ca.Issue(pki.Opts{CommonName: "held.example.test", SANs: []string{"held.example.test"}}, start)
	f := newCleanupFixture(t, held, held)
	comp := f.issue("comp")
	f.compromise(comp)
	plan := providers.CleanupPlan{Watched: []providers.CleanupWatched{watched(comp, providers.WatchRemovable, "")}}
	for i := range inventory.CleanupMaxItems {
		plan.Candidates = append(plan.Candidates, providers.CleanupCertificate{Store: "My", SHA1: fmt.Sprintf("%040x", i+1),
			SHA256: fmt.Sprintf("%064x", i+1), Eligible: providers.CleanupAged})
	}
	d, err := f.h.svc.JudgeCleanup(f.h.ctx, f.win, plan)
	require.NoError(t, err)
	require.Len(t, d.Remove, inventory.CleanupMaxItems)
	assert.Equal(t, removeItem(comp, providers.CleanupIncident), d.Remove[0], "the compromised certificate first")
}

// Ruling 9: the watch list is every compromised certificate a deployment or a location of the server names (new or
// previous; held or last deployed), each once, never another server's or one that is not compromised.
func TestCleanupWatchListsCompromisedCertificatesOfTheTarget(t *testing.T) {
	ca := pki.NewCA("Cleanup held", pki.ECDSA256, start)
	held := ca.Issue(pki.Opts{CommonName: "held.example.test", SANs: []string{"held.example.test"}}, start)
	f := newCleanupFixture(t, held, held)
	h := f.h
	got, err := h.svc.CleanupWatch(h.ctx, f.win)
	require.NoError(t, err)
	assert.Empty(t, got, "nothing compromised")

	pnew, pprev, pdep, other, clean := f.issue("pnew"), f.issue("pprev"), f.issue("pdep"), f.issue("other"), f.issue("clean")
	f.deployment(f.win, f.loc1, derSHA(pnew), derSHA(pprev), h.clock.Now())
	f.deployment(f.win, f.loc1, derSHA(clean), derSHA(pnew), h.clock.Now())
	f.deployment(f.win2, f.loc4, derSHA(other), derSHA(f.cur), h.clock.Now())
	_, err = h.db.Owner.Exec(h.ctx, "UPDATE certificate_locations SET deployed_fingerprint = $2 WHERE id = $1", f.loc2, derSHA(pdep))
	require.NoError(t, err)
	for _, l := range []pki.Leaf{pnew, pprev, pdep, other, held} {
		f.compromise(l)
	}
	got, err = h.svc.CleanupWatch(h.ctx, f.win)
	require.NoError(t, err)
	want := []providers.CleanupRef{}
	for _, l := range []pki.Leaf{pnew, pprev, pdep, held} {
		want = append(want, providers.CleanupRef{SHA1: thumbprint(l), SHA256: derSHA(l)})
	}
	assert.ElementsMatch(t, want, got, "the deployments' new and previous, a location's last deployed and held certificate; not iis-02's")
	got, err = h.svc.CleanupWatch(h.ctx, f.win2)
	require.NoError(t, err)
	assert.Equal(t, []providers.CleanupRef{{SHA1: thumbprint(other), SHA256: derSHA(other)}}, got)
}

// Ruling 13: the schedule queues one windows.cleanup per day for each connected Windows server with the cleanup
// capability, never for a Linux server, a disabled one or one whose host key changed, nor twice within 24 hours.
func TestScheduleWindowsCleanup(t *testing.T) {
	ca := pki.NewCA("Cleanup held", pki.ECDSA256, start)
	held := ca.Issue(pki.Opts{CommonName: "held.example.test", SANs: []string{"held.example.test"}}, start)
	f := newCleanupFixture(t, held, held)
	h := f.h
	off, gone := winTarget(t, h, f.admin, "iis-03").ID, winTarget(t, h, f.admin, "iis-04").ID
	linux := nginxTarget(t, h, f.admin, "web-01").ID
	_, err := h.db.Owner.Exec(h.ctx, "UPDATE targets SET status = 'disabled' WHERE id = $1", off)
	require.NoError(t, err)
	_, err = h.db.Owner.Exec(h.ctx, "UPDATE targets SET status = 'host_key_changed' WHERE id = $1", gone)
	require.NoError(t, err)
	_, err = h.db.Owner.Exec(h.ctx, "UPDATE targets SET capabilities = array_remove(capabilities, 'cleanup_certificates') WHERE id = $1", f.win2)
	require.NoError(t, err)

	jobsOf := func() map[uuid.UUID][]string {
		out := map[uuid.UUID][]string{}
		for _, r := range h.jobs.requests() {
			if r.Type == inventory.JobWindowsCleanup {
				out[r.TargetID] = append(out[r.TargetID], r.DedupeKey)
				assert.Equal(t, "scheduled", r.Kind)
				assert.Empty(t, r.Payload)
			}
		}
		return out
	}
	n, err := h.svc.ScheduleWindowsCleanup(h.ctx)
	require.NoError(t, err)
	assert.Equal(t, 1, n)
	dayNo := h.clock.Now().Unix() / 86400
	assert.Equal(t, map[uuid.UUID][]string{f.win: {fmt.Sprintf("windows.cleanup:%s:%d", f.win, dayNo)}}, jobsOf(),
		"not iis-02 (no capability), iis-03 (disabled), iis-04 (host key changed) nor web-01 (%s)", linux)

	h.clock.Advance(23 * time.Hour)
	n, err = h.svc.ScheduleWindowsCleanup(h.ctx)
	require.NoError(t, err)
	assert.Zero(t, n, "not twice within 24 hours")

	h.clock.Advance(time.Hour + time.Minute)
	n, err = h.svc.ScheduleWindowsCleanup(h.ctx)
	require.NoError(t, err)
	assert.Equal(t, 1, n, "the next day")
	assert.Len(t, jobsOf()[f.win], 2)
	assert.Equal(t, 2, h.count("SELECT count(*) FROM jobs WHERE type = 'windows.cleanup' AND target_id = $1", f.win))
}

// Ruling 13: each removal is audited once; Ruling 9: an incident's job tells the server's and the certificate's services
// once about a watched compromised certificate that is still in a store, a scheduled job never does.
func TestRecordCleanupAuditsAndNotifiesOnce(t *testing.T) {
	ca := pki.NewCA("Cleanup held", pki.ECDSA256, start)
	held := ca.Issue(pki.Opts{CommonName: "held.example.test", SANs: []string{"held.example.test"}}, start)
	f := newCleanupFixture(t, held, held)
	h := f.h
	a, b, kept, gone, absent := f.issue("a"), f.issue("b"), f.issue("kept"), f.issue("gone"), f.issue("absent")
	for _, l := range []pki.Leaf{kept, gone, absent} {
		f.compromise(l)
	}
	plan := providers.CleanupPlan{
		Candidates: []providers.CleanupCertificate{candidate(a, providers.CleanupAged), candidate(b, providers.CleanupExpired)},
		Watched: []providers.CleanupWatched{watched(kept, providers.WatchKept, "bound"), watched(gone, providers.WatchRemovable, ""),
			{SHA1: thumbprint(absent), SHA256: derSHA(absent), State: providers.WatchAbsent}},
	}
	d := inventory.CleanupDecision{Remove: []providers.CleanupItem{removeItem(a, providers.CleanupAged), removeItem(b, providers.CleanupExpired),
		removeItem(gone, providers.CleanupIncident)}}
	res := providers.CleanupApplyResult{Results: []providers.CleanupItemResult{{SHA256: derSHA(a), Result: providers.CleanupRemoved},
		{SHA256: derSHA(b), Result: providers.CleanupRemoved}, {SHA256: derSHA(gone), Result: providers.CleanupAbsent}}}

	require.NoError(t, h.svc.RecordCleanup(h.ctx, f.win, nil, plan, d, res))
	assert.Equal(t, []map[string]string{
		{"store": "My", "sha1": thumbprint(a), "sha256": derSHA(a), "reason": providers.CleanupAged},
		{"store": "My", "sha1": thumbprint(b), "sha256": derSHA(b), "reason": providers.CleanupExpired},
	}, h.auditDetails("windows.certificate_removed"), "two removals, two rows; an absent one is not audited")
	assert.Equal(t, 2, h.count(`SELECT count(*) FROM audit_log WHERE action = 'windows.certificate_removed' AND actor_type = 'system'
    AND object_type = 'target' AND object_id = $1`, f.win.String()))
	assert.Zero(t, h.emails(inventory.TemplateWindowsCompromisedInStore), "a scheduled job never tells")

	notices := func() []map[string]string {
		rows, err := h.db.Owner.Query(h.ctx, "SELECT params FROM notifications_outbox WHERE template_key = $1 ORDER BY params->>'thumbprint'",
			inventory.TemplateWindowsCompromisedInStore)
		require.NoError(t, err)
		var got []map[string]string
		for rows.Next() {
			var p map[string]string
			require.NoError(t, rows.Scan(&p))
			got = append(got, p)
		}
		require.NoError(t, rows.Err())
		return got
	}
	notice := func(l pki.Leaf, name string, incident uuid.UUID) map[string]string {
		return map[string]string{"target_name": "iis-01", "certificate_name": name, "store": "My", "thumbprint": thumbprint(l), "incident_id": incident.String()}
	}

	// An incident tells only about its own certificates: the incident of kept reports kept (still bound), not gone (another
	// incident's certificate, removable and not removed); the incident of gone reports gone; absent is never told.
	incident, goneIncident := f.incident(kept), f.incident(gone)
	require.NoError(t, h.svc.RecordCleanup(h.ctx, f.win, &incident, plan, inventory.CleanupDecision{}, providers.CleanupApplyResult{}))
	assert.Equal(t, []map[string]string{notice(kept, "kept.example.test", incident)}, notices(), "only the incident's own certificate")
	require.NotZero(t, h.emails(inventory.TemplateWindowsCompromisedInStore))
	_, err := h.db.Owner.Exec(h.ctx, "DELETE FROM notifications_outbox")
	require.NoError(t, err)
	require.NoError(t, h.svc.RecordCleanup(h.ctx, f.win, &goneIncident, plan, inventory.CleanupDecision{}, providers.CleanupApplyResult{}))
	assert.Equal(t, []map[string]string{notice(gone, "gone.example.test", goneIncident)}, notices(), "the removable one that was not removed")
	unknown := uuid.Must(uuid.NewV7())
	require.NoError(t, h.svc.RecordCleanup(h.ctx, f.win, &unknown, plan, inventory.CleanupDecision{}, providers.CleanupApplyResult{}))
	assert.Len(t, notices(), 1, "an incident Alice does not hold names no certificate")

	// A second cleanup of the same incident (another place of it on the server settled after the first job ended) does not
	// tell again about the same certificate; another incident of the same key does.
	require.NoError(t, h.svc.RecordCleanup(h.ctx, f.win, &goneIncident, plan, inventory.CleanupDecision{}, providers.CleanupApplyResult{}))
	assert.Len(t, notices(), 1, "once per incident and certificate")
	other := f.incident(gone)
	require.NoError(t, h.svc.RecordCleanup(h.ctx, f.win, &other, plan, inventory.CleanupDecision{}, providers.CleanupApplyResult{}))
	assert.Len(t, notices(), 2, "another incident tells again")
	incident = goneIncident

	_, err = h.db.Owner.Exec(h.ctx, "DELETE FROM notifications_outbox")
	require.NoError(t, err)
	require.NoError(t, h.svc.RecordCleanup(h.ctx, f.win, &incident, providers.CleanupPlan{Watched: []providers.CleanupWatched{watched(gone, providers.WatchRemovable, "")}},
		inventory.CleanupDecision{Remove: []providers.CleanupItem{removeItem(gone, providers.CleanupIncident)}},
		providers.CleanupApplyResult{Results: []providers.CleanupItemResult{{SHA256: derSHA(gone), Result: providers.CleanupRemoved}}}))
	assert.Zero(t, h.emails(inventory.TemplateWindowsCompromisedInStore), "a compromised certificate the job removed is not reported")
	assert.Equal(t, map[string]string{"store": "My", "sha1": thumbprint(gone), "sha256": derSHA(gone), "reason": providers.CleanupIncident,
		"incident_id": incident.String()}, h.auditDetails("windows.certificate_removed")[2], "an incident's removal names the incident")
}

// The store notice under a race (HB-09, R64 Ruling 12): two cleanup jobs of the same incident record the same still-bound
// certificate at the same moment; one notice set is queued and one incident_notices row written.
func TestCompromisedInStoreNoticeOnceUnderRace(t *testing.T) {
	ca := pki.NewCA("Cleanup race", pki.ECDSA256, start)
	held := ca.Issue(pki.Opts{CommonName: "held.example.test", SANs: []string{"held.example.test"}}, start)
	f := newCleanupFixture(t, held, held)
	h := f.h
	kept := f.issue("kept")
	f.compromise(kept)
	incident := f.incident(kept)
	plan := providers.CleanupPlan{Watched: []providers.CleanupWatched{watched(kept, providers.WatchKept, "bound")}}
	var wg sync.WaitGroup
	errs := make([]error, 4)
	for n := range errs {
		wg.Add(1)
		go func() {
			defer wg.Done()
			errs[n] = h.svc.RecordCleanup(h.ctx, f.win, &incident, plan, inventory.CleanupDecision{}, providers.CleanupApplyResult{})
		}()
	}
	wg.Wait()
	for _, err := range errs {
		require.NoError(t, err)
	}
	sets := h.count(`SELECT count(DISTINCT to_address) FROM notifications_outbox WHERE template_key = $1`, inventory.TemplateWindowsCompromisedInStore)
	require.Positive(t, sets)
	assert.Equal(t, sets, h.emails(inventory.TemplateWindowsCompromisedInStore), "one e-mail per recipient, not one per job")
	assert.Equal(t, 1, h.count("SELECT count(*) FROM incident_notices WHERE incident_id = $1", incident))
}

// The store notice after the outbox's retention pruning (HB-09, R64 Ruling 12): the record is the notice's, not the
// outbox's, so a later job does not send it again.
func TestCompromisedInStoreNoticeSurvivesOutboxPruning(t *testing.T) {
	ca := pki.NewCA("Cleanup prune", pki.ECDSA256, start)
	held := ca.Issue(pki.Opts{CommonName: "held.example.test", SANs: []string{"held.example.test"}}, start)
	f := newCleanupFixture(t, held, held)
	h := f.h
	kept := f.issue("kept")
	f.compromise(kept)
	incident := f.incident(kept)
	plan := providers.CleanupPlan{Watched: []providers.CleanupWatched{watched(kept, providers.WatchKept, "bound")}}
	require.NoError(t, h.svc.RecordCleanup(h.ctx, f.win, &incident, plan, inventory.CleanupDecision{}, providers.CleanupApplyResult{}))
	require.Positive(t, h.emails(inventory.TemplateWindowsCompromisedInStore))
	_, err := h.db.Owner.Exec(h.ctx, "DELETE FROM notifications_outbox")
	require.NoError(t, err)
	require.NoError(t, h.svc.RecordCleanup(h.ctx, f.win, &incident, plan, inventory.CleanupDecision{}, providers.CleanupApplyResult{}))
	assert.Zero(t, h.emails(inventory.TemplateWindowsCompromisedInStore), "never sent twice")
}
