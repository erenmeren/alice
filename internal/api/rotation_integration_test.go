//go:build integration

package api

import (
	"context"
	"net/http"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/ssh"
)

// TestEditOfEnabledPolicySwitchesItOffOverTheWire (S2) with the real service: an Administrator's operate token
// prepares a policy, the Administrator switches it on with step-up, the token changes how it rotates and the answer
// and the stored policy show it switched off and audited; the token can never switch it on again, nor can the
// browser session once its step-up has expired. A name-only change leaves a policy that is on as it is.
func TestEditOfEnabledPolicySwitchesItOffOverTheWire(t *testing.T) {
	s, browser, admin := installed(t)
	token, _ := createToken(t, s, browser, admin, "operate", 1)
	api := s.client("198.51.100.60")
	api.bearer = token

	rec := api.do(http.MethodPost, "/api/v1/ssh-keys/generate", map[string]string{"label": "ci deploy", "key_type": "ed25519"})
	requireStatus(t, rec, http.StatusCreated)
	key := decodeBody[map[string]any](t, rec)
	require.NotNil(t, key["managed_key"])
	rec = api.do(http.MethodPost, "/api/v1/rotation/policies", map[string]any{"ssh_key_id": key["id"], "name": "ci", "interval_days": 90})
	requireStatus(t, rec, http.StatusCreated)
	pol := decodeBody[map[string]any](t, rec)
	assert.Equal(t, false, pol["enabled"])
	path := "/api/v1/rotation/policies/" + pol["id"].(string)
	etag := rec.Header().Get("ETag")
	require.Equal(t, `"1"`, etag)

	// Switching on: never the token, never without a fresh step-up.
	requireError(t, api.do(http.MethodPost, path+"/actions/enable", nil, withHeader("If-Match", etag)), http.StatusForbidden, "ALC-AUTH-0002")
	s.stepUp(browser, admin)
	rec = browser.do(http.MethodPost, path+"/actions/enable", nil, withHeader("If-Match", etag))
	requireStatus(t, rec, http.StatusOK)
	assert.Equal(t, true, decodeBody[map[string]any](t, rec)["enabled"])
	etag = rec.Header().Get("ETag")

	// A name-only change leaves it on.
	rec = api.do(http.MethodPatch, path, map[string]any{"name": "ci runners"}, withHeader("If-Match", etag))
	requireStatus(t, rec, http.StatusOK)
	assert.Equal(t, true, decodeBody[map[string]any](t, rec)["enabled"])
	etag = rec.Header().Get("ETag")

	// Any change of how it rotates switches it off in the same step.
	rec = api.do(http.MethodPatch, path, map[string]any{"interval_days": 1, "overlap_days": 0, "notify_before_hours": 1}, withHeader("If-Match", etag))
	requireStatus(t, rec, http.StatusOK)
	got := decodeBody[map[string]any](t, rec)
	assert.Equal(t, false, got["enabled"])
	assert.Nil(t, got["next_run_at"])
	assert.EqualValues(t, 1, got["interval_days"])
	etag = rec.Header().Get("ETag")
	rec = api.do(http.MethodGet, path, nil)
	requireStatus(t, rec, http.StatusOK)
	assert.Equal(t, false, decodeBody[map[string]any](t, rec)["enabled"], "the stored policy is off")
	var reason string
	require.NoError(t, s.db.Owner.QueryRow(context.Background(), `SELECT details->>'reason' FROM audit_log
WHERE action = 'rotation.policy_disabled' ORDER BY seq DESC LIMIT 1`).Scan(&reason))
	assert.Equal(t, "edited", reason)

	// The token cannot switch it back on; the session without a fresh step-up cannot either.
	requireError(t, api.do(http.MethodPost, path+"/actions/enable", nil, withHeader("If-Match", etag)), http.StatusForbidden, "ALC-AUTH-0002")
	s.clock.Advance(10 * time.Minute)
	requireError(t, browser.do(http.MethodPost, path+"/actions/enable", nil, withHeader("If-Match", etag)), http.StatusForbidden, "ALC-AUTH-0003")
	rec = api.do(http.MethodGet, path, nil)
	assert.Equal(t, false, decodeBody[map[string]any](t, rec)["enabled"])
}

// phase6Records makes one generated key, its rotation policy (through the API) and a previewed run (written as the
// service writes it), so every Phase 6 GET of an item answers 200 with a real record.
func phase6Records(t *testing.T, s *stack, c *client) map[string]string {
	t.Helper()
	rec := c.do(http.MethodPost, "/api/v1/ssh-keys/generate", map[string]string{"label": "records", "key_type": "ed25519"})
	requireStatus(t, rec, http.StatusCreated)
	key := decodeBody[map[string]any](t, rec)["id"].(string)
	rec = c.do(http.MethodPost, "/api/v1/rotation/policies", map[string]any{"ssh_key_id": key, "name": "records", "interval_days": 30})
	requireStatus(t, rec, http.StatusCreated)
	policy := decodeBody[map[string]any](t, rec)["id"].(string)
	run := uuid.Must(uuid.NewV7())
	_, err := s.db.Owner.Exec(context.Background(), `INSERT INTO rotations (id, policy_id, old_ssh_key_id, trigger, status, plan, plan_digest,
    new_key_type, overlap_minutes, planned_for, notified_at, created_at, updated_at)
VALUES ($1, $2, $3, 'manual', 'dry_run_notified', '{}', repeat('a', 64), 'ed25519', 0, $4, $4, $4, $4)`, run, policy, key, s.clock.Now())
	require.NoError(t, err)
	return map[string]string{"/api/v1/rotation/policies/": policy, "/api/v1/rotation/runs/": run.String()}
}

// outboxTemplates counts the queued and sent emails per template.
func (s *stack) outboxTemplates() map[string]int {
	s.t.Helper()
	rows, err := s.db.Owner.Query(context.Background(), `SELECT template_key, count(*) FROM notifications_outbox GROUP BY 1`)
	require.NoError(s.t, err)
	defer rows.Close()
	out := map[string]int{}
	for rows.Next() {
		var tpl string
		var n int
		require.NoError(s.t, rows.Scan(&tpl, &n))
		out[tpl] = n
	}
	require.NoError(s.t, rows.Err())
	return out
}

// transitions are the run's audited status changes "from>to", in order.
func (s *stack) transitions(runID string) []string {
	s.t.Helper()
	var out []string
	for _, d := range s.auditRows("rotation.status_changed") {
		if d["rotation_id"] == runID {
			out = append(out, d["from"]+">"+d["to"])
		}
	}
	return out
}

// TestOwnerSteps3To5OverTheWire is the §26.8 acceptance journey through the API, the real job handlers and the
// emulated server: an Operator generates a key and deploys it (the job's test login with the new key succeeds); the
// Administrator creates a policy (off), previews it (the actions name the server, user and file; an email is queued),
// switches it on with step-up and starts it with the previewed digest; the run adds and verifies the new key, keeps
// both keys through the overlap, re-checks the new key and removes the old one; the run is completed, the old key is
// gone from the file, the new key logs in, every step is audited and the emails are queued and delivered as designed.
func TestOwnerSteps3To5OverTheWire(t *testing.T) {
	e := newKeyEnv(t)
	operator := e.createUser(e.admin, e.adminAcct, "otto", "operator", operatorPassword)
	oc := e.freshClient()
	e.firstSignIn(oc, operator)
	e.signedIn(oc, operator)

	// Owner steps 1-2 as an Operator: generate and deploy.
	k := e.generate(oc, "app deploy", "ed25519")
	job := e.deploy(oc, k.id, e.targetID, "deploy", deployKeysPath)
	e.drain()
	require.Equal(t, "verified", e.job(oc, job)["result"].(map[string]any)["result"])
	require.True(t, e.f.emu.AcceptsLogin("deploy", k.pub))
	others := e.f.file(deployKeysPath)

	// Step 3: a policy for the key, off until switched on.
	rec := e.admin.do(http.MethodPost, "/api/v1/rotation/policies", map[string]any{"ssh_key_id": k.id, "name": "app",
		"interval_days": 90, "overlap_days": 7})
	requireStatus(t, rec, http.StatusCreated)
	pol := decodeBody[map[string]any](t, rec)
	assert.Equal(t, false, pol["enabled"])
	assert.EqualValues(t, 7, pol["overlap_days"])
	policyID, etag := pol["id"].(string), rec.Header().Get("ETag")
	requireError(t, oc.do(http.MethodPost, "/api/v1/rotation/policies", map[string]any{"ssh_key_id": k.id, "name": "x", "interval_days": 9}),
		http.StatusForbidden, "ALC-AUTH-0002")

	// Step 4: the preview names exactly what changes and is emailed.
	p := e.preview(e.admin, policyID)
	assert.True(t, p.Emailed)
	assert.Equal(t, 1, p.ChangeCount)
	require.Len(t, p.Actions, 1)
	a := p.Actions[0]
	assert.Equal(t, "web-01", a["target_name"])
	assert.Equal(t, "deploy", a["os_user"])
	assert.Equal(t, deployKeysPath, a["file_path"])
	assert.Equal(t, "", a["skip_reason"])
	assert.Equal(t, true, a["verify"])
	assert.Contains(t, a["remove_line"], k.blob())
	assert.Equal(t, "ed25519 (new key) alice:app-deploy:2026-10-01", a["add_line"], "the new key is shown by its type")
	assert.Equal(t, 1, e.outboxTemplates()["rotation.preview"])
	assert.Zero(t, e.count("rotations"), "a preview creates no run")

	// Switched on with step-up only.
	e.advance(6 * time.Minute)
	requireError(t, e.admin.do(http.MethodPost, "/api/v1/rotation/policies/"+policyID+"/actions/enable", nil, withHeader("If-Match", etag)),
		http.StatusForbidden, "ALC-AUTH-0003")
	e.stepUp(e.admin, e.adminAcct)
	rec = e.admin.do(http.MethodPost, "/api/v1/rotation/policies/"+policyID+"/actions/enable", nil, withHeader("If-Match", etag))
	requireStatus(t, rec, http.StatusOK)
	assert.Equal(t, true, decodeBody[map[string]any](t, rec)["enabled"])

	// Step 5: Run now with the previewed digest.
	runID := e.runNow(policyID, p.PlanDigest)
	e.drain()
	r := e.run(e.admin, runID)
	require.Equal(t, "overlap", r.Status, "%+v", r)
	assert.Equal(t, p.PlanDigest, r.PlanDigest)
	require.NotNil(t, r.NewSSHKeyID)
	newKey := decodeBody[map[string]any](t, e.admin.do(http.MethodGet, "/api/v1/ssh-keys/"+*r.NewSSHKeyID, nil))
	newPub := parsePub(t, newKey["public_key"].(string))
	file := e.f.file(deployKeysPath)
	assert.Contains(t, file, k.blob(), "the old key stays during the overlap")
	assert.Contains(t, file, strings.Join(strings.Fields(newKey["public_key"].(string))[:2], " "), "the new key is there")
	assert.True(t, e.f.emu.AcceptsLogin("deploy", newPub))
	assert.True(t, e.f.emu.AcceptsLogin("deploy", k.pub))
	assert.Equal(t, "verified", r.Locations[0]["state"])
	e.assertGETsChangeNothing(k.id, policyID, runID)

	// Nothing is removed before the overlap has passed.
	e.advance(6 * 24 * time.Hour)
	e.sweep(2)
	assert.Equal(t, "overlap", e.run(e.admin, runID).Status)
	assert.Contains(t, e.f.file(deployKeysPath), k.blob())
	e.advance(24*time.Hour + time.Minute)
	e.sweep(3)
	r = e.run(e.admin, runID)
	require.Equal(t, "completed", r.Status, "%+v", r)
	assert.Nil(t, r.Result)
	assert.Equal(t, "removed", r.Locations[0]["state"])
	assert.NotNil(t, r.Locations[0]["reverified_at"], "the new key was checked again before the removal")

	after := e.f.file(deployKeysPath)
	assert.NotContains(t, after, k.blob(), "the old key is gone from the file")
	assert.False(t, e.f.emu.AcceptsLogin("deploy", k.pub))
	assert.True(t, e.f.emu.AcceptsLogin("deploy", newPub), "the new key logs in")
	for _, line := range strings.Split(strings.TrimSpace(others), "\n") {
		if !strings.Contains(line, k.blob()) {
			assert.Contains(t, after, line+"\n", "every other line stays")
		}
	}
	for _, path := range []string{rootKeysPath, aliceKeysPath} {
		assert.Equal(t, e.f.files[path], e.f.file(path), path)
	}

	// Audit: every step of the journey.
	assert.Equal(t, []string{"dry_run_notified>adding_new", "adding_new>overlap", "overlap>removing_old", "removing_old>completed"},
		e.transitions(runID))
	for action, n := range map[string]int{"sshkey.generated": 2, "sshkey.deploy_requested": 1, "rotation.policy_created": 1,
		"rotation.previewed": 1, "rotation.policy_enabled": 1, "rotation.created": 1, "sshkey.added": 2, "sshkey.removed": 1, "sshkey.retired": 1} {
		assert.Equal(t, n, e.auditCount(action), action)
	}
	var places []string
	for _, d := range e.auditRows("rotation.location_changed") {
		places = append(places, d["from"]+">"+d["to"])
	}
	assert.Equal(t, []string{"planned>adding", "adding>added", "added>verified", "verified>removing", "removing>removed"}, places,
		"every step of the place is audited")
	m := decodeBody[map[string]any](t, e.admin.do(http.MethodGet, "/api/v1/ssh-keys/"+k.id, nil))["managed_key"].(map[string]any)
	assert.NotNil(t, m["retired_at"], "the old key is retired")
	pol = decodeBody[map[string]any](t, e.admin.do(http.MethodGet, "/api/v1/rotation/policies/"+policyID, nil))
	assert.Equal(t, *r.NewSSHKeyID, pol["ssh_key_id"], "the policy moves to the new key")
	assert.Equal(t, "completed", pol["last_run_status"])

	// Emails: queued as designed and delivered by the sender.
	tpls := e.outboxTemplates()
	for _, tpl := range []string{"rotation.preview", "rotation.overlap_started", "rotation.overlap_ending", "rotation.completed"} {
		assert.Positive(t, tpls[tpl], tpl)
	}
	for _, tpl := range []string{"rotation.aborted", "rotation.needs_attention", "rotation.paused_license", "rotation.completed_partial"} {
		assert.Zero(t, tpls[tpl], tpl)
	}
	assert.Equal(t, e.count("notifications_outbox"), e.deliverMail())
	subjects := []string{}
	for _, msg := range e.mailbox.messages() {
		assert.Equal(t, "ada@example.com", msg.To)
		assert.NotContains(t, msg.Subject+msg.Body, "{{", "every parameter is filled in")
		subjects = append(subjects, msg.Subject)
	}
	assert.Len(t, subjects, e.count("notifications_outbox"))
	assert.False(t, slices.Contains(subjects, ""))
}

// parsePub parses an authorized_keys line.
func parsePub(t *testing.T, line string) ssh.PublicKey {
	t.Helper()
	p, _, _, _, err := ssh.ParseAuthorizedKey([]byte(line))
	require.NoError(t, err)
	return p
}

// placeOf is a run's place or a preview's action reduced to what the plan decides (the dry run must equal the run).
func placeOf(m map[string]any) string {
	verify := ""
	if v, ok := m["verify"]; ok {
		verify = "verify=" + fmtAny(v)
	}
	return strings.Join([]string{fmtAny(m["n"]), fmtAny(m["target_id"]), fmtAny(m["os_user"]), fmtAny(m["file_path"]),
		fmtAny(m["options"]), fmtAny(m["skip_reason"]), fmtAny(m["verify_note"]), verify}, "|")
}

func fmtAny(v any) string {
	switch x := v.(type) {
	case nil:
		return ""
	case string:
		return x
	case float64:
		return strconv.FormatFloat(x, 'f', -1, 64)
	case bool:
		return strconv.FormatBool(x)
	}
	return "?"
}

// runRefused asserts Run now with digest answers 409 ALC-ROT-0003 and that nothing was created, queued or sent.
func (e *keyEnv) runRefused(policyID, digest string, f ...*sshFixture) {
	e.t.Helper()
	writes := map[*sshFixture]int{}
	for _, fx := range f {
		writes[fx] = len(fx.helperWrites())
	}
	runs, jobsBefore := e.count("rotations"), e.countWhere("jobs", "type = 'rotation.location'")
	e.stepUp(e.admin, e.adminAcct)
	requireError(e.t, e.admin.do(http.MethodPost, "/api/v1/rotation/policies/"+policyID+"/actions/run", map[string]string{"plan_digest": digest}),
		http.StatusConflict, "ALC-ROT-0003")
	assert.Equal(e.t, runs, e.count("rotations"), "no run created")
	assert.Equal(e.t, jobsBefore, e.countWhere("jobs", "type = 'rotation.location'"), "nothing queued")
	e.drain()
	for fx, n := range writes {
		assert.Len(e.t, fx.helperWrites(), n, "nothing sent")
	}
}

// TestDryRunEqualsActualPlan (Review Focus 4, §13.6 item 1) over the wire: the run executes exactly the previewed plan
// (its places equal the preview's actions one to one, its digest is the previewed one); when the world changes between
// the preview and Run now (a new place of the key appears, a server's PermitRootLogin changes, the connection
// account's key files are no longer known completely) Run now with the old digest answers 409 ALC-ROT-0003 and nothing
// is created, queued or sent.
func TestDryRunEqualsActualPlan(t *testing.T) {
	e := newKeyEnv(t)
	k := e.generate(e.admin, "dry run", "ed25519")
	e.deployed(k)
	job := e.deploy(e.admin, k.id, e.targetID, "root", rootKeysPath)
	e.drain()
	require.Equal(t, "succeeded", e.job(e.admin, job)["status"])
	// A place that is skipped: the key by hand in the connection account's file.
	e.f.emu.SetFile(aliceKeysPath, []byte(e.f.files[aliceKeysPath]+k.blob()+" by-hand\n"))
	e.discover(e.targetID)

	t.Run("the run is the preview", func(t *testing.T) {
		other := e.generate(e.admin, "dry run 2", "ed25519")
		e.deployed(other)
		policyID, _ := e.createPolicy(e.admin, k.id, 1)
		p := e.preview(e.admin, policyID)
		require.Len(t, p.Actions, 3)
		assert.Equal(t, 2, p.ChangeCount)
		assert.Equal(t, 1, p.SkipCount)
		runID := e.runNow(policyID, p.PlanDigest)
		r := e.run(e.admin, runID)
		assert.Equal(t, p.PlanDigest, r.PlanDigest)
		var want, got []string
		for _, a := range p.Actions {
			want = append(want, placeOf(a))
		}
		for _, l := range r.Locations {
			got = append(got, placeOf(l))
		}
		// The run's places carry no "verify" field; the run's stored plan does: compare it (by n) with the preview's.
		stored := map[string]bool{}
		res, err := e.db.Owner.Query(context.Background(), `SELECT (a->>'N'), (a->>'Verify')::boolean FROM rotations r,
jsonb_array_elements(r.plan->'Actions') a WHERE r.id = $1`, runID)
		require.NoError(t, err)
		for res.Next() {
			var n string
			var v bool
			require.NoError(t, res.Scan(&n, &v))
			stored[n] = v
		}
		require.NoError(t, res.Err())
		require.Len(t, stored, len(p.Actions))
		for i, a := range p.Actions {
			assert.Equal(t, a["verify"], stored[fmtAny(a["n"])], "verify of action %v", a["n"])
			want[i] = strings.TrimSuffix(strings.TrimSuffix(want[i], "verify=true"), "verify=false")
		}
		slices.Sort(want)
		slices.Sort(got)
		assert.Equal(t, want, got, "the run's places are the preview's actions")
		e.drain()
		r = e.run(e.admin, runID)
		require.Equal(t, "overlap", r.Status, "%+v", r)
		states := map[string]string{}
		for _, l := range r.Locations {
			states[l["os_user"].(string)] = l["state"].(string)
		}
		assert.Equal(t, map[string]string{"deploy": "verified", "root": "verified", "alice-svc": "skipped"}, states)
		assert.Contains(t, e.f.file(aliceKeysPath), k.blob()+" by-hand", "the skipped place is not touched")
		e.stepUp(e.admin, e.adminAcct)
		requireStatus(t, e.admin.do(http.MethodPost, "/api/v1/rotation/runs/"+runID+"/actions/abort", nil), http.StatusNoContent)
		e.drain()
		require.Equal(t, "aborted", e.run(e.admin, runID).Status)
	})

	t.Run("the world changes after the preview", func(t *testing.T) {
		k2 := e.generate(e.admin, "dry run 3", "ed25519")
		e.deployed(k2)
		job := e.deploy(e.admin, k2.id, e.targetID, "root", rootKeysPath)
		e.drain()
		require.Equal(t, "succeeded", e.job(e.admin, job)["status"])
		policyID, _ := e.createPolicy(e.admin, k2.id, 1)
		f2, t2 := e.addKeyServer("web-02")

		// A new place of the key appears (deployed to another server).
		p := e.preview(e.admin, policyID)
		job = e.deploy(e.admin, k2.id, t2, "deploy", deployKeysPath)
		e.drain()
		require.Equal(t, "succeeded", e.job(e.admin, job)["status"])
		e.runRefused(policyID, p.PlanDigest, e.f, f2)
		assert.Len(t, e.preview(e.admin, policyID).Actions, len(p.Actions)+1)

		// PermitRootLogin changes on web-01 (rescanned).
		p = e.preview(e.admin, policyID)
		e.f.emu.SetSSHD(strings.Replace(sshdOf(e.f), "permitrootlogin prohibit-password", "permitrootlogin no", 1))
		e.discover(e.targetID)
		e.runRefused(policyID, p.PlanDigest, e.f, f2)
		for _, a := range e.preview(e.admin, policyID).Actions {
			if a["os_user"] == "root" {
				assert.Equal(t, "root_login_disabled", a["verify_note"], "%v", a)
			}
		}

		// The connection account's key files of web-02 are no longer known completely.
		p = e.preview(e.admin, policyID)
		f2.emu.SetUnsupported(aliceKeysPath)
		e.discover(t2)
		e.runRefused(policyID, p.PlanDigest, e.f, f2)
		for _, a := range e.preview(e.admin, policyID).Actions {
			if a["target_id"] == t2 {
				assert.Equal(t, "connection_files_unknown", a["skip_reason"], "%v", a)
			}
		}
		assert.Zero(t, e.countWhere("rotations", "policy_id = '"+policyID+"'"))
	})
}

// sshdOf is the sshd -T text the fixture serves (sshFixture sets it).
func sshdOf(*sshFixture) string {
	return "authorizedkeysfile .ssh/authorized_keys\nauthorizedkeyscommand none\npubkeyauthentication yes\n" +
		"passwordauthentication no\npermitrootlogin prohibit-password\nhostkey /etc/ssh/ssh_host_ed25519_key\n"
}

// scheduled switches on a daily policy of k with one hour's notice (step-up), moves the clock to its notice time and
// runs the planner: the scheduled run is previewed and its notice queued. It returns the run.
func (e *keyEnv) scheduled(k keyLine) runDoc {
	e.t.Helper()
	rec := e.admin.do(http.MethodPost, "/api/v1/rotation/policies", map[string]any{"ssh_key_id": k.id, "name": "daily", "interval_days": 1,
		"overlap_days": 1, "notify_before_hours": 1})
	requireStatus(e.t, rec, http.StatusCreated)
	policyID := decodeBody[map[string]any](e.t, rec)["id"].(string)
	e.stepUp(e.admin, e.adminAcct)
	rec = e.admin.do(http.MethodPost, "/api/v1/rotation/policies/"+policyID+"/actions/enable", nil, withHeader("If-Match", rec.Header().Get("ETag")))
	requireStatus(e.t, rec, http.StatusOK)
	next, err := time.Parse(time.RFC3339, decodeBody[map[string]any](e.t, rec)["next_run_at"].(string))
	require.NoError(e.t, err)
	e.advance(next.Add(-time.Hour).Sub(e.clock.Now()) + time.Second)
	require.NoError(e.t, e.task("rotation.plan"))
	page := decodeBody[struct {
		Items []map[string]any `json:"items"`
	}](e.t, e.admin.do(http.MethodGet, "/api/v1/rotation/runs?policy_id="+policyID, nil))
	require.Len(e.t, page.Items, 1)
	r := e.run(e.admin, page.Items[0]["id"].(string))
	require.Equal(e.t, "dry_run_notified", r.Status)
	return r
}

// notice is the run's rotation.preview row: its status and when it was sent.
func (e *keyEnv) notice(runID string) (string, *time.Time) {
	e.t.Helper()
	var status string
	var sent *time.Time
	require.NoError(e.t, e.db.Owner.QueryRow(context.Background(), `SELECT status, sent_at FROM notifications_outbox
WHERE template_key = 'rotation.preview' AND params->>'rotation_id' = $1`, runID).Scan(&status, &sent))
	return status, sent
}

func (e *keyEnv) plannedFor(runID string) time.Time {
	e.t.Helper()
	var at time.Time
	require.NoError(e.t, e.db.Owner.QueryRow(context.Background(), "SELECT planned_for FROM rotations WHERE id = $1", runID).Scan(&at))
	return at
}

// TestScheduledStartWaitsForADeliveredNotice (S1) over the wire, on a clock that moves on every read: a scheduled run
// starts only when its notice email was delivered (marked sent by the mail sender, as in production) before its planned
// start; with the notice still undelivered at the planned start it is cancelled rotation.notice_undelivered; a notice
// delivered after the planned start does not start it either. A cancelled run sends nothing and generates no key.
func TestScheduledStartWaitsForADeliveredNotice(t *testing.T) {
	t.Run("delivered before the start", func(t *testing.T) {
		e := newKeyEnv(t)
		e.tick.on.Store(true)
		k := e.generate(e.admin, "scheduled", "ed25519")
		e.deployed(k)
		r := e.scheduled(k)
		require.Positive(t, e.deliverMail())
		status, sent := e.notice(r.ID)
		require.Equal(t, "sent", status)
		require.True(t, sent.Before(e.plannedFor(r.ID)))
		e.sweep(1)
		assert.Equal(t, "dry_run_notified", e.run(e.admin, r.ID).Status, "nothing starts before the planned time")
		e.advance(e.plannedFor(r.ID).Sub(e.clock.Now()) + time.Second)
		e.sweep(2)
		got := e.run(e.admin, r.ID)
		require.Equal(t, "overlap", got.Status, "%+v", got)
		assert.Equal(t, []string{"dry_run_notified>adding_new", "adding_new>overlap"}, e.transitions(r.ID))
		newKey := decodeBody[map[string]any](t, e.admin.do(http.MethodGet, "/api/v1/ssh-keys/"+*got.NewSSHKeyID, nil))
		assert.True(t, e.f.emu.AcceptsLogin("deploy", parsePub(t, newKey["public_key"].(string))))
	})

	refused := func(t *testing.T, late bool) {
		e := newKeyEnv(t)
		e.tick.on.Store(true)
		k := e.generate(e.admin, "scheduled", "ed25519")
		e.deployed(k)
		writes := len(e.f.helperWrites())
		e.mailbox.setDown(true)
		r := e.scheduled(k)
		e.deliverMail()
		status, _ := e.notice(r.ID)
		require.Equal(t, "pending", status, "the SMTP server refused it; it is retried")
		e.advance(e.plannedFor(r.ID).Sub(e.clock.Now()) + time.Second)
		if late {
			e.mailbox.setDown(false)
			e.deliverMail()
			status, sent := e.notice(r.ID)
			require.Equal(t, "sent", status)
			require.True(t, sent.After(e.plannedFor(r.ID)), "delivered after the planned start")
		}
		e.sweep(2)
		got := e.run(e.admin, r.ID)
		assert.Equal(t, "cancelled", got.Status)
		require.NotNil(t, got.Result)
		assert.Equal(t, "rotation.notice_undelivered", got.Result["reason"])
		assert.Equal(t, "ALC-ROT-0017", got.Result["code"])
		assert.Nil(t, got.NewSSHKeyID, "no key was generated")
		assert.Len(t, e.f.helperWrites(), writes, "nothing was sent to the server")
		assert.Zero(t, e.countWhere("jobs", "type = 'rotation.location'"))
	}
	t.Run("undelivered at the start", func(t *testing.T) { refused(t, false) })
	t.Run("delivered after the start", func(t *testing.T) { refused(t, true) })
}

// assertGETsChangeNothing reads every Phase 6 GET route (and the inventory reads they build on) and requires that no
// table changed and no audit row was appended (A-06 for Phase 6 in the run's current state: the run detail computes
// its decisions and notice state on every read).
func (e *keyEnv) assertGETsChangeNothing(keyID, policyID, runID string) {
	e.t.Helper()
	var tables []string
	for _, table := range e.dumpTables() {
		// api_tokens: a token's last use is the credential's own bookkeeping (as a session's), not a resource's state.
		if table != "audit_log" && table != "api_tokens" {
			tables = append(tables, table)
		}
	}
	snapshot := func() map[string]string {
		m := map[string]string{}
		for _, table := range tables {
			m[table] = e.rowsChecksum(table, "true")
		}
		return m
	}
	token, _ := createToken(e.t, e.stack, e.admin, e.adminAcct, "read", 1)
	api := e.client("198.51.100.90")
	api.bearer = token
	before, seq := snapshot(), e.maxAuditSeq()
	for _, c := range []*client{e.admin, api} {
		for _, path := range []string{"/api/v1/ssh-keys", "/api/v1/ssh-keys/" + keyID, "/api/v1/targets/" + e.targetID + "/key-files",
			"/api/v1/targets/" + e.targetID + "/ssh-keys", "/api/v1/rotation/policies", "/api/v1/rotation/policies/" + policyID,
			"/api/v1/rotation/runs", "/api/v1/rotation/runs?policy_id=" + policyID, "/api/v1/rotation/runs/" + runID, "/api/v1/jobs"} {
			rec := c.do(http.MethodGet, path, nil)
			assert.Equal(e.t, http.StatusOK, rec.Code, "%s: %s", path, rec.Body.String())
			assert.Equal(e.t, before, snapshot(), "GET %s changed stored state", path)
			assert.Equal(e.t, seq, e.maxAuditSeq(), "GET %s appended audit rows", path)
		}
	}
}

// TestDeployOfARunsNewKeyIsRefused (re-review N-m11): while a rotation is unfinished its new key cannot be deployed
// elsewhere (a rollback of the run would remove that line too): 409 sshkey.in_rotation, nothing queued or written;
// once the run has completed the same deploy is accepted.
func TestDeployOfARunsNewKeyIsRefused(t *testing.T) {
	e := newKeyEnv(t)
	k := e.generate(e.admin, "in rotation", "ed25519")
	e.deployed(k)
	policyID, _ := e.createPolicy(e.admin, k.id, 1)
	runID := e.runNow(policyID, e.preview(e.admin, policyID).PlanDigest)
	e.drain()
	r := e.run(e.admin, runID)
	require.Equal(t, "overlap", r.Status)
	writes := len(e.f.helperWrites())
	rec := e.admin.do(http.MethodPost, "/api/v1/ssh-keys/"+*r.NewSSHKeyID+"/actions/deploy", map[string]any{"target_id": e.targetID,
		"os_user": "root", "file_path": rootKeysPath})
	requireStatus(t, rec, http.StatusConflict)
	assert.Equal(t, "sshkey.in_rotation", decodeBody[apiError](t, rec).Error.Reason, rec.Body.String())
	assert.True(t, strings.HasPrefix(errCode(rec), "ALC-KEY-"), rec.Body.String())
	assert.Zero(t, e.countWhere("jobs", "type = 'sshkey.add' AND payload->>'ssh_key_id' = '"+*r.NewSSHKeyID+"'"))
	e.drain()
	assert.Len(t, e.f.helperWrites(), writes)

	e.advance(24*time.Hour + time.Minute)
	e.sweep(3)
	require.Equal(t, "completed", e.run(e.admin, runID).Status)
	job := e.deploy(e.admin, *r.NewSSHKeyID, e.targetID, "root", rootKeysPath)
	e.drain()
	assert.Equal(t, "verified", e.job(e.admin, job)["result"].(map[string]any)["result"])
}

// TestUndoOfAnUnreadFileEndsListingIncomplete: Stop and undo while the key file cannot be read (the helper lists it
// without its content and refuses to read it): neither "new key absent" nor "old key gone" can be proven, so nothing
// is sent; after the bounded retries the place ends undo_failed with the reason rotation.listing_incomplete, the run
// needs attention, and the file is unchanged (both keys still there).
func TestUndoOfAnUnreadFileEndsListingIncomplete(t *testing.T) {
	e := newKeyEnv(t)
	k, _, runID := e.overlapRun(7)
	before := e.f.file(deployKeysPath)
	e.f.emu.FailRead(deployKeysPath)
	e.stepUp(e.admin, e.adminAcct)
	requireStatus(t, e.admin.do(http.MethodPost, "/api/v1/rotation/runs/"+runID+"/actions/abort", nil), http.StatusNoContent)
	for i := 0; i < 12 && !slices.Contains([]string{"needs_attention", "aborted"}, e.run(e.admin, runID).Status); i++ {
		e.drain()
		e.advance(10 * time.Minute)
		e.sweep(1)
	}
	r := e.run(e.admin, runID)
	assert.Equal(t, "needs_attention", r.Status, "%+v", r)
	require.Len(t, r.Locations, 1)
	assert.Equal(t, "undo_failed", r.Locations[0]["state"])
	errRef, _ := r.Locations[0]["error"].(map[string]any)
	assert.Equal(t, "rotation.listing_incomplete", errRef["reason"], "%v", r.Locations[0])
	assert.Equal(t, before, e.f.file(deployKeysPath), "nothing was sent to the unread file")
	assert.Contains(t, e.f.file(deployKeysPath), k.blob())
}

// TestRunNowReplayedWhileTheRunIsLive (I5): the same Run now (same digest, step-up) sent again after it was accepted
// is 409 ALC-ROT-0002: no second run, no second generated key, nothing more written.
func TestRunNowReplayedWhileTheRunIsLive(t *testing.T) {
	e := newKeyEnv(t)
	k := e.generate(e.admin, "replay", "ed25519")
	e.deployed(k)
	policyID, _ := e.createPolicy(e.admin, k.id, 7)
	digest := e.preview(e.admin, policyID).PlanDigest
	e.runNow(policyID, digest)
	keys := e.count("ssh_keys")
	e.stepUp(e.admin, e.adminAcct)
	requireError(t, e.admin.do(http.MethodPost, "/api/v1/rotation/policies/"+policyID+"/actions/run", map[string]string{"plan_digest": digest}),
		http.StatusConflict, "ALC-ROT-0002")
	e.drain()
	writes := len(e.f.helperWrites())
	requireError(t, e.admin.do(http.MethodPost, "/api/v1/rotation/policies/"+policyID+"/actions/run", map[string]string{"plan_digest": digest}),
		http.StatusConflict, "ALC-ROT-0002")
	e.drain()
	assert.Equal(t, 1, e.count("rotations"))
	assert.Equal(t, keys, e.count("ssh_keys"), "no second new key")
	assert.Len(t, e.f.helperWrites(), writes)
}

// TestFinishNowMailsTheNewRemovalTime (plan row 31): Finish now during the overlap ends it now and mails the
// Administrators the new removal time; the next sweep removes the old key after a fresh login.
func TestFinishNowMailsTheNewRemovalTime(t *testing.T) {
	e := newKeyEnv(t)
	k := e.generate(e.admin, "finish", "ed25519")
	e.deployed(k)
	policyID, _ := e.createPolicy(e.admin, k.id, 7)
	runID := e.runNow(policyID, e.preview(e.admin, policyID).PlanDigest)
	e.drain()
	e.advance(time.Hour)
	e.stepUp(e.admin, e.adminAcct)
	at := e.clock.Now()
	requireStatus(t, e.admin.do(http.MethodPost, "/api/v1/rotation/runs/"+runID+"/actions/finish-now", nil), http.StatusNoContent)
	var until string
	require.NoError(t, e.db.Owner.QueryRow(context.Background(), `SELECT params->>'overlap_until' FROM notifications_outbox
WHERE template_key = 'rotation.overlap_ending' ORDER BY created_at DESC LIMIT 1`).Scan(&until))
	assert.Equal(t, at.UTC().Format("2006-01-02 15:04 UTC"), until, "the mail names the new removal time")
	e.deliverMail()
	found := false
	for _, m := range e.mailbox.messages() {
		found = found || strings.Contains(m.Body, until)
	}
	assert.True(t, found, "the delivered email shows it")
	e.advance(time.Minute)
	e.sweep(3)
	assert.Equal(t, "completed", e.run(e.admin, runID).Status)
	assert.NotContains(t, e.f.file(deployKeysPath), k.blob())
}
