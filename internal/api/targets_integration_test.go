//go:build integration

package api

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"fmt"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/ssh"

	"alice/internal/providers/linuxssh/helperproto"
	"alice/internal/providers/linuxssh/linuxsshtest"
)

// End-to-end API journeys for Phase 3 (spec §26.5 owner steps 2–6, F-30..F-33, F-36, L-04,
// L-26, L-29, L-81): real services and jobs, a fake SSH server answering like alice-helper.

const (
	rootKeysPath   = "/root/.ssh/authorized_keys"
	deployKeysPath = "/home/deploy/.ssh/authorized_keys"
	aliceKeysPath  = "/var/lib/alice-svc/.ssh/authorized_keys"
)

// fixtureKey is a public key generated for one test (no key material is committed).
type fixtureKey struct {
	line string // "ssh-ed25519 AAAA…" without comment
	fp   string
}

func newFixtureKey(t testing.TB) fixtureKey {
	t.Helper()
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	sp, err := ssh.NewPublicKey(pub)
	require.NoError(t, err)
	return fixtureKey{line: strings.TrimSpace(string(ssh.MarshalAuthorizedKey(sp))), fp: ssh.FingerprintSHA256(sp)}
}

// sshFixture is one Linux server: the fake SSH server, its emulated helper and the files on it.
type sshFixture struct {
	server           *linuxsshtest.Server
	emu              *linuxsshtest.Emulator
	host             string
	port             int
	laptop, ci, root fixtureKey
	platform         string // Alice's key as "type base64"
	platformFP       string
	files            map[string]string // path -> content as seeded
}

func (s *stack) sshFixture() *sshFixture {
	t := s.t
	t.Helper()
	pk, err := s.inv.PlatformKey(context.Background())
	require.NoError(t, err)
	fields := strings.Fields(pk.PublicKey)
	require.GreaterOrEqual(t, len(fields), 2)
	pub, _, _, _, err := ssh.ParseAuthorizedKey([]byte(pk.PublicKey))
	require.NoError(t, err)

	f := &sshFixture{laptop: newFixtureKey(t), ci: newFixtureKey(t), root: newFixtureKey(t),
		platform: fields[0] + " " + fields[1], platformFP: pk.Fingerprint}
	require.Equal(t, ssh.FingerprintSHA256(pub), f.platformFP)
	f.files = map[string]string{
		rootKeysPath: `from="10.0.0.0/8" ` + f.root.line + " root@bastion\n",
		// Alice's key also sits in deploy's file under another comment: still Alice's key (F-36).
		deployKeysPath: f.laptop.line + " deploy@laptop\n" + f.ci.line + " ci@build\n" + f.platform + " copied-by-hand\n",
		aliceKeysPath:  "no-agent-forwarding,no-port-forwarding,no-X11-forwarding " + f.platform + " alice\n",
	}
	f.emu = linuxsshtest.NewEmulator()
	f.emu.SetSSHD("authorizedkeysfile .ssh/authorized_keys\nauthorizedkeyscommand none\npubkeyauthentication yes\n" +
		"passwordauthentication no\npermitrootlogin prohibit-password\nhostkey /etc/ssh/ssh_host_ed25519_key\n")
	for p, c := range f.files {
		f.emu.SetFile(p, []byte(c))
	}
	f.server = linuxsshtest.NewServer(t, f.emu.Handler())
	f.server.Authorize(pub)
	f.host, f.port = f.server.Addr()
	return f
}

// runJobs runs due jobs until none is due and returns how many ran.
func (s *stack) runJobs() int {
	s.t.Helper()
	for n := 0; n < 20; n++ {
		ran, err := s.runner.RunOnce(context.Background())
		require.NoError(s.t, err)
		if !ran {
			return n
		}
	}
	s.t.Fatal("jobs did not settle after 20 runs")
	return 0
}

func (s *stack) job(c *client, id string) map[string]any {
	s.t.Helper()
	rec := c.do(http.MethodGet, "/api/v1/jobs/"+id, nil)
	requireStatus(s.t, rec, http.StatusOK)
	return decodeBody[map[string]any](s.t, rec)
}

func jobErrorCode(job map[string]any) string {
	e, _ := job["error"].(map[string]any)
	code, _ := e["code"].(string)
	return code
}

func (s *stack) target(c *client, id string) map[string]any {
	s.t.Helper()
	rec := c.do(http.MethodGet, "/api/v1/targets/"+id, nil)
	requireStatus(s.t, rec, http.StatusOK)
	return decodeBody[map[string]any](s.t, rec)
}

func (s *stack) auditCount(action string) int {
	s.t.Helper()
	var n int
	require.NoError(s.t, s.db.Owner.QueryRow(context.Background(), "SELECT count(*) FROM audit_log WHERE action = $1", action).Scan(&n))
	return n
}

// addServer adds the fixture as a Linux server and returns the target and job IDs.
func (s *stack) addServer(c *client, name string, f *sshFixture) (string, string) {
	s.t.Helper()
	rec := c.do(http.MethodPost, "/api/v1/targets", map[string]any{"name": name, "host": f.host, "port": f.port, "username": "alice-svc"})
	requireStatus(s.t, rec, http.StatusCreated)
	body := decodeBody[map[string]any](s.t, rec)
	return body["target"].(map[string]any)["id"].(string), body["job_id"].(string)
}

// hostKeys lists the server's host keys.
func (s *stack) hostKeys(c *client, targetID string) []map[string]any {
	s.t.Helper()
	rec := c.do(http.MethodGet, "/api/v1/targets/"+targetID+"/host-keys", nil)
	requireStatus(s.t, rec, http.StatusOK)
	return decodeBody[struct {
		Items []map[string]any `json:"items"`
	}](s.t, rec).Items
}

func withStatus(keys []map[string]any, status string) []map[string]any {
	var out []map[string]any
	for _, k := range keys {
		if k["status"] == status {
			out = append(out, k)
		}
	}
	return out
}

// pinServer runs the first test, confirms the observed fingerprint and runs the test and the
// discovery that follow.
func (s *stack) pinServer(c *client, targetID string) {
	s.t.Helper()
	s.runJobs()
	observed := withStatus(s.hostKeys(c, targetID), "observed")
	require.Len(s.t, observed, 1)
	rec := c.do(http.MethodPost, "/api/v1/targets/"+targetID+"/host-keys/"+observed[0]["id"].(string)+"/actions/confirm",
		map[string]string{"fingerprint": observed[0]["fingerprint"].(string)})
	requireStatus(s.t, rec, http.StatusAccepted)
	s.runJobs()
	require.Equal(s.t, "ok", s.target(c, targetID)["status"])
}

func (s *stack) targetLocations(c *client, targetID string, missing bool) []map[string]any {
	s.t.Helper()
	path := "/api/v1/targets/" + targetID + "/ssh-keys"
	if missing {
		path += "?missing=true"
	}
	rec := c.do(http.MethodGet, path, nil)
	requireStatus(s.t, rec, http.StatusOK)
	return decodeBody[struct {
		Items []map[string]any `json:"items"`
	}](s.t, rec).Items
}

func locationOf(t testing.TB, locs []map[string]any, osUser, fp string) map[string]any {
	t.Helper()
	for _, l := range locs {
		if l["os_user"] == osUser && l["fingerprint"] == fp {
			return l
		}
	}
	t.Fatalf("no location of %s for %s", fp, osUser)
	return nil
}

// F-30, owner steps 2–3: the fingerprint is shown, nothing is trusted or run until an
// Administrator confirms it; then the inventory matches the server's files exactly.
func TestAddServerJourney(t *testing.T) {
	s, admin, _ := installed(t)
	f := s.sshFixture()
	targetID, jobID := s.addServer(admin, "web-01", f)

	assert.Equal(t, 1, s.runJobs())
	job := s.job(admin, jobID)
	assert.Equal(t, "failed", job["status"])
	assert.Equal(t, "ALC-TGT-0002", jobErrorCode(job))
	assert.Equal(t, "pending_host_key", s.target(admin, targetID)["status"])
	assert.Zero(t, f.server.AuthAttempts(), "no authentication before the fingerprint is confirmed")
	assert.Empty(t, f.server.Commands(), "no command before the fingerprint is confirmed")

	keys := s.hostKeys(admin, targetID)
	require.Len(t, keys, 1)
	assert.Equal(t, "observed", keys[0]["status"])
	assert.Equal(t, ssh.FingerprintSHA256(f.server.HostKey()), keys[0]["fingerprint"])
	assert.Equal(t, "ssh-keygen -lf /etc/ssh/ssh_host_ed25519_key.pub", keys[0]["verify_command"])

	confirm := "/api/v1/targets/" + targetID + "/host-keys/" + keys[0]["id"].(string) + "/actions/confirm"
	requireError(t, admin.do(http.MethodPost, confirm, map[string]string{"fingerprint": "SHA256:" + strings.Repeat("A", 43)}),
		http.StatusConflict, "ALC-TGT-0003")
	assert.Empty(t, withStatus(s.hostKeys(admin, targetID), "pinned"))
	assert.Zero(t, s.auditCount("hostkey.pinned"))

	requireStatus(t, admin.do(http.MethodPost, confirm, map[string]string{"fingerprint": keys[0]["fingerprint"].(string)}), http.StatusAccepted)
	var who string
	require.NoError(t, s.db.Owner.QueryRow(context.Background(), "SELECT actor_name FROM audit_log WHERE action = 'hostkey.pinned'").Scan(&who))
	assert.Equal(t, "ada", who, "F-30: the pin is audited with the confirming user")

	assert.Equal(t, 2, s.runJobs(), "a connection test, then the discovery it starts")
	tg := s.target(admin, targetID)
	assert.Equal(t, "ok", tg["status"])
	assert.Equal(t, float64(helperproto.Protocol), tg["facts"].(map[string]any)["helper_protocol"])
	assert.Positive(t, f.server.AuthAttempts())

	got := map[string]bool{}
	for _, l := range s.targetLocations(admin, targetID, false) {
		got[fmt.Sprintf("%s|%s|%s|%v", l["os_user"], l["file_path"], l["fingerprint"], l["is_alice_connection_key"])] = true
	}
	assert.Equal(t, map[string]bool{
		"root|" + rootKeysPath + "|" + f.root.fp + "|false":         true,
		"deploy|" + deployKeysPath + "|" + f.laptop.fp + "|false":   true,
		"deploy|" + deployKeysPath + "|" + f.ci.fp + "|false":       true,
		"deploy|" + deployKeysPath + "|" + f.platformFP + "|true":   true,
		"alice-svc|" + aliceKeysPath + "|" + f.platformFP + "|true": true,
	}, got, "the inventory matches the seeded files exactly (§26.5 exit criterion)")

	rec := admin.do(http.MethodGet, "/api/v1/ssh-keys?target_id="+targetID, nil)
	requireStatus(t, rec, http.StatusOK)
	page := decodeBody[struct {
		Items []map[string]any `json:"items"`
	}](t, rec)
	assert.Len(t, page.Items, 4, "one row per distinct key")
	for _, k := range page.Items {
		assert.Equal(t, k["fingerprint"] == f.platformFP, k["is_platform_key"], k["fingerprint"])
	}
}

// F-36, owner step 4: Alice's own key is refused in every file and under any comment; nothing is
// written and no job is queued.
func TestOwnKeyRemovalIsRefused(t *testing.T) {
	s, admin, _ := installed(t)
	f := s.sshFixture()
	targetID, _ := s.addServer(admin, "web-01", f)
	s.pinServer(admin, targetID)
	locs := s.targetLocations(admin, targetID, false)

	for _, user := range []string{"alice-svc", "deploy"} {
		loc := locationOf(t, locs, user, f.platformFP)
		rec := admin.do(http.MethodPost, "/api/v1/ssh-keys/locations/"+loc["id"].(string)+"/actions/remove", nil)
		requireError(t, rec, http.StatusConflict, "ALC-KEY-0001")
		assert.Contains(t, decodeBody[apiError](t, rec).Error.Message, "Alice needs this key to connect to this server and will not remove it.")
	}
	assert.Equal(t, 2, s.auditCount("sshkey.remove.denied"))
	assert.Empty(t, f.emu.Writes())
	var queued int
	require.NoError(t, s.db.Owner.QueryRow(context.Background(), "SELECT count(*) FROM jobs WHERE type = 'sshkey.remove'").Scan(&queued))
	assert.Zero(t, queued)
	for p, c := range f.files {
		got, ok := f.emu.File(p)
		require.True(t, ok)
		assert.Equal(t, c, string(got), p)
	}
}

// An Operator removes another key (§15.4): only that line goes, every other byte stays.
func TestRemoveKeyJourney(t *testing.T) {
	s, admin, adminAcct := installed(t)
	f := s.sshFixture()
	targetID, _ := s.addServer(admin, "web-01", f)
	s.pinServer(admin, targetID)
	operator := s.createUser(admin, adminAcct, "otto", "operator", "operator-password-2026")
	oc := s.freshClient()
	s.firstSignIn(oc, operator)

	loc := locationOf(t, s.targetLocations(oc, targetID, false), "deploy", f.laptop.fp)
	rec := oc.do(http.MethodPost, "/api/v1/ssh-keys/locations/"+loc["id"].(string)+"/actions/remove", nil)
	requireStatus(t, rec, http.StatusAccepted)
	jobID := decodeBody[map[string]string](t, rec)["job_id"]
	assert.Equal(t, 1, s.runJobs())
	assert.Equal(t, "succeeded", s.job(oc, jobID)["status"])

	deploy, _ := f.emu.File(deployKeysPath)
	assert.Equal(t, f.ci.line+" ci@build\n"+f.platform+" copied-by-hand\n", string(deploy), "only the removed line is gone")
	for _, p := range []string{rootKeysPath, aliceKeysPath} {
		got, _ := f.emu.File(p)
		assert.Equal(t, f.files[p], string(got), p)
	}
	assert.Equal(t, []string{deployKeysPath}, f.emu.Writes())
	assert.Equal(t, 1, s.auditCount("sshkey.removed"))
	removed := locationOf(t, s.targetLocations(oc, targetID, true), "deploy", f.laptop.fp)
	assert.NotNil(t, removed["removed_at"])
}

// F-31..F-33, owner step 5, Review Focus 5: a changed host key stops everything before
// authentication, emails the administrators once, and only an Administrator with step-up and a
// reason can accept it; the old fingerprint stays in the history.
func TestChangedHostKeyJourney(t *testing.T) {
	s, admin, adminAcct := installed(t)
	s.stepUp(admin, adminAcct)
	requireStatus(t, admin.do(http.MethodPatch, "/api/v1/users/"+adminAcct.id, map[string]string{"email": "ada@example.com"}), http.StatusOK)
	f := s.sshFixture()
	targetID, _ := s.addServer(admin, "web-01", f)
	s.pinServer(admin, targetID)
	oldFP := ssh.FingerprintSHA256(f.server.HostKey())
	laptop := locationOf(t, s.targetLocations(admin, targetID, false), "deploy", f.laptop.fp)

	attempts, commands := f.server.AuthAttempts(), len(f.server.Commands())
	f.server.SetHostKey(linuxsshtest.NewHostKey(t))
	outbox := func() int {
		var n int
		require.NoError(t, s.db.Owner.QueryRow(context.Background(),
			"SELECT count(*) FROM notifications_outbox WHERE template_key = 'target.host_key_changed'").Scan(&n))
		return n
	}

	dials := f.server.Connections()
	for i := 0; i < 2; i++ { // the second test must neither dial nor email again
		rec := admin.do(http.MethodPost, "/api/v1/targets/"+targetID+"/actions/test", nil)
		requireStatus(t, rec, http.StatusAccepted)
		assert.Equal(t, 1, s.runJobs())
		// The first test dials a fresh connection and sees the new key; the second fails without
		// dialing (A-14: the server counts every TCP connection, not only authentications).
		assert.Equal(t, "ALC-TGT-0004", jobErrorCode(s.job(admin, decodeBody[map[string]string](t, rec)["job_id"])), "test %d", i)
		assert.Equal(t, "host_key_changed", s.target(admin, targetID)["status"], "test %d", i)
		assert.Equal(t, dials+1, f.server.Connections(), "test %d: one dial in total", i)
	}
	assert.Equal(t, "host_key_changed", s.target(admin, targetID)["status"])
	assert.Equal(t, attempts, f.server.AuthAttempts(), "F-31: no authentication reaches the server")
	assert.Equal(t, commands, len(f.server.Commands()))
	assert.Equal(t, 1, outbox(), "one email for the one administrator with an address")
	assert.Equal(t, 1, s.auditCount("hostkey.changed"))

	requireError(t, admin.do(http.MethodPost, "/api/v1/targets/"+targetID+"/actions/discover", nil), http.StatusConflict, "ALC-TGT-0004")
	requireError(t, admin.do(http.MethodPost, "/api/v1/ssh-keys/locations/"+laptop["id"].(string)+"/actions/remove", nil),
		http.StatusConflict, "ALC-TGT-0004")

	s.clock.Advance(25 * time.Hour)                          // nightly discovery is due, but the server is blocked
	require.NoError(t, s.license.Tick(context.Background())) // the hourly evaluation ran meanwhile (AUD-02)
	n, err := s.inv.ScheduleDiscovery(context.Background())
	require.NoError(t, err)
	assert.Zero(t, n)
	assert.Zero(t, s.runJobs())
	assert.Equal(t, commands, len(f.server.Commands()))

	s.signIn(admin, adminAcct) // the old session reached its 12-hour limit
	operator := s.createUser(admin, adminAcct, "otto", "operator", "operator-password-2026")
	oc := s.freshClient()
	s.firstSignIn(oc, operator)
	observed := withStatus(s.hostKeys(admin, targetID), "observed")
	require.Len(t, observed, 1)
	newFP := observed[0]["fingerprint"].(string)
	assert.NotEqual(t, oldFP, newFP)
	repin := "/api/v1/targets/" + targetID + "/host-keys/" + observed[0]["id"].(string) + "/actions/repin"
	body := map[string]string{"fingerprint": newFP, "reason": "Server reinstalled by the platform team (ticket 4711)"}

	denied := s.auditCount("authz.denied")
	requireError(t, oc.do(http.MethodPost, repin, body), http.StatusForbidden, "ALC-AUTH-0002") // F-33
	assert.Equal(t, denied+1, s.auditCount("authz.denied"))

	s.clock.Advance(6 * time.Minute) // the step-up window of the sign-in has closed
	requireError(t, admin.do(http.MethodPost, repin, body), http.StatusForbidden, "ALC-AUTH-0003")
	s.stepUp(admin, adminAcct)
	requireError(t, admin.do(http.MethodPost, repin, map[string]string{"fingerprint": newFP, "reason": "short"}),
		http.StatusUnprocessableEntity, "ALC-SYS-0006")
	requireStatus(t, admin.do(http.MethodPost, repin, body), http.StatusAccepted)
	assert.Equal(t, 1, s.auditCount("hostkey.repinned"))

	history := s.hostKeys(admin, targetID)
	require.Len(t, withStatus(history, "pinned"), 1)
	assert.Equal(t, newFP, withStatus(history, "pinned")[0]["fingerprint"])
	require.Len(t, withStatus(history, "superseded"), 1)
	assert.Equal(t, oldFP, withStatus(history, "superseded")[0]["fingerprint"], "F-32: the old fingerprint stays in the history")

	assert.GreaterOrEqual(t, s.runJobs(), 1)
	assert.Equal(t, "ok", s.target(admin, targetID)["status"])
	assert.Greater(t, f.server.AuthAttempts(), attempts, "operations resume after the re-pin")
}

// A false alarm: the server shows its confirmed key again, but the target stays blocked until an
// Administrator dismisses the change by "re-pinning" the pinned key (step-up and a reason); the
// candidate is rejected, nothing is superseded and work resumes.
func TestDismissedHostKeyChange(t *testing.T) {
	s, admin, adminAcct := installed(t)
	f := s.sshFixture()
	original := linuxsshtest.NewHostKey(t)
	f.server.SetHostKey(original)
	targetID, _ := s.addServer(admin, "web-01", f)
	s.pinServer(admin, targetID)
	pinned := withStatus(s.hostKeys(admin, targetID), "pinned")
	require.Len(t, pinned, 1)
	require.Equal(t, ssh.FingerprintSHA256(original.PublicKey()), pinned[0]["fingerprint"])

	f.server.SetHostKey(linuxsshtest.NewHostKey(t))
	requireStatus(t, admin.do(http.MethodPost, "/api/v1/targets/"+targetID+"/actions/test", nil), http.StatusAccepted)
	assert.Equal(t, 1, s.runJobs())
	require.Equal(t, "host_key_changed", s.target(admin, targetID)["status"])

	f.server.SetHostKey(original) // the confirmed key is back: still blocked until a person decides
	attempts := f.server.AuthAttempts()
	requireStatus(t, admin.do(http.MethodPost, "/api/v1/targets/"+targetID+"/actions/test", nil), http.StatusAccepted)
	assert.Equal(t, 1, s.runJobs())
	assert.Equal(t, "host_key_changed", s.target(admin, targetID)["status"])
	assert.Equal(t, attempts, f.server.AuthAttempts(), "a blocked server is not dialed")

	s.stepUp(admin, adminAcct)
	dismiss := "/api/v1/targets/" + targetID + "/host-keys/" + pinned[0]["id"].(string) + "/actions/repin"
	requireStatus(t, admin.do(http.MethodPost, dismiss, map[string]string{"fingerprint": pinned[0]["fingerprint"].(string),
		"reason": "False alarm: the load balancer briefly routed to the standby"}), http.StatusAccepted)
	assert.Equal(t, 1, s.auditCount("hostkey.change_dismissed"))
	assert.Zero(t, s.auditCount("hostkey.repinned"))

	history := s.hostKeys(admin, targetID)
	require.Len(t, withStatus(history, "pinned"), 1)
	assert.Equal(t, pinned[0]["id"], withStatus(history, "pinned")[0]["id"], "the confirmed key stays pinned")
	assert.Empty(t, withStatus(history, "superseded"))
	assert.Empty(t, withStatus(history, "observed"), "the candidate can no longer be confirmed")
	assert.Len(t, withStatus(history, "rejected"), 1)

	assert.GreaterOrEqual(t, s.runJobs(), 1)
	assert.Equal(t, "ok", s.target(admin, targetID)["status"])
	assert.Greater(t, f.server.AuthAttempts(), attempts, "operations resume after the dismissal")
}

// L-26, L-29: in lock every infrastructure change is refused and audited, reads work, queued
// read-only work is not claimed, and no command reaches the server.
func TestLockRefusesInfrastructureChanges(t *testing.T) {
	s, admin, adminAcct := installed(t)
	f := s.sshFixture()
	targetID, _ := s.addServer(admin, "web-01", f)
	s.pinServer(admin, targetID)
	laptop := locationOf(t, s.targetLocations(admin, targetID, false), "deploy", f.laptop.fp)
	rec := admin.do(http.MethodPost, "/api/v1/targets/"+targetID+"/actions/discover", nil)
	requireStatus(t, rec, http.StatusAccepted)
	queuedDiscovery := decodeBody[map[string]string](t, rec)["job_id"]

	counts := func() map[string]int {
		out := map[string]int{}
		for _, table := range []string{"targets", "host_keys", "ssh_keys", "ssh_key_locations", "credentials"} {
			out[table] = s.count(table)
		}
		return out
	}
	rec = admin.do(http.MethodPost, "/api/v1/certificates/csr", map[string]any{"common_name": "www.example.test", "key_type": "ecdsa-p256"})
	requireStatus(t, rec, http.StatusCreated)
	csrID := decodeBody[map[string]any](t, rec)["id"].(string)
	before, commands := counts(), len(f.server.Commands())
	storedKeys, csrs := s.count("managed_private_keys"), s.count("csr_requests")

	s.clock.Advance(31 * 24 * time.Hour) // the evaluation ends (R1)
	require.NoError(t, s.license.Tick(t.Context()))
	require.True(t, s.license.Snapshot().Eval.Locked())
	s.signIn(admin, adminAcct)
	s.stepUp(admin, adminAcct) // so a refusal can only come from the license gate, not from step-up
	pinned := withStatus(s.hostKeys(admin, targetID), "pinned")
	require.Len(t, pinned, 1)
	hostKey := "/api/v1/targets/" + targetID + "/host-keys/" + pinned[0]["id"].(string)
	fingerprint := map[string]string{"fingerprint": pinned[0]["fingerprint"].(string)}

	denied := s.auditCount("request.denied_license")
	requests := []struct {
		method, path string
		body         any
	}{
		{http.MethodPost, "/api/v1/targets", map[string]any{"name": "web-02", "host": "web-02.example.test"}},
		{http.MethodPatch, "/api/v1/targets/" + targetID, map[string]any{"name": "web-01b"}},
		{http.MethodDelete, "/api/v1/targets/" + targetID, nil},
		{http.MethodPost, "/api/v1/targets/" + targetID + "/actions/test", nil},
		{http.MethodPost, "/api/v1/targets/" + targetID + "/actions/discover", nil},
		{http.MethodPost, hostKey + "/actions/confirm", fingerprint},
		{http.MethodPost, hostKey + "/actions/repin", map[string]string{"fingerprint": fingerprint["fingerprint"],
			"reason": "False alarm reported by the monitoring team"}},
		{http.MethodPost, "/api/v1/ssh-keys/locations/" + laptop["id"].(string) + "/actions/remove", nil},
		{http.MethodPost, "/api/v1/jobs/" + queuedDiscovery + "/actions/confirm", nil},
		// Phase 4: certificates, signing requests, deployments and location settings (the lock is
		// decided before the body is read, so no body has to be valid).
		{http.MethodPost, "/api/v1/certificates/upload", map[string]any{"certificate_pem": "x", "private_key_pem": "y"}},
		{http.MethodPost, "/api/v1/certificates/csr", map[string]any{"common_name": "www.example.test", "key_type": "ecdsa-p256"}},
		{http.MethodPost, "/api/v1/certificates/csr/" + csrID + "/actions/complete", map[string]any{"certificate_pem": "x"}},
		{http.MethodPost, "/api/v1/certificates/csr/" + csrID + "/actions/cancel", nil},
		{http.MethodPost, "/api/v1/certificates/" + uuid.NewString() + "/deploy", map[string]any{"location_ids": []string{uuid.NewString()}}},
		{http.MethodPatch, "/api/v1/locations/" + uuid.NewString(), map[string]any{"skip_verify": true}},
	}
	for _, rq := range requests {
		requireError(t, admin.do(rq.method, rq.path, rq.body), http.StatusForbidden, "ALC-LIC-0001")
	}
	assert.Equal(t, denied+len(requests), s.auditCount("request.denied_license"))
	assert.Equal(t, "web-01", s.target(admin, targetID)["name"])
	for _, path := range []string{"/api/v1/targets", "/api/v1/targets/" + targetID, "/api/v1/targets/" + targetID + "/ssh-keys",
		"/api/v1/targets/" + targetID + "/host-keys", "/api/v1/ssh-keys", "/api/v1/jobs",
		"/api/v1/certificates", "/api/v1/certificates/csr", "/api/v1/certificates/csr/" + csrID, "/api/v1/deployments",
		"/api/v1/targets/" + targetID + "/certificate-locations"} {
		requireStatus(t, admin.do(http.MethodGet, path, nil), http.StatusOK)
	}

	s.runJobs()
	assert.Equal(t, "cancelled", s.job(admin, queuedDiscovery)["status"], "§8.6: queued read-only work is cancelled in lock")
	assert.Equal(t, commands, len(f.server.Commands()), "L-29: no remote command in lock")
	assert.Equal(t, before, counts(), "L-29: nothing deleted or added")
	assert.Equal(t, storedKeys, s.count("managed_private_keys"), "L-29: no key was stored in lock")
	assert.Equal(t, csrs, s.count("csr_requests"), "L-29: no signing request was changed in lock")
	assert.Equal(t, "pending", decodeBody[map[string]any](t, admin.do(http.MethodGet, "/api/v1/certificates/csr/"+csrID, nil))["status"])
}

// L-81, R29: a removal queued before the lock is not run; after the renewal it waits for an
// Administrator's confirmation, then runs.
func TestBlockedRemovalNeedsConfirmation(t *testing.T) {
	s, admin, adminAcct := installed(t)
	f := s.sshFixture()
	targetID, _ := s.addServer(admin, "web-01", f)
	s.pinServer(admin, targetID)
	laptop := locationOf(t, s.targetLocations(admin, targetID, false), "deploy", f.laptop.fp)
	rec := admin.do(http.MethodPost, "/api/v1/ssh-keys/locations/"+laptop["id"].(string)+"/actions/remove", nil)
	requireStatus(t, rec, http.StatusAccepted)
	jobID := decodeBody[map[string]string](t, rec)["job_id"]

	s.clock.Advance(31 * 24 * time.Hour)
	require.NoError(t, s.license.Tick(t.Context()))
	s.signIn(admin, adminAcct)
	s.runJobs()
	assert.Equal(t, "blocked_license", s.job(admin, jobID)["status"])
	assert.GreaterOrEqual(t, s.auditCount("job.blocked_license"), 1)
	assert.Empty(t, f.emu.Writes())

	rec = admin.do(http.MethodGet, "/api/v1/jobs?status=blocked_license", nil)
	requireStatus(t, rec, http.StatusOK)
	var listed []string
	for _, j := range decodeBody[struct {
		Items []map[string]any `json:"items"`
	}](t, rec).Items {
		listed = append(listed, j["id"].(string))
	}
	assert.Equal(t, []string{jobID}, listed)

	now := s.clock.Now()
	s.stepUp(admin, adminAcct)
	requireStatus(t, admin.do(http.MethodPost, "/api/v1/license", map[string]string{"license": s.signedLicense("LIC-R", now, now.AddDate(1, 0, 0), 10)}),
		http.StatusOK)
	assert.Zero(t, s.runJobs(), "after the renewal the paused change does not start by itself")
	assert.Equal(t, "blocked_license", s.job(admin, jobID)["status"])

	operator := s.createUser(admin, adminAcct, "otto", "operator", "operator-password-2026")
	oc := s.freshClient()
	s.firstSignIn(oc, operator)
	requireError(t, oc.do(http.MethodPost, "/api/v1/jobs/"+jobID+"/actions/confirm", nil), http.StatusForbidden, "ALC-AUTH-0002")

	rec = admin.do(http.MethodPost, "/api/v1/jobs/"+jobID+"/actions/confirm", nil)
	requireStatus(t, rec, http.StatusOK)
	assert.Equal(t, "queued", decodeBody[map[string]any](t, rec)["status"])
	assert.Equal(t, 1, s.auditCount("job.confirmed"))
	requireError(t, admin.do(http.MethodPost, "/api/v1/jobs/"+jobID+"/actions/confirm", nil), http.StatusConflict, "ALC-JOB-0001")

	assert.Equal(t, 1, s.runJobs())
	assert.Equal(t, "succeeded", s.job(admin, jobID)["status"])
	deploy, _ := f.emu.File(deployKeysPath)
	assert.NotContains(t, string(deploy), f.laptop.line)
}

// L-04, carry 5: the evaluation allows five servers; the sixth is refused and audited, and the
// administrator sees the "all licensed targets in use" banner.
func TestEvaluationLimitViaAPI(t *testing.T) {
	s, admin, _ := installed(t)
	for i := 1; i <= 5; i++ {
		rec := admin.do(http.MethodPost, "/api/v1/targets", map[string]any{"name": fmt.Sprintf("web-%d", i), "host": fmt.Sprintf("web-%d.example.test", i)})
		requireStatus(t, rec, http.StatusCreated)
	}
	rec := admin.do(http.MethodPost, "/api/v1/targets", map[string]any{"name": "web-6", "host": "web-6.example.test"})
	requireError(t, rec, http.StatusConflict, "ALC-LIC-0008")
	assert.Equal(t, map[string]string{"used": "5", "max": "5"}, decodeBody[paramsBody](t, rec).Error.Params)
	assert.Equal(t, 5, s.count("targets"))
	assert.Equal(t, 1, s.auditCount("target.add.denied_license"))

	st := decodeBody[map[string]any](t, admin.do(http.MethodGet, "/api/v1/license/status", nil))
	var kinds []string
	for _, b := range st["banners"].([]any) {
		kinds = append(kinds, b.(map[string]any)["kind"].(string))
	}
	assert.Contains(t, kinds, "limit_reached", "the snapshot counts targets right after the commit")
}
