//go:build release

package release

import (
	"bytes"
	"crypto/x509"
	"encoding/binary"
	"fmt"
	"maps"
	"net/http"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"alice/internal/testutil/pki"
)

const (
	// mailPassword is the SMTP password of the drill: a canary that must never appear in the backup file.
	mailPassword = "CANARY-release-smtp-password-3f9a"
	msgDamaged   = "The passphrase is wrong or the file is damaged. Nothing was changed."
	msgNotBackup = "This is not an Alice backup."
	wwwSite      = "www.example.test"
)

// eventually polls check every interval until it succeeds or timeout passes; the last reason is in the failure.
func eventually(t testing.TB, timeout, interval time.Duration, what string, check func() (bool, string)) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for {
		done, reason := check()
		if done {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("%s: not done after %s: %s", what, timeout, reason)
		}
		time.Sleep(interval)
	}
}

// target is the e2e SSH and Nginx target of an installation, attached to its frontend network as "sshtarget".
type target struct {
	name     string // container name
	id       string // Alice's target ID
	location string // the location ID of www.example.test
}

func (i *inst) frontend() string { return i.project + "_frontend" }

// startTarget starts the target container on the installation's frontend network.
func (i *inst) startTarget() *target {
	t := i.t
	t.Helper()
	tg := &target{name: i.project + "-target"}
	trackContainer(tg.name)
	i.extra = append(i.extra, tg.name)
	must(t, docker(t, "run", "-d", "--name", tg.name, "--network", i.frontend(), "--network-alias", "sshtarget", targetImage), "start the SSH target")
	eventually(t, time.Minute, time.Second, "the target's sshd and nginx", func() (bool, string) {
		r := docker(t, "exec", tg.name, "sh", "-c", "test -f /etc/nginx/ssl/www.crt && pgrep -x sshd >/dev/null")
		return r.Code == 0, r.Out
	})
	return tg
}

func (tg *target) exec(t testing.TB, stdin []byte, args ...string) result {
	t.Helper()
	return runCmd(t, stdin, "docker", append([]string{"exec", "-i", tg.name}, args...)...)
}

// addTarget prepares the target with the setup script Alice shows, adds it, confirms its host key after comparing it
// with the server's own, and waits for the discovery of www.example.test (the e2e journeys' steps, through the API).
func (i *inst) addTarget(c *client, tg *target) {
	t := i.t
	t.Helper()
	key := c.expect(http.StatusOK, http.MethodGet, "/api/v1/ssh-keys/platform-key", nil)
	script := str(t, key, "profiles", "nginx", "script")
	must(t, tg.exec(t, []byte(script), "/usr/local/sbin/alice-e2e-prepare"), "run the setup script on the target")
	created := c.expect(http.StatusCreated, http.MethodPost, "/api/v1/targets", map[string]any{
		"type": "nginx", "name": "web-1", "host": "sshtarget", "port": 22, "username": "alice-svc",
	})
	tg.id = str(t, created, "target", "id")
	onServer := regexp.MustCompile(`SHA256:[A-Za-z0-9+/]+`).FindString(must(t, tg.exec(t, nil, "ssh-keygen", "-lf", "/etc/ssh/ssh_host_ed25519_key.pub"), "ssh-keygen").Out)
	require.NotEmpty(t, onServer)
	var keyID string
	eventually(t, 2*time.Minute, 2*time.Second, "the observed host key", func() (bool, string) {
		code, out, _ := c.call(http.MethodGet, "/api/v1/targets/"+tg.id+"/host-keys", nil)
		var v struct {
			Items []struct{ ID, Status, Fingerprint string }
		}
		if code != http.StatusOK || jsonUnmarshal(out, &v) != nil {
			return false, string(out)
		}
		for _, k := range v.Items {
			if k.Status == "observed" && k.Fingerprint == onServer {
				keyID = k.ID
				return true, ""
			}
		}
		return false, string(out)
	})
	c.expect(http.StatusAccepted, http.MethodPost, "/api/v1/targets/"+tg.id+"/host-keys/"+keyID+"/actions/confirm", map[string]string{"fingerprint": onServer})
	eventually(t, 3*time.Minute, 2*time.Second, "the discovery of "+wwwSite, func() (bool, string) {
		code, out, _ := c.call(http.MethodGet, "/api/v1/targets/"+tg.id+"/certificate-locations", nil)
		var v struct {
			Items []struct {
				ID      string
				Servers []struct{ Names []string }
			}
		}
		if code != http.StatusOK || jsonUnmarshal(out, &v) != nil {
			return false, string(out)
		}
		for _, l := range v.Items {
			for _, s := range l.Servers {
				for _, n := range s.Names {
					if n == wwwSite {
						tg.location = l.ID
						return true, ""
					}
				}
			}
		}
		return false, string(out)
	})
}

// newCertFromTarget is a certificate for name signed by the target's test CA, with its key.
func newCertFromTarget(t testing.TB, tg *target, name string) (certPEM, keyPEM string) {
	t.Helper()
	out := must(t, tg.exec(t, nil, "/usr/local/sbin/alice-e2e-newcert", name), "alice-e2e-newcert").Out
	m := regexp.MustCompile(`(?s)-----ALICE CERT-----\n(.+?)-----ALICE KEY-----\n(.+?)-----ALICE END-----`).FindStringSubmatch(out)
	require.NotNil(t, m)
	return m[1], m[2]
}

// upload uploads a certificate with its key and returns its ID.
func upload(c *client, label, certPEM, keyPEM string) string {
	c.t.Helper()
	v := c.expect(http.StatusCreated, http.MethodPost, "/api/v1/certificates/upload", map[string]string{
		"label": label, "certificate_pem": certPEM, "private_key_pem": keyPEM,
	})
	return str(c.t, v, "certificate", "id")
}

// waitJob waits until a job ends and requires it to have succeeded.
func waitJob(c *client, id string) {
	c.t.Helper()
	var last map[string]any
	eventually(c.t, 3*time.Minute, 2*time.Second, "job "+id, func() (bool, string) {
		last = c.expect(http.StatusOK, http.MethodGet, "/api/v1/jobs/"+id, nil)
		switch last["status"] {
		case "queued", "running":
			return false, fmt.Sprint(last)
		}
		return true, ""
	})
	require.Equal(c.t, "succeeded", last["status"], "job %s: %v", id, last)
}

// deploy deploys a certificate to one location and waits until the deployment succeeded.
func deploy(c *client, certID, location string) {
	c.t.Helper()
	v := c.expect(http.StatusAccepted, http.MethodPost, "/api/v1/certificates/"+certID+"/deploy", map[string]any{
		"location_ids": []string{location}, "confirm_incomplete_chain": true,
	})
	deps, isList := v["deployments"].([]any)
	require.True(c.t, isList && len(deps) == 1, "%v", v)
	id := str(c.t, deps[0].(map[string]any), "id")
	var last map[string]any
	eventually(c.t, 4*time.Minute, 2*time.Second, "deployment "+id, func() (bool, string) {
		last = c.expect(http.StatusOK, http.MethodGet, "/api/v1/deployments/"+id, nil)
		switch last["status"] {
		case "succeeded", "failed", "rolled_back", "rollback_failed", "outcome_unknown", "cancelled":
			return true, ""
		}
		return false, fmt.Sprint(last["status"])
	})
	require.Equal(c.t, "succeeded", last["status"], "deployment %s: %v", id, last)
}

// facts are what the drill compares before the backup and after the restore (§20.6 step 2).
type facts struct {
	counts         map[string]int64
	headSeq        string
	headHash       string
	installationID string
	phase          string
}

var auditHead = regexp.MustCompile(`The audit log is intact: \d+ entries checked, head entry (\d+), head hash ([0-9a-f]{64})\.`)

func (i *inst) facts(c *client) facts {
	i.t.Helper()
	r := must(i.t, i.alicectl("audit", "verify"), "alicectl audit verify")
	m := auditHead.FindStringSubmatch(r.Out)
	require.NotNil(i.t, m, r.Out)
	lic := c.expect(http.StatusOK, http.MethodGet, "/api/v1/license", nil)
	require.Equal(i.t, m[2], i.psql("SELECT encode(hash, 'hex') FROM audit_log WHERE seq = "+m[1]))
	// alicectl audit verify appended its own audit.verified entry after the entries it checked: the head of the chain
	// that goes into the backup is that entry, the one after the head it reported.
	// A scheduled verification (M-6, scheduledVerify) between this and the backup would move the head and fail the
	// drill loudly; it cannot happen: its ticker first fires an hour after the Alice process started, and the drill's
	// installation runs for minutes.
	last := strings.Split(i.psql("SELECT seq || ' ' || encode(hash, 'hex') || ' ' || action FROM audit_log ORDER BY seq DESC LIMIT 1"), " ")
	require.Len(i.t, last, 3)
	require.Equal(i.t, "audit.verified", last[2])
	return facts{counts: i.counts(), headSeq: last[0], headHash: last[1], installationID: str(i.t, lic, "installation_id"), phase: str(i.t, lic, "phase")}
}

// backupName runs alicectl backup and returns the file's name.
func (i *inst) backup() string {
	i.t.Helper()
	r := must(i.t, i.alicectl("backup"), "alicectl backup")
	m := regexp.MustCompile(`Backup written: /opt/alice/backups/([A-Za-z0-9._-]+\.alicebak) \(`).FindStringSubmatch(r.Out)
	require.NotNil(i.t, m, r.Out)
	return m[1]
}

// TestReleaseF85Drill is §20.6: install, seed through the API, back up, wipe, install in restore mode, restore, verify.
func TestReleaseF85Drill(t *testing.T) {
	i := newInst(t, "drill", "ubuntu22", 19443)
	r := i.install(rc2)
	require.Equal(t, 0, r.Code)

	now := time.Now()
	ca := pki.NewCA("Alice release drill", pki.ECDSA256, now)
	roots := []*x509.Certificate{ca.Root}

	// The wizard: administrator with TOTP, recovery passphrase, an uploaded HTTPS certificate, mail settings with a
	// password, the evaluation license.
	httpsLeaf := ca.Issue(pki.Opts{CommonName: hostName, SANs: []string{hostName}}, now)
	httpsStep := func(c *client, _ *account) {
		v := c.expect(http.StatusOK, http.MethodPut, "/api/v1/settings/https", map[string]string{
			"cert_pem": string(httpsLeaf.FullchainPEM), "key_pem": string(httpsLeaf.KeyPEM),
		})
		assert.Equal(t, false, v["temporary"])
	}
	mailStep := func(c *client, _ *account) {
		_, _, h := c.call(http.MethodGet, "/api/v1/settings/smtp", nil)
		c.expect(http.StatusOK, http.MethodPut, "/api/v1/settings/smtp", map[string]any{
			"host": "mail.alice-rel.test", "port": 587, "tls_mode": "starttls", "from": "alice@alice-rel.test",
			"username": "mailer", "password": mailPassword, "ca_pem": "",
		}, "If-Match", h.Get("ETag"))
	}
	i.code = setupCode(t, r.Out)
	c, admin := i.wizard(i.client(roots...), httpsStep, mailStep)
	require.Equal(t, httpsLeaf.Cert.Raw, i.servedLeaf(roots), "Alice serves the uploaded certificate")

	// The first SSH target, its host key confirmed.
	tg := i.startTarget()
	i.addTarget(c, tg)

	// Three users in each role, each signed in once with TOTP enrolled.
	users := []*account{admin}
	stepUp(c, admin)
	for _, role := range []string{"admin", "operator", "auditor"} {
		for n := 1; n <= 3; n++ {
			a := &account{username: fmt.Sprintf("%s%d", role, n), password: fmt.Sprintf("release harness %s%d lantern 7", role, n), role: role}
			createUser(c, a)
			users = append(users, a)
		}
	}
	for _, a := range users[1:] {
		i.signIn(a, roots...)
	}

	// Ten certificates with their keys; the one for www.example.test is signed by the target's CA and deployed later.
	wwwCert, wwwKey := newCertFromTarget(t, tg, wwwSite)
	wwwID := upload(c, "www", wwwCert, wwwKey)
	for n := 1; n <= 9; n++ {
		leaf := ca.Issue(pki.Opts{CommonName: fmt.Sprintf("site%d.alice-rel.test", n), SANs: []string{fmt.Sprintf("site%d.alice-rel.test", n)}}, now)
		upload(c, fmt.Sprintf("site%d", n), string(leaf.FullchainPEM)+string(ca.RootPEM), string(leaf.KeyPEM))
	}

	// 500 audit rows: the sign-ins above, then reads of the audit chain by the administrator and the auditors.
	readers := []*client{c}
	for _, a := range users {
		if a.role == "auditor" {
			readers = append(readers, i.signIn(a, roots...))
		}
	}
	for n := 0; ; n++ {
		if n%25 == 0 {
			if rows := i.counts()["audit_log"]; rows >= 500 {
				t.Logf("%d audit rows after %d chain reads", rows, n)
				break
			}
		}
		readers[n%len(readers)].expect(http.StatusOK, http.MethodPost, "/api/v1/audit/verify", nil)
	}

	before := i.facts(c)
	t.Logf("facts before the backup: head %s %s, installation %s, phase %s, counts %v", before.headSeq, before.headHash,
		before.installationID, before.phase, before.counts)
	require.GreaterOrEqual(t, before.counts["audit_log"], int64(500))
	require.Equal(t, int64(10), before.counts["users"])
	require.GreaterOrEqual(t, before.counts["certificates"], int64(10))
	keysBefore := i.keysHash()
	masterKey := strings.TrimSpace(string(i.readFile(filepath.Join(i.dir, "keys", "master.key"))))

	name := i.backup()
	file := i.readFile(filepath.Join(i.dir, "backups", name))
	sum := i.readFile(filepath.Join(i.dir, "backups", name+".sha256"))
	out := filepath.Join(i.work, "out", name)
	must(t, i.sh("install -d -m 0700 \"$(dirname \"$1\")\"", out), "mkdir out")
	i.writeFile(out, file, "0:0", "0600")
	// The needles go to grep in 0600 files (grep -f), never as arguments: a secret in docker run's argv would be in the
	// container's create arguments and in runCmd's failure message (M-1).
	for n, nd := range []struct{ what, needle string }{{"the mail password", mailPassword}, {"a PEM header", "-----BEGIN"},
		{"the passphrase", passphrase}, {"the master key", masterKey}, {"a private key", strings.Split(string(httpsLeaf.KeyPEM), "\n")[1]}} {
		pattern := filepath.Join(i.work, "out", fmt.Sprintf("needle-%d", n))
		i.writeFile(pattern, []byte(nd.needle+"\n"), "0:0", "0600")
		r := i.in("", "grep", "-c", "-F", "-f", pattern, out)
		assert.Equal(t, "0", strings.TrimSpace(r.Out), "grep -c %s in the backup file", nd.what)
		assert.Equal(t, 1, r.Code, "grep finds no %s", nd.what)
	}

	// A wrong passphrase: the C7 sentence, no data in the output, nothing changed.
	afterBackup := i.snapshot()
	wrong := i.passphraseFile("wrong-pass", "amber canyon violet orbit lantern harbour")
	r = i.alicectl("restore", filepath.Join(i.dir, "backups", name), "--passphrase-file", wrong, "--confirm", "RESTORE")
	assert.Equal(t, 1, r.Code)
	assert.Equal(t, msgDamaged, strings.TrimSpace(r.Out))
	i.requireSame(afterBackup, nil, nil, false)
	assert.Equal(t, keysBefore, i.keysHash())
	i.selfcheck()

	// Wipe: the containers, the database volume and the whole installation directory (master.key included).
	must(t, docker(t, "network", "disconnect", i.frontend(), tg.name), "disconnect the target")
	must(t, i.compose("down", "-v", "--remove-orphans"), "compose down -v")
	must(t, i.rootSh(i.work, "rm -rf -- \"$1\"", i.dir), "remove the installation directory")
	require.Equal(t, 1, i.sh("test -e \"$1\"", i.dir).Code)

	// A fresh installation in restore mode, the file copied in, the restore.
	r = i.install(rc2, "--restore-mode")
	require.Equal(t, 0, r.Code)
	assert.Contains(t, r.Out, "Alice is ready for a restore. Copy the backup file into "+i.dir+"/backups, then run: sudo "+i.dir+
		"/alicectl restore "+i.dir+"/backups/<file>\n")
	assert.Equal(t, 1, i.sh("test -e \"$1\"", filepath.Join(i.dir, "keys", "master.key")).Code, "restore mode writes no master key")
	i.writeFile(filepath.Join(i.dir, "backups", name), file, "10001:10001", "0600")
	i.writeFile(filepath.Join(i.dir, "backups", name+".sha256"), sum, "10001:10001", "0600")
	pass := i.passphraseFile("pass", passphrase)
	r = i.alicectl("restore", filepath.Join(i.dir, "backups", name), "--passphrase-file", pass, "--confirm", "RESTORE")
	require.Equal(t, 0, r.Code, r.Out)
	assert.Contains(t, r.Out, "Restore finished. Everyone must sign in again. Users and API tokens are as they were when the backup was made; review them.")
	i.selfcheck()
	must(t, docker(t, "network", "connect", "--alias", "sshtarget", i.frontend(), tg.name), "reconnect the target")

	// Verify: counts (sessions 0, one audit row more), the audit head before system.restored, the master key's files.
	after := i.counts()
	want := stable(before.counts)
	want["sessions"] = 0
	want["audit_log"]++ // system.restored
	want["settings"]++  // backup.restore_id, the restore ID of the swap (C1, R43 row 8), stays in the database
	assert.Equal(t, 1, strings.Count(i.psql("SELECT string_agg(key, ',') FROM settings"), "backup.restore_id"))
	assert.Equal(t, want, stable(after), "row counts after the restore")
	assert.Equal(t, "1", i.psql("SELECT count(*) FROM audit_log WHERE action = 'system.restored'"))
	assert.Equal(t, before.headSeq, i.psql("SELECT seq - 1 FROM audit_log WHERE action = 'system.restored'"), "system.restored follows the recorded head")
	assert.Equal(t, before.headHash, i.psql("SELECT encode(hash, 'hex') FROM audit_log WHERE seq = (SELECT seq - 1 FROM audit_log WHERE action = 'system.restored')"),
		"the chain before system.restored ends at the recorded head")
	assert.Equal(t, keysBefore, i.keysHash(), "master key and HTTPS pair restored")
	assert.Equal(t, httpsLeaf.Cert.Raw, i.servedLeaf(roots))

	// Every seeded user signs in with password and TOTP.
	var adminC *client
	for _, a := range users {
		uc := i.signIn(a, roots...)
		if a == admin {
			adminC = uc
		}
	}
	lic := adminC.expect(http.StatusOK, http.MethodGet, "/api/v1/license", nil)
	assert.Equal(t, before.installationID, str(t, lic, "installation_id"))
	assert.Equal(t, before.phase, str(t, lic, "phase"))

	// The restored platform key still opens the target, and a deployment runs.
	stepUp(adminC, admin)
	job := adminC.expect(http.StatusAccepted, http.MethodPost, "/api/v1/targets/"+tg.id+"/actions/test", nil)
	waitJob(adminC, str(t, job, "job_id"))
	deploy(adminC, wwwID, tg.location)
}

// servedLeaf is the certificate Alice's listener presents.
func (i *inst) servedLeaf(roots []*x509.Certificate) []byte {
	i.t.Helper()
	c := i.client(roots...)
	res, err := c.hc.Get(c.base + "/healthz")
	require.NoError(i.t, err)
	_ = res.Body.Close()
	require.NotEmpty(i.t, res.TLS.PeerCertificates)
	return res.TLS.PeerCertificates[0].Raw
}

// TestReleaseRestoreNegatives: damaged, truncated, foreign and newer files are refused by alicectl restore with the
// exact C7 sentences and exit 1, and nothing changes.
func TestReleaseRestoreNegatives(t *testing.T) {
	i := newInst(t, "negatives", "ubuntu22", 19444)
	r := i.install(rc2)
	require.Equal(t, 0, r.Code)
	i.code = setupCode(t, r.Out)
	c, _ := i.wizard(i.client(), nil, nil)
	// Enough incompressible data (RSA keys) for a payload of more than one 64 KiB chunk.
	now := time.Now()
	ca := pki.NewCA("Alice release negatives", pki.RSA2048, now)
	for n := 1; n <= 40; n++ {
		leaf := ca.Issue(pki.Opts{CommonName: fmt.Sprintf("n%d.alice-rel.test", n), KeyType: pki.RSA2048}, now)
		upload(c, fmt.Sprintf("n%d", n), string(leaf.FullchainPEM), string(leaf.KeyPEM))
	}
	name := i.backup()
	good := i.readFile(filepath.Join(i.dir, "backups", name))
	hdrEnd := headerEnd(t, good)
	const chunk = 65536 + 16
	require.Greater(t, len(good), hdrEnd+chunk+16, "the payload spans more than one chunk")

	flip := func(at int) []byte {
		b := bytes.Clone(good)
		b[at] ^= 0x01
		return b
	}
	replaceIn := func(field string, offset int, with byte) []byte {
		b := bytes.Clone(good)
		at := bytes.Index(b[:hdrEnd], []byte(`"`+field+`":"`))
		require.Positive(t, at, field)
		at += len(field) + 4 + offset
		require.NotEqual(t, with, b[at])
		b[at] = with
		return b
	}
	cases := []struct {
		name string
		data []byte
		want string
	}{
		{"header", replaceIn("created_at", 3, '7'), msgDamaged}, // a digit of the year: valid JSON, other AAD
		{"salt", replaceIn("salt", 0, pick(good, hdrEnd, "salt")), msgDamaged},
		{"ciphertext", flip(hdrEnd + 1000), msgDamaged},
		{"chunk-boundary-end", flip(hdrEnd + chunk - 1), msgDamaged},           // the last tag byte of chunk 0 (F-81)
		{"chunk-boundary-start", flip(hdrEnd + chunk), msgDamaged},             // the first byte of chunk 1 (F-81)
		{"truncated", bytes.Clone(good[:hdrEnd+chunk]), msgDamaged},            // no final chunk (F-82)
		{"truncated-mid-chunk", bytes.Clone(good[:len(good)-7]), msgDamaged},   // F-82
		{"empty", []byte{}, msgNotBackup},                                      // F-83
		{"text", []byte("This is a text file, not a backup.\n"), msgNotBackup}, // F-83
		{"newer", newerHeader(t, good, hdrEnd, "9.0.0"), "This backup was created by a newer Alice version (9.0.0). Install Alice 9.0.0 or newer, then restore."},
	}
	countsBefore := stable(i.counts())
	seqBefore := i.psql("SELECT max(seq) FROM audit_log")
	keysBefore := i.keysHash()
	pass := i.passphraseFile("pass", passphrase)
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			path := filepath.Join(i.dir, "backups", "negative-"+tc.name+".alicebak")
			i.writeFile(path, tc.data, "10001:10001", "0600")
			r := i.alicectl("restore", path, "--passphrase-file", pass, "--confirm", "RESTORE")
			assert.Equal(t, 1, r.Code)
			assert.Equal(t, tc.want, strings.TrimSpace(r.Out))
			added, total := i.auditSince(seqBefore)
			assert.Empty(t, added, "a refused restore adds no audit entry")
			want := maps.Clone(countsBefore)
			want["audit_log"] += total // only a tolerated scheduled verification (M-6, scheduledVerify)
			assert.Equal(t, want, stable(i.counts()), "row counts unchanged")
			assert.Equal(t, keysBefore, i.keysHash(), "keys/ unchanged")
			assert.Equal(t, rc2, i.runningVersion(), "Alice keeps running")
		})
	}
	i.selfcheck()
}

// headerEnd is the offset of the first chunk: "ALICEBK1", uint16 version, uint32 n, n bytes of JSON (C7).
func headerEnd(t testing.TB, b []byte) int {
	t.Helper()
	require.True(t, bytes.HasPrefix(b, []byte("ALICEBK1")))
	n := int(binary.BigEndian.Uint32(b[10:14]))
	return 14 + n
}

// pick is a base64 character other than the first one of a field's value.
func pick(b []byte, hdrEnd int, field string) byte {
	at := bytes.Index(b[:hdrEnd], []byte(`"`+field+`":"`)) + len(field) + 4
	if b[at] == 'A' {
		return 'B'
	}
	return 'A'
}

// newerHeader rewrites alice_version in the header JSON and the JSON length, and recomputes nothing else (the chunks'
// additional data no longer match; the version is refused before that matters).
func newerHeader(t testing.TB, b []byte, hdrEnd int, version string) []byte {
	t.Helper()
	js := b[14:hdrEnd]
	m := regexp.MustCompile(`"alice_version":"[^"]*"`)
	require.True(t, m.Match(js))
	newJS := m.ReplaceAll(js, []byte(`"alice_version":"`+version+`"`))
	out := append([]byte{}, b[:10]...)
	out = binary.BigEndian.AppendUint32(out, uint32(len(newJS))) //nolint:gosec // G115: a header is at most 64 KiB
	out = append(out, newJS...)
	return append(out, b[hdrEnd:]...)
}
