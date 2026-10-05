//go:build integration

package api

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/ssh"
)

// Phase 6 over the wire (Task 14): SSH key generation, deploy, the audited private-key download (S-09) and F-36/F-37
// for keys, against the real service, the real sshkey.add handler and the emulated server.

const downloadReason = "break-glass copy for the on-call laptop"

// keyFilesDoc is GET /targets/{id}/key-files.
type keyFilesDoc struct {
	Items []struct {
		OSUser      string   `json:"os_user"`
		Files       []string `json:"files"`
		DefaultFile string   `json:"default_file"`
	} `json:"items"`
	Refusal map[string]any `json:"refusal"`
}

func (e *keyEnv) keyFiles(c *client, targetID string) keyFilesDoc {
	e.t.Helper()
	rec := c.do(http.MethodGet, "/api/v1/targets/"+targetID+"/key-files", nil)
	requireStatus(e.t, rec, http.StatusOK)
	return decodeBody[keyFilesDoc](e.t, rec)
}

// download asks for the key's file with a reason (and a passphrase when not nil).
func download(c *client, keyID, reason string, passphrase *string) *httptest.ResponseRecorder {
	body := map[string]any{"reason": reason}
	if passphrase != nil {
		body["passphrase"] = *passphrase
	}
	return c.do(http.MethodPost, "/api/v1/ssh-keys/"+keyID+"/actions/download-private-key", body)
}

// §26.8 owner steps 1-2 over the wire: generate an Ed25519 key, offer only the files a deploy may change, deploy it to
// deploy's file (the job adds the line and logs in with the new key), then the download asks for step-up and a reason
// and is recorded in the audit log.
func TestOwnerSteps1And2OverTheWire(t *testing.T) {
	e := newKeyEnv(t)
	before := e.f.file(deployKeysPath)

	files := e.keyFiles(e.admin, e.targetID)
	assert.Nil(t, files.Refusal)
	offered := map[string][]string{}
	for _, it := range files.Items {
		offered[it.OSUser] = it.Files
	}
	assert.Equal(t, []string{deployKeysPath}, offered["deploy"])
	assert.Equal(t, []string{rootKeysPath}, offered["root"])
	assert.NotContains(t, offered, "alice-svc", "the connection account is never offered (S7)")

	k := e.generate(e.admin, "ci deploy", "ed25519")
	assert.True(t, strings.HasPrefix(k.publicKey, "ssh-ed25519 "))
	assert.False(t, e.f.emu.AcceptsLogin("deploy", k.pub), "the new key does not log in before the deploy")
	e.deployed(k)

	after := e.f.file(deployKeysPath)
	require.True(t, strings.HasPrefix(after, before), "every earlier line is kept byte for byte")
	added := strings.TrimSuffix(strings.TrimPrefix(after, before), "\n")
	assert.NotContains(t, added, "\n", "one line was added")
	assert.True(t, strings.HasPrefix(added, k.blob()+" "), added)
	assert.True(t, e.f.emu.AcceptsLogin("deploy", k.pub), "the test login with the new key succeeds")
	assert.Equal(t, []string{deployKeysPath}, e.f.emu.Writes())
	for _, p := range []string{rootKeysPath, aliceKeysPath} {
		assert.Equal(t, e.f.files[p], e.f.file(p), p)
	}
	assert.Equal(t, 1, e.auditCount("sshkey.deploy_requested"))
	assert.Equal(t, 1, e.auditCount("sshkey.added"))

	// Download: without a fresh step-up refused; with it the file.
	e.advance(6 * time.Minute)
	requireError(t, download(e.admin, k.id, downloadReason, nil), http.StatusForbidden, "ALC-AUTH-0003")
	assert.Zero(t, e.auditCount("sshkey.private_key_downloaded"))
	e.stepUp(e.admin, e.adminAcct)
	rec := download(e.admin, k.id, downloadReason, nil)
	requireStatus(t, rec, http.StatusOK)
	signer, err := ssh.ParsePrivateKey(rec.Body.Bytes())
	require.NoError(t, err)
	assert.Equal(t, k.fingerprint, ssh.FingerprintSHA256(signer.PublicKey()))

	page := decodeBody[struct {
		Items []map[string]any `json:"items"`
	}](t, e.admin.do(http.MethodGet, "/api/v1/audit?action=sshkey.private_key_downloaded", nil))
	require.Len(t, page.Items, 1)
	details := page.Items[0]["details"].(map[string]any)
	assert.Equal(t, downloadReason, details["reason"])
	assert.Equal(t, k.id, details["ssh_key_id"])
	assert.Equal(t, "ada", page.Items[0]["actor_name"])
}

// downloadedRows are the committed sshkey.private_key_downloaded rows of keyID.
func (e *keyEnv) downloadedRows(keyID string) []map[string]string {
	e.t.Helper()
	var out []map[string]string
	for _, d := range e.auditRows("sshkey.private_key_downloaded") {
		if d["ssh_key_id"] == keyID {
			out = append(out, d)
		}
	}
	return out
}

// downloadCount is managed_private_keys.download_count of a generated key.
func (e *keyEnv) downloadCount(keyID string) int {
	e.t.Helper()
	var n int
	require.NoError(e.t, e.db.Owner.QueryRow(context.Background(), `SELECT m.download_count FROM managed_private_keys m
JOIN ssh_keys k ON k.private_key_id = m.id WHERE k.id = $1`, keyID).Scan(&n))
	return n
}

// browserRequest builds the request c.do would send (same-origin headers, CSRF token, cookies).
func browserRequest(t *testing.T, c *client, method, path string, body any) *http.Request {
	t.Helper()
	raw, err := json.Marshal(body)
	require.NoError(t, err)
	req := httptest.NewRequest(method, "https://alice.test"+path, bytes.NewReader(raw))
	req.RemoteAddr = c.ip + ":40000"
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Origin", "https://alice.test")
	req.Header.Set("Sec-Fetch-Site", "same-origin")
	req.Header.Set("X-CSRF-Token", c.csrf)
	req.Header.Set(activityHeader, "1")
	for name, value := range c.cookies {
		req.AddCookie(&http.Cookie{Name: name, Value: value})
	}
	return req
}

// probeWriter is the server side of one answer: at the FIRST WriteHeader or Write (the moment the first byte of the
// answer is handed to the connection), it asks the database, on the owner pool (another connection than the
// application's), whether the download's audit row is already committed, and records the answer (S-09: the audit
// event is written before the response is sent). A client gone mid-body is simulated by failing every Write.
type probeWriter struct {
	header   http.Header
	status   int
	body     bytes.Buffer
	probe    func() bool
	probed   bool
	rowFirst bool
	gone     bool // every Write fails, as for a client that went away
}

func (w *probeWriter) first() {
	if !w.probed {
		w.probed = true
		w.rowFirst = w.probe()
	}
}

func (w *probeWriter) Header() http.Header { return w.header }

func (w *probeWriter) WriteHeader(code int) {
	w.first()
	if w.status == 0 {
		w.status = code
	}
}

func (w *probeWriter) Write(b []byte) (int, error) {
	w.first()
	if w.status == 0 {
		w.status = http.StatusOK
	}
	if w.gone {
		return 0, errors.New("write tcp: connection reset by peer")
	}
	return w.body.Write(b)
}

// probedDownload sends one download as c through the stack's handler with a probeWriter that looks for the
// download's audit row with number n at the first byte.
func (e *keyEnv) probedDownload(c *client, keyID string, n int, gone bool) *probeWriter {
	e.t.Helper()
	w := &probeWriter{header: http.Header{}, gone: gone, probe: func() bool {
		var seq int64
		err := e.db.Owner.QueryRow(context.Background(), `SELECT seq FROM audit_log WHERE action = 'sshkey.private_key_downloaded'
AND details->>'ssh_key_id' = $1 AND details->>'download_count' = $2`, keyID, strconv.Itoa(n)).Scan(&seq)
		return err == nil
	}}
	e.handler.ServeHTTP(w, browserRequest(e.t, c, http.MethodPost, "/api/v1/ssh-keys/"+keyID+"/actions/download-private-key",
		map[string]string{"reason": downloadReason}))
	return w
}

// s09 is one S-09 case: its own installation, a generated key and the Administrator ready to download (a fresh
// minute of the limiter and a fresh step-up), so every subtest runs alone.
func s09(t *testing.T) (*keyEnv, keyLine) {
	e := newKeyEnv(t)
	k := e.generate(e.admin, "s09 key", "ed25519")
	e.advance(time.Minute + time.Second)
	e.stepUp(e.admin, e.adminAcct)
	return e, k
}

// TestS09PrivateKeyDownload is S-09 over the wire (R41 rows 4, 5; SEC-045): only an Administrator's browser session
// with a fresh step-up and a reason downloads; every other caller is refused and audited, and nothing is counted; the
// audit row is committed before the first byte of the answer is handed to the connection, also when the client is
// gone, and a failed audit gives no file; the answer is not cached; every download is audited with its number; the
// file is the OpenSSH private key of the public key, with and without a passphrase; 5 per minute per USER (tokens,
// anonymous and pending callers spend nothing); allowed in lock. Each subtest has its own installation.
func TestS09PrivateKeyDownload(t *testing.T) {
	t.Run("refused callers", func(t *testing.T) {
		e, k := s09(t)
		operator := e.createUser(e.admin, e.adminAcct, "otto", "operator", operatorPassword)
		oc := e.freshClient()
		e.firstSignIn(oc, operator)
		auditor := e.createUser(e.admin, e.adminAcct, "audrey", "auditor", operatorPassword)
		ac := e.freshClient()
		e.firstSignIn(ac, auditor)
		adminOperate, _ := createToken(t, e.stack, e.admin, e.adminAcct, "operate", 30)
		adminRead, _ := createToken(t, e.stack, e.admin, e.adminAcct, "read", 30)
		opToken, _ := createToken(t, e.stack, oc, operator, "operate", 30)
		e.stepUp(oc, operator)
		e.stepUp(ac, auditor)
		denied := e.auditCount("authz.denied")
		for _, c := range []*client{oc, ac} {
			requireError(t, download(c, k.id, downloadReason, nil), http.StatusForbidden, "ALC-AUTH-0002")
		}
		for name, tok := range map[string]string{"admin operate token": adminOperate, "admin read token": adminRead, "operator operate token": opToken} {
			api := e.client("198.51.100.70")
			api.bearer = tok
			rec := download(api, k.id, downloadReason, nil)
			requireError(t, rec, http.StatusForbidden, "ALC-AUTH-0002")
			assert.NotEqual(t, "application/octet-stream", rec.Header().Get("Content-Type"), name)
		}
		e.advance(6 * time.Minute) // the Administrator's step-up from the token creation has ended
		requireError(t, download(e.admin, k.id, downloadReason, nil), http.StatusForbidden, "ALC-AUTH-0003")

		// The Administrator between the password and the code (MFA pending), and nobody at all.
		pending := e.freshClient()
		rec := pending.do(http.MethodPost, "/api/v1/auth/login", loginBody(e.adminAcct.username, e.adminAcct.password))
		requireStatus(t, rec, http.StatusOK)
		require.Equal(t, "mfa_required", decodeBody[map[string]string](t, rec)["status"])
		requireError(t, download(pending, k.id, downloadReason, nil), http.StatusUnauthorized, "ALC-AUTH-0001")
		requireError(t, download(e.client("198.51.100.71"), k.id, downloadReason, nil), http.StatusUnauthorized, "ALC-AUTH-0001")

		assert.Empty(t, e.downloadedRows(k.id), "no refused caller produced a download")
		assert.Zero(t, e.downloadCount(k.id))
		// Each refused session and token is audited (R39 item 4; refusals of one user, permission, reason and route within
		// ten minutes share one row, AUD-06).
		got := map[string]bool{}
		rows, err := e.db.Owner.Query(context.Background(), `SELECT actor_type, actor_name, details->>'reason', details->>'permission'
FROM audit_log WHERE action = 'authz.denied' AND details->>'path' = '/api/v1/ssh-keys/{id}/actions/download-private-key'`)
		require.NoError(t, err)
		for rows.Next() {
			var typ, name, reason, perm string
			require.NoError(t, rows.Scan(&typ, &name, &reason, &perm))
			assert.Equal(t, "sshkeys.download", perm)
			got[typ+" "+name+" "+reason] = true
		}
		require.NoError(t, rows.Err())
		assert.Equal(t, map[string]bool{"user otto permission": true, "user audrey permission": true, "api_token ada permission": true,
			"api_token otto permission": true, "user ada stepup": true}, got)
		assert.GreaterOrEqual(t, e.auditCount("authz.denied")-denied, 5)
	})

	t.Run("refused requests", func(t *testing.T) {
		e, k := s09(t)
		path := "/api/v1/ssh-keys/" + k.id + "/actions/download-private-key"
		cases := []struct {
			name   string
			body   any
			status int
			code   string
		}{
			{"empty reason", map[string]any{"reason": ""}, http.StatusUnprocessableEntity, "ALC-SYS-0006"},
			{"reason with a private key marker", map[string]any{"reason": "see -----BEGIN " + "OPENSSH PRIVATE KEY----- here"}, http.StatusUnprocessableEntity, "ALC-SYS-0006"},
			{"over-long passphrase", map[string]any{"reason": downloadReason, "passphrase": strings.Repeat("p", 1025)}, http.StatusUnprocessableEntity, "ALC-SYS-0006"},
			{"short passphrase", map[string]any{"reason": downloadReason, "passphrase": "eleven char"}, http.StatusUnprocessableEntity, "ALC-SYS-0006"},
			{"empty passphrase is never 'unencrypted'", map[string]any{"reason": downloadReason, "passphrase": ""}, http.StatusUnprocessableEntity, "ALC-SYS-0006"},
			{"unknown field", map[string]any{"reason": downloadReason, "format": "pem"}, http.StatusBadRequest, "ALC-SYS-0004"},
			{"wrong type", `{"reason": 42}`, http.StatusBadRequest, "ALC-SYS-0004"},
		}
		for _, c := range cases {
			// Every refused request of a session spends the limiter (the guard charges first): one per minute here.
			e.advance(time.Minute + time.Second)
			e.stepUp(e.admin, e.adminAcct)
			rec := e.admin.do(http.MethodPost, path, c.body)
			assert.Equal(t, c.status, rec.Code, "%s: %s", c.name, rec.Body.String())
			assert.Equal(t, c.code, errCode(rec), "%s: %s", c.name, rec.Body.String())
			assert.NotEqual(t, "application/octet-stream", rec.Header().Get("Content-Type"), c.name)
		}
		requireError(t, download(e.admin, uuid.NewString(), downloadReason, nil), http.StatusNotFound, "ALC-SYS-0001")
		assert.Empty(t, e.downloadedRows(k.id))
		assert.Zero(t, e.downloadCount(k.id))
		// passphrase null is "no passphrase": the unencrypted file.
		e.advance(time.Minute + time.Second)
		e.stepUp(e.admin, e.adminAcct)
		rec := e.admin.do(http.MethodPost, path, `{"reason": "`+downloadReason+`", "passphrase": null}`)
		requireStatus(t, rec, http.StatusOK)
		_, err := ssh.ParsePrivateKey(rec.Body.Bytes())
		require.NoError(t, err, "null passphrase: an unencrypted file")
		assert.Equal(t, "false", e.downloadedRows(k.id)[0]["protected"])
	})

	t.Run("audited before the first byte, not cached, counted", func(t *testing.T) {
		e, k := s09(t)
		w := e.probedDownload(e.admin, k.id, 1, false)
		require.Equal(t, http.StatusOK, w.status, w.body.String())
		require.True(t, w.probed)
		assert.True(t, w.rowFirst, "the audit row was committed before the answer's first byte was written")
		first := w.body.Bytes()
		assert.Equal(t, "no-store", w.header.Get("Cache-Control"))
		assert.Equal(t, "application/octet-stream", w.header.Get("Content-Type"))
		assert.Equal(t, "nosniff", w.header.Get("X-Content-Type-Options"))
		assert.Regexp(t, `^attachment; filename="alice-s09-key-[0-9a-f]{8}\.key"$`, w.header.Get("Content-Disposition"))
		assert.Equal(t, strconv.Itoa(len(first)), w.header.Get("Content-Length"))
		signer, err := ssh.ParsePrivateKey(first)
		require.NoError(t, err, "the file is an OpenSSH private key")
		assert.Equal(t, k.pub.Marshal(), signer.PublicKey().Marshal(), "of the key's public key")

		// The second download, with a passphrase, is audited too, with its number.
		e.stepUp(e.admin, e.adminAcct)
		pass := "a passphrase of the on-call team"
		rec := download(e.admin, k.id, downloadReason+" again", &pass)
		requireStatus(t, rec, http.StatusOK)
		_, err = ssh.ParsePrivateKey(rec.Body.Bytes())
		var missing *ssh.PassphraseMissingError
		require.ErrorAs(t, err, &missing, "a protected file needs its passphrase")
		signer, err = ssh.ParsePrivateKeyWithPassphrase(rec.Body.Bytes(), []byte(pass))
		require.NoError(t, err)
		assert.Equal(t, k.pub.Marshal(), signer.PublicKey().Marshal())
		_, err = ssh.ParsePrivateKeyWithPassphrase(rec.Body.Bytes(), []byte("not the passphrase at all"))
		assert.Error(t, err)

		rows := e.downloadedRows(k.id)
		require.Len(t, rows, 2)
		assert.Equal(t, []string{"1", "2"}, []string{rows[0]["download_count"], rows[1]["download_count"]})
		assert.Equal(t, []string{"false", "true"}, []string{rows[0]["protected"], rows[1]["protected"]})
		assert.Equal(t, k.fingerprint, rows[1]["fingerprint"])
		for _, r := range rows {
			assert.Equal(t, "success", r["_result"])
			for key := range r {
				assert.NotContains(t, key, "passphrase")
			}
		}
		assert.Equal(t, 2, e.downloadCount(k.id))
		m := decodeBody[map[string]any](t, e.admin.do(http.MethodGet, "/api/v1/ssh-keys/"+k.id, nil))["managed_key"].(map[string]any)
		assert.EqualValues(t, 2, m["download_count"])
	})

	t.Run("a client gone while the file is sent", func(t *testing.T) {
		e, k := s09(t)
		w := e.probedDownload(e.admin, k.id, 1, true)
		assert.Equal(t, http.StatusOK, w.status)
		assert.True(t, w.rowFirst, "committed before the first byte")
		assert.Zero(t, w.body.Len(), "the client received nothing")
		rows := e.downloadedRows(k.id)
		require.Len(t, rows, 1, "the download is audited although the client never received it")
		assert.Equal(t, 1, e.downloadCount(k.id))
	})

	t.Run("a failed audit gives no file", func(t *testing.T) {
		e, k := s09(t)
		// Test-side fault: the audit insert of a download fails in the test database (a trigger installed by the owner).
		ctx := context.Background()
		_, err := e.db.Owner.Exec(ctx, `CREATE FUNCTION t14_refuse_download_audit() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
  IF NEW.action = 'sshkey.private_key_downloaded' THEN RAISE EXCEPTION 't14: audit refused'; END IF;
  RETURN NEW;
END $$;
CREATE TRIGGER t14_refuse_download_audit BEFORE INSERT ON audit_log FOR EACH ROW EXECUTE FUNCTION t14_refuse_download_audit();`)
		require.NoError(t, err)
		drop := `DROP TRIGGER IF EXISTS t14_refuse_download_audit ON audit_log; DROP FUNCTION IF EXISTS t14_refuse_download_audit();`
		t.Cleanup(func() { _, _ = e.db.Owner.Exec(context.Background(), drop) })
		w := e.probedDownload(e.admin, k.id, 1, false)
		_, err = e.db.Owner.Exec(ctx, drop) // the audit works again for the rest of this subtest
		require.NoError(t, err)
		assert.GreaterOrEqual(t, w.status, 500, w.body.String())
		assert.Contains(t, w.header.Get("Content-Type"), "application/json")
		var body apiError
		require.NoError(t, json.Unmarshal(w.body.Bytes(), &body), w.body.String())
		assert.NotEmpty(t, body.Error.Code)
		assert.NotContains(t, w.body.String(), "PRIVATE KEY")
		_, rows := e.storedKeys()
		for _, sk := range rows {
			for _, sec := range sshKeyCanaries(t, "key", sk.der) {
				_, found := sec.leakedIn(w.body.String())
				assert.False(t, found, "%s in the error answer", sec.name)
			}
		}
		assert.Zero(t, e.downloadCount(k.id), "the counter was rolled back with the audit row")
		assert.Empty(t, e.downloadedRows(k.id))
		// With the audit working again the same Administrator downloads (number 1).
		e.stepUp(e.admin, e.adminAcct)
		w = e.probedDownload(e.admin, k.id, 1, false)
		assert.Equal(t, http.StatusOK, w.status)
		assert.True(t, w.rowFirst)
	})

	t.Run("five per minute per user", func(t *testing.T) {
		e, k := s09(t)
		admin2 := e.createUser(e.admin, e.adminAcct, "bea", "admin", "a second administrator password")
		bea := e.client(e.admin.ip) // the second Administrator on the first one's address
		e.firstSignIn(bea, admin2)
		ada2 := e.freshClient() // the same Administrator in a second browser on another address
		e.signIn(ada2, e.adminAcct)
		adminOperate, _ := createToken(t, e.stack, e.admin, e.adminAcct, "operate", 30)
		e.advance(time.Minute + time.Second)
		e.stepUp(e.admin, e.adminAcct)
		e.stepUp(ada2, e.adminAcct)
		e.stepUp(bea, admin2)
		// Tokens of that Administrator and anonymous callers on her address spend nothing of her allowance.
		for i := 0; i < 6; i++ {
			api := e.client(e.admin.ip)
			api.bearer = adminOperate
			requireError(t, download(api, k.id, downloadReason, nil), http.StatusForbidden, "ALC-AUTH-0002")
			requireError(t, download(e.client(e.admin.ip), k.id, downloadReason, nil), http.StatusUnauthorized, "ALC-AUTH-0001")
		}
		for i := 0; i < 5; i++ {
			requireStatus(t, download(e.admin, k.id, downloadReason, nil), http.StatusOK)
		}
		before := len(e.downloadedRows(k.id))
		rec := download(ada2, k.id, downloadReason, nil)
		requireError(t, rec, http.StatusTooManyRequests, "ALC-SYS-0005")
		assert.NotEmpty(t, rec.Header().Get("Retry-After"))
		requireError(t, download(e.admin, k.id, downloadReason, nil), http.StatusTooManyRequests, "ALC-SYS-0005")
		assert.Len(t, e.downloadedRows(k.id), before, "the refused sixth is not a download")
		requireStatus(t, download(bea, k.id, downloadReason, nil), http.StatusOK) // another Administrator on the same address
		e.advance(time.Minute + time.Second)
		e.stepUp(ada2, e.adminAcct)
		requireStatus(t, download(ada2, k.id, downloadReason, nil), http.StatusOK)
	})

	t.Run("allowed in lock", func(t *testing.T) {
		e, k := s09(t)
		e.advance(31 * 24 * time.Hour)
		require.True(t, e.license.Snapshot().Eval.Locked())
		e.stepUp(e.admin, e.adminAcct)
		rec := download(e.admin, k.id, downloadReason, nil)
		requireStatus(t, rec, http.StatusOK)
		_, err := ssh.ParsePrivateKey(rec.Body.Bytes())
		require.NoError(t, err)
		requireError(t, e.admin.do(http.MethodPost, "/api/v1/ssh-keys/generate", map[string]string{"label": "x", "key_type": "ed25519"}),
			http.StatusForbidden, "ALC-LIC-0001")
	})
}

// discover rescans a server through the API and runs the job.
func (e *keyEnv) discover(targetID string) {
	e.t.Helper()
	requireStatus(e.t, e.admin.do(http.MethodPost, "/api/v1/targets/"+targetID+"/actions/discover", nil), http.StatusAccepted)
	e.drain()
}

// platformKeyRow is the ssh_keys id of Alice's own key as the inventory of web-01 lists it.
func (e *keyEnv) platformKeyRow() string {
	e.t.Helper()
	page := decodeBody[struct {
		Items []map[string]any `json:"items"`
	}](e.t, e.admin.do(http.MethodGet, "/api/v1/ssh-keys?target_id="+e.targetID, nil))
	for _, k := range page.Items {
		if k["is_platform_key"] == true {
			require.Equal(e.t, e.f.platformFP, k["fingerprint"])
			return k["id"].(string)
		}
	}
	e.t.Fatal("no platform key row")
	return ""
}

// keyRowOf is the ssh_keys id of a discovered key.
func (e *keyEnv) keyRowOf(fp string) string {
	e.t.Helper()
	return locationOf(e.t, e.targetLocations(e.admin, e.targetID, false), "deploy", fp)["ssh_key_id"].(string)
}

// lastDenial is the reason of the newest audit row of action.
func (e *keyEnv) lastDenial(action string) string {
	e.t.Helper()
	rows := e.auditRows(action)
	require.NotEmpty(e.t, rows, action)
	last := rows[len(rows)-1]
	require.Equal(e.t, "denied", last["_result"], action)
	return last["reason"]
}

// TestS09DownloadOfKeysAliceDoesNotHold: a retired key can still be downloaded (Alice keeps its private key 30 days for
// emergencies, ALC-KEY-0007's text; Task 7's rule), a destroyed one answers 410 ALC-KEY-0008, a key Alice found on a
// server and did not generate 409 ALC-KEY-0006; every refusal is audited sshkey.private_key_download.denied with its
// reason and counts nothing.
func TestS09DownloadOfKeysAliceDoesNotHold(t *testing.T) {
	e := newKeyEnv(t)
	e.stepUp(e.admin, e.adminAcct)
	now := e.clock.Now()
	requireStatus(t, e.admin.do(http.MethodPost, "/api/v1/license", map[string]string{"license": e.signedLicense("LIC-S09", now, now.AddDate(1, 0, 0), 10)}),
		http.StatusOK) // the 30-day retention outlives the evaluation
	old := e.generate(e.admin, "retiring", "ed25519")
	e.deployed(old)
	e.rotateOnce(old)
	m := decodeBody[map[string]any](t, e.admin.do(http.MethodGet, "/api/v1/ssh-keys/"+old.id, nil))["managed_key"].(map[string]any)
	require.NotNil(t, m["retired_at"], "the completed rotation retired the old key")

	e.stepUp(e.admin, e.adminAcct)
	rec := download(e.admin, old.id, downloadReason, nil)
	requireStatus(t, rec, http.StatusOK)
	_, err := ssh.ParsePrivateKey(rec.Body.Bytes())
	require.NoError(t, err, "a retired key is downloadable until it is destroyed")

	e.advance(30*24*time.Hour + time.Hour)
	require.NoError(t, e.task("sshkey.destroy_retired"))
	m = decodeBody[map[string]any](t, e.admin.do(http.MethodGet, "/api/v1/ssh-keys/"+old.id, nil))["managed_key"].(map[string]any)
	require.NotNil(t, m["destroyed_at"])
	e.stepUp(e.admin, e.adminAcct)
	requireError(t, download(e.admin, old.id, downloadReason, nil), http.StatusGone, "ALC-KEY-0008")
	assert.Equal(t, "destroyed", e.lastDenial("sshkey.private_key_download.denied"))

	laptop := e.keyRowOf(e.f.laptop.fp)
	requireError(t, download(e.admin, laptop, downloadReason, nil), http.StatusConflict, "ALC-KEY-0006")
	assert.Equal(t, "not_managed", e.lastDenial("sshkey.private_key_download.denied"))
	assert.Len(t, e.downloadedRows(old.id), 1)
	assert.Empty(t, e.downloadedRows(laptop))
}

// TestF36OwnKeyNeverRotatedOrDownloaded is F-36 over the API with Alice's own key in deploy's file under another
// comment (compared by key blob): a policy for it is 409 ALC-KEY-0001 (audit rotation.policy.denied own_key), its
// download and its deploy 409 ALC-KEY-0006 (audited own_key), and nothing is written on the server. A policy for a key
// Alice does not hold is 409 ALC-KEY-0006 (not_managed).
func TestF36OwnKeyNeverRotatedOrDownloaded(t *testing.T) {
	e := newKeyEnv(t)
	own := e.platformKeyRow()
	commands := len(e.f.server.Commands())

	rec := e.admin.do(http.MethodPost, "/api/v1/rotation/policies", map[string]any{"ssh_key_id": own, "name": "own", "interval_days": 30})
	requireError(t, rec, http.StatusConflict, "ALC-KEY-0001")
	assert.Equal(t, "own_key", e.lastDenial("rotation.policy.denied"))
	e.stepUp(e.admin, e.adminAcct)
	requireError(t, download(e.admin, own, downloadReason, nil), http.StatusConflict, "ALC-KEY-0006")
	assert.Equal(t, "own_key", e.lastDenial("sshkey.private_key_download.denied"))
	rec = e.admin.do(http.MethodPost, "/api/v1/ssh-keys/"+own+"/actions/deploy", map[string]any{"target_id": e.targetID, "os_user": "root",
		"file_path": rootKeysPath})
	requireError(t, rec, http.StatusConflict, "ALC-KEY-0006")
	assert.Equal(t, "own_key", e.lastDenial("sshkey.deploy.denied"))

	laptop := e.keyRowOf(e.f.laptop.fp)
	rec = e.admin.do(http.MethodPost, "/api/v1/rotation/policies", map[string]any{"ssh_key_id": laptop, "name": "laptop", "interval_days": 30})
	requireError(t, rec, http.StatusConflict, "ALC-KEY-0006")
	assert.Equal(t, "not_managed", e.lastDenial("rotation.policy.denied"))

	e.drain()
	assert.Empty(t, e.f.helperWrites(), "no authkeys-write")
	assert.Len(t, e.f.server.Commands(), commands, "no command at all")
	assert.Zero(t, e.count("rotation_policies"))
	assert.Zero(t, e.countWhere("jobs", "type = 'sshkey.add'"))
	assert.Zero(t, e.auditCount("sshkey.private_key_downloaded"))
}

// TestF36ConnectionAccountOverTheAPI: a deploy into the account Alice connects with, or into one of its key files as
// another user, is 409 ALC-KEY-0009 (audited); a rotation whose every place is in that account's file previews with
// every place skipped for that reason and nothing to run (409 ALC-ROT-0004 on Run now); a server whose connection
// account's key files are not known completely refuses every deploy with 409 ALC-KEY-0014, and GET …/key-files offers
// nothing and names that refusal.
func TestF36ConnectionAccountOverTheAPI(t *testing.T) {
	e := newKeyEnv(t)
	k := e.generate(e.admin, "conn", "ed25519")

	for _, c := range []struct{ user, file string }{{"alice-svc", aliceKeysPath}, {"deploy", aliceKeysPath}, {"root", aliceKeysPath}} {
		rec := e.admin.do(http.MethodPost, "/api/v1/ssh-keys/"+k.id+"/actions/deploy", map[string]any{"target_id": e.targetID, "os_user": c.user,
			"file_path": c.file})
		requireError(t, rec, http.StatusConflict, "ALC-KEY-0009")
		assert.Equal(t, "connection_account", e.lastDenial("sshkey.deploy.denied"), c.user)
	}

	// The key placed by hand in the connection account's file only: every place is skipped.
	e.f.emu.SetFile(aliceKeysPath, []byte(e.f.files[aliceKeysPath]+k.blob()+" placed-by-hand\n"))
	e.discover(e.targetID)
	policyID, _ := e.createPolicy(e.admin, k.id, 1)
	p := e.preview(e.admin, policyID)
	assert.Zero(t, p.ChangeCount)
	require.NotEmpty(t, p.Actions)
	assert.Equal(t, len(p.Actions), p.SkipCount)
	for _, a := range p.Actions {
		assert.Equal(t, "alice-svc", a["os_user"])
		assert.Contains(t, []string{"connection_account", "connection_account_file"}, a["skip_reason"], "%v", a)
	}
	e.stepUp(e.admin, e.adminAcct)
	requireError(t, e.admin.do(http.MethodPost, "/api/v1/rotation/policies/"+policyID+"/actions/run", map[string]string{"plan_digest": p.PlanDigest}),
		http.StatusConflict, "ALC-ROT-0004")
	assert.Zero(t, e.count("rotations"))

	// The connection account's files not known completely (an unsupported entry): nothing offered, every deploy refused.
	f2, t2 := e.addKeyServer("web-02")
	f2.emu.SetUnsupported(aliceKeysPath)
	e.discover(t2)
	files := e.keyFiles(e.admin, t2)
	assert.Empty(t, files.Items)
	require.NotNil(t, files.Refusal)
	assert.Equal(t, "ALC-KEY-0014", files.Refusal["code"])
	assert.Equal(t, "sshkey.connection_files_unknown", files.Refusal["reason"])
	rec := e.admin.do(http.MethodPost, "/api/v1/ssh-keys/"+k.id+"/actions/deploy", map[string]any{"target_id": t2, "os_user": "deploy",
		"file_path": deployKeysPath})
	requireError(t, rec, http.StatusConflict, "ALC-KEY-0014")
	assert.Equal(t, "connection_files_unknown", e.lastDenial("sshkey.deploy.denied"))
	e.drain()
	assert.Empty(t, e.f.helperWrites())
	assert.Empty(t, f2.helperWrites())
	assert.Zero(t, e.countWhere("jobs", "type = 'sshkey.add'"))
}

// TestF37DeployIntoFileWithoutNewline: a deploy into a file whose last line has no line break puts the new key on a
// line of its own and leaves every other byte as it was.
func TestF37DeployIntoFileWithoutNewline(t *testing.T) {
	e := newKeyEnv(t)
	before := e.f.laptop.line + " deploy@laptop\n" + e.f.ci.line + " ci@build" // no final newline
	e.f.emu.SetFile(deployKeysPath, []byte(before))
	e.discover(e.targetID)
	k := e.generate(e.admin, "f37", "ecdsa-p256")
	e.deployed(k)
	after := e.f.file(deployKeysPath)
	require.True(t, strings.HasPrefix(after, before+"\n"), "the earlier bytes are kept and the last line is ended")
	added := strings.TrimPrefix(after, before+"\n")
	assert.True(t, strings.HasPrefix(added, k.blob()+" "), added)
	assert.True(t, strings.HasSuffix(added, "\n"))
	assert.Equal(t, 1, strings.Count(added, "\n"))
	assert.True(t, e.f.emu.AcceptsLogin("deploy", k.pub))
	assert.True(t, e.f.emu.AcceptsLogin("deploy", e.f.ci.pub()), "the formerly last key still logs in")
}

// TestF38DeployWhenTheFileChangesBetweenReadAndWrite: someone adds a line to the file between Alice's read and her
// write; the helper's compare-and-swap refuses the stale write, Alice reads again and writes once more: both the line
// added meanwhile and the new key are there, nothing else changed.
func TestF38DeployWhenTheFileChangesBetweenReadAndWrite(t *testing.T) {
	e := newKeyEnv(t)
	meanwhile := newFixtureKey(t)
	var changed atomic.Bool // set on the emulator's goroutine
	e.f.emu.BeforeWrite(func(p string) {
		if p == deployKeysPath && changed.CompareAndSwap(false, true) {
			e.f.emu.SetFile(p, []byte(e.f.files[p]+meanwhile.line+" added-meanwhile\n"))
		}
	})
	k := e.generate(e.admin, "f38", "ed25519")
	e.deployed(k)
	require.True(t, changed.Load())
	after := e.f.file(deployKeysPath)
	assert.True(t, strings.HasPrefix(after, e.f.files[deployKeysPath]+meanwhile.line+" added-meanwhile\n"), after)
	assert.Contains(t, after, k.blob())
	assert.Equal(t, 4+1, strings.Count(after, "\n"))
}
