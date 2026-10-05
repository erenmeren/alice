//go:build integration

package api

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/ssh"

	"alice/internal/notify"
)

// Secret-leak suite with generated SSH keys (spec §25.2, S-01..S-05 for Phase 6; Review Focus 2). Every private key
// Alice generated (the ones generated through the API and the ones its rotations generated) is decrypted at the end
// with the test's keyring and spelled every way a leak could spell it; the download bodies, a passphrase canary and the
// sealed envelopes are canaries too. They are looked for in the DEBUG log of the whole stack, in every HTTP answer
// except the download answers themselves (headers included), in every row of every table (which covers job payloads,
// results and error codes, audit details, rotation steps and plans, and the outbox params), in every email the sender
// delivered, and the raw ciphertext column holds none of them (S-04).

// sshKeyCanaries are the spellings of one private key (PKCS #8 DER as Alice stores it) that must never appear: the
// OpenSSH file Alice would hand out (PEM, its lines, its body in every encoding and in pieces), the PKCS #8 DER and PEM,
// the Ed25519 seed, the RSA private exponent and primes, the ECDSA scalar. Pieces that are also part of the public key
// are left out (a private key's encodings repeat the public key, which Alice shows on purpose).
func sshKeyCanaries(t *testing.T, name string, der []byte) []secretValue {
	t.Helper()
	key, err := x509.ParsePKCS8PrivateKey(der)
	require.NoError(t, err)
	signer, err := ssh.NewSignerFromKey(key)
	require.NoError(t, err)
	public := [][]byte{signer.PublicKey().Marshal()}
	if pkix, err := x509.MarshalPKIXPublicKey(signer.PublicKey().(ssh.CryptoPublicKey).CryptoPublicKey()); err == nil {
		public = append(public, pkix)
	}
	block, err := ssh.MarshalPrivateKey(key, "")
	require.NoError(t, err)
	file := pem.EncodeToMemory(block)
	out := []secretValue{
		{name: name + " (OpenSSH file)", forms: pemForms(file)},
		binaryCanary(name+" (OpenSSH body pieces)", block.Bytes, public...),
		binaryCanary(name+" (PKCS#8 DER pieces)", der, public...),
		{name: name + " (PKCS#8 PEM)", forms: pemForms(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}))},
	}
	switch k := key.(type) {
	case ed25519.PrivateKey:
		out = append(out, secretValue{name: name + " (Ed25519 seed)", forms: binaryForms(k.Seed())[1:]})
	case *rsa.PrivateKey:
		out = append(out, secretValue{name: name + " (RSA d)", forms: binaryForms(k.D.Bytes())[1:]},
			secretValue{name: name + " (RSA p)", forms: binaryForms(k.Primes[0].Bytes())[1:]},
			secretValue{name: name + " (RSA q)", forms: binaryForms(k.Primes[1].Bytes())[1:]},
			secretValue{name: name + " (PKCS#1 PEM)", forms: pemForms(pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY",
				Bytes: x509.MarshalPKCS1PrivateKey(k)}))})
	case *ecdsa.PrivateKey:
		d, err := k.Bytes()
		require.NoError(t, err)
		out = append(out, secretValue{name: name + " (ECDSA scalar)", forms: binaryForms(d)[1:]})
	default:
		t.Fatalf("%s: unexpected key type %T", name, key)
	}
	return out
}

// publicCorpus are the spellings of public keys (every alignment and encoding of the SSH wire form and of PKIX, and
// the authorized_keys line): Alice shows them on purpose, so a canary spelling contained in one of them is no leak.
func publicCorpus(t *testing.T, lines ...string) []string {
	t.Helper()
	var out []string
	for _, line := range lines {
		pub, _, _, _, err := ssh.ParseAuthorizedKey([]byte(line))
		require.NoError(t, err)
		raws := [][]byte{pub.Marshal()}
		if pkix, err := x509.MarshalPKIXPublicKey(pub.(ssh.CryptoPublicKey).CryptoPublicKey()); err == nil {
			raws = append(raws, pkix)
		}
		out = append(append(out, publicSpellings(raws...)...), line)
	}
	return out
}

// dropPublic removes from every canary the spellings that are part of a public key.
func dropPublic(secs []secretValue, corpus []string) []secretValue {
	out := make([]secretValue, 0, len(secs))
	for _, sec := range secs {
		forms := sec.forms
		if forms == nil {
			forms = variants(sec.value)
		}
		var keep []string
		for _, f := range forms {
			public := false
			for _, c := range corpus {
				if strings.Contains(c, f) {
					public = true
					break
				}
			}
			if !public {
				keep = append(keep, f)
			}
		}
		out = append(out, secretValue{name: sec.name, forms: keep})
	}
	return out
}

// leakPlaces are the texts the suite scans: the log, every answer but the downloads' bodies, every table (as text, bytea
// as hex and base64 in both alphabets) and the delivered emails. withoutEnvelopes leaves the one table that holds the
// envelopes out (for the canaries that are the envelopes themselves).
func (s *stack) leakPlaces(withoutEnvelopes bool) map[string]string {
	s.t.Helper()
	places := map[string]string{"log": s.logs.String()}
	var b strings.Builder
	for _, e := range s.recorded() {
		fmt.Fprintf(&b, "%s %d\n", e.key(), e.status)
		for k, vs := range e.header {
			fmt.Fprintf(&b, "%s: %s\n", k, strings.Join(vs, ","))
		}
		if e.status == http.StatusOK && strings.HasSuffix(e.path, "/actions/download-private-key") {
			b.WriteString("(the downloaded file)\n") // the one answer that carries the key, by design
			continue
		}
		b.Write(e.body)
		b.WriteByte('\n')
	}
	places["responses"] = b.String()
	var tables strings.Builder
	for _, table := range s.dumpTables() {
		if withoutEnvelopes && table == "managed_private_keys" {
			continue
		}
		var rows string
		require.NoError(s.t, s.db.Owner.QueryRow(context.Background(),
			"SELECT coalesce(string_agg(to_jsonb(t)::text, E'\\n'), '') FROM "+pgx.Identifier{table}.Sanitize()+" t").Scan(&rows))
		tables.WriteString(table + ":\n" + rows + "\n")
	}
	places["tables"] = tables.String()
	if !withoutEnvelopes {
		std, url := s.byteaBase64()
		places["bytea base64"], places["bytea base64url"] = std, url
	}
	var mails strings.Builder
	for _, m := range s.mailbox.messages() {
		mails.WriteString(m.To + "\n" + m.Subject + "\n" + m.Body + "\n")
	}
	places["emails"] = mails.String()
	return places
}

// sshLeaks lists "canary in place" for every canary found.
func (s *stack) sshLeaks(secs []secretValue, withoutEnvelopes bool) []string {
	s.t.Helper()
	var out []string
	for place, text := range s.leakPlaces(withoutEnvelopes) {
		for _, sec := range secs {
			if _, found := sec.leakedIn(text); found {
				out = append(out, sec.name+" in "+place)
			}
		}
	}
	return out
}

// readPhase6 makes the API answer every Phase 6 read and every job, so the scan sees those answers.
func (e *keyEnv) readPhase6() {
	e.t.Helper()
	paths := []string{"/api/v1/ssh-keys", "/api/v1/targets/" + e.targetID + "/key-files", "/api/v1/targets/" + e.targetID + "/ssh-keys?missing=true",
		"/api/v1/rotation/policies", "/api/v1/rotation/runs", "/api/v1/jobs?limit=200", "/api/v1/audit?limit=200", "/api/v1/audit/export?format=json"}
	for _, p := range paths {
		rec := e.admin.do(http.MethodGet, p, nil)
		require.Equal(e.t, http.StatusOK, rec.Code, "%s: %s", p, rec.Body.String())
	}
	list := func(path string) []map[string]any {
		return decodeBody[struct {
			Items []map[string]any `json:"items"`
		}](e.t, e.admin.do(http.MethodGet, path, nil)).Items
	}
	for _, k := range list("/api/v1/ssh-keys?missing=true") {
		requireStatus(e.t, e.admin.do(http.MethodGet, "/api/v1/ssh-keys/"+k["id"].(string), nil), http.StatusOK)
	}
	for _, p := range list("/api/v1/rotation/policies") {
		requireStatus(e.t, e.admin.do(http.MethodGet, "/api/v1/rotation/policies/"+p["id"].(string), nil), http.StatusOK)
	}
	for _, r := range list("/api/v1/rotation/runs") {
		requireStatus(e.t, e.admin.do(http.MethodGet, "/api/v1/rotation/runs/"+r["id"].(string), nil), http.StatusOK)
	}
	for _, j := range list("/api/v1/jobs?limit=200") {
		requireStatus(e.t, e.admin.do(http.MethodGet, "/api/v1/jobs/"+j["id"].(string), nil), http.StatusOK)
	}
}

// TestSecretLeakSuiteWithGeneratedKeys runs the Phase 6 journeys with every canary in place (S-01..S-05 with SSH
// private keys): keys of all four types are generated; one is deployed and logs in, one is deployed and its login is
// refused (the line is undone); one rotation completes and one is stopped and undone; every key is downloaded once
// (one with a passphrase canary); a reason that holds a private key marker is refused. Then no private key in any
// spelling, no download body, no passphrase and no sealed envelope appears in the log, any answer but the downloads,
// any table, any email, and the stored ciphertext holds none of them.
func TestSecretLeakSuiteWithGeneratedKeys(t *testing.T) {
	e := newKeyEnv(t)
	passphrase := canary("download-passphrase")
	keys := map[string]keyLine{}
	for _, kt := range []string{"ed25519", "rsa-3072", "rsa-4096", "ecdsa-p256"} {
		keys[kt] = e.generate(e.admin, "leak "+kt, kt)
	}

	// A deploy that logs in, and one whose login is refused (the line is undone).
	e.deployed(keys["ed25519"])
	refused := keys["rsa-3072"]
	e.f.server.SetLoginCheck(func(user string, key ssh.PublicKey) bool {
		return !bytes.Equal(key.Marshal(), refused.pub.Marshal()) && e.f.emu.AcceptsLogin(user, key)
	})
	job := e.deploy(e.admin, refused.id, e.targetID, "deploy", deployKeysPath)
	e.drain()
	got := e.job(e.admin, job)
	assert.Equal(t, "failed", got["status"], "%v", got)
	assert.NotContains(t, e.f.file(deployKeysPath), refused.blob(), "the refused key's line was undone")

	// A rotation that completes and one that is stopped and undone.
	_, rotatedTo := e.rotateOnce(keys["ed25519"])
	e.deployed(keys["ecdsa-p256"])
	policyID, _ := e.createPolicy(e.admin, keys["ecdsa-p256"].id, 7)
	runID := e.runNow(policyID, e.preview(e.admin, policyID).PlanDigest)
	e.drain()
	e.stepUp(e.admin, e.adminAcct)
	requireStatus(t, e.admin.do(http.MethodPost, "/api/v1/rotation/runs/"+runID+"/actions/abort", nil), http.StatusNoContent)
	e.drain()
	e.sweep(2)
	require.Equal(t, "aborted", e.run(e.admin, runID).Status)

	// Every key downloaded once; one with the passphrase canary; a reason with a private key marker is refused.
	var bodies []secretValue
	ids := []string{rotatedTo}
	for _, k := range keys {
		ids = append(ids, k.id)
	}
	for i, id := range ids {
		if i%5 == 0 {
			e.advance(time.Minute + time.Second) // 5 downloads per minute
		}
		e.stepUp(e.admin, e.adminAcct)
		var pass *string
		if id == keys["rsa-4096"].id {
			pass = &passphrase
		}
		rec := download(e.admin, id, downloadReason, pass)
		requireStatus(t, rec, http.StatusOK)
		bodies = append(bodies, secretValue{name: "download body of " + id, forms: pemForms(rec.Body.Bytes())})
	}
	e.advance(time.Minute + time.Second)
	e.stepUp(e.admin, e.adminAcct)
	marker := "-----BEGIN " + "OPENSSH PRIVATE KEY-----"
	requireError(t, download(e.admin, keys["ecdsa-p256"].id, "pasted "+marker+" by mistake", nil), http.StatusUnprocessableEntity, "ALC-SYS-0006")
	requireError(t, download(e.admin, keys["ecdsa-p256"].id, downloadReason, &[]string{passphrase[:11]}[0]), http.StatusUnprocessableEntity, "ALC-SYS-0006")

	e.deliverMail()
	e.readPhase6()

	// The canaries: every stored key decrypted with the test's keyring, its envelope and DEK, the bodies, the passphrase.
	stored, rows := e.storedKeys()
	require.GreaterOrEqual(t, len(rows), 6, "the four generated keys and the rotations' new keys")
	secs := append([]secretValue{}, stored...)
	var envelopes []secretValue
	for id, k := range rows {
		require.Equal(t, "ssh_key", k.owner)
		secs = append(secs, sshKeyCanaries(t, "key "+id, k.der)...)
		envelopes = append(envelopes, binaryCanary("sealed envelope "+id, k.env.Ciphertext))
	}
	secs = append(secs, bodies...)
	secs = append(secs, textCanary("download passphrase", passphrase))
	res, err := e.db.Owner.Query(context.Background(), "SELECT public_key FROM ssh_keys")
	require.NoError(t, err)
	publicLines, err := pgx.CollectRows(res, pgx.RowTo[string])
	require.NoError(t, err)
	secs = dropPublic(secs, publicCorpus(t, publicLines...))

	for _, l := range e.sshLeaks(secs, false) {
		t.Errorf("leak: %s", l)
	}
	for _, l := range e.sshLeaks(envelopes, true) {
		t.Errorf("leak: %s", l)
	}
	for place, text := range e.leakPlaces(false) {
		for _, m := range append([]string{"OPENSSH PRIVATE KEY", "PRIVATE KEY-----"}, privateKeyMarkers...) {
			assert.NotContains(t, text, m, "a private key marker in %s", place)
		}
	}
	// S-04: the stored ciphertext is no spelling of the key, no download, no passphrase, no marker.
	for id, k := range rows {
		raw := string(k.env.Ciphertext)
		for _, sec := range secs {
			_, found := sec.leakedIn(raw)
			assert.False(t, found, "%s in the ciphertext of %s", sec.name, id)
		}
		for _, m := range privateKeyMarkers {
			assert.NotContains(t, raw, m)
		}
	}
	// The scan saw what it claims: the answers of every Phase 6 read and the journeys' emails.
	seen := map[string]bool{}
	for _, ex := range e.recorded() {
		seen[ex.method+" "+ex.path] = true
	}
	for _, r := range []string{"GET /api/v1/rotation/runs/" + runID, "POST /api/v1/ssh-keys/generate", "GET /api/v1/jobs/" + job} {
		assert.True(t, seen[r], r)
	}
	tpls := map[string]bool{}
	for _, m := range e.mailbox.messages() {
		tpls[m.Subject] = true
	}
	assert.GreaterOrEqual(t, len(tpls), 4, "rotation emails were delivered and scanned")
}

// TestSSHKeyLeakScannerFindsEveryCanary proves the scan of the suite above is not vacuous: a key's file, its body on
// one line, its PKCS #8 in a JSON []byte, its seed or exponent in hex, a misaligned slice of its body in base64, the
// passphrase inside JSON, and an envelope in a bytea column are each found where a leak would put them (a log line,
// an answer, a table, an email); the public key and its fingerprint are not mistaken for a leak.
func TestSSHKeyLeakScannerFindsEveryCanary(t *testing.T) {
	e := newKeyEnv(t)
	_, edKey, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	passphrase := canary("download-passphrase")
	for name, key := range map[string]any{"ed25519": edKey, "rsa": rsaKey} {
		der, err := x509.MarshalPKCS8PrivateKey(key)
		require.NoError(t, err)
		signer, err := ssh.NewSignerFromKey(key)
		require.NoError(t, err)
		publicLine := string(ssh.MarshalAuthorizedKey(signer.PublicKey()))
		secs := dropPublic(append(sshKeyCanaries(t, name, der), textCanary("passphrase", passphrase)), publicCorpus(t, strings.TrimSpace(publicLine)))
		block, err := ssh.MarshalPrivateKey(key, "")
		require.NoError(t, err)
		file := pem.EncodeToMemory(block)
		jsonDER, _ := json.Marshal(der)
		jsonFile, _ := json.Marshal(string(file))
		var secret string
		switch k := key.(type) {
		case ed25519.PrivateKey:
			secret = hex.EncodeToString(k.Seed())
		case *rsa.PrivateKey:
			secret = hex.EncodeToString(k.D.Bytes())
		}
		leaks := map[string]string{
			"file":             string(file),
			"file in JSON":     string(jsonFile),
			"body on one line": strings.ReplaceAll(strings.TrimSpace(string(file)), "\n", ""),
			"PKCS#8 as []byte": string(jsonDER),
			"secret in hex":    secret,
			"misaligned slice": base64.StdEncoding.EncodeToString(block.Bytes[61 : len(block.Bytes)-17]),
			"passphrase":       `{"passphrase":"` + passphrase + `"}`,
		}
		for what, text := range leaks {
			found := false
			for _, sec := range secs {
				if _, ok := sec.leakedIn("x " + text + " y"); ok {
					found = true
				}
			}
			assert.True(t, found, "%s: %s is caught", name, what)
		}
		for _, sec := range secs {
			_, ok := sec.leakedIn(publicLine + " " + ssh.FingerprintSHA256(signer.PublicKey()))
			assert.False(t, ok, "%s: %s matches the public key", name, sec.name)
		}

		// The places: a log line, an answer, a table row, an email.
		mark := func(where string) {
			n := len(e.sshLeaks(secs, false))
			switch where {
			case "log":
				logLine := slog.New(slog.NewJSONHandler(e.logs, &slog.HandlerOptions{Level: slog.LevelDebug}))
				logLine.Debug("leak", "blob", block.Bytes)
			case "answer":
				e.mu.Lock()
				e.exchanges = append(e.exchanges, exchange{method: http.MethodGet, path: "/api/v1/planted", status: http.StatusOK,
					header: http.Header{}, body: jsonFile})
				e.mu.Unlock()
			case "table":
				_, err := e.db.Owner.Exec(context.Background(), `INSERT INTO settings (key, value) VALUES ($1, to_jsonb($2::text))`,
					"planted."+name, string(jsonDER))
				require.NoError(t, err)
			case "email":
				require.NoError(t, e.mailbox.Send(context.Background(), notify.Message{To: "ada@example.com", Subject: "planted", Body: secret}))
			}
			assert.Greater(t, len(e.sshLeaks(secs, false)), n, "%s: a leak in the %s is found", name, where)
		}
		for _, where := range []string{"log", "answer", "table", "email"} {
			mark(where)
		}
	}
	// An envelope in a bytea column of another table is found by the envelope scan.
	env := make([]byte, 96)
	_, _ = rand.Read(env)
	n := len(e.sshLeaks([]secretValue{binaryCanary("sealed envelope", env)}, true))
	_, err = e.db.Owner.Exec(context.Background(), `INSERT INTO settings (key, value) VALUES ('planted.envelope', to_jsonb($1::text))`,
		base64.StdEncoding.EncodeToString(env[6:]))
	require.NoError(t, err)
	assert.Greater(t, len(e.sshLeaks([]secretValue{binaryCanary("sealed envelope", env)}, true)), n)
}
