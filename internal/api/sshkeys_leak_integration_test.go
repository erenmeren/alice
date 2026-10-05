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
	"math/big"
	"net/http"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/ssh"
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
	out = append(out, secretValue{name: name + " (PKCS#8 DER printed with %v)", forms: sprintForms(der)})
	switch k := key.(type) {
	case ed25519.PrivateKey:
		out = append(out, secretValue{name: name + " (Ed25519 seed)", forms: append(binaryForms(k.Seed())[1:], sprintForms(k.Seed())...)})
	case *rsa.PrivateKey:
		out = append(out, secretValue{name: name + " (RSA d)", forms: append(binaryForms(k.D.Bytes())[1:], k.D.String())},
			secretValue{name: name + " (RSA p)", forms: append(binaryForms(k.Primes[0].Bytes())[1:], k.Primes[0].String())},
			secretValue{name: name + " (RSA q)", forms: append(binaryForms(k.Primes[1].Bytes())[1:], k.Primes[1].String())},
			secretValue{name: name + " (PKCS#1 PEM)", forms: pemForms(pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY",
				Bytes: x509.MarshalPKCS1PrivateKey(k)}))})
	case *ecdsa.PrivateKey:
		d, err := k.Bytes()
		require.NoError(t, err)
		out = append(out, secretValue{name: name + " (ECDSA scalar)", forms: append(append(binaryForms(d)[1:], sprintForms(d)...), new(big.Int).SetBytes(d).String())})
	default:
		t.Fatalf("%s: unexpected key type %T", name, key)
	}
	return out
}

// sprintForms are the spellings of a byte slice printed by Go's fmt (%v, %+v, slog's text of a []byte inside a
// struct): the whole "[12 34 …]" and its inner runs of 24 bytes every 12 bytes (a printed key or signer struct
// contains the slice's numbers, not its brackets).
func sprintForms(b []byte) []string {
	inner := func(p []byte) string { return strings.TrimSuffix(strings.TrimPrefix(goPrint(p), "["), "]") }
	out := []string{goPrint(b)}
	for i := 0; i+24 <= len(b); i += 12 {
		out = append(out, inner(b[i:i+24]))
	}
	return out
}

// goPrint is how fmt prints a []byte with %v: "[12 34 …]".
func goPrint(b []byte) string {
	parts := make([]string, len(b))
	for i, x := range b {
		parts[i] = strconv.Itoa(int(x))
	}
	return "[" + strings.Join(parts, " ") + "]"
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
		for _, r := range raws {
			out = append(out, goPrint(r))
		}
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
// one line, its PKCS #8 in a JSON []byte, its seed or exponent in hex and in decimal, a misaligned slice of its body in
// base64, the key, its seed and its signer printed by Go (%v, %+v, slog.Any) through the stack's own logger, and the
// passphrase inside JSON are each caught; each is found where it was planted in a real sink (the stack's logger, the
// outbox delivered by the real sender, a bytea column of a table the dump reads) and in the harness's record of
// answers; the public key and its fingerprint are not mistaken for a leak.
func TestSSHKeyLeakScannerFindsEveryCanary(t *testing.T) {
	e := newKeyEnv(t)
	_, edKey, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	passphrase := canary("download-passphrase")
	stackLog := e.deps().Log // the logger the server is built with (logging.New over the stack's log, DEBUG)
	_, err = e.db.Owner.Exec(context.Background(), "CREATE TABLE t14_planted (name text PRIMARY KEY, blob bytea NOT NULL)")
	require.NoError(t, err)
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
		var secret, decimal string
		var seed []byte
		switch k := key.(type) {
		case ed25519.PrivateKey:
			secret, seed = hex.EncodeToString(k.Seed()), k.Seed()
			decimal = fmt.Sprintf("%v", k)
		case *rsa.PrivateKey:
			secret, decimal = hex.EncodeToString(k.D.Bytes()), k.D.String()
			seed = k.Primes[0].Bytes()
		}
		leaks := map[string]string{
			"file":                    string(file),
			"file in JSON":            string(jsonFile),
			"body on one line":        strings.ReplaceAll(strings.TrimSpace(string(file)), "\n", ""),
			"PKCS#8 as []byte":        string(jsonDER),
			"secret in hex":           secret,
			"secret in decimal or %v": decimal,
			"key printed with %+v":    fmt.Sprintf("%+v", key),
			"misaligned slice":        base64.StdEncoding.EncodeToString(block.Bytes[61 : len(block.Bytes)-17]),
			"passphrase":              `{"passphrase":"` + passphrase + `"}`,
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

		// Each sink, one plant at a time: what the plant added to that place (the log, the answers and the emails grow at
		// their end; the table is new) must hold a canary.
		plant := func(place, what string, do func()) {
			before := len(e.leakPlaces(false)[place])
			do()
			text := e.leakPlaces(false)[place]
			if place != "tables" {
				text = text[before:]
			}
			hit := false
			for _, sec := range secs {
				if _, ok := sec.leakedIn(text); ok {
					hit = true
				}
			}
			assert.True(t, hit, "%s: %s planted in the %s is found", name, what, place)
		}
		plant("log", "slog.Any of the key", func() { stackLog.Debug("planted", slog.Any("material", key)) })
		if name == "ed25519" { // an RSA or ECDSA signer prints pointers only; its key is printed below
			leaks := []string{fmt.Sprintf("%v", signer), fmt.Sprintf("%+v", signer)}
			plant("log", "the signer with %v", func() { stackLog.Debug("planted " + leaks[0]) })
			plant("log", "the signer with %+v", func() { stackLog.Debug("planted " + leaks[1]) })
		}
		plant("log", "the key with %+v", func() { stackLog.Debug(fmt.Sprintf("planted %+v", key)) })
		plant("log", "slog.Any of the seed bytes", func() { stackLog.Debug("planted", slog.Any("blob", seed)) })
		plant("log", "the block as bytes", func() { stackLog.Debug("planted", "blob", block.Bytes) })
		plant("responses", "an answer body", func() {
			// The harness's record of answers (no handler echoes a key; this proves the record is scanned).
			e.mu.Lock()
			e.exchanges = append(e.exchanges, exchange{method: http.MethodGet, path: "/api/v1/planted", status: http.StatusOK,
				header: http.Header{}, body: jsonFile})
			e.mu.Unlock()
		})
		plant("tables", "a bytea column", func() {
			_, err := e.db.Owner.Exec(context.Background(), "INSERT INTO t14_planted (name, blob) VALUES ($1, $2)", name, der)
			require.NoError(t, err)
		})
		plant("emails", "an email the sender delivered", func() {
			_, err := e.db.Owner.Exec(context.Background(), `INSERT INTO notifications_outbox (id, kind, to_address, template_key, params, locale,
    status, attempts, next_attempt_at, created_at) VALUES (gen_random_uuid(), 'email', 'ada@example.com', 'rotation.paused_license',
    jsonb_build_object('key_label', $1::text), 'en', 'pending', 0, now() - interval '1 year', now() - interval '1 year')`, secret)
			require.NoError(t, err)
			require.Positive(t, e.deliverMail())
		})
	}
	// An envelope slice in a bytea column (hex in to_jsonb, base64 in the bytea scan) is found by the envelope scan.
	env := make([]byte, 96)
	_, _ = rand.Read(env)
	n := len(e.sshLeaks([]secretValue{binaryCanary("sealed envelope", env)}, true))
	_, err = e.db.Owner.Exec(context.Background(), "INSERT INTO t14_planted (name, blob) VALUES ('envelope', $1)", env[6:])
	require.NoError(t, err)
	assert.Greater(t, len(e.sshLeaks([]secretValue{binaryCanary("sealed envelope", env)}, true)), n)
}
