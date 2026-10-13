//go:build integration

package api

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"alice/internal/i18n"
	"alice/internal/jobs/acmejobs"
	"alice/internal/notify"
	"alice/internal/secrets"
	"alice/internal/testutil/fakeacme"
	"alice/internal/testutil/pki"
	"alice/locales"
)

// Secret-leak suite for ACME issuance (plan 2026-10-13 Task 17). A whole journey runs against fakeacme: a provider with
// an external account binding, the account registration and a key rollover, a DNS-01 hook with a secret (the bearer
// token and HMAC key of every hook call), an order that generates and seals a new managed private key, a deployment,
// a Test run, a failed order and a backup. Then every place a secret could land in is scanned: the captured DEBUG log,
// every HTTP answer of the API (headers and bodies) after every list and detail of providers, hooks, certificates,
// orders, bindings, deployments, jobs and the audit log was read, every row of every table (which holds the job
// payloads, results and errors, the audit details and the notification outbox), the bytea columns as base64, the
// emails rendered from the outbox and the manifest of the backup. The canaries: every ACME account key (PKCS#8 and
// SEC1, PEM and DER in every encoding and in pieces, and the data-encryption key sealing it), the EAB HMAC key (raw
// and base64url, as the CA hands it out), the hook secret and every managed private key (the issued leaf's).

// acmeLeakWorld is acmeWorld with canary credentials: the EAB HMAC key and the hook secret are chosen by the test.
type acmeLeakWorld struct {
	*acmeWorld
	eabRaw []byte
	// raw buffers of two canaries for the positive control's bytea plant
	activeAccountDER, leafDER []byte
}

func newACMELeakWorld(t *testing.T) *acmeLeakWorld {
	t.Helper()
	n := newNJ(t, wwwSite())
	raw := make([]byte, 32)
	_, err := rand.Read(raw)
	require.NoError(t, err)
	fake, err := fakeacme.New(fakeacme.Options{Now: n.clock.Now, RequireEAB: true, EABKey: raw, HookSecret: canary("hook-secret")})
	require.NoError(t, err)
	require.NoError(t, fake.Start())
	t.Cleanup(fake.Close)
	return &acmeLeakWorld{acmeWorld: &acmeWorld{nj: n, fake: fake, cred: fake.Credentials()}, eabRaw: raw}
}

// credentialCanaries are the EAB HMAC key (the raw key in every encoding, and the base64url text Alice is given, in
// every encoding and in pieces) and the hook secret (as typed, every encoding, pieces).
func (w *acmeLeakWorld) credentialCanaries() []secretValue {
	require.Equal(w.t, base64.RawURLEncoding.EncodeToString(w.eabRaw), w.cred.EABHMAC)
	return []secretValue{
		{name: "EAB HMAC key (raw)", forms: binaryForms(w.eabRaw)},
		binaryCanary("EAB HMAC key (raw, pieces)", w.eabRaw),
		textCanary("EAB HMAC key (base64url)", w.cred.EABHMAC),
		textCanary("hook secret", w.cred.HookSecret),
	}
}

// sealingKeys are the data-encryption keys sealing the EAB HMAC key and the hook secret (the rows are opened with the
// keyring to prove the envelopes are the canaries').
func (w *acmeLeakWorld) sealingKeys() []secretValue {
	t := w.t
	t.Helper()
	ctx := context.Background()
	var secs []secretValue
	for _, q := range []struct{ name, table, column, sql, want string }{
		{"EAB sealing DEK", "acme_providers", "eab_hmac", "SELECT id, eab_hmac_ct, eab_hmac_nonce, eab_hmac_wrapped_dek, eab_hmac_key_version FROM acme_providers WHERE eab_hmac_ct IS NOT NULL", w.cred.EABHMAC},
		{"hook sealing DEK", "acme_hooks", "secret", "SELECT id, secret_ct, secret_nonce, secret_wrapped_dek, secret_key_version FROM acme_hooks", w.cred.HookSecret},
	} {
		rows, err := w.db.Owner.Query(ctx, q.sql)
		require.NoError(t, err)
		n := 0
		for rows.Next() {
			var id uuid.UUID
			var env secrets.Envelope
			require.NoError(t, rows.Scan(&id, &env.Ciphertext, &env.Nonce, &env.WrappedDEK, &env.KeyVersion))
			loc := secrets.Location{Table: q.table, RowID: id.String(), Column: q.column}
			pt, err := w.keyring.Open(loc, env)
			require.NoError(t, err)
			assert.Equal(t, q.want, string(pt.Bytes()), "%s seals the canary", q.table)
			pt.Zero()
			secs = append(secs, secretValue{name: q.name, forms: binaryForms(unwrapDEK(t, w.masterKey(), loc, env))})
			n++
		}
		require.NoError(t, rows.Err())
		rows.Close()
		require.Positive(t, n, q.table)
	}
	return secs
}

// accountKeys opens every sealed ACME account key with the stack's keyring (test only) and returns its canaries: the
// PEM and DER forms, pieces of the DER (minus the public key, which is no secret) and the data-encryption key.
func (w *acmeLeakWorld) accountKeys() []secretValue {
	t := w.t
	t.Helper()
	ctx := context.Background()
	rows, err := w.db.Owner.Query(ctx, "SELECT id, key_ct, key_nonce, key_wrapped_dek, key_version, state FROM acme_accounts ORDER BY created_at")
	require.NoError(t, err)
	defer rows.Close()
	var secs []secretValue
	for rows.Next() {
		var id uuid.UUID
		var env secrets.Envelope
		var state string
		require.NoError(t, rows.Scan(&id, &env.Ciphertext, &env.Nonce, &env.WrappedDEK, &env.KeyVersion, &state))
		loc := secrets.Location{Table: "acme_accounts", RowID: id.String(), Column: "key"}
		pt, err := w.keyring.Open(loc, env)
		require.NoError(t, err)
		der := append([]byte(nil), pt.Bytes()...)
		pt.Zero()
		key, err := x509.ParsePKCS8PrivateKey(der)
		require.NoError(t, err)
		pub, err := x509.MarshalPKIXPublicKey(key.(crypto.Signer).Public())
		require.NoError(t, err)
		name := "ACME account key " + state
		kc := newKeyCanary(name, key)
		secs = append(secs, kc.secrets()...)
		secs = append(secs, keyPieces(name, kc, pub)...)
		if state == "active" {
			w.activeAccountDER = der
		}
		secs = append(secs, storedKeySecrets(name, der, unwrapDEK(t, w.masterKey(), loc, env))...)
	}
	require.NoError(t, rows.Err())
	return secs
}

// keyPieces are needles cut out of a key's DER (PKCS#8 and PKCS#1/SEC1). Needles also found in the public material or
// in a sibling key of the same type are dropped: the public key is no secret, and the ASN.1 framing every key of the
// type shares (version, algorithm identifiers, lengths) would flag any other key of that type as this one.
func keyPieces(name string, kc keyCanary, public ...[]byte) []secretValue {
	k, err := x509.ParsePKCS8PrivateKey(kc.der8)
	if err != nil {
		panic(err)
	}
	var sibling keyCanary
	switch ek := k.(type) {
	case *ecdsa.PrivateKey:
		sibling = newKeyCanary("sibling", pki.NewKey(pki.ECDSA256))
		if ek.Curve != elliptic.P256() {
			sibling = newKeyCanary("sibling", pki.NewKey(pki.ECDSA384))
		}
	default:
		sibling = newKeyCanary("sibling", pki.NewKey(pki.RSA2048))
	}
	return []secretValue{
		binaryCanary(name+" (PKCS#8 DER pieces)", kc.der8, append([][]byte{sibling.der8}, public...)...),
		binaryCanary(name+" (PKCS#1/SEC1 DER pieces)", kc.derOld, append([][]byte{sibling.derOld}, public...)...),
	}
}

// leafKeys are the canaries of every managed private key (storedKeys: plaintext DER, PEM, DEK) and pieces of the DER
// of each key that belongs to a certificate (minus the certificate's own bytes).
func (w *acmeLeakWorld) leafKeys() []secretValue {
	t := w.t
	t.Helper()
	secs, rows := w.storedKeys()
	for id, k := range rows {
		var chain string
		require.NoError(t, w.db.Owner.QueryRow(context.Background(), "SELECT pem_chain FROM certificates WHERE private_key_id = $1", id).Scan(&chain))
		b, _ := pem.Decode([]byte(chain))
		require.NotNil(t, b)
		cert, err := x509.ParseCertificate(b.Bytes)
		require.NoError(t, err)
		key, err := x509.ParsePKCS8PrivateKey(k.der)
		require.NoError(t, err)
		kc := newKeyCanary("managed key "+k.owner, key)
		for _, sec := range kc.secrets() {
			secs = append(secs, withoutPublic(sec, cert))
		}
		secs = append(secs, keyPieces(kc.name, kc, cert.Raw)...)
		if k.owner == "certificate" {
			w.leafDER = k.der
		}
	}
	return secs
}

// readEverything makes the API answer every list and detail the journey produced, so the scan sees those answers.
func (w *acmeLeakWorld) readEverything(providerID, hookID, certID string) {
	t := w.t
	t.Helper()
	items := func(path string) []map[string]any {
		rec := w.admin.do(http.MethodGet, path, nil)
		requireStatus(t, rec, http.StatusOK)
		return decodeBody[struct {
			Items []map[string]any `json:"items"`
		}](t, rec).Items
	}
	for _, p := range []string{"/api/v1/acme/providers/" + providerID, "/api/v1/acme/hooks/" + hookID, "/api/v1/acme/certificates/" + certID,
		"/api/v1/acme/certificates/" + certID + "/bindings", "/api/v1/certificates", "/api/v1/audit?limit=200", "/api/v1/backups"} {
		requireStatus(t, w.admin.do(http.MethodGet, p, nil), http.StatusOK)
	}
	require.NotEmpty(t, items("/api/v1/acme/providers"))
	require.NotEmpty(t, items("/api/v1/acme/hooks"))
	require.NotEmpty(t, items("/api/v1/acme/certificates"))
	require.NotEmpty(t, items("/api/v1/acme/certificates/"+certID+"/orders"))
	for _, c := range items("/api/v1/certificates") {
		requireStatus(t, w.admin.do(http.MethodGet, "/api/v1/certificates/"+c["id"].(string), nil), http.StatusOK)
	}
	jobs := items("/api/v1/jobs")
	require.NotEmpty(t, jobs)
	for _, j := range jobs {
		requireStatus(t, w.admin.do(http.MethodGet, "/api/v1/jobs/"+j["id"].(string), nil), http.StatusOK)
	}
	deps := items("/api/v1/deployments")
	require.NotEmpty(t, deps)
	for _, d := range deps {
		requireStatus(t, w.admin.do(http.MethodGet, "/api/v1/deployments/"+d["id"].(string), nil), http.StatusOK)
	}
}

// emails renders every message of the outbox the way the sender does.
func (w *acmeLeakWorld) emails() (string, map[string]bool) {
	t := w.t
	t.Helper()
	catalog, err := i18n.Load(locales.FS)
	require.NoError(t, err)
	sender := notify.Sender{Catalog: catalog}
	rows, err := w.db.Owner.Query(context.Background(), `SELECT to_address, template_key, locale, params FROM notifications_outbox`)
	require.NoError(t, err)
	defer rows.Close()
	var b strings.Builder
	templates := map[string]bool{}
	for rows.Next() {
		var to, tpl, locale string
		var params map[string]string
		require.NoError(t, rows.Scan(&to, &tpl, &locale, &params))
		templates[tpl] = true
		msg := sender.Render(to, tpl, locale, params)
		b.WriteString(msg.Subject + "\n" + msg.Body + "\n")
	}
	require.NoError(t, rows.Err())
	return b.String(), templates
}

// acmeLeaks lists "canary in place" for every canary found in the stack's places, the rendered emails and the extra
// places (the backup manifest).
func (w *acmeLeakWorld) acmeLeaks(secs []secretValue, extra map[string]string) []string {
	w.t.Helper()
	out := w.leaks(secs)
	mail, _ := w.emails()
	extra["emails"] = mail
	extra["raw log"] = w.rawLogs.String()
	for place, text := range extra {
		for _, sec := range secs {
			if _, found := sec.leakedIn(text); found {
				out = append(out, sec.name+" in "+place)
			}
		}
	}
	return out
}

func TestACMESecretsNeverLeak(t *testing.T) {
	w := newACMELeakWorld(t)
	providerID, hookID := w.setUp()

	// The key change: a second account key, the first one retired (both are canaries).
	rec := w.admin.do(http.MethodGet, "/api/v1/acme/providers/"+providerID, nil)
	requireStatus(t, rec, http.StatusOK)
	firstAccount := decodeBody[map[string]any](t, rec)["active_account_id"].(string)
	rec = w.admin.do(http.MethodPost, "/api/v1/acme/accounts/"+firstAccount+"/rollover", nil)
	requireStatus(t, rec, http.StatusOK)

	// A DNS-01 certificate: a Test run, an order (the hook is called with its secret, a new managed key is sealed), a
	// binding and Deploy now.
	rec = w.defineCert(providerID, hookID, wwwName)
	requireStatus(t, rec, http.StatusCreated)
	certID := decodeBody[map[string]any](t, rec)["id"].(string)
	requireStatus(t, w.op.do(http.MethodPost, "/api/v1/acme/certificates/"+certID+"/test", nil), http.StatusAccepted)
	w.runJobs()
	requireStatus(t, w.op.do(http.MethodPost, "/api/v1/acme/certificates/"+certID+"/order", nil), http.StatusAccepted)
	issued := w.waitIssued(w.op, certID)
	require.Equal(t, "active", issued["state"], "%v", issued)
	loc := w.locs[wwwCert]
	requireStatus(t, w.op.do(http.MethodPut, "/api/v1/acme/certificates/"+certID+"/bindings/"+loc, map[string]any{"auto_deploy": false}), http.StatusOK)
	rec = w.op.do(http.MethodPost, "/api/v1/acme/certificates/"+certID+"/deploy", nil)
	requireStatus(t, rec, http.StatusAccepted)
	deps := decodeBody[struct {
		Deployments []deployRef `json:"deployments"`
	}](t, rec).Deployments
	require.Len(t, deps, 1)
	require.Equal(t, "succeeded", w.settle(w.op, deps[0].ID).Status)

	// A renewal the planner starts (the CA's renewal information says now): the acme.schedule tick logs it, and the
	// renewal order runs through the hook and seals a second managed key.
	w.clock.Advance(16 * time.Minute) // past renew.MinSpacing since the order
	require.NoError(t, w.fake.SetARIWindow(w.clock.Now().Add(-time.Hour), w.clock.Now().Add(time.Hour)))
	require.NoError(t, acmejobs.ScheduleTask(w.inv, time.Minute, w.logger()).Run(context.Background()))
	renewed := w.waitIssued(w.op, certID)
	require.NotEqual(t, issued["current"].(map[string]any)["id"], renewed["current"].(map[string]any)["id"], "the planner renewed the certificate")

	// Failed orders: the CA refuses the DNS-01 validation (an error, a failed job, a failed order row).
	require.NoError(t, w.fake.FailValidation(fakeacme.DNS01, true))
	// Five in a row (automatic renewal is on): the "renewal failed" e-mail after the third, the stop after the fifth.
	for range 5 {
		requireStatus(t, w.op.do(http.MethodPost, "/api/v1/acme/certificates/"+certID+"/order", nil), http.StatusAccepted)
		w.waitIssued(w.op, certID)
	}
	require.NoError(t, w.fake.FailValidation(fakeacme.DNS01, false))

	// A backup: its manifest is scanned too.
	w.stepUp(w.admin, w.adminAcct)
	rec = w.admin.do(http.MethodPost, "/api/v1/backups", nil)
	requireStatus(t, rec, http.StatusCreated)
	name := decodeBody[map[string]any](t, rec)["name"].(string)
	m, err := w.backup.VerifyDeep(context.Background(), filepath.Join(w.backupsDir, name), []byte(backupPassphrase))
	require.NoError(t, err)
	manifest, err := json.Marshal(m)
	require.NoError(t, err)
	require.Contains(t, m.Tables, "acme_accounts", "the backup holds the ACME tables")

	w.readEverything(providerID, hookID, certID)

	// The canaries, and proof that the journey really held each of them.
	accountKeys := w.accountKeys()
	leafKeys := w.leafKeys()
	secs := append(append(w.credentialCanaries(), accountKeys...), leafKeys...)
	require.Len(t, accountKeys, 2*9, "two account keys (the rollover's retired and active), nine canaries each")
	var owners []string
	for _, s := range leafKeys {
		owners = append(owners, s.name)
	}
	assert.Contains(t, strings.Join(owners, ";"), "managed key certificate", "the issued certificate's sealed key is a canary")
	for _, sec := range secs {
		require.NotEmpty(t, sec.forms, sec.name)
	}
	var orders, failed, hookCalls int
	require.NoError(t, w.db.Owner.QueryRow(context.Background(), "SELECT count(*) FROM acme_orders").Scan(&orders))
	require.NoError(t, w.db.Owner.QueryRow(context.Background(), "SELECT count(*) FROM acme_orders WHERE state = 'failed' AND error_code <> ''").Scan(&failed))
	assert.GreaterOrEqual(t, orders, 3, "a Test run, an issued and a failed order")
	assert.Positive(t, failed, "an order error is in the scan")
	for _, r := range w.fake.Requests() {
		if strings.HasPrefix(r.Path, "/hook") {
			hookCalls++
		}
	}
	assert.Positive(t, hookCalls, "the hook was called with its secret")

	// The log channels are not vacuous: the journey's ACME activity is in them (the planner's line), redacted and raw.
	for name, text := range map[string]string{"log": w.logs.String(), "raw log": w.rawLogs.String()} {
		assert.Contains(t, text, "planned ACME renewals", "%s holds the journey's ACME lines", name)
	}
	secs = append(secs, w.sealingKeys()...)

	// The scan.
	extra := map[string]string{"backup manifest": string(manifest)}
	for _, l := range w.acmeLeaks(secs, extra) {
		t.Errorf("leak: %s", l)
	}
	_, templates := w.emails()
	assert.True(t, templates["acme.renewal_failed"], "the scan saw the renewal-failed e-mail: %v", templates)
	assert.True(t, templates["acme.auto_renew_stopped"], "the scan saw the stop e-mail: %v", templates)

	// Positive control: each kind of canary planted in each kind of place is found. A plant gets the canary's text (as a
	// log value, a JSON string or an e-mail spells it) and its raw bytes (for a bytea column).
	ctx := context.Background()
	plants := []struct {
		place string
		plant func(text string, raw []byte)
	}{
		{"log", func(text string, _ []byte) {
			_, _ = w.logs.Write([]byte("level=DEBUG msg=planted value=" + text + "\n"))
		}},
		{"raw log", func(text string, _ []byte) {
			_, _ = w.rawLogs.Write([]byte("level=DEBUG msg=planted value=" + text + "\n"))
		}},
		{"responses", func(text string, _ []byte) {
			r := httptest.NewRecorder()
			_, _ = r.WriteString(`{"planted":"` + text + `"}`)
			w.record(http.MethodGet, "/planted", r)
		}},
		{"tables", func(text string, _ []byte) {
			_, err := w.db.Owner.Exec(ctx, "UPDATE jobs SET result = jsonb_build_object('planted', $1::text) WHERE id = (SELECT id FROM jobs LIMIT 1)", text)
			require.NoError(t, err)
		}},
		{"bytea base64", func(_ string, raw []byte) {
			_, err := w.db.Owner.Exec(ctx, "UPDATE acme_hooks SET secret_ct = $1", raw)
			require.NoError(t, err)
		}},
		{"emails", func(text string, _ []byte) {
			_, err := w.db.Owner.Exec(ctx, `UPDATE notifications_outbox SET params = params || jsonb_build_object('names', $1::text)
WHERE template_key = 'acme.renewal_failed'`, text)
			require.NoError(t, err)
		}},
		{"backup manifest", func(text string, _ []byte) { extra["backup manifest"] += text }},
	}
	type sample struct {
		sec  secretValue
		text string
		raw  []byte
	}
	raws := map[string][]byte{"EAB HMAC key (base64url)": []byte(w.cred.EABHMAC), "hook secret": []byte(w.cred.HookSecret),
		"ACME account key active (PKCS#8 PEM)": w.activeAccountDER, "managed key certificate (PKCS#8 DER pieces)": w.leafDER}
	samples := map[string]sample{}
	for _, sec := range secs {
		raw, ok := raws[sec.name]
		if !ok {
			continue
		}
		require.NotEmpty(t, raw, sec.name)
		text := sec.forms[len(sec.forms)-1]
		if strings.HasSuffix(sec.name, "PEM)") {
			text = strings.ReplaceAll(sec.forms[0], "\n", `\n`) // as a JSON string or a log value spells it
		}
		samples[sec.name] = sample{sec: sec, text: text, raw: raw}
	}
	require.Len(t, samples, 4)
	for _, p := range plants {
		for name, smp := range samples {
			p.plant(smp.text, smp.raw)
			got := w.acmeLeaks([]secretValue{smp.sec}, extra)
			assert.Contains(t, strings.Join(got, "; "), smp.sec.name+" in "+p.place, "a %s planted in %s is found", name, p.place)
		}
	}

	// The raw log sees what the redacting handler hides: a canary logged under a secret-looking key is in the raw log
	// only (the redaction is the defence; the raw log proves no ACME code hands a secret to a logger at all).
	hidden := textCanary("hidden", canary("hidden"))
	w.logger().Debug("planted", "secret", hidden.forms[0])
	got := strings.Join(w.acmeLeaks([]secretValue{hidden}, extra), "; ")
	assert.Contains(t, got, "hidden in raw log")
	assert.NotContains(t, got, "hidden in log")
}
