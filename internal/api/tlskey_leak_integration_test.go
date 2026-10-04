//go:build integration

package api

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"alice/internal/i18n"
	"alice/internal/notify"
	"alice/internal/providers"
	"alice/internal/providers/linuxssh/helperproto"
	"alice/internal/secrets"
	"alice/internal/testutil/pki"
	"alice/locales"
)

// Secret-leak suite with TLS private keys (spec §25.2, S-01..S-05, S-08). The canaries are keys
// generated for this run, in every form they could leak: PKCS#8, PKCS#1 and SEC1 PEM, their base64
// body lines, the DER as hex and base64, PEM with escaped line breaks (as JSON and logs write it),
// and the PFX password. Upload (PEM and PFX, good and refused), signing requests, deployments
// (success, rollback, a failed rollback, a lost answer and its recovery) and every read run first;
// then every response and header, every table, the debug log and the emails rendered from the
// outbox are scanned. The emulated server receives the key on stdin: that is the customer's side
// and is the one place the key must be.

// keyCanary is one private key and everything that spells it.
type keyCanary struct {
	name   string
	der8   []byte // PKCS#8
	derOld []byte // PKCS#1 or SEC1
	pem8   []byte
	pemOld []byte
}

func newKeyCanary(name string, key any) keyCanary {
	c := keyCanary{name: name}
	var err error
	if c.der8, err = x509.MarshalPKCS8PrivateKey(key); err != nil {
		panic(err)
	}
	switch k := key.(type) {
	case *rsa.PrivateKey:
		c.derOld = x509.MarshalPKCS1PrivateKey(k)
		c.pemOld = pki.KeyPEMPKCS1(k)
	case *ecdsa.PrivateKey:
		if c.derOld, err = x509.MarshalECPrivateKey(k); err != nil {
			panic(err)
		}
		c.pemOld = pki.KeyPEMSEC1(k)
	}
	c.pem8 = pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: c.der8})
	return c
}

// pemForms are the spellings of a PEM text: as is, with CRLF, with the line breaks escaped the way
// JSON and log lines write them, and every long body line alone (a leak that wraps or re-wraps the
// key still shows one of its lines).
func pemForms(p []byte) []string {
	text := string(p)
	out := []string{text, strings.ReplaceAll(text, "\n", "\r\n"), strings.ReplaceAll(text, "\n", `\n`), strings.ReplaceAll(strings.ReplaceAll(text, "\n", "\r\n"), "\r\n", `\r\n`)}
	var body []string
	for _, line := range strings.Split(strings.TrimSpace(text), "\n") {
		if !strings.HasPrefix(line, "-----") {
			body = append(body, line)
			if len(line) >= 40 {
				out = append(out, line)
			}
		}
	}
	return append(out, strings.Join(body, ""))
}

// secrets lists the secretValues of the key.
func (c keyCanary) secrets() []secretValue {
	var forms8, formsOld []string
	forms8 = append(forms8, binaryForms(c.der8)[1:]...)
	formsOld = append(formsOld, binaryForms(c.derOld)[1:]...)
	return []secretValue{
		{name: c.name + " (PKCS#8 PEM)", forms: pemForms(c.pem8)},
		{name: c.name + " (PKCS#1/SEC1 PEM)", forms: pemForms(c.pemOld)},
		{name: c.name + " (PKCS#8 DER)", forms: forms8},
		{name: c.name + " (PKCS#1/SEC1 DER)", forms: formsOld},
	}
}

// storedKeys decrypts every managed key with the stack's keyring (test only): the plaintext
// PKCS#8 DER and the data-encryption key behind each row.
func (s *stack) storedKeys() (secs []secretValue, rows map[string]storedKey) {
	s.t.Helper()
	ctx := context.Background()
	res, err := s.db.Owner.Query(ctx, `SELECT id, owner_type, public_key_sha256, ciphertext, nonce, wrapped_dek, key_version FROM managed_private_keys ORDER BY created_at`)
	require.NoError(s.t, err)
	defer res.Close()
	rows = map[string]storedKey{}
	for res.Next() {
		var id uuid.UUID
		var k storedKey
		require.NoError(s.t, res.Scan(&id, &k.owner, &k.public, &k.env.Ciphertext, &k.env.Nonce, &k.env.WrappedDEK, &k.env.KeyVersion))
		loc := secrets.Location{Table: "managed_private_keys", RowID: id.String(), Column: "ciphertext"}
		pt, err := s.keyring.Open(loc, k.env)
		require.NoError(s.t, err)
		der := append([]byte(nil), pt.Bytes()...)
		pt.Zero()
		k.der = der
		rows[id.String()] = k
		name := "stored key " + k.owner
		secs = append(secs,
			secretValue{name: name + " (plaintext DER)", forms: binaryForms(der)[1:]},
			secretValue{name: name + " (PEM)", forms: pemForms(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}))},
			secretValue{name: name + " (DEK)", forms: binaryForms(unwrapDEK(s.t, s.masterKey(), loc, k.env))},
		)
	}
	require.NoError(s.t, res.Err())
	return secs, rows
}

type storedKey struct {
	owner, public string
	env           secrets.Envelope
	der           []byte
}

// jsonFieldNames collects every object key of a JSON document.
func jsonFieldNames(v any, out map[string]bool) {
	switch x := v.(type) {
	case map[string]any:
		for k, val := range x {
			out[k] = true
			jsonFieldNames(val, out)
		}
	case []any:
		for _, val := range x {
			jsonFieldNames(val, out)
		}
	}
}

// tlsKeyMarkers are the PEM headers of every kind of private key, and Phase 3's markers.
var tlsKeyMarkers = append([]string{"BEGIN " + "PRIVATE", "BEGIN RSA " + "PRIVATE", "BEGIN EC " + "PRIVATE", "BEGIN ENCRYPTED " + "PRIVATE"},
	privateKeyMarkers...)

// secretFieldNames are field names no response may have (has_private_key says only that a key is held).
var secretFieldNames = []string{"private_key", "private_key_pem", "private_key_id", "key_pem", "pfx_base64", "pfx_password", "password",
	"ciphertext", "nonce", "wrapped_dek", "dek", "key_version"}

func TestTLSKeysNeverLeak(t *testing.T) {
	n := newNJRSA(t, []string{apiCert}, wwwSite(), apiSite())
	s := n.stack
	now := s.clock.Now()

	ecKey, ok := pki.NewKey(pki.ECDSA256).(*ecdsa.PrivateKey)
	require.True(t, ok)
	rsaKey, ok := pki.NewKey(pki.RSA2048).(*rsa.PrivateKey)
	require.True(t, ok)
	ecCanary, rsaCanary := newKeyCanary("ECDSA canary key", ecKey), newKeyCanary("RSA canary key", rsaKey)
	pfxPassword, wrongPassword := canary("pfx-password"), canary("pfx-wrong-password")
	hostile := canary("hostile-text")
	opts := func(key any) pki.Opts {
		o := pki.Opts{CommonName: wwwName, SANs: []string{wwwName, apiName}}
		switch k := key.(type) {
		case *ecdsa.PrivateKey:
			o.Key = k
		case *rsa.PrivateKey:
			o.Key = k
		}
		return o
	}
	ecLeaf, ecLeaf2 := s.ca.Issue(opts(ecKey), now), s.ca.Issue(opts(ecKey), now)
	rsaLeaf, rsaLeaf2 := s.ca.Issue(opts(rsaKey), now), s.ca.Issue(opts(rsaKey), now)

	upload := func(label string, body map[string]any) *httptest.ResponseRecorder {
		body["label"] = label
		return n.op.do(http.MethodPost, "/api/v1/certificates/upload", body)
	}
	idOf := func(rec *httptest.ResponseRecorder) string {
		requireStatus(t, rec, http.StatusCreated)
		return decodeBody[struct {
			Certificate struct {
				ID string `json:"id"`
			} `json:"certificate"`
		}](t, rec).Certificate.ID
	}

	// Uploads: PEM with a SEC1 key, the same key again with another certificate (PKCS#8), a PFX with
	// the canary password, the RSA key as PKCS#1, and what is refused: a key of another certificate,
	// a wrong PFX password, a key protected by a password.
	ecCert := idOf(upload("EC", map[string]any{"certificate_pem": string(ecLeaf.FullchainPEM), "private_key_pem": string(ecCanary.pemOld)}))
	ecCert2 := idOf(upload("EC again", map[string]any{"certificate_pem": string(ecLeaf2.FullchainPEM), "private_key_pem": string(ecCanary.pem8)}))
	rsaCert := idOf(upload("RSA PFX", map[string]any{"pfx_base64": base64.StdEncoding.EncodeToString(pki.PFX(rsaLeaf, s.ca, pfxPassword)), "pfx_password": pfxPassword}))
	rsaCert2 := idOf(upload("RSA PKCS1", map[string]any{"certificate_pem": string(rsaLeaf2.FullchainPEM), "private_key_pem": string(rsaCanary.pemOld)}))
	requireError(t, upload("mismatch", map[string]any{"certificate_pem": string(ecLeaf.FullchainPEM), "private_key_pem": string(rsaCanary.pemOld)}),
		http.StatusUnprocessableEntity, "ALC-CRT-0002")
	requireError(t, upload("wrong password", map[string]any{"pfx_base64": base64.StdEncoding.EncodeToString(pki.PFX(rsaLeaf, s.ca, pfxPassword)),
		"pfx_password": wrongPassword}), http.StatusUnprocessableEntity, "ALC-CRT-0005")
	encrypted := pki.EncryptedKeyPEM(ecLeaf)
	requireError(t, upload("encrypted", map[string]any{"certificate_pem": string(ecLeaf.FullchainPEM), "private_key_pem": string(encrypted)}),
		http.StatusUnprocessableEntity, "ALC-CRT-0004")
	// A key pasted into the certificate field, and text that is neither (the hostile text must not come back).
	requireError(t, upload("key in certificate", map[string]any{"certificate_pem": string(ecCanary.pem8), "private_key_pem": hostile}),
		http.StatusUnprocessableEntity, "ALC-SYS-0006")
	requireError(t, upload("hostile", map[string]any{"certificate_pem": hostile, "private_key_pem": hostile}),
		http.StatusUnprocessableEntity, "ALC-CRT-0001")
	requireError(t, upload("duplicate", map[string]any{"certificate_pem": string(ecLeaf.FullchainPEM), "private_key_pem": string(ecCanary.pem8)}),
		http.StatusConflict, "ALC-CRT-0008")

	// A signing request: Alice makes the key; the CA signs; the certificate completes the request.
	rec := n.op.do(http.MethodPost, "/api/v1/certificates/csr", map[string]any{"common_name": wwwName, "sans": []string{wwwName}, "key_type": "ecdsa-p256"})
	requireStatus(t, rec, http.StatusCreated)
	csr := decodeBody[csrView](t, rec)
	signed := s.ca.IssueForCSR(parseCSR(t, csr.CSRPEM), now)
	rec = n.op.do(http.MethodPost, "/api/v1/certificates/csr/"+csr.ID+"/actions/complete", map[string]any{"certificate_pem": string(signed.FullchainPEM)})
	requireStatus(t, rec, http.StatusCreated)
	csrCert := decodeBody[struct {
		Certificate struct {
			ID string `json:"id"`
		} `json:"certificate"`
	}](t, rec).Certificate.ID
	requireError(t, n.op.do(http.MethodPost, "/api/v1/certificates/csr/"+csr.ID+"/actions/complete", map[string]any{"certificate_pem": string(signed.FullchainPEM)}),
		http.StatusConflict, "ALC-CRT-0012")

	// Deployments: a success, a rollback (the reload fails), a lost answer that recovery finishes and
	// a rollback that cannot be confirmed (the website is answered by something else).
	var deployments []string
	run := func(certID, location string) depView {
		ref := n.deploy(n.op, certID, location)[0]
		deployments = append(deployments, ref.ID)
		n.runJobs()
		return n.deployment(n.op, ref.ID)
	}
	assert.Equal(t, "succeeded", run(ecCert, n.locs[wwwCert]).Status)
	n.f.emu.FailReload(1)
	assert.Equal(t, "rolled_back", run(rsaCert, n.locs[apiCert]).Status)
	n.f.emu.HangupAfter(helperproto.StepReload)
	ref := n.deploy(n.op, csrCert, n.locs[wwwCert])[0]
	deployments = append(deployments, ref.ID)
	n.runJobs()
	require.Equal(t, "recovering", n.deployment(n.op, ref.ID).State)
	assert.Equal(t, "succeeded", n.settle(n.op, ref.ID).Status)
	n.setWrap(func(_ providers.TargetRef, sess providers.Session) providers.Session {
		return otherAnswers{Session: sess, f: n.f}
	})
	assert.Equal(t, "rollback_failed", run(rsaCert2, n.locs[apiCert]).Status)
	n.setWrap(nil)
	n.f.emu.ServeOther(443, "")

	// Every read that shows what these flows made, so that its response is scanned too.
	var jobIDs []string
	rec = n.admin.do(http.MethodGet, "/api/v1/jobs?limit=200", nil)
	requireStatus(t, rec, http.StatusOK)
	for _, j := range decodeBody[struct {
		Items []map[string]any `json:"items"`
	}](t, rec).Items {
		jobIDs = append(jobIDs, j["id"].(string))
	}
	require.NotEmpty(t, jobIDs)
	reads := []string{"/api/v1/certificates", "/api/v1/certificates/csr", "/api/v1/certificates/csr/" + csr.ID, "/api/v1/deployments",
		"/api/v1/deployments?target_id=" + n.targetID, "/api/v1/targets/" + n.targetID, "/api/v1/targets/" + n.targetID + "/certificate-locations?missing=true",
		"/api/v1/jobs", "/api/v1/providers", "/api/v1/audit", "/api/v1/audit/export?format=json", "/api/v1/ssh-keys/platform-key"}
	for _, id := range []string{ecCert, ecCert2, rsaCert, rsaCert2, csrCert} {
		reads = append(reads, "/api/v1/certificates/"+id)
	}
	for _, id := range deployments {
		reads = append(reads, "/api/v1/deployments/"+id)
	}
	for _, id := range jobIDs {
		reads = append(reads, "/api/v1/jobs/"+id)
	}
	for _, p := range reads {
		requireStatus(t, n.admin.do(http.MethodGet, p, nil), http.StatusOK)
	}

	// What is scanned for: both canary keys, the keys Alice stored (plaintext and DEK), the PFX
	// passwords, the master key and the hostile text a refused upload carried.
	stored, keyRows := s.storedKeys()
	require.Len(t, keyRows, 5, "EC twice, RSA twice and the signing request's key")
	secs := append([]secretValue{
		{name: "PFX password", value: pfxPassword},
		{name: "wrong PFX password", value: wrongPassword},
		{name: "hostile upload text", value: hostile},
		{name: "refused encrypted key body", forms: pemForms(encrypted)},
		s.masterKeySecret(),
	}, ecCanary.secrets()...)
	secs = append(secs, rsaCanary.secrets()...)
	secs = append(secs, stored...)

	// The scan is not vacuous: each canary key really reached the system. The emulated server
	// received it on stdin (the one place it belongs), and the rows Alice sealed open to it; the PFX
	// password opened the PFX (201 with a key held) while the wrong one was refused above.
	stdins := n.f.emu.DeployStdins()
	require.NotEmpty(t, stdins)
	for _, c := range []keyCanary{ecCanary, rsaCanary} {
		line := []byte(strings.Split(strings.TrimSpace(string(c.pem8)), "\n")[1])
		var onServer bool
		for _, in := range stdins {
			onServer = onServer || bytes.Contains(in, line)
		}
		assert.True(t, onServer, "%s reached the server's stdin", c.name)
		var sealed int
		for _, k := range keyRows {
			if bytes.Equal(k.der, c.der8) {
				sealed++
			}
		}
		assert.Equal(t, 2, sealed, "%s was sealed twice (two uploads) and opens to the canary", c.name)
	}
	pfxCert := decodeBody[map[string]any](t, n.op.do(http.MethodGet, "/api/v1/certificates/"+rsaCert, nil))
	assert.Equal(t, true, pfxCert["has_private_key"], "the PFX password opened the PFX and its key is held")

	scan := func(where, text string) {
		t.Helper()
		assertNoSecret(t, where, text, secs)
		for _, m := range tlsKeyMarkers {
			assert.NotContains(t, text, m, where)
		}
	}
	scan("logs", s.logs.String())
	assert.NotEmpty(t, s.logs.String(), "the debug log of the stack was captured")
	recorded := s.recorded()
	seen := map[string]bool{}
	for _, ex := range recorded {
		scan("response "+ex.key(), string(ex.body)+fmt.Sprint(ex.header))
		seen[ex.key()] = true
		var doc any
		if json.Unmarshal(ex.body, &doc) == nil {
			names := map[string]bool{}
			jsonFieldNames(doc, names)
			for name := range names {
				if name == "has_private_key" {
					continue
				}
				assert.NotContains(t, secretFieldNames, name, "S-08: response %s has a field %q", ex.key(), name)
			}
		}
	}
	for _, route := range []string{"POST /api/v1/certificates/upload", "POST /api/v1/certificates/csr", "POST /api/v1/certificates/csr/{id}/actions/complete",
		"GET /api/v1/certificates", "GET /api/v1/deployments/{id}", "GET /api/v1/jobs/{id}", "GET /api/v1/audit/export"} {
		assert.True(t, seenRoute(seen, route), "the scan saw %s", route)
	}
	dump := s.dump()
	scan("database", dump)
	for _, table := range []string{"jobs", "deployments", "deployment_steps", "audit_log", "notifications_outbox", "certificates", "managed_private_keys"} {
		assert.Contains(t, dump, table+":\n", "the dump has %s", table)
	}
	assert.Contains(t, dump, "certificate.deploy", "the dump has the deploy jobs")

	catalog, err := i18n.Load(locales.FS)
	require.NoError(t, err)
	sender := notify.Sender{Catalog: catalog}
	mail, err := s.db.Owner.Query(context.Background(), `SELECT to_address, template_key, locale, params FROM notifications_outbox`)
	require.NoError(t, err)
	templates := map[string]bool{}
	for mail.Next() {
		var to, tpl, locale string
		var params map[string]string
		require.NoError(t, mail.Scan(&to, &tpl, &locale, &params))
		templates[tpl] = true
		msg := sender.Render(to, tpl, locale, params)
		scan("email "+tpl, msg.Subject+"\n"+msg.Body)
	}
	require.NoError(t, mail.Err())
	mail.Close()
	assert.True(t, templates["deployment.failed"], "the scan saw the failed-deployment email")
	assert.True(t, templates["deployment.restored_unverified"], "the scan saw the rollback email")

	// S-04: a key is stored only as its envelope; the same key stored twice has two ciphertexts and
	// two data-encryption keys.
	byPublic := map[string][]storedKey{}
	for _, k := range keyRows {
		byPublic[k.public] = append(byPublic[k.public], k)
		assert.NotContains(t, string(k.env.Ciphertext), "PRIVATE", "no PEM marker in a ciphertext")
		for _, c := range []keyCanary{ecCanary, rsaCanary} {
			assert.False(t, bytes.Contains(k.env.Ciphertext, c.der8) || bytes.Contains(k.env.Ciphertext, c.derOld), "no canary DER in a ciphertext")
		}
	}
	twice := 0
	for _, same := range byPublic {
		if len(same) == 2 {
			twice++
			assert.NotEqual(t, same[0].env.Ciphertext, same[1].env.Ciphertext, "the same key sealed twice has two ciphertexts")
			assert.NotEqual(t, same[0].env.WrappedDEK, same[1].env.WrappedDEK, "and two data-encryption keys")
			assert.NotEqual(t, same[0].env.Nonce, same[1].env.Nonce)
			assert.Equal(t, same[0].der, same[1].der, "both open to the same key")
		}
	}
	assert.Equal(t, 2, twice, "EC and RSA were each uploaded twice")
}

// seenRoute reports whether a recorded exchange matches the route pattern (an {id} segment matches
// one path segment).
func seenRoute(seen map[string]bool, route string) bool {
	parts := strings.SplitN(route, " ", 2)
	for key := range seen {
		k := strings.SplitN(key, " ", 2)
		if k[0] != parts[0] {
			continue
		}
		a, b := strings.Split(k[1], "/"), strings.Split(parts[1], "/")
		if len(a) != len(b) {
			continue
		}
		match := true
		for i := range a {
			if b[i] != "{id}" && a[i] != b[i] {
				match = false
			}
		}
		if match {
			return true
		}
	}
	return false
}

// The scanner itself: every spelling it claims to look for is flagged when it is in a text, so a
// scanner that silently stops matching a form (a PEM variant, hex, an alphabet of base64, a
// password) fails here and not by finding nothing in the suite above.
func TestKeyScannerFlagsEverySpelling(t *testing.T) {
	ecKey, ok := pki.NewKey(pki.ECDSA256).(*ecdsa.PrivateKey)
	require.True(t, ok)
	rsaKey, ok := pki.NewKey(pki.RSA2048).(*rsa.PrivateKey)
	require.True(t, ok)
	var secs []secretValue
	for _, c := range []keyCanary{newKeyCanary("EC", ecKey), newKeyCanary("RSA", rsaKey)} {
		secs = append(secs, c.secrets()...)
		// Each kind of spelling the scanner must hold for this key.
		for _, der := range [][]byte{c.der8, c.derOld} {
			want := map[string]bool{hex.EncodeToString(der): false, base64.StdEncoding.EncodeToString(der): false,
				base64.RawStdEncoding.EncodeToString(der): false, base64.URLEncoding.EncodeToString(der): false,
				base64.RawURLEncoding.EncodeToString(der): false}
			for _, sec := range c.secrets() {
				for _, f := range sec.forms {
					if _, ok := want[f]; ok {
						want[f] = true
					}
				}
			}
			for f, found := range want {
				// Alphabets that spell a DER the same way (no "+", "/" or padding in it) collapse into one.
				assert.True(t, found || len(f) == 0, "%s: a spelling of the DER is not scanned for", c.name)
			}
		}
		pem8 := pemForms(c.pem8)
		assert.GreaterOrEqual(t, len(pem8), 6, "PEM as is, CRLF, escaped (two ways), body lines and the joined body")
		assert.Contains(t, pem8, string(c.pem8))
		assert.Contains(t, pem8, strings.ReplaceAll(string(c.pem8), "\n", `\n`))
		assert.Contains(t, pem8, strings.ReplaceAll(string(c.pem8), "\n", "\r\n"))
	}
	for _, pw := range []string{canary("pfx-password"), canary("pfx-wrong-password")} {
		sec := secretValue{name: "PFX password", value: pw}
		secs = append(secs, sec)
		assert.Contains(t, variants(pw), pw)
		assert.Contains(t, variants(pw), hex.EncodeToString([]byte(pw)))
		assert.Contains(t, variants(pw), base64.StdEncoding.EncodeToString([]byte(pw)))
		assert.Contains(t, variants(pw), base64.RawURLEncoding.EncodeToString([]byte(pw)))
	}
	for _, sec := range secs {
		forms := sec.forms
		if forms == nil {
			forms = variants(sec.value)
		}
		require.NotEmpty(t, forms, sec.name)
		for i, f := range forms {
			if f == "" {
				continue
			}
			sample := "log line: user=ada msg=" + f + " end"
			_, found := sec.leakedIn(sample)
			assert.True(t, found, "%s spelling #%d is not flagged", sec.name, i)
			assert.Contains(t, sample, f)
		}
		_, found := sec.leakedIn("a harmless text with no key, certificate or password in it")
		assert.False(t, found, sec.name)
	}
	// And the marker scan: a PEM header of any private key kind is flagged by the suite's markers.
	for _, header := range []string{"-----BEGIN PRIVATE KEY-----", "-----BEGIN RSA PRIVATE KEY-----", "-----BEGIN EC PRIVATE KEY-----",
		"-----BEGIN ENCRYPTED PRIVATE KEY-----"} {
		var hit bool
		for _, m := range tlsKeyMarkers {
			hit = hit || strings.Contains(header, m)
		}
		assert.True(t, hit, header)
	}
}
