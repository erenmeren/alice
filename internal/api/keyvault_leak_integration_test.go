//go:build integration

package api

import (
	"context"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	pkcs12 "software.sslmate.com/src/go-pkcs12"

	"alice/internal/testutil/fakekv"
	"alice/internal/testutil/pki"
)

// Secret-leak suite for Key Vault (spec §25.2, S-01..S-05) over the wire: the real provider talks to the fake Azure
// service, the real services store and deploy, and after every journey ALL of the places a secret could land in are
// scanned for the canaries: the captured DEBUG log, every HTTP answer the API gave (headers and bodies), every row of
// every table (text as is, bytea as hex and as base64 in both alphabets), which also covers job payloads and results,
// audit details and the outbox. A binary canary is looked for in every encoding AND by needles cut out of the encoding
// of the whole buffer at many offsets and at all three byte alignments (a base64 text of a part of a buffer is a
// different text from the same part of the base64 of the whole buffer unless the part starts at a multiple of three
// bytes: an earlier test used misaligned needles and could not see a leak that re-encoded a slice).

// encodings are the text spellings of a byte buffer a leak can have.
var kvEncodings = []func([]byte) string{
	func(b []byte) string { return hex.EncodeToString(b) },
	base64.StdEncoding.EncodeToString,
	base64.RawStdEncoding.EncodeToString,
	base64.URLEncoding.EncodeToString,
	base64.RawURLEncoding.EncodeToString,
}

// cuts returns text itself (when short) and pieces of it of width w at a fixed step, the last piece ending at the end.
func cuts(text string, w, step int) []string {
	if len(text) <= w {
		return []string{text}
	}
	out := []string{text}
	for off := 0; off+w < len(text); off += step {
		out = append(out, text[off:off+w])
	}
	return append(out, text[len(text)-w:])
}

// needlesOf are the spellings and the cut pieces of buf: for the byte alignments 0, 1 and 2 (the buffer without its
// first a bytes: what a leak that encodes a slice prints), in every encoding, whole and in pieces of 48 characters
// taken every max(48, len/40) characters (a leak is caught when it contains one whole piece: any window of at least
// step+48 characters does; the step grows with the text only to bound the number of needles).
// A needle that is also found in the public material (certificates the scenario holds in the clear: a private key's
// DER repeats the public key) is dropped, so it cannot make a legitimate row look like a leak.
func needlesOf(buf []byte, public []string) []string {
	seen := map[string]bool{}
	var out []string
	add := func(n string) {
		if len(n) < 24 || seen[n] {
			return
		}
		for _, p := range public {
			if strings.Contains(p, n) {
				return
			}
		}
		seen[n] = true
		out = append(out, n)
	}
	for a := 0; a < 3 && a < len(buf); a++ {
		for _, enc := range kvEncodings {
			text := enc(buf[a:])
			step := max(48, len(text)/40)
			for _, c := range cuts(text, 48, step) {
				add(c)
			}
			add(text)
		}
	}
	return out
}

// publicSpellings are the spellings of public byte strings (certificates) in every alignment, for needlesOf.
func publicSpellings(raws ...[]byte) []string {
	var out []string
	for _, raw := range raws {
		for a := 0; a < 3 && a < len(raw); a++ {
			for _, enc := range kvEncodings {
				out = append(out, enc(raw[a:]))
			}
		}
	}
	return out
}

// binaryCanary is a buffer that must never appear (the private part of a key, a PFX).
func binaryCanary(name string, buf []byte, public ...[]byte) secretValue {
	return secretValue{name: name, forms: needlesOf(buf, publicSpellings(public...))}
}

// textCanary is a text that must never appear: itself, every encoding of it and pieces of it.
func textCanary(name, text string) secretValue {
	forms := append([]string{}, variants(text)...)
	forms = append(forms, cuts(text, 24, 12)...)
	forms = append(forms, needlesOf([]byte(text), nil)...)
	return secretValue{name: name, forms: forms}
}

// keyCanaries are the canaries of a private key: its PEM, its DER (both forms) with pieces. public: the key's
// certificate (its DER shares bytes with the key's).
func keyCanaries(name string, key any, cert *x509.Certificate) []secretValue {
	kc := newKeyCanary(name, key)
	pub := [][]byte{}
	if cert != nil {
		pub = append(pub, cert.Raw)
	}
	// The key's PEM lines and DER repeat the public key: a form that is also part of the certificate is no needle.
	var out []secretValue
	for _, sec := range kc.secrets() {
		out = append(out, withoutPublic(sec, cert))
	}
	out = append(out, binaryCanary(name+" (PKCS#8 DER pieces)", kc.der8, pub...), binaryCanary(name+" (PKCS#1/SEC1 DER pieces)", kc.derOld, pub...))
	return out
}

// withoutPublic drops the forms that are found in the certificate's own spellings (DER in every encoding and
// alignment, PEM as is and unwrapped).
func withoutPublic(sec secretValue, cert *x509.Certificate) secretValue {
	if cert == nil {
		return sec
	}
	certPEM := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw}))
	corpus := append(publicSpellings(cert.Raw), certPEM, strings.ReplaceAll(certPEM, "\n", ""))
	var keep []string
	for _, f := range sec.forms {
		dup := false
		for _, p := range corpus {
			dup = dup || strings.Contains(p, f)
		}
		if !dup {
			keep = append(keep, f)
		}
	}
	return secretValue{name: sec.name, forms: keep}
}

// pfxCanaries are the canaries of a PFX (base64 text as the vault serves it): the text, the decoded container with
// pieces, and the private key inside it.
func pfxCanaries(t *testing.T, name string, value []byte, cert *x509.Certificate) []secretValue {
	t.Helper()
	raw, err := base64.StdEncoding.DecodeString(string(value))
	require.NoError(t, err)
	key, _, _, err := pkcs12.DecodeChain(raw, "")
	require.NoError(t, err)
	out := []secretValue{textCanary(name+" (served value)", string(value)), binaryCanary(name+" (container)", raw)}
	return append(out, keyCanaries(name+" key", key, cert)...)
}

// pemSecretCanaries are the canaries of a PEM secret: the whole text and the private key block in it.
func pemSecretCanaries(t *testing.T, name string, value []byte, cert *x509.Certificate) []secretValue {
	t.Helper()
	// The certificates in the value are public (Alice stores them); the canary is the private key block alone and
	// the whole value as one text (the certificates and the key together).
	out := []secretValue{{name: name + " (whole value)", forms: variants(string(value))}}
	rest := value
	for {
		var b *pem.Block
		b, rest = pem.Decode(rest)
		if b == nil {
			break
		}
		if strings.HasSuffix(b.Type, "PRIVATE KEY") {
			out = append(out, binaryCanary(name+" key (DER pieces)", b.Bytes, cert.Raw))
			out = append(out, withoutPublic(secretValue{name: name + " key (PEM)", forms: pemForms(pem.EncodeToMemory(b))}, cert))
		}
	}
	require.Len(t, out, 3, "the PEM secret holds a private key block")
	return out
}

// scanPlaces are every text the suite scans: the log, the API's answers, the tables (text as is, bytea as hex by
// to_jsonb, and as base64 in both alphabets).
func (s *stack) scanPlaces() map[string]string {
	s.t.Helper()
	places := map[string]string{"log": s.logs.String()}
	var b strings.Builder
	for _, e := range s.recorded() {
		fmt.Fprintf(&b, "%s %d\n", e.key(), e.status)
		for k, vs := range e.header {
			fmt.Fprintf(&b, "%s: %s\n", k, strings.Join(vs, ","))
		}
		b.Write(e.body)
		b.WriteByte('\n')
	}
	places["responses"] = b.String()
	places["tables"] = s.dump()
	std, url := s.byteaBase64()
	places["bytea base64"], places["bytea base64url"] = std, url
	return places
}

// byteaBase64 renders every bytea value of every table as base64 (standard and URL alphabets).
func (s *stack) byteaBase64() (std, url string) {
	s.t.Helper()
	ctx := context.Background()
	rows, err := s.db.Owner.Query(ctx, `SELECT table_name::text, column_name::text FROM information_schema.columns
		WHERE table_schema = 'public' AND data_type = 'bytea' ORDER BY 1, 2`)
	require.NoError(s.t, err)
	type col struct{ table, column string }
	var cols []col
	for rows.Next() {
		var c col
		require.NoError(s.t, rows.Scan(&c.table, &c.column))
		cols = append(cols, c)
	}
	require.NoError(s.t, rows.Err())
	var sb strings.Builder
	for _, c := range cols {
		var text string
		q := "SELECT coalesce(string_agg(translate(encode(" + pgx.Identifier{c.column}.Sanitize() + ", 'base64'), E'\\n', ''), E'\\n'), '') FROM " + pgx.Identifier{c.table}.Sanitize()
		require.NoError(s.t, s.db.Owner.QueryRow(ctx, q).Scan(&text))
		sb.WriteString(text + "\n")
	}
	std = sb.String()
	return std, strings.NewReplacer("+", "-", "/", "_").Replace(std)
}

// leaks lists "canary in place" for every canary found in any place.
func (s *stack) leaks(secs []secretValue) []string {
	s.t.Helper()
	var out []string
	for place, text := range s.scanPlaces() {
		for _, sec := range secs {
			if _, found := sec.leakedIn(text); found {
				out = append(out, sec.name+" in "+place)
			}
		}
	}
	return out
}

// scanAll fails for every canary found in any place (it never prints the places: they can be megabytes long).
func (s *stack) scanAll(where string, secs []secretValue) {
	s.t.Helper()
	for _, l := range s.leaks(secs) {
		s.t.Errorf("%s: %s", where, l)
	}
}

// readEverything makes the API answer for every record the journeys produced, so the scan sees those answers.
func (k *kvnj) readEverything(vault string) {
	k.t.Helper()
	for _, p := range []string{"/api/v1/targets", "/api/v1/targets/" + vault, "/api/v1/targets/" + vault + "/kv/certificates?missing=include",
		"/api/v1/targets/" + vault + "/kv/keys", "/api/v1/targets/" + vault + "/kv/secrets", "/api/v1/targets/" + vault + "/kv/imports",
		"/api/v1/certificates", "/api/v1/deployments", "/api/v1/jobs", "/api/v1/audit?limit=200", "/api/v1/certificate-locations"} {
		rec := k.admin.do(http.MethodGet, p, nil)
		require.Less(k.t, rec.Code, 500, "%s: %s", p, rec.Body.String())
	}
	rec := k.admin.do(http.MethodGet, "/api/v1/jobs", nil)
	if rec.Code == http.StatusOK {
		for _, j := range decodeBody[struct {
			Items []map[string]any `json:"items"`
		}](k.t, rec).Items {
			k.admin.do(http.MethodGet, "/api/v1/jobs/"+j["id"].(string), nil)
		}
	}
	rec = k.admin.do(http.MethodGet, "/api/v1/deployments", nil)
	if rec.Code == http.StatusOK {
		for _, d := range decodeBody[struct {
			Items []map[string]any `json:"items"`
		}](k.t, rec).Items {
			k.admin.do(http.MethodGet, "/api/v1/deployments/"+d["id"].(string), nil)
		}
	}
}

// leakCase is the growing state of the suite: the canaries known so far.
type leakCase struct {
	k      *kvnj
	vault  string
	secs   []secretValue
	tokens map[string]bool
	// sentPFX is the PFX the import sent (for the scanner's non-vacuity check).
	sentPFX []byte
}

func (c *leakCase) add(secs ...secretValue) { c.secs = append(c.secs, secs...) }

// token adds every access token the harness has seen the fake issue (it samples the fake's newest token after every
// session open and every job: the fake keeps no list) as a canary, with the signature segment as a needle of its own.
func (c *leakCase) token() {
	for _, tok := range c.k.issuedTokens() {
		if c.tokens[tok] {
			continue
		}
		c.tokens[tok] = true
		c.add(textCanary("access token", tok))
		if parts := strings.Split(tok, "."); len(parts) == 3 {
			c.add(secretValue{name: "access token signature", forms: []string{parts[2]}})
			c.add(secretValue{name: "access token claims", forms: []string{parts[1]}})
		}
	}
}

// after reads everything and scans everything.
func (c *leakCase) after(journey string) {
	c.k.t.Helper()
	c.token()
	c.k.readEverything(c.vault)
	c.k.scanAll(journey, c.secs)
}

// TestSecretLeakSuiteWithAzureCanaries runs the journeys with every canary in place and scans after each:
//
//	canary                     where it enters                                            journeys
//	client secret              add vault, replace credentials (request bodies)           J1 J3 J4
//	service principal key      add/replace with certificate sign-in (PEM in the request)  J3
//	access tokens              issued by the fake, held by the SDK                        all
//	vault secret as PFX        deployment's secret read                                   J2 J3 J4
//	vault secret as PEM        deployment's secret read                                   J2
//	canary in a 403 body       secret read and import answered 403 with a canary         J4 J5
//	canary in a malformed body certificate listing answered with garbage and a canary    J4
//	imported PFX / key         import of an uploaded certificate                          J5
func TestSecretLeakSuiteWithAzureCanaries(t *testing.T) {
	// The service principal's certificate: an RSA key and certificate registered at the fake.
	spCA := pki.NewCA("SP CA", pki.ECDSA256, time.Now())
	sp := spCA.Issue(pki.Opts{CommonName: "alice-sp", KeyType: pki.RSA2048}, time.Now())
	k := newKVNJ(t, fakekv.Options{ClientCert: sp.Cert}, wwwSite())
	b, _, bLocs := k.addNginx("web-02", apiSite())
	c := &leakCase{k: k, tokens: map[string]bool{}}

	secret := k.kv.Secret()
	c.add(textCanary("client secret", secret))
	c.add(keyCanaries("service principal key", sp.Key, sp.Cert)...)
	k.kv.AddCertificate("web-cert", fakekv.CertOptions{CommonName: wwwName, SANs: []string{wwwName, apiName}, Exportable: true})
	k.kv.AddCertificate("pem-cert", fakekv.CertOptions{CommonName: apiName, SANs: []string{apiName}, Exportable: true, ContentType: "application/x-pem-file"})

	// J1: add the vault with the client secret, poll, bind (web-cert on web-01 as PFX, pem-cert on web-02 as PEM).
	vault := k.addVault("prod-vault")
	c.vault = vault
	c.after("J1 add vault")
	webID, pemID := k.kvCertByName(k.admin, vault, "web-cert")["id"].(string), k.kvCertByName(k.admin, vault, "pem-cert")["id"].(string)
	b1, b2 := k.bind(k.op, webID, k.locs[wwwCert]), k.bind(k.op, pemID, bLocs[apiCert])
	requireStatus(t, k.autoDeploy(b1["id"].(string), 1, true), http.StatusOK)
	requireStatus(t, k.autoDeploy(b2["id"].(string), 1, true), http.StatusOK)
	k.clock.Advance(2 * time.Minute)
	managedKeys := k.count("managed_private_keys")

	// J2: both certificates renew; the deployments read a PFX and a PEM secret.
	webV := k.kv.Renew("web-cert")
	pemV := k.kv.Renew("pem-cert")
	c.add(pfxCanaries(t, "vault PFX secret", k.kv.SecretValue("web-cert", webV), k.kv.Leaf("web-cert", webV))...)
	c.add(pemSecretCanaries(t, "vault PEM secret", k.kv.SecretValue("pem-cert", pemV), k.kv.Leaf("pem-cert", pemV))...)
	k.clock.Advance(time.Minute)
	k.checkNow(vault)
	require.NoError(t, k.plan())
	for _, loc := range []string{k.locs[wwwCert], bLocs[apiCert]} {
		deps := k.kvDeployments(k.op, loc)
		require.Len(t, deps, 1)
		require.Equal(t, "succeeded", k.settleKV(k.op, deps[0].ID).Status)
	}
	assert.Equal(t, pki.Fingerprint(k.kv.Leaf("web-cert", webV)), k.f.served(wwwName))
	assert.Equal(t, pki.Fingerprint(k.kv.Leaf("pem-cert", pemV)), b.served(apiName))
	assert.Equal(t, 2, strings.Count(string(k.f.emu.NginxFile(wwwCert)), "BEGIN CERTIFICATE"), "PFX deployment: leaf and intermediate installed")
	assert.Equal(t, 2, strings.Count(string(b.emu.NginxFile(apiCert)), "BEGIN CERTIFICATE"), "PEM deployment: leaf and intermediate installed")
	assert.Equal(t, managedKeys, k.count("managed_private_keys"), "a Key Vault deployment seals no private key of its own")
	assert.Equal(t, 2, secretReads(k.kv))
	c.after("J2 deployments of a PFX and a PEM secret")

	// J3: certificate sign-in through "replace credentials", then the same secret again (S-04).
	k.stepUp(k.admin, k.adminAcct)
	version := k.targetVersion(vault)
	rec := k.admin.do(http.MethodPut, "/api/v1/targets/"+vault+"/vault-credentials", map[string]any{
		"auth": "certificate", "tenant_id": k.kv.TenantID(), "client_id": k.kv.ClientID(),
		"certificate_pem": string(sp.FullchainPEM), "private_key_pem": string(sp.KeyPEM)}, ifMatchOf(itoa(version)))
	requireStatus(t, rec, http.StatusOK)
	k.runKV()
	require.Equal(t, "ok", k.vaultState(k.admin, vault).Status)
	webV2 := k.kv.Renew("web-cert")
	c.add(pfxCanaries(t, "vault PFX secret 2", k.kv.SecretValue("web-cert", webV2), k.kv.Leaf("web-cert", webV2))...)
	k.clock.Advance(time.Minute)
	k.checkNow(vault)
	require.NoError(t, k.plan())
	deps := k.kvDeployments(k.op, k.locs[wwwCert])
	require.Len(t, deps, 2)
	require.Equal(t, "succeeded", k.settleKV(k.op, deps[0].ID).Status, "deployed with the certificate sign-in")
	c.after("J3 certificate sign-in")

	for i := 0; i < 2; i++ { // the same client secret twice: two rows, two ciphertexts
		k.stepUp(k.admin, k.adminAcct)
		rec = k.admin.do(http.MethodPut, "/api/v1/targets/"+vault+"/vault-credentials", map[string]any{
			"auth": "client_secret", "tenant_id": k.kv.TenantID(), "client_id": k.kv.ClientID(), "client_secret": secret}, ifMatchOf(itoa(k.targetVersion(vault))))
		requireStatus(t, rec, http.StatusOK)
		k.runKV()
	}
	assert.Equal(t, "ok", k.vaultState(k.admin, vault).Status)
	rows, err := k.db.Owner.Query(context.Background(), `SELECT encode(ciphertext, 'hex'), encode(nonce, 'hex'), encode(wrapped_dek, 'hex') FROM credentials
WHERE target_id = $1 AND kind = 'azure_sp_secret'`, vault)
	require.NoError(t, err)
	type env struct{ ct, nonce, dek string }
	var seen []env
	for rows.Next() {
		var e env
		require.NoError(t, rows.Scan(&e.ct, &e.nonce, &e.dek))
		seen = append(seen, e)
	}
	require.NoError(t, rows.Err())
	require.GreaterOrEqual(t, len(seen), 2, "every replacement keeps its own sealed row")
	for i := range seen {
		for j := i + 1; j < len(seen); j++ {
			assert.NotEqual(t, seen[i].ct, seen[j].ct, "S-04: the same secret seals to different ciphertexts")
			assert.NotEqual(t, seen[i].nonce, seen[j].nonce)
			assert.NotEqual(t, seen[i].dek, seen[j].dek)
		}
	}
	c.after("J3 replace credentials")

	// J4: failures with canaries in the answers: a 403 body echoing a canary on the secret read, a malformed listing
	// holding a canary, the F-40, F-49, F-51 and F-52 paths.
	echo := textCanary("canary in a 403 body", canaryText("403"))
	garbage := textCanary("canary in a malformed answer", canaryText("garbage"))
	c.add(echo, garbage)
	webV3 := k.kv.Renew("web-cert")
	k.clock.Advance(time.Minute)
	k.checkNow(vault)
	k.kv.FailNext("/secrets/web-cert", fakekv.Fault{Status: http.StatusForbidden,
		Body: `{"error":{"code":"Forbidden","innererror":{"code":"ForbiddenByRbac"},"message":"` + echo.forms[0] + `"}}`})
	require.NoError(t, k.plan())
	for _, d := range k.kvDeployments(k.op, k.locs[wwwCert]) {
		if d.KVVersion == webV3 {
			got := k.settleKV(k.op, d.ID)
			assert.Equal(t, "failed", got.Status)
			assert.Equal(t, "ALC-AKV-0003", got.errorCode(), "the 403 is the role problem; its text is nowhere")
		}
	}
	k.kv.FailNext("/certificates", fakekv.Fault{Body: `{"value":[{"id":"` + garbage.forms[0] + `","attributes":{`})
	k.clock.Advance(time.Minute)
	k.checkNow(vault)
	c.after("J4 canaries in a 403 body and in a malformed answer")

	k.kv.RevokeRole("certificates/list") // F-40
	k.checkNow(vault)
	k.kv.GrantRole("certificates/list")
	k.kv.Firewall("203.0.113.7") // F-51
	k.checkNow(vault)
	k.kv.Firewall("")
	k.kv.FailNext("/certificates", fakekv.Fault{Truncate: true}) // F-52
	k.checkNow(vault)
	c.after("J4 F-40, F-51, F-52")

	// F-49 needs the client secret sign-in: switch back and expire it.
	k.kv.ExpireSecret()
	k.checkNow(vault)
	for i := 0; i < 3; i++ {
		k.pass(31 * time.Minute)
		require.NoError(t, k.schedule())
	}
	k.kv.RestoreSecret()
	c.after("J4 F-49")

	// J5: import an uploaded certificate (its key and the PFX Alice builds are canaries), and an import answered 403
	// with a canary in the body.
	up := k.issue()
	c.add(keyCanaries("uploaded key", up.Key, up.Cert)...)
	certID := k.uploadCertificate(k.op, certBody(up, "To import"))
	im := k.requestImport(certID, vault, "imported-cert", false)
	require.Equal(t, "succeeded", im.State, "%+v", im)
	echo2 := textCanary("canary in an import's 403 body", canaryText("import-403"))
	c.add(echo2)
	k.kv.FailNext("/certificates/leaky-cert/import", fakekv.Fault{Status: http.StatusForbidden,
		Body: `{"error":{"code":"Forbidden","innererror":{"code":"ForbiddenByRbac"},"message":"` + echo2.forms[0] + `"}}`})
	imF := k.requestImport(certID, vault, "leaky-cert", false)
	assert.Equal(t, "failed", imF.State)
	assert.Equal(t, "ALC-AKV-0003", imF.errCode())

	// The PFXs Alice SENT (captured from the session before the provider call; the fake re-encodes its own copy with
	// fresh salts, which would be a different byte string): as buffers in every encoding, cut at several offsets, and as
	// the base64 text a careless log line would print.
	sent := k.sentPFXs()
	require.Len(t, sent, 2, "two imports were sent")
	for i, buf := range sent {
		require.NotEmpty(t, buf)
		c.add(binaryCanary(fmt.Sprintf("sent PFX %d (buffer)", i), buf))
		c.add(textCanary(fmt.Sprintf("sent PFX %d (base64 text)", i), base64.StdEncoding.EncodeToString(buf)))
		c.add(textCanary(fmt.Sprintf("sent PFX %d (base64url text)", i), base64.URLEncoding.EncodeToString(buf)))
	}
	c.sentPFX = sent[0]
	c.after("J5 import")

	// Credentials rows hold ciphertext only: no PEM marker, no canary (the scan above), and no PEM marker anywhere in
	// the tables outside the certificates' own public PEM.
	var marker int
	require.NoError(t, k.db.Owner.QueryRow(context.Background(),
		`SELECT count(*) FROM credentials WHERE encode(ciphertext, 'escape') LIKE '%PRIVATE KEY%'`).Scan(&marker))
	assert.Zero(t, marker)
	// The scan is not vacuous: every canary has needles, and the fake really did hold the secrets it was asked for.
	for _, sec := range c.secs {
		assert.NotEmpty(t, sec.forms, sec.name)
	}
	assert.GreaterOrEqual(t, secretReads(k.kv), 3)
}

// canaryText is a recognizable text unique per run, made of characters that survive JSON.
func canaryText(label string) string { return canary(label) }

// targetVersion is a target's ETag version.
func (k *kvnj) targetVersion(id string) int {
	k.t.Helper()
	return int(k.target(k.admin, id)["version"].(float64))
}

// TestKVLeakScannerFlagsEveryForm proves the scanner can see what it claims to see: every needle of a canary is
// flagged when it sits in the log, in an API answer, in a table dump and in a base64 rendering of a bytea; a leak that
// re-encodes a SLICE of the buffer (misaligned base64) or prints a window of the encoding of the whole buffer is
// flagged; and an unrelated text is not.
func TestKVLeakScannerFlagsEveryForm(t *testing.T) {
	buf := make([]byte, 700)
	for i := range buf {
		buf[i] = byte((i*131 + 7) % 251)
	}
	sec := binaryCanary("buffer", buf)
	require.NotEmpty(t, sec.forms)
	places := map[string]func(n string) string{
		"log":      func(n string) string { return "time=x level=DEBUG msg=sent body=" + n + " end" },
		"response": func(n string) string { return `{"error":{"message":"` + n + `"}}` },
		"table":    func(n string) string { return `audit_log:` + "\n" + `{"details":{"x":"` + n + `"}}` },
		"bytea":    func(n string) string { return "AAAA\n" + n + "\nBBBB" },
	}
	for _, n := range sec.forms {
		for place, render := range places {
			_, found := sec.leakedIn(render(n))
			require.True(t, found, "a needle is not flagged in %s", place)
		}
	}
	// A leak of a slice of the buffer, re-encoded from its own start (alignments 1 and 2), is flagged in every encoding.
	for a := 1; a <= 2; a++ {
		for i, enc := range kvEncodings {
			_, found := sec.leakedIn("leak: " + enc(buf[a+30:a+130]) + " .")
			assert.True(t, found, "slice at %d, encoding #%d is flagged", a, i)
		}
	}
	// A window of the encoding of the whole buffer, at an offset that is not a multiple of four, is flagged.
	whole := base64.StdEncoding.EncodeToString(buf)
	for _, off := range []int{1, 7, 50, 101, 333} {
		_, found := sec.leakedIn("window: " + whole[off:off+160])
		assert.True(t, found, "window at %d", off)
	}
	_, found := sec.leakedIn("a harmless text with certificates, tokens and nothing else in it")
	assert.False(t, found)

	// The text canary and the key canaries: every form is flagged, the public part of a key is not a needle.
	txt := textCanary("client secret", fakekv.NewClientSecret())
	for _, n := range txt.forms {
		_, found := txt.leakedIn("log " + n)
		require.True(t, found)
	}
	leaf := pki.NewCA("t", pki.ECDSA256, time.Now()).Issue(pki.Opts{CommonName: "x"}, time.Now())
	for _, ks := range keyCanaries("key", leaf.Key, leaf.Cert) {
		require.NotEmpty(t, ks.forms, ks.name)
		for _, n := range ks.forms {
			_, found := ks.leakedIn("log " + n)
			require.True(t, found, ks.name)
		}
	}
	for _, pubPiece := range publicSpellings(leaf.Cert.Raw) {
		for _, ks := range keyCanaries("key", leaf.Key, leaf.Cert) {
			_, found := ks.leakedIn(pubPiece)
			assert.False(t, found, "%s: the certificate's own bytes are not a leak", ks.name)
		}
	}
	// The scan of a real stack finds a canary planted in each place it claims to scan: the log, an API answer, a text
	// column and a bytea column (as hex through to_jsonb, and as base64 in both alphabets).
	k := newKVNJ(t, fakekv.Options{})
	k.addVault("v")
	require.Empty(t, k.leaks([]secretValue{sec}), "nothing planted yet")
	ctx := context.Background()
	plant := func(where string, do func(buf []byte), wants ...string) {
		for _, w := range wants {
			fresh := make([]byte, 700)
			_, err := rand.Read(fresh)
			require.NoError(t, err)
			fs := binaryCanary("planted", fresh)
			require.Empty(t, k.leaks([]secretValue{fs}))
			do(fresh)
			got := k.leaks([]secretValue{fs})
			require.NotEmpty(t, got, "%s (%s): the scan did not see a planted canary", where, w)
			assert.Contains(t, strings.Join(got, "; "), "in "+where, "%s (%s)", where, w)
		}
	}
	plant("log", func(buf []byte) {
		_, _ = k.logs.Write([]byte("planted " + base64.StdEncoding.EncodeToString(buf) + "\n"))
	}, "base64")
	plant("responses", func(buf []byte) {
		rec := httptest.NewRecorder()
		_, _ = rec.WriteString(hex.EncodeToString(buf))
		k.record(http.MethodGet, "/planted", rec)
	}, "hex")
	plant("tables", func(buf []byte) {
		_, err := k.db.Owner.Exec(ctx, "UPDATE users SET display_name = $1", base64.RawURLEncoding.EncodeToString(buf[1:]))
		require.NoError(t, err)
	}, "text column, misaligned base64url")
	plant("bytea base64", func(buf []byte) {
		_, err := k.db.Owner.Exec(ctx, "UPDATE credentials SET public_info = public_info, ciphertext = $1", buf)
		require.NoError(t, err)
	}, "bytea column")
}
