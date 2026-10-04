package azurekv

import (
	"context"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/security/keyvault/azcertificates"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"software.sslmate.com/src/go-pkcs12"

	"alice/internal/platform/azureid"
	"alice/internal/providers"
	"alice/internal/providers/providertest"
	"alice/internal/testutil/fakekv"
	"alice/internal/testutil/pki"
)

// testPFX is a PFX of a fresh leaf in the profile Alice sends (LegacyDES, empty password).
func testPFX(t testing.TB, kt pki.KeyType) ([]byte, pki.Leaf) {
	t.Helper()
	ca := pki.NewCA("import-test", pki.ECDSA256, time.Now())
	leaf := ca.Issue(pki.Opts{CommonName: "imported.example.test", KeyType: kt}, time.Now())
	pfx, err := pkcs12.LegacyDES.Encode(leaf.Key, leaf.Cert, []*x509.Certificate{ca.Intermediate}, "")
	require.NoError(t, err)
	pfxThumbs.Store(string(pfx), azureid.ThumbprintOf(leaf.Cert.Raw))
	return pfx, leaf
}

// pfxThumbs remembers the leaf thumbprint of each test PFX: the caller states it (C1).
var pfxThumbs sync.Map

func importReq(name string, pfx []byte, kt string, size int) providers.ImportRequest {
	tp, ok := pfxThumbs.Load(string(pfx))
	if !ok {
		tp = strings.Repeat("ab", 20) // a PFX that was not built here: any valid thumbprint
	}
	return providers.ImportRequest{OperationID: uuid.New(), Name: name, PFX: providers.NewSecret(append([]byte(nil), pfx...)), KeyType: kt, KeySize: size,
		LeafThumbprint: tp.(string)}
}

type stepLog struct {
	mu    sync.Mutex
	steps []string
}

func (l *stepLog) Step(name string, status providers.StepStatus, params map[string]string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.steps = append(l.steps, name+":"+string(status))
	for k := range params {
		if k != "certificate_name" {
			panic("a step carries a param off the allowlist: " + k)
		}
	}
}

// doImport runs ImportCertificate and checks the contract on whatever came out.
func (w *world) doImport(t *testing.T, ctx context.Context, req providers.ImportRequest, steps providers.StepLogger) (providers.ImportResult, error) {
	t.Helper()
	var res providers.ImportResult
	err := w.run(func() error {
		var e error
		res, e = w.sess.ImportCertificate(ctx, req, steps)
		return e
	})
	providertest.CheckImportResult(t, res, err)
	return res, err
}

// posts counts the authenticated POSTs to the vault (the SDK's challenge probe carries no token).
func (w *world) posts() int {
	n := 0
	for _, r := range w.vaultRequests() {
		if r.Method == "POST" && r.HadAuth {
			n++
		}
	}
	return n
}

func TestImportCreatesAVersion(t *testing.T) {
	for _, tc := range []struct {
		name string
		kt   pki.KeyType
		typ  string
		size int
	}{{"ecdsa", pki.ECDSA256, "ecdsa", 256}, {"ecdsa 384", pki.ECDSA384, "ecdsa", 384}, {"rsa", pki.RSA2048, "rsa", 2048}} {
		t.Run(tc.name, func(t *testing.T) {
			w := newWorld(t, fakekv.Options{})
			pfx, leaf := testPFX(t, tc.kt)
			req := importReq("new-cert", pfx, tc.typ, tc.size)
			steps := &stepLog{}
			res, err := w.doImport(t, context.Background(), req, steps)
			require.NoError(t, err)
			assert.Equal(t, providers.ImportCreated, res.Outcome)
			assert.Equal(t, azureid.ThumbprintOf(leaf.Cert.Raw), res.Thumbprint, "the thumbprint of the leaf that was sent")
			assert.Equal(t, leaf.Cert.Raw, res.CER)
			assert.Equal(t, w.s.Versions("new-cert"), []string{res.Version})
			assert.Equal(t, 1, w.posts())
			assert.Equal(t, []string{"sign_in:started", "sign_in:ok", "import:started", "import:ok"}, steps.steps)
			assert.Equal(t, pfx, req.PFX.Bytes(), "the caller's PFX is not touched: the caller zeroes it")

			// What the vault now holds: exportable, PKCS #12, issuer Unknown (an imported certificate).
			var c azcertificates.Certificate
			require.NoError(t, w.run(func() (e error) { c, e = w.sess.api.GetCertificate(context.Background(), "new-cert", ""); return e }))
			require.NotNil(t, c.Policy)
			assert.True(t, *c.Policy.KeyProperties.Exportable)
			assert.Equal(t, "application/x-pkcs12", *c.Policy.SecretProperties.ContentType)
			assert.Equal(t, "Unknown", *c.Policy.IssuerParameters.Name)
		})
	}
}

// The request body: an empty password, the policy of an imported certificate, the PFX in base64.
func TestImportRequestBody(t *testing.T) {
	pfx, _ := testPFX(t, pki.RSA3072)
	var got azcertificates.ImportCertificateParameters
	var name string
	api := &stubAPI{
		get: func(string, string) (azcertificates.Certificate, error) {
			return azcertificates.Certificate{}, providers.NewError(codeCertificateNotFound, false, nil, nil)
		},
		imp: func(n string, p azcertificates.ImportCertificateParameters) (azcertificates.Certificate, error) {
			name, got = n, p
			return azcertificates.Certificate{}, providers.NewError(codeUnreachable, true, nil, nil)
		},
	}
	sess, _ := stubSession(api)
	res, err := sess.ImportCertificate(context.Background(), importReq("body-cert", pfx, "rsa", 3072), nil)
	require.Error(t, err)
	assert.Equal(t, providers.ImportUncertain, res.Outcome)
	assert.Equal(t, "body-cert", name)
	require.NotNil(t, got.Base64EncodedCertificate)
	assert.Equal(t, base64.StdEncoding.EncodeToString(pfx), *got.Base64EncodedCertificate)
	require.NotNil(t, got.Password)
	assert.Equal(t, "", *got.Password)
	p := got.CertificatePolicy
	require.NotNil(t, p)
	assert.True(t, *p.KeyProperties.Exportable)
	assert.False(t, *p.KeyProperties.ReuseKey)
	assert.Equal(t, azcertificates.KeyTypeRSA, *p.KeyProperties.KeyType)
	assert.EqualValues(t, 3072, *p.KeyProperties.KeySize)
	assert.Nil(t, p.KeyProperties.Curve)
	assert.Equal(t, "application/x-pkcs12", *p.SecretProperties.ContentType)
	assert.Equal(t, "Unknown", *p.IssuerParameters.Name)
	assert.Empty(t, p.LifetimeActions)

	ec, _ := testPFX(t, pki.ECDSA384)
	_, _ = sess.ImportCertificate(context.Background(), importReq("body-cert", ec, "ecdsa", 384), nil)
	assert.Equal(t, azcertificates.KeyTypeEC, *got.CertificatePolicy.KeyProperties.KeyType)
	assert.Equal(t, azcertificates.CurveNameP384, *got.CertificatePolicy.KeyProperties.Curve)
	assert.Nil(t, got.CertificatePolicy.KeyProperties.KeySize)
}

func withThumb(r providers.ImportRequest, tp string) providers.ImportRequest {
	r.LeafThumbprint = tp
	return r
}

func TestImportRefusesInvalidRequestsBeforeSending(t *testing.T) {
	w := newWorld(t, fakekv.Options{})
	pfx, _ := testPFX(t, pki.ECDSA256)
	rsa, _ := testPFX(t, pki.RSA2048)
	cases := map[string]providers.ImportRequest{
		"empty name":            importReq("", pfx, "ecdsa", 256),
		"name with a space":     importReq("a b", pfx, "ecdsa", 256),
		"name with a slash":     importReq("a/b", pfx, "ecdsa", 256),
		"name too long":         importReq(strings.Repeat("a", 128), pfx, "ecdsa", 256),
		"empty PFX":             importReq("c", nil, "ecdsa", 256),
		"no thumbprint":         withThumb(importReq("c", pfx, "ecdsa", 256), ""),
		"upper-case thumbprint": withThumb(importReq("c", pfx, "ecdsa", 256), strings.Repeat("AB", 20)),
		"short thumbprint":      withThumb(importReq("c", pfx, "ecdsa", 256), strings.Repeat("a", 39)),
		"PFX above the bound":   importReq("c", make([]byte, maxImportPFX+1), "ecdsa", 256),
		"unknown key type":      importReq("c", pfx, "dsa", 256),
		"ecdsa size 521":        importReq("c", pfx, "ecdsa", 521),
		"rsa size 1024":         importReq("c", rsa, "rsa", 1024),
		"rsa size above 16384":  importReq("c", rsa, "rsa", 16385),
		"rsa size beyond int32": importReq("c", rsa, "rsa", 1<<40),
		"negative size":         importReq("c", rsa, "rsa", -2048),
	}
	for name, req := range cases {
		t.Run(name, func(t *testing.T) {
			res, err := w.doImport(t, context.Background(), req, nil)
			pe := asProviderError(t, err)
			assert.Equal(t, providers.ImportRefused, res.Outcome)
			assert.Equal(t, providers.CodeKVImportInvalid, pe.Code)
			assert.False(t, pe.Retryable)
			assert.Empty(t, w.s.Requests(), "nothing was sent, not even a token request")
		})
	}
}

// S9: importing into a name that exists needs the Administrator's confirmation. The existence check
// is a read, so there is an inherent race with another writer: the vault has no conditional import.
func TestImportIntoAnExistingName(t *testing.T) {
	pfx, leaf := testPFX(t, pki.ECDSA256)
	t.Run("without confirmation: refused, nothing created, no import request", func(t *testing.T) {
		w := newWorld(t, fakekv.Options{})
		w.s.AddCertificate("web-cert", fakekv.CertOptions{CommonName: "www.example.test", Exportable: true})
		for _, name := range []string{"web-cert", "WEB-cert"} { // names are case-insensitive in Azure
			res, err := w.doImport(t, context.Background(), importReq(name, pfx, "ecdsa", 256), nil)
			pe := asProviderError(t, err)
			assert.Equal(t, providers.ImportRefused, res.Outcome)
			assert.Equal(t, providers.CodeKVImportNameExists, pe.Code, name)
		}
		assert.Equal(t, 0, w.posts())
		assert.Len(t, w.s.Versions("web-cert"), 1)
	})
	t.Run("with confirmation: a new version", func(t *testing.T) {
		w := newWorld(t, fakekv.Options{})
		w.s.AddCertificate("web-cert", fakekv.CertOptions{CommonName: "www.example.test", Exportable: true})
		req := importReq("web-cert", pfx, "ecdsa", 256)
		req.ReplaceExisting = true
		res, err := w.doImport(t, context.Background(), req, nil)
		require.NoError(t, err)
		assert.Equal(t, azureid.ThumbprintOf(leaf.Cert.Raw), res.Thumbprint)
		assert.Len(t, w.s.Versions("web-cert"), 2)
		gets := 0
		for _, r := range w.vaultRequests() {
			if r.Method == "GET" && r.HadAuth {
				gets++
			}
		}
		assert.Equal(t, 0, gets, "with confirmation the name is not read first")
	})
	t.Run("a soft-deleted name answers 409: a closed refusal", func(t *testing.T) {
		w := newWorld(t, fakekv.Options{})
		w.s.AddCertificate("web-cert", fakekv.CertOptions{CommonName: "www.example.test", Exportable: true})
		w.s.DeleteCertificate("web-cert")
		res, err := w.doImport(t, context.Background(), importReq("web-cert", pfx, "ecdsa", 256), nil)
		pe := asProviderError(t, err)
		assert.Equal(t, providers.ImportRefused, res.Outcome)
		assert.Equal(t, codeImportRejected, pe.Code)
		assert.Equal(t, "Conflict", pe.Params[paramAzureCode])
		assert.Equal(t, 1, w.posts())
	})
	t.Run("the existence check fails: refused with its reason, nothing sent that changes the vault", func(t *testing.T) {
		w := newWorld(t, fakekv.Options{})
		w.s.RevokeRole("certificates/get")
		res, err := w.doImport(t, context.Background(), importReq("new-cert", pfx, "ecdsa", 256), nil)
		pe := asProviderError(t, err)
		assert.Equal(t, providers.ImportRefused, res.Outcome)
		assert.Equal(t, codeForbidden, pe.Code)
		assert.Equal(t, providers.RoleKeyVaultCertificatesOfficer, pe.Params["role"], "the role of an import, not of a read")
		assert.Equal(t, 0, w.posts())

		w = newWorld(t, fakekv.Options{})
		w.s.FailAll("/certificates/new-cert", fakekv.Fault{Status: 503})
		res, err = w.doImport(t, context.Background(), importReq("new-cert", pfx, "ecdsa", 256), nil)
		assert.Equal(t, providers.ImportRefused, res.Outcome)
		assert.Equal(t, codeUnreachable, asProviderError(t, err).Code)
		assert.Equal(t, 0, w.posts())
	})
}

// Every situation of the import table: the outcome follows positive evidence only.
func TestImportOutcomes(t *testing.T) {
	pfx, leaf := testPFX(t, pki.ECDSA256)
	other := pki.NewCA("other", pki.ECDSA256, time.Now()).Issue(pki.Opts{CommonName: "other.example.test"}, time.Now())
	const path = "/certificates/new-cert/import"
	version := strings.Repeat("a", 32)
	bundle := func(cert *x509.Certificate, id string) string {
		b, _ := json.Marshal(map[string]any{"id": id, "x5t": base64.RawURLEncoding.EncodeToString(sha1sum(cert.Raw)),
			"cer": base64.StdEncoding.EncodeToString(cert.Raw), "attributes": map[string]any{"enabled": true}})
		return string(b)
	}
	vaultID := "https://" + testVaultHost + "/certificates/new-cert/" + version

	cases := []struct {
		name     string
		opts     fakekv.Options
		try      time.Duration // the per-try timeout of the session, when a test needs it short
		setup    func(w *world)
		outcome  string
		code     string
		azCode   string
		posts    int
		versions int // versions of new-cert in the fake afterwards
		cause    func(t *testing.T, err error)
	}{
		{name: "missing role", setup: func(w *world) { w.s.RevokeRole("certificates/import") },
			outcome: providers.ImportRefused, code: codeForbidden, posts: 1},
		{name: "400 BadParameter", setup: func(w *world) {
			w.s.FailNext(path, fakekv.Fault{Status: 400, Body: kvBody("BadParameter", "", "no")})
		}, outcome: providers.ImportRefused, code: codeImportRejected, azCode: "BadParameter", posts: 1},
		{name: "409 Conflict", setup: func(w *world) {
			w.s.FailNext(path, fakekv.Fault{Status: 409, Body: kvBody("Conflict", "", "no")})
		}, outcome: providers.ImportRefused, code: codeImportRejected, azCode: "Conflict", posts: 1},
		{name: "401 with a code", setup: func(w *world) {
			w.s.FailNext(path, fakekv.Fault{Status: 401, Body: kvBody("Unauthorized", "", "no")})
		}, outcome: providers.ImportRefused, code: codeAuthFailed, posts: 1},
		{name: "403 firewall", setup: func(w *world) {
			w.s.FailNext(path, fakekv.Fault{Status: 403, Body: kvBody("Forbidden", "ForbiddenByFirewall", "Client address: 203.0.113.7")})
		},
			outcome: providers.ImportRefused, code: codeFirewall, posts: 1},
		{name: "400 without a code in the body", setup: func(w *world) { w.s.FailNext(path, fakekv.Fault{Status: 400, Body: "no json"}) },
			outcome: providers.ImportUncertain, posts: 1},
		{name: "503", setup: func(w *world) { w.s.FailNext(path, fakekv.Fault{Status: 503}) }, outcome: providers.ImportUncertain, code: codeUnreachable, posts: 1},
		{name: "503 after the version was created", setup: func(w *world) { w.s.FailNext(path, fakekv.Fault{Status: 503, Apply: true}) },
			outcome: providers.ImportUncertain, code: codeUnreachable, posts: 1, versions: 1},
		{name: "500", setup: func(w *world) { w.s.FailNext(path, fakekv.Fault{Status: 500}) }, outcome: providers.ImportUncertain, posts: 1},
		{name: "408", setup: func(w *world) { w.s.FailNext(path, fakekv.Fault{Status: 408, Body: kvBody("RequestTimeout", "", "x")}) },
			outcome: providers.ImportUncertain, posts: 1},
		{name: "429 is not retried", setup: func(w *world) {
			w.s.FailNext(path, fakekv.Fault{Status: 429, RetryAfter: "1", Body: kvBody("Throttled", "", "x")})
		}, outcome: providers.ImportUncertain, code: codeThrottled, posts: 1},
		{name: "connection reset after the version was created", setup: func(w *world) { w.s.FailNext(path, fakekv.Fault{Reset: true, Apply: true}) },
			outcome: providers.ImportUncertain, posts: 1, versions: 1},
		{name: "connection reset before anything was done", setup: func(w *world) { w.s.FailNext(path, fakekv.Fault{Reset: true}) },
			outcome: providers.ImportUncertain, posts: 1},
		{name: "connection dropped in the answer", setup: func(w *world) { w.s.FailNext(path, fakekv.Fault{Drop: true, Apply: true}) },
			outcome: providers.ImportUncertain, posts: 1, versions: 1},
		{name: "timeout after the request was written", try: 150 * time.Millisecond, setup: func(w *world) {
			w.s.FailNext(path, fakekv.Fault{Delay: 3 * time.Second, Apply: true})
		}, outcome: providers.ImportUncertain, code: codeUnreachable, posts: 1, versions: 1,
			cause: func(t *testing.T, err error) { assert.ErrorIs(t, err, context.DeadlineExceeded) }},
		{name: "malformed 2xx", setup: func(w *world) { w.s.FailNext(path, fakekv.Fault{Body: "{not json", Apply: true}) },
			outcome: providers.ImportUncertain, posts: 1, versions: 1},
		{name: "truncated 2xx", setup: func(w *world) { w.s.FailNext(path, fakekv.Fault{Truncate: true, Apply: true}) },
			outcome: providers.ImportUncertain, posts: 1, versions: 1},
		{name: "2xx for another certificate", setup: func(w *world) { w.s.FailNext(path, fakekv.Fault{Body: bundle(other.Cert, vaultID)}) },
			outcome: providers.ImportUncertain, code: codeUnexpected, posts: 1, versions: 1},
		{name: "2xx without a usable version id", setup: func(w *world) {
			w.s.FailNext(path, fakekv.Fault{Body: bundle(leaf.Cert, "https://"+testVaultHost+"/certificates/new-cert")})
		}, outcome: providers.ImportUncertain, code: codeUnexpected, posts: 1, versions: 1},
		{name: "2xx for another name", setup: func(w *world) {
			w.s.FailNext(path, fakekv.Fault{Body: bundle(leaf.Cert, "https://"+testVaultHost+"/certificates/elsewhere/"+version)})
		}, outcome: providers.ImportUncertain, code: codeUnexpected, posts: 1, versions: 1},
		{name: "2xx whose thumbprint is not its certificate's", setup: func(w *world) {
			b, _ := json.Marshal(map[string]any{"id": vaultID, "x5t": base64.RawURLEncoding.EncodeToString(sha1sum(leaf.Cert.Raw)),
				"cer": base64.StdEncoding.EncodeToString(other.Cert.Raw)})
			w.s.FailNext(path, fakekv.Fault{Body: string(b)})
		}, outcome: providers.ImportUncertain, code: codeUnexpected, posts: 1, versions: 1},
		{name: "2xx without a certificate", setup: func(w *world) {
			b, _ := json.Marshal(map[string]any{"id": vaultID, "x5t": base64.RawURLEncoding.EncodeToString(sha1sum(leaf.Cert.Raw))})
			w.s.FailNext(path, fakekv.Fault{Body: string(b)})
		}, outcome: providers.ImportUncertain, code: codeUnexpected, posts: 1, versions: 1},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			var tune []func(*fakekv.Server, *Provider)
			if c.try > 0 {
				tune = append(tune, func(_ *fakekv.Server, p *Provider) { p.o.try = c.try })
			}
			w := newWorld(t, c.opts, tune...)
			if c.setup != nil {
				c.setup(w)
			}
			steps := &stepLog{}
			res, err := w.doImport(t, context.Background(), importReq("new-cert", pfx, "ecdsa", 256), steps)
			require.Error(t, err)
			pe := asProviderError(t, err)
			assert.Equal(t, c.outcome, res.Outcome)
			if c.code != "" {
				assert.Equal(t, c.code, pe.Code)
			}
			if c.azCode != "" {
				assert.Equal(t, c.azCode, pe.Params[paramAzureCode])
			}
			assert.Equal(t, c.posts, w.posts(), "the import is sent once, whatever the answer")
			assert.Len(t, w.s.Versions("new-cert"), c.versions)
			if c.cause != nil {
				c.cause(t, err)
			}
			assertCauseChainIsOurs(t, pe)
			assertNoLeak(t, pe, w.s)
			last := steps.steps[len(steps.steps)-1]
			assert.Equal(t, "import:failed", last)
		})
	}
}

func TestImportFailsBeforeTheSend(t *testing.T) {
	pfx, _ := testPFX(t, pki.ECDSA256)
	t.Run("sign-in refused: nothing reached the vault", func(t *testing.T) {
		s := fakekv.Start(t, fakekv.Options{})
		id := secretIdentity(s)
		id.ClientSecret = providers.NewSecret([]byte(fakekv.NewClientSecret()))
		clk := nearNow()
		w := &world{s: s, clk: clk, sess: openSession(t, testProvider(s), &idSource{id: id}, clk)}
		steps := &stepLog{}
		res, err := w.doImport(t, context.Background(), importReq("new-cert", pfx, "ecdsa", 256), steps)
		pe := asProviderError(t, err)
		assert.Equal(t, providers.ImportRefused, res.Outcome)
		assert.Equal(t, codeAuthFailed, pe.Code)
		assert.Empty(t, w.vaultRequests())
		assert.Equal(t, []string{"sign_in:started", "sign_in:failed"}, steps.steps)
		assertCauseChainIsOurs(t, pe)
	})
	t.Run("the token endpoint is down: refused, the cause is not the transport", func(t *testing.T) {
		w := newWorld(t, fakekv.Options{})
		w.s.FailAll("/"+w.s.TenantID()+"/oauth2/v2.0/token", fakekv.Fault{Status: 503})
		// a fresh session: the one of newWorld holds no token yet
		res, err := w.doImport(t, context.Background(), importReq("new-cert", pfx, "ecdsa", 256), nil)
		pe := asProviderError(t, err)
		assert.Equal(t, providers.ImportRefused, res.Outcome)
		assert.Equal(t, codeUnreachable, pe.Code)
		assert.True(t, pe.Retryable)
		assert.Empty(t, w.vaultRequests())
	})
	t.Run("a cancelled context: refused, never blocking the name, no context cause", func(t *testing.T) {
		w := newWorld(t, fakekv.Options{})
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		res, err := w.doImport(t, ctx, importReq("new-cert", pfx, "ecdsa", 256), nil)
		pe := asProviderError(t, err)
		assert.Equal(t, providers.ImportRefused, res.Outcome)
		assert.Equal(t, codeUnreachable, pe.Code)
		assert.NotErrorIs(t, err, context.Canceled)
		assert.Empty(t, w.s.Requests())
	})
	t.Run("cancelled while the request is with the vault: uncertain, with the context error", func(t *testing.T) {
		w := newWorld(t, fakekv.Options{})
		release := w.s.Hold("/certificates/new-cert/import")
		defer release()
		ctx, cancel := context.WithCancel(context.Background())
		go func() {
			for w.s.Held() == 0 {
				time.Sleep(time.Millisecond)
			}
			cancel()
		}()
		res, err := w.doImport(t, ctx, importReq("new-cert", pfx, "ecdsa", 256), nil)
		require.Error(t, err)
		assert.Equal(t, providers.ImportUncertain, res.Outcome)
		assert.ErrorIs(t, err, context.Canceled)
		assert.Equal(t, 1, w.posts())
	})
}

// C1: the caller states the leaf's thumbprint. A wrong statement can never produce "created": the
// vault carries the import out, the answer's certificate is not the stated one, the outcome is
// uncertain (and a poll that sees the real thumbprint settles it).
func TestImportWithAWrongLeafThumbprintIsNeverCreated(t *testing.T) {
	w := newWorld(t, fakekv.Options{})
	pfx, _ := testPFX(t, pki.ECDSA256)
	res, err := w.doImport(t, context.Background(), withThumb(importReq("new-cert", pfx, "ecdsa", 256), strings.Repeat("cd", 20)), nil)
	require.Error(t, err)
	assert.Equal(t, providers.ImportUncertain, res.Outcome)
	assert.Equal(t, codeUnexpected, asProviderError(t, err).Code)
	assert.Len(t, w.s.Versions("new-cert"), 1, "the vault did carry it out")
}
