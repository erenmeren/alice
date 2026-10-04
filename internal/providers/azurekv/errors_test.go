package azurekv

import (
	"bytes"
	"context"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/to"
	"github.com/Azure/azure-sdk-for-go/sdk/azidentity"
	"github.com/Azure/azure-sdk-for-go/sdk/security/keyvault/azcertificates"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"alice/internal/platform/azureid"
	"alice/internal/platform/clock"
	"alice/internal/platform/netaddr"
	"alice/internal/providers"
	"alice/internal/testutil/fakekv"
)

const canary = "CANARY-7f3a91c2-do-not-leak"

var allowedParams = map[string]bool{
	paramAADSTS: true, paramRole: true, paramModel: true, paramClientIP: true, paramReason: true,
	paramRequestID: true, paramAzureCode: true,
}

var closedCodes = map[string]bool{
	codeAuthFailed: true, codeCredentialsExpired: true, codeForbidden: true, codeFirewall: true, codeVaultNotFound: true,
	codeUnreachable: true, codeThrottled: true, codeUnexpected: true, codeClockSkew: true, codeManagedIdentityGone: true,
	codeAddressNotAllowed: true, codeTLSUntrusted: true, codeVersionDisabled: true, codeCertificateNotFound: true,
}

// kvBody is a Key Vault error body with the canary in its message.
func kvBody(code, inner, msg string) string {
	b := map[string]any{"code": code, "message": msg + " " + canary}
	if inner != "" {
		b["innererror"] = map[string]any{"code": inner}
	}
	out, _ := json.Marshal(map[string]any{"error": b})
	return string(out)
}

// entraBody is the Entra error body of one AADSTS code with the canary in its description.
func entraBody(code int, oauth string) string {
	out, _ := json.Marshal(map[string]any{"error": oauth, "error_codes": []int{code},
		"error_description": fmt.Sprintf("AADSTS%d: %s\r\nTrace ID: %s", code, canary, uuid.NewString()), "trace_id": canary})
	return string(out)
}

// drive runs fn while advancing the fake clock, so waits end without real time passing.
func drive(clk *clock.Fake, fn func() error) error {
	done := make(chan error, 1)
	go func() { done <- fn() }()
	for {
		select {
		case err := <-done:
			return err
		case <-time.After(2 * time.Millisecond):
			clk.Advance(6 * time.Second)
		}
	}
}

type row struct {
	name  string
	opts  fakekv.Options
	op    string // token | list | get | secret | import | keys
	setup func(t *testing.T, s *fakekv.Server, p *Provider)
	id    func(s *fakekv.Server) providers.AzureIdentity

	code      string
	retryable bool
	params    map[string]string // exact, except azure_request_id and azure_code, checked by shape
	cause     error             // errors.Is, when set
}

func vaultFault(f fakekv.Fault, path string) func(*testing.T, *fakekv.Server, *Provider) {
	return func(_ *testing.T, s *fakekv.Server, _ *Provider) { s.FailAll(path, f) }
}

func tokenFault(f fakekv.Fault) func(*testing.T, *fakekv.Server, *Provider) {
	return func(_ *testing.T, s *fakekv.Server, _ *Provider) { s.FailAll("/"+s.TenantID()+"/oauth2/v2.0/token", f) }
}

func dialFailing(hostPrefix string, err error) func(*testing.T, *fakekv.Server, *Provider) {
	return func(_ *testing.T, s *fakekv.Server, p *Provider) {
		p.o.dial = func(ctx context.Context, network, addr string) (net.Conn, error) {
			if strings.HasPrefix(addr, hostPrefix) {
				return nil, err
			}
			return (&net.Dialer{}).DialContext(ctx, network, s.DialAddr(addr))
		}
	}
}

func TestMapErrorTable(t *testing.T) {
	forbidden := func(inner string) fakekv.Fault {
		return fakekv.Fault{Status: 403, Body: kvBody("Forbidden", inner, "Caller is not authorized to perform action")}
	}
	nxdomain := &net.DNSError{Err: "no such host", Name: testVaultHost, IsNotFound: true}
	refused := &net.OpError{Op: "dial", Net: "tcp", Err: errors.New("connection refused")}
	miID := func(*fakekv.Server) providers.AzureIdentity {
		return providers.AzureIdentity{Auth: providers.AzureAuthManagedIdentity, ClientID: uuid.NewString()}
	}
	rows := []row{
		{name: "token 401 wrong secret", op: "token", setup: tokenFault(fakekv.Fault{Status: 401, Body: entraBody(7000215, "invalid_client")}),
			code: codeAuthFailed, params: map[string]string{"aadsts": "7000215"}},
		{name: "token 400 unknown application", op: "token", setup: tokenFault(fakekv.Fault{Status: 400, Body: entraBody(700016, "unauthorized_client")}),
			code: codeAuthFailed, params: map[string]string{"aadsts": "700016"}},
		{name: "token 400 unknown tenant", op: "token", setup: tokenFault(fakekv.Fault{Status: 400, Body: entraBody(90002, "invalid_request")}),
			code: codeAuthFailed, params: map[string]string{"aadsts": "90002"}},
		{name: "token 401 expired secret", op: "token", setup: tokenFault(fakekv.Fault{Status: 401, Body: entraBody(7000222, "invalid_client")}),
			code: codeCredentialsExpired, params: map[string]string{"aadsts": "7000222"}},
		{name: "token 401 unregistered certificate", op: "token", setup: tokenFault(fakekv.Fault{Status: 401, Body: entraBody(700027, "invalid_client")}),
			code: codeAuthFailed, params: map[string]string{"aadsts": "700027"}},
		{name: "token 400 clock", op: "token", setup: tokenFault(fakekv.Fault{Status: 400, Body: entraBody(700024, "invalid_client")}),
			code: codeClockSkew, params: map[string]string{"aadsts": "700024"}},
		{name: "token 400 without error codes", op: "token", setup: tokenFault(fakekv.Fault{Status: 400, Body: `{"error":"x","error_description":"` + canary + `"}`}),
			code: codeAuthFailed},
		{name: "token answer with an absurd code", op: "token", setup: tokenFault(fakekv.Fault{Status: 400, Body: entraBody(999999999, "x")}),
			code: codeAuthFailed},
		{name: "token 503", op: "token", setup: tokenFault(fakekv.Fault{Status: 503, Body: entraBody(90033, "temporarily_unavailable")}),
			code: codeUnreachable, retryable: true},
		{name: "token 429", op: "token", setup: tokenFault(fakekv.Fault{Status: 429, Body: entraBody(50196, "temporarily_unavailable")}),
			code: codeThrottled, retryable: true},
		{name: "IMDS identity not found", op: "token", opts: fakekv.Options{ManagedIdentity: true, MIClientID: uuid.NewString()},
			id: miID, code: codeManagedIdentityGone},
		{name: "no IMDS", op: "token", opts: fakekv.Options{ManagedIdentity: true}, id: miID,
			setup: dialFailing("169.254.169.254", refused), code: codeManagedIdentityGone},
		{name: "IMDS 429", op: "token", opts: fakekv.Options{ManagedIdentity: true}, id: miID,
			setup: vaultFault(fakekv.Fault{Status: 429}, "/metadata/"), code: codeThrottled, retryable: true},
		{name: "vault 401 after a token", op: "get", setup: vaultFault(fakekv.Fault{Status: 401, Body: kvBody("Unauthorized", "", "AKV10000")}, "/certificates"),
			code: codeAuthFailed},
		{name: "403 ForbiddenByRbac list", op: "list", setup: vaultFault(forbidden("ForbiddenByRbac"), "/certificates"),
			code: codeForbidden, params: map[string]string{"role": "Key Vault Reader", "model": "rbac"}},
		{name: "403 ForbiddenByPolicy secret", op: "secret", setup: vaultFault(forbidden("ForbiddenByPolicy"), "/secrets/"),
			code: codeForbidden, params: map[string]string{"role": "Key Vault Secrets User", "model": "access_policy"}},
		{name: "403 AccessDenied secret", op: "secret", setup: vaultFault(forbidden("AccessDenied"), "/secrets/"),
			code: codeForbidden, params: map[string]string{"role": "Key Vault Secrets User", "model": "access_policy"}},
		{name: "403 without inner code import", op: "import", setup: vaultFault(forbidden(""), "/certificates/new-cert/import"),
			code: codeForbidden, params: map[string]string{"role": "Key Vault Certificates Officer", "model": "unknown"}},
		{name: "403 firewall with address", op: "list", setup: vaultFault(fakekv.Fault{Status: 403,
			Body: kvBody("Forbidden", "ForbiddenByFirewall", "Client address (203.0.113.7) is not authorized.\r\nClient address: 203.0.113.7")}, "/certificates"),
			code: codeFirewall, params: map[string]string{"client_address": "203.0.113.7"}},
		{name: "403 firewall without a readable address", op: "list", setup: vaultFault(fakekv.Fault{Status: 403,
			Body: kvBody("Forbidden", "ForbiddenByFirewall", "Client address: 203.0.113.7.evil; Client address: not-an-ip")}, "/certificates"),
			code: codeFirewall},
		{name: "403 secret disabled", op: "secret", setup: vaultFault(forbidden("SecretDisabled"), "/secrets/"), code: codeVersionDisabled},
		{name: "404 certificate", op: "get", setup: vaultFault(fakekv.Fault{Status: 404, Body: kvBody("CertificateNotFound", "", "not found")}, "/certificates"),
			code: codeCertificateNotFound},
		{name: "404 secret", op: "secret", setup: vaultFault(fakekv.Fault{Status: 404, Body: kvBody("SecretNotFound", "", "not found")}, "/secrets/"),
			code: codeCertificateNotFound},
		{name: "NXDOMAIN for the vault", op: "list", setup: dialFailing(testVaultHost, nxdomain), code: codeVaultNotFound, cause: errDNS},
		{name: "NXDOMAIN for the login host", op: "token", setup: dialFailing("login.microsoftonline.com", &net.DNSError{IsNotFound: true}),
			code: codeUnreachable, retryable: true, cause: errDNS},
		{name: "refused connection to the login host", op: "token", setup: dialFailing("login.microsoftonline.com", refused),
			code: codeUnreachable, retryable: true, cause: errNotSent},
		{name: "connection reset after the connection was made", op: "get", setup: func(_ *testing.T, s *fakekv.Server, _ *Provider) {
			s.FailAll("/certificates", fakekv.Fault{Drop: true, Status: 200, Body: `{"id":"x"}`})
		}, code: codeUnexpected, retryable: true, cause: providers.ErrUnexpectedAnswer},
		{name: "dial refused by netaddr", op: "list", setup: func(_ *testing.T, s *fakekv.Server, p *Provider) {
			p.o.dialAddr = func(a string) string {
				if strings.HasPrefix(a, testVaultHost) {
					return "169.254.169.254:443"
				}
				return s.DialAddr(a)
			}
		}, code: codeAddressNotAllowed},
		{name: "TLS unknown authority", op: "list", setup: func(_ *testing.T, _ *fakekv.Server, p *Provider) {
			p.o.RootCAs = func() (*x509.CertPool, error) { return x509.NewCertPool(), nil }
		}, code: codeTLSUntrusted, cause: errTLS},
		{name: "429 after the retries", op: "get", setup: vaultFault(fakekv.Fault{Status: 429, Body: kvBody("Throttled", "", "slow down")}, "/certificates"),
			code: codeThrottled, retryable: true},
		{name: "500", op: "get", setup: vaultFault(fakekv.Fault{Status: 500}, "/certificates"), code: codeUnreachable, retryable: true},
		{name: "502", op: "get", setup: vaultFault(fakekv.Fault{Status: 502}, "/certificates"), code: codeUnreachable, retryable: true},
		{name: "503", op: "get", setup: vaultFault(fakekv.Fault{Status: 503}, "/certificates"), code: codeUnreachable, retryable: true},
		{name: "504", op: "get", setup: vaultFault(fakekv.Fault{Status: 504}, "/certificates"), code: codeUnreachable, retryable: true},
		{name: "408", op: "get", setup: vaultFault(fakekv.Fault{Status: 408}, "/certificates"), code: codeUnreachable, retryable: true},
		{name: "timeout", op: "get", setup: func(_ *testing.T, s *fakekv.Server, p *Provider) {
			p.o.try = 80 * time.Millisecond
			s.FailAll("/certificates", fakekv.Fault{Status: 200, Body: "{}", Delay: 3 * time.Second})
		}, code: codeUnreachable, retryable: true, cause: context.DeadlineExceeded},
		{name: "malformed JSON", op: "get", setup: vaultFault(fakekv.Fault{Status: 200, Body: "{not json " + canary}, "/certificates"),
			code: codeUnexpected, retryable: true, cause: providers.ErrUnexpectedAnswer},
		{name: "truncated body", op: "get", setup: vaultFault(fakekv.Fault{Truncate: true}, "/certificates"),
			code: codeUnexpected, retryable: true, cause: providers.ErrUnexpectedAnswer},
		{name: "body too large", op: "get", setup: vaultFault(fakekv.Fault{Status: 200, Body: strings.Repeat(canary, MaxBody/len(canary)+2)}, "/certificates"),
			code: codeUnexpected, retryable: true, cause: errBodyTooLarge},
		{name: "redirect", op: "get", setup: vaultFault(fakekv.Fault{Status: 302, Location: "https://evil.test/" + canary}, "/certificates"),
			code: codeUnexpected, retryable: true, cause: errRedirect},
		{name: "a server-chosen URL: foreign nextLink", op: "list", opts: fakekv.Options{ExtraHosts: []string{"evil.test"}},
			setup: vaultFault(fakekv.Fault{NextLink: "https://evil.test/certificates?" + canary}, "/certificates"),
			code:  codeUnexpected, retryable: true, cause: errHostNotAllowed},
		{name: "other 4xx", op: "import", setup: vaultFault(fakekv.Fault{Status: 400, Body: kvBody("BadParameter", "", "bad")}, "/certificates/new-cert/import"),
			code: codeUnexpected, retryable: true, cause: &answerError{status: 400, code: "BadParameter"}},
	}
	for _, rw := range rows {
		t.Run(rw.name, func(t *testing.T) {
			s := fakekv.Start(t, rw.opts)
			ver := addSeed(s)
			p := testProvider(s)
			clk := nearNow()
			if rw.setup != nil {
				rw.setup(t, s, p)
			}
			id := secretIdentity(s)
			if rw.id != nil {
				id = rw.id(s)
			}
			sess := openSession(t, p, &idSource{id: id}, clk)
			ctx := context.Background()
			err := drive(clk, func() error {
				switch rw.op {
				case "token":
					_, err := sess.api.Token(ctx)
					return err
				case "list":
					return sess.api.ListCertificates(ctx, func([]*azcertificates.CertificateProperties) error { return nil })
				case "get":
					_, err := sess.api.GetCertificate(ctx, "web-cert", "")
					return err
				case "secret":
					_, err := sess.api.GetSecret(ctx, "web-cert", ver)
					return err
				case "import":
					_, err := sess.api.ImportCertificate(ctx, "new-cert", azcertificates.ImportCertificateParameters{Base64EncodedCertificate: to.Ptr("AA==")})
					return err
				}
				return errors.New("unknown op")
			})
			var pe *providers.Error
			require.ErrorAs(t, err, &pe)
			assert.Equal(t, rw.code, pe.Code)
			assert.Equal(t, rw.retryable, pe.Retryable, "retryable")
			assert.True(t, closedCodes[pe.Code])
			checkParams(t, rw.params, pe)
			if rw.cause != nil {
				var ae *answerError
				if errors.As(rw.cause, &ae) {
					st, code, ok := answerOf(pe)
					assert.True(t, ok)
					assert.Equal(t, ae.status, st)
					assert.Equal(t, ae.code, code)
				} else {
					assert.ErrorIs(t, pe, rw.cause)
				}
			}
			assertNoLeak(t, pe, s)
		})
	}
}

func checkParams(t *testing.T, want map[string]string, pe *providers.Error) {
	t.Helper()
	for k, v := range pe.Params {
		assert.True(t, allowedParams[k], "param %q is not on the allowlist", k)
		switch k {
		case paramRequestID:
			assert.True(t, azureid.ValidRequestID(v))
		case paramAzureCode:
			assert.True(t, azureid.ValidAzureCode(v))
		default:
			assert.Equal(t, want[k], v, k)
		}
	}
	for k, v := range want {
		assert.Equal(t, v, pe.Params[k], k)
	}
}

// assertNoLeak: no rendering of the error carries Azure's text, the canary or a token.
func assertNoLeak(t *testing.T, pe *providers.Error, s *fakekv.Server) {
	t.Helper()
	assert.Equal(t, "providers: "+pe.Code, pe.Error())
	assertCauseChainIsOurs(t, pe)
	js, err := json.Marshal(pe)
	require.NoError(t, err)
	var buf bytes.Buffer
	slog.New(slog.NewTextHandler(&buf, nil)).Error("failed", "err", pe)
	jbuf := bytes.Buffer{}
	slog.New(slog.NewJSONHandler(&jbuf, nil)).Error("failed", "err", pe)
	renderings := map[string]string{
		"Error()": pe.Error(), "%v": fmt.Sprintf("%v", pe), "%+v": fmt.Sprintf("%+v", pe), "%#v": fmt.Sprintf("%#v", pe),
		"%s": fmt.Sprintf("%s", pe), "json": string(js), "slog text": buf.String(), "slog json": jbuf.String(),
		"cause": fmt.Sprint(pe.Cause),
	}
	needles := []string{canary, "AADSTS", "error_description", "Trace ID", "evil.test", "Bearer", s.Secret()}
	if tok := s.LastAccessToken(); tok != "" {
		needles = append(needles, tok)
	}
	for name, text := range renderings {
		for _, n := range needles {
			assert.NotContains(t, text, n, name)
		}
	}
}

func TestMapErrorContextAndUnknown(t *testing.T) {
	pe := mapError(context.Canceled, actionListCertificates)
	assert.Equal(t, codeUnreachable, pe.Code)
	assert.True(t, pe.Retryable)
	assert.ErrorIs(t, pe, context.Canceled)
	pe = mapError(fmt.Errorf("wrapped: %w", context.DeadlineExceeded), actionListCertificates)
	assert.ErrorIs(t, pe, context.DeadlineExceeded)
	pe = mapError(errors.New("some SDK text "+canary), actionListCertificates)
	assert.Equal(t, codeUnexpected, pe.Code)
	assertNoLeak(t, pe, fakekv.Start(t, fakekv.Options{}))
	pe = mapError(errors.New(`challenge resource "https://evil.test" doesn't match the requested domain`), actionListCertificates)
	assert.Equal(t, codeUnexpected, pe.Code)
	_, _, ok := answerOf(pe)
	assert.False(t, ok)
}

func TestMapErrorTenantMismatchAndForeignResource(t *testing.T) {
	s := fakekv.Start(t, fakekv.Options{})
	addSeed(s)
	// The vault's challenge names another tenant than the credential's.
	s.SetChallenge(`Bearer authorization="https://login.microsoftonline.com/` + uuid.NewString() + `" resource="https://vault.azure.net"`)
	sess := openSession(t, testProvider(s), &idSource{id: secretIdentity(s)}, nearNow())
	_, err := sess.api.GetCertificate(context.Background(), "web-cert", "")
	var pe *providers.Error
	require.ErrorAs(t, err, &pe)
	assert.Equal(t, codeAuthFailed, pe.Code)
	assert.Equal(t, map[string]string{"reason": "tenant_mismatch"}, pe.Params)
	assert.False(t, pe.Retryable)
	s.ClearRequests()

	// A challenge for another resource is refused by the SDK itself (verification stays on).
	s.SetChallenge(`Bearer authorization="https://login.microsoftonline.com/` + s.TenantID() + `" resource="https://evil.test"`)
	sess = openSession(t, testProvider(s), &idSource{id: secretIdentity(s)}, nearNow())
	_, err = sess.api.GetCertificate(context.Background(), "web-cert", "")
	require.ErrorAs(t, err, &pe)
	assert.Equal(t, codeUnexpected, pe.Code)
	for _, r := range s.Requests() {
		assert.False(t, r.HadAuth, "no token went anywhere")
	}

	// A resource of the vault's domain family but not the vault resource: the credential refuses
	// to fetch a token for it (the SDK's suffix check passes).
	s.SetChallenge(`Bearer authorization="https://login.microsoftonline.com/` + s.TenantID() + `" resource="https://azure.net"`)
	sess = openSession(t, testProvider(s), &idSource{id: secretIdentity(s)}, nearNow())
	_, err = sess.api.GetCertificate(context.Background(), "web-cert", "")
	require.ErrorAs(t, err, &pe)
	assert.Equal(t, codeUnexpected, pe.Code)
	assert.ErrorIs(t, pe, providers.ErrUnexpectedAnswer)
}

// assertCauseChainIsOurs: every node of the cause chain of a mapped error is a package sentinel, one
// of this package's cause types, a context error or a standard-library marker, never an SDK, MSAL
// or HTTP error (whose Error() holds Azure's text).
func assertCauseChainIsOurs(t *testing.T, err error) {
	t.Helper()
	known := []error{errNotSent, errDNS, errTLS, errDial, errMalformed, errUnclassified, errChallenge, errPanic,
		errHostNotAllowed, errRedirect, errBodyTooLarge, errTenantMismatch, errChallengeScope, errBadIdentity,
		errPageCap, errPageLoop, providers.ErrUnexpectedAnswer, netaddr.ErrNotAllowed, context.Canceled,
		context.DeadlineExceeded, io.ErrUnexpectedEOF}
	var walk func(e error)
	walk = func(e error) {
		if e == nil {
			return
		}
		switch x := e.(type) { //nolint:errorlint // the walk visits each node itself; errors.As would skip nodes
		case *providers.Error:
			walk(x.Cause)
			return
		case *answerError, *transportError:
			return
		case interface{ Unwrap() []error }: // errors.Join
			assert.Equal(t, "*errors.joinError", fmt.Sprintf("%T", e))
			for _, c := range x.Unwrap() {
				walk(c)
			}
			return
		}
		for _, k := range known {
			if e == k { //nolint:errorlint // identity of a sentinel is the point
				return
			}
		}
		assert.Fail(t, "a node of the cause chain is not one of ours", "%T", e)
	}
	walk(err)
}

func TestHostileHeadersAndCodesAreDropped(t *testing.T) {
	hdr := http.Header{"X-Ms-Request-Id": {"id with spaces\r\n<script>"}}
	body, _ := json.Marshal(map[string]any{"error": map[string]any{"code": "Not Valid", "message": canary,
		"innererror": map[string]any{"code": "bad code!\n" + canary}}})
	re := &azcore.ResponseError{StatusCode: 403, ErrorCode: "Not Valid <x>", RawResponse: response(403, hdr, string(body))} //nolint:bodyclose // in-memory body
	pe := mapError(re, actionListCertificates)
	assert.Equal(t, codeForbidden, pe.Code)
	assert.NotContains(t, pe.Params, paramRequestID)
	assert.NotContains(t, pe.Params, paramAzureCode)
	assert.Equal(t, "unknown", pe.Params[paramModel])
	assertCauseChainIsOurs(t, pe)
	// The same through an Entra answer.
	af := &azidentity.AuthenticationFailedError{RawResponse: response(401, hdr, entraBody(7000215, "x"))} //nolint:bodyclose // in-memory body
	pe = mapError(af, actionSignIn)
	assert.NotContains(t, pe.Params, paramRequestID)
	// A request id of the strict shape is kept in any letter case.
	hdr.Set("x-ms-request-id", "6B8E2C1A-0F3D-4C2B-9A7E-1D2C3B4A5F60")
	re.RawResponse = response(403, hdr, string(body)) //nolint:bodyclose // in-memory body
	assert.Equal(t, "6B8E2C1A-0F3D-4C2B-9A7E-1D2C3B4A5F60", mapError(re, actionListCertificates).Params[paramRequestID])
}

func TestCompleteRefusal(t *testing.T) {
	refusal := func(status int, code string) error {
		return perr(codeUnexpected, true, &answerError{status: status, code: code}, nil)
	}
	for _, tc := range []struct {
		err  error
		want bool
	}{
		{refusal(400, "BadParameter"), true}, {refusal(409, "Conflict"), true}, {refusal(403, "Forbidden"), true},
		{refusal(401, "Unauthorized"), true}, {refusal(404, "NotFound"), true},
		{refusal(400, ""), false}, {refusal(408, "RequestTimeout"), false}, {refusal(429, "Throttled"), false},
		{refusal(500, "Internal"), false}, {refusal(503, "Unavailable"), false}, {refusal(302, "x"), false},
		{perr(codeUnreachable, true, &transportError{}, nil), false}, {errors.New("x"), false}, {nil, false},
	} {
		assert.Equal(t, tc.want, completeRefusal(tc.err), "%v", tc.err)
	}
}
