package azurekv

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/netip"
	"regexp"
	"strconv"
	"strings"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/runtime"
	"github.com/Azure/azure-sdk-for-go/sdk/azidentity"

	"alice/internal/platform/azureid"
	"alice/internal/platform/netaddr"
	"alice/internal/providers"
)

// Reason codes this package produces (the closed set of spec §11.9).
const (
	codeAuthFailed          = "azure.auth_failed"
	codeCredentialsExpired  = "azure.credentials_expired" //nolint:gosec // G101 false positive: a reason code, not a credential
	codeForbidden           = "azure.forbidden"
	codeFirewall            = "azure.firewall"
	codeVaultNotFound       = "azure.vault_not_found"
	codeUnreachable         = "azure.unreachable"
	codeThrottled           = "azure.throttled"
	codeUnexpected          = "azure.unexpected_response"
	codeClockSkew           = "azure.clock_skew"
	codeManagedIdentityGone = "azure.managed_identity_unavailable"
	codeAddressNotAllowed   = "azure.address_not_allowed"
	codeTLSUntrusted        = "azure.tls_untrusted"
	codeVersionDisabled     = "kv.version_disabled"
	codeCertificateNotFound = "kv.certificate_not_found"
	codeInternal            = "internal.unexpected"
)

// Param names a provider error of this package may carry. mapError never produces another one.
const (
	paramAADSTS    = "aadsts"
	paramRole      = "role"
	paramModel     = "model"
	paramClientIP  = "client_address"
	paramReason    = "reason"
	paramRequestID = "azure_request_id"
	paramAzureCode = "azure_code"
)

// Actions name the operation an error belongs to; they decide the role a 403 asks for.
const (
	actionSignIn           = "sign_in"
	actionListCertificates = "list_certificates"
	actionGetCertificate   = "get_certificate"
	actionListVersions     = "list_certificate_versions"
	actionListKeys         = "list_keys"
	actionGetKey           = "get_key"
	actionListSecrets      = "list_secrets"
	actionReadSecret       = "read_secret"
	actionImport           = "import_certificate"
)

// Causes kept on a *providers.Error. They are values of this package (or of the standard library
// without text from Azure): the SDK's own error is never kept, because its Error() holds the
// response text. errors.Is on them is how callers (and providers.CheckImportReturn) tell a failure
// before anything was sent from one after the request may have been carried out.
var (
	// errNotSent: the failure happened before any request byte left (refusal, DNS, dial, TLS).
	errNotSent = errors.New("azurekv: nothing was sent")
	errDNS     = errors.New("azurekv: the host name does not exist")
	errTLS     = errors.New("azurekv: the certificate of the host is not trusted")
	errDial    = errors.New("azurekv: the connection could not be made")
	// errMalformed marks a 2xx answer whose body could not be used.
	errMalformed = &json.SyntaxError{}
	// errUnclassified: an error without any evidence of what happened.
	errUnclassified = errors.New("azurekv: failure without a classification")
	// errChallenge: a Key Vault challenge the SDK refused.
	errChallenge = errors.New("azurekv: the vault's challenge was refused")
	// errPanic: the SDK panicked on an answer (a malformed challenge).
	errPanic = errors.New("azurekv: the SDK failed on an answer")
)

// answerError is the cause of a complete answer of Azure with an error status.
type answerError struct {
	status int
	code   string // a validated Azure code, or ""
}

func (e *answerError) Error() string {
	return "azurekv: Azure answered with HTTP status " + strconv.Itoa(e.status)
}

// answerOf reports whether err was caused by a complete, parsed answer of Azure with an error
// status (the positive evidence an import needs to be "refused"), and its status and validated
// Azure code.
func answerOf(err error) (status int, code string, ok bool) {
	var a *answerError
	if errors.As(err, &a) {
		return a.status, a.code, true
	}
	return 0, "", false
}

// transportError is the cause of a failure on an open connection. It is a net.Error, so
// providers.CheckImportReturn counts it as a transport failure.
type transportError struct{ timeout bool }

func (e *transportError) Error() string   { return "azurekv: the connection failed" }
func (e *transportError) Timeout() bool   { return e.timeout }
func (e *transportError) Temporary() bool { return false }

var _ net.Error = (*transportError)(nil)

// failure is a mapped error and what the retry loop may do about it.
type failure struct {
	err   *providers.Error
	retry bool   // another attempt may help
	after string // the Retry-After header of the answer, verbatim ("" none)
}

// mapError maps any failure of an SDK call to one *providers.Error with a closed code and
// allowlisted params. Transport evidence recorded by the transports is used by call (classify).
func mapError(err error, action string) *providers.Error { return classify(err, action, nil).err }

func perr(code string, retryable bool, cause error, params map[string]string) *providers.Error {
	return providers.NewError(code, retryable, cause, params)
}

func ctxFailure(err error) failure {
	return failure{err: perr(codeUnreachable, true, err, nil), retry: errors.Is(err, context.DeadlineExceeded) && !errors.Is(err, context.Canceled)}
}

// classify implements the table of errors. st may be nil.
func classify(err error, action string, st *wireState) failure {
	sn := st.snapshot()
	var te *tokenError
	var re *azcore.ResponseError
	var af *azidentity.AuthenticationFailedError
	switch {
	case errors.Is(err, context.Canceled):
		return ctxFailure(context.Canceled)
	case errors.Is(err, context.DeadlineExceeded):
		return ctxFailure(context.DeadlineExceeded)
	case errors.As(err, &te):
		return classifySignIn(te, sn)
	case errors.As(err, &re):
		return classifyVault(re, action)
	case errors.As(err, &af) && af.RawResponse != nil:
		return classifyEntra(af.RawResponse, false)
	case errors.Is(err, errPanic):
		return failure{err: perr(codeUnexpected, true, errors.Join(providers.ErrUnexpectedAnswer, errPanic), nil)}
	case strings.Contains(err.Error(), "doesn't match the requested domain"):
		// The SDK's challenge-resource check. It compares the request's host, which carries ":443" on
		// a page after the first, with the resource: a challenge that came from the vault's own host
		// naming the vault resource is that port quirk (retry: the pager asks again with a fresh
		// token), any other challenge is refused for good.
		cause := errors.Join(providers.ErrUnexpectedAnswer, errChallenge)
		return failure{err: perr(codeUnexpected, true, cause, nil), retry: sn.ownChallenge}
	}
	if f, ok := classifyWire(sn); ok {
		return f
	}
	return failure{err: perr(codeUnexpected, true, errors.Join(providers.ErrUnexpectedAnswer, errUnclassified), nil)}
}

// classifyWire maps what the transports saw on the last request of the attempt.
func classifyWire(sn wireSnapshot) (failure, bool) {
	switch sn.kind {
	case wireContext:
		return ctxFailure(sn.ctxErr), true
	case wireHostNotAllowed:
		return failure{err: perr(codeUnexpected, true, errors.Join(errNotSent, errHostNotAllowed), nil)}, true
	case wireRedirect:
		return failure{err: perr(codeUnexpected, true, errors.Join(providers.ErrUnexpectedAnswer, errRedirect), nil)}, true
	case wireAddrRefused:
		return failure{err: perr(codeAddressNotAllowed, false, errors.Join(errNotSent, netaddr.ErrNotAllowed), nil)}, true
	case wireDNSNotFound:
		if sn.host == azureid.AuthorityHost {
			return failure{err: perr(codeUnreachable, true, errors.Join(errNotSent, errDNS), nil), retry: true}, true
		}
		return failure{err: perr(codeVaultNotFound, false, errors.Join(errNotSent, errDNS), nil)}, true
	case wireTLSUntrusted:
		return failure{err: perr(codeTLSUntrusted, false, errors.Join(errNotSent, errTLS), nil)}, true
	case wireDial:
		return failure{err: perr(codeUnreachable, true, errors.Join(errNotSent, errDial), nil), retry: true}, true
	case wireOther:
		return failure{err: perr(codeUnreachable, true, &transportError{}, nil), retry: true}, true
	case wireBodyTooLarge:
		return failure{err: perr(codeUnexpected, true, errors.Join(providers.ErrUnexpectedAnswer, errBodyTooLarge), nil)}, true
	case wireBodyRead:
		if sn.status == 0 || sn.status/100 == 2 {
			return failure{err: perr(codeUnexpected, true, errors.Join(providers.ErrUnexpectedAnswer, io.ErrUnexpectedEOF), nil), retry: true}, true
		}
	}
	switch {
	case sn.status/100 == 2:
		return failure{err: perr(codeUnexpected, true, errors.Join(providers.ErrUnexpectedAnswer, errMalformed), nil), retry: true}, true
	case sn.status == http.StatusTooManyRequests:
		return failure{err: perr(codeThrottled, true, &answerError{status: sn.status}, nil), retry: true}, true
	case sn.status >= 500:
		return failure{err: perr(codeUnreachable, true, &answerError{status: sn.status}, nil), retry: true}, true
	}
	return failure{}, false
}

var clientAddrRE = regexp.MustCompile(`Client address: ([0-9A-Fa-f.:]{2,45})`)

type kvErrorBody struct {
	Error struct {
		Code       string `json:"code"`
		Message    string `json:"message"`
		InnerError *struct {
			Code string `json:"code"`
		} `json:"innererror"`
	} `json:"error"`
}

type entraErrorBody struct {
	ErrorCodes []int `json:"error_codes"`
}

// answerBody reads the already buffered body of an answer, at most 64 KiB.
func answerBody(resp *http.Response) []byte {
	if resp == nil || resp.Body == nil {
		return nil
	}
	b, err := runtime.Payload(resp)
	if err != nil {
		return nil
	}
	return b[:min(len(b), 64<<10)]
}

func addCommon(p map[string]string, resp *http.Response, azureCode string) {
	if resp != nil {
		if id := resp.Header.Get("x-ms-request-id"); azureid.ValidRequestID(id) {
			p[paramRequestID] = id
		}
	}
	if azureid.ValidAzureCode(azureCode) {
		p[paramAzureCode] = azureCode
	}
}

func roleFor(action string) string {
	switch action {
	case actionReadSecret:
		return providers.RoleKeyVaultSecretsUser
	case actionImport:
		return providers.RoleKeyVaultCertificatesOfficer
	default:
		return providers.RoleKeyVaultReader
	}
}

func validCode(s string) string {
	if azureid.ValidAzureCode(s) {
		return s
	}
	return ""
}

// classifyVault maps an error answer of the vault.
func classifyVault(re *azcore.ResponseError, action string) failure {
	var body kvErrorBody
	_ = json.Unmarshal(answerBody(re.RawResponse), &body)
	inner := ""
	if body.Error.InnerError != nil {
		inner = validCode(body.Error.InnerError.Code)
	}
	code := inner
	if code == "" {
		code = validCode(re.ErrorCode)
	}
	if code == "" {
		code = validCode(body.Error.Code)
	}
	params := map[string]string{}
	addCommon(params, re.RawResponse, code)
	cause := &answerError{status: re.StatusCode, code: code}
	after := ""
	if re.RawResponse != nil {
		after = re.RawResponse.Header.Get("Retry-After")
	}
	switch {
	case re.StatusCode == http.StatusUnauthorized:
		return failure{err: perr(codeAuthFailed, false, cause, params)}
	case re.StatusCode == http.StatusForbidden && inner == "SecretDisabled":
		return failure{err: perr(codeVersionDisabled, false, cause, params)}
	case re.StatusCode == http.StatusForbidden && inner == "ForbiddenByFirewall":
		if m := clientAddrRE.FindStringSubmatch(body.Error.Message); m != nil {
			if a, err := netip.ParseAddr(m[1]); err == nil {
				params[paramClientIP] = a.String()
			}
		}
		return failure{err: perr(codeFirewall, false, cause, params)}
	case re.StatusCode == http.StatusForbidden:
		params[paramRole] = roleFor(action)
		switch inner {
		case "ForbiddenByRbac":
			params[paramModel] = "rbac"
		case "ForbiddenByPolicy", "AccessDenied": // the real access-policy code is unverified
			params[paramModel] = "access_policy"
		default:
			params[paramModel] = "unknown"
		}
		return failure{err: perr(codeForbidden, false, cause, params)}
	case re.StatusCode == http.StatusNotFound:
		return failure{err: perr(codeCertificateNotFound, false, cause, params)}
	case re.StatusCode == http.StatusTooManyRequests:
		return failure{err: perr(codeThrottled, true, cause, params), retry: true, after: after}
	case re.StatusCode == http.StatusRequestTimeout || re.StatusCode >= 500:
		return failure{err: perr(codeUnreachable, true, cause, params), retry: true, after: after}
	}
	return failure{err: perr(codeUnexpected, true, cause, params)} // other 4xx: Task 8 reads answerOf for an import
}

// classifyEntra maps an error answer of the token endpoint (or of IMDS when mi).
func classifyEntra(resp *http.Response, mi bool) failure {
	params := map[string]string{}
	addCommon(params, resp, "")
	cause := &answerError{status: resp.StatusCode}
	after := resp.Header.Get("Retry-After")
	switch {
	case resp.StatusCode == http.StatusTooManyRequests:
		return failure{err: perr(codeThrottled, true, cause, params), retry: true, after: after}
	case resp.StatusCode >= 500:
		return failure{err: perr(codeUnreachable, true, cause, params), retry: true, after: after}
	case mi:
		return failure{err: perr(codeManagedIdentityGone, false, cause, params)}
	}
	var body entraErrorBody
	_ = json.Unmarshal(answerBody(resp), &body)
	code := codeAuthFailed
	if len(body.ErrorCodes) > 0 && body.ErrorCodes[0] > 0 && body.ErrorCodes[0] < 100_000_000 {
		n := body.ErrorCodes[0]
		params[paramAADSTS] = strconv.Itoa(n)
		switch n {
		case 7000222:
			code = codeCredentialsExpired
		case 700024:
			code = codeClockSkew
		}
	}
	return failure{err: perr(code, false, cause, params)}
}

// classifySignIn maps a failure of the credential's GetToken.
func classifySignIn(te *tokenError, sn wireSnapshot) failure {
	mi := te.auth == providers.AzureAuthManagedIdentity
	var af *azidentity.AuthenticationFailedError
	switch {
	case errors.Is(te.err, context.Canceled):
		return ctxFailure(context.Canceled)
	case errors.Is(te.err, context.DeadlineExceeded):
		return ctxFailure(context.DeadlineExceeded)
	case errors.As(te.err, &af) && af.RawResponse != nil:
		return classifyEntra(af.RawResponse, mi)
	case errors.Is(te.err, errTenantMismatch):
		return failure{err: perr(codeAuthFailed, false, errTenantMismatch, map[string]string{paramReason: "tenant_mismatch"})}
	case errors.Is(te.err, errChallengeScope):
		return failure{err: perr(codeUnexpected, true, errors.Join(providers.ErrUnexpectedAnswer, errChallengeScope), nil)}
	}
	f, ok := classifyWire(sn)
	if !ok {
		if mi {
			return failure{err: perr(codeManagedIdentityGone, false, nil, nil)}
		}
		return failure{err: perr(codeAuthFailed, false, nil, nil)}
	}
	switch sn.kind {
	case wireHostNotAllowed, wireRedirect, wireAddrRefused, wireDNSNotFound, wireTLSUntrusted, wireDial, wireOther:
		if mi { // no metadata endpoint, or the SDK picked another source: fail closed
			return failure{err: perr(codeManagedIdentityGone, false, f.err.Cause, nil)}
		}
	}
	return f
}

// completeRefusal reports an error that is a complete, parsed 4xx answer of Azure that carries a
// validated Azure code, other than 408 and 429 (timeouts and throttling say nothing about whether
// the request was carried out): the one kind of failure an import may treat as "refused". Anything
// else, including a 5xx, a transport failure or an answer without a code, is uncertain.
func completeRefusal(err error) bool {
	status, code, ok := answerOf(err)
	return ok && code != "" && status >= 400 && status < 500 && status != http.StatusRequestTimeout && status != http.StatusTooManyRequests
}
