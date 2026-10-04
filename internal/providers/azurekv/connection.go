package azurekv

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"

	"github.com/Azure/azure-sdk-for-go/sdk/security/keyvault/azcertificates"
	"github.com/Azure/azure-sdk-for-go/sdk/security/keyvault/azkeys"
	"github.com/Azure/azure-sdk-for-go/sdk/security/keyvault/azsecrets"

	"alice/internal/platform/azureid"
	"alice/internal/providers"
)

// maxTokenForClaims bounds the token Alice is willing to split and decode for display.
const maxTokenForClaims = 16 << 10

// errStopListing ends a listing after the pages a caller wanted (it is not a failure).
var errStopListing = errors.New("azurekv: stop listing")

// ctxError is the closed error of a context that ended before or during an operation.
func ctxError(err error) *providers.Error { return perr(codeUnreachable, true, err, nil) }

// claimsOf reads the oid and tid claims of an access token for display and returns each only when
// it is a GUID (ruling S13). The token is never stored, logged or returned, and nothing here is
// ever an error: a token that does not decode leaves both empty. The decoded payload is cleared.
func claimsOf(token string) (oid, tid string) {
	if len(token) > maxTokenForClaims {
		return "", ""
	}
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return "", ""
	}
	payload, err := base64.RawURLEncoding.DecodeString(strings.TrimRight(parts[1], "="))
	if err != nil {
		return "", ""
	}
	defer clear(payload)
	var c struct {
		OID string `json:"oid"`
		TID string `json:"tid"`
	}
	if json.Unmarshal(payload, &c) != nil {
		return "", ""
	}
	oid, _ = azureid.NormalizeGUID(c.OID)
	tid, _ = azureid.NormalizeGUID(c.TID)
	return oid, tid
}

// TestConnection is the access check of spec §11.3 without the optional secret read: sign-in, then
// the first page of each of the three lists. It returns the report whenever sign-in worked and the
// vault answered the first list with anything but a refusal of this identity (F-40); a vault that
// does not exist, cannot be reached or answers with something else is an error (F-43), so that
// adding a vault can be refused.
func (s *session) TestConnection(ctx context.Context) (providers.ConnectionReport, error) {
	if err := ctx.Err(); err != nil {
		return providers.ConnectionReport{}, ctxError(err)
	}
	ctx, cancel := context.WithTimeout(ctx, PreflightBudget)
	defer cancel()
	tok, err := s.api.Token(ctx)
	if err != nil {
		return providers.ConnectionReport{}, err
	}
	oid, tid := claimsOf(tok.Token)
	facts := &providers.AzureFacts{ObjectID: oid, TenantID: tid, PermissionModel: "unknown",
		Checks: []providers.AzureCheck{{Name: providers.AzureCheckSignIn, Result: providers.AzureResultOK}}}
	model := ""

	row := func(name string, err error) (*providers.Error, bool) {
		if err == nil || errors.Is(err, errStopListing) {
			facts.Checks = append(facts.Checks, providers.AzureCheck{Name: name, Result: providers.AzureResultOK})
			return nil, true
		}
		pe := toProviderError(err)
		c := providers.AzureCheck{Name: name, Result: providers.AzureResultFailed, Reason: pe.Code}
		if pe.Code == codeForbidden || pe.Code == codeFirewall {
			c.Result = providers.AzureResultForbidden
			c.Role = pe.Params[paramRole]
			if m := pe.Params[paramModel]; model == "" && m != "" {
				model = m
			}
		}
		facts.Checks = append(facts.Checks, c)
		return pe, false
	}
	pe, ok := row(providers.AzureCheckListCertificates, s.api.ListCertificates(ctx, stopAfterFirst[*azcertificates.CertificateProperties]))
	if !ok && pe.Code != codeForbidden && pe.Code != codeFirewall {
		return providers.ConnectionReport{}, pe
	}
	if ctx.Err() != nil {
		return providers.ConnectionReport{}, ctxError(ctx.Err())
	}
	_, _ = row(providers.AzureCheckListKeys, s.api.ListKeys(ctx, stopAfterFirst[*azkeys.KeyProperties]))
	_, _ = row(providers.AzureCheckListSecrets, s.api.ListSecrets(ctx, stopAfterFirst[*azsecrets.SecretProperties]))
	if err := ctx.Err(); err != nil {
		return providers.ConnectionReport{}, ctxError(err)
	}
	facts.Checks = append(facts.Checks,
		providers.AzureCheck{Name: providers.AzureCheckReadSecret, Result: providers.AzureResultNotChecked},
		providers.AzureCheck{Name: providers.AzureCheckImport, Result: providers.AzureResultNotChecked})
	if model != "" {
		facts.PermissionModel = model
	}
	facts.CheckedAt = s.clock.Now()
	return providers.ConnectionReport{Azure: facts}, nil
}

func stopAfterFirst[T any](_ []T) error { return errStopListing }

// toProviderError returns err as a *providers.Error; anything else (a callback's own error) is an
// unexpected answer with no cause worth keeping.
func toProviderError(err error) *providers.Error {
	var pe *providers.Error
	if errors.As(err, &pe) {
		return pe
	}
	return perr(codeUnexpected, true, providers.ErrUnexpectedAnswer, nil)
}
