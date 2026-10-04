package azurekv

import (
	"context"
	"crypto/ecdsa"
	"crypto/rsa"
	"encoding/base64"
	"slices"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore/to"
	"github.com/Azure/azure-sdk-for-go/sdk/security/keyvault/azcertificates"
	"software.sslmate.com/src/go-pkcs12"

	"alice/internal/platform/azureid"
	"alice/internal/providers"
)

// maxImportPFX bounds the PFX of an import: its base64 form, and the PFX the vault serves back as
// the certificate's secret, must stay under the secret bound (256 KiB; 192 KiB of PFX is 256 KiB of
// base64).
const maxImportPFX = 192 << 10

// importPlan is what a valid request says, read from the PFX itself.
type importPlan struct {
	thumb string // SHA-1 of the leaf that is sent
	kty   azcertificates.KeyType
	crv   *azcertificates.CurveName
	size  *int32 // RSA bits
}

// planImport validates the request without sending anything and reads the leaf and the key type of
// the PFX. The parsed key objects cannot be zeroed (a known residual next to the SDK's copies); only
// the leaf's thumbprint is kept.
func planImport(req providers.ImportRequest) (importPlan, bool) {
	var p importPlan
	if !azureid.ValidObjectName(req.Name) || len(req.PFX.Bytes()) == 0 || len(req.PFX.Bytes()) > maxImportPFX {
		return p, false
	}
	key, leaf, _, err := pkcs12.DecodeChain(req.PFX.Bytes(), "")
	if err != nil || leaf == nil {
		return p, false
	}
	switch k := key.(type) {
	case *rsa.PrivateKey:
		bits := k.N.BitLen()
		if req.KeyType != "rsa" || req.KeySize != bits || bits < 2048 || bits > 16384 {
			return p, false
		}
		p.kty, p.size = azcertificates.KeyTypeRSA, to.Ptr(int32(bits)) //nolint:gosec // G115: 2048..16384 checked above
	case *ecdsa.PrivateKey:
		bits := k.Curve.Params().BitSize
		if req.KeyType != "ecdsa" || req.KeySize != bits {
			return p, false
		}
		switch bits {
		case 256:
			p.crv = to.Ptr(azcertificates.CurveNameP256)
		case 384:
			p.crv = to.Ptr(azcertificates.CurveNameP384)
		default:
			return p, false
		}
		p.kty = azcertificates.KeyTypeEC
	default:
		return p, false
	}
	p.thumb = azureid.ThumbprintOf(leaf.Raw)
	return p, true
}

func importRefused(code string, retryable bool, cause error, params map[string]string) (providers.ImportResult, error) {
	return providers.ImportResult{Outcome: providers.ImportRefused}, perr(code, retryable, cause, params)
}

// beforeSend turns a failure that happened before the import request left into a refusal. Its cause
// is ours, never the transport's: a refusal that wraps a timeout would be uncertain by contract.
func beforeSend(err error) (providers.ImportResult, error) {
	pe := toProviderError(err)
	return importRefused(pe.Code, pe.Retryable, errNotSent, pe.Params)
}

func importUncertain(err error) (providers.ImportResult, error) {
	return providers.ImportResult{Outcome: providers.ImportUncertain}, toProviderError(err)
}

// ImportCertificate adds a version to the certificate Name from a PFX with an empty password. The
// vault has no idempotency key, so the request is sent exactly once (the SDK's retries are off and
// Alice's loop runs in its send-once mode); the outcome follows positive evidence only:
//
//	refused    before the send (invalid request, a name that exists without ReplaceExisting, a
//	           sign-in or existence-check failure, a cancelled context), or a complete 4xx answer of
//	           the vault with a validated Azure code other than 408/429
//	created    a complete, parsed 2xx that names this certificate, a 32-hex version and a certificate
//	           whose SHA-1 is the thumbprint of the leaf that was sent
//	uncertain  everything else after the request was written: 5xx, 408, 429, a 4xx without a code, a
//	           reset, a timeout, a cancelled context, an unparsable, truncated or foreign 2xx
//
// The existence check before an import without ReplaceExisting is a read, so another writer can
// create the name between the read and the import (the vault offers no conditional import): the
// import then adds a version to a certificate that appeared meanwhile.
//
// req.PFX is the caller's: it is neither kept nor zeroed here. The base64 text is built in a buffer
// Alice zeroes; the Go string the SDK needs, its request body and the parsed key (planImport) are
// copies Alice cannot zero.
func (s *session) ImportCertificate(ctx context.Context, req providers.ImportRequest, steps providers.StepLogger) (providers.ImportResult, error) {
	if ctx.Err() != nil { // nothing was sent: not "uncertain", which would block the name for 24 hours
		return importRefused(codeUnreachable, true, errNotSent, nil)
	}
	plan, ok := planImport(req)
	if !ok {
		return importRefused(providers.CodeKVImportInvalid, false, errNotSent, nil)
	}
	step := func(name string, st providers.StepStatus) {
		if steps != nil {
			steps.Step(name, st, map[string]string{"certificate_name": req.Name})
		}
	}

	pre, cancel := context.WithTimeout(ctx, PreflightBudget)
	defer cancel()
	step("sign_in", providers.StepStarted)
	if _, err := s.api.Token(pre); err != nil {
		step("sign_in", providers.StepFailed)
		return beforeSend(err)
	}
	step("sign_in", providers.StepOK)

	if !req.ReplaceExisting {
		_, err := s.api.GetCertificate(pre, req.Name, "")
		switch {
		case err == nil:
			return importRefused(providers.CodeKVImportNameExists, false, errNotSent, nil)
		case toProviderError(err).Code != codeCertificateNotFound:
			res, perr := beforeSend(err)
			if pe := toProviderError(perr); pe.Code == codeForbidden { // an import needs the officer role, not the reader's
				pe.Params[paramRole] = providers.RoleKeyVaultCertificatesOfficer
			}
			return res, perr
		}
	}

	b64 := base64.StdEncoding.AppendEncode(make([]byte, 0, base64.StdEncoding.EncodedLen(len(req.PFX.Bytes()))), req.PFX.Bytes())
	defer clear(b64)
	params := azcertificates.ImportCertificateParameters{
		Base64EncodedCertificate: to.Ptr(string(b64)), // the SDK's copy: a Go string cannot be zeroed
		Password:                 to.Ptr(""),
		CertificatePolicy: &azcertificates.CertificatePolicy{
			KeyProperties:    &azcertificates.KeyProperties{Exportable: to.Ptr(true), KeyType: &plan.kty, KeySize: plan.size, Curve: plan.crv, ReuseKey: to.Ptr(false)},
			SecretProperties: &azcertificates.SecretProperties{ContentType: to.Ptr(contentTypePKCS12)},
			IssuerParameters: &azcertificates.IssuerParameters{Name: to.Ptr("Unknown")},
		},
	}
	step("import", providers.StepStarted)
	resp, err := s.api.ImportCertificate(ctx, req.Name, params)
	if err != nil {
		step("import", providers.StepFailed)
		pe := toProviderError(err)
		if !completeRefusal(pe) {
			return importUncertain(pe)
		}
		switch pe.Code {
		case codeForbidden, codeFirewall, codeAuthFailed:
			return importRefused(pe.Code, false, pe.Cause, pe.Params)
		}
		keep := map[string]string{}
		for _, k := range []string{paramAzureCode, paramRequestID} {
			if v, ok := pe.Params[k]; ok {
				keep[k] = v
			}
		}
		return importRefused(codeImportRejected, false, pe.Cause, keep)
	}
	version, thumb, ok := confirmImport(req.Name, plan, resp)
	if !ok {
		step("import", providers.StepFailed)
		return importUncertain(perr(codeUnexpected, true, providers.ErrUnexpectedAnswer, nil))
	}
	step("import", providers.StepOK)
	return providers.ImportResult{Outcome: providers.ImportCreated, Version: version, Thumbprint: thumb, CER: slices.Clone(resp.CER)}, nil
}

// confirmImport accepts an answer only when it is for this certificate and carries the leaf that was
// sent: anything else leaves the import uncertain.
func confirmImport(name string, plan importPlan, resp azcertificates.Certificate) (version, thumb string, ok bool) {
	n, version, idOK := parseObjectID(idStr(resp.ID), kindCertificates)
	thumb, thumbOK := azureid.Thumbprint(resp.X509Thumbprint)
	if !idOK || !thumbOK || foldASCII(n) != foldASCII(name) || !azureid.ValidVersion(version) ||
		len(resp.CER) == 0 || len(resp.CER) > maxCER || azureid.ThumbprintOf(resp.CER) != thumb || thumb != plan.thumb {
		return "", "", false
	}
	return version, thumb, true
}
