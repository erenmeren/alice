package azurekv

import (
	"context"
	"strings"

	"alice/internal/platform/azureid"
	"alice/internal/providers"
)

// The content types of a certificate's backing secret Alice accepts, exactly (certs has the same two).
const (
	contentTypePKCS12 = "application/x-pkcs12"
	contentTypePEM    = "application/x-pem-file"
)

// maxSecretValue bounds the value of a certificate secret before it is copied (it equals
// certs.MaxKVSecretSize, which azurekv may not import). A variable so a test can lower it.
var maxSecretValue = 256 << 10

// ReadCertificateSecret reads the backing secret of one version of a certificate (spec §11.5): the
// value Alice's deployments decode. It never asks for "latest": the name must be a valid object
// name and the version 32 lower-case hex digits, or the request is refused before anything is sent.
// The deployment holds a server's lock meanwhile, so the read has the short budget of ruling S3
// (two attempts, one minute) whatever the caller's context says.
//
// The value comes back in a Plaintext holder the caller zeroes. What the SDK copied cannot be
// zeroed: its decoded response body and the Go string of the value (R40 row 33). A non-exportable
// certificate answers 200 with a value that has no private key; the provider does not parse the
// container (it cannot import certs), the caller sees ErrNoKey when it decodes the value.
func (s *session) ReadCertificateSecret(ctx context.Context, req providers.SecretRequest) (providers.CertificateSecret, error) {
	if err := ctx.Err(); err != nil {
		return providers.CertificateSecret{}, ctxError(err)
	}
	if !azureid.ValidObjectName(req.Name) || !azureid.ValidVersion(req.Version) {
		return providers.CertificateSecret{}, perr(codeVersionNotDeployable, false, nil, nil)
	}
	ctx, cancel := context.WithTimeout(ctx, SecretReadBudget)
	defer cancel()
	sec, err := s.api.GetSecret(ctx, req.Name, req.Version)
	if err != nil {
		return providers.CertificateSecret{}, err
	}
	unreadable := func() (providers.CertificateSecret, error) {
		return providers.CertificateSecret{}, perr(codeSecretUnreadable, false, providers.ErrUnexpectedAnswer, nil)
	}
	name, version, ok := parseObjectID(idStr(sec.ID), "secrets", s.vault.Host)
	if !ok || version != req.Version || foldASCII(name) != foldASCII(req.Name) { // the vault answered for another object
		return unreadable()
	}
	if sec.Value == nil || sec.ContentType == nil || *sec.Value == "" || len(*sec.Value) > maxSecretValue {
		return unreadable()
	}
	if ct := *sec.ContentType; ct != contentTypePKCS12 && ct != contentTypePEM {
		return unreadable()
	}
	// The one copy Alice owns, in a holder the caller zeroes.
	value := make([]byte, len(*sec.Value))
	copy(value, *sec.Value)
	return providers.CertificateSecret{ContentType: strings.Clone(*sec.ContentType), Value: providers.NewSecret(value)}, nil
}
