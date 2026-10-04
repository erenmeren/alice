package azurekv

import (
	"context"
	"encoding/json"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/policy"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/runtime"
	"github.com/Azure/azure-sdk-for-go/sdk/security/keyvault/azcertificates"
	"github.com/Azure/azure-sdk-for-go/sdk/security/keyvault/azkeys"
	"github.com/Azure/azure-sdk-for-go/sdk/security/keyvault/azsecrets"

	"alice/internal/platform/azureid"
)

// kvAPI is what the provider asks of one vault (spec §11.2): sdkAPI over the SDK clients in
// production; a hand fake in unit tests. Page callbacks see one page at a time; returning an error
// stops the listing. Every error is a *providers.Error already (retries are inside: one request
// (page) at a time, so a failed page is asked again without restarting the listing).
type kvAPI interface {
	Token(ctx context.Context) (azcore.AccessToken, error)
	ListCertificates(ctx context.Context, page func([]*azcertificates.CertificateProperties) error) error
	GetCertificate(ctx context.Context, name, version string) (azcertificates.Certificate, error)
	ListCertificateVersions(ctx context.Context, name string, page func([]*azcertificates.CertificateProperties) error) error
	ListKeys(ctx context.Context, page func([]*azkeys.KeyProperties) error) error
	GetKey(ctx context.Context, name string) (azkeys.KeyBundle, error)
	ListSecrets(ctx context.Context, page func([]*azsecrets.SecretProperties) error) error
	GetSecret(ctx context.Context, name, version string) (azsecrets.Secret, error)
	// ImportCertificate is sent once: never retried, whatever the failure.
	ImportCertificate(ctx context.Context, name string, p azcertificates.ImportCertificateParameters) (azcertificates.Certificate, error)
}

type sdkAPI struct {
	cred    azcore.TokenCredential
	certs   *azcertificates.Client
	keys    *azkeys.Client
	secrets *azsecrets.Client
	r       *retryer
}

var _ kvAPI = (*sdkAPI)(nil)

// newSDKAPI builds the three clients on the vault transport. The SDK's challenge-resource
// verification stays on (ruling S2): no option disables it.
func newSDKAPI(v azureid.Vault, cred azcore.TokenCredential, opts azcore.ClientOptions, r *retryer) (*sdkAPI, error) {
	certs, err := azcertificates.NewClient(v.URL, cred, &azcertificates.ClientOptions{ClientOptions: opts})
	if err != nil {
		return nil, err
	}
	keys, err := azkeys.NewClient(v.URL, cred, &azkeys.ClientOptions{ClientOptions: opts})
	if err != nil {
		return nil, err
	}
	secrets, err := azsecrets.NewClient(v.URL, cred, &azsecrets.ClientOptions{ClientOptions: opts})
	if err != nil {
		return nil, err
	}
	return &sdkAPI{cred: cred, certs: certs, keys: keys, secrets: secrets, r: r}, nil
}

// pages runs a listing one page per call: retry, limiter slot and deadline are per page, so a failed
// page is asked again without restarting the listing (D26).
//
// azcore's Pager enters a terminal state after an error (every later NextPage returns the same
// error without a request), so after a failure the pager is rebuilt at the same position: a new
// pager seeded, through its UnmarshalJSON, with the nextLink of the last page that succeeded (the
// first page needs no seed). The link is the server's; the vault transport still refuses a host
// that is not the session's own.
func pages[R any](ctx context.Context, r *retryer, action string, newPager func() *runtime.Pager[R], nextLink func(R) *string, each func(R) error) error {
	var last *string
	seed := func() *runtime.Pager[R] {
		p := newPager()
		if last != nil {
			if b, err := json.Marshal(map[string]string{"nextLink": *last}); err == nil {
				_ = json.Unmarshal(b, p) // sets the pager's current page: only its next link matters
				// A pager resumed this way hands back that seed once, with no request (the resume path
				// of long-running operations); take it so the next NextPage fetches the real next page.
				_, _ = p.NextPage(context.Background())
			}
		}
		return p
	}
	pager := seed()
	for pager.More() {
		page, err := call(ctx, r, readBudget, action, func(c context.Context) (R, error) {
			pg, err := pager.NextPage(c)
			if err != nil {
				pager = seed()
			}
			return pg, err
		})
		if err != nil {
			return err
		}
		last = nextLink(page)
		if err := each(page); err != nil {
			return err
		}
	}
	return nil
}

func (a *sdkAPI) Token(ctx context.Context) (azcore.AccessToken, error) {
	return call(ctx, a.r, readBudget, actionSignIn, func(c context.Context) (azcore.AccessToken, error) {
		return a.cred.GetToken(c, policy.TokenRequestOptions{Scopes: []string{azureid.VaultScope}})
	})
}

func (a *sdkAPI) ListCertificates(ctx context.Context, page func([]*azcertificates.CertificateProperties) error) error {
	return pages(ctx, a.r, actionListCertificates, func() *runtime.Pager[azcertificates.ListCertificatePropertiesResponse] {
		return a.certs.NewListCertificatePropertiesPager(nil)
	}, func(p azcertificates.ListCertificatePropertiesResponse) *string { return p.NextLink },
		func(p azcertificates.ListCertificatePropertiesResponse) error { return page(p.Value) })
}

func (a *sdkAPI) GetCertificate(ctx context.Context, name, version string) (azcertificates.Certificate, error) {
	return call(ctx, a.r, readBudget, actionGetCertificate, func(c context.Context) (azcertificates.Certificate, error) {
		resp, err := a.certs.GetCertificate(c, name, version, nil)
		return resp.Certificate, err
	})
}

func (a *sdkAPI) ListCertificateVersions(ctx context.Context, name string, page func([]*azcertificates.CertificateProperties) error) error {
	return pages(ctx, a.r, actionListVersions, func() *runtime.Pager[azcertificates.ListCertificatePropertiesVersionsResponse] {
		return a.certs.NewListCertificatePropertiesVersionsPager(name, nil)
	}, func(p azcertificates.ListCertificatePropertiesVersionsResponse) *string { return p.NextLink },
		func(p azcertificates.ListCertificatePropertiesVersionsResponse) error { return page(p.Value) })
}

func (a *sdkAPI) ListKeys(ctx context.Context, page func([]*azkeys.KeyProperties) error) error {
	return pages(ctx, a.r, actionListKeys, func() *runtime.Pager[azkeys.ListKeyPropertiesResponse] { return a.keys.NewListKeyPropertiesPager(nil) },
		func(p azkeys.ListKeyPropertiesResponse) *string { return p.NextLink },
		func(p azkeys.ListKeyPropertiesResponse) error { return page(p.Value) })
}

func (a *sdkAPI) GetKey(ctx context.Context, name string) (azkeys.KeyBundle, error) {
	return call(ctx, a.r, readBudget, actionGetKey, func(c context.Context) (azkeys.KeyBundle, error) {
		resp, err := a.keys.GetKey(c, name, "", nil)
		return resp.KeyBundle, err
	})
}

func (a *sdkAPI) ListSecrets(ctx context.Context, page func([]*azsecrets.SecretProperties) error) error {
	return pages(ctx, a.r, actionListSecrets, func() *runtime.Pager[azsecrets.ListSecretPropertiesResponse] {
		return a.secrets.NewListSecretPropertiesPager(nil)
	},
		func(p azsecrets.ListSecretPropertiesResponse) *string { return p.NextLink },
		func(p azsecrets.ListSecretPropertiesResponse) error { return page(p.Value) })
}

// GetSecret has the short budget of ruling S3: a deployment holds a server's lock meanwhile.
func (a *sdkAPI) GetSecret(ctx context.Context, name, version string) (azsecrets.Secret, error) {
	return call(ctx, a.r, secretBudget, actionReadSecret, func(c context.Context) (azsecrets.Secret, error) {
		resp, err := a.secrets.GetSecret(c, name, version, nil)
		return resp.Secret, err
	})
}

func (a *sdkAPI) ImportCertificate(ctx context.Context, name string, p azcertificates.ImportCertificateParameters) (azcertificates.Certificate, error) {
	return call(ctx, a.r, sendOnce, actionImport, func(c context.Context) (azcertificates.Certificate, error) {
		resp, err := a.certs.ImportCertificate(c, name, p, nil)
		return resp.Certificate, err
	})
}
