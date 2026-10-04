package azurekv

import (
	"context"
	"encoding/json"
	"errors"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/policy"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/runtime"
	"github.com/Azure/azure-sdk-for-go/sdk/security/keyvault/azcertificates"
	"github.com/Azure/azure-sdk-for-go/sdk/security/keyvault/azkeys"
	"github.com/Azure/azure-sdk-for-go/sdk/security/keyvault/azsecrets"

	"alice/internal/platform/azureid"
	"alice/internal/providers"
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

var (
	errPageCap  = errors.New("azurekv: a listing has more pages than any vault Alice supports")
	errPageLoop = errors.New("azurekv: a listing repeats a next link")
)

// resumePager builds a pager positioned after the page whose nextLink is link: a new pager seeded,
// through its UnmarshalJSON, with that link (azcore's Pager is terminal after an error, so a failed
// page is asked again through a fresh one). A pager resumed this way hands back the seed once, with
// no request; the seed is taken here with an already-cancelled context, so that call cannot send
// anything even if azcore changes: a request would fail before it left, and resumePager would
// report it.
func resumePager[R any](newPager func() *runtime.Pager[R], link *string) (*runtime.Pager[R], error) {
	p := newPager()
	if link == nil {
		return p, nil
	}
	b, _ := json.Marshal(map[string]string{"nextLink": *link}) // a map of strings always encodes
	_ = json.Unmarshal(b, p)                                   // the pager's response types are flat structs with a nextLink
	dead, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := p.NextPage(dead); err != nil {
		return nil, err
	}
	return p, nil
}

// pages runs a listing one page per call: retry, limiter slot and deadline are per page, so a failed
// page is asked again without restarting the listing (D26). The first page needs no seed; later
// pages resume at the nextLink of the last page that succeeded. The link is the server's; the vault
// transport still refuses a host that is not the session's own.
//
// A hostile or broken vault could answer with a nextLink cycle forever, so a listing ends as
// azure.unexpected_response when a nextLink repeats within it or when it has more than maxPages
// pages (MaxListPages unless the retryer says otherwise).
func pages[R any](ctx context.Context, r *retryer, action string, newPager func() *runtime.Pager[R], nextLink func(R) *string, each func(R) error) error {
	unexpected := func(cause error) error {
		return perr(codeUnexpected, true, errors.Join(providers.ErrUnexpectedAnswer, cause), nil)
	}
	limit := r.maxPages
	if limit <= 0 {
		limit = MaxListPages
	}
	var last *string
	seen := map[string]bool{}
	pager := newPager()
	for n := 0; pager.More(); n++ {
		if n >= limit {
			return unexpected(errPageCap)
		}
		page, err := call(ctx, r, readBudget, action, func(c context.Context) (R, error) {
			pg, err := pager.NextPage(c)
			if err != nil {
				if np, rerr := resumePager(newPager, last); rerr == nil {
					pager = np
				}
			}
			return pg, err
		})
		if err != nil {
			return err
		}
		last = nextLink(page)
		if last != nil {
			if seen[*last] {
				return unexpected(errPageLoop)
			}
			seen[*last] = true
		}
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
