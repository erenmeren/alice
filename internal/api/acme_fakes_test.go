package api

import (
	"context"

	"github.com/google/uuid"

	"alice/internal/authz"
	"alice/internal/inventory"
)

// fakeACME implements ACMEService. Each method calls its function field when set; otherwise it returns zero values
// and errNotConfigured.
type fakeACME struct {
	ListACMEProvidersFn     func(ctx context.Context) ([]inventory.ACMEProvider, error)
	GetACMEProviderFn       func(ctx context.Context, id uuid.UUID) (inventory.ACMEProvider, error)
	CreateACMEProviderFn    func(ctx context.Context, a inventory.Actor, in inventory.ACMEProviderInput) (inventory.ACMEProvider, error)
	UpdateACMEProviderFn    func(ctx context.Context, a inventory.Actor, id uuid.UUID, p inventory.ACMEProviderPatch) (inventory.ACMEProvider, error)
	DeleteACMEProviderFn    func(ctx context.Context, a inventory.Actor, id uuid.UUID) error
	ListACMEAccountsFn      func(ctx context.Context, providerID uuid.UUID) ([]inventory.ACMEAccount, error)
	RegisterACMEAccountFn   func(ctx context.Context, a inventory.Actor, providerID uuid.UUID, contactEmail string, tosAccepted bool, acceptedTermsURL string) (inventory.ACMEAccount, error)
	PreviewACMEProviderFn   func(ctx context.Context, providerID uuid.UUID) (inventory.ACMEProviderPreview, error)
	RolloverACMEAccountFn   func(ctx context.Context, a inventory.Actor, accountID uuid.UUID) (inventory.ACMEAccount, error)
	RecoverACMERolloverFn   func(ctx context.Context, a inventory.Actor, accountID uuid.UUID) (inventory.ACMEAccount, error)
	DeactivateACMEAccountFn func(ctx context.Context, a inventory.Actor, accountID uuid.UUID) (inventory.ACMEAccount, error)
	ListACMEHooksFn         func(ctx context.Context) ([]inventory.ACMEHook, error)
	GetACMEHookFn           func(ctx context.Context, id uuid.UUID) (inventory.ACMEHook, error)
	CreateACMEHookFn        func(ctx context.Context, a inventory.Actor, in inventory.ACMEHookInput) (inventory.ACMEHook, error)
	UpdateACMEHookFn        func(ctx context.Context, a inventory.Actor, id uuid.UUID, p inventory.ACMEHookPatch) (inventory.ACMEHook, error)
	DeleteACMEHookFn        func(ctx context.Context, a inventory.Actor, id uuid.UUID) error
	ListACMECertificatesFn  func(ctx context.Context) ([]inventory.ACMECertificate, error)
	GetACMECertificateFn    func(ctx context.Context, id uuid.UUID) (inventory.ACMECertificate, error)
	CreateACMECertificateFn func(ctx context.Context, a inventory.Actor, in inventory.ACMECertificateInput) (inventory.ACMECertificate, error)
	UpdateACMECertificateFn func(ctx context.Context, a inventory.Actor, id uuid.UUID, p inventory.ACMECertificatePatch) (inventory.ACMECertificate, error)
	DeleteACMECertificateFn func(ctx context.Context, a inventory.Actor, id uuid.UUID) error
	RequestOrderFn          func(ctx context.Context, a inventory.Actor, acmeCertificateID uuid.UUID, kind string) (inventory.ACMEOrder, error)
	ListACMEOrdersFn        func(ctx context.Context, acmeCertificateID uuid.UUID, limit int) ([]inventory.ACMEOrder, error)
	ReArmACMEAutoRenewFn    func(ctx context.Context, a inventory.Actor, id uuid.UUID) (inventory.ACMECertificate, error)
	ACMENoticeDeliveryFn    func(ctx context.Context, id uuid.UUID) (*inventory.ACMENoticeDelivery, error)
	ReleaseACMEDeployHoldFn func(ctx context.Context, a inventory.Actor, id uuid.UUID) error
	ListACMEBindingsFn      func(ctx context.Context, id uuid.UUID) ([]inventory.ACMEBinding, error)
	AddACMEBindingFn        func(ctx context.Context, a inventory.Actor, id, location uuid.UUID, autoDeploy, strictSession bool) (inventory.ACMEBinding, error)
	RemoveACMEBindingFn     func(ctx context.Context, a inventory.Actor, id, location uuid.UUID) error
	DeployACMENowFn         func(ctx context.Context, a inventory.Actor, id uuid.UUID, in inventory.ACMEDeployInput) ([]inventory.RequestedDeployment, error)
	DeployACMENowRolloutFn  func(ctx context.Context, a inventory.Actor, id uuid.UUID, in inventory.ACMEDeployInput) ([]inventory.RequestedDeployment, *inventory.Rollout, error)
	RevokeACMECertificateFn func(ctx context.Context, a inventory.Actor, id uuid.UUID, in inventory.ACMERevokeInput) (inventory.Certificate, error)
}

func (f *fakeACME) RevokeACMECertificate(ctx context.Context, a inventory.Actor, id uuid.UUID, in inventory.ACMERevokeInput) (inventory.Certificate, error) {
	if f.RevokeACMECertificateFn != nil {
		return f.RevokeACMECertificateFn(ctx, a, id, in)
	}
	return inventory.Certificate{}, errNotConfigured
}

func (f *fakeACME) ListACMEProviders(ctx context.Context) ([]inventory.ACMEProvider, error) {
	if f.ListACMEProvidersFn != nil {
		return f.ListACMEProvidersFn(ctx)
	}
	return nil, errNotConfigured
}

func (f *fakeACME) GetACMEProvider(ctx context.Context, id uuid.UUID) (inventory.ACMEProvider, error) {
	if f.GetACMEProviderFn != nil {
		return f.GetACMEProviderFn(ctx, id)
	}
	return inventory.ACMEProvider{}, errNotConfigured
}

func (f *fakeACME) CreateACMEProvider(ctx context.Context, a inventory.Actor, in inventory.ACMEProviderInput) (inventory.ACMEProvider, error) {
	if f.CreateACMEProviderFn != nil {
		return f.CreateACMEProviderFn(ctx, a, in)
	}
	return inventory.ACMEProvider{}, errNotConfigured
}

func (f *fakeACME) UpdateACMEProvider(ctx context.Context, a inventory.Actor, id uuid.UUID, p inventory.ACMEProviderPatch) (inventory.ACMEProvider, error) {
	if f.UpdateACMEProviderFn != nil {
		return f.UpdateACMEProviderFn(ctx, a, id, p)
	}
	return inventory.ACMEProvider{}, errNotConfigured
}

func (f *fakeACME) DeleteACMEProvider(ctx context.Context, a inventory.Actor, id uuid.UUID) error {
	if f.DeleteACMEProviderFn != nil {
		return f.DeleteACMEProviderFn(ctx, a, id)
	}
	return errNotConfigured
}

func (f *fakeACME) ListACMEAccounts(ctx context.Context, providerID uuid.UUID) ([]inventory.ACMEAccount, error) {
	if f.ListACMEAccountsFn != nil {
		return f.ListACMEAccountsFn(ctx, providerID)
	}
	return nil, errNotConfigured
}

func (f *fakeACME) RegisterACMEAccountTerms(ctx context.Context, a inventory.Actor, providerID uuid.UUID, contactEmail string, tosAccepted bool,
	acceptedTermsURL string) (inventory.ACMEAccount, error) {
	if f.RegisterACMEAccountFn != nil {
		return f.RegisterACMEAccountFn(ctx, a, providerID, contactEmail, tosAccepted, acceptedTermsURL)
	}
	return inventory.ACMEAccount{}, errNotConfigured
}

func (f *fakeACME) PreviewACMEProvider(ctx context.Context, providerID uuid.UUID) (inventory.ACMEProviderPreview, error) {
	if f.PreviewACMEProviderFn != nil {
		return f.PreviewACMEProviderFn(ctx, providerID)
	}
	return inventory.ACMEProviderPreview{}, errNotConfigured
}

func (f *fakeACME) RolloverACMEAccount(ctx context.Context, a inventory.Actor, accountID uuid.UUID) (inventory.ACMEAccount, error) {
	if f.RolloverACMEAccountFn != nil {
		return f.RolloverACMEAccountFn(ctx, a, accountID)
	}
	return inventory.ACMEAccount{}, errNotConfigured
}

func (f *fakeACME) RecoverACMERollover(ctx context.Context, a inventory.Actor, accountID uuid.UUID) (inventory.ACMEAccount, error) {
	if f.RecoverACMERolloverFn != nil {
		return f.RecoverACMERolloverFn(ctx, a, accountID)
	}
	return inventory.ACMEAccount{}, errNotConfigured
}

func (f *fakeACME) DeactivateACMEAccount(ctx context.Context, a inventory.Actor, accountID uuid.UUID) (inventory.ACMEAccount, error) {
	if f.DeactivateACMEAccountFn != nil {
		return f.DeactivateACMEAccountFn(ctx, a, accountID)
	}
	return inventory.ACMEAccount{}, errNotConfigured
}

func (f *fakeACME) ListACMEHooks(ctx context.Context) ([]inventory.ACMEHook, error) {
	if f.ListACMEHooksFn != nil {
		return f.ListACMEHooksFn(ctx)
	}
	return nil, errNotConfigured
}

func (f *fakeACME) GetACMEHook(ctx context.Context, id uuid.UUID) (inventory.ACMEHook, error) {
	if f.GetACMEHookFn != nil {
		return f.GetACMEHookFn(ctx, id)
	}
	return inventory.ACMEHook{}, errNotConfigured
}

func (f *fakeACME) CreateACMEHook(ctx context.Context, a inventory.Actor, in inventory.ACMEHookInput) (inventory.ACMEHook, error) {
	if f.CreateACMEHookFn != nil {
		return f.CreateACMEHookFn(ctx, a, in)
	}
	return inventory.ACMEHook{}, errNotConfigured
}

func (f *fakeACME) UpdateACMEHook(ctx context.Context, a inventory.Actor, id uuid.UUID, p inventory.ACMEHookPatch) (inventory.ACMEHook, error) {
	if f.UpdateACMEHookFn != nil {
		return f.UpdateACMEHookFn(ctx, a, id, p)
	}
	return inventory.ACMEHook{}, errNotConfigured
}

func (f *fakeACME) DeleteACMEHook(ctx context.Context, a inventory.Actor, id uuid.UUID) error {
	if f.DeleteACMEHookFn != nil {
		return f.DeleteACMEHookFn(ctx, a, id)
	}
	return errNotConfigured
}

func (f *fakeACME) ListACMECertificatesIn(ctx context.Context, _ authz.Reach) ([]inventory.ACMECertificate, error) {
	if f.ListACMECertificatesFn != nil {
		return f.ListACMECertificatesFn(ctx)
	}
	return nil, errNotConfigured
}

func (f *fakeACME) GetACMECertificate(ctx context.Context, id uuid.UUID) (inventory.ACMECertificate, error) {
	if f.GetACMECertificateFn != nil {
		return f.GetACMECertificateFn(ctx, id)
	}
	return inventory.ACMECertificate{}, errNotConfigured
}

func (f *fakeACME) CreateACMECertificate(ctx context.Context, a inventory.Actor, in inventory.ACMECertificateInput) (inventory.ACMECertificate, error) {
	if f.CreateACMECertificateFn != nil {
		return f.CreateACMECertificateFn(ctx, a, in)
	}
	return inventory.ACMECertificate{}, errNotConfigured
}

func (f *fakeACME) UpdateACMECertificate(ctx context.Context, a inventory.Actor, id uuid.UUID, p inventory.ACMECertificatePatch) (inventory.ACMECertificate, error) {
	if f.UpdateACMECertificateFn != nil {
		return f.UpdateACMECertificateFn(ctx, a, id, p)
	}
	return inventory.ACMECertificate{}, errNotConfigured
}

func (f *fakeACME) DeleteACMECertificate(ctx context.Context, a inventory.Actor, id uuid.UUID) error {
	if f.DeleteACMECertificateFn != nil {
		return f.DeleteACMECertificateFn(ctx, a, id)
	}
	return errNotConfigured
}

func (f *fakeACME) RequestOrder(ctx context.Context, a inventory.Actor, acmeCertificateID uuid.UUID, kind string) (inventory.ACMEOrder, error) {
	if f.RequestOrderFn != nil {
		return f.RequestOrderFn(ctx, a, acmeCertificateID, kind)
	}
	return inventory.ACMEOrder{}, errNotConfigured
}

func (f *fakeACME) ListACMEOrders(ctx context.Context, acmeCertificateID uuid.UUID, limit int) ([]inventory.ACMEOrder, error) {
	if f.ListACMEOrdersFn != nil {
		return f.ListACMEOrdersFn(ctx, acmeCertificateID, limit)
	}
	return nil, errNotConfigured
}

func (f *fakeACME) ReArmACMEAutoRenew(ctx context.Context, a inventory.Actor, id uuid.UUID) (inventory.ACMECertificate, error) {
	if f.ReArmACMEAutoRenewFn != nil {
		return f.ReArmACMEAutoRenewFn(ctx, a, id)
	}
	return inventory.ACMECertificate{}, errNotConfigured
}

// ACMENoticeDelivery answers "no e-mail yet" unless the test sets it.
func (f *fakeACME) ACMENoticeDelivery(ctx context.Context, id uuid.UUID) (*inventory.ACMENoticeDelivery, error) {
	if f.ACMENoticeDeliveryFn != nil {
		return f.ACMENoticeDeliveryFn(ctx, id)
	}
	return nil, nil
}

func (f *fakeACME) ReleaseACMEDeployHold(ctx context.Context, a inventory.Actor, id uuid.UUID) error {
	if f.ReleaseACMEDeployHoldFn != nil {
		return f.ReleaseACMEDeployHoldFn(ctx, a, id)
	}
	return errNotConfigured
}

func (f *fakeACME) ListACMEBindings(ctx context.Context, id uuid.UUID) ([]inventory.ACMEBinding, error) {
	if f.ListACMEBindingsFn != nil {
		return f.ListACMEBindingsFn(ctx, id)
	}
	return nil, errNotConfigured
}

func (f *fakeACME) AddACMEBindingStrict(ctx context.Context, a inventory.Actor, id, location uuid.UUID, autoDeploy, strictSession bool) (inventory.ACMEBinding, error) {
	if f.AddACMEBindingFn != nil {
		return f.AddACMEBindingFn(ctx, a, id, location, autoDeploy, strictSession)
	}
	return inventory.ACMEBinding{}, errNotConfigured
}

func (f *fakeACME) RemoveACMEBinding(ctx context.Context, a inventory.Actor, id, location uuid.UUID) error {
	if f.RemoveACMEBindingFn != nil {
		return f.RemoveACMEBindingFn(ctx, a, id, location)
	}
	return errNotConfigured
}

func (f *fakeACME) DeployACMENowWithRollout(ctx context.Context, a inventory.Actor, id uuid.UUID, in inventory.ACMEDeployInput) ([]inventory.RequestedDeployment, *inventory.Rollout, error) {
	if f.DeployACMENowRolloutFn != nil {
		return f.DeployACMENowRolloutFn(ctx, a, id, in)
	}
	got, err := f.DeployACMENow(ctx, a, id, in)
	return got, nil, err
}

func (f *fakeACME) DeployACMENow(ctx context.Context, a inventory.Actor, id uuid.UUID, in inventory.ACMEDeployInput) ([]inventory.RequestedDeployment, error) {
	if f.DeployACMENowFn != nil {
		return f.DeployACMENowFn(ctx, a, id, in)
	}
	return nil, errNotConfigured
}
