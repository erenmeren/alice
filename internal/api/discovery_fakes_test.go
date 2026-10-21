package api

import (
	"context"

	"github.com/google/uuid"

	"alice/internal/authz"
	"alice/internal/discovery"
	"alice/internal/discovery/discoverysvc"
)

// fakeDiscovery implements DiscoveryService. Each method calls its function field when set; otherwise it returns zero
// values and errNotConfigured. actors records the actor of every change.
type fakeDiscovery struct {
	phase7Fake
	actors             []discoverysvc.Actor
	ListScopesFn       func(ctx context.Context, f discoverysvc.ScopeFilter) ([]discoverysvc.ScopeView, bool, error)
	GetScopeFn         func(ctx context.Context, id uuid.UUID) (discoverysvc.ScopeView, error)
	CreateScopeFn      func(ctx context.Context, in discovery.Scope) (discoverysvc.ScopeView, error)
	createService      uuid.UUID // the service CreateScopeIn was given (R49)
	UpdateScopeFn      func(ctx context.Context, id uuid.UUID, ifVersion *int, p discoverysvc.ScopePatch) (discoverysvc.ScopeView, error)
	DeleteScopeFn      func(ctx context.Context, id uuid.UUID, ifVersion *int) error
	PreviewFn          func(ctx context.Context, sc discovery.Scope) (discovery.Preview, error)
	StartScanFn        func(ctx context.Context, scopeID uuid.UUID) (discoverysvc.ScanView, error)
	CancelScanFn       func(ctx context.Context, id uuid.UUID) (discoverysvc.ScanView, error)
	GetScanFn          func(ctx context.Context, id uuid.UUID) (discoverysvc.ScanView, error)
	ListScansFn        func(ctx context.Context, f discoverysvc.ScanFilter) ([]discoverysvc.ScanView, bool, error)
	ListCertificatesFn func(ctx context.Context, f discovery.CertificateFilter) ([]discovery.CertificateRow, bool, error)
	CertificateFn      func(ctx context.Context, fp string) (discovery.CertificateRow, []discovery.EndpointRow, bool, error)
	ListEndpointsFn    func(ctx context.Context, f discovery.EndpointFilter) ([]discovery.EndpointRow, bool, error)
	SettingsFn         func(ctx context.Context) (discoverysvc.SettingsView, error)
	SaveSettingsFn     func(ctx context.Context, in discoverysvc.Settings) (discoverysvc.SettingsView, error)
	SummaryFn          func(ctx context.Context) (discoverysvc.Summary, error)
}

func (f *fakeDiscovery) actor(a discoverysvc.Actor) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.actors = append(f.actors, a)
}

func (f *fakeDiscovery) lastActor() discoverysvc.Actor {
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.actors) == 0 {
		return discoverysvc.Actor{}
	}
	return f.actors[len(f.actors)-1]
}

func (f *fakeDiscovery) ListScopes(ctx context.Context, fl discoverysvc.ScopeFilter) ([]discoverysvc.ScopeView, bool, error) {
	f.record()
	if f.ListScopesFn != nil {
		return f.ListScopesFn(ctx, fl)
	}
	return nil, false, errNotConfigured
}

func (f *fakeDiscovery) GetScope(ctx context.Context, id uuid.UUID) (discoverysvc.ScopeView, error) {
	f.record()
	if f.GetScopeFn != nil {
		return f.GetScopeFn(ctx, id)
	}
	return discoverysvc.ScopeView{}, errNotConfigured
}

func (f *fakeDiscovery) CreateScopeIn(ctx context.Context, a discoverysvc.Actor, in discovery.Scope, service uuid.UUID) (discoverysvc.ScopeView, error) {
	f.record()
	f.actor(a)
	f.createService = service
	if f.CreateScopeFn != nil {
		return f.CreateScopeFn(ctx, in)
	}
	return discoverysvc.ScopeView{}, errNotConfigured
}

func (f *fakeDiscovery) UpdateScope(ctx context.Context, a discoverysvc.Actor, id uuid.UUID, ifVersion *int, p discoverysvc.ScopePatch) (discoverysvc.ScopeView, error) {
	f.record()
	f.actor(a)
	if f.UpdateScopeFn != nil {
		return f.UpdateScopeFn(ctx, id, ifVersion, p)
	}
	return discoverysvc.ScopeView{}, errNotConfigured
}

func (f *fakeDiscovery) DeleteScope(ctx context.Context, a discoverysvc.Actor, id uuid.UUID, ifVersion *int) error {
	f.record()
	f.actor(a)
	if f.DeleteScopeFn != nil {
		return f.DeleteScopeFn(ctx, id, ifVersion)
	}
	return errNotConfigured
}

func (f *fakeDiscovery) Preview(ctx context.Context, sc discovery.Scope) (discovery.Preview, error) {
	f.record()
	if f.PreviewFn != nil {
		return f.PreviewFn(ctx, sc)
	}
	return discovery.Preview{}, errNotConfigured
}

func (f *fakeDiscovery) StartScan(ctx context.Context, a discoverysvc.Actor, scopeID uuid.UUID) (discoverysvc.ScanView, error) {
	f.record()
	f.actor(a)
	if f.StartScanFn != nil {
		return f.StartScanFn(ctx, scopeID)
	}
	return discoverysvc.ScanView{}, errNotConfigured
}

func (f *fakeDiscovery) CancelScan(ctx context.Context, a discoverysvc.Actor, id uuid.UUID) (discoverysvc.ScanView, error) {
	f.record()
	f.actor(a)
	if f.CancelScanFn != nil {
		return f.CancelScanFn(ctx, id)
	}
	return discoverysvc.ScanView{}, errNotConfigured
}

func (f *fakeDiscovery) GetScan(ctx context.Context, id uuid.UUID) (discoverysvc.ScanView, error) {
	f.record()
	if f.GetScanFn != nil {
		return f.GetScanFn(ctx, id)
	}
	return discoverysvc.ScanView{}, errNotConfigured
}

func (f *fakeDiscovery) ListScans(ctx context.Context, fl discoverysvc.ScanFilter) ([]discoverysvc.ScanView, bool, error) {
	f.record()
	if f.ListScansFn != nil {
		return f.ListScansFn(ctx, fl)
	}
	return nil, false, errNotConfigured
}

func (f *fakeDiscovery) ListCertificates(ctx context.Context, fl discovery.CertificateFilter) ([]discovery.CertificateRow, bool, error) {
	f.record()
	if f.ListCertificatesFn != nil {
		return f.ListCertificatesFn(ctx, fl)
	}
	return nil, false, errNotConfigured
}

func (f *fakeDiscovery) CertificateIn(ctx context.Context, fp string, _ authz.Reach) (discovery.CertificateRow, []discovery.EndpointRow, bool, error) {
	f.record()
	if f.CertificateFn != nil {
		return f.CertificateFn(ctx, fp)
	}
	return discovery.CertificateRow{}, nil, false, errNotConfigured
}

func (f *fakeDiscovery) ListEndpoints(ctx context.Context, fl discovery.EndpointFilter) ([]discovery.EndpointRow, bool, error) {
	f.record()
	if f.ListEndpointsFn != nil {
		return f.ListEndpointsFn(ctx, fl)
	}
	return nil, false, errNotConfigured
}

func (f *fakeDiscovery) Settings(ctx context.Context) (discoverysvc.SettingsView, error) {
	f.record()
	if f.SettingsFn != nil {
		return f.SettingsFn(ctx)
	}
	return discoverysvc.SettingsView{}, errNotConfigured
}

func (f *fakeDiscovery) SaveSettings(ctx context.Context, a discoverysvc.Actor, in discoverysvc.Settings) (discoverysvc.SettingsView, error) {
	f.record()
	f.actor(a)
	if f.SaveSettingsFn != nil {
		return f.SaveSettingsFn(ctx, in)
	}
	return discoverysvc.SettingsView{}, errNotConfigured
}

func (f *fakeDiscovery) SummaryIn(ctx context.Context, _ authz.Reach) (discoverysvc.Summary, error) {
	f.record()
	if f.SummaryFn != nil {
		return f.SummaryFn(ctx)
	}
	return discoverysvc.Summary{}, errNotConfigured
}
