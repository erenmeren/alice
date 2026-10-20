package api

import (
	"context"

	"github.com/google/uuid"

	"alice/internal/inventory"
)

// fakeIncidents is the IncidentService of the handler tests: every method answers errNotConfigured unless its Fn is set.
type fakeIncidents struct {
	CertificateImpactFn         func(ctx context.Context, id uuid.UUID) (inventory.CertificateImpact, error)
	StartIncidentFn             func(ctx context.Context, a inventory.Actor, certificateID uuid.UUID, in inventory.IncidentInput) (inventory.Incident, error)
	GetIncidentFn               func(ctx context.Context, id uuid.UUID) (inventory.Incident, error)
	ListIncidentsFn             func(ctx context.Context, certificateID *uuid.UUID, openOnly bool, limit int) ([]inventory.Incident, error)
	RetryIncidentFn             func(ctx context.Context, a inventory.Actor, id uuid.UUID) (inventory.Incident, error)
	RevokeIncidentNowFn         func(ctx context.Context, a inventory.Actor, id uuid.UUID) (inventory.Incident, error)
	ChooseIncidentReplacementFn func(ctx context.Context, a inventory.Actor, id, certificateID uuid.UUID) (inventory.Incident, error)
	CloseIncidentFn             func(ctx context.Context, a inventory.Actor, id uuid.UUID) (inventory.Incident, error)
}

func (f *fakeIncidents) CertificateImpact(ctx context.Context, id uuid.UUID) (inventory.CertificateImpact, error) {
	if f.CertificateImpactFn != nil {
		return f.CertificateImpactFn(ctx, id)
	}
	return inventory.CertificateImpact{}, errNotConfigured
}

func (f *fakeIncidents) StartIncident(ctx context.Context, a inventory.Actor, certificateID uuid.UUID, in inventory.IncidentInput) (inventory.Incident, error) {
	if f.StartIncidentFn != nil {
		return f.StartIncidentFn(ctx, a, certificateID, in)
	}
	return inventory.Incident{}, errNotConfigured
}

func (f *fakeIncidents) GetIncident(ctx context.Context, id uuid.UUID) (inventory.Incident, error) {
	if f.GetIncidentFn != nil {
		return f.GetIncidentFn(ctx, id)
	}
	return inventory.Incident{}, errNotConfigured
}

func (f *fakeIncidents) ListIncidents(ctx context.Context, certificateID *uuid.UUID, openOnly bool, limit int) ([]inventory.Incident, error) {
	if f.ListIncidentsFn != nil {
		return f.ListIncidentsFn(ctx, certificateID, openOnly, limit)
	}
	return nil, errNotConfigured
}

func (f *fakeIncidents) RetryIncident(ctx context.Context, a inventory.Actor, id uuid.UUID) (inventory.Incident, error) {
	if f.RetryIncidentFn != nil {
		return f.RetryIncidentFn(ctx, a, id)
	}
	return inventory.Incident{}, errNotConfigured
}

func (f *fakeIncidents) RevokeIncidentNow(ctx context.Context, a inventory.Actor, id uuid.UUID) (inventory.Incident, error) {
	if f.RevokeIncidentNowFn != nil {
		return f.RevokeIncidentNowFn(ctx, a, id)
	}
	return inventory.Incident{}, errNotConfigured
}

func (f *fakeIncidents) ChooseIncidentReplacement(ctx context.Context, a inventory.Actor, id, certificateID uuid.UUID) (inventory.Incident, error) {
	if f.ChooseIncidentReplacementFn != nil {
		return f.ChooseIncidentReplacementFn(ctx, a, id, certificateID)
	}
	return inventory.Incident{}, errNotConfigured
}

func (f *fakeIncidents) CloseIncident(ctx context.Context, a inventory.Actor, id uuid.UUID) (inventory.Incident, error) {
	if f.CloseIncidentFn != nil {
		return f.CloseIncidentFn(ctx, a, id)
	}
	return inventory.Incident{}, errNotConfigured
}
