package api

import (
	"context"
	"net/http"
	"strconv"
	"time"

	"github.com/google/uuid"

	"alice/internal/inventory"
	"alice/internal/license"
	"alice/internal/platform/validate"
	"alice/internal/rbac"
)

// Revocation, the impact of a certificate, the per-source capability matrix and key-compromise incidents (owner decision
// 2026-10-20, docs/superpowers/rulings/certificate-revocation.md).
//
// Revoking an ACME certificate at its CA is acme.manage (an Administrator with a fresh step-up, never a token), a
// licence change, and limited like the other CA calls (limitACME). Reading the impact, the capability matrix and the
// incidents is Read (every role and read tokens) — except the endpoints of network discovery in an impact, which only a
// caller with discovery.view sees (the internal network map, D7: read tokens never do). Starting an incident and acting
// on one is certificates.incident (an Administrator with a fresh step-up, never a token) and a licence change; closing
// one changes nothing on a server or a CA, so it is ClassAlways.

// IncidentService is the part of inventory.Service the incident routes use.
type IncidentService interface {
	CertificateImpact(ctx context.Context, id uuid.UUID) (inventory.CertificateImpact, error)
	StartIncident(ctx context.Context, a inventory.Actor, certificateID uuid.UUID, in inventory.IncidentInput) (inventory.Incident, error)
	GetIncident(ctx context.Context, id uuid.UUID) (inventory.Incident, error)
	ListIncidents(ctx context.Context, certificateID *uuid.UUID, openOnly bool, limit int) ([]inventory.Incident, error)
	RetryIncident(ctx context.Context, a inventory.Actor, id uuid.UUID) (inventory.Incident, error)
	RevokeIncidentNow(ctx context.Context, a inventory.Actor, id uuid.UUID) (inventory.Incident, error)
	ChooseIncidentReplacement(ctx context.Context, a inventory.Actor, id, certificateID uuid.UUID) (inventory.Incident, error)
	CloseIncident(ctx context.Context, a inventory.Actor, id uuid.UUID) (inventory.Incident, error)
}

var _ IncidentService = (*inventory.Service)(nil)

// Body caps of the revocation and incident requests.
const (
	maxRevokeBody   = 1 << 10
	maxIncidentBody = 1 << 10
)

func (s *server) incidentRoutes() []route {
	const incidents = "/api/v1/incidents"
	incident, change, always := rbac.CertificatesIncident, license.ClassChange, license.ClassAlways
	return []route{
		{method: http.MethodGet, pattern: "/api/v1/certificates/capabilities", scope: scopeAny, perm: rbac.Read, handler: s.certificateCapabilities},
		{method: http.MethodGet, pattern: "/api/v1/certificate-impact/{id}", scope: scopeResource, perm: rbac.Read, handler: s.certificateImpact},
		{method: http.MethodPost, pattern: "/api/v1/certificates/{id}/incidents", scope: scopeCross, perm: incident, lic: change, handler: s.startIncident},
		{method: http.MethodGet, pattern: incidents, scope: scopeList, perm: rbac.Read, handler: s.listIncidents},
		{method: http.MethodGet, pattern: incidents + "/{id}", scope: scopeResource, perm: rbac.Read, handler: s.getIncident},
		{method: http.MethodPost, pattern: incidents + "/{id}/retry", scope: scopeCross, perm: incident, lic: change, handler: s.incidentAction(actRetry)},
		{method: http.MethodPost, pattern: incidents + "/{id}/revoke-now", scope: scopeCross, perm: incident, lic: change, limit: limitACME,
			handler: s.incidentAction(actRevokeNow)},
		{method: http.MethodPost, pattern: incidents + "/{id}/replacement", scope: scopeCross, perm: incident, lic: change, handler: s.chooseReplacement},
		{method: http.MethodPost, pattern: incidents + "/{id}/close", scope: scopeCross, perm: incident, lic: always, handler: s.incidentAction(actClose)},
	}
}

// revokeACME revokes a version of an ACME certificate at its CA (none named: the current certificate) with an RFC 5280
// reason; 200 with the certificate as it is now.
func (s *server) revokeACME(w http.ResponseWriter, r *http.Request) {
	refs := s.serviceRefs(r)
	id, ok := pathUUID(r, "id")
	if !ok {
		s.writeError(w, r, ErrNotFound)
		return
	}
	var req struct {
		CertificateID *string `json:"certificate_id"`
		Reason        string  `json:"reason"`
	}
	if !s.decodeExact(w, r, &req, maxRevokeBody, "certificate_id", "reason") {
		return
	}
	var v validate.Errors
	version := parseOptionalID(req.CertificateID, "certificate_id", &v)
	if err := v.Err(); err != nil {
		s.fail(w, r, err)
		return
	}
	c, err := s.deps.ACME.RevokeACMECertificate(r.Context(), s.actor(r), id, inventory.ACMERevokeInput{CertificateID: version, Reason: req.Reason})
	if err != nil {
		s.fail(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, certificateJSON(c, refs))
}

type sourceCapabilitiesDTO struct {
	Source       string   `json:"source"`
	Capabilities []string `json:"capabilities"`
}

// certificateCapabilities is the per-source capability matrix, in source order.
func (s *server) certificateCapabilities(w http.ResponseWriter, _ *http.Request) {
	m := inventory.SourceCapabilityMatrix()
	items := []sourceCapabilitiesDTO{}
	for _, src := range []string{"acme", "azure_kv", "uploaded", "csr", "discovered"} {
		items = append(items, sourceCapabilitiesDTO{Source: src, Capabilities: capabilityNames(m[src])})
	}
	all := capabilityNames(inventory.SourceCapabilities())
	writeJSON(w, http.StatusOK, map[string]any{"capabilities": all, "sources": items})
}

type impactCertificateDTO struct {
	ID            string     `json:"id"`
	Fingerprint   string     `json:"fingerprint"`
	SubjectCN     string     `json:"subject_cn"`
	Label         string     `json:"label"`
	Source        string     `json:"source"`
	NotAfter      time.Time  `json:"not_after"`
	RevokedAt     *time.Time `json:"revoked_at"`
	CompromisedAt *time.Time `json:"compromised_at"`
	Match         string     `json:"match"`
}

type impactLocationDTO struct {
	LocationID        string  `json:"location_id"`
	TargetID          string  `json:"target_id"`
	TargetName        string  `json:"target_name"`
	TargetType        string  `json:"target_type"`
	CertPath          string  `json:"cert_path"`
	CertificateID     *string `json:"certificate_id"`
	Fingerprint       string  `json:"fingerprint"`
	Match             string  `json:"match"`
	Deployable        bool    `json:"deployable"`
	ACMECertificateID *string `json:"acme_certificate_id"`
	KVBound           bool    `json:"kv_bound"`
}

type impactVaultDTO struct {
	VaultID         string `json:"vault_id"`
	VaultName       string `json:"vault_name"`
	KVCertificateID string `json:"kv_certificate_id"`
	Name            string `json:"name"`
	Version         string `json:"version"`
	CertificateID   string `json:"certificate_id"`
	Current         bool   `json:"current"`
	Match           string `json:"match"`
}

type impactEndpointDTO struct {
	EndpointID  string     `json:"endpoint_id"`
	ScopeID     string     `json:"scope_id"`
	ScopeName   string     `json:"scope_name"`
	Address     string     `json:"address"`
	Port        int        `json:"port"`
	SNI         string     `json:"sni"`
	Host        string     `json:"host"`
	Fingerprint string     `json:"fingerprint"`
	State       string     `json:"state"`
	LastSeen    *time.Time `json:"last_seen"`
	Match       string     `json:"match"`
}

type impactDTO struct {
	Certificate     certificateDTO         `json:"certificate"`
	Certificates    []impactCertificateDTO `json:"certificates"`
	Locations       []impactLocationDTO    `json:"locations"`
	Vaults          []impactVaultDTO       `json:"vaults"`
	Endpoints       []impactEndpointDTO    `json:"endpoints"`
	EndpointsHidden bool                   `json:"endpoints_hidden"`
	Truncated       bool                   `json:"truncated"`
	OpenIncidentID  *string                `json:"open_incident_id"`
}

func impactJSON(m inventory.CertificateImpact, showEndpoints bool) impactDTO {
	d := impactDTO{Certificate: certificateJSON(m.Certificate, nil), Certificates: []impactCertificateDTO{}, Locations: []impactLocationDTO{},
		Vaults: []impactVaultDTO{}, Endpoints: []impactEndpointDTO{}, EndpointsHidden: !showEndpoints, Truncated: m.Truncated,
		OpenIncidentID: idPtr(m.OpenIncidentID)}
	for _, c := range m.Certificates {
		d.Certificates = append(d.Certificates, impactCertificateDTO{ID: c.ID.String(), Fingerprint: c.Fingerprint, SubjectCN: c.SubjectCN,
			Label: c.Label, Source: c.Source, NotAfter: c.NotAfter.UTC(), RevokedAt: utcPtr(c.RevokedAt), CompromisedAt: utcPtr(c.CompromisedAt),
			Match: c.Match})
	}
	for _, l := range m.Locations {
		d.Locations = append(d.Locations, impactLocationDTO{LocationID: l.LocationID.String(), TargetID: l.TargetID.String(),
			TargetName: l.TargetName, TargetType: l.TargetType, CertPath: l.CertPath, CertificateID: idPtr(l.CertificateID),
			Fingerprint: l.Fingerprint, Match: l.Match, Deployable: l.Deployable, ACMECertificateID: idPtr(l.ACMECertificateID), KVBound: l.KVBound})
	}
	for _, v := range m.Vaults {
		d.Vaults = append(d.Vaults, impactVaultDTO{VaultID: v.VaultID.String(), VaultName: v.VaultName, KVCertificateID: v.KVCertificateID.String(),
			Name: v.Name, Version: v.Version, CertificateID: v.CertificateID.String(), Current: v.Current, Match: v.Match})
	}
	if showEndpoints {
		for _, e := range m.Endpoints {
			d.Endpoints = append(d.Endpoints, impactEndpointDTO{EndpointID: e.EndpointID.String(), ScopeID: e.ScopeID.String(), ScopeName: e.ScopeName,
				Address: e.Address.String(), Port: e.Port, SNI: e.SNI, Host: e.Host, Fingerprint: e.Fingerprint, State: e.State,
				LastSeen: utcPtr(e.LastSeen), Match: e.Match})
		}
	}
	return d
}

// certificateImpact is where the certificate, or another certificate with its key, is deployed or was found.
func (s *server) certificateImpact(w http.ResponseWriter, r *http.Request) {
	id, ok := pathUUID(r, "id")
	if !ok {
		s.writeError(w, r, ErrNotFound)
		return
	}
	m, err := s.deps.Incidents.CertificateImpact(r.Context(), id)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	show := rbac.Decide(rbac.DiscoveryView, principalFrom(r.Context()).Subject(s.deps.Clock.Now())) == rbac.Allow
	writeJSON(w, http.StatusOK, impactJSON(m, show))
}

type incidentLocationDTO struct {
	LocationID   string       `json:"location_id"`
	TargetID     string       `json:"target_id"`
	TargetName   string       `json:"target_name"`
	CertPath     string       `json:"cert_path"`
	Status       string       `json:"status"`
	DeploymentID *string      `json:"deployment_id"`
	Error        *errorRefDTO `json:"error"`
	Attempts     int          `json:"attempts"`
	UpdatedAt    time.Time    `json:"updated_at"`
	// OutcomeUncertain: sent, not confirmed (R48); error is then why, when the deployment knows.
	OutcomeUncertain bool `json:"outcome_uncertain"`
}

type incidentDTO struct {
	ID                       string                 `json:"id"`
	CertificateID            string                 `json:"certificate_id"`
	CertificateName          string                 `json:"certificate_name"`
	Fingerprint              string                 `json:"fingerprint"`
	Source                   string                 `json:"source"`
	PublicKeySHA256          string                 `json:"public_key_sha256"`
	ACMECertificateID        *string                `json:"acme_certificate_id"`
	State                    string                 `json:"state"`
	RevokeMode               string                 `json:"revoke_mode"`
	Revocation               string                 `json:"revocation"`
	OrderID                  *string                `json:"order_id"`
	OrderState               string                 `json:"order_state"`
	ReplacementCertificateID *string                `json:"replacement_certificate_id"`
	ReplacementFingerprint   string                 `json:"replacement_fingerprint"`
	Attention                *errorRefDTO           `json:"attention"`
	RevokeAttempts           int                    `json:"revoke_attempts"`
	NextAttemptAt            *time.Time             `json:"next_attempt_at"`
	RevokedAt                *time.Time             `json:"revoked_at"`
	StartedBy                *string                `json:"started_by"`
	StartedByName            string                 `json:"started_by_name"`
	ClosedBy                 *string                `json:"closed_by"`
	CreatedAt                time.Time              `json:"created_at"`
	UpdatedAt                time.Time              `json:"updated_at"`
	FinishedAt               *time.Time             `json:"finished_at"`
	Counts                   map[string]int         `json:"counts"`
	Locations                *[]incidentLocationDTO `json:"locations,omitempty"` // GET /incidents/{id} and the actions only
}

func incidentJSON(i inventory.Incident, withLocations bool) incidentDTO {
	d := incidentDTO{ID: i.ID.String(), CertificateID: i.CertificateID.String(), CertificateName: i.CertificateName, Fingerprint: i.Fingerprint,
		Source: i.Source, PublicKeySHA256: i.PublicKeySHA256, ACMECertificateID: idPtr(i.ACMECertificateID), State: i.State,
		RevokeMode: i.RevokeMode, Revocation: i.Revocation, OrderID: idPtr(i.OrderID), OrderState: i.OrderState,
		ReplacementCertificateID: idPtr(i.ReplacementCertificateID), ReplacementFingerprint: i.ReplacementFingerprint,
		RevokeAttempts: i.RevokeAttempts, NextAttemptAt: utcPtr(i.NextAttemptAt), RevokedAt: utcPtr(i.RevokedAt), StartedBy: idPtr(i.StartedBy),
		StartedByName: i.StartedByName, ClosedBy: idPtr(i.ClosedBy), CreatedAt: i.CreatedAt.UTC(), UpdatedAt: i.UpdatedAt.UTC(),
		FinishedAt: utcPtr(i.FinishedAt), Counts: map[string]int{}}
	if i.AttentionCode != "" {
		d.Attention = errorRef(i.AttentionCode, nil)
	}
	for k, v := range i.Counts {
		d.Counts[k] = v
	}
	if withLocations {
		list := make([]incidentLocationDTO, 0, len(i.Locations))
		for _, l := range i.Locations {
			x := incidentLocationDTO{LocationID: l.LocationID.String(), TargetID: l.TargetID.String(), TargetName: l.TargetName, CertPath: l.CertPath,
				Status: l.Status, DeploymentID: idPtr(l.DeploymentID), Attempts: l.Attempts, UpdatedAt: l.UpdatedAt.UTC(), OutcomeUncertain: l.OutcomeUncertain}
			switch {
			case l.ErrorCode != "":
				x.Error = errorRef(l.ErrorCode, nil)
			case l.OutcomeUncertain && l.UncertainCode != "":
				x.Error = errorRef(l.UncertainCode, nil)
			}
			list = append(list, x)
		}
		d.Locations = &list
	}
	return d
}

// startIncident starts a key-compromise incident for the certificate; 201 with the incident.
func (s *server) startIncident(w http.ResponseWriter, r *http.Request) {
	id, ok := pathUUID(r, "id")
	if !ok {
		s.writeError(w, r, ErrNotFound)
		return
	}
	var req struct {
		RevokeMode string `json:"revoke_mode"`
	}
	if !s.decodeExactOptional(w, r, &req, maxIncidentBody, "revoke_mode") {
		return
	}
	i, err := s.deps.Incidents.StartIncident(r.Context(), s.actor(r), id, inventory.IncidentInput{RevokeMode: req.RevokeMode})
	if err != nil {
		s.fail(w, r, err)
		return
	}
	w.Header().Set("Location", "/api/v1/incidents/"+i.ID.String())
	writeJSON(w, http.StatusCreated, incidentJSON(i, true))
}

// listIncidents is the newest incidents (?open=true: open ones only; ?certificate_id=: of one certificate; ?limit=
// 1..200, default 50).
func (s *server) listIncidents(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	var v validate.Errors
	limit := 0
	if raw := q.Get("limit"); raw != "" {
		n, err := strconv.Atoi(raw)
		if err != nil || n < 1 || n > inventory.MaxIncidentsListed {
			v.Add("limit", validate.OutOfRange, map[string]string{"min": "1", "max": strconv.Itoa(inventory.MaxIncidentsListed)})
		}
		limit = n
	}
	open := false
	switch q.Get("open") {
	case "", "false":
	case "true":
		open = true
	default:
		v.Add("open", validate.OneOf, map[string]string{"values": "true, false"})
	}
	var cert *uuid.UUID
	if raw := q.Get("certificate_id"); raw != "" {
		cert = parseOptionalID(&raw, "certificate_id", &v)
	}
	if err := v.Err(); err != nil {
		s.fail(w, r, err)
		return
	}
	list, err := s.deps.Incidents.ListIncidents(r.Context(), cert, open, limit)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	items := make([]incidentDTO, 0, len(list))
	for _, i := range list {
		items = append(items, incidentJSON(i, false))
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": items})
}

func (s *server) getIncident(w http.ResponseWriter, r *http.Request) {
	id, ok := pathUUID(r, "id")
	if !ok {
		s.writeError(w, r, ErrNotFound)
		return
	}
	i, err := s.deps.Incidents.GetIncident(r.Context(), id)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, incidentJSON(i, true))
}

// The actions without a body.
const (
	actRetry = iota
	actRevokeNow
	actClose
)

func (s *server) incidentAction(act int) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		id, ok := pathUUID(r, "id")
		if !ok {
			s.writeError(w, r, ErrNotFound)
			return
		}
		if !s.decodeExactOptional(w, r, &struct{}{}, maxIncidentBody) {
			return
		}
		var (
			i   inventory.Incident
			err error
		)
		switch act {
		case actRetry:
			i, err = s.deps.Incidents.RetryIncident(r.Context(), s.actor(r), id)
		case actRevokeNow:
			i, err = s.deps.Incidents.RevokeIncidentNow(r.Context(), s.actor(r), id)
		default:
			i, err = s.deps.Incidents.CloseIncident(r.Context(), s.actor(r), id)
		}
		if err != nil {
			s.fail(w, r, err)
			return
		}
		writeJSON(w, http.StatusOK, incidentJSON(i, true))
	}
}

// chooseReplacement sets the replacement of an incident of a certificate from another source.
func (s *server) chooseReplacement(w http.ResponseWriter, r *http.Request) {
	id, ok := pathUUID(r, "id")
	if !ok {
		s.writeError(w, r, ErrNotFound)
		return
	}
	var req struct {
		CertificateID string `json:"certificate_id"`
	}
	if !s.decodeExact(w, r, &req, maxIncidentBody, "certificate_id") {
		return
	}
	var v validate.Errors
	cert := parseOptionalID(&req.CertificateID, "certificate_id", &v)
	if cert == nil && len(v) == 0 {
		v.Add("certificate_id", validate.Required, nil)
	}
	if err := v.Err(); err != nil {
		s.fail(w, r, err)
		return
	}
	i, err := s.deps.Incidents.ChooseIncidentReplacement(r.Context(), s.actor(r), id, *cert)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, incidentJSON(i, true))
}
