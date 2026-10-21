package api

// Certificate drift (R52, docs/superpowers/rulings/certificate-drift.md): what a bound location should have, what Alice
// last deployed there and what is observed today, the health derived from it, the repair mode and the one-action
// repair.

import (
	"net/http"
	"slices"
	"time"

	"alice/internal/authz/services"
	"alice/internal/inventory"
	"alice/internal/license"
	"alice/internal/providers"
	"alice/internal/rbac"
)

// driftRoutes are the repair mode of a bound location and its repair. Choosing a mode changes nothing on a server
// (certificates.operate, as editing a binding); choosing automatic repair is switching unattended deployment on: the
// inventory refuses it unless an Administrator's browser session with a fresh step-up asks (the rule of switching
// automatic deployment on) and the licence allows changes. The repair is a person's deployment (certificates.operate,
// refused in lock).
func (s *server) driftRoutes() []route {
	return []route{
		{method: http.MethodPut, pattern: "/api/v1/locations/{id}/drift-mode", scope: scopeResource, resolve: by(services.KindLocation, "id"), perm: rbac.CertificatesOperate, lic: license.ClassChange,
			handler: s.putDriftMode},
		{method: http.MethodPost, pattern: "/api/v1/locations/{id}/actions/repair", scope: scopeResource, resolve: by(services.KindLocation, "id"), perm: rbac.CertificatesOperate, lic: license.ClassChange,
			handler: s.repairDrift},
	}
}

// maxDriftModeBody bounds the drift mode body ({"mode": "..."}); the repair takes none.
const maxDriftModeBody = 1 << 10

// observedCertDTO is a certificate an observation names: its fingerprint and, when Alice holds it, its id and end.
type observedCertDTO struct {
	CertificateID *string    `json:"certificate_id"`
	Fingerprint   string     `json:"fingerprint"`
	NotAfter      *time.Time `json:"not_after"`
}

// lastDeploymentDTO is the newest succeeded or unchanged deployment to the location and the level it proved (R51).
type lastDeploymentDTO struct {
	DeploymentID string     `json:"deployment_id"`
	Fingerprint  string     `json:"fingerprint"`
	FinishedAt   *time.Time `json:"finished_at"`
	Level        int        `json:"level"`
}

// fileObservationDTO is what the last scan that read the file found in it (fingerprint "" when the file holds no
// certificate), when (observed_at: never the time of a scan that could not read the file), and when a scan found a
// change outside Alice.
type fileObservationDTO struct {
	observedCertDTO
	ObservedAt       time.Time  `json:"observed_at"`
	ChangedOutsideAt *time.Time `json:"changed_outside_at"`
}

// tlsObservationDTO is what the websites served at the last probe that completed a handshake, when, from where (alice:
// Alice's own probe; helper: the server itself), the level (served or trusted when the desired certificate was served,
// 0 otherwise) and the served chain's trust ("" when not measured).
type tlsObservationDTO struct {
	observedCertDTO
	ObservedAt time.Time `json:"observed_at"`
	Probe      string    `json:"probe"`
	Level      int       `json:"level"`
	Trust      string    `json:"trust"`
	TrustError string    `json:"trust_error"`
}

// locationObservationDTO is the observation model of a bound location (R52).
type locationObservationDTO struct {
	Health             string              `json:"health"`
	Source             string              `json:"source"`
	SourceID           *string             `json:"source_id"`
	Desired            *observedCertDTO    `json:"desired"`
	LastDeployment     *lastDeploymentDTO  `json:"last_deployment"`
	File               *fileObservationDTO `json:"file"`
	TLS                *tlsObservationDTO  `json:"tls"`
	TLSAttemptedAt     *time.Time          `json:"tls_attempted_at"`
	TLSError           *errorRefDTO        `json:"tls_error"`
	Mode               string              `json:"mode"`
	ModeSetting        string              `json:"mode_setting"`
	DefaultMode        string              `json:"default_mode"`
	DriftSince         *time.Time          `json:"drift_since"`
	DriftFingerprint   string              `json:"drift_fingerprint"`
	DriftSource        string              `json:"drift_source"`
	BackoffReason      string              `json:"backoff_reason"`
	BackedOffAt        *time.Time          `json:"backed_off_at"`
	ActiveDeploymentID *string             `json:"active_deployment_id"`
	NextObserveAt      *time.Time          `json:"next_observe_at"`
	RepairAvailable    bool                `json:"repair_available"`
}

func observedCertJSON(c inventory.ObservedCertificate) observedCertDTO {
	return observedCertDTO{CertificateID: idPtr(c.CertificateID), Fingerprint: c.Fingerprint, NotAfter: utcPtr(c.NotAfter)}
}

// observationJSON renders o; a value outside its closed list reads as not measured (a health outside the list as
// stale).
func observationJSON(o *inventory.LocationObservation) *locationObservationDTO {
	if o == nil {
		return nil
	}
	d := &locationObservationDTO{Health: o.Health, Source: o.Source, SourceID: idPtr(o.SourceID), TLSAttemptedAt: utcPtr(o.TLSAttemptAt),
		Mode: o.Mode, ModeSetting: o.ModeSetting, DefaultMode: o.DefaultMode, DriftSince: utcPtr(o.DriftSince), DriftFingerprint: o.DriftFingerprint,
		DriftSource: o.DriftSource, BackoffReason: o.BackoffReason, BackedOffAt: utcPtr(o.BackedOffAt), ActiveDeploymentID: idPtr(o.ActiveDeploymentID),
		NextObserveAt: utcPtr(o.NextObserveAt), RepairAvailable: o.Health == inventory.HealthDrifted}
	if !slices.Contains(inventory.HealthStates, d.Health) {
		d.Health = inventory.HealthStale
	}
	if d.ModeSetting == "" {
		d.ModeSetting = inventory.DriftModeDefault
	}
	if o.Desired != nil {
		c := observedCertJSON(*o.Desired)
		d.Desired = &c
	}
	if l := o.LastDeployment; l != nil {
		d.LastDeployment = &lastDeploymentDTO{DeploymentID: l.DeploymentID.String(), Fingerprint: l.Fingerprint, FinishedAt: utcPtr(l.At),
			Level: min(max(l.Level, providers.LevelNone), providers.LevelTrusted)}
	}
	if f := o.File; f != nil {
		d.File = &fileObservationDTO{observedCertDTO: observedCertJSON(f.ObservedCertificate), ObservedAt: f.At.UTC(),
			ChangedOutsideAt: utcPtr(f.ChangedOutsideAt)}
	}
	if t := o.TLS; t != nil {
		d.TLS = &tlsObservationDTO{observedCertDTO: observedCertJSON(t.ObservedCertificate), ObservedAt: t.At.UTC(), Probe: t.Probe,
			Level: min(max(t.Level, providers.LevelNone), providers.LevelTrusted), Trust: t.Trust}
		if slices.Contains(providers.TrustErrors, t.TrustError) {
			d.TLS.TrustError = t.TrustError
		}
	}
	if o.TLSError != "" {
		d.TLSError = errorRef(o.TLSError, nil)
	}
	return d
}

// putDriftMode sets the repair mode of a bound location: observe, approve, auto or default (the binding's default:
// auto when automatic deployment is on for it, observe otherwise). The inventory decides whether this session may
// switch automatic repair on (an Administrator with a fresh step-up, never an API token, and the licence).
func (s *server) putDriftMode(w http.ResponseWriter, r *http.Request) {
	id, ok := pathUUID(r, "id")
	if !ok {
		s.writeError(w, r, ErrNotFound)
		return
	}
	var req struct {
		Mode string `json:"mode"`
	}
	if !s.decodeExact(w, r, &req, maxDriftModeBody, "mode") {
		return
	}
	o, err := s.deps.Inventory.SetDriftMode(r.Context(), s.actor(r), id, req.Mode, s.strictSession(r))
	if err != nil {
		s.fail(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, observationJSON(&o))
}

// repairDrift is the one action that repairs a drifted location: the desired certificate is deployed again through
// its source's request path (Deploy now of the ACME certificate, or the Key Vault binding's current version), with
// every check of a person's deployment. 202 with the deployments; 409 ALC-DEP-0029 (no binding) or ALC-DEP-0030 (not
// drifted).
func (s *server) repairDrift(w http.ResponseWriter, r *http.Request) {
	id, ok := pathUUID(r, "id")
	if !ok {
		s.writeError(w, r, ErrNotFound)
		return
	}
	if !s.decodeExactOptional(w, r, &struct{}{}, maxCancelBody) {
		return
	}
	got, err := s.deps.Inventory.RepairDrift(r.Context(), s.actor(r), id, s.strictSession(r))
	if err != nil {
		s.fail(w, r, err)
		return
	}
	items := make([]requestedDeploymentDTO, 0, len(got))
	for _, g := range got {
		items = append(items, requestedDeploymentJSON(g))
	}
	writeJSON(w, http.StatusAccepted, map[string][]requestedDeploymentDTO{"deployments": items})
}
