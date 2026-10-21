package api

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"slices"
	"time"

	"github.com/google/uuid"

	"alice/internal/authz"
	"alice/internal/authz/services"
	"alice/internal/license"
	"alice/internal/platform/validate"
	"alice/internal/rbac"
)

// ServicesService is the part of *services.Store the HTTP layer uses (R49, design
// docs/superpowers/specs/2026-10-21-scoped-rbac-and-service-ownership-design.md §8.1): environments, services and their
// policy history, trusts between services, moving resources to a service, and the services as rows show them.
type ServicesService interface {
	Environments(ctx context.Context) ([]services.Environment, error)
	CreateEnvironment(ctx context.Context, a services.Actor, in services.EnvironmentInput) (services.Environment, error)
	UpdateEnvironment(ctx context.Context, a services.Actor, id uuid.UUID, version int, p services.EnvironmentPatch) (services.Environment, error)
	DeleteEnvironment(ctx context.Context, a services.Actor, id uuid.UUID, version int) error
	Services(ctx context.Context) ([]services.Service, error)
	Service(ctx context.Context, id uuid.UUID) (services.Service, error)
	CreateService(ctx context.Context, a services.Actor, in services.ServiceInput) (services.Service, error)
	UpdateService(ctx context.Context, a services.Actor, id uuid.UUID, version int, p services.ServicePatch) (services.Service, error)
	DeleteService(ctx context.Context, a services.Actor, id uuid.UUID, version int) error
	Policy(ctx context.Context, id uuid.UUID) (services.Policy, error)
	PolicyVersions(ctx context.Context, id uuid.UUID) ([]services.Policy, error)
	Trusts(ctx context.Context, service *uuid.UUID) ([]services.Trust, error)
	CreateTrust(ctx context.Context, a services.Actor, source, target uuid.UUID) (services.Trust, error)
	DeleteTrust(ctx context.Context, a services.Actor, id uuid.UUID) error
	Assign(ctx context.Context, a services.Actor, dest uuid.UUID, resources []services.Resource, dryRun bool) (services.AssignResult, error)
	Refs(ctx context.Context) (map[uuid.UUID]authz.ServiceRef, error)
	// R49 Phase 2: where a resource belongs (guard's check of the path's resource), the role bindings and a person's
	// access.
	Resolve(ctx context.Context, kind string, id any) (services.Resolution, error)
	TargetServices(ctx context.Context, ids []uuid.UUID) (map[uuid.UUID]uuid.UUID, error)
	Bindings(ctx context.Context, f services.BindingFilter) ([]services.Binding, error)
	Binding(ctx context.Context, id uuid.UUID) (services.Binding, error)
	CreateBinding(ctx context.Context, a services.Actor, in services.BindingInput) (services.Binding, error)
	DeleteBinding(ctx context.Context, a services.Actor, id uuid.UUID) error
	Access(ctx context.Context, userID uuid.UUID) (services.UserAccess, error)
}

var _ ServicesService = (*services.Store)(nil)

// serviceRoutes are services, environments, trusts and assignment (R49). Reading them is every role's; changing them
// decides who may reach what, so it is a global Administrator's browser session with step-up, never a token, and it
// works in lock (Alice's own records, ClassAlways).
func (s *server) serviceRoutes() []route {
	const (
		envs   = "/api/v1/environments"
		svcs   = "/api/v1/services"
		trusts = "/api/v1/service-trusts"
	)
	always := license.ClassAlways
	return []route{
		{method: http.MethodGet, pattern: envs, scope: scopeAny, perm: rbac.Read, handler: s.listEnvironments},
		{method: http.MethodPost, pattern: envs, scope: scopePlatform, perm: rbac.ServicesManage, lic: always, handler: s.createEnvironment},
		{method: http.MethodPatch, pattern: envs + "/{id}", scope: scopePlatform, perm: rbac.ServicesManage, lic: always, handler: s.updateEnvironment},
		{method: http.MethodDelete, pattern: envs + "/{id}", scope: scopePlatform, perm: rbac.ServicesManage, lic: always, handler: s.deleteEnvironment},
		{method: http.MethodGet, pattern: svcs, scope: scopeList, perm: rbac.Read, handler: s.listServices},
		{method: http.MethodPost, pattern: svcs, scope: scopePlatform, perm: rbac.ServicesManage, lic: always, handler: s.createService},
		{method: http.MethodGet, pattern: svcs + "/{id}", scope: scopeResource, resolve: by(services.KindService, "id"), perm: rbac.Read, handler: s.getService},
		{method: http.MethodPatch, pattern: svcs + "/{id}", scope: scopePlatform, perm: rbac.ServicesManage, lic: always, handler: s.updateService},
		{method: http.MethodDelete, pattern: svcs + "/{id}", scope: scopePlatform, perm: rbac.ServicesManage, lic: always, handler: s.deleteService},
		{method: http.MethodGet, pattern: svcs + "/{id}/policy", scope: scopeResource, resolve: by(services.KindService, "id"), perm: rbac.Read, handler: s.getServicePolicy},
		{method: http.MethodGet, pattern: svcs + "/{id}/policy/versions", scope: scopeResource, resolve: by(services.KindService, "id"), perm: rbac.Read, handler: s.listServicePolicies},
		{method: http.MethodPost, pattern: svcs + "/{id}/actions/assign", scope: scopeCross, resolve: by(services.KindService, "id"), perm: rbac.ServicesAssign, lic: always, handler: s.assignToService},
		{method: http.MethodGet, pattern: trusts, scope: scopeList, perm: rbac.Read, handler: s.listTrusts},
		{method: http.MethodPost, pattern: trusts, scope: scopeCross, perm: rbac.ServicesTrust, lic: always, handler: s.createTrust},
		{method: http.MethodDelete, pattern: trusts + "/{id}", scope: scopeCross, resolve: &resolver{kind: services.KindServiceTrust, param: "id", anyVisible: true}, perm: rbac.ServicesTrust, lic: always, handler: s.deleteTrust},
	}
}

// Bodies of the service routes: names and descriptions are short; an assignment names at most services.MaxAssign
// resources (about 80 bytes each).
const (
	maxServiceBody = 8 << 10
	maxAssignBody  = 64 << 10
)

// serviceActor is the caller as the services module needs it.
func (s *server) serviceActor(r *http.Request) services.Actor {
	p := principalFrom(r.Context())
	return services.Actor{Audit: p.Actor(s.meta(r)), UserID: p.UserID}
}

// servicesReady answers 503 when the services module is not wired (a test build without it).
func (s *server) servicesReady(w http.ResponseWriter, r *http.Request) bool {
	if s.deps.Services == nil {
		s.writeError(w, r, ErrUnavailable)
		return false
	}
	return true
}

// The answers.

type environmentRefDTO struct {
	ID   uuid.UUID `json:"id"`
	Key  string    `json:"key"`
	Name string    `json:"name"`
}

// serviceRefDTO is how a row shows the service that owns it (design §8.2). A service outside the caller's reach is
// {"outside": true}: a person with role bindings learns that the row belongs elsewhere, never where (design §5.8).
type serviceRefDTO struct {
	ID          uuid.UUID          `json:"id"`
	Name        string             `json:"name"`
	Environment *environmentRefDTO `json:"environment"`
	Outside     bool               `json:"-"`
}

// MarshalJSON writes {"outside": true} for a service outside the caller's reach.
func (d serviceRefDTO) MarshalJSON() ([]byte, error) {
	if d.Outside {
		return []byte(`{"outside":true}`), nil
	}
	type plain serviceRefDTO
	return json.Marshal(plain(d))
}

// outsideName marks, in a serviceRefs map, a service the caller cannot see (no service name holds a control character).
const outsideName = "\x00outside"

func environmentRefJSON(e *authz.EnvironmentRef) *environmentRefDTO {
	if e == nil {
		return nil
	}
	return &environmentRefDTO{ID: e.ID, Key: e.Key, Name: e.Name}
}

func serviceRefJSON(ref authz.ServiceRef) serviceRefDTO {
	return serviceRefDTO{ID: ref.ID, Name: ref.Name, Environment: environmentRefJSON(ref.Environment)}
}

// serviceRefs are the services of one answer by id (read once per request, at most services.MaxServices), and the
// caller whose allowed_actions the rows show.
type serviceRefs struct {
	byID    map[uuid.UUID]authz.ServiceRef
	subject rbac.Subject
}

// resourcePermissions are the permissions a row's allowed_actions may name (design §8.2: what the caller holds on the
// row's owning service), in a fixed order.
var resourcePermissions = []rbac.Permission{rbac.Read, rbac.TargetsManage, rbac.HostKeysConfirm, rbac.HostKeysRepin, rbac.InventoryOperate,
	rbac.JobsConfirm, rbac.CertificatesOperate, rbac.CredentialsManage, rbac.SSHKeysDownload, rbac.RotationManage, rbac.RotationOperate,
	rbac.AcmeView, rbac.AcmeOperate, rbac.AcmeManage, rbac.DiscoveryView, rbac.DiscoveryOperate, rbac.CertificatesIncident,
	rbac.ServicesAssign, rbac.ServicesTrust}

// actions is a row's allowed_actions: the permissions the caller holds on its owning service (a global grant counts on
// every service; the token scope narrows; the step-up window is not considered: the web UI asks for it when needed).
func (refs serviceRefs) actions(service uuid.UUID) []string {
	sub := refs.subject
	if sub.Kind == rbac.UserSession {
		sub.StepUp = true
	}
	out := []string{}
	for _, p := range resourcePermissions {
		if rbac.DecideIn(p, sub, service) == rbac.Allow {
			out = append(out, string(p))
		}
	}
	return out
}

// of is the owning service of a row as its DTO shows it: nil for no service (a test double's zero id); a service the
// answer did not read (deleted meanwhile) shows its id alone.
func (refs serviceRefs) of(id uuid.UUID) *serviceRefDTO {
	if id == uuid.Nil {
		return nil
	}
	if ref, ok := refs.byID[id]; ok {
		if ref.Name == outsideName {
			return &serviceRefDTO{Outside: true}
		}
		d := serviceRefJSON(ref)
		return &d
	}
	return &serviceRefDTO{ID: id}
}

// serviceRefs reads the services the rows of an answer name. It never fails the answer: without the services module,
// or when the read fails (logged), the rows show the service's id alone.
func (s *server) serviceRefs(r *http.Request) serviceRefs {
	out := serviceRefs{subject: s.subjectOf(r)}
	if s.deps.Services == nil {
		return out
	}
	refs, err := s.deps.Services.Refs(r.Context())
	if err != nil {
		s.deps.Log.Warn("could not read the services of an answer", append([]any{"request_id", RequestID(r.Context())}, errorAttrs(err)...)...)
		return out
	}
	// A person with role bindings sees the name of a service in their read reach only (R49 Phase 2, design §5.8).
	if reach := s.reachOf(r, rbac.Read); reach.Limited {
		for id := range refs {
			if !reach.Contains(id) {
				refs[id] = authz.ServiceRef{ID: id, Name: outsideName}
			}
		}
	}
	out.byID = refs
	return out
}

// serviceFilter reads the list filters service_id and environment_id (each repeatable, design §5.8) as the set of
// services they name: nil without either (no filter); otherwise the services that are among the named ones (when
// service_id is given) and carry one of the named environments (when environment_id is given), possibly none. A
// malformed id is added to v.
func (s *server) serviceFilter(r *http.Request, v *validate.Errors) []uuid.UUID {
	q := r.URL.Query()
	wantServices, okS := parseFilterIDs(q["service_id"])
	wantEnvs, okE := parseFilterIDs(q["environment_id"])
	if !okS {
		v.Add("service_id", validate.Pattern, nil)
	}
	if !okE {
		v.Add("environment_id", validate.Pattern, nil)
	}
	if !okS || !okE || (wantServices == nil && wantEnvs == nil) {
		return nil
	}
	refs := s.serviceRefs(r)
	out := []uuid.UUID{}
	for id, ref := range refs.byID {
		if wantServices != nil && !slices.Contains(wantServices, id) {
			continue
		}
		if wantEnvs != nil && (ref.Environment == nil || !slices.Contains(wantEnvs, ref.Environment.ID)) {
			continue
		}
		out = append(out, id)
	}
	if refs.byID == nil && wantEnvs == nil {
		out = wantServices // without the module the ids are taken as given
	}
	slices.SortFunc(out, func(a, b uuid.UUID) int { return bytes.Compare(a[:], b[:]) })
	return out
}

// parseIDList parses repeated id parameters (nil when there is none); false when one is not an id.
func parseFilterIDs(raw []string) ([]uuid.UUID, bool) {
	if len(raw) == 0 {
		return nil, true
	}
	out := make([]uuid.UUID, 0, len(raw))
	for _, s := range raw {
		id, err := uuid.Parse(s)
		if err != nil || id == uuid.Nil {
			return nil, false
		}
		out = append(out, id)
	}
	return out, true
}

// inServices reports whether a row of service id passes a filter from serviceFilter (nil: every row does).
func inServices(filter []uuid.UUID, id uuid.UUID) bool {
	return filter == nil || slices.Contains(filter, id)
}

type environmentDTO struct {
	ID        uuid.UUID `json:"id"`
	Key       string    `json:"key"`
	Name      string    `json:"name"`
	Sort      int       `json:"sort"`
	Version   int       `json:"version"`
	Services  int       `json:"services"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

func environmentJSON(e services.Environment) environmentDTO {
	return environmentDTO{ID: e.ID, Key: e.Key, Name: e.Name, Sort: e.Sort, Version: e.Version, Services: e.Services,
		CreatedAt: e.CreatedAt.UTC(), UpdatedAt: e.UpdatedAt.UTC()}
}

type serviceCountsDTO struct {
	Servers          int `json:"servers"`
	KeyVaults        int `json:"key_vaults"`
	Certificates     int `json:"certificates"`
	SigningRequests  int `json:"signing_requests"`
	ACMECertificates int `json:"acme_certificates"`
	SSHKeys          int `json:"ssh_keys"`
	DiscoveryScopes  int `json:"discovery_scopes"`
}

func serviceCountsJSON(c services.Counts) serviceCountsDTO {
	return serviceCountsDTO{Servers: c.Servers, KeyVaults: c.KeyVaults, Certificates: c.Certificates, SigningRequests: c.SigningRequests,
		ACMECertificates: c.ACMECertificates, SSHKeys: c.SSHKeys, DiscoveryScopes: c.DiscoveryScopes}
}

type serviceDTO struct {
	ID            uuid.UUID          `json:"id"`
	Name          string             `json:"name"`
	Description   string             `json:"description"`
	Environment   *environmentRefDTO `json:"environment"`
	IsDefault     bool               `json:"is_default"`
	PolicyVersion int                `json:"policy_version"`
	Version       int                `json:"version"`
	Counts        serviceCountsDTO   `json:"counts"`
	CreatedAt     time.Time          `json:"created_at"`
	UpdatedAt     time.Time          `json:"updated_at"`
}

func serviceJSON(sv services.Service) serviceDTO {
	return serviceDTO{ID: sv.ID, Name: sv.Name, Description: sv.Description, Environment: environmentRefJSON(sv.Environment),
		IsDefault: sv.IsDefault, PolicyVersion: sv.PolicyVersion, Version: sv.Version, Counts: serviceCountsJSON(sv.Counts),
		CreatedAt: sv.CreatedAt.UTC(), UpdatedAt: sv.UpdatedAt.UTC()}
}

type servicePolicyDTO struct {
	Version       int             `json:"version"`
	Body          json.RawMessage `json:"body"`
	CreatedBy     *uuid.UUID      `json:"created_by"`
	CreatedByName string          `json:"created_by_name"`
	CreatedAt     time.Time       `json:"created_at"`
}

func servicePolicyJSON(p services.Policy) servicePolicyDTO {
	return servicePolicyDTO{Version: p.Version, Body: p.Document, CreatedBy: p.CreatedBy, CreatedByName: p.CreatedByName, CreatedAt: p.CreatedAt.UTC()}
}

type serviceTrustDTO struct {
	ID            uuid.UUID     `json:"id"`
	Source        serviceRefDTO `json:"source"`
	Target        serviceRefDTO `json:"target"`
	CreatedByName string        `json:"created_by_name"`
	CreatedAt     time.Time     `json:"created_at"`
}

func serviceTrustJSON(t services.Trust) serviceTrustDTO {
	return serviceTrustDTO{ID: t.ID, Source: serviceRefJSON(t.Source), Target: serviceRefJSON(t.Target), CreatedByName: t.CreatedByName,
		CreatedAt: t.CreatedAt.UTC()}
}

type assignMoveDTO struct {
	Type    string        `json:"type"`
	ID      uuid.UUID     `json:"id"`
	Name    string        `json:"name"`
	From    serviceRefDTO `json:"from"`
	Changed bool          `json:"changed"`
}

type untrustedBindingDTO struct {
	Kind          string        `json:"kind"`
	SourceID      uuid.UUID     `json:"source_id"`
	SourceName    string        `json:"source_name"`
	LocationID    uuid.UUID     `json:"location_id"`
	TargetID      uuid.UUID     `json:"target_id"`
	TargetName    string        `json:"target_name"`
	SourceService serviceRefDTO `json:"source_service"`
	TargetService serviceRefDTO `json:"target_service"`
}

type assignResultDTO struct {
	DryRun      bool                  `json:"dry_run"`
	Destination serviceRefDTO         `json:"destination"`
	Moves       []assignMoveDTO       `json:"moves"`
	Untrusted   []untrustedBindingDTO `json:"untrusted"`
}

func assignResultJSON(res services.AssignResult) assignResultDTO {
	out := assignResultDTO{DryRun: res.DryRun, Destination: serviceRefJSON(res.Destination), Moves: []assignMoveDTO{}, Untrusted: []untrustedBindingDTO{}}
	for _, m := range res.Moves {
		out.Moves = append(out.Moves, assignMoveDTO{Type: m.Type, ID: m.ID, Name: m.Name, From: serviceRefJSON(m.From), Changed: m.Changed})
	}
	for _, u := range res.Untrusted {
		out.Untrusted = append(out.Untrusted, untrustedBindingDTO{Kind: u.Kind, SourceID: u.SourceID, SourceName: u.SourceName,
			LocationID: u.LocationID, TargetID: u.TargetID, TargetName: u.TargetName, SourceService: serviceRefJSON(u.Source),
			TargetService: serviceRefJSON(u.Target)})
	}
	return out
}

// The handlers.

func (s *server) listEnvironments(w http.ResponseWriter, r *http.Request) {
	if !s.servicesReady(w, r) {
		return
	}
	envs, err := s.deps.Services.Environments(r.Context())
	if err != nil {
		s.fail(w, r, err)
		return
	}
	items := make([]environmentDTO, 0, len(envs))
	for _, e := range envs {
		items = append(items, environmentJSON(e))
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": items})
}

func (s *server) createEnvironment(w http.ResponseWriter, r *http.Request) {
	if !s.servicesReady(w, r) {
		return
	}
	var req struct {
		Key  string `json:"key"`
		Name string `json:"name"`
		Sort int    `json:"sort"`
	}
	if !s.decodeLimit(w, r, &req, maxServiceBody) {
		return
	}
	e, err := s.deps.Services.CreateEnvironment(r.Context(), s.serviceActor(r), services.EnvironmentInput{Key: req.Key, Name: req.Name, Sort: req.Sort})
	if err != nil {
		s.fail(w, r, err)
		return
	}
	w.Header().Set("ETag", etag(e.Version))
	writeJSON(w, http.StatusCreated, environmentJSON(e))
}

func (s *server) updateEnvironment(w http.ResponseWriter, r *http.Request) {
	if !s.servicesReady(w, r) {
		return
	}
	id, ok := pathUUID(r, "id")
	if !ok {
		s.writeError(w, r, ErrNotFound)
		return
	}
	version, ok := ifMatch(r)
	if !ok {
		s.writeError(w, r, ErrPreconditionFailed)
		return
	}
	var req struct {
		Name *string `json:"name"`
		Sort *int    `json:"sort"`
	}
	if !s.decodeLimit(w, r, &req, maxServiceBody) {
		return
	}
	e, err := s.deps.Services.UpdateEnvironment(r.Context(), s.serviceActor(r), id, version, services.EnvironmentPatch{Name: req.Name, Sort: req.Sort})
	if err != nil {
		s.fail(w, r, err)
		return
	}
	w.Header().Set("ETag", etag(e.Version))
	writeJSON(w, http.StatusOK, environmentJSON(e))
}

func (s *server) deleteEnvironment(w http.ResponseWriter, r *http.Request) {
	if !s.servicesReady(w, r) {
		return
	}
	id, ok := pathUUID(r, "id")
	if !ok {
		s.writeError(w, r, ErrNotFound)
		return
	}
	version, ok := ifMatch(r)
	if !ok {
		s.writeError(w, r, ErrPreconditionFailed)
		return
	}
	s.finishDelete(w, r, s.deps.Services.DeleteEnvironment(r.Context(), s.serviceActor(r), id, version))
}

func (s *server) listServices(w http.ResponseWriter, r *http.Request) {
	if !s.servicesReady(w, r) {
		return
	}
	var v validate.Errors
	filter := s.serviceFilter(r, &v)
	if err := v.Err(); err != nil {
		s.fail(w, r, err)
		return
	}
	list, err := s.deps.Services.Services(r.Context())
	if err != nil {
		s.fail(w, r, err)
		return
	}
	reach := s.reachOf(r, rbac.Read) // R49 Phase 2: the caller's services; every service for a global grant
	items := make([]serviceDTO, 0, len(list))
	for _, sv := range list {
		if inServices(filter, sv.ID) && reach.Contains(sv.ID) {
			items = append(items, serviceJSON(sv))
		}
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": items})
}

func (s *server) createService(w http.ResponseWriter, r *http.Request) {
	if !s.servicesReady(w, r) {
		return
	}
	var req struct {
		Name          string     `json:"name"`
		Description   string     `json:"description"`
		EnvironmentID *uuid.UUID `json:"environment_id"`
	}
	if !s.decodeLimit(w, r, &req, maxServiceBody) {
		return
	}
	sv, err := s.deps.Services.CreateService(r.Context(), s.serviceActor(r), services.ServiceInput{Name: req.Name, Description: req.Description,
		EnvironmentID: req.EnvironmentID})
	if err != nil {
		s.fail(w, r, err)
		return
	}
	w.Header().Set("ETag", etag(sv.Version))
	writeJSON(w, http.StatusCreated, serviceJSON(sv))
}

func (s *server) getService(w http.ResponseWriter, r *http.Request) {
	if !s.servicesReady(w, r) {
		return
	}
	id, ok := pathUUID(r, "id")
	if !ok {
		s.writeError(w, r, ErrSVCNotFound)
		return
	}
	sv, err := s.deps.Services.Service(r.Context(), id)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	w.Header().Set("ETag", etag(sv.Version))
	writeJSON(w, http.StatusOK, serviceJSON(sv))
}

func (s *server) updateService(w http.ResponseWriter, r *http.Request) {
	if !s.servicesReady(w, r) {
		return
	}
	id, ok := pathUUID(r, "id")
	if !ok {
		s.writeError(w, r, ErrSVCNotFound)
		return
	}
	version, ok := ifMatch(r)
	if !ok {
		s.writeError(w, r, ErrPreconditionFailed)
		return
	}
	// environment_id: absent keeps it, null removes it, an id sets it (a relabel changes which environment bindings reach
	// the service, so it is audited with both environments).
	var req struct {
		Name          *string         `json:"name"`
		Description   *string         `json:"description"`
		EnvironmentID json.RawMessage `json:"environment_id"`
	}
	if !s.decodeLimit(w, r, &req, maxServiceBody) {
		return
	}
	p := services.ServicePatch{Name: req.Name, Description: req.Description}
	if req.EnvironmentID != nil {
		p.SetEnvironment = true
		if string(req.EnvironmentID) != "null" {
			var env uuid.UUID
			if err := json.Unmarshal(req.EnvironmentID, &env); err != nil || env == uuid.Nil {
				s.fail(w, r, validate.Errors{{Field: "environment_id", Code: validate.Pattern}})
				return
			}
			p.EnvironmentID = &env
		}
	}
	sv, err := s.deps.Services.UpdateService(r.Context(), s.serviceActor(r), id, version, p)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	w.Header().Set("ETag", etag(sv.Version))
	writeJSON(w, http.StatusOK, serviceJSON(sv))
}

func (s *server) deleteService(w http.ResponseWriter, r *http.Request) {
	if !s.servicesReady(w, r) {
		return
	}
	id, ok := pathUUID(r, "id")
	if !ok {
		s.writeError(w, r, ErrSVCNotFound)
		return
	}
	version, ok := ifMatch(r)
	if !ok {
		s.writeError(w, r, ErrPreconditionFailed)
		return
	}
	s.finishDelete(w, r, s.deps.Services.DeleteService(r.Context(), s.serviceActor(r), id, version))
}

func (s *server) getServicePolicy(w http.ResponseWriter, r *http.Request) {
	if !s.servicesReady(w, r) {
		return
	}
	id, ok := pathUUID(r, "id")
	if !ok {
		s.writeError(w, r, ErrSVCNotFound)
		return
	}
	p, err := s.deps.Services.Policy(r.Context(), id)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, servicePolicyJSON(p))
}

func (s *server) listServicePolicies(w http.ResponseWriter, r *http.Request) {
	if !s.servicesReady(w, r) {
		return
	}
	id, ok := pathUUID(r, "id")
	if !ok {
		s.writeError(w, r, ErrSVCNotFound)
		return
	}
	list, err := s.deps.Services.PolicyVersions(r.Context(), id)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	items := make([]servicePolicyDTO, 0, len(list))
	for _, p := range list {
		items = append(items, servicePolicyJSON(p))
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": items})
}

// assignToService moves resources to the service of the path (design §8.1): ?dry_run=true answers what the move would
// do (the moves and the binding locations that would cross services without a trust) and changes nothing.
func (s *server) assignToService(w http.ResponseWriter, r *http.Request) {
	if !s.servicesReady(w, r) {
		return
	}
	id, ok := pathUUID(r, "id")
	if !ok {
		s.writeError(w, r, ErrSVCNotFound)
		return
	}
	var v validate.Errors
	dryRun := parseBool(r.URL.Query().Get("dry_run"), "dry_run", &v)
	if err := v.Err(); err != nil {
		s.fail(w, r, err)
		return
	}
	var req struct {
		Resources []struct {
			Type string    `json:"type"`
			ID   uuid.UUID `json:"id"`
		} `json:"resources"`
	}
	if !s.decodeLimit(w, r, &req, maxAssignBody) {
		return
	}
	in := make([]services.Resource, 0, len(req.Resources))
	for _, res := range req.Resources {
		in = append(in, services.Resource{Type: res.Type, ID: res.ID})
	}
	// R49 Phase 2, design §5.6: services.assign on each resource's current service too (the guard checked the
	// destination's): nobody pulls another service's resource into their own. An unknown kind is the store's refusal.
	if !s.reachOf(r, rbac.ServicesAssign).All() {
		var from []uuid.UUID
		for _, res := range in {
			if !slices.Contains(services.AssignKinds, res.Type) {
				continue
			}
			got, err := s.servicesOf(r.Context(), res.Type, []uuid.UUID{res.ID})
			if err != nil {
				s.fail(w, r, err)
				return
			}
			from = append(from, got...)
		}
		if !s.checkDestinations(w, r, rbac.ServicesAssign, from) {
			return
		}
	}
	res, err := s.deps.Services.Assign(r.Context(), s.serviceActor(r), id, in, dryRun)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, assignResultJSON(res))
}

func (s *server) listTrusts(w http.ResponseWriter, r *http.Request) {
	if !s.servicesReady(w, r) {
		return
	}
	var service *uuid.UUID
	if raw := r.URL.Query().Get("service_id"); raw != "" {
		id, err := uuid.Parse(raw)
		if err != nil {
			s.fail(w, r, validate.Errors{{Field: "service_id", Code: validate.Pattern}})
			return
		}
		service = &id
	}
	list, err := s.deps.Services.Trusts(r.Context(), service)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	reach := s.reachOf(r, rbac.Read) // R49 Phase 2: the trusts with either side in the caller's reach
	items := make([]serviceTrustDTO, 0, len(list))
	for _, t := range list {
		if reach.Contains(t.Source.ID) || reach.Contains(t.Target.ID) {
			d := serviceTrustJSON(t)
			d.Source.Outside, d.Target.Outside = !reach.Contains(t.Source.ID), !reach.Contains(t.Target.ID) // the other side unnamed
			items = append(items, d)
		}
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": items})
}

func (s *server) createTrust(w http.ResponseWriter, r *http.Request) {
	if !s.servicesReady(w, r) {
		return
	}
	var req struct {
		SourceServiceID uuid.UUID `json:"source_service_id"`
		TargetServiceID uuid.UUID `json:"target_service_id"`
	}
	if !s.decodeLimit(w, r, &req, maxServiceBody) {
		return
	}
	// R49 Phase 2, design §5.6: services.trust on both services.
	if !s.checkDestinations(w, r, rbac.ServicesTrust, []uuid.UUID{req.SourceServiceID, req.TargetServiceID}) {
		return
	}
	t, err := s.deps.Services.CreateTrust(r.Context(), s.serviceActor(r), req.SourceServiceID, req.TargetServiceID)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	writeJSON(w, http.StatusCreated, serviceTrustJSON(t))
}

func (s *server) deleteTrust(w http.ResponseWriter, r *http.Request) {
	if !s.servicesReady(w, r) {
		return
	}
	id, ok := pathUUID(r, "id")
	if !ok {
		s.writeError(w, r, ErrNotFound)
		return
	}
	s.finishDelete(w, r, s.deps.Services.DeleteTrust(r.Context(), s.serviceActor(r), id))
}

// untrustedParams names the two services of a refused cross-service action (ALC-SVC-0007): the caller sees both (design
// §5.6). An id the answer cannot name stays out.
func (s *server) untrustedParams(r *http.Request, err error) map[string]string {
	var u *authz.UntrustedError
	if !errors.As(err, &u) {
		return nil
	}
	refs := s.serviceRefs(r)
	params := map[string]string{"source_service_id": u.Source.String(), "target_service_id": u.Target.String()}
	if ref, ok := refs.byID[u.Source]; ok && ref.Name != outsideName {
		params["source_service"] = ref.Name
	}
	if ref, ok := refs.byID[u.Target]; ok && ref.Name != outsideName {
		params["target_service"] = ref.Name
	}
	return params
}
