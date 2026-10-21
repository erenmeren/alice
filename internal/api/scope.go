package api

import (
	"context"
	"errors"
	"net/http"
	"slices"
	"strconv"

	"github.com/google/uuid"

	"alice/internal/auth"
	"alice/internal/authz"
	"alice/internal/authz/services"
	"alice/internal/platform/validate"
	"alice/internal/rbac"
)

// Scoped access in the HTTP layer (R49 Phase 2, design docs/superpowers/specs/2026-10-21-scoped-rbac-and-service-
// ownership-design.md §5.3, §5.4, §5.6, §5.10). The route table says how each operation meets a person's roles on
// services (route.scope); guard decides the route-level permission (rbac.Decide for a global grant, rbac.DecideAnywhere
// for a grant anywhere) and, for a resource or cross route, checks the resource the path names (checkResource) before
// the handler runs. Lists filter by the caller's reach (reachOf) inside their queries; create routes resolve the body's
// service_id (serviceForCreate); cross routes check every destination (checkDestinations).

// resolver names the resource the path of a scopeResource or scopeCross route points at (design §5.4): one indexed
// query (services.Store.Resolve) gives its owning service and the services it is visible from.
type resolver struct {
	kind  string // services.Kind*: the scoped IDOR test plants a resource of this kind for every route
	param string // the path parameter that names it
	// either: removing a location from a binding (design §5.6 "either side"): the write is allowed with the permission
	// on this resource's owning service as well (the receiving service can always detach its own server).
	either *resolver
	// anyVisible: a write is allowed with the permission on any service the resource is visible from (a trust: either
	// of its two services removes it).
	anyVisible bool
	// allVisible: a write needs the permission on every service the resource is visible from (an incident: every
	// service in its service_ids, design §5.6).
	allVisible bool
}

// by is the resolver of the resource of kind named by the path parameter param.
func by(kind, param string) *resolver { return &resolver{kind: kind, param: param} }

// byEither is by, where a write right on the second resource's service (kind2 named by param2) suffices too.
func byEither(kind, param, kind2, param2 string) *resolver {
	return &resolver{kind: kind, param: param, either: by(kind2, param2)}
}

// readPermissions are the permissions that read: a route with one of them needs the resource visible, nothing more.
var readPermissions = []rbac.Permission{rbac.Read, rbac.AcmeView, rbac.DiscoveryView}

func isReadPermission(p rbac.Permission) bool { return slices.Contains(readPermissions, p) }

// notFoundOf is the answer of a route to a resource it cannot see (design §5.10: the route's own 404, the answer to an
// absent one): ALC-SYS-0001 for most kinds.
func notFoundOf(kind string) ErrorCode {
	switch kind {
	case services.KindService:
		return ErrSVCNotFound
	case services.KindDiscoveryScope:
		return ErrDSCScopeNotFound
	}
	return ErrNotFound
}

// subjectOf is the request's caller as the authorization check sees it.
func (s *server) subjectOf(r *http.Request) rbac.Subject {
	return principalFrom(r.Context()).Subject(s.deps.Clock.Now())
}

// reachOf is where the request's caller may use permission p (design §5.1): every service for a global grant.
func (s *server) reachOf(r *http.Request, p rbac.Permission) authz.Reach {
	return authz.ReachOf(p, s.subjectOf(r))
}

// accessOf is the request's caller's grants as the service functions see them.
func (s *server) accessOf(r *http.Request) authz.Access {
	return authz.AccessOf(s.subjectOf(r))
}

// scopedDecision is the route-level decision of guard (design §5.3): a platform route (and every route that involves no
// grant, or the caller's own records) needs a global grant (rbac.Decide); every other route a grant anywhere
// (rbac.DecideAnywhere), its resource or its answer then limited to the caller's reach.
func scopedDecision(rt route, subject rbac.Subject) rbac.Decision {
	switch rt.scope {
	case scopePlatform, scopeNone, scopeSelf:
		return rbac.Decide(rt.perm, subject)
	default:
		return rbac.DecideAnywhere(rt.perm, subject)
	}
}

// pathKey reads the path parameter of a resolver: a resource id, or a discovered certificate's fingerprint as the route
// reads it. ok is false when the value names no resource (a malformed id): the handler answers it as it always did,
// and nothing is found either way.
func pathKey(r *http.Request, rv *resolver) (any, bool) {
	if rv.kind == services.KindDiscoveredCert {
		fp, ok := pathFingerprint(r, rv.param)
		return fp, ok
	}
	id, ok := pathUUID(r, rv.param)
	if !ok || id == uuid.Nil {
		return nil, false
	}
	return id, true
}

// checkResource is design §5.4 for the resource the path of rt names: the caller (whose grant anywhere the guard has
// checked) must see it (a service it is visible from in the caller's read reach), and for a write hold the route's
// permission on its owning service (or as the resolver says). A caller with a global grant for the permission reaches
// every service and is not looked up at all, so nothing changes for anyone who has no role binding. It writes the
// refusal and returns false: the route's 404 for a resource that is absent or out of sight (never telling the two
// apart, design Q9), 403 ALC-AUTH-0002 for one the caller sees but may not change; both are audited (authz.denied,
// reasons out_of_scope and scope, coalesced like every refusal).
//
// A caller with role bindings is looked up even when a global grant covers the route, so that the conditional
// permissions inside the handler (design §5.5: a Key Vault's held version, an automatic deployment switched on) are
// judged by the caller's role on the resource's own service (roleOn). The request it returns carries that service.
func (s *server) checkResource(w http.ResponseWriter, r *http.Request, rt route, p auth.Principal) (*http.Request, bool) {
	subject := p.Subject(s.deps.Clock.Now())
	permReach := authz.ReachOf(rt.perm, subject)
	if permReach.All() && len(subject.Grants) == 0 {
		return r, true
	}
	if s.deps.Services == nil {
		if permReach.All() {
			return r, true
		}
		// Scoped grants without the services module cannot be checked: refused, never let through.
		s.auditDenied(r, rt, p, "scope")
		s.writeError(w, r, ErrForbidden)
		return r, false
	}
	rv := rt.resolve
	key, ok := pathKey(r, rv)
	if !ok {
		return r, true // the handler answers a malformed id; it names nothing
	}
	res, err := s.deps.Services.Resolve(r.Context(), rv.kind, key)
	switch {
	case errors.Is(err, services.ErrResourceNotFound) && permReach.All():
		return r, true // the handler answers its own absent resource, as for everyone with a global grant
	case errors.Is(err, services.ErrResourceNotFound):
		s.auditDenied(r, rt, p, "out_of_scope")
		s.writeError(w, r, notFoundOf(rv.kind))
		return r, false
	case err != nil:
		s.fail(w, r, err)
		return r, false
	}
	r = r.WithContext(context.WithValue(r.Context(), resourceKey{}, res))
	if permReach.All() {
		return r, true
	}
	readPerm := rt.perm
	if !isReadPermission(readPerm) {
		readPerm = rbac.Read
	}
	if !authz.ReachOf(readPerm, subject).ContainsAny(res.Visible) {
		s.auditDenied(r, rt, p, "out_of_scope")
		s.writeError(w, r, notFoundOf(rv.kind))
		return r, false
	}
	if isReadPermission(rt.perm) {
		return r, true
	}
	allowed := false
	switch {
	case rv.allVisible:
		allowed = len(res.Visible) > 0
		for _, sv := range res.Visible {
			allowed = allowed && permReach.Contains(sv)
		}
	case rv.anyVisible:
		allowed = permReach.ContainsAny(res.Visible)
	default:
		allowed = res.Owning != uuid.Nil && permReach.Contains(res.Owning)
	}
	if !allowed && rv.either != nil {
		if k2, ok := pathKey(r, rv.either); ok {
			second, err := s.deps.Services.Resolve(r.Context(), rv.either.kind, k2)
			switch {
			case err == nil:
				allowed = second.Owning != uuid.Nil && permReach.Contains(second.Owning)
			case !errors.Is(err, services.ErrResourceNotFound):
				s.fail(w, r, err)
				return r, false
			}
		}
	}
	if !allowed {
		s.auditDenied(r, rt, p, "scope")
		s.writeError(w, r, ErrForbidden)
		return r, false
	}
	return r, true
}

// resourceKey holds the services.Resolution of the path's resource (set by checkResource for a caller with role
// bindings).
type resourceKey struct{}

// pathResource is the resolution checkResource stored, if any.
func pathResource(ctx context.Context) (services.Resolution, bool) {
	res, ok := ctx.Value(resourceKey{}).(services.Resolution)
	return res, ok
}

// roleOn is the role the request's caller holds on the path resource's owning service (design §5.5: the conditional
// permissions are judged on the owning service of the source): the strongest of its global role and of its role
// bindings that cover the service. Without a resolved resource (a caller without role bindings, a route without a
// path resource) it is the global role, as before scoped access.
func (s *server) roleOn(r *http.Request) rbac.Role {
	p := principalFrom(r.Context())
	res, ok := pathResource(r.Context())
	if !ok || res.Owning == uuid.Nil {
		return p.Role
	}
	return strongestRole(p.Role, p.Grants, res.Owning)
}

// decideOn is the decision of a permission inside a handler (design §5.5: a conditional permission, the strict
// session of a held version or of an automatic deployment switched on): on the path resource's owning service when
// guard resolved one (a caller with role bindings), otherwise the global decision, as before scoped access.
func (s *server) decideOn(r *http.Request, p rbac.Permission) rbac.Decision {
	sub := s.subjectOf(r)
	if res, ok := pathResource(r.Context()); ok && res.Owning != uuid.Nil {
		return rbac.DecideIn(p, sub, res.Owning)
	}
	return rbac.Decide(p, sub)
}

// strongestRole is the strongest of global and of the grants that cover service ("" when none does).
func strongestRole(global rbac.Role, grants []rbac.ScopedGrant, service uuid.UUID) rbac.Role {
	held := []rbac.Role{global}
	for _, g := range grants {
		if slices.Contains(g.Services, service) {
			held = append(held, g.Role)
		}
	}
	for _, r := range rbac.Roles() { // most privileged first
		if slices.Contains(held, r) {
			return r
		}
	}
	return ""
}

// serviceForCreate is design §4.4 for a create route: the service the new resource goes to. A named service needs the
// route's permission there (403 ALC-SVC-0006, the field named); without one, a caller with a global grant gets the
// Default service (uuid.Nil: the module resolves it) and a scoped caller the only service where it holds the permission
// (422 ALC-SVC-0005 when there are several). It writes the refusal and returns false.
func (s *server) serviceForCreate(w http.ResponseWriter, r *http.Request, p rbac.Permission, named *uuid.UUID) (uuid.UUID, bool) {
	reach := s.reachOf(r, p)
	switch {
	case named != nil && *named != uuid.Nil:
		if !reach.Contains(*named) {
			s.writeErrorWith(w, r, ErrSVCNotAllowed, nil, []validate.FieldError{{Field: "service_id", Code: "service.not_allowed"}})
			return uuid.Nil, false
		}
		return *named, true
	case reach.All():
		return uuid.Nil, true
	case len(reach.Services) == 1:
		return reach.Services[0], true
	}
	s.writeErrorWith(w, r, ErrSVCRequired, nil, []validate.FieldError{{Field: "service_id", Code: validate.Required}})
	return uuid.Nil, false
}

// checkDestinations is design §5.6 (b): the caller holds permission p on every destination service of a cross-service
// action. The refusal (403 ALC-SVC-0012) counts the destinations outside the caller's reach and names none of them.
// It writes the refusal and returns false.
func (s *server) checkDestinations(w http.ResponseWriter, r *http.Request, p rbac.Permission, destinations []uuid.UUID) bool {
	reach := s.reachOf(r, p)
	if reach.All() {
		return true
	}
	outside := 0
	seen := map[uuid.UUID]bool{}
	for _, d := range destinations {
		if seen[d] {
			continue
		}
		seen[d] = true
		if !reach.Contains(d) {
			outside++
		}
	}
	if outside == 0 {
		return true
	}
	s.writeErrorWith(w, r, ErrSVCSpansServices, map[string]string{"count": strconv.Itoa(outside)}, nil)
	return false
}

// checkDestinationsOf is checkDestinations for the resources of one kind a cross action places a key on (locations,
// servers, Key Vaults): their owning services must all be in the caller's reach for p. Without role bindings nothing is
// looked up.
func (s *server) checkDestinationsOf(w http.ResponseWriter, r *http.Request, p rbac.Permission, kind string, ids []uuid.UUID) bool {
	if s.reachOf(r, p).All() {
		return true
	}
	dest, err := s.servicesOf(r.Context(), kind, ids)
	if err != nil {
		s.fail(w, r, err)
		return false
	}
	return s.checkDestinations(w, r, p, dest)
}

// servicesOf resolves the owning services of resources of one kind (the destinations of a cross action), in the
// order given, without repeats. An absent resource adds nothing: the service function refuses it as it always did.
func (s *server) servicesOf(ctx context.Context, kind string, ids []uuid.UUID) ([]uuid.UUID, error) {
	if s.deps.Services == nil {
		return nil, nil
	}
	var out []uuid.UUID
	for _, id := range ids {
		res, err := s.deps.Services.Resolve(ctx, kind, id)
		if errors.Is(err, services.ErrResourceNotFound) {
			continue
		}
		if err != nil {
			return nil, err
		}
		if res.Owning != uuid.Nil && !slices.Contains(out, res.Owning) {
			out = append(out, res.Owning)
		}
	}
	return out, nil
}

// targetsSeen answers which of the servers and Key Vaults a detail answer names the caller sees (design §5.8: a
// certificate's, an SSH key's, a binding's, an incident's locations and a certificate's impact list only the rows in
// reach; hidden_count counts the others). Every one for a caller whose read reach is every service, without a query.
func (s *server) targetsSeen(r *http.Request, ids []uuid.UUID) (func(uuid.UUID) bool, error) {
	reach := s.reachOf(r, rbac.Read)
	if reach.All() {
		return func(uuid.UUID) bool { return true }, nil
	}
	if s.deps.Services == nil {
		return func(uuid.UUID) bool { return false }, nil
	}
	of, err := s.deps.Services.TargetServices(r.Context(), ids)
	if err != nil {
		return nil, err
	}
	return func(id uuid.UUID) bool {
		svc, ok := of[id]
		return ok && reach.Contains(svc)
	}, nil
}

// keepSeen filters rows by their target (seen reports whether the caller sees it) and counts the rows left out.
func keepSeen[T any](rows []T, target func(T) uuid.UUID, seen func(uuid.UUID) bool) ([]T, int) {
	out := make([]T, 0, len(rows))
	hidden := 0
	for _, row := range rows {
		if seen(target(row)) {
			out = append(out, row)
		} else {
			hidden++
		}
	}
	return out, hidden
}

// targetIDsOf lists the targets of rows.
func targetIDsOf[T any](rows []T, target func(T) uuid.UUID) []uuid.UUID {
	out := make([]uuid.UUID, 0, len(rows))
	for _, row := range rows {
		out = append(out, target(row))
	}
	return out
}
