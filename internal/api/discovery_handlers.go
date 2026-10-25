package api

import (
	"context"
	"encoding/base64"
	"errors"
	"net/http"
	"net/netip"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/google/uuid"

	"alice/internal/alerts/expiry"
	"alice/internal/authz/services"
	"alice/internal/discovery"
	"alice/internal/discovery/discoverysvc"
	"alice/internal/license"
	"alice/internal/platform/validate"
	"alice/internal/rbac"
	"alice/internal/reports"
)

// discoveryRoutes are network certificate discovery (plan 2026-10-13-network-discovery, Task 9; decisions D1, D7,
// amendments A2, A3, A5). Reading the results, scopes, scans and settings is discovery.view: every role in a browser,
// but a token needs the operate scope (D7: the internal network map is never readable with a read token). Starting and
// cancelling scans is discovery.operate (Admin, Operator; operate tokens), 10 a minute per user or token (one budget for
// both). Defining scopes and the settings is discovery.manage (an Administrator's browser session with a fresh step-up,
// never a token); the routes that may look a listed host name up (create, change) share limitDiscoveryResolve (30 a
// minute); the size preview, asked while the form is typed in, has limitDiscoveryPreview (60 a minute). The API never takes free-form targets for a scan: only a scope id.
//
// Licence (A5): starting a scan is ClassReadOnly (403 license.locked in lock, nothing queued); every other change is
// ClassAlways, so a locked installation can still stop a scan and change or remove its scopes.
func (s *server) discoveryRoutes() []route {
	const base = "/api/v1/discovery"
	view, operate, manage := rbac.DiscoveryView, rbac.DiscoveryOperate, rbac.DiscoveryManage
	always, readOnly := license.ClassAlways, license.ClassReadOnly
	return []route{
		{method: http.MethodGet, pattern: base + "/summary", scope: scopeAny, perm: view, handler: s.discoverySummary},
		{method: http.MethodGet, pattern: base + "/scopes", scope: scopeList, perm: view, handler: s.listDiscoveryScopes},
		{method: http.MethodPost, pattern: base + "/scopes", scope: scopePlatform, perm: manage, lic: always, limit: limitDiscoveryResolve, handler: s.createDiscoveryScope},
		{method: http.MethodPost, pattern: base + "/scopes/preview", scope: scopePlatform, perm: manage, lic: always, limit: limitDiscoveryPreview, handler: s.previewDiscoveryScope},
		{method: http.MethodGet, pattern: base + "/scopes/{id}", scope: scopeResource, resolve: by(services.KindDiscoveryScope, "id"), perm: view, handler: s.getDiscoveryScope},
		{method: http.MethodPatch, pattern: base + "/scopes/{id}", scope: scopePlatform, perm: manage, lic: always, limit: limitDiscoveryResolve, handler: s.updateDiscoveryScope},
		{method: http.MethodDelete, pattern: base + "/scopes/{id}", scope: scopePlatform, perm: manage, lic: always, handler: s.deleteDiscoveryScope},
		{method: http.MethodPost, pattern: base + "/scopes/{id}/scans", scope: scopeResource, resolve: by(services.KindDiscoveryScope, "id"), perm: operate, lic: readOnly, limit: limitDiscovery, handler: s.startDiscoveryScan},
		{method: http.MethodGet, pattern: base + "/scans", scope: scopeList, perm: view, handler: s.listDiscoveryScans},
		{method: http.MethodGet, pattern: base + "/scans/{id}", scope: scopeResource, resolve: by(services.KindDiscoveryScan, "id"), perm: view, handler: s.getDiscoveryScan},
		{method: http.MethodPost, pattern: base + "/scans/{id}/cancel", scope: scopeResource, resolve: by(services.KindDiscoveryScan, "id"), perm: operate, lic: always, limit: limitDiscovery, handler: s.cancelDiscoveryScan},
		{method: http.MethodGet, pattern: base + "/certificates", scope: scopeList, perm: view, handler: s.listDiscoveredCertificates},
		{method: http.MethodGet, pattern: base + "/certificates/export", scope: scopeList, perm: view, limit: limitExport, getOnly: true,
			handler: s.exportDiscoveredCertificates},
		{method: http.MethodGet, pattern: base + "/certificates/{fingerprint}", scope: scopeResource, resolve: by(services.KindDiscoveredCert, "fingerprint"), perm: view, handler: s.getDiscoveredCertificate},
		{method: http.MethodGet, pattern: base + "/endpoints", scope: scopeList, perm: view, handler: s.listDiscoveredEndpoints},
		{method: http.MethodGet, pattern: base + "/settings", scope: scopePlatform, perm: view, handler: s.getDiscoverySettings},
		{method: http.MethodPut, pattern: base + "/settings", scope: scopePlatform, perm: manage, lic: always, handler: s.putDiscoverySettings},
	}
}

// Body caps (SEC-023): a scope of 256 entries, 256 SNI names and 256 exclusions of at most 255 characters each, and the
// settings' two lists of 256.
const (
	maxDiscoveryScopeBody    = 256 << 10
	maxDiscoverySettingsBody = 192 << 10
	maxDiscoveryExpiringDays = 3650
)

// discoveryActor is the caller as the discovery service needs it.
func (s *server) discoveryActor(r *http.Request) discoverysvc.Actor {
	p := principalFrom(r.Context())
	return discoverysvc.Actor{Audit: p.Actor(s.meta(r)), UserID: p.UserID, Role: string(p.Role)}
}

// --- scopes ---

type discoveryScopeBody struct {
	// ServiceID is a new scope's service (R49; nil: the Default service). A change never takes it: a scope moves to
	// another service only by POST /api/v1/services/{id}/actions/assign.
	ServiceID     *uuid.UUID `json:"service_id"`
	Name          *string    `json:"name"`
	Entries       *[]string  `json:"entries"`
	Ports         *[]int     `json:"ports"`
	SNINames      *[]string  `json:"sni_names"`
	Exclusions    *[]string  `json:"exclusions"`
	Enabled       *bool      `json:"enabled"`
	ScheduleHours *int       `json:"schedule_hours"`
	WindowStart   *string    `json:"window_start"`
	WindowEnd     *string    `json:"window_end"`
	WindowTZ      *string    `json:"window_tz"`
	AlertOnExpiry *bool      `json:"alert_on_expiry"`
	RatePerSec    *int       `json:"rate_per_sec"`
	Concurrency   *int       `json:"concurrency"`
}

var discoveryScopeKeys = []string{"name", "entries", "ports", "sni_names", "exclusions", "enabled", "schedule_hours", "window_start", "window_end",
	"window_tz", "alert_on_expiry", "rate_per_sec", "concurrency"}

func derefOr[T any](p *T, d T) T {
	if p == nil {
		return d
	}
	return *p
}

// schedule reports the schedule the body names: the four schedule fields are one group, so sending any of them
// replaces the whole schedule (an absent one is empty: no schedule, no window, UTC).
func (b *discoveryScopeBody) schedule() (discovery.Schedule, bool) {
	if b.ScheduleHours == nil && b.WindowStart == nil && b.WindowEnd == nil && b.WindowTZ == nil {
		return discovery.Schedule{}, false
	}
	return discovery.Schedule{Hours: derefOr(b.ScheduleHours, 0), WindowStart: derefOr(b.WindowStart, ""), WindowEnd: derefOr(b.WindowEnd, ""),
		TimeZone: derefOr(b.WindowTZ, "")}, true
}

// scope is the body as a new scope (enabled unless it says otherwise); the validator decides the rest.
func (b *discoveryScopeBody) scope() discovery.Scope {
	sc, _ := b.schedule()
	return discovery.Scope{Name: derefOr(b.Name, ""), Entries: derefOr(b.Entries, nil), Ports: derefOr(b.Ports, nil),
		SNINames: derefOr(b.SNINames, nil), Exclusions: derefOr(b.Exclusions, nil), Enabled: derefOr(b.Enabled, true), Schedule: sc,
		AlertOnExpiry: derefOr(b.AlertOnExpiry, false), RatePerSec: derefOr(b.RatePerSec, 0), Concurrency: derefOr(b.Concurrency, 0)}
}

func (b *discoveryScopeBody) patch() discoverysvc.ScopePatch {
	p := discoverysvc.ScopePatch{Name: b.Name, Entries: b.Entries, Ports: b.Ports, SNINames: b.SNINames, Exclusions: b.Exclusions,
		Enabled: b.Enabled, AlertOnExpiry: b.AlertOnExpiry, RatePerSec: b.RatePerSec, Concurrency: b.Concurrency}
	if sc, ok := b.schedule(); ok {
		p.Schedule = &sc
	}
	return p
}

func (s *server) writeDiscoveryScope(w http.ResponseWriter, r *http.Request, status int, v discoverysvc.ScopeView) {
	w.Header().Set("ETag", etag(v.Version))
	writeJSON(w, status, discoveryScopeJSON(v, s.serviceRefs(r)))
}

// timeIDCursor is a keyset position of (time, id): "<unix nanoseconds>.<uuid>".
func timeIDCursor(t time.Time, id uuid.UUID) string {
	return strconv.FormatInt(t.UnixNano(), 10) + "." + id.String()
}

// cursorParam reads ?cursor= with parse; a cursor that does not parse is a field error.
func cursorParam[T any](raw string, parse func(string) (T, bool), v *validate.Errors) *T {
	switch {
	case raw == "":
		return nil
	case len(raw) > maxCursorBytes:
		v.Add("cursor", validate.TooLong, map[string]string{"max": strconv.Itoa(maxCursorBytes)})
		return nil
	}
	c, ok := parse(raw)
	if !ok {
		v.Add("cursor", validate.Pattern, nil)
		return nil
	}
	return &c
}

func parseScopeCursor(raw string) (discoverysvc.ScopeCursor, bool) {
	t, id, ok := parseACMECertCursor(raw)
	return discoverysvc.ScopeCursor{CreatedAt: t, ID: id}, ok
}

func (s *server) listDiscoveryScopes(w http.ResponseWriter, r *http.Request) {
	refs := s.serviceRefs(r)
	q := r.URL.Query()
	var v validate.Errors
	f := discoverysvc.ScopeFilter{Limit: pageLimit(q.Get("limit"), &v), After: cursorParam(q.Get("cursor"), parseScopeCursor, &v),
		ServiceIDs: s.serviceFilter(r, &v), Reach: s.reachOf(r, rbac.DiscoveryView)}
	if err := v.Err(); err != nil {
		s.fail(w, r, err)
		return
	}
	list, more, err := s.deps.Discovery.ListScopes(r.Context(), f)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	items := make([]discoveryScopeDTO, 0, len(list))
	for _, sc := range list {
		items = append(items, discoveryScopeJSON(sc, refs))
	}
	next := ""
	if more && len(list) > 0 {
		last := list[len(list)-1]
		next = timeIDCursor(last.CreatedAt, last.ID)
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": items, "next_cursor": nextCursor(next)})
}

func (s *server) createDiscoveryScope(w http.ResponseWriter, r *http.Request) {
	var req discoveryScopeBody
	if !s.decodeExact(w, r, &req, maxDiscoveryScopeBody, append(slices.Clone(discoveryScopeKeys), "service_id")...) {
		return
	}
	v, err := s.deps.Discovery.CreateScopeIn(r.Context(), s.discoveryActor(r), req.scope(), derefOr(req.ServiceID, uuid.Nil))
	if err != nil {
		s.fail(w, r, err)
		return
	}
	w.Header().Set("Location", "/api/v1/discovery/scopes/"+v.ID.String())
	s.writeDiscoveryScope(w, r, http.StatusCreated, v)
}

// previewDiscoveryScope is the scope form's live size (no name resolved, nothing dialed, nothing stored). A body
// without a name is previewed under a placeholder name.
func (s *server) previewDiscoveryScope(w http.ResponseWriter, r *http.Request) {
	var req discoveryScopeBody
	if !s.decodeExact(w, r, &req, maxDiscoveryScopeBody, discoveryScopeKeys...) {
		return
	}
	sc := req.scope()
	if strings.TrimSpace(sc.Name) == "" {
		sc.Name = "preview"
	}
	p, err := s.deps.Discovery.Preview(r.Context(), sc)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, discoveryPreviewJSON(p))
}

func (s *server) getDiscoveryScope(w http.ResponseWriter, r *http.Request) {
	id, ok := pathUUID(r, "id")
	if !ok {
		s.writeError(w, r, ErrDSCScopeNotFound)
		return
	}
	v, err := s.deps.Discovery.GetScope(r.Context(), id)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	s.writeDiscoveryScope(w, r, http.StatusOK, v)
}

// optionalIfMatch reads an optional strong If-Match: absent is nil; anything else that is not one strong validator is
// answered 412.
func (s *server) optionalIfMatch(w http.ResponseWriter, r *http.Request) (*int, bool) {
	if r.Header.Get("If-Match") == "" {
		return nil, true
	}
	n, ok := ifMatch(r)
	if !ok {
		s.writeError(w, r, ErrPreconditionFailed)
		return nil, false
	}
	return &n, true
}

func (s *server) updateDiscoveryScope(w http.ResponseWriter, r *http.Request) {
	id, ok := pathUUID(r, "id")
	if !ok {
		s.writeError(w, r, ErrDSCScopeNotFound)
		return
	}
	version, ok := s.optionalIfMatch(w, r)
	if !ok {
		return
	}
	var req discoveryScopeBody
	if !s.decodeExact(w, r, &req, maxDiscoveryScopeBody, discoveryScopeKeys...) {
		return
	}
	if req == (discoveryScopeBody{}) {
		// An empty change would bump the version and write an audit row for nothing (Task 9 review 8).
		s.fail(w, r, validate.Errors{{Field: "body", Code: validate.Required}})
		return
	}
	v, err := s.deps.Discovery.UpdateScope(r.Context(), s.discoveryActor(r), id, version, req.patch())
	if err != nil {
		s.fail(w, r, err)
		return
	}
	s.writeDiscoveryScope(w, r, http.StatusOK, v)
}

func (s *server) deleteDiscoveryScope(w http.ResponseWriter, r *http.Request) {
	id, ok := pathUUID(r, "id")
	if !ok {
		s.writeError(w, r, ErrDSCScopeNotFound)
		return
	}
	version, ok := s.optionalIfMatch(w, r)
	if !ok {
		return
	}
	if err := s.deps.Discovery.DeleteScope(r.Context(), s.discoveryActor(r), id, version); err != nil {
		s.fail(w, r, err)
		return
	}
	noContent(w)
}

// --- scans ---

// startDiscoveryScan queues a scan of the scope (no body): 202 with the scan, which the netdisco.scan job runs.
func (s *server) startDiscoveryScan(w http.ResponseWriter, r *http.Request) {
	id, ok := pathUUID(r, "id")
	if !ok {
		s.writeError(w, r, ErrDSCScopeNotFound)
		return
	}
	v, err := s.deps.Discovery.StartScan(r.Context(), s.discoveryActor(r), id)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	w.Header().Set("Location", "/api/v1/discovery/scans/"+v.ID.String())
	writeJSON(w, http.StatusAccepted, discoveryScanJSON(v))
}

// discoveryScanStates are the values of GET /discovery/scans?state=.
var discoveryScanStates = []string{discovery.ScanQueued, discovery.ScanRunning, discovery.ScanDone, discovery.ScanCancelled, discovery.ScanTimedOut,
	discovery.ScanFailed}

func parseScanCursor(raw string) (discoverysvc.ScanCursor, bool) {
	t, id, ok := parseACMECertCursor(raw)
	return discoverysvc.ScanCursor{QueuedAt: t, ID: id}, ok
}

func (s *server) listDiscoveryScans(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	var v validate.Errors
	f := discoverysvc.ScanFilter{ScopeID: optionalUUID(q.Get("scope_id"), "scope_id", &v), State: q.Get("state"),
		Limit: pageLimit(q.Get("limit"), &v), After: cursorParam(q.Get("cursor"), parseScanCursor, &v), Reach: s.reachOf(r, rbac.DiscoveryView)}
	if f.State != "" && !slices.Contains(discoveryScanStates, f.State) {
		v.Add("state", validate.OneOf, map[string]string{"values": strings.Join(discoveryScanStates, ", ")})
	}
	if err := v.Err(); err != nil {
		s.fail(w, r, err)
		return
	}
	list, more, err := s.deps.Discovery.ListScans(r.Context(), f)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	items := make([]discoveryScanDTO, 0, len(list))
	for _, sc := range list {
		items = append(items, discoveryScanJSON(sc))
	}
	next := ""
	if more && len(list) > 0 {
		last := list[len(list)-1]
		next = timeIDCursor(last.QueuedAt, last.ID)
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": items, "next_cursor": nextCursor(next)})
}

func (s *server) getDiscoveryScan(w http.ResponseWriter, r *http.Request) {
	id, ok := pathUUID(r, "id")
	if !ok {
		s.writeError(w, r, ErrNotFound)
		return
	}
	v, err := s.deps.Discovery.GetScan(r.Context(), id)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, discoveryScanJSON(v))
}

// cancelDiscoveryScan asks the scan to stop (no body). Idempotent: a scan already asked, or already over, is answered as
// it is.
func (s *server) cancelDiscoveryScan(w http.ResponseWriter, r *http.Request) {
	id, ok := pathUUID(r, "id")
	if !ok {
		s.writeError(w, r, ErrNotFound)
		return
	}
	v, err := s.deps.Discovery.CancelScan(r.Context(), s.discoveryActor(r), id)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, discoveryScanJSON(v))
}

// --- certificates and endpoints ---

var (
	fingerprintRE = regexp.MustCompile(`^[0-9a-f]{64}$`)
	// discoveryStatuses are the values of ?status= ("all", or none, is every status).
	discoveryStatuses = []string{"all", discovery.StatusUnmanaged, discovery.StatusManaged, discovery.StatusKnown}
)

// triState reads an optional boolean query parameter: absent is nil.
func triState(raw, field string, v *validate.Errors) *bool {
	if raw == "" {
		return nil
	}
	b := parseBool(raw, field, v)
	return &b
}

var (
	minCursorMicro = time.Date(1, 1, 1, 0, 0, 0, 0, time.UTC).UnixMicro()
	maxCursorMicro = time.Date(9999, 12, 31, 23, 59, 59, 999999000, time.UTC).UnixMicro()
)

func parseCertificateCursor(raw string) (discovery.CertificateCursor, bool) {
	ns, fp, ok := strings.Cut(raw, ".")
	n, err := strconv.ParseInt(ns, 10, 64)
	// Years 1 to 9999: the dates PostgreSQL's timestamptz and the API's RFC 3339 carry; a position outside them was not issued.
	if !ok || err != nil || !fingerprintRE.MatchString(fp) || n < minCursorMicro || n > maxCursorMicro {
		return discovery.CertificateCursor{}, false
	}
	return discovery.CertificateCursor{NotAfter: time.UnixMicro(n).UTC(), Fingerprint: fp}, true
}

// certificateCursor is the certificate list's keyset position: "<not_after in Unix microseconds>.<fingerprint>".
// Microseconds are PostgreSQL's precision and hold every date up to 9999-12-31 (Unix nanoseconds overflow after 2262).
func certificateCursor(c discovery.CertificateRow) string {
	return strconv.FormatInt(c.NotAfter.UnixMicro(), 10) + "." + c.Fingerprint
}

// discoveryCertificateFilter reads the certificate list's filters (paging only when paged; the export refuses it) and
// the export's audit details of the filters given.
func (s *server) discoveryCertificateFilter(w http.ResponseWriter, r *http.Request, paged bool) (discovery.CertificateFilter, map[string]string, bool) {
	q := r.URL.Query()
	var v validate.Errors
	now := s.deps.Clock.Now().UTC()
	f := discovery.CertificateFilter{Now: now, ScopeID: optionalUUID(q.Get("scope_id"), "scope_id", &v),
		Expired: triState(q.Get("expired"), "expired", &v), SelfSigned: triState(q.Get("self_signed"), "self_signed", &v),
		Query: strings.TrimSpace(q.Get("q")), Reach: s.reachOf(r, rbac.DiscoveryView)}
	// current: only certificates some endpoint that is not gone presents or last presented (the summary's definition).
	if c := triState(q.Get("current"), "current", &v); c != nil {
		f.Current = *c
	}
	details := map[string]string{}
	for _, k := range []string{"status", "q", "expired", "self_signed", "current", "expiring_within_days", "scope_id"} {
		if val := q.Get(k); val != "" {
			details[k] = val
		}
	}
	switch st := q.Get("status"); {
	case st == "" || st == "all":
	case slices.Contains(discoveryStatuses, st):
		f.Status = st
	default:
		v.Add("status", validate.OneOf, map[string]string{"values": strings.Join(discoveryStatuses, ", ")})
	}
	if utf8.RuneCountInString(f.Query) > maxQueryRunes {
		v.Add("q", validate.TooLong, map[string]string{"max": strconv.Itoa(maxQueryRunes)})
	}
	if raw := q.Get("expiring_within_days"); raw != "" {
		n, err := strconv.Atoi(raw)
		if err != nil || n < 1 || n > maxDiscoveryExpiringDays {
			v.Add("expiring_within_days", validate.OutOfRange, map[string]string{"min": "1", "max": strconv.Itoa(maxDiscoveryExpiringDays)})
		} else {
			f.ExpiringBy = now.AddDate(0, 0, n)
		}
	}
	if paged {
		f.Limit = pageLimit(q.Get("limit"), &v)
		f.After = cursorParam(q.Get("cursor"), parseCertificateCursor, &v)
	} else {
		refusePaging(q, &v)
	}
	if err := v.Err(); err != nil {
		s.fail(w, r, err)
		return discovery.CertificateFilter{}, nil, false
	}
	return f, details, true
}

func (s *server) listDiscoveredCertificates(w http.ResponseWriter, r *http.Request) {
	f, _, ok := s.discoveryCertificateFilter(w, r, true)
	if !ok {
		return
	}
	list, more, err := s.deps.Discovery.ListCertificates(r.Context(), f)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	items := make([]discoveryCertificateDTO, 0, len(list))
	for _, c := range list {
		items = append(items, discoveryCertificateJSON(c, f.Now))
	}
	next := ""
	if more && len(list) > 0 {
		next = certificateCursor(list[len(list)-1])
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": items, "next_cursor": nextCursor(next)})
}

func (s *server) getDiscoveredCertificate(w http.ResponseWriter, r *http.Request) {
	fp, ok := pathFingerprint(r, "fingerprint")
	if !ok {
		s.writeError(w, r, ErrNotFound)
		return
	}
	c, eps, more, err := s.deps.Discovery.CertificateIn(r.Context(), fp, s.reachOf(r, rbac.DiscoveryView))
	if err != nil {
		s.fail(w, r, err)
		return
	}
	d := discoveryCertificateJSON(c, s.deps.Clock.Now())
	list := make([]discoveryEndpointDTO, 0, len(eps))
	for _, e := range eps {
		list = append(list, discoveryEndpointJSON(e))
	}
	d.Endpoints, d.MoreEndpoints = &list, &more
	writeJSON(w, http.StatusOK, discoveryCertificateDetailDTO{discoveryCertificateDTO: d, RevocationCheck: discoveryRevocationJSON(c.Revocation)})
}

// errExportCursor: a cursor the export made itself did not parse back (Alice's own mistake: the file is cut).
var errExportCursor = errors.New("api: an export cursor does not parse")

// discoveryExportColumns are the columns of the discovered certificates' CSV.
var discoveryExportColumns = []string{"fingerprint_sha256", "subject_cn", "sans", "issuer_cn", "not_before", "not_after", "days_left",
	"key_algorithm", "self_signed", "status", "managed_certificate_id", "endpoint_count", "seen_on_count", "first_seen", "last_seen"}

// exportDiscoveredCertificates streams the certificate list for its filters as CSV through the report export machinery
// (reports.ExportRows): one export at a time per person (409 ALC-RPT-0004), at most 50,000 rows counted first, the
// discovery.export audit row committed before the first byte, every cell through csvx's formula guard.
func (s *server) exportDiscoveredCertificates(w http.ResponseWriter, r *http.Request) {
	f, details, ok := s.discoveryCertificateFilter(w, r, false)
	if !ok {
		return
	}
	details["kind"], details["format"] = "discovery_certificates", "csv"
	if f.Reach.Limited {
		details["reach"] = f.Reach.String() // R49 Phase 2: the services the caller sees (absent: every service)
	}
	page := func(ctx context.Context, cursor string) ([][]string, string, error) {
		g := f
		g.Limit, g.After = 200, nil
		if cursor != "" {
			c, ok := parseCertificateCursor(cursor)
			if !ok {
				return nil, "", errExportCursor
			}
			g.After = &c
		}
		list, more, err := s.deps.Discovery.ListCertificates(ctx, g)
		if err != nil {
			return nil, "", err
		}
		rows := make([][]string, 0, len(list))
		for _, c := range list {
			managed := ""
			if c.ManagedID.Valid {
				managed = c.ManagedID.UUID.String()
			}
			rows = append(rows, []string{c.Fingerprint, c.SubjectCN, strings.Join(c.SANs, " "), c.IssuerCN, c.NotBefore.UTC().Format(time.RFC3339),
				c.NotAfter.UTC().Format(time.RFC3339), strconv.Itoa(expiry.DaysLeft(c.NotAfter, f.Now)), c.KeyAlgorithm, strconv.FormatBool(c.SelfSigned),
				c.Status, managed, strconv.Itoa(c.Endpoints), strconv.Itoa(c.SeenOn), c.FirstSeen.UTC().Format(time.RFC3339),
				c.LastSeen.UTC().Format(time.RFC3339)})
		}
		next := ""
		if more && len(list) > 0 {
			next = certificateCursor(list[len(list)-1])
		}
		return rows, next, nil
	}
	out := &csvResponse{w: w, name: s.exportName("discovered-certificates")}
	_, err := s.deps.Reports.ExportRows(r.Context(), principalFrom(r.Context()).Actor(s.meta(r)), reports.RowExport{Action: "discovery.export",
		Details: details, Header: discoveryExportColumns, Page: page}, out)
	s.endExport(w, r, out, err)
}

// endpointCursor is the endpoint list's keyset position: base64url of "address|port|sni|id" (the SNI grammar has no
// "|"; inside a scope the id is not used).
func endpointCursor(e discovery.EndpointRow) string {
	return base64.RawURLEncoding.EncodeToString([]byte(e.Address.String() + "|" + strconv.Itoa(e.Port) + "|" + e.SNI + "|" + e.ID.String()))
}

func parseEndpointCursor(raw string) (discovery.EndpointCursor, bool) {
	b, err := base64.RawURLEncoding.DecodeString(raw)
	if err != nil {
		return discovery.EndpointCursor{}, false
	}
	parts := strings.Split(string(b), "|")
	if len(parts) != 4 {
		return discovery.EndpointCursor{}, false
	}
	a, err1 := netip.ParseAddr(parts[0])
	port, err2 := strconv.Atoi(parts[1])
	id, err3 := uuid.Parse(parts[3])
	if err1 != nil || err2 != nil || err3 != nil || port < 1 || port > 65535 || a.Zone() != "" {
		return discovery.EndpointCursor{}, false
	}
	if parts[2] != "" {
		if c, err := discovery.CanonicalHostname(parts[2]); err != nil || c != parts[2] {
			return discovery.EndpointCursor{}, false
		}
	}
	return discovery.EndpointCursor{Address: a, Port: port, SNI: parts[2], ID: id}, true
}

// listDiscoveredEndpoints lists endpoints; inside a scope (scope_id) in the order of its unique key (address, port,
// SNI), across scopes by (address, port, SNI, id). fingerprint selects the endpoints presenting one leaf.
func (s *server) listDiscoveredEndpoints(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	var v validate.Errors
	f := discovery.EndpointFilter{ScopeID: optionalUUID(q.Get("scope_id"), "scope_id", &v), Fingerprint: q.Get("fingerprint"),
		Limit: pageLimit(q.Get("limit"), &v), After: cursorParam(q.Get("cursor"), parseEndpointCursor, &v), Reach: s.reachOf(r, rbac.DiscoveryView)}
	if f.Fingerprint != "" && !fingerprintRE.MatchString(f.Fingerprint) {
		v.Add("fingerprint", validate.Pattern, nil)
	}
	if err := v.Err(); err != nil {
		s.fail(w, r, err)
		return
	}
	list, more, err := s.deps.Discovery.ListEndpoints(r.Context(), f)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	items := make([]discoveryEndpointDTO, 0, len(list))
	for _, e := range list {
		items = append(items, discoveryEndpointJSON(e))
	}
	next := ""
	if more && len(list) > 0 {
		next = endpointCursor(list[len(list)-1])
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": items, "next_cursor": nextCursor(next)})
}

// --- settings and summary ---

func (s *server) getDiscoverySettings(w http.ResponseWriter, r *http.Request) {
	v, err := s.deps.Discovery.Settings(r.Context())
	if err != nil {
		s.fail(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, discoverySettingsJSON(v))
}

// putDiscoverySettings replaces the settings (every field required). An empty allowed_networks is valid: nothing may be
// scanned then (scanning_enabled false).
func (s *server) putDiscoverySettings(w http.ResponseWriter, r *http.Request) {
	var req struct {
		AllowedNetworks  *[]string `json:"allowed_networks"`
		GlobalExclusions *[]string `json:"global_exclusions"`
		RetentionDays    *int      `json:"retention_days"`
	}
	if !s.decodeExact(w, r, &req, maxDiscoverySettingsBody, "allowed_networks", "global_exclusions", "retention_days") {
		return
	}
	var v validate.Errors
	if req.AllowedNetworks == nil {
		v.Add("allowed_networks", validate.Required, nil)
	}
	if req.GlobalExclusions == nil {
		v.Add("global_exclusions", validate.Required, nil)
	}
	if req.RetentionDays == nil {
		v.Add("retention_days", validate.Required, nil)
	}
	for field, list := range map[string]*[]string{"allowed_networks": req.AllowedNetworks, "global_exclusions": req.GlobalExclusions} {
		if list != nil && len(*list) > discovery.MaxExclusions {
			v.Add(field, validate.TooLong, map[string]string{"max": strconv.Itoa(discovery.MaxExclusions)})
		}
	}
	if err := v.Err(); err != nil {
		s.fail(w, r, err)
		return
	}
	got, err := s.deps.Discovery.SaveSettings(r.Context(), s.discoveryActor(r), discoverysvc.Settings{AllowedNetworks: *req.AllowedNetworks,
		GlobalExclusions: *req.GlobalExclusions, RetentionDays: *req.RetentionDays})
	if err != nil {
		s.fail(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, discoverySettingsJSON(got))
}

func (s *server) discoverySummary(w http.ResponseWriter, r *http.Request) {
	v, err := s.deps.Discovery.SummaryIn(r.Context(), s.reachOf(r, rbac.DiscoveryView))
	if err != nil {
		s.fail(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, discoverySummaryJSON(v))
}
