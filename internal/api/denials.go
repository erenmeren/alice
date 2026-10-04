package api

import (
	"context"
	"hash/maphash"
	"maps"
	"net/http"
	"net/netip"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"alice/internal/audit"
	"alice/internal/auth"
	"alice/internal/platform/clock"
	"alice/internal/rbac"
)

// Coalescing of the guard's denial audit rows (AUD-06, R39): within denialWindow, repeated refusals
// with one key (the subject, the permission or license class, the reason and the route) add no row.
// The first refusal of a window is written at once. When the window ends with refusals left out,
// one more row is appended: the same action and details plus suppressed_count, window_start,
// window_end and what the left-out refusals varied in (distinct_ip_count with up to
// maxIPSamples addresses in ip_samples, distinct_object_count, distinct_token_count). No row is
// ever updated: the chain stays append-only.
const (
	// denialWindow is how long repeated refusals of one key are left out after the row written for
	// the first one.
	denialWindow = 10 * time.Minute
	// maxDenialKeys bounds the coalescer's memory. At the cap, closed windows are summarised and
	// dropped first, then the oldest open window is summarised early; a new key always gets its row.
	maxDenialKeys = 10000
	// denialSweepInterval is how often RunDenialSummaries looks for windows that have ended.
	denialSweepInterval = time.Minute
	// maxDistinct bounds each distinct-value set of a window; beyond it the count is written as
	// "<maxDistinct>+" ("64+": more than 64). Three sets of at most 64 hashes per open window keep the
	// coalescer's memory small at maxDenialKeys windows.
	maxDistinct = 64
	// maxIPSamples is how many client addresses a summary names.
	maxIPSamples = 3
)

// denialState is one open window: the row written for its first refusal and how many refusals of
// the same key were left out since.
type denialState struct {
	gen        uint64 // tells this window from a later one of the same key (release)
	opened     time.Time
	suppressed int
	ev         audit.Event
	// What the window's refusals (the first included) varied in.
	ips, objects, tokens distinctSet
	ipSamples            []string
}

// distinctSet counts distinct values up to maxDistinct, keeping only 64-bit hashes.
type distinctSet struct {
	seen map[uint64]struct{}
	over bool
}

func (d *distinctSet) add(seed maphash.Seed, v string) {
	if v == "" {
		return
	}
	h := maphash.String(seed, v)
	if _, ok := d.seen[h]; ok {
		return
	}
	if len(d.seen) >= maxDistinct {
		d.over = true
		return
	}
	if d.seen == nil {
		d.seen = map[uint64]struct{}{}
	}
	d.seen[h] = struct{}{}
}

func (d *distinctSet) count() string {
	n := strconv.Itoa(len(d.seen))
	if d.over {
		n += "+"
	}
	return n
}

// observe adds one refusal's client address, object and token to st. The address is the one the
// audit row stores (parsed, canonical: never request text).
func (st *denialState) observe(seed maphash.Seed, ev audit.Event) {
	if ev.Actor.IP.IsValid() {
		ip := ev.Actor.IP.Unmap().WithZone("").String()
		st.ips.add(seed, ip)
		if len(st.ipSamples) < maxIPSamples && !slices.Contains(st.ipSamples, ip) {
			st.ipSamples = append(st.ipSamples, ip)
		}
	}
	st.objects.add(seed, ev.ObjectID)
	st.tokens.add(seed, ev.Details["token_id"])
}

// denialCoalescer holds the open windows of this process (in memory: each process coalesces on its
// own, and counts not yet written are lost if the process dies).
type denialCoalescer struct {
	mu   sync.Mutex
	clk  clock.Clock
	seed maphash.Seed
	gen  uint64
	open map[string]*denialState
}

func newDenialCoalescer(clk clock.Clock) *denialCoalescer {
	return &denialCoalescer{clk: clk, seed: maphash.MakeSeed(), open: map[string]*denialState{}}
}

// admit decides about one refusal with key, whose row would be ev. write reports whether ev is
// written now (the first refusal of a new window, gen naming it for release). summaries are rows to append
// before it, for windows this call closed: key's own window that has ended, or, at the cap, the
// windows it had to drop.
func (c *denialCoalescer) admit(key string, ev audit.Event) (gen uint64, write bool, summaries []audit.Event) {
	c.mu.Lock()
	defer c.mu.Unlock()
	now := c.clk.Now()
	if st, ok := c.open[key]; ok {
		if now.Sub(st.opened) < denialWindow {
			st.suppressed++
			st.observe(c.seed, ev)
			return 0, false, nil
		}
		summaries = appendSummary(summaries, st, st.opened.Add(denialWindow))
		delete(c.open, key)
	}
	if len(c.open) >= maxDenialKeys {
		summaries = append(summaries, c.makeRoom(now)...)
	}
	c.gen++
	st := &denialState{gen: c.gen, opened: now, ev: ev}
	st.observe(c.seed, ev)
	c.open[key] = st
	return c.gen, true, summaries
}

// release forgets key's window gen, because its first row could not be written: the
// next refusal of key gets a row again instead of being left out behind a row that does not exist.
// Refusals already left out are returned as a summary to write.
func (c *denialCoalescer) release(key string, gen uint64) []audit.Event {
	c.mu.Lock()
	defer c.mu.Unlock()
	st, ok := c.open[key]
	if !ok || st.gen != gen {
		return nil // a later window replaced it
	}
	delete(c.open, key)
	return appendSummary(nil, st, c.clk.Now())
}

// makeRoom drops windows until a new key fits: every closed window, then (if none was closed) the
// oldest open one, whose count is summarised early (window_end is now). The caller holds c.mu.
func (c *denialCoalescer) makeRoom(now time.Time) []audit.Event {
	out := c.sweepLocked(now)
	if len(c.open) < maxDenialKeys {
		return out
	}
	var oldestKey string
	var oldest *denialState
	for k, st := range c.open {
		if oldest == nil || st.opened.Before(oldest.opened) {
			oldestKey, oldest = k, st
		}
	}
	delete(c.open, oldestKey)
	return appendSummary(out, oldest, now)
}

// sweep drops every window that has ended and returns the summaries of those with refusals left out.
func (c *denialCoalescer) sweep() []audit.Event {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.sweepLocked(c.clk.Now())
}

func (c *denialCoalescer) sweepLocked(now time.Time) []audit.Event {
	var closed []*denialState
	for k, st := range c.open {
		if now.Sub(st.opened) >= denialWindow {
			closed = append(closed, st)
			delete(c.open, k)
		}
	}
	return summariesOf(closed, now)
}

// drain drops every window, ended or not, and returns the summaries of those with refusals left
// out; an open window's summary ends now (shutdown).
func (c *denialCoalescer) drain() []audit.Event {
	c.mu.Lock()
	defer c.mu.Unlock()
	all := slices.Collect(maps.Values(c.open))
	c.open = map[string]*denialState{}
	return summariesOf(all, c.clk.Now())
}

// summariesOf returns the summaries of windows, oldest first; a window ends at its full length or
// at now, whichever is earlier.
func summariesOf(windows []*denialState, now time.Time) []audit.Event {
	slices.SortFunc(windows, func(a, b *denialState) int { return a.opened.Compare(b.opened) })
	var out []audit.Event
	for _, st := range windows {
		end := st.opened.Add(denialWindow)
		if now.Before(end) {
			end = now
		}
		out = appendSummary(out, st, end)
	}
	return out
}

func (c *denialCoalescer) len() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.open)
}

// reset forgets every window without writing anything (the e2e reset endpoint).
func (c *denialCoalescer) reset() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.open = map[string]*denialState{}
}

// appendSummary appends the summary row of st's window ending at end, when refusals were left out.
// It names the same subject, action and details as the window's first row, plus the counts. The
// address, the request ID and the object ID are left out, as the row stands for many requests;
// ip_samples names up to maxIPSamples of the addresses.
func appendSummary(out []audit.Event, st *denialState, end time.Time) []audit.Event {
	if st.suppressed == 0 {
		return out
	}
	d := maps.Clone(st.ev.Details)
	if d == nil {
		d = map[string]string{}
	}
	delete(d, "token_id") // the first row names its token; the summary may stand for several
	d["suppressed_count"] = strconv.Itoa(st.suppressed)
	d["window_start"] = st.opened.UTC().Format(time.RFC3339Nano)
	d["window_end"] = end.UTC().Format(time.RFC3339Nano)
	if len(st.ipSamples) > 0 {
		d["distinct_ip_count"] = st.ips.count()
		d["ip_samples"] = strings.Join(st.ipSamples, ",")
	}
	if len(st.objects.seen) > 0 {
		d["distinct_object_count"] = st.objects.count()
	}
	if len(st.tokens.seen) > 0 {
		d["distinct_token_count"] = st.tokens.count()
	}
	actor := st.ev.Actor
	actor.IP, actor.RequestID = netip.Addr{}, ""
	return append(out, audit.Event{Actor: actor, Action: st.ev.Action, ObjectType: st.ev.ObjectType,
		Result: st.ev.Result, Details: d})
}

// denialSubject identifies who was refused: a person by user, all their sessions together, and
// all API tokens of one owner together, apart from that owner's sessions. Tokens are unlimited per
// user, so a per-token subject would multiply the bound on log growth by the number of tokens.
func denialSubject(p auth.Principal) string {
	if p.Kind == rbac.APIToken {
		return "u:" + p.UserID.String() + "|tok"
	}
	return "u:" + p.UserID.String()
}

// denialActor is the audit actor of a refusal, and the details that name the API token of a token
// principal (the coalescing subject groups an owner's tokens; each first row names its token).
func (s *server) denialActor(r *http.Request, p auth.Principal, details map[string]string) audit.Actor {
	if p.Kind == rbac.APIToken {
		details["token_id"] = p.TokenID.String()
	}
	return p.Actor(s.meta(r))
}

// denialKey is the coalescing key: subject, what was refused (a permission or "license:<class>"),
// the reason and the route (method and pattern, never the requested path), so the log still shows
// every route that was probed (ruling S3).
func denialKey(p auth.Principal, what, reason string, rt route) string {
	return denialSubject(p) + "|" + what + "|" + reason + "|" + rt.method + " " + rt.pattern
}

// auditNotOwner records a refused access to another user's object (reason not_owner). The key is
// the subject, permission, reason and route, never the object: asking for many IDs is one window,
// whose summary counts the distinct objects (distinct_object_count). The first row names its object.
func (s *server) auditNotOwner(r *http.Request, p auth.Principal, rt route, objectType, objectID string) {
	details := map[string]string{"permission": string(rt.perm), "method": rt.method, "path": rt.pattern, "reason": "not_owner"}
	ev := audit.Event{Actor: s.denialActor(r, p, details), Action: "authz.denied", ObjectType: objectType, ObjectID: objectID,
		Result: audit.Denied, Details: details}
	s.recordDenial(r, denialKey(p, string(rt.perm), "not_owner", rt), ev)
}

// recordDenial writes ev for a refusal unless the window of key already has its row, and first any
// summary rows the coalescer hands back. A first row that cannot be written releases its window, so
// the next refusal is written instead of being left out.
func (s *server) recordDenial(r *http.Request, key string, ev audit.Event) {
	gen, write, summaries := s.denials.admit(key, ev)
	for _, sm := range summaries {
		s.writeAuditDetached(r, sm)
	}
	if write && !s.writeAuditDetached(r, ev) {
		for _, sm := range s.denials.release(key, gen) {
			s.writeAuditDetached(r, sm)
		}
	}
}

// auditWriteTimeout bounds an audit write that outlives its request (AUD-15), and so how long a
// refusal's answer can wait for its audit row.
const auditWriteTimeout = 5 * time.Second

// writeAuditDetached writes ev on a context that the client's disconnect does not cancel, for at
// most auditWriteTimeout (AUD-15). A failure is logged with fixed labels only and reported as
// false; the refusal it records stays a refusal.
func (s *server) writeAuditDetached(r *http.Request, ev audit.Event) bool {
	ctx, cancel := context.WithTimeout(context.WithoutCancel(r.Context()), auditWriteTimeout)
	defer cancel()
	if err := s.deps.Audit.Write(ctx, ev); err != nil {
		s.deps.Log.Error("audit write failed", append([]any{"request_id", RequestID(r.Context()), "action", ev.Action,
			"actor_id", ev.Actor.ID.String(), "route", ev.Details["path"]}, errorAttrs(err)...)...)
		return false
	}
	return true
}

// writeSummaries writes summary rows outside any request, each on its own bounded context. It stops
// when ctx ends and logs how many counts were not written then.
func (s *server) writeSummaries(ctx context.Context, evs []audit.Event) {
	for i, ev := range evs {
		if ctx.Err() != nil {
			s.deps.Log.Error("denial summaries not written", "count", len(evs)-i)
			return
		}
		wctx, cancel := context.WithTimeout(ctx, auditWriteTimeout)
		err := s.deps.Audit.Write(wctx, ev)
		cancel()
		if err != nil {
			s.deps.Log.Error("audit write failed", append([]any{"action", ev.Action, "actor_id", ev.Actor.ID.String(),
				"route", ev.Details["path"], "suppressed_count", ev.Details["suppressed_count"]}, errorAttrs(err)...)...)
		}
	}
}

// RunDenialSummaries writes, every denialSweepInterval on the injected clock, the summary row of
// each denial window that has ended with refusals left out (AUD-06). It returns when ctx ends;
// summaries taken from the coalescer are still written then, each within auditWriteTimeout.
func (s *Server) RunDenialSummaries(ctx context.Context) {
	t := s.s.deps.Clock.NewTicker(denialSweepInterval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C():
			s.s.writeSummaries(context.WithoutCancel(ctx), s.s.denials.sweep())
		}
	}
}

// FlushDenials writes the summary of every denial window with refusals left out, open windows
// included (their window_end is now), and forgets them. cmd/alice calls it at shutdown after the
// HTTP servers stopped; it is best effort within ctx: counts not written by then are lost (and
// logged as a number), as they are when the process dies.
func (s *Server) FlushDenials(ctx context.Context) {
	s.s.writeSummaries(ctx, s.s.denials.drain())
}
