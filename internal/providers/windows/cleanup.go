package windows

import (
	"context"
	"encoding/json"
	"errors"
	"maps"
	"slices"
	"time"

	"alice/internal/providers"
	"alice/internal/providers/windows/winproto"
)

// The certificate cleanup on Alice's side (R62 W3 Rulings 2, 3, 12): iis-cleanup --plan and --apply,
// each one call on a connection of its own (runWrite), mirroring status.go (one call, decode, map) and
// the W2 version gate and refusal mapping (W2 Ruling 6).

// cleanupRefusals are iis-cleanup's refusals that changed nothing (winhelper's cleanup: usage and input
// at exit 2, failures before its write gate at 4) and OUTCOME_UNKNOWN at 4, which is no refusal: the
// helper's budget ended after its first durable write (ReasonCleanupOutcomeUnknown). Any other code, or
// one of these at another exit, is outside the contract: ssh.protocol_error.
var cleanupRefusals = withCodes(inputRefusals, winproto.ExitFailed, winproto.CodeOutcomeUnknown)

// The helper's vocabulary of a cleanup answer: why a certificate is kept (an apply's result; a watched
// certificate's verdict never says too_young, which only an apply's age check gives), the plan's
// warnings, the stores a watched certificate is looked up in (winhelper's watchStores) and what a
// candidate may be eligible as (incident is Alice's reason only).
var (
	keptReasons = []string{winproto.KeptBound, winproto.KeptRDP, winproto.KeptWinRM, winproto.KeptJournal, winproto.KeptNotAlice,
		winproto.KeptTooYoung, winproto.KeptJournalUnreadable}
	watchedReasons = slices.DeleteFunc(slices.Clone(keptReasons), func(r string) bool { return r == winproto.KeptTooYoung })
	planWarnings   = []string{winproto.WarnJournalUnreadable, winproto.WarnBindingRecordUnreadable}
	watchStores    = []string{"my", "webhosting"} // folded
	eligibleValues = []string{"", winproto.CleanupAged, winproto.CleanupExpired}
)

// cleanupReady refuses a helper older than winproto.CleanupMinVersion before iis-cleanup is sent (Ruling
// 2: a 0.2.0 helper would answer UNKNOWN_SUBCOMMAND; it still deploys, writeReady).
func (s *session) cleanupReady() error {
	if winproto.VersionAtLeast(s.version.Helper, winproto.CleanupMinVersion) {
		return nil
	}
	return outdatedForCleanup(s.version.Helper, nil)
}

// outdatedForCleanup is windows.helper_outdated naming the helper's version and CleanupMinVersion (with
// the cause's params, when a helper's refusal is the cause).
func outdatedForCleanup(helper string, cause *providers.Error) *providers.Error {
	params := map[string]string{}
	var err error
	if cause != nil { // a helper's UNKNOWN_SUBCOMMAND: its subcommand and code stay
		maps.Copy(params, cause.Params)
		err = cause
	}
	params["helper_version"], params["required_version"] = helper, winproto.CleanupMinVersion
	return providers.NewError(ReasonHelperOutdated, false, err, params)
}

// cleanupStart is what both methods check first: the capability, an open session, a helper of at
// least CleanupMinVersion.
func (s *session) cleanupStart() error {
	if !s.caps.Has(providers.CapCleanupCertificates) {
		return providers.ErrUnsupported
	}
	if err := s.open(); err != nil {
		return err
	}
	return s.cleanupReady()
}

// PlanCleanup implements providers.CertificateCleaner with iis-cleanup --plan: watch (duplicates sent
// once) goes on standard input as winproto.CleanupPlanInput. The answer is checked against the helper's
// vocabulary (checkPlan); one that breaks it is an ssh.protocol_error, never a plan. Refusals map as W2
// Ruling 6 (UNKNOWN_SUBCOMMAND: windows.helper_outdated); OUTCOME_UNKNOWN is the retryable
// windows.cleanup_outcome_unknown. A watch list the helper would refuse (more than MaxForbidden
// certificates, a malformed hash) is refused before anything is sent (internal.unexpected).
func (s *session) PlanCleanup(ctx context.Context, watch []providers.CleanupRef) (providers.CleanupPlan, error) {
	if err := s.cleanupStart(); err != nil {
		return providers.CleanupPlan{}, err
	}
	in := winproto.CleanupPlanInput{Watch: []winproto.CleanupRef{}}
	sent := map[providers.CleanupRef]bool{}
	for _, r := range watch {
		if !winproto.ValidSHA1(r.SHA1) || !winproto.ValidSHA256(r.SHA256) {
			return providers.CleanupPlan{}, providers.NewError(reasonUnexpected, false, errors.New("windows: a watched certificate is not a valid reference"), nil)
		}
		if !sent[r] {
			sent[r] = true
			in.Watch = append(in.Watch, winproto.CleanupRef{SHA1: r.SHA1, SHA256: r.SHA256})
		}
	}
	if len(in.Watch) > winproto.MaxForbidden {
		return providers.CleanupPlan{}, providers.NewError(reasonUnexpected, false, errors.New("windows: the watch list is too long"), nil)
	}
	raw, _ := json.Marshal(in) // strings only: cannot fail; MaxForbidden references fit MaxCleanupInput
	r, err := cleanupCall[winproto.CleanupPlanResponse](ctx, s, winproto.ArgPlan, raw)
	if err != nil {
		return providers.CleanupPlan{}, err
	}
	plan, why := checkPlan(r, sent)
	if why != "" {
		return providers.CleanupPlan{}, protocolError(winproto.SubIISCleanup, why)
	}
	return plan, nil
}

// ApplyCleanup implements providers.CertificateCleaner with iis-cleanup --apply: the items go on
// standard input as winproto.CleanupApplyInput; the helper judges each again under its lock and answers
// one result per item in order (checkApply). An empty list sends nothing and answers nothing; a list the
// helper would refuse (more than MaxCleanupItems, an item that is not winproto.ValidCleanupItem) is
// refused before anything is sent. Errors as PlanCleanup's.
func (s *session) ApplyCleanup(ctx context.Context, items []providers.CleanupItem) (providers.CleanupApplyResult, error) {
	if err := s.cleanupStart(); err != nil {
		return providers.CleanupApplyResult{}, err
	}
	if len(items) == 0 {
		return providers.CleanupApplyResult{}, nil
	}
	if len(items) > winproto.MaxCleanupItems {
		return providers.CleanupApplyResult{}, providers.NewError(reasonUnexpected, false, errors.New("windows: too many certificates to remove"), nil)
	}
	in := winproto.CleanupApplyInput{Remove: make([]winproto.CleanupItem, 0, len(items))}
	for _, it := range items {
		w := winproto.CleanupItem{Store: it.Store, SHA1: it.SHA1, SHA256: it.SHA256, Reason: it.Reason}
		if !winproto.ValidCleanupItem(w) {
			return providers.CleanupApplyResult{}, providers.NewError(reasonUnexpected, false, errors.New("windows: a certificate to remove is not a valid item"), nil)
		}
		in.Remove = append(in.Remove, w)
	}
	raw, _ := json.Marshal(in) // strings only: cannot fail; MaxCleanupItems items fit MaxCleanupInput
	r, err := cleanupCall[winproto.CleanupApplyResponse](ctx, s, winproto.ArgApply, raw)
	if err != nil {
		return providers.CleanupApplyResult{}, err
	}
	res, why := checkApply(r, items)
	if why != "" {
		return providers.CleanupApplyResult{}, protocolError(winproto.SubIISCleanup, why)
	}
	return res, nil
}

// cleanupCall runs iis-cleanup in mode with input and sorts the result: an answer; OUTCOME_UNKNOWN →
// windows.cleanup_outcome_unknown (retryable); UNKNOWN_SUBCOMMAND → windows.helper_outdated with the
// versions; any other refusal as mapHelper names it; anything uncertain (a transport error after the
// send, no answer, a code outside cleanupRefusals) as runWrite sorted it.
func cleanupCall[T any](ctx context.Context, s *session, mode string, input []byte) (T, error) {
	var zero T
	c := runWrite[T](ctx, s, winproto.SubIISCleanup, input, cleanupRefusals, mode)
	switch {
	case c.uncertain != nil:
		return zero, c.uncertain
	case c.code == winproto.CodeOutcomeUnknown:
		return zero, providers.NewError(ReasonCleanupOutcomeUnknown, true, c.refusal, map[string]string{"subcommand": winproto.SubIISCleanup})
	case c.code == winproto.CodeUnknownSubcommand:
		return zero, outdatedForCleanup(s.version.Helper, c.refusal)
	case c.refusal != nil:
		return zero, c.refusal
	}
	return c.answer, nil
}

// checkPlan converts a plan answer, or names why it breaks the helper's contract: at most
// MaxCleanupCandidates candidates, each in a valid store with valid hashes, an eligibility of
// eligibleValues, an RFC 3339 unbound_since and a not_after that is RFC 3339 or absent; the verdicts
// (checkWatched); known warnings (each once in the plan); a pruned count within MaxPrunePerRun.
func checkPlan(r winproto.CleanupPlanResponse, sent map[providers.CleanupRef]bool) (providers.CleanupPlan, string) {
	var plan providers.CleanupPlan
	if len(r.Candidates) > winproto.MaxCleanupCandidates {
		return plan, "more candidates than a plan lists"
	}
	for _, c := range r.Candidates {
		since, err1 := time.Parse(time.RFC3339, c.UnboundSince)
		var notAfter time.Time
		var err2 error
		if c.NotAfter != "" {
			notAfter, err2 = time.Parse(time.RFC3339, c.NotAfter)
		}
		switch {
		case !winproto.ValidStore(c.Store) || !winproto.ValidSHA1(c.SHA1) || !winproto.ValidSHA256(c.SHA256):
			return providers.CleanupPlan{}, "a candidate that is not a valid certificate reference"
		case !slices.Contains(eligibleValues, c.Eligible):
			return providers.CleanupPlan{}, "a candidate with an unknown eligibility"
		case err1 != nil || err2 != nil:
			return providers.CleanupPlan{}, "a candidate with a time that is not RFC 3339"
		}
		plan.Candidates = append(plan.Candidates, providers.CleanupCertificate{Store: c.Store, SHA1: c.SHA1, SHA256: c.SHA256,
			FriendlyName: cleanValue(c.FriendlyName, winproto.MaxText), Eligible: c.Eligible, NotAfter: notAfter.UTC(), UnboundSince: since.UTC()})
	}
	watched, why := checkWatched(r.Watched, sent)
	if why != "" {
		return providers.CleanupPlan{}, why
	}
	plan.Watched = watched
	for _, w := range r.Warnings {
		if !slices.Contains(planWarnings, w) {
			return providers.CleanupPlan{}, "an unknown warning"
		}
		if !slices.Contains(plan.Warnings, w) {
			plan.Warnings = append(plan.Warnings, w)
		}
	}
	if r.Pruned < 0 || r.Pruned > winproto.MaxPrunePerRun {
		return providers.CleanupPlan{}, "a pruned count outside a run's bound"
	}
	plan.Pruned, plan.Partial = r.Pruned, r.Truncated
	return plan, ""
}

// checkWatched checks the verdicts on the watched certificates: each names a certificate that was sent;
// a found one (removable, or kept for a reason of watchedReasons; removable gives no reason) names one of
// watchStores, each store once per certificate; an absent one names no store and no reason and is the
// certificate's only verdict; every certificate sent has a verdict.
func checkWatched(in []winproto.CleanupWatched, sent map[providers.CleanupRef]bool) ([]providers.CleanupWatched, string) {
	type seen struct {
		absent bool
		stores []string
	}
	got := map[providers.CleanupRef]*seen{}
	var out []providers.CleanupWatched
	for _, w := range in {
		k := providers.CleanupRef{SHA1: w.SHA1, SHA256: w.SHA256}
		if !sent[k] {
			return nil, "a verdict on a certificate that was not watched"
		}
		g := got[k]
		if g == nil {
			g = &seen{}
			got[k] = g
		}
		switch w.State {
		case winproto.WatchAbsent:
			if w.Store != "" || w.Reason != "" || g.absent || len(g.stores) > 0 {
				return nil, "an absent verdict with a store, a reason or another verdict"
			}
			g.absent = true
		case winproto.WatchRemovable, winproto.WatchKept:
			store := foldASCII(w.Store)
			switch {
			case !slices.Contains(watchStores, store) || g.absent || slices.Contains(g.stores, store):
				return nil, "a verdict in an unknown store, or a store twice"
			case w.State == winproto.WatchRemovable && w.Reason != "":
				return nil, "a removable verdict with a reason"
			case w.State == winproto.WatchKept && !slices.Contains(watchedReasons, w.Reason):
				return nil, "a kept verdict without a known reason"
			}
			g.stores = append(g.stores, store)
		default:
			return nil, "a verdict with an unknown state"
		}
		out = append(out, providers.CleanupWatched{Store: w.Store, SHA1: w.SHA1, SHA256: w.SHA256, State: w.State, Reason: w.Reason})
	}
	if len(got) != len(sent) {
		return nil, "a watched certificate without a verdict"
	}
	return out, ""
}

// checkApply converts an apply answer, or names why it breaks the helper's contract: one result per
// item in order, each naming its item's SHA-256, a known result, and a reason of keptReasons exactly
// when kept.
func checkApply(r winproto.CleanupApplyResponse, items []providers.CleanupItem) (providers.CleanupApplyResult, string) {
	if len(r.Results) != len(items) {
		return providers.CleanupApplyResult{}, "not one result per certificate"
	}
	out := providers.CleanupApplyResult{Results: make([]providers.CleanupItemResult, 0, len(r.Results))}
	for i, res := range r.Results {
		switch {
		case res.SHA256 != items[i].SHA256:
			return providers.CleanupApplyResult{}, "a result for a certificate that was not sent there"
		case res.Result == winproto.CleanupKept && !slices.Contains(keptReasons, res.Reason):
			return providers.CleanupApplyResult{}, "a kept result without a known reason"
		case res.Result != winproto.CleanupKept && (res.Reason != "" || (res.Result != winproto.CleanupRemoved && res.Result != winproto.CleanupAbsent)):
			return providers.CleanupApplyResult{}, "an unknown result, or a reason for one that was not kept"
		}
		out.Results = append(out.Results, providers.CleanupItemResult{SHA256: res.SHA256, Result: res.Result, Reason: res.Reason})
	}
	return out, ""
}
