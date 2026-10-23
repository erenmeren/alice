package windows

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"alice/internal/providers"
	"alice/internal/providers/linuxssh/linuxsshtest"
	"alice/internal/providers/windows/winproto"
	"alice/internal/testutil/pki"
)

// versionAnswer scripts the helper's version answer.
func versionAnswer(helper string) func([]byte) linuxsshtest.Response {
	return func([]byte) linuxsshtest.Response {
		b, _ := json.Marshal(winproto.VersionResponse{OK: true, Helper: helper, Protocol: 1})
		return linuxsshtest.Response{Stdout: append(b, '\n')}
	}
}

// jsonAnswer is an exit-0 answer of v.
func jsonAnswer(v any) linuxsshtest.Response {
	b, _ := json.Marshal(v)
	return linuxsshtest.Response{Stdout: append(b, '\n')}
}

// redeploy deploys a over the wenv's old certificate and then b over a, both through the helper on the
// model (operations of their own), so a is a certificate Alice imported that nothing uses any more.
func (w *wenv) redeploy(t *testing.T) (a, b pki.Leaf) {
	t.Helper()
	a, b = w.issue(), w.issue()
	require.Equal(t, winproto.PhaseCommitted, w.deploy(t, uuid.New(), w.old.Cert.Raw, a).Phase)
	require.Equal(t, winproto.PhaseCommitted, w.deploy(t, uuid.New(), a.Cert.Raw, b).Phase)
	return a, b
}

func refOf(l pki.Leaf) providers.CleanupRef {
	return providers.CleanupRef{SHA1: sha1Hex(l.Cert.Raw), SHA256: derSHA256(l.Cert.Raw)}
}

func itemFor(l pki.Leaf, reason string) providers.CleanupItem {
	return providers.CleanupItem{Store: "My", SHA1: sha1Hex(l.Cert.Raw), SHA256: derSHA256(l.Cert.Raw), Reason: reason}
}

// The values Alice's judgement (internal/inventory, which may not import winproto) reads are the helper's.
func TestCleanupValuesAreTheHelpers(t *testing.T) {
	assert.Equal(t, []string{winproto.CleanupAged, winproto.CleanupExpired, winproto.CleanupIncident, winproto.CleanupRemoved,
		winproto.CleanupKept, winproto.CleanupAbsent, winproto.WatchRemovable, winproto.WatchKept, winproto.WatchAbsent},
		[]string{providers.CleanupAged, providers.CleanupExpired, providers.CleanupIncident, providers.CleanupRemoved, providers.CleanupKept,
			providers.CleanupAbsent, providers.WatchRemovable, providers.WatchKept, providers.WatchAbsent})
	assert.Equal(t, []string{winproto.KeptBound, winproto.KeptRDP, winproto.KeptWinRM, winproto.KeptJournal, winproto.KeptNotAlice,
		winproto.KeptTooYoung, winproto.KeptJournalUnreadable}, keptReasons)
	assert.Equal(t, []string{winproto.WarnJournalUnreadable, winproto.WarnBindingRecordUnreadable}, planWarnings)
}

// Review Focus 6, W3 Ruling 2: a W2 helper (0.2.0) is named outdated before iis-cleanup is sent, and
// still deploys; a helper that answers UNKNOWN_SUBCOMMAND anyway is outdated too.
func TestCleanupNeedsHelper030(t *testing.T) {
	ctx := context.Background()
	w := newWEnv(t)
	w.script(winproto.SubVersion, versionAnswer("0.2.0"))
	s := w.session(t)
	want := map[string]string{"helper_version": "0.2.0", "required_version": "0.3.0"}
	_, err := s.PlanCleanup(ctx, []providers.CleanupRef{refOf(w.old)})
	pe := providerErr(t, err)
	assert.Equal(t, ReasonHelperOutdated, pe.Code)
	assert.False(t, pe.Retryable)
	assert.Equal(t, want, pe.Params)
	_, err = s.ApplyCleanup(ctx, []providers.CleanupItem{itemFor(w.old, providers.CleanupAged)})
	pe = providerErr(t, err)
	assert.Equal(t, ReasonHelperOutdated, pe.Code)
	assert.Equal(t, want, pe.Params)
	assert.Equal(t, []string{"version"}, w.srv.Commands(), "nothing but the version was sent")

	out, err := s.DeployCertificate(ctx, w.deployReq(w.issue()), nil)
	require.NoError(t, err)
	assert.Equal(t, providers.DeployCommitted, out.Result, "a W2 helper still deploys (WriteMinVersion stays 0.2.0)")

	// The backstop: a helper that does not know iis-cleanup although it says 0.3.0.
	w = newWEnv(t)
	w.script(winproto.SubIISCleanup, func([]byte) linuxsshtest.Response { return refusalResponse(2, winproto.CodeUnknownSubcommand) })
	s = w.session(t)
	_, err = s.PlanCleanup(ctx, nil)
	pe = providerErr(t, err)
	assert.Equal(t, ReasonHelperOutdated, pe.Code)
	assert.Equal(t, "0.3.0", pe.Params["required_version"])
	assert.Equal(t, winproto.Version, pe.Params["helper_version"])
	_, err = s.ApplyCleanup(ctx, []providers.CleanupItem{itemFor(w.old, providers.CleanupAged)})
	assert.Equal(t, ReasonHelperOutdated, providerErr(t, err).Code)
}

// The Task 4 scenario through the provider: a certificate replaced by a later deployment is a candidate,
// eligible after seven days by the helper's clock, removed with its key; the one bound stays; watched
// certificates get their verdicts; a second apply finds it absent.
func TestPlanAndApplyOverSSH(t *testing.T) {
	ctx := context.Background()
	w := newWEnv(t)
	a, b := w.redeploy(t)
	s := w.session(t)
	zero := providers.CleanupRef{SHA1: strings.Repeat("0", 40), SHA256: strings.Repeat("0", 64)}

	plan, err := s.PlanCleanup(ctx, []providers.CleanupRef{refOf(a), refOf(w.old), zero})
	require.NoError(t, err)
	require.Len(t, plan.Candidates, 1)
	c := plan.Candidates[0]
	assert.Equal(t, []string{"My", sha1Hex(a.Cert.Raw), derSHA256(a.Cert.Raw), ""}, []string{c.Store, c.SHA1, c.SHA256, c.Eligible},
		"a fresh unbound import is a candidate, not yet eligible")
	assert.True(t, strings.HasPrefix(c.FriendlyName, "Alice"), c.FriendlyName)
	assert.True(t, c.NotAfter.Equal(a.Cert.NotAfter.Truncate(time.Second)), "%s %s", c.NotAfter, a.Cert.NotAfter)
	assert.WithinDuration(t, time.Now(), c.UnboundSince, time.Minute)
	assert.Equal(t, []providers.CleanupWatched{
		{Store: "My", SHA1: sha1Hex(a.Cert.Raw), SHA256: derSHA256(a.Cert.Raw), State: providers.WatchRemovable},
		{Store: "My", SHA1: w.oldSHA1, SHA256: derSHA256(w.old.Cert.Raw), State: providers.WatchKept, Reason: winproto.KeptNotAlice},
		{SHA1: zero.SHA1, SHA256: zero.SHA256, State: providers.WatchAbsent},
	}, plan.Watched)
	assert.False(t, plan.Partial)
	assert.Empty(t, plan.Warnings)
	assert.Zero(t, plan.Pruned)
	in := w.stdinsOf(winproto.SubIISCleanup)
	require.Len(t, in, 1)
	var pi winproto.CleanupPlanInput
	require.NoError(t, json.Unmarshal(in[0], &pi))
	assert.Equal(t, []winproto.CleanupRef{{SHA1: sha1Hex(a.Cert.Raw), SHA256: derSHA256(a.Cert.Raw)},
		{SHA1: w.oldSHA1, SHA256: derSHA256(w.old.Cert.Raw)}, {SHA1: zero.SHA1, SHA256: zero.SHA256}}, pi.Watch)

	w.model.Advance(winproto.CleanupMinAge + time.Minute)
	plan, err = s.PlanCleanup(ctx, nil)
	require.NoError(t, err)
	require.Len(t, plan.Candidates, 1)
	assert.Equal(t, providers.CleanupAged, plan.Candidates[0].Eligible)
	assert.Empty(t, plan.Watched)

	res, err := s.ApplyCleanup(ctx, []providers.CleanupItem{itemFor(a, providers.CleanupAged), itemFor(b, providers.CleanupAged)})
	require.NoError(t, err)
	assert.Equal(t, providers.CleanupApplyResult{Results: []providers.CleanupItemResult{
		{SHA256: derSHA256(a.Cert.Raw), Result: providers.CleanupRemoved},
		{SHA256: derSHA256(b.Cert.Raw), Result: providers.CleanupKept, Reason: winproto.KeptBound},
	}}, res)
	assert.False(t, w.model.HasCertificate("My", sha1Hex(a.Cert.Raw)))
	assert.False(t, w.model.HasKey("My", sha1Hex(a.Cert.Raw)))
	assert.True(t, w.model.HasCertificate("My", sha1Hex(b.Cert.Raw)))

	res, err = s.ApplyCleanup(ctx, []providers.CleanupItem{itemFor(a, providers.CleanupAged)})
	require.NoError(t, err)
	assert.Equal(t, []providers.CleanupItemResult{{SHA256: derSHA256(a.Cert.Raw), Result: providers.CleanupAbsent}}, res.Results)
	var ai winproto.CleanupApplyInput
	in = w.stdinsOf(winproto.SubIISCleanup)
	require.Len(t, in, 4)
	require.NoError(t, json.Unmarshal(in[3], &ai))
	assert.Equal(t, []winproto.CleanupItem{{Store: "My", SHA1: sha1Hex(a.Cert.Raw), SHA256: derSHA256(a.Cert.Raw), Reason: winproto.CleanupAged}}, ai.Remove)
	assert.JSONEq(t, `{"watch":[]}`, string(w.stdinsOf(winproto.SubIISCleanup)[1]), "no watch list is an empty one")

	// A certificate watched twice is sent once and has one verdict per store.
	plan, err = s.PlanCleanup(ctx, []providers.CleanupRef{refOf(b), refOf(b)})
	require.NoError(t, err)
	assert.Equal(t, []providers.CleanupWatched{{Store: "My", SHA1: sha1Hex(b.Cert.Raw), SHA256: derSHA256(b.Cert.Raw), State: providers.WatchKept,
		Reason: winproto.KeptBound}}, plan.Watched)
	assert.Empty(t, plan.Candidates, "A is gone, B is bound")
	in = w.stdinsOf(winproto.SubIISCleanup)
	require.Len(t, in, 5)
	assert.JSONEq(t, `{"watch":[{"sha1":"`+sha1Hex(b.Cert.Raw)+`","sha256":"`+derSHA256(b.Cert.Raw)+`"}]}`, string(in[4]))
	assert.Equal(t, []string{"version", "iis-cleanup --plan", "iis-cleanup --plan", "iis-cleanup --apply", "iis-cleanup --apply", "iis-cleanup --plan"},
		w.srv.Commands(), "the command line carries the subcommand and its mode only")
}

func hexOf(c byte, n int) string { return strings.Repeat(string(c), n) }

// Every value of an answer is checked against the helper's vocabulary; anything outside it is an
// ssh.protocol_error, never a plan or a result.
func TestCleanupAnswerValidation(t *testing.T) {
	ref := providers.CleanupRef{SHA1: hexOf('a', 40), SHA256: hexOf('b', 64)}
	basePlan := func() winproto.CleanupPlanResponse {
		return winproto.CleanupPlanResponse{OK: true,
			Candidates: []winproto.CleanupCandidate{{Store: "My", SHA1: hexOf('c', 40), SHA256: hexOf('d', 64), FriendlyName: "Alice \x1b[31mx",
				NotAfter: "2027-01-01T00:00:00Z", UnboundSince: "2026-10-01T00:00:00Z", Eligible: winproto.CleanupAged},
				{Store: "WebHosting", SHA1: hexOf('e', 40), SHA256: hexOf('f', 64), UnboundSince: "2026-10-20T00:00:00Z"}},
			Watched: []winproto.CleanupWatched{{Store: "My", SHA1: ref.SHA1, SHA256: ref.SHA256, State: winproto.WatchKept, Reason: winproto.KeptBound},
				{Store: "WebHosting", SHA1: ref.SHA1, SHA256: ref.SHA256, State: winproto.WatchRemovable}},
			Pruned: 3, Warnings: []string{winproto.WarnJournalUnreadable, winproto.WarnBindingRecordUnreadable}, Truncated: true}
	}
	items := []providers.CleanupItem{{Store: "My", SHA1: hexOf('1', 40), SHA256: hexOf('2', 64), Reason: providers.CleanupAged},
		{Store: "My", SHA1: hexOf('3', 40), SHA256: hexOf('4', 64), Reason: providers.CleanupIncident}}
	baseApply := func() winproto.CleanupApplyResponse {
		return winproto.CleanupApplyResponse{OK: true, Results: []winproto.CleanupResult{{SHA256: hexOf('2', 64), Result: winproto.CleanupRemoved},
			{SHA256: hexOf('4', 64), Result: winproto.CleanupKept, Reason: winproto.KeptTooYoung}}}
	}

	// The well-formed answers map whole.
	w := newWEnv(t)
	w.script(winproto.SubIISCleanup, func(in []byte) linuxsshtest.Response {
		if strings.Contains(string(in), `"watch"`) {
			return jsonAnswer(basePlan())
		}
		return jsonAnswer(baseApply())
	})
	s := w.session(t)
	plan, err := s.PlanCleanup(context.Background(), []providers.CleanupRef{ref})
	require.NoError(t, err)
	assert.Equal(t, providers.CleanupPlan{
		Candidates: []providers.CleanupCertificate{
			{Store: "My", SHA1: hexOf('c', 40), SHA256: hexOf('d', 64), FriendlyName: "Alice [31mx", Eligible: providers.CleanupAged,
				NotAfter: time.Date(2027, 1, 1, 0, 0, 0, 0, time.UTC), UnboundSince: time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC)},
			{Store: "WebHosting", SHA1: hexOf('e', 40), SHA256: hexOf('f', 64), UnboundSince: time.Date(2026, 10, 20, 0, 0, 0, 0, time.UTC)}},
		Watched: []providers.CleanupWatched{{Store: "My", SHA1: ref.SHA1, SHA256: ref.SHA256, State: providers.WatchKept, Reason: winproto.KeptBound},
			{Store: "WebHosting", SHA1: ref.SHA1, SHA256: ref.SHA256, State: providers.WatchRemovable}},
		Pruned: 3, Partial: true, Warnings: []string{winproto.WarnJournalUnreadable, winproto.WarnBindingRecordUnreadable},
	}, plan, "the friendly name is cleaned; Truncated is Partial")
	res, err := s.ApplyCleanup(context.Background(), items)
	require.NoError(t, err)
	assert.Equal(t, providers.CleanupApplyResult{Results: []providers.CleanupItemResult{{SHA256: hexOf('2', 64), Result: providers.CleanupRemoved},
		{SHA256: hexOf('4', 64), Result: providers.CleanupKept, Reason: winproto.KeptTooYoung}}}, res)

	plans := []struct {
		name string
		mod  func(*winproto.CleanupPlanResponse)
	}{
		{"an unknown eligible", func(r *winproto.CleanupPlanResponse) { r.Candidates[0].Eligible = "soon" }},
		{"incident is Alice's reason, never the helper's", func(r *winproto.CleanupPlanResponse) { r.Candidates[0].Eligible = winproto.CleanupIncident }},
		{"a bad unbound_since", func(r *winproto.CleanupPlanResponse) { r.Candidates[0].UnboundSince = "2026-10-01 00:00:00" }},
		{"no unbound_since", func(r *winproto.CleanupPlanResponse) { r.Candidates[0].UnboundSince = "" }},
		{"a bad not_after", func(r *winproto.CleanupPlanResponse) { r.Candidates[0].NotAfter = "tomorrow" }},
		{"a bad store", func(r *winproto.CleanupPlanResponse) { r.Candidates[0].Store = `My\..` }},
		{"a bad sha1", func(r *winproto.CleanupPlanResponse) { r.Candidates[0].SHA1 = hexOf('C', 40) }},
		{"a bad sha256", func(r *winproto.CleanupPlanResponse) { r.Candidates[0].SHA256 = hexOf('d', 63) }},
		{"too many candidates", func(r *winproto.CleanupPlanResponse) {
			for len(r.Candidates) <= winproto.MaxCleanupCandidates {
				r.Candidates = append(r.Candidates, r.Candidates[1])
			}
		}},
		{"a verdict on a certificate not watched", func(r *winproto.CleanupPlanResponse) { r.Watched[1].SHA256 = hexOf('9', 64) }},
		{"an unknown state", func(r *winproto.CleanupPlanResponse) { r.Watched[1].State = "gone" }},
		{"kept without a reason", func(r *winproto.CleanupPlanResponse) { r.Watched[0].Reason = "" }},
		{"kept for an unknown reason", func(r *winproto.CleanupPlanResponse) { r.Watched[0].Reason = "fond" }},
		{"kept as too young (an apply's reason)", func(r *winproto.CleanupPlanResponse) { r.Watched[0].Reason = winproto.KeptTooYoung }},
		{"removable with a reason", func(r *winproto.CleanupPlanResponse) { r.Watched[1].Reason = winproto.KeptBound }},
		{"a verdict without a store", func(r *winproto.CleanupPlanResponse) { r.Watched[1].Store = "" }},
		{"the same store twice", func(r *winproto.CleanupPlanResponse) { r.Watched[1].Store = "MY" }},
		{"absent with a store", func(r *winproto.CleanupPlanResponse) {
			r.Watched = []winproto.CleanupWatched{{Store: "My", SHA1: ref.SHA1, SHA256: ref.SHA256, State: winproto.WatchAbsent}}
		}},
		{"absent with a reason", func(r *winproto.CleanupPlanResponse) {
			r.Watched = []winproto.CleanupWatched{{SHA1: ref.SHA1, SHA256: ref.SHA256, State: winproto.WatchAbsent, Reason: winproto.KeptBound}}
		}},
		{"absent and found", func(r *winproto.CleanupPlanResponse) {
			r.Watched = append(r.Watched, winproto.CleanupWatched{SHA1: ref.SHA1, SHA256: ref.SHA256, State: winproto.WatchAbsent})
		}},
		{"a watched certificate without a verdict", func(r *winproto.CleanupPlanResponse) { r.Watched = nil }},
		{"an unknown warning", func(r *winproto.CleanupPlanResponse) { r.Warnings = append(r.Warnings, "list_truncated") }},
		{"a negative count", func(r *winproto.CleanupPlanResponse) { r.Pruned = -1 }},
		{"more pruned than a run may", func(r *winproto.CleanupPlanResponse) { r.Pruned = winproto.MaxPrunePerRun + 1 }},
	}
	for _, tc := range plans {
		t.Run("plan: "+tc.name, func(t *testing.T) {
			w := newWEnv(t)
			r := basePlan()
			tc.mod(&r)
			w.script(winproto.SubIISCleanup, func([]byte) linuxsshtest.Response { return jsonAnswer(r) })
			plan, err := w.session(t).PlanCleanup(context.Background(), []providers.CleanupRef{ref})
			pe := providerErr(t, err)
			assert.Equal(t, "ssh.protocol_error", pe.Code)
			assert.Equal(t, winproto.SubIISCleanup, pe.Params["subcommand"])
			assert.Equal(t, providers.CleanupPlan{}, plan)
		})
	}
	applies := []struct {
		name string
		mod  func(*winproto.CleanupApplyResponse)
	}{
		{"a result for a SHA-256 not sent", func(r *winproto.CleanupApplyResponse) { r.Results[1].SHA256 = hexOf('5', 64) }},
		{"results out of order", func(r *winproto.CleanupApplyResponse) { r.Results[0], r.Results[1] = r.Results[1], r.Results[0] }},
		{"a result missing", func(r *winproto.CleanupApplyResponse) { r.Results = r.Results[:1] }},
		{"a result too many", func(r *winproto.CleanupApplyResponse) { r.Results = append(r.Results, r.Results[0]) }},
		{"an unknown result", func(r *winproto.CleanupApplyResponse) { r.Results[0].Result = "burnt" }},
		{"removed with a reason", func(r *winproto.CleanupApplyResponse) { r.Results[0].Reason = winproto.KeptBound }},
		{"absent with a reason", func(r *winproto.CleanupApplyResponse) {
			r.Results[0].Result, r.Results[0].Reason = winproto.CleanupAbsent, winproto.KeptBound
		}},
		{"kept without a reason", func(r *winproto.CleanupApplyResponse) { r.Results[1].Reason = "" }},
		{"kept for an unknown reason", func(r *winproto.CleanupApplyResponse) { r.Results[1].Reason = "fond" }},
	}
	for _, tc := range applies {
		t.Run("apply: "+tc.name, func(t *testing.T) {
			w := newWEnv(t)
			r := baseApply()
			tc.mod(&r)
			w.script(winproto.SubIISCleanup, func([]byte) linuxsshtest.Response { return jsonAnswer(r) })
			res, err := w.session(t).ApplyCleanup(context.Background(), items)
			assert.Equal(t, "ssh.protocol_error", providerErr(t, err).Code)
			assert.Equal(t, providers.CleanupApplyResult{}, res)
		})
	}
}

// W3 Ruling 12: OUTCOME_UNKNOWN (the helper's budget ended after its first durable write) is the retryable
// windows.cleanup_outcome_unknown for both modes; the next run settles. The emulator's kill between key
// and certificate produces it for real. OUTCOME_UNKNOWN at another exit is outside the contract.
func TestCleanupOutcomeUnknown(t *testing.T) {
	ctx := context.Background()
	w := newWEnv(t)
	w.script(winproto.SubIISCleanup, func([]byte) linuxsshtest.Response { return refusalResponse(4, winproto.CodeOutcomeUnknown) })
	s := w.session(t)
	_, err := s.PlanCleanup(ctx, nil)
	pe := providerErr(t, err)
	assert.Equal(t, ReasonCleanupOutcomeUnknown, pe.Code)
	assert.True(t, pe.Retryable)
	assert.Equal(t, winproto.SubIISCleanup, pe.Params["subcommand"])
	_, err = s.ApplyCleanup(ctx, []providers.CleanupItem{itemFor(w.old, providers.CleanupAged)})
	pe = providerErr(t, err)
	assert.Equal(t, ReasonCleanupOutcomeUnknown, pe.Code)
	assert.True(t, pe.Retryable)

	w = newWEnv(t)
	a, _ := w.redeploy(t)
	s = w.session(t)
	_, err = s.PlanCleanup(ctx, nil)
	require.NoError(t, err)
	w.model.Advance(winproto.CleanupMinAge + time.Minute)
	w.model.FailAfterKey(true)
	_, err = s.ApplyCleanup(ctx, []providers.CleanupItem{itemFor(a, providers.CleanupAged)})
	pe = providerErr(t, err)
	assert.Equal(t, ReasonCleanupOutcomeUnknown, pe.Code)
	assert.True(t, pe.Retryable)
	assert.True(t, w.model.HasCertificate("My", sha1Hex(a.Cert.Raw)), "the certificate stays, keyless")
	assert.False(t, w.model.HasKey("My", sha1Hex(a.Cert.Raw)))

	w = newWEnv(t)
	w.script(winproto.SubIISCleanup, func([]byte) linuxsshtest.Response { return refusalResponse(2, winproto.CodeOutcomeUnknown) })
	_, err = w.session(t).PlanCleanup(ctx, nil)
	pe = providerErr(t, err)
	assert.Equal(t, "ssh.protocol_error", pe.Code)
	assert.Equal(t, winproto.CodeOutcomeUnknown, pe.Params["helper_code"])
}

// The helper's refusals map as W2 Ruling 6; a code outside iis-cleanup's table is a protocol error; an
// exit without an answer is the helper missing.
func TestCleanupRefusals(t *testing.T) {
	for _, tc := range []struct {
		name      string
		resp      linuxsshtest.Response
		code      string
		retryable bool
	}{
		{"busy", refusalResponse(4, winproto.CodeBusy), ReasonBusy, true},
		{"io error", refusalResponse(4, winproto.CodeIOError), ReasonIOError, true},
		{"store error", refusalResponse(4, winproto.CodeStoreError), ReasonStoreError, false},
		{"not elevated", refusalResponse(2, winproto.CodeNotElevated), ReasonNotElevated, false},
		{"invalid argument", refusalResponse(2, winproto.CodeInvalidArgument), ReasonHelperRefused, false},
		{"a deployment's code", refusalResponse(3, winproto.CodeHashMismatch), "ssh.protocol_error", false},
		{"busy at the wrong exit", refusalResponse(2, winproto.CodeBusy), "ssh.protocol_error", false},
		{"killed", linuxsshtest.Response{Exit: 255}, ReasonHelperMissing, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			w := newWEnv(t)
			w.script(winproto.SubIISCleanup, func([]byte) linuxsshtest.Response { return tc.resp })
			s := w.session(t)
			_, err := s.PlanCleanup(context.Background(), nil)
			pe := providerErr(t, err)
			assert.Equal(t, tc.code, pe.Code)
			assert.Equal(t, tc.retryable, pe.Retryable)
			_, err = s.ApplyCleanup(context.Background(), []providers.CleanupItem{itemFor(w.old, providers.CleanupAged)})
			assert.Equal(t, tc.code, providerErr(t, err).Code)
		})
	}
}

// What Alice would send that the helper refuses is refused before anything is sent; an empty apply
// sends nothing and answers nothing; a closed session and a session without the capability send nothing.
func TestCleanupRefusesBeforeSending(t *testing.T) {
	ctx := context.Background()
	w := newWEnv(t)
	s := w.session(t)
	many := make([]providers.CleanupRef, winproto.MaxForbidden+1)
	for i := range many {
		many[i] = providers.CleanupRef{SHA1: fmt.Sprintf("%040x", i), SHA256: fmt.Sprintf("%064x", i)}
	}
	for name, watch := range map[string][]providers.CleanupRef{
		"an upper-case sha1": {{SHA1: hexOf('A', 40), SHA256: hexOf('b', 64)}},
		"a short sha256":     {{SHA1: hexOf('a', 40), SHA256: hexOf('b', 63)}},
		"too many":           many,
	} {
		_, err := s.PlanCleanup(ctx, watch)
		assert.Equal(t, reasonUnexpected, providerErr(t, err).Code, name)
	}
	tooMany := make([]providers.CleanupItem, winproto.MaxCleanupItems+1)
	for i := range tooMany {
		tooMany[i] = itemFor(w.old, providers.CleanupAged)
	}
	bad := itemFor(w.old, "whim")
	badStore := itemFor(w.old, providers.CleanupAged)
	badStore.Store = `..\My`
	for name, items := range map[string][]providers.CleanupItem{"too many": tooMany, "an unknown reason": {bad}, "a bad store": {badStore}} {
		_, err := s.ApplyCleanup(ctx, items)
		assert.Equal(t, reasonUnexpected, providerErr(t, err).Code, name)
	}
	res, err := s.ApplyCleanup(ctx, nil)
	require.NoError(t, err)
	assert.Equal(t, providers.CleanupApplyResult{}, res)
	assert.Equal(t, []string{"version"}, w.srv.Commands())

	_, err = s.ApplyCleanup(ctx, nil) // still nothing: an empty apply is no call
	require.NoError(t, err)
	cancelled, cancel := context.WithCancel(ctx)
	cancel()
	_, err = s.PlanCleanup(cancelled, nil)
	require.Error(t, err)
	assert.ErrorIs(t, err, context.Canceled)
	_, err = s.ApplyCleanup(cancelled, []providers.CleanupItem{itemFor(w.old, providers.CleanupAged)})
	assert.ErrorIs(t, err, context.Canceled)

	require.NoError(t, s.Close())
	_, err = s.PlanCleanup(ctx, nil)
	assert.Equal(t, "ssh.unreachable", providerErr(t, err).Code)
	_, err = s.ApplyCleanup(ctx, []providers.CleanupItem{itemFor(w.old, providers.CleanupAged)})
	assert.Equal(t, "ssh.unreachable", providerErr(t, err).Code)

	s = w.session(t)
	s.caps = providers.NewCapabilitySet(providers.CapTestConnection)
	_, err = s.PlanCleanup(ctx, nil)
	assert.ErrorIs(t, err, providers.ErrUnsupported)
	_, err = s.ApplyCleanup(ctx, nil)
	assert.ErrorIs(t, err, providers.ErrUnsupported)
	assert.Equal(t, []string{"version", "version"}, w.srv.Commands())
}

// W0 (design §8): each cleanup call has a connection of its own, closed after its one command.
func TestEachCleanupCallUsesItsOwnConnection(t *testing.T) {
	e := newEnv(t)
	s, ok := e.open(t).(*session)
	require.True(t, ok)
	assert.Equal(t, 1, e.srv.Connections())
	e.waitNoOpenConnections(t)
	_, err := s.PlanCleanup(context.Background(), nil)
	require.NoError(t, err, "a reused connection would answer the plan as version")
	assert.Equal(t, 2, e.srv.Connections())
	e.waitNoOpenConnections(t)
	res, err := s.ApplyCleanup(context.Background(), []providers.CleanupItem{{Store: "My", SHA1: hexOf('a', 40), SHA256: hexOf('b', 64),
		Reason: providers.CleanupIncident}})
	require.NoError(t, err, "a reused connection would answer the apply as version")
	assert.Equal(t, []providers.CleanupItemResult{{SHA256: hexOf('b', 64), Result: providers.CleanupAbsent}}, res.Results)
	assert.Equal(t, 3, e.srv.Connections(), "one connection per helper call")
	assert.Equal(t, []string{"version", "iis-cleanup --plan", "iis-cleanup --apply"}, e.srv.Commands())
	e.waitNoOpenConnections(t)
}
