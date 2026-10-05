package sshkeys

import (
	"context"
	"encoding/base64"
	"errors"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"alice/internal/inventory"
	"alice/internal/platform/validate"
	"alice/internal/providers"
	"alice/internal/sshkeys/plan"
)

// What deployOptions writes, parseDeployOptions reads back unchanged; nothing else passes (S7).
func TestDeployOptionsRoundTrip(t *testing.T) {
	for _, c := range []struct {
		from     string
		restrict bool
	}{{"", false}, {"", true}, {`from="10.0.0.0/8"`, false}, {`from="10.0.0.0/8,2001:db8::1"`, true}} {
		opts := deployOptions(c.from, c.restrict)
		got, err := parseDeployOptions(opts)
		require.NoError(t, err, opts)
		assert.Equal(t, opts, got)
	}
	for _, opts := range []string{",restrict", "restrict,", `from=10.0.0.0/8`, `from="10.0.0.0/8`, `from="10.0.0.0/8""`,
		`from="10.0.0.0/8",from="10.0.0.0/8"`, `x,restrict`, `from="10.0.0.0/08"`} {
		_, err := parseDeployOptions(opts)
		assert.ErrorIs(t, err, errForeignOptions, opts)
	}
}

func TestCheckDeployInput(t *testing.T) {
	opts, errs := checkDeployInput(DeployInput{OSUser: "deploy", FilePath: "/home/deploy/.ssh/authorized_keys", From: "10.0.0.1", Restrict: true})
	assert.Empty(t, errs)
	assert.Equal(t, `from="10.0.0.1",restrict`, opts)
	for _, c := range []struct {
		in    DeployInput
		field string
		code  string
	}{
		{DeployInput{FilePath: "/f"}, "os_user", validate.Required},
		{DeployInput{OSUser: strings.Repeat("u", 257), FilePath: "/f"}, "os_user", validate.TooLong},
		{DeployInput{OSUser: "a b", FilePath: "/f"}, "os_user", validate.Pattern},
		{DeployInput{OSUser: "a\u202e", FilePath: "/f"}, "os_user", validate.Pattern},
		{DeployInput{OSUser: "u"}, "file_path", validate.Required},
		{DeployInput{OSUser: "u", FilePath: "/" + strings.Repeat("f", 4096)}, "file_path", validate.TooLong},
		{DeployInput{OSUser: "u", FilePath: "f"}, "file_path", validate.Pattern},
		{DeployInput{OSUser: "u", FilePath: "/f\x00"}, "file_path", validate.Pattern},
		{DeployInput{OSUser: "u", FilePath: "/f", From: "10.0.0.1/8"}, "from", validate.Pattern},
	} {
		_, errs := checkDeployInput(c.in)
		require.Len(t, errs, 1, "%+v", c.in)
		assert.Equal(t, c.field, errs[0].Field)
		assert.Equal(t, c.code, errs[0].Code)
	}
}

func TestFileName(t *testing.T) {
	name := fileName("CI deploy / prod \u202e", "SHA256:abc")
	assert.Regexp(t, regexp.MustCompile(`^alice-ci-deploy-prod-[0-9a-f]{8}\.key$`), name)
	assert.NotEqual(t, name, fileName("CI deploy / prod", "SHA256:abd"))
	assert.Regexp(t, `^alice-key-[0-9a-f]{8}\.key$`, fileName("ÇÖ", "SHA256:x"))
}

func TestDeployDedupe(t *testing.T) {
	k, tg := uuid.New(), uuid.New()
	a := deployDedupe(k, tg, "deploy", "/a")
	assert.Regexp(t, `^sshkey\.add:`+k.String()+`:`+tg.String()+`:[0-9a-f]{16}$`, a)
	assert.NotEqual(t, a, deployDedupe(k, tg, "deploy", "/b"))
}

func TestGenerationSlots(t *testing.T) {
	release := HoldGenerationSlots(t)
	_, ok := acquireGenSlot()
	assert.False(t, ok)
	release()
	r, ok := acquireGenSlot()
	require.True(t, ok)
	r()
}

func TestSmallHelpers(t *testing.T) {
	d := &denial{reason: DenyOwnKey, err: ErrNotManaged}
	assert.Equal(t, ErrNotManaged.Error(), d.Error())
	assert.ErrorIs(t, d, ErrNotManaged)
	assert.Equal(t, "system", jobKind(inventory.Actor{}))
	assert.Equal(t, "user", jobKind(inventory.Actor{UserID: uuid.New()}))
	assert.Nil(t, nullableUser(uuid.Nil))
	assert.Equal(t, inventory.ServiceUser, connectionUser(inventory.Target{}))
	assert.Equal(t, "ops", connectionUser(inventory.Target{Username: "ops"}))
}

func TestPlanMappings(t *testing.T) {
	assert.ErrorIs(t, planError(plan.ErrOwnKey), ErrOwnKeyProtected)
	assert.ErrorIs(t, planError(plan.ErrNotManaged), ErrNotManaged)
	assert.ErrorIs(t, planError(plan.ErrRetired), ErrRetired)
	assert.ErrorIs(t, planError(plan.ErrNothingToRotate), ErrNothingToRotate)
	assert.ErrorIs(t, planError(plan.ErrNewKeyType), plan.ErrNewKeyType)
	assert.Equal(t, "own_key", plannerDisableReason(plan.ErrOwnKey))
	assert.Equal(t, "not_managed", plannerDisableReason(plan.ErrNotManaged))
	assert.Equal(t, "retired", plannerDisableReason(plan.ErrRetired))
	assert.Equal(t, "new_key_type", plannerDisableReason(plan.ErrNewKeyType))
	assert.Equal(t, "other", plannerDisableReason(errors.New("plan: other")))
	assert.ErrorIs(t, policyWriteError(&pgconn.PgError{Code: "23505"}), ErrPolicyExists)
	assert.ErrorIs(t, policyWriteError(&pgconn.PgError{Code: "Z1010"}), ErrRetired)
	assert.Error(t, policyWriteError(errors.New("x")))
	assert.Equal(t, uuid.Nil, orNil(nil))
}

// toPlanInput reads per-user and server-wide warnings and the sshd summary the way the planner
// expects them.
func TestToPlanInput(t *testing.T) {
	tid, lid := uuid.New(), uuid.New()
	now := time.Date(2026, 10, 5, 0, 0, 0, 0, time.UTC)
	key := keyRow{id: uuid.New(), privateKeyID: uuid.New(), fingerprint: "SHA256:x", publicKey: "ssh-ed25519 AAAA", label: "CI",
		algorithm: "rsa", bits: 3072}
	tg := inventory.Target{Name: "web", Status: "ok", Username: "ops", Facts: inventory.Facts{
		SSHD: &providers.SSHDSummary{Read: true, PermitRootLogin: "no", PubkeyAuthentication: "yes"}, UID0Users: []string{"root"},
		Warnings: []providers.Warning{{Code: "keys_managed_elsewhere", Params: map[string]string{"user": "bob"}},
			{Code: "sshd_unreadable", Params: map[string]string{"user": "eve"}}, {Code: "keys_managed_elsewhere", Params: map[string]string{}},
			{Code: "other"}}}}
	missing := now
	in := toPlanInput(key, []inventory.KeyLocation{{ID: lid, TargetID: tid, OSUser: "deploy", FilePath: "/f", MissingSince: &missing}},
		map[uuid.UUID]inventory.Target{tid: tg}, []string{"SHA256:p"}, Policy{NewKeyType: "same", OverlapMinutes: 5}, now)
	assert.Equal(t, "rsa-3072", in.Key.KeyType)
	assert.True(t, in.Key.Managed)
	assert.Equal(t, "alice:ci:2026-10-05", in.NewComment)
	pt := in.Targets[tid]
	assert.Equal(t, plan.Target{ID: tid, Name: "web", Status: "ok", ConnectionUser: "ops", SSHDRead: true, PermitRootLogin: "no",
		PubkeyAuthentication: "yes", UID0Users: []string{"root"}, ManagedElsewhereUsers: []string{"bob"}, SSHDUnreadUsers: []string{"eve"}}, pt,
		"no key files in the facts: not known")
	assert.True(t, in.Locations[0].Missing)
	tg.Facts.Warnings = []providers.Warning{{Code: "sshd_unreadable", Params: map[string]string{}}}
	in = toPlanInput(key, nil, map[uuid.UUID]inventory.Target{tid: tg}, nil, Policy{}, now)
	assert.False(t, in.Targets[tid].SSHDRead, "a server-wide unreadable warning")
	// Re-review M10: the connection account's files, listed completely once, are known and passed on
	// (the send-time rule depends on them as much as the planner).
	tg.Facts.KeyFiles = []providers.UserKeyFiles{{OSUser: "deploy", Files: []string{"/home/deploy/.ssh/authorized_keys"}, Complete: true},
		{OSUser: "ops", Files: []string{"/home/ops/.ssh/authorized_keys", "/etc/ssh/keys/ops"}, Complete: true}}
	in = toPlanInput(key, nil, map[uuid.UUID]inventory.Target{tid: tg}, nil, Policy{}, now)
	assert.True(t, in.Targets[tid].ConnectionFilesKnown)
	assert.Equal(t, []string{"/home/ops/.ssh/authorized_keys", "/etc/ssh/keys/ops"}, in.Targets[tid].ConnectionFiles)
	tg.Facts.KeyFiles[1].Complete = false
	in = toPlanInput(key, nil, map[uuid.UUID]inventory.Target{tid: tg}, nil, Policy{}, now)
	assert.False(t, in.Targets[tid].ConnectionFilesKnown, "an incomplete list is not known")
}

// Re-review A-I1: the evidence of a listing before a deploy's send, and whose line it is.
func TestDeployEvidenceAndOwnership(t *testing.T) {
	d := DeployJob{OSUser: "deploy", FilePath: "/f", Fingerprint: "SHA256:k"}
	read := providers.KeyListing{Files: []providers.FileCoverage{{OSUser: "deploy", FilePath: "/f", State: providers.CoverageComplete}}}
	assert.Equal(t, DeployEvidence{Coverage: providers.CoverageComplete, Absent: true}, DeployEvidenceFrom(read, nil, d))
	read.Keys = []providers.DiscoveredSSHKey{{FilePath: "/f", Fingerprint: "SHA256:k"}}
	assert.Equal(t, DeployEvidence{Coverage: providers.CoverageComplete}, DeployEvidenceFrom(read, nil, d))
	assert.Equal(t, DeployEvidence{Coverage: providers.CoverageUnknown}, DeployEvidenceFrom(providers.KeyListing{}, nil, d))
	assert.Equal(t, DeployEvidence{}, DeployEvidenceFrom(read, errors.New("x"), d), "a failed listing proves nothing")

	assert.False(t, DeploySendRecord{}.Owned(), "nothing sent")
	assert.False(t, DeploySendRecord{AbsentBefore: true, FirstCoverage: providers.CoverageComplete}.Owned(), "nothing sent")
	owned := DeploySendRecord{Count: 1, AbsentBefore: true, FirstCoverage: providers.CoverageComplete}
	assert.True(t, owned.Owned())
	owned.AnsweredPresent = true
	assert.False(t, owned.Owned())
	owned.AnsweredAdded = true
	assert.True(t, owned.Owned(), "a send that wrote the line")
	assert.False(t, DeploySendRecord{Count: 2, AbsentBefore: true, FirstCoverage: providers.CoveragePartial}.Owned())
	assert.False(t, DeploySendRecord{Count: 2, FirstCoverage: providers.CoverageComplete}.Owned())
	assert.True(t, DeploySendRecord{Count: 1, AnsweredAdded: true}.Owned())
	assert.False(t, DeploySendRecord{AnsweredAdded: true}.Owned(), "no send on record")
	assert.True(t, DeploySendRecord{Count: 1, LastAt: time.Now()}.UndoNotBefore(time.Minute, true).IsZero(), "the only send answered")
}

// An oversized plan is refused with a closed reason before anything is written (the transaction is
// not even used).
func TestInsertRunRefusesAnOversizedPlan(t *testing.T) {
	s := &Service{}
	many := plan.Plan{Changes: 1, Actions: make([]plan.Action, maxPlanActions+1)}
	_, err := s.insertRun(context.Background(), nil, policyRow{}, keyRow{}, many, "", TriggerManual, time.Time{}, inventory.Actor{})
	assert.ErrorIs(t, err, ErrPlanTooLarge)
	big := plan.Plan{Changes: 1, Actions: []plan.Action{{AddLine: strings.Repeat("a", maxPlanBytes)}}}
	_, err = s.insertRun(context.Background(), nil, policyRow{}, keyRow{}, big, "", TriggerManual, time.Time{}, inventory.Actor{})
	assert.ErrorIs(t, err, ErrPlanTooLarge)
	assert.Equal(t, "rotation.plan_too_large", ReasonPlanTooLarge)
}

func TestAllowedActions(t *testing.T) {
	now := time.Now()
	verified := []RotationLocation{{State: LocVerified}, {State: LocUnverifiable}}
	for _, c := range []struct {
		r    Rotation
		gate bool
		want []string
	}{
		{Rotation{Status: StatusDryRunNotified}, true, []string{"abort"}},
		{Rotation{Status: StatusDryRunNotified}, false, []string{"abort"}},                // Abort stays possible in lock
		{Rotation{Status: StatusAddingNew, PausedLicense: true}, true, []string{"abort"}}, // the renewal notice is not out yet (I2)
		{Rotation{Status: StatusAddingNew, PausedLicense: true}, false, []string{"abort"}},
		{Rotation{Status: StatusAddingNew, PausedLicense: true, RenotifiedAt: &now}, true, []string{"continue", "abort"}},
		{Rotation{Status: StatusOverlap}, true, []string{"finish_now", "abort"}},
		{Rotation{Status: StatusOverlap, PausedLicense: true, RenotifiedAt: &now}, true, []string{"continue", "abort"}},
		{Rotation{Status: StatusOverlap, PausedLicense: true, RenotifiedAt: &now}, false, []string{"abort"}},
		{Rotation{Status: StatusVerifyingNew, AwaitingDecision: true, Locations: verified}, true, []string{"keep_old", "abort"}},
		{Rotation{Status: StatusVerifyingNew, AwaitingDecision: true, Locations: verified[1:]}, false, []string{"abort"}},
		{Rotation{Status: StatusVerifyingNew, AwaitingDecision: true, Locations: verified, PausedLicense: true}, true, []string{"abort"}},
		{Rotation{Status: StatusRemovingOld}, true, []string{}},
		{Rotation{Status: StatusCompleted, PausedLicense: true}, true, []string{}},
	} {
		assert.Equal(t, c.want, AllowedActions(c.r, c.gate), "%+v %v", c.r.Status, c.gate)
	}
}

func TestSmallStoreHelpers(t *testing.T) {
	assert.Equal(t, "fallback", closedReason("", "fallback"))
	assert.Equal(t, "internal.unexpected", closedReason("free text", "x"))
	assert.Equal(t, "a.b", closedReason("a.b", "x"))
	assert.Nil(t, lineNoOrNil(0))
	assert.Equal(t, 3, *lineNoOrNil(3))
	assert.Equal(t, "", backupText(strings.Repeat("b", 201)))
	assert.Equal(t, "", backupText("a\x00"))
	assert.Equal(t, "/x.bak", backupText("/x.bak"))
	assert.Equal(t, "continued", stepOf("rotation.continued"))
	assert.Equal(t, "plain", stepOf("plain"))
	assert.Nil(t, errIf(false, ErrNotYourTurn))
	_, _, err := decodeRotationCursor("!!")
	assert.ErrorIs(t, err, ErrBadCursor)
	_, _, err = decodeRotationCursor(base64.RawURLEncoding.EncodeToString([]byte("x")))
	assert.ErrorIs(t, err, ErrBadCursor)
	_, _, err = decodeRotationCursor(base64.RawURLEncoding.EncodeToString([]byte("x|y")))
	assert.ErrorIs(t, err, ErrBadCursor)
	_, _, err = decodeRotationCursor(base64.RawURLEncoding.EncodeToString([]byte("1|y")))
	assert.ErrorIs(t, err, ErrBadCursor)
	id := uuid.New()
	at, got, err := decodeRotationCursor(encodeRotationCursor(time.UnixMicro(5).UTC(), id))
	require.NoError(t, err)
	assert.Equal(t, id, got)
	assert.Equal(t, time.UnixMicro(5).UTC(), at)
	assert.Nil(t, nilUUID(uuid.Nil))
	assert.True(t, uncertainAdd(locRow{state: LocAddFailed, errorCode: ReasonRetriesExhausted, addSentAt: &at}))
	assert.True(t, uncertainAdd(locRow{state: LocUnverifiable, addSentAt: &at}), "an unproven login proves nothing (I1)")
	assert.False(t, uncertainAdd(locRow{state: LocAddFailed, addSentAt: &at, addAnswered: true}), "FinishAdd answered")
	assert.False(t, uncertainAdd(locRow{state: LocVerified, addSentAt: &at, verifiedAt: &at}), "an accepted login")
	assert.False(t, uncertainAdd(locRow{state: LocPlanned}))
	g := &GuardRefusal{Code: "Z1011", Constraint: "c", Message: "m"}
	assert.Contains(t, g.Error(), "Z1011 c: m")
	assert.Panics(t, func() { New(Config{}) }, "HelperBudget is required")
}

func TestTemplates(t *testing.T) {
	assert.Equal(t, []string{"rotation.preview", "rotation.preview_after_license", "rotation.overlap_started", "rotation.overlap_ending",
		"rotation.completed", "rotation.aborted", "rotation.needs_attention", "rotation.paused_license", "rotation.decision_needed",
		"rotation.completed_partial", "rotation.late_result", "rotation.nothing_to_rotate"}, Templates())
}

// Review M2: a run that kept changing hands, or a live-run index refusal, never leaves as a raw
// database error.
func TestConcurrentRunMapping(t *testing.T) {
	assert.ErrorIs(t, concurrentRunError(errConcurrentRun), ErrRotationInProgress)
	assert.ErrorIs(t, concurrentRunError(ErrNotFound), ErrNotFound)
	assert.ErrorIs(t, runInsertError(&pgconn.PgError{Code: "23505"}), errConcurrentRun)
	assert.NotErrorIs(t, runInsertError(&pgconn.PgError{Code: "Z1013"}), errConcurrentRun)
}

// Review M9: a target without a user name connects as alice-svc, and the planner hears so.
func TestPlanInputConnectionUserDefault(t *testing.T) {
	tid := uuid.New()
	in := toPlanInput(keyRow{}, nil, map[uuid.UUID]inventory.Target{tid: {}}, nil, Policy{}, time.Time{})
	assert.Equal(t, inventory.ServiceUser, in.Targets[tid].ConnectionUser)
}
