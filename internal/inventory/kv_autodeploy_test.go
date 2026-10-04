package inventory

import (
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
)

var planNow = time.Date(2026, 10, 10, 12, 0, 0, 0, time.UTC)

func tp(t time.Time) *time.Time { return &t }

// planFixture is a binding created 10 days ago, automatic deployment on since 5 days ago, three
// websites that serve an older certificate, and a current version V2 that arrived an hour ago.
type planFixture struct {
	sn      planSnapshot
	v2, v1  uuid.UUID
	leaf    uuid.UUID
	a, b, c uuid.UUID
}

func newPlanFixture() *planFixture {
	f := &planFixture{v2: uuid.New(), v1: uuid.New(), leaf: uuid.New()}
	ids := []uuid.UUID{uuid.New(), uuid.New(), uuid.New()}
	f.a, f.b, f.c = ids[0], ids[1], ids[2]
	served := uuid.New()
	f.sn = planSnapshot{now: planNow, gateOpen: true, vaultOK: true, bindingCreated: planNow.Add(-10 * 24 * time.Hour), autoDeploy: true,
		autoSince: tp(planNow.Add(-5 * 24 * time.Hour)), remaining: autoDeployBatch,
		versions: []planVersion{{id: f.v2, version: "v2", current: true, leaf: &f.leaf, leafNotBefore: tp(planNow.Add(-time.Hour)),
			leafNotAfter: tp(planNow.Add(60 * 24 * time.Hour)), enabled: true, keyType: "ecdsa", kvCreatedAt: tp(planNow.Add(-time.Hour)),
			detectedAt: planNow.Add(-time.Hour)}}}
	for _, id := range ids {
		f.sn.locations = append(f.sn.locations, planLocation{id: id, served: &served, servedNotAfter: tp(planNow.Add(10 * 24 * time.Hour))})
	}
	return f
}

func (f *planFixture) cur() *planVersion { return &f.sn.versions[0] }

func (f *planFixture) failed(loc uuid.UUID, ago time.Duration, code string) {
	f.sn.deployments = append(f.sn.deployments, planDeployment{location: loc, version: &f.v2, automatic: true, done: true, status: "failed",
		errorCode: code, createdAt: planNow.Add(-ago - time.Minute), finishedAt: tp(planNow.Add(-ago))})
}

func templates(p autoPlan) []string {
	out := []string{}
	for _, n := range p.notices {
		out = append(out, n.template)
	}
	return out
}

func TestAutoDeployPlanTable(t *testing.T) {
	for _, tc := range []struct {
		name     string
		mutate   func(f *planFixture)
		deploy   func(f *planFixture) []uuid.UUID
		budget   int
		notices  []string
		stopped  bool
		skipMark bool // the notice marks skipped_notified_at
	}{
		{name: "a new version with three websites: one deployment each", deploy: func(f *planFixture) []uuid.UUID { return []uuid.UUID{f.a, f.b, f.c} }, budget: AutoDeployWave},
		{name: "the run's own budget caps the wave", mutate: func(f *planFixture) { f.sn.remaining = 2 },
			deploy: func(f *planFixture) []uuid.UUID { return []uuid.UUID{f.a, f.b, f.c} }, budget: 2},
		{name: "two unfinished automatic deployments leave room for three", mutate: func(f *planFixture) {
			f.sn.deployments = append(f.sn.deployments,
				planDeployment{location: f.a, version: &f.v1, automatic: true, status: "running", createdAt: planNow},
				planDeployment{location: f.b, version: &f.v1, automatic: true, status: "running", createdAt: planNow})
		}, deploy: func(f *planFixture) []uuid.UUID { return []uuid.UUID{f.c} }, budget: AutoDeployWave - 2},
		{name: "a full wave plans nothing", mutate: func(f *planFixture) {
			for i := 0; i < AutoDeployWave; i++ {
				f.sn.deployments = append(f.sn.deployments, planDeployment{location: uuid.New(), version: &f.v1, automatic: true, status: "running", createdAt: planNow})
			}
		}, deploy: func(f *planFixture) []uuid.UUID { return nil }, budget: 0},
		{name: "a second renewal while the first wave runs: the busy websites wait, no parallel deployment", mutate: func(f *planFixture) {
			f.sn.deployments = append(f.sn.deployments, planDeployment{location: f.a, version: &f.v1, automatic: true, status: "running", createdAt: planNow})
		}, deploy: func(f *planFixture) []uuid.UUID { return []uuid.UUID{f.b, f.c} }, budget: AutoDeployWave - 1},
		{name: "an unfinished manual deployment of the website blocks it too", mutate: func(f *planFixture) {
			f.sn.deployments = append(f.sn.deployments, planDeployment{location: f.b, status: "pending", createdAt: planNow})
		}, deploy: func(f *planFixture) []uuid.UUID { return []uuid.UUID{f.a, f.c} }, budget: AutoDeployWave},
		{name: "failed 30 minutes ago: it waits", mutate: func(f *planFixture) { f.failed(f.a, 30*time.Minute, "deployment.interrupted") },
			deploy: func(f *planFixture) []uuid.UUID { return []uuid.UUID{f.b, f.c} }, budget: AutoDeployWave},
		{name: "failed 61 minutes ago: one more attempt, after the fresh websites", mutate: func(f *planFixture) { f.failed(f.a, 61*time.Minute, "deployment.interrupted") },
			deploy: func(f *planFixture) []uuid.UUID { return []uuid.UUID{f.b, f.c, f.a} }, budget: AutoDeployWave},
		{name: "a website that failed three times gets no fourth attempt (even when neutral)", mutate: func(f *planFixture) {
			for i := 0; i < AutoDeployMaxFailed; i++ {
				f.failed(f.a, time.Duration(3+i)*time.Hour, "certificate.chain_unconfirmed")
			}
		}, deploy: func(f *planFixture) []uuid.UUID { return []uuid.UUID{f.b, f.c} }, budget: AutoDeployWave},
		{name: "three failures of the version stop the wave, with one notice of the stop", mutate: func(f *planFixture) {
			f.failed(f.a, 3*time.Hour, "deployment.failed")
			f.failed(f.b, 3*time.Hour, "deployment.failed")
			f.failed(f.c, 3*time.Hour, "deployment.failed")
		}, deploy: func(f *planFixture) []uuid.UUID { return nil }, stopped: true},
		{name: "failures before automatic deployment was switched on again do not count", mutate: func(f *planFixture) {
			for _, l := range []uuid.UUID{f.a, f.b, f.c} {
				f.failed(l, 6*24*time.Hour, "deployment.failed")
			}
		}, deploy: func(f *planFixture) []uuid.UUID { return []uuid.UUID{f.a, f.b, f.c} }, budget: AutoDeployWave},
		{name: "refusals that are not failures (held chain, binding gone, ...) never stop a wave", mutate: func(f *planFixture) {
			f.failed(f.a, 3*time.Hour, "certificate.chain_unconfirmed")
			f.failed(f.b, 3*time.Hour, "kv.binding_gone")
			f.failed(f.c, 3*time.Hour, "kv.version_held")
		}, deploy: func(f *planFixture) []uuid.UUID { return []uuid.UUID{f.a, f.b, f.c} }, budget: AutoDeployWave}, // each website's one attempt is an hour old
		{name: "an already stopped version plans and mails nothing more", mutate: func(f *planFixture) {
			f.sn.stoppedVersion = "v2"
			f.failed(f.a, 3*time.Hour, "deployment.failed")
			f.failed(f.b, 3*time.Hour, "deployment.failed")
			f.failed(f.c, 3*time.Hour, "deployment.failed")
		}, deploy: func(f *planFixture) []uuid.UUID { return nil }},
		{name: "the stop names V2 only: V3 is planned", mutate: func(f *planFixture) { f.sn.stoppedVersion = "v1" },
			deploy: func(f *planFixture) []uuid.UUID { return []uuid.UUID{f.a, f.b, f.c} }, budget: AutoDeployWave},
		{name: "a website that serves the leaf already is left alone", mutate: func(f *planFixture) { f.sn.locations[0].served = &f.leaf },
			deploy: func(f *planFixture) []uuid.UUID { return []uuid.UUID{f.b, f.c} }, budget: AutoDeployWave},
		{name: "a website whose deployment of the version succeeded is left alone", mutate: func(f *planFixture) {
			f.sn.deployments = append(f.sn.deployments, planDeployment{location: f.b, version: &f.v2, done: true, status: "unchanged", createdAt: planNow.Add(-time.Hour), finishedAt: tp(planNow)})
		}, deploy: func(f *planFixture) []uuid.UUID { return []uuid.UUID{f.a, f.c} }, budget: AutoDeployWave},
		{name: "disabled: skipped, mailed once", mutate: func(f *planFixture) { f.cur().enabled = false },
			deploy: func(f *planFixture) []uuid.UUID { return nil }, notices: []string{TemplateKVSkippedDisabled}, skipMark: true},
		{name: "expired: skipped, mailed once", mutate: func(f *planFixture) { f.cur().expires = tp(planNow.Add(-time.Second)) },
			deploy: func(f *planFixture) []uuid.UUID { return nil }, notices: []string{TemplateKVSkippedExpired}, skipMark: true},
		{name: "the leaf's own end counts as expired", mutate: func(f *planFixture) { f.cur().leafNotAfter = tp(planNow) },
			deploy: func(f *planFixture) []uuid.UUID { return nil }, notices: []string{TemplateKVSkippedExpired}, skipMark: true},
		{name: "not yet valid: skipped, mailed once", mutate: func(f *planFixture) { f.cur().notBefore = tp(planNow.Add(time.Minute)) },
			deploy: func(f *planFixture) []uuid.UUID { return nil }, notices: []string{TemplateKVSkippedNotYetValid}, skipMark: true},
		{name: "a skipped version already mailed stays quiet", mutate: func(f *planFixture) { f.cur().enabled = false; f.cur().skippedAt = tp(planNow) },
			deploy: func(f *planFixture) []uuid.UUID { return nil }},
		{name: "older than what a website serves: that website only, mailed once", mutate: func(f *planFixture) {
			f.sn.locations[1].servedNotAfter = tp(planNow.Add(90 * 24 * time.Hour))
		}, deploy: func(f *planFixture) []uuid.UUID { return []uuid.UUID{f.a, f.c} }, budget: AutoDeployWave, notices: []string{TemplateKVSkippedOlder}, skipMark: true},
		{name: "details unknown: nothing, silently", mutate: func(f *planFixture) { f.cur().leaf = nil }, deploy: func(f *planFixture) []uuid.UUID { return nil }},
		{name: "not exportable: nothing, silently", mutate: func(f *planFixture) { f.cur().exportable = ptrTo(false) }, deploy: func(f *planFixture) []uuid.UUID { return nil }},
		{name: "a key type Alice cannot deploy: nothing, silently", mutate: func(f *planFixture) { f.cur().keyType = "other" }, deploy: func(f *planFixture) []uuid.UUID { return nil }},
		{name: "held for the license: mailed once, never planned", mutate: func(f *planFixture) { f.cur().held, f.cur().heldReason = true, "license" },
			deploy: func(f *planFixture) []uuid.UUID { return nil }, notices: []string{TemplateKVNewVersionHeldLicense}},
		{name: "held for the chain: mailed once, never planned", mutate: func(f *planFixture) { f.cur().held, f.cur().heldReason = true, "incomplete_chain" },
			deploy: func(f *planFixture) []uuid.UUID { return nil }, notices: []string{TemplateKVNewVersionHeldChain}},
		{name: "held and already mailed: nothing", mutate: func(f *planFixture) {
			f.cur().held, f.cur().heldReason, f.cur().notifiedAt = true, "license", tp(planNow)
		},
			deploy: func(f *planFixture) []uuid.UUID { return nil }},
		{name: "held before the binding existed: nothing to say", mutate: func(f *planFixture) {
			f.cur().held, f.cur().heldReason = true, "license"
			f.cur().detectedAt, f.cur().kvCreatedAt = planNow.Add(-11*24*time.Hour), tp(planNow.Add(-11*24*time.Hour))
		}, deploy: func(f *planFixture) []uuid.UUID { return nil }},
		{name: "the licence gate locked mid-wave: nothing", mutate: func(f *planFixture) { f.sn.gateOpen = false }, deploy: func(f *planFixture) []uuid.UUID { return nil }},
		{name: "automatic deployment switched off: one notice, no deployment", mutate: func(f *planFixture) { f.sn.autoDeploy, f.sn.autoSince = false, nil },
			deploy: func(f *planFixture) []uuid.UUID { return nil }, notices: []string{TemplateKVNewVersion}},
		{name: "automatic deployment off and the notice already sent", mutate: func(f *planFixture) {
			f.sn.autoDeploy, f.sn.autoSince, f.cur().notifiedAt = false, nil, tp(planNow)
		}, deploy: func(f *planFixture) []uuid.UUID { return nil }},
		{name: "a vault that is not usable: nothing", mutate: func(f *planFixture) { f.sn.vaultOK = false }, deploy: func(f *planFixture) []uuid.UUID { return nil }},
		{name: "the certificate is missing from the vault: nothing", mutate: func(f *planFixture) { f.sn.certificateMissing = true }, deploy: func(f *planFixture) []uuid.UUID { return nil }},
		{name: "no websites left in the binding: nothing", mutate: func(f *planFixture) { f.sn.locations = nil }, deploy: func(f *planFixture) []uuid.UUID { return nil }, budget: AutoDeployWave},
		{name: "detected before automatic deployment was switched on: deploy manually, mailed once", mutate: func(f *planFixture) {
			f.cur().detectedAt, f.cur().kvCreatedAt = planNow.Add(-6*24*time.Hour), tp(planNow.Add(-6*24*time.Hour))
		}, deploy: func(f *planFixture) []uuid.UUID { return nil }, notices: []string{TemplateKVSkippedManual}, skipMark: true},
		{name: "created in Azure before it was switched on, though detected after: deploy manually", mutate: func(f *planFixture) {
			f.cur().kvCreatedAt = tp(planNow.Add(-6 * 24 * time.Hour))
		}, deploy: func(f *planFixture) []uuid.UUID { return nil }, notices: []string{TemplateKVSkippedManual}, skipMark: true},
		{name: "created exactly when it was switched on is not later", mutate: func(f *planFixture) { f.cur().kvCreatedAt = f.sn.autoSince },
			deploy: func(f *planFixture) []uuid.UUID { return nil }, notices: []string{TemplateKVSkippedManual}, skipMark: true},
		{name: "no creation time: the detection time decides", mutate: func(f *planFixture) { f.cur().kvCreatedAt = nil },
			deploy: func(f *planFixture) []uuid.UUID { return []uuid.UUID{f.a, f.b, f.c} }, budget: AutoDeployWave},
		{name: "a version row that was history and became current is judged by its own row", mutate: func(f *planFixture) {
			f.cur().detectedAt = planNow.Add(-9 * 24 * time.Hour) // stored as history long ago
			f.cur().kvCreatedAt = tp(planNow.Add(-time.Hour))
		}, deploy: func(f *planFixture) []uuid.UUID { return nil }, notices: []string{TemplateKVSkippedManual}, skipMark: true},
		{name: "the baseline version, there before the binding: nothing to say", mutate: func(f *planFixture) {
			f.cur().detectedAt, f.cur().kvCreatedAt = planNow.Add(-11*24*time.Hour), tp(planNow.Add(-11*24*time.Hour))
		}, deploy: func(f *planFixture) []uuid.UUID { return nil }},
		{name: "the manual notice is not sent when the person was told at detection", mutate: func(f *planFixture) {
			f.cur().detectedAt, f.cur().kvCreatedAt, f.cur().notifiedAt = planNow.Add(-6*24*time.Hour), tp(planNow.Add(-6*24*time.Hour)), tp(planNow)
		}, deploy: func(f *planFixture) []uuid.UUID { return nil }},
		{name: "a version superseded before it deployed is mailed once", mutate: func(f *planFixture) {
			f.sn.versions = append(f.sn.versions, planVersion{id: f.v1, version: "v1", enabled: true, kvCreatedAt: tp(planNow.Add(-2 * time.Hour)),
				detectedAt: planNow.Add(-2 * time.Hour)})
		}, deploy: func(f *planFixture) []uuid.UUID { return []uuid.UUID{f.a, f.b, f.c} }, budget: AutoDeployWave, notices: []string{TemplateKVSkippedSuperseded}, skipMark: true},
		{name: "a superseded version that was deployed somewhere is not mailed", mutate: func(f *planFixture) {
			f.sn.versions = append(f.sn.versions, planVersion{id: f.v1, version: "v1", enabled: true, kvCreatedAt: tp(planNow.Add(-2 * time.Hour)),
				detectedAt: planNow.Add(-2 * time.Hour)})
			f.sn.deployments = append(f.sn.deployments, planDeployment{location: f.a, version: &f.v1, automatic: true, done: true, status: "succeeded",
				createdAt: planNow.Add(-90 * time.Minute), finishedAt: tp(planNow.Add(-80 * time.Minute))})
		}, deploy: func(f *planFixture) []uuid.UUID { return []uuid.UUID{f.a, f.b, f.c} }, budget: AutoDeployWave},
		{name: "a held version that was superseded is not mailed again", mutate: func(f *planFixture) {
			f.sn.versions = append(f.sn.versions, planVersion{id: f.v1, version: "v1", enabled: true, held: true, heldReason: "license",
				kvCreatedAt: tp(planNow.Add(-2 * time.Hour)), detectedAt: planNow.Add(-2 * time.Hour)})
		}, deploy: func(f *planFixture) []uuid.UUID { return []uuid.UUID{f.a, f.b, f.c} }, budget: AutoDeployWave},
		{name: "no current version row: nothing", mutate: func(f *planFixture) { f.cur().current = false }, deploy: func(f *planFixture) []uuid.UUID { return nil }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newPlanFixture()
			if tc.mutate != nil {
				tc.mutate(f)
			}
			got := planAutoDeploy(f.sn)
			var want []uuid.UUID
			if tc.deploy != nil {
				want = tc.deploy(f)
			}
			assert.Equal(t, want, got.deploy)
			if len(want) > 0 || tc.budget > 0 {
				assert.Equal(t, tc.budget, got.budget)
			}
			assert.Equal(t, len(tc.notices) == 0, len(got.notices) == 0, "notices %v", templates(got))
			if len(tc.notices) > 0 {
				assert.Equal(t, tc.notices, templates(got))
				for _, n := range got.notices {
					assert.Equal(t, tc.skipMark, n.skipped, n.template)
				}
			}
			assert.Equal(t, tc.stopped, got.stop != nil)
			if tc.stopped {
				assert.Equal(t, "v2", got.stop.name)
				assert.Equal(t, 3, got.stop.failed)
			}
		})
	}
}

// Running the plan twice on the same snapshot gives the same plan: it is a function of the snapshot.
func TestAutoDeployPlanIsDeterministic(t *testing.T) {
	f := newPlanFixture()
	f.failed(f.b, 2*time.Hour, "deployment.failed")
	assert.Equal(t, planAutoDeploy(f.sn), planAutoDeploy(f.sn))
}
