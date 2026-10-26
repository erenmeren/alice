package inventory

// The decision of automatic deployment (spec §11.6; R40 rows 20, 21), as a pure function: a snapshot
// of one binding in, a plan out. kv_autodeploy.go reads the snapshot under the binding's locks and
// applies the plan in the same transaction.

import (
	"slices"
	"time"

	"github.com/google/uuid"
)

// Limits and timings of automatic deployment.
const (
	// AutoDeployWave is how many automatic deployments of one binding may be unfinished at a time.
	AutoDeployWave = 5
	// AutoDeployMaxFailed is how many failed automatic deployments of one version stop the wave of its
	// binding (stopped_version); it is also the most attempts one website gets for one version.
	AutoDeployMaxFailed = 3
	// AutoDeployRetryAfter is how long a website waits after a failed automatic deployment of a
	// version before the next attempt.
	AutoDeployRetryAfter = time.Hour
)

var (
	// autoDeployBatch is how many deployments one run of the planner creates in all (a variable so
	// that tests can lower it).
	autoDeployBatch = 50
	// autoDeployBindings is the size of a page of candidate bindings (the run reads every page).
	autoDeployBindings = 200
	// planMailLimit is how many individual notices one run sends per vault and kind of notice; the rest
	// of that kind are counted in one summary mail (marks are written for all of them).
	planMailLimit = 20
)

type planVersion struct {
	id                          uuid.UUID
	version                     string
	current                     bool       // the certificate's current version (kv_certificates.current_version)
	leaf                        *uuid.UUID // the leaf's certificates row; nil until Alice read the version's details
	leafNotBefore, leafNotAfter *time.Time
	enabled                     bool
	exportable                  *bool
	keyType                     string
	notBefore, expires          *time.Time
	kvCreatedAt                 *time.Time
	detectedAt                  time.Time
	held                        bool
	heldReason                  string
	notifiedAt, skippedAt       *time.Time
}

type planLocation struct {
	id             uuid.UUID
	served         *uuid.UUID // the certificate the website served at the last scan
	servedNotAfter *time.Time
}

// planDeployment is a deployment of one of the binding's websites (any version, any trigger) that the
// plan needs to know: those of the current version and every unfinished one.
type planDeployment struct {
	location   uuid.UUID
	version    *uuid.UUID
	automatic  bool // trigger kv_renewal
	done       bool
	holding    bool // a wave-1 deployment under its canary's observation (R65): waiting, not working
	status     string
	errorCode  string
	createdAt  time.Time
	finishedAt *time.Time
}

type planSnapshot struct {
	now                                   time.Time
	gateOpen, vaultOK, certificateMissing bool
	bindingCreated                        time.Time
	autoDeploy                            bool
	autoSince                             *time.Time
	stoppedVersion                        string
	versions                              []planVersion
	locations                             []planLocation // in id order
	deployments                           []planDeployment
	remaining                             int        // deployments the run may still create (all bindings)
	reopened                              *time.Time // when the licence gate last reopened (nil: never)
	// canary is the canary of the binding's current version (R65, design §12; nil: none read).
	canary *canaryPlanState
}

// planNotice is an email the plan asks for, with the mark that makes it once.
type planNotice struct {
	version  uuid.UUID
	template string
	skipped  bool // marks skipped_notified_at instead of notified_at
	onHold   bool // sent only if the hold is applied (the apply step finds a website it could deploy to)
}

// HoldRuleDetectedBeforeReopening is the audit detail hold_rule of a version the planner held because it
// was detected before the licence gate last reopened (the poll's rules are gate_closed,
// created_before_reopening and unconfirmed_since_reopening).
const HoldRuleDetectedBeforeReopening = "detected_before_reopening"

// planHold asks to hold the version for the licence: it was detected before the gate last reopened, so no
// person has seen it since the lock.
// candidates are the websites the plan would deploy to; the hold is applied only if the apply step finds one
// of them it can actually deploy to now.
type planHold struct {
	version    uuid.UUID
	candidates []uuid.UUID
}

type planStop struct {
	version uuid.UUID
	name    string
	failed  int
}

// autoPlan is the outcome: websites to deploy to in order (at most budget of them are created: a
// website the checks refuse does not use up the budget), notices, and the stop of a wave.
type autoPlan struct {
	deploy  []uuid.UUID
	budget  int
	notices []planNotice
	stop    *planStop
	hold    *planHold
	// R65: the rollout to create (deploy is then its wave 1), and why the canary was skipped ("" or "expiry").
	createRollout *rolloutWaves
	canarySkipped string
}

// Closed reasons of a deployment (deployments.error_code) that say the state a deployment was
// requested in no longer held, or that a version needs a person. They are not failures of the version
// on a website: they count toward neither the "three failures stop the wave" rule nor a website's cap,
// and the website is tried again under the hourly rule (what they mean is decided elsewhere: a binding
// that is gone or switched off, a version that is held or disabled and a vault that is unavailable are
// not planned for).
const (
	ReasonChainUnconfirmed   = "certificate.chain_unconfirmed"
	ReasonBindingGone        = "kv.binding_gone"
	ReasonAutoDeployOff      = "kv.auto_deploy_off"
	ReasonVaultUnavailable   = "kv.vault_unavailable"
	ReasonVersionHeld        = "kv.version_held"
	ReasonVersionDisabled    = "kv.version_disabled"
	ReasonCertificateMissing = "kv.certificate_not_found"
	ReasonCertificateExpired = "certificate.expired"
	ReasonNotYetValid        = "certificate.not_yet_valid"
	// ReasonInternal is a fault of Alice's own: it is retried under the hourly rule but each website gets
	// AutoDeployMaxFailed of them, after which the wave of the version stops with one mail.
	ReasonInternal = "internal.unexpected"
	// ReasonVersionSuperseded and ReasonWaveStopped end an automatic deployment whose version is no longer
	// current, or whose wave was stopped (neutral: not failures of the version on a website).
	ReasonVersionSuperseded = "kv.version_superseded"
	ReasonWaveStopped       = "kv.wave_stopped"
)

// NeutralDeploymentReasons lists the reasons that are not counted as failures of a wave.
func NeutralDeploymentReasons() []string {
	return []string{ReasonChainUnconfirmed, ReasonBindingGone, ReasonAutoDeployOff, ReasonVaultUnavailable, ReasonVersionHeld,
		ReasonVersionDisabled, ReasonCertificateMissing, ReasonCertificateExpired, ReasonNotYetValid, ReasonVersionSuperseded, ReasonWaveStopped,
		// The ACME planner's queued deployments judged again at run time (acmeDeployPrecheck).
		ReasonACMEBindingGone, ReasonACMEAutoDeployOff, ReasonACMESuperseded, ReasonACMEDeployStopped, ReasonACMEDeployHeld,
		// A queued deployment across services whose trust was removed before its first send (R49).
		ReasonServiceUntrusted,
		// A queued automatic deployment whose source's policy forbade automatic deployment before its first send (R67).
		ReasonAutoDeployForbidden}
}

func neutralReason(code string) bool {
	for _, r := range NeutralDeploymentReasons() {
		if r == code {
			return true
		}
	}
	return false
}

// laterThan is the rule of the planner: a version is later than t when it was detected after t and
// its Azure creation time, if Alice knows it, is after t as well (strict comparisons, no allowance
// for skew; Azure's own time has whole seconds).
func (v planVersion) laterThan(t time.Time) bool {
	return v.detectedAt.After(t) && (v.kvCreatedAt == nil || v.kvCreatedAt.After(t))
}

// lacksVersion reports whether some website of the binding neither serves the version's leaf nor got the
// version by a succeeded deployment: only then "a new version was found, not deployed" is true.
func lacksVersion(sn planSnapshot, v *planVersion) bool {
	for _, l := range sn.locations {
		if v.leaf != nil && l.served != nil && *l.served == *v.leaf {
			continue
		}
		done := false
		for _, d := range sn.deployments {
			if d.location == l.id && d.version != nil && *d.version == v.id && d.done && (d.status == "succeeded" || d.status == "unchanged") {
				done = true
			}
		}
		if !done {
			return true
		}
	}
	return false
}

// anyDeploymentOf reports whether the binding has any deployment of the version, whatever its trigger or status.
func anyDeploymentOf(sn planSnapshot, v *planVersion) bool {
	for _, d := range sn.deployments {
		if d.version != nil && *d.version == v.id {
			return true
		}
	}
	return false
}

func failedStatus(s string) bool {
	return s == "failed" || s == "rolled_back" || s == "rollback_failed"
}

// planAutoDeploy decides what the planner does for one binding. The version it considers is the
// certificate's current version, judged by its own row (never by the pointer alone: whether it is
// held, enabled, valid and later than the binding comes from the row). Rules, in order:
//
//   - nothing while the licence gate is closed, the vault cannot be used or the certificate is missing;
//   - a held version (whatever the reason) is mailed once and never planned; released, it is planned;
//   - with automatic deployment off the version is mailed once ("new version") when it is later than
//     the binding's creation;
//   - a version already stopped is left alone; one that is not later than automatic deployment's
//     switch-on (auto_since) is never deployed automatically and mails "deploy manually" once when it is
//     later than the binding; a version Alice knows too little of (no details, not exportable, a key
//     type it cannot deploy) is left alone silently; a disabled, expired or not yet valid one is
//     skipped with one mail;
//   - three failed automatic deployments of the version since auto_since stop the wave. Transient-looking
//     reasons (azure.unreachable, azure.throttled, ssh.*) count like any other failure, as Review Focus 3
//     says ("three failures of a version stop the wave with one email"); only the neutral reasons
//     (NeutralDeploymentReasons) are exempt
//     stop the wave: no more deployments, one notice; so does a website whose attempts are used up by any
//     mix of counted failures and internal faults (internal.unexpected): never a silent cap. The
//     hourly spacing applies to a website's last failed attempt of the version whatever its trigger;
//   - otherwise the websites: not those with an unfinished deployment of any kind, not those that serve
//     the leaf already or got the version, not those with three attempts; a website whose certificate
//     ends later than the version's is skipped (one mail); a failed website waits AutoDeployRetryAfter;
//     fresh websites come before retries; at most budget deployments are created.
//
// Versions that are not current, qualify (as above), were never deployed and are not held are mailed
// once as superseded.
func planAutoDeploy(sn planSnapshot) autoPlan {
	var p autoPlan
	if !sn.gateOpen || !sn.vaultOK || sn.certificateMissing {
		return p
	}
	notify := func(v *planVersion, tpl string, skipped bool) {
		p.notices = append(p.notices, planNotice{version: v.id, template: tpl, skipped: skipped})
	}
	var cur *planVersion
	for i := range sn.versions {
		if sn.versions[i].current {
			cur = &sn.versions[i]
		}
	}
	if cur == nil {
		return p
	}
	if sn.autoDeploy && sn.autoSince != nil {
		for i := range sn.versions {
			v := &sn.versions[i]
			if v.current || v.held || v.skippedAt != nil || v.leaf == nil || !v.laterThan(*sn.autoSince) {
				continue // a history row that was never current (no details) is never announced
			}
			served := len(sn.locations) > 0
			for _, l := range sn.locations {
				if l.served == nil || *l.served != *v.leaf {
					served = false
				}
			}
			if served {
				continue // every website has that leaf already: nothing was skipped
			}
			deployed := false
			for _, d := range sn.deployments {
				if d.version != nil && *d.version == v.id {
					deployed = true
				}
			}
			if !deployed {
				notify(v, TemplateKVSkippedSuperseded, true)
			}
		}
	}
	later := cur.laterThan(sn.bindingCreated)
	if cur.held {
		if later && cur.notifiedAt == nil {
			tpl := TemplateKVNewVersionHeldLicense
			if cur.heldReason == heldIncompleteChain {
				tpl = TemplateKVNewVersionHeldChain
			}
			notify(cur, tpl, false)
		}
		return p
	}
	if !sn.autoDeploy || sn.autoSince == nil {
		if later && cur.notifiedAt == nil && lacksVersion(sn, cur) {
			notify(cur, TemplateKVNewVersion, false)
		}
		return p
	}
	if sn.stoppedVersion == cur.version {
		return p
	}
	if !cur.laterThan(*sn.autoSince) {
		// Not eligible, and the person is told once to deploy it by hand. Whether it is NEW does not depend
		// on Azure's clock alone: Alice's own detection time counts too (Azure's clock may run behind), so a
		// version Alice detected after the binding existed and after automatic deployment was switched on is
		// announced whatever its stamp says. Baselines (detected before the binding) stay silent.
		detectedByAlice := cur.detectedAt.After(sn.bindingCreated) && cur.detectedAt.After(*sn.autoSince)
		if (later || detectedByAlice) && cur.notifiedAt == nil && cur.skippedAt == nil {
			notify(cur, TemplateKVSkippedManual, true)
		}
		return p
	}
	if cur.leaf == nil || (cur.exportable != nil && !*cur.exportable) || cur.keyType == "other" {
		return p
	}
	skip := func(tpl string) autoPlan {
		if cur.skippedAt == nil {
			notify(cur, tpl, true)
		}
		return p
	}
	now := sn.now
	switch {
	case !cur.enabled:
		return skip(TemplateKVSkippedDisabled)
	case (cur.leafNotAfter != nil && !now.Before(*cur.leafNotAfter)) || (cur.expires != nil && !now.Before(*cur.expires)):
		return skip(TemplateKVSkippedExpired)
	case (cur.leafNotBefore != nil && now.Before(*cur.leafNotBefore)) || (cur.notBefore != nil && now.Before(*cur.notBefore)):
		return skip(TemplateKVSkippedNotYetValid)
	}

	failed := 0
	busy := map[uuid.UUID]bool{}
	attempted := map[uuid.UUID]bool{}
	capped := map[uuid.UUID]int{} // real failures and internal faults of a website
	deployed := map[uuid.UUID]bool{}
	lastFailure := map[uuid.UUID]time.Time{}
	lastAny := map[uuid.UUID]time.Time{} // the last failed attempt of the version on a website, whatever its trigger
	inFlight := 0
	for _, d := range sn.deployments {
		if !d.done {
			busy[d.location] = true
			if d.automatic && !d.holding { // final review C1: a hold uses no budget, or a wave 1 over 5 never completes
				inFlight++
			}
		}
		if d.version == nil || *d.version != cur.id {
			continue
		}
		if d.done && (d.status == "succeeded" || d.status == "unchanged") {
			deployed[d.location] = true
		}
		if d.done && failedStatus(d.status) && d.finishedAt != nil && d.finishedAt.After(lastAny[d.location]) {
			lastAny[d.location] = *d.finishedAt
		}
		if d.automatic && d.done && failedStatus(d.status) && !d.createdAt.Before(*sn.autoSince) {
			attempted[d.location] = true
			switch {
			case neutralReason(d.errorCode):
			case d.errorCode == ReasonInternal:
				capped[d.location]++
			default:
				failed++
				capped[d.location]++
			}
			if d.finishedAt != nil && d.finishedAt.After(lastFailure[d.location]) {
				lastFailure[d.location] = *d.finishedAt
			}
		}
	}
	// A website whose attempts are used up by any mix of failures and internal faults is not capped
	// silently: it stops the wave, with the one notice.
	for _, n := range capped {
		failed = max(failed, n)
	}
	if failed >= AutoDeployMaxFailed {
		p.stop = &planStop{version: cur.id, name: cur.version, failed: failed}
		return p
	}
	older := false
	var fresh, retries []uuid.UUID
	for _, l := range sn.locations {
		switch {
		case busy[l.id], deployed[l.id]:
		case !lastAny[l.id].IsZero() && lastAny[l.id].Add(AutoDeployRetryAfter).After(now):
		case l.served != nil && *l.served == *cur.leaf:
		case l.servedNotAfter != nil && cur.leafNotAfter != nil && l.servedNotAfter.After(*cur.leafNotAfter):
			older = true
		case capped[l.id] >= AutoDeployMaxFailed:
		case !attempted[l.id]:
			fresh = append(fresh, l.id)
		case !lastFailure[l.id].Add(AutoDeployRetryAfter).After(now):
			retries = append(retries, l.id)
		}
	}
	if older && cur.skippedAt == nil {
		notify(cur, TemplateKVSkippedOlder, true)
	}
	// R65 (design §12): the canary of the vault's service's policy decides which of them go now.
	candidates, create, canarySkip := canaryFilter(sn.canary, append(fresh, retries...), func(l uuid.UUID) bool { return !lastAny[l].IsZero() }, now)
	if sn.reopened != nil && !cur.detectedAt.After(*sn.reopened) && cur.notifiedAt == nil && len(candidates) > 0 && !anyDeploymentOf(sn, cur) {
		// Detected before the licence gate last reopened (a renewal that arrived just before a lock and was not
		// planned yet), no wave of it ever began (no deployment of it at all, any trigger or status) and not
		// released by an Administrator (ReleaseVersion sets notified_at): without a person it would roll out the
		// moment the licence returns. Held for the licence instead, if the apply step finds a website it could
		// really deploy to; the existing "held" mail goes once. A wave that began before the lock continues under
		// the normal rules.
		p.hold = &planHold{version: cur.id, candidates: slices.Clone(candidates)}
		p.notices = append(p.notices, planNotice{version: cur.id, template: TemplateKVNewVersionHeldLicense, onHold: true})
		return p
	}
	p.budget = max(0, min(AutoDeployWave-inFlight, sn.remaining))
	if p.budget > 0 && len(candidates) > 0 {
		// Fresh websites first, then the retries, each in website order (the canary's wave 1 in its order).
		p.deploy, p.createRollout, p.canarySkipped = candidates, create, canarySkip
	}
	return p
}
