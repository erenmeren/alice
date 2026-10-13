package inventory

// The decision of the automatic deployment of ACME certificates (plan 2026-10-13 Task 12; design row 7; amendment A2),
// as a pure function: a snapshot of one ACME certificate and its bindings in, a plan out. acme_autodeploy.go reads the
// snapshot under the certificate's row lock and applies the plan in the same transaction. The rules are the Key Vault
// planner's (kv_autodeploy_plan.go: AutoDeployWave, AutoDeployMaxFailed, AutoDeployRetryAfter, the neutral reasons, the
// hold of a certificate that arrived before the licence gate last reopened), applied to the ACME certificate's current
// certificate and the locations bound to it: the "wave" of a certificate is its automatic deployments to its bound
// locations, as the wave of a vault version is its automatic deployments to the binding's websites.

import (
	"slices"
	"time"

	"github.com/google/uuid"
)

// Hold reasons of an ACME certificate's current certificate (acme_certificates.deploy_held_reason).
const (
	// ACMEHoldLicense: issued before the licence gate last reopened and no deployment of it began; an Administrator
	// releases it (ReleaseACMEDeployHold).
	ACMEHoldLicense = "license"
	// ACMEHoldChainIncomplete: its chain does not reach a trusted root (with the provider's bundle, A3). The planner never
	// confirms a chain: only a person's Deploy now with an Administrator's confirmation deploys it.
	ACMEHoldChainIncomplete = "chain_incomplete"
)

// acmeDeployCert is the current certificate of an ACME certificate.
type acmeDeployCert struct {
	id                  uuid.UUID
	notBefore, notAfter time.Time
	chainComplete       bool
	issuedAt            time.Time // when it became the current certificate (see readACMEDeploySnapshot)
}

// acmeDeployBinding is a bound location of a live server.
type acmeDeployBinding struct {
	location      uuid.UUID
	autoDeploy    bool
	createdAt     time.Time
	served        *uuid.UUID // the certificate the location served at the last scan
	attentionCode string     // "" when the binding is not marked
}

// acmeDeployment is a deployment the plan needs to know: every unfinished one of a bound location, and every one of the
// current certificate to a bound location.
type acmeDeployment struct {
	location    uuid.UUID
	certificate uuid.UUID
	automatic   bool // trigger acme_renewal
	done        bool
	status      string
	errorCode   string
	createdAt   time.Time
	finishedAt  *time.Time
}

type acmeDeploySnapshot struct {
	now                  time.Time
	gateOpen, autoDeploy bool
	current              *acmeDeployCert
	heldReason           string // the hold of the current certificate ("" none)
	released             bool   // an Administrator released the current certificate from the licence hold
	stopped              bool   // the wave of the current certificate stopped
	reopened             *time.Time
	bindings             []acmeDeployBinding // in location id order
	deployments          []acmeDeployment
	remaining            int // deployments the run may still create (all certificates)
}

// acmeAttention is a change of a binding's attention mark: code "" clears it.
type acmeAttention struct {
	location uuid.UUID
	code     string
}

// acmeDeployPlan is the outcome: locations to deploy to in order (at most budget of them are created: a location the
// checks refuse does not use up the budget), the hold to set (when the apply step finds a location it could deploy to),
// the stop of the wave, and the attention marks to change.
type acmeDeployPlan struct {
	deploy    []uuid.UUID
	budget    int
	hold      string      // ACMEHoldLicense or ACMEHoldChainIncomplete; candidates are the locations it is about
	candidate []uuid.UUID // the locations a hold would have deployed to
	stop      *planStop   // version is the certificate id, name unused
	stopCode  string      // the reason of the last counted failure
	attention []acmeAttention
}

// planACMEAutoDeploy decides what the planner does for one ACME certificate. Rules, in order:
//
//   - nothing while the licence gate is closed, automatic deployment of the certificate is off, or it has no current
//     certificate;
//   - the attention marks: a binding whose last automatic deployment of the current certificate (since the binding
//     exists) failed for a counted reason is marked with that reason; one whose location got or serves the current
//     certificate, or whose last such deployment did not fail, is cleared (also when nothing else is planned);
//   - a current certificate that is held (and not released) or whose wave stopped is left alone; an expired or not
//     yet valid one too (renewal is the renewal planner's matter);
//   - three failed automatic deployments of the current certificate (counted as the Key Vault planner counts:
//     the neutral reasons are exempt, a location whose attempts are used up by failures and internal faults counts
//     as much) stop the wave: no more deployments, one notice;
//   - the locations: only bindings with automatic deployment on; not those with an unfinished deployment of any kind,
//     not those that serve the current certificate or got it, not those within AutoDeployRetryAfter of a failed
//     attempt of it (whatever its trigger), not those with three attempts; fresh locations before retries. Unlike a
//     vault binding's website, a bound location whose certificate ends later than the current one is NOT skipped: the
//     binding is the person's explicit statement that the location follows this ACME certificate;
//   - an incomplete chain is held (chain_incomplete) with one notice, never deployed;
//   - a current certificate issued before the licence gate last reopened, of which no deployment exists (any trigger,
//     any status, any bound location), not released by an Administrator, is held (license) with one notice: without a
//     person it would roll out the moment the licence returns;
//   - otherwise at most min(AutoDeployWave - unfinished automatic deployments, remaining) are created.
func planACMEAutoDeploy(sn acmeDeploySnapshot) acmeDeployPlan {
	var p acmeDeployPlan
	if !sn.gateOpen || !sn.autoDeploy || sn.current == nil {
		return p
	}
	cur := sn.current
	auto := map[uuid.UUID]bool{}
	created := map[uuid.UUID]time.Time{}
	for _, b := range sn.bindings {
		auto[b.location] = b.autoDeploy
		created[b.location] = b.createdAt
	}
	failed := 0
	busy := map[uuid.UUID]bool{}
	attempted := map[uuid.UUID]bool{}
	capped := map[uuid.UUID]int{}
	deployed := map[uuid.UUID]bool{}
	lastFailure := map[uuid.UUID]time.Time{}
	lastAny := map[uuid.UUID]time.Time{}
	lastAuto := map[uuid.UUID]acmeDeployment{} // the newest finished automatic deployment of the current certificate
	anyOfCurrent, inFlight := false, 0
	lastCode := ""
	var lastCodeAt time.Time
	for _, d := range sn.deployments {
		if !d.done {
			busy[d.location] = true
			if d.automatic {
				inFlight++
			}
		}
		if d.certificate != cur.id {
			continue
		}
		anyOfCurrent = true
		if d.done && (d.status == DeployStatusSucceeded || d.status == DeployStatusUnchanged) {
			deployed[d.location] = true
		}
		if d.done && failedStatus(d.status) && d.finishedAt != nil && d.finishedAt.After(lastAny[d.location]) {
			lastAny[d.location] = *d.finishedAt
		}
		if !d.automatic || !d.done || d.createdAt.Before(created[d.location]) {
			continue
		}
		if prev, ok := lastAuto[d.location]; !ok || d.createdAt.After(prev.createdAt) {
			lastAuto[d.location] = d
		}
		if !failedStatus(d.status) {
			continue
		}
		attempted[d.location] = true
		switch {
		case neutralReason(d.errorCode):
		case d.errorCode == ReasonInternal:
			capped[d.location]++
		default:
			failed++
			capped[d.location]++
			if d.finishedAt != nil && !d.finishedAt.Before(lastCodeAt) {
				lastCode, lastCodeAt = d.errorCode, *d.finishedAt
			}
		}
		if d.finishedAt != nil && d.finishedAt.After(lastFailure[d.location]) {
			lastFailure[d.location] = *d.finishedAt
		}
	}

	for _, b := range sn.bindings {
		want := ""
		served := b.served != nil && *b.served == cur.id
		if d, ok := lastAuto[b.location]; ok && !served && !deployed[b.location] && failedStatus(d.status) && !neutralReason(d.errorCode) {
			want = d.errorCode
		}
		if want != b.attentionCode {
			p.attention = append(p.attention, acmeAttention{location: b.location, code: want})
		}
	}

	releasedFromLicence := sn.heldReason == ACMEHoldLicense && sn.released
	if (sn.heldReason != "" && !releasedFromLicence) || sn.stopped {
		return p
	}
	if !sn.now.Before(cur.notAfter) || sn.now.Before(cur.notBefore) {
		return p
	}
	for _, n := range capped {
		failed = max(failed, n)
	}
	if failed >= AutoDeployMaxFailed {
		p.stop = &planStop{version: cur.id, failed: failed}
		p.stopCode = lastCode
		if p.stopCode == "" { // only internal faults used the attempts up
			p.stopCode = ReasonInternal
		}
		return p
	}
	var fresh, retries []uuid.UUID
	for _, b := range sn.bindings {
		l := b.location
		switch {
		case !auto[l], busy[l], deployed[l]:
		case !lastAny[l].IsZero() && lastAny[l].Add(AutoDeployRetryAfter).After(sn.now):
		case b.served != nil && *b.served == cur.id:
		case capped[l] >= AutoDeployMaxFailed:
		case !attempted[l]:
			fresh = append(fresh, l)
		case !lastFailure[l].Add(AutoDeployRetryAfter).After(sn.now):
			retries = append(retries, l)
		}
	}
	candidates := append(slices.Clone(fresh), retries...)
	if len(candidates) == 0 {
		return p
	}
	if !cur.chainComplete {
		p.hold, p.candidate = ACMEHoldChainIncomplete, candidates
		return p
	}
	if sn.reopened != nil && !sn.released && !cur.issuedAt.After(*sn.reopened) && !anyOfCurrent {
		p.hold, p.candidate = ACMEHoldLicense, candidates
		return p
	}
	p.budget = max(0, min(AutoDeployWave-inFlight, sn.remaining))
	if p.budget > 0 {
		p.deploy = candidates
	}
	return p
}
