// Package jobs runs Alice's background work. Every job type declares its license class
// (spec §8.6, X-01), and every run passes the license gate first: the periodic in-process
// scheduler before each tick, the durable PostgreSQL queue (§8.1, queue.go and runner.go)
// before and right after every claim.
package jobs

import (
	"fmt"
	"sort"
	"sync"

	"github.com/google/uuid"

	"alice/internal/inventory"
	"alice/internal/license"
)

// Type is a job type and the way lock mode treats it.
type Type struct {
	Name  string
	Class license.Class
}

var (
	registryMu sync.Mutex
	registry   = map[string]Type{}
)

// Register declares a job type. It panics on an invalid license class or a duplicate name,
// so no job type can exist without a class (X-01).
func Register(name string, class license.Class) Type {
	if name == "" || !class.Valid() {
		panic(fmt.Sprintf("jobs: job type %q must declare a license class", name))
	}
	registryMu.Lock()
	defer registryMu.Unlock()
	if _, dup := registry[name]; dup {
		panic(fmt.Sprintf("jobs: job type %q is registered twice", name))
	}
	t := Type{Name: name, Class: class}
	registry[name] = t
	return t
}

// Types returns every registered job type, sorted by name.
func Types() []Type {
	registryMu.Lock()
	defer registryMu.Unlock()
	out := make([]Type, 0, len(registry))
	for _, t := range registry {
		out = append(out, t)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}

func lookup(name string) (Type, bool) {
	registryMu.Lock()
	defer registryMu.Unlock()
	t, ok := registry[name]
	return t, ok
}

// Phase 2 job types (spec §8.2). Both run in every license state (§8.6).
var (
	LicenseEvaluate = Register("license.evaluate", license.ClassAlways)
	NotifySend      = Register("notify.send", license.ClassAlways)
)

// Phase 3 periodic tasks (spec §8.2): the daily audit chain verification and the cleanup run in
// every license state; scheduling discovery is read-only work and pauses in lock (L-27).
var (
	AuditVerify        = Register("audit.verify", license.ClassAlways)
	MaintenanceCleanup = Register("maintenance.cleanup", license.ClassAlways)
	DiscoverySchedule  = Register("discovery.schedule", license.ClassReadOnly)
)

// Phase 3 queue job types (spec §8.2, §8.6): connection tests and discovery are read-only work
// (paused in lock); removing a key changes a managed server (refused in lock, R9).
var (
	TargetTestConnection = Register(inventory.JobTestConnection, license.ClassReadOnly)
	TargetDiscover       = Register(inventory.JobDiscover, license.ClassReadOnly)
	SSHKeyRemove         = Register(inventory.JobSSHKeyRemove, license.ClassChange)
)

// Phase 4 job types (spec §8.2, §8.6, §8.7): a deployment changes a server (refused and held in
// lock); finishing or undoing an interrupted one is never blocked (L-82, R38 item 8); the sweep
// that finds interrupted ones runs in every state.
var (
	CertificateDeploy        = Register(inventory.JobCertificateDeploy, license.ClassChange)
	CertificateDeployRecover = Register(inventory.JobDeployRecover, license.ClassAlways)
	DeploymentRecoverySweep  = Register("deployment.recovery_sweep", license.ClassAlways)
)

// CertificateDeployAuto is a deployment the automatic planners (Key Vault and ACME) queued to a location the
// certificate is already bound to (owner decision 2026-10-20). It runs the certificate.deploy handler and shares
// its dedupe key namespace (certificate.deploy:<deployment id>), but its class is ClassContinuity: it runs in the
// continuity window of a lock, while a person's deployment (certificate.deploy, ClassChange) is refused and held.
var CertificateDeployAuto = Register(inventory.JobCertificateDeployAuto, license.ClassContinuity)

// Phase 5 queue job types (Key Vault, spec §8.2, §11): the access check of a vault is read-only work
// (paused in lock); an import into a vault changes a managed system (refused in lock). The poll of a vault
// is continuity work (owner decision 2026-10-20): it is how a version renewed in Azure is seen, so it runs
// in the continuity window of a lock too. The runners are in internal/jobs/kvjobs.
var (
	KVTestConnection = Register(inventory.JobKVTest, license.ClassReadOnly)
	KVPoll           = Register(inventory.JobKVPoll, license.ClassContinuity)
	KVImport         = Register(inventory.JobKVImport, license.ClassChange)
)

// Phase 5 periodic tasks (R40 row 29): the poll scheduler and the automatic deployment planner. Both are
// continuity work (owner decision 2026-10-20): they run wherever changes run and in the continuity window
// of a lock (the scheduler refuses a ClassChange task: external-change work a person asked for waits for a
// person). The planner queues certificate.deploy_auto jobs (ClassContinuity) and returns at once while the
// gate refuses continuity work (PlanKVAutoDeploy).
var (
	KVSchedule   = Register("kv.schedule", license.ClassContinuity)
	KVAutoDeploy = Register("kv.auto_deploy", license.ClassContinuity)
)

// Phase 6 job types (spec §8.2, §8.6, §13.4-§13.6; R41 rows 18-20). Deploying a generated key changes a
// server (refused and held in lock). A rotation's per-location work finishes in-flight operations and
// undoes the run's own additions in every state; its forward steps ask the gate themselves at every
// boundary (internal/jobs/sshkeyjobs, sshkeys.BeginAdd and BeginRemove). Planning previews is read-only
// work (no tick in lock: L-88); the sweep runs in every state to flag pauses (L-83); destroying retired
// private keys is a deletion, so it pauses in lock. The names are literals (the web's label guard reads
// literal Register calls) and equal the sshkeys module's constants (TestPhase6JobTypesAreTheModulesNames).
var (
	SSHKeyAdd            = Register("sshkey.add", license.ClassChange)
	RotationLocation     = Register("rotation.location", license.ClassAlways)
	RotationPlan         = Register("rotation.plan", license.ClassReadOnly)
	RotationSweep        = Register("rotation.sweep", license.ClassAlways)
	SSHKeyDestroyRetired = Register("sshkey.destroy_retired", license.ClassReadOnly)
)

// Phase 8 periodic tasks (contract C1), all in every license state: the daily backup check (backup.schedule, every
// 5 minutes), the renewal of the temporary HTTPS certificate (tls.renew, every 6 hours), audit forwarding
// (audit.forward, every 15 seconds) and the scheduler's heartbeat that alice selfcheck reads (jobs.heartbeat, every
// minute). The names are literals (the web's label guard reads literal Register calls).
var (
	BackupSchedule = Register("backup.schedule", license.ClassAlways)
	TLSRenew       = Register("tls.renew", license.ClassAlways)
	AuditForward   = Register("audit.forward", license.ClassAlways)
	JobsHeartbeat  = Register("jobs.heartbeat", license.ClassAlways)
)

// ACME certificate issuance (the names are literals: the web's label guard reads literal Register calls). An order a
// person starts (first issuance, Renew now, a test run) contacts a certificate authority and may change a DNS zone
// through a hook, so it is refused and held in lock (acme.issue). An order the renewal planner starts for an issued
// certificate is continuity work (acme.renew, owner decision 2026-10-20): the same handler, the same dedupe key
// (acme.issue:<acme certificate id>), but it runs in the continuity window of a lock. Cleanup of leftover challenge
// records runs in every state; the renewal planner and the auto-deploy planner are periodic continuity work (the
// scheduler refuses a ClassChange task; the planners call license.Allow(ClassContinuity) themselves). The sweep
// (acme.sweep, periodic, every license state) ends the orders a crash left running and queues the cleanup of leftover
// challenge records, so it runs in lock too (it contacts a CA only to finish an issued order, and only when the gate
// allows the order's class).
var (
	ACMEIssue      = Register("acme.issue", license.ClassChange)
	ACMERenew      = Register(inventory.JobACMERenew, license.ClassContinuity)
	ACMECleanup    = Register("acme.cleanup", license.ClassAlways)
	ACMESchedule   = Register("acme.schedule", license.ClassContinuity)
	ACMEAutoDeploy = Register("acme.auto_deploy", license.ClassContinuity)
	ACMESweep      = Register("acme.sweep", license.ClassAlways)
)

// continuityReadOnly lists the continuity job types that only read a managed system. After the continuity window
// ends, the runner treats a queued continuity job as its kind of work was treated before the window existed: one that
// only reads (a Key Vault poll) is cancelled, as read-only work is in lock, and re-planned by its scheduler after a
// renewal; every other one (a renewal order, an automatic deployment) is held for an Administrator's confirmation, as
// a change is (blocked_license, R29).
var continuityReadOnly = map[string]bool{inventory.JobKVPoll: true}

// continuityReadOnlyTypes is continuityReadOnly as a list (the runner's lock sweep).
func continuityReadOnlyTypes() []string {
	out := make([]string, 0, len(continuityReadOnly))
	for name := range continuityReadOnly {
		out = append(out, name)
	}
	sort.Strings(out)
	return out
}

// heldInLock reports whether a job of type t that the confirmed lock refuses is held for an Administrator's
// confirmation (blocked_license) rather than cancelled: a change, and continuity work that is not read-only.
func heldInLock(t Type) bool {
	return t.Class == license.ClassChange || (t.Class == license.ClassContinuity && !continuityReadOnly[t.Name])
}

// Network certificate discovery (plan amendments A1, A5). The namespace is netdisco.*: discovery.schedule above is the
// SSH-key target discovery task and is a different thing. netdisco.scan probes the endpoints of one scope: read-only work
// (paused in lock; the scanner also asks license.Allow(ClassReadOnly) per batch), one attempt (MaxAttemptsFor), at most
// MaxConcurrentNetdiscoScans running at once (maxRunning) and one per scope (dedupe key NetdiscoScanDedupeKey).
// netdisco.schedule is the periodic task that queues the scans of scopes with a schedule (ReadOnly: no tick in lock).
// netdisco.retention is the periodic cleanup of gone endpoints, orphan certificates and old scans (ClassAlways: it only
// deletes Alice's own rows, so it runs in lock too). The names are literals (the web's label guard reads literal Register
// calls); the handler and the two tasks are in internal/jobs/netdiscojobs.
var (
	NetdiscoScan      = Register("netdisco.scan", license.ClassReadOnly)
	NetdiscoSchedule  = Register("netdisco.schedule", license.ClassReadOnly)
	NetdiscoRetention = Register("netdisco.retention", license.ClassAlways)
)

// MaxConcurrentNetdiscoScans is the number of netdisco.scan jobs that may run at once in the installation (design
// decision 1: at most 2 scans at once). A third stays queued with its attempt unspent.
const MaxConcurrentNetdiscoScans = 2

// NetdiscoScanDedupeKey is the dedupe key of a scan job: "netdisco.scan:<scope id>". The queue keeps at most one live
// job per key, so a scope has at most one queued or running scan; the backup restore matches the same type name.
func NetdiscoScanDedupeKey(scopeID uuid.UUID) string {
	return NetdiscoScan.Name + ":" + scopeID.String()
}

// Kind says who asks for a job (jobs.kind).
type Kind string

// Job kinds.
const (
	KindUser      Kind = "user"
	KindScheduled Kind = "scheduled"
	KindSystem    Kind = "system"
)

func (k Kind) valid() bool { return k == KindUser || k == KindScheduled || k == KindSystem }

// Status is a job's state (jobs.status).
type Status string

// Job statuses. StatusBlocked: external-change work that was due while the license was
// expired; it runs only after an Administrator confirms it (R29, L-81).
const (
	StatusQueued    Status = "queued"
	StatusRunning   Status = "running"
	StatusSucceeded Status = "succeeded"
	StatusFailed    Status = "failed"
	StatusCancelled Status = "cancelled"
	StatusDead      Status = "dead"
	StatusBlocked   Status = "blocked_license"
)

// MaxAttemptsFor is the default number of attempts of a job type (spec §8.4): a connection
// test (an access check of a vault, a poll of it) is shown to the user at once and not retried (the
// vault's own back-off paces polls); discovery tolerates a flaky network. A key deploy and a rotation
// location job keep the default 3 (their handlers retry only before anything was sent, or after the
// wait an uncertain write needs). An import into a vault runs
// at most 3 times and is retried only before its request was sent. A
// deployment's job runs at most 3 times (a run after the first send never sends again: it reads
// the deployment's state and recovers). A recovery job runs once: the deployment sweep paces
// recovery (a new job every inventory.RecoveryRetryInterval, at most inventory.MaxRecoveryAttempts),
// so a failed attempt waits for the sweep instead of polling the server on the queue's backoff. An ACME order runs
// once: a repeat would start a second order at the authority, so the planner (acme.schedule) paces retries. The
// cleanup of an order's leftover challenge records is tried 5 times on the queue's backoff (a hook or a server that is
// briefly down), then the sweep (acme.sweep) queues it again after an hour. A network discovery scan runs once: a
// failed or interrupted scan is started again by a person or by its scope's schedule, never by the queue's backoff (a
// retry would probe the same hosts again within minutes). An observation of a server's bound locations runs once too:
// a failed probe is recorded on the locations, and the next one comes with the observation interval (R52).
func MaxAttemptsFor(t Type) int {
	switch t.Name {
	case inventory.JobTestConnection, inventory.JobDeployRecover, inventory.JobKVTest, inventory.JobKVPoll, ACMEIssue.Name,
		inventory.JobACMERenew, NetdiscoScan.Name, inventory.JobDriftObserve:
		return 1
	case inventory.JobDiscover, ACMECleanup.Name:
		return 5
	default:
		return 3
	}
}

// AlertsWhenExhausted reports whether a job of the type that fails retryably on its last attempt
// is dead with the job.dead email to every Administrator (spec §8.4). A recovery job is not: its
// failure ends the job as a plain failure (failed, no email), the deployment sweep queues the next
// one, and the deployment's own needs-attention email, sent once, is the alert. Otherwise an
// unreachable server would send one job.dead email per recovery cycle (plan decision 15). A poll of a
// vault is not either: its failure is on the vault (status, last error, its own email) and polls repeat
// on the vault's interval, so a dead-job email per cycle would only repeat it. A rotation's location job
// is not either: the rotation sweep re-queues it and the rotation's own emails carry its failures. The cleanup of an
// ACME order is not either: its failure is recorded on the order (cleanup_error_code, audit acme.order.cleanup_failed)
// and the ACME sweep queues it again every hour, so a dead-job email would repeat every hour while a hook is down. An
// observation of a server is not either: its failure is on the locations (unreachable) and in the drift notices.
func AlertsWhenExhausted(t Type) bool {
	return t.Name != inventory.JobDeployRecover && t.Name != inventory.JobKVPoll && t.Name != RotationLocation.Name &&
		t.Name != ACMECleanup.Name && t.Name != inventory.JobDriftObserve
}

// maxRunning is the concurrency cap of a job type: the runner claims no job of the type while that many
// of them are running (in any process: the count is the jobs table's). A type that is not listed has no
// cap. A poll of a vault is capped at inventory.MaxConcurrentKVPolls (ruling S12): a poll beyond the cap
// stays queued, with its attempt unspent, instead of occupying a worker that waits for the poll slot while
// deployments, imports and access checks wait behind it. The poll's own slot (inventory.AcquireKVPoll)
// stays as the backstop. A network discovery scan is capped at MaxConcurrentNetdiscoScans (A5).
var maxRunning = map[string]int{
	inventory.JobKVPoll: inventory.MaxConcurrentKVPolls,
	NetdiscoScan.Name:   MaxConcurrentNetdiscoScans,
}

// MaxRunningFor returns the concurrency cap of the job type (false: none).
func MaxRunningFor(t Type) (int, bool) {
	n, ok := maxRunning[t.Name]
	return n, ok
}

// Key-compromise incidents (owner decision 2026-10-20, docs/superpowers/rulings/certificate-revocation.md): the periodic
// task that advances every open incident (inventory.AdvanceIncidents). ClassAlways: it follows the deployments and orders
// an incident started in every license state, and asks the gate itself (ClassChange) before it requests a deployment,
// starts an order or revokes at a CA. The name is a literal (the web's label guard reads literal Register calls) and
// equals inventory.JobIncidentAdvance.
var IncidentAdvance = Register("incident.advance", license.ClassAlways)

// Certificate drift (R52, docs/superpowers/rulings/certificate-drift.md). drift.schedule is the periodic task that queues
// the observation of the bound locations that are due, and drift.observe observes one server (a scan of its certificate
// files and a probe of its websites): both only read managed systems (ClassReadOnly: paused in lock). drift.repair is
// the periodic task that repairs drifted locations in mode auto through the deployment engine (each repair a
// certificate.deploy_auto job): automatic upkeep of certificates already managed, ClassContinuity as
// certificate.deploy_auto (R44). The names are literals (the web's label guard reads literal Register calls); the
// observation's equals inventory.JobDriftObserve (TestDriftTypes).
var (
	DriftSchedule = Register("drift.schedule", license.ClassReadOnly)
	DriftObserve  = Register("drift.observe", license.ClassReadOnly)
	DriftRepair   = Register("drift.repair", license.ClassContinuity)
)

// Phase 7 periodic task (R42 rows 3 and 5; §8.2 alerts.evaluate, §8.6 "not gated"): the expiry scan sends notices in
// every license state (in lock with the license note, L-28).
var AlertsScan = Register("alerts.scan", license.ClassAlways)
