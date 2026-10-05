package fake

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"slices"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	"golang.org/x/crypto/ssh"

	"alice/internal/providers"
	"alice/internal/providers/linuxssh"
	"alice/internal/providers/linuxssh/helperproto"
)

// ConnectionAccount is the account Alice signs in with on every modelled target: the world refuses
// to remove its last key, as the real provider does.
const ConnectionAccount = linuxssh.ServiceUser

// DefaultLateDelay is how long after its call a FaultLateWrite change lands unless SetLateDelay says
// otherwise: inside the helper's own budget, because the helper never writes after its deadline.
const DefaultLateDelay = helperproto.HelperBudget - 5*time.Second

// KeyWorld models authorized_keys files of several targets (C5). A file is identified by its target
// and path. Put declares which users' logins read a file, so a shared file serves all of them
// (spec §13.3); nothing else does: an add never extends what a user's login reads, as sshd reads
// only the user's candidate files.
//
// It follows the real provider's rules (see providertest.CheckKeyLifecycle, which runs one script
// against both): an add or a removal changes a file only as the account the helper resolved it to
// (the owner), an add to a file the user does not read is refused, cert-authority and unparseable
// lines are refused on add, a cert-authority line is never removed and never logs anyone in, the
// last key of the connection account (ConnectionAccount) and of root is not removed (root unless
// AllowLastRootKey). Not modelled: from= and other options (use FaultRefuse on a login), uid-0
// accounts other than "root", file size limits and StrictModes.
//
// The owner of a shared file is the first user Put for it; the real helper resolves a file to the
// first account in its scan order (uid ascending, then name), so Put the users of a shared file in
// that order.
//
// The fault decision runs outside the world's lock: it may read the world (Lines, Has, Events).
type KeyWorld struct {
	mu        sync.Mutex
	files     map[worldFile][]string
	users     map[worldUser][]string // (target, user) -> file paths the user's logins read
	owners    map[worldFile]string   // file -> the user first Put for it: the account the helper resolves it to
	events    []Event
	fault     func(FaultPoint) Fault
	n         int
	now       func() time.Time
	flushOnly bool // SetClock(nil): late writes land only through FlushLate
	late      time.Duration
	queued    []lateWrite
	landed    int
	keyFiles  map[worldUser]keyFilesState
	coverage  map[worldFile]providers.CoverageState // SetCoverage: persistent per-file listing coverage
}

// keyFilesState is what a world's discovery says about one user's candidate key files.
type keyFilesState int

const (
	keyFilesComplete keyFilesState = iota
	keyFilesIncomplete
	keyFilesUnknown
)

// lateWrite is a change a stalled call lands after it already answered (FaultLateWrite).
type lateWrite struct {
	due   time.Time
	p     FaultPoint
	apply func() bool // reports whether the file changed
}

type worldFile struct {
	target uuid.UUID
	path   string
}

type worldUser struct {
	target uuid.UUID
	user   string
}

// FaultPoint describes one call of the world, for the fault decision.
type FaultPoint struct {
	N           int    // 1-based index over every Add, Remove, VerifyKeyLogin and ListKeys call of the world
	Method      string // "AddAuthorizedKey" | "RemoveAuthorizedKey" | "VerifyKeyLogin" | "ListKeys"
	Target      uuid.UUID
	OSUser      string
	FilePath    string
	Fingerprint string // remove: the key removed; add and login: the key added or offered
}

// Fault is what goes wrong in one call.
type Fault int

// The faults.
const (
	FaultNone        Fault = iota
	FaultRefuse            // add/remove: helper refusal before any change (ssh.helper_refused, definite); login: KeyLoginRefused
	FaultUnreachable       // nothing happens; ssh.unreachable (retryable, nothing sent)
	FaultAfterWrite        // add/remove: the change happens, then ssh.timeout (outcome uncertain); login: ssh.timeout
	FaultFileChanged       // add/remove: ssh.file_changed after 3 attempts (definite, nothing written)
	FaultUnprovable        // login only: KeyLoginUnprovable
	FaultHang              // block until ctx ends, then the change does NOT happen and ctx.Err is returned wrapped in ssh.timeout
	// FaultLateWrite: add/remove: the call fails with ssh.timeout now, nothing has changed yet, and the
	// change lands once the world's clock (SetClock) has passed the call's time plus the late delay
	// (SetLateDelay, DefaultLateDelay): a stalled write that finishes after the caller gave up (S3).
	// A world with no clock and no explicit SetClock(nil) panics on the call, so a harness cannot
	// forget the clock and pass without the write ever landing; PendingLate and LateLanded let a test
	// assert it did. Login: ssh.timeout.
	FaultLateWrite
	// FaultUnread: ListKeys only: the listing omits every file of the target and says so (every
	// file CoverageUnread, no keys), as a real listing does when it cannot read them.
	FaultUnread
	// FaultPartial: ListKeys only: the answer comes back cut (every file CoveragePartial, no keys).
	FaultPartial
)

// Event is one recorded call of the world, or (Landed) a late write landing.
type Event struct {
	FaultPoint
	Fault   Fault
	Changed bool
	Outcome providers.KeyLoginOutcome // logins
	// Landed marks the landing of a FaultLateWrite change: N and the rest are those of the call that
	// stalled, Changed is true.
	Landed bool
}

// SetClock sets the world's clock, which dates FaultLateWrite changes. SetClock(nil) states that
// late writes land only through FlushLate.
func (w *KeyWorld) SetClock(now func() time.Time) {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.now, w.flushOnly = now, now == nil
}

// SetLateDelay sets how long after its call a FaultLateWrite change lands (default DefaultLateDelay).
func (w *KeyWorld) SetLateDelay(d time.Duration) {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.late = d
}

// FlushLate lands every pending late write now.
func (w *KeyWorld) FlushLate() {
	w.mu.Lock()
	defer w.mu.Unlock()
	queued := w.queued
	w.queued = nil
	for _, q := range queued {
		w.land(q)
	}
}

// PendingLate is the number of late writes that have not landed yet.
func (w *KeyWorld) PendingLate() int {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.landLate()
	return len(w.queued)
}

// LateLanded is the number of late writes that landed and changed a file.
func (w *KeyWorld) LateLanded() int {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.landLate()
	return w.landed
}

// land applies one late write and records its landing; the caller holds the lock.
func (w *KeyWorld) land(q lateWrite) {
	if !q.apply() {
		return
	}
	w.landed++
	w.events = append(w.events, Event{FaultPoint: q.p, Fault: FaultLateWrite, Changed: true, Landed: true})
}

// landLate lands the late writes that are due; the caller holds the lock.
func (w *KeyWorld) landLate() {
	if w.now == nil || len(w.queued) == 0 {
		return
	}
	now := w.now()
	var rest []lateWrite
	due := w.queued
	for _, q := range due {
		if now.Before(q.due) {
			rest = append(rest, q)
		}
	}
	w.queued = rest
	for _, q := range due {
		if !now.Before(q.due) {
			w.land(q)
		}
	}
}

// queueLate schedules apply for the late delay after now; the caller holds the lock.
func (w *KeyWorld) queueLate(p FaultPoint, apply func() bool) {
	if w.now == nil && !w.flushOnly {
		panic("fake.KeyWorld: FaultLateWrite needs SetClock(clock), or SetClock(nil) to land late writes with FlushLate only")
	}
	d := w.late
	if d == 0 {
		d = DefaultLateDelay
	}
	var due time.Time
	if w.now != nil {
		due = w.now().Add(d)
	}
	w.queued = append(w.queued, lateWrite{due: due, p: p, apply: apply})
}

// NewKeyWorld returns an empty world without faults.
func NewKeyWorld() *KeyWorld {
	return &KeyWorld{files: map[worldFile][]string{}, users: map[worldUser][]string{}, owners: map[worldFile]string{}, keyFiles: map[worldUser]keyFilesState{}, coverage: map[worldFile]providers.CoverageState{}}
}

// Put sets a file's lines (verbatim) and records that osUser reads it. The first user put for a file
// is its owner, the account the real helper resolves it to: changes by any other user are refused
// (the real provider's owner rule, S10), while every recorded user's login reads it. A file that
// was Put exists, even with no lines.
func (w *KeyWorld) Put(target uuid.UUID, osUser, file string, lines ...string) {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.landLate()
	wf := worldFile{target, file}
	w.files[wf] = slices.Clone(lines)
	if _, ok := w.owners[wf]; !ok {
		w.owners[wf] = osUser
	}
	u := worldUser{target, osUser}
	if !slices.Contains(w.users[u], file) {
		w.users[u] = append(w.users[u], file)
	}
}

// Lines returns a copy of a file's lines (nil when the file does not exist).
func (w *KeyWorld) Lines(target uuid.UUID, file string) []string {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.landLate()
	return slices.Clone(w.files[worldFile{target, file}])
}

// Has reports whether any line of the file holds the key with this fingerprint.
func (w *KeyWorld) Has(target uuid.UUID, file, fingerprint string) bool {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.landLate()
	return indexOf(w.files[worldFile{target, file}], fingerprint) >= 0
}

// Events returns every call, in order.
func (w *KeyWorld) Events() []Event {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.landLate()
	return slices.Clone(w.events)
}

// MarkKeyFilesIncomplete makes discovery report the user's candidate key files as incomplete
// (UserKeyFiles.Complete false): some file sshd reads for the user may be missing from the list.
func (w *KeyWorld) MarkKeyFilesIncomplete(target uuid.UUID, osUser string) {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.keyFiles[worldUser{target, osUser}] = keyFilesIncomplete
}

// HideKeyFiles makes discovery leave the user out of the candidate key files (unknown).
func (w *KeyWorld) HideKeyFiles(target uuid.UUID, osUser string) {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.keyFiles[worldUser{target, osUser}] = keyFilesUnknown
}

// SetCoverage makes every listing (ListKeys) of the target report the file with this coverage:
// CoverageUnread or CoveragePartial hide its keys and withhold any proof of absence;
// CoverageComplete (the default) restores it.
func (w *KeyWorld) SetCoverage(target uuid.UUID, file string, state providers.CoverageState) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if state == providers.CoverageComplete {
		delete(w.coverage, worldFile{target, file})
		return
	}
	w.coverage[worldFile{target, file}] = state
}

// listKeys is a listing with coverage: every file a user reads is named, complete unless SetCoverage
// or a FaultUnread/FaultPartial at this call index says otherwise (those files list no keys).
// FaultUnreachable and FaultHang fail the call.
func (w *KeyWorld) listKeys(ctx context.Context, target uuid.UUID) (providers.KeyListing, error) {
	w.mu.Lock()
	p, f := w.begin(FaultPoint{Method: "ListKeys", Target: target})
	if f == FaultHang {
		w.record(p, f, false, "")
		w.mu.Unlock()
		return providers.KeyListing{}, hang(ctx)
	}
	defer w.mu.Unlock()
	w.record(p, f, false, "")
	if f == FaultUnreachable {
		return providers.KeyListing{}, providers.NewError("ssh.unreachable", true, nil, nil)
	}
	var users []worldUser
	for u := range w.users {
		if u.target == target {
			users = append(users, u)
		}
	}
	sort.Slice(users, func(i, j int) bool { return users[i].user < users[j].user })
	var l providers.KeyListing
	for _, u := range users {
		for _, file := range w.users[u] {
			st := w.coverage[worldFile{target, file}]
			switch f {
			case FaultUnread:
				st = providers.CoverageUnread
			case FaultPartial:
				st = providers.CoveragePartial
			}
			if st == "" {
				st = providers.CoverageComplete
				ak := parse(w.files[worldFile{target, file}])
				keys, bad := ak.Keys(u.user, file)
				l.Keys = append(l.Keys, keys...)
				if len(bad) > 0 {
					st = providers.CoveragePartial // a line that is not a key, comment or blank: as the real discovery
				}
			}
			l.Files = append(l.Files, providers.FileCoverage{OSUser: u.user, FilePath: file, State: st})
		}
	}
	return l, nil
}

// userKeyFiles is what a discovery of the target reports: every user that has a file, in name order,
// complete unless MarkKeyFilesIncomplete or HideKeyFiles said otherwise.
func (w *KeyWorld) userKeyFiles(target uuid.UUID) []providers.UserKeyFiles {
	w.mu.Lock()
	defer w.mu.Unlock()
	var users []worldUser
	for u := range w.users {
		if u.target == target && w.keyFiles[u] != keyFilesUnknown {
			users = append(users, u)
		}
	}
	sort.Slice(users, func(i, j int) bool { return users[i].user < users[j].user })
	out := make([]providers.UserKeyFiles, 0, len(users))
	for _, u := range users {
		out = append(out, providers.UserKeyFiles{OSUser: u.user, Files: slices.Clone(w.users[u]), Complete: w.keyFiles[u] == keyFilesComplete})
	}
	return out
}

// SetFault installs the fault decision (nil: none).
func (w *KeyWorld) SetFault(f func(FaultPoint) Fault) {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.fault = f
}

// parse reads world lines as the real provider reads a file.
func parse(lines []string) linuxssh.AuthorizedKeys {
	ak, _ := linuxssh.ParseAuthorizedKeys([]byte(strings.Join(lines, "\n")))
	return ak
}

func lineFingerprint(line string) string {
	ak := parse([]string{line})
	if len(ak.Lines) != 1 || ak.Lines[0].Kind != linuxssh.LineKey {
		return ""
	}
	return ak.Lines[0].Fingerprint
}

func hasOption(l linuxssh.Line, name string) bool {
	for _, o := range l.Options {
		k, _, _ := strings.Cut(o, "=")
		if strings.EqualFold(strings.TrimSpace(k), name) {
			return true
		}
	}
	return false
}

func indexOf(lines []string, fp string) int {
	if fp == "" {
		return -1
	}
	for i, l := range parse(lines).Lines {
		if l.Kind == linuxssh.LineKey && l.Fingerprint == fp {
			return i
		}
	}
	return -1
}

// without returns lines minus every key line of the fingerprint.
func without(lines []string, fp string) []string {
	var out []string
	for i, l := range parse(lines).Lines {
		if l.Kind == linuxssh.LineKey && l.Fingerprint == fp {
			continue
		}
		out = append(out, lines[i])
	}
	return out
}

func digest(lines []string) string {
	sum := sha256.Sum256([]byte(strings.Join(lines, "\n")))
	return hex.EncodeToString(sum[:])
}

// begin numbers the call and asks the fault decision. The caller holds the lock; the decision runs
// with it released, so it may read the world, and the lock is held again on return.
func (w *KeyWorld) begin(p FaultPoint) (FaultPoint, Fault) {
	w.landLate()
	w.n++
	p.N = w.n
	fault := w.fault
	if fault == nil {
		return p, FaultNone
	}
	w.mu.Unlock()
	f := fault(p)
	w.mu.Lock()
	return p, f
}

func (w *KeyWorld) record(p FaultPoint, f Fault, changed bool, o providers.KeyLoginOutcome) {
	w.events = append(w.events, Event{FaultPoint: p, Fault: f, Changed: changed, Outcome: o})
}

func step(log providers.StepLogger, name string, st providers.StepStatus) {
	if log != nil {
		log.Step(name, st, nil)
	}
}

// hang blocks until ctx ends (FaultHang), then answers as a timed-out call that changed nothing.
func hang(ctx context.Context) error {
	<-ctx.Done()
	return providers.NewError("ssh.timeout", true, ctx.Err(), nil)
}

func refusedRequest(field string) error {
	return providers.NewError("ssh.helper_refused", false, nil,
		map[string]string{"helper_code": helperproto.CodeInvalidArgument, "field": field})
}

// checkOwner mirrors linuxssh: a file the helper resolved to one account refuses a change that
// names another, and a file the user does not read (never Put) is refused as a missing file the
// helper does not list for the user.
func (w *KeyWorld) checkOwner(file worldFile, osUser string) error {
	owner, ok := w.owners[file]
	if !ok || owner != osUser {
		return refusedRequest("os_user")
	}
	return nil
}

// checkAddLine refuses, before anything is sent, a line that is not exactly one plain key line.
func checkAddLine(line string) error {
	if strings.ContainsAny(line, "\r\n") {
		return refusedRequest("line")
	}
	ak := parse([]string{line})
	if len(ak.Lines) != 1 || ak.Lines[0].Kind != linuxssh.LineKey || hasOption(ak.Lines[0], "cert-authority") {
		return refusedRequest("line")
	}
	return nil
}

// list returns every parseable line of the target's files as the accounts that read them see it,
// with the flags and sizes the real discovery sets.
func (w *KeyWorld) list(target uuid.UUID) []providers.DiscoveredSSHKey {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.landLate()
	var users []worldUser
	for u := range w.users {
		if u.target == target {
			users = append(users, u)
		}
	}
	sort.Slice(users, func(i, j int) bool { return users[i].user < users[j].user })
	var out []providers.DiscoveredSSHKey
	for _, u := range users {
		for _, file := range w.users[u] {
			keys, _ := parse(w.files[worldFile{target, file}]).Keys(u.user, file)
			out = append(out, keys...)
		}
	}
	return out
}

func (w *KeyWorld) add(ctx context.Context, target uuid.UUID, req providers.AuthKeyChange, log providers.StepLogger) (providers.AuthKeyResult, error) {
	if !helperproto.ValidAccount(req.OSUser) {
		return providers.AuthKeyResult{}, refusedRequest("os_user")
	}
	if err := checkAddLine(req.Line); err != nil {
		return providers.AuthKeyResult{}, err
	}
	fp := lineFingerprint(req.Line)
	w.mu.Lock()
	p, f := w.begin(FaultPoint{Method: "AddAuthorizedKey", Target: target, OSUser: req.OSUser, FilePath: req.FilePath, Fingerprint: fp})
	if f == FaultHang {
		w.record(p, f, false, "")
		w.mu.Unlock()
		return providers.AuthKeyResult{}, hang(ctx)
	}
	defer w.mu.Unlock()
	file := worldFile{target, req.FilePath}
	old := w.files[file]
	step(log, "precheck", providers.StepOK)
	switch f {
	case FaultRefuse:
		w.record(p, f, false, "")
		return providers.AuthKeyResult{}, providers.NewError("ssh.helper_refused", false, nil, map[string]string{"helper_code": "INVALID_ARGUMENT"})
	case FaultUnreachable:
		w.record(p, f, false, "")
		return providers.AuthKeyResult{}, providers.NewError("ssh.unreachable", true, nil, nil)
	case FaultFileChanged:
		step(log, "write", providers.StepStarted)
		step(log, "write", providers.StepFailed)
		w.record(p, f, false, "")
		return providers.AuthKeyResult{}, providers.NewError("ssh.file_changed", true, nil, map[string]string{"attempts": "3"})
	}
	if err := w.checkOwner(file, req.OSUser); err != nil {
		w.record(p, f, false, "")
		return providers.AuthKeyResult{}, err
	}
	if i := indexOf(old, fp); i >= 0 {
		w.record(p, f, false, "")
		return providers.AuthKeyResult{OldSHA256: digest(old), NewSHA256: digest(old), LineNo: i + 1}, nil
	}
	step(log, "write", providers.StepStarted)
	if f == FaultLateWrite {
		w.queueLate(p, func() bool {
			cur := w.files[file]
			if indexOf(cur, fp) >= 0 {
				return false
			}
			w.files[file] = append(slices.Clone(cur), req.Line)
			return true
		})
		w.record(p, f, false, "")
		return providers.AuthKeyResult{}, providers.NewError("ssh.timeout", true, nil, nil)
	}
	next := append(slices.Clone(old), req.Line)
	w.files[file] = next
	res := providers.AuthKeyResult{Changed: true, OldSHA256: digest(old), NewSHA256: digest(next), LineNo: len(next), Verified: true,
		Backup: "/var/lib/alice-helper/backups/" + req.OperationID.String()}
	w.record(p, f, true, "")
	if f == FaultAfterWrite {
		return res, providers.NewError("ssh.timeout", true, nil, nil)
	}
	step(log, "write", providers.StepOK)
	return res, nil
}

func (w *KeyWorld) remove(ctx context.Context, target uuid.UUID, req providers.AuthKeyChange, log providers.StepLogger) (providers.AuthKeyResult, error) {
	if slices.Contains(req.ProtectedFingerprints, req.Fingerprint) {
		return providers.AuthKeyResult{}, providers.NewError("sshkey.own_key_protected", false, nil,
			map[string]string{"reason": "protected_fingerprint"})
	}
	if !helperproto.ValidAccount(req.OSUser) {
		return providers.AuthKeyResult{}, refusedRequest("os_user")
	}
	if req.Fingerprint == "" {
		return providers.AuthKeyResult{}, refusedRequest("fingerprint")
	}
	w.mu.Lock()
	p, f := w.begin(FaultPoint{Method: "RemoveAuthorizedKey", Target: target, OSUser: req.OSUser, FilePath: req.FilePath, Fingerprint: req.Fingerprint})
	if f == FaultHang {
		w.record(p, f, false, "")
		w.mu.Unlock()
		return providers.AuthKeyResult{}, hang(ctx)
	}
	defer w.mu.Unlock()
	file := worldFile{target, req.FilePath}
	old, exists := w.files[file]
	step(log, "precheck", providers.StepOK)
	switch f {
	case FaultRefuse:
		w.record(p, f, false, "")
		return providers.AuthKeyResult{}, providers.NewError("ssh.helper_refused", false, nil, map[string]string{"helper_code": "INVALID_ARGUMENT"})
	case FaultUnreachable:
		w.record(p, f, false, "")
		return providers.AuthKeyResult{}, providers.NewError("ssh.unreachable", true, nil, nil)
	case FaultFileChanged:
		step(log, "write", providers.StepStarted)
		step(log, "write", providers.StepFailed)
		w.record(p, f, false, "")
		return providers.AuthKeyResult{}, providers.NewError("ssh.file_changed", true, nil, map[string]string{"attempts": "3"})
	}
	if !exists {
		w.record(p, f, false, "")
		return providers.AuthKeyResult{OldSHA256: helperproto.AbsentSHA256, NewSHA256: helperproto.AbsentSHA256}, nil
	}
	if err := w.checkOwner(file, req.OSUser); err != nil {
		w.record(p, f, false, "")
		return providers.AuthKeyResult{}, err
	}
	for _, l := range parse(old).Lines {
		if l.Kind == linuxssh.LineKey && l.Fingerprint == req.Fingerprint && hasOption(l, "cert-authority") {
			w.record(p, f, false, "")
			return providers.AuthKeyResult{}, providers.NewError("sshkey.not_removable", false, nil, map[string]string{"reason": "cert_authority"})
		}
	}
	next := without(old, req.Fingerprint)
	removed := len(old) - len(next)
	if removed == 0 {
		w.record(p, f, false, "")
		return providers.AuthKeyResult{OldSHA256: digest(old), NewSHA256: digest(old)}, nil
	}
	if parse(next).CountKeys() == 0 {
		if req.OSUser == ConnectionAccount {
			w.record(p, f, false, "")
			return providers.AuthKeyResult{}, providers.NewError("sshkey.own_key_protected", false, nil,
				map[string]string{"reason": "last_key_of_connection_account"})
		}
		if !req.AllowLastRootKey && w.owners[file] == "root" {
			w.record(p, f, false, "")
			return providers.AuthKeyResult{}, providers.NewError("sshkey.last_root_key", false, nil, nil)
		}
	}
	step(log, "write", providers.StepStarted)
	if f == FaultLateWrite {
		w.queueLate(p, func() bool {
			cur := w.files[file]
			after := without(cur, req.Fingerprint)
			if len(after) == len(cur) {
				return false
			}
			w.files[file] = after
			return true
		})
		w.record(p, f, false, "")
		return providers.AuthKeyResult{}, providers.NewError("ssh.timeout", true, nil, nil)
	}
	w.files[file] = next
	res := providers.AuthKeyResult{Changed: true, Removed: removed, OldSHA256: digest(old), NewSHA256: digest(next), Verified: true,
		Backup: "/var/lib/alice-helper/backups/" + req.OperationID.String()}
	w.record(p, f, true, "")
	if f == FaultAfterWrite {
		return res, providers.NewError("ssh.timeout", true, nil, nil)
	}
	step(log, "write", providers.StepOK)
	return res, nil
}

// login decides a test login: accepted when a plain (not cert-authority) line of one of the files
// req.OSUser's login reads holds the offered key. The real sshd also applies from= and the other
// options to Alice's address; the world does not (inject FaultRefuse for that).
func (w *KeyWorld) login(ctx context.Context, target uuid.UUID, req providers.KeyLoginRequest) (providers.KeyLoginResult, error) {
	if req.OSUser == "" || req.Key == nil || !helperproto.ValidAccount(req.OSUser) {
		return providers.KeyLoginResult{}, refusedRequest("os_user")
	}
	s, release, err := req.Key.SSHSigner(ctx)
	if err != nil {
		return providers.KeyLoginResult{}, providers.NewError("internal.unexpected", false, err, nil)
	}
	fp := ssh.FingerprintSHA256(s.PublicKey())
	release()
	w.mu.Lock()
	p, f := w.begin(FaultPoint{Method: "VerifyKeyLogin", Target: target, OSUser: req.OSUser, Fingerprint: fp})
	if f == FaultHang {
		w.record(p, f, false, "")
		w.mu.Unlock()
		return providers.KeyLoginResult{}, hang(ctx)
	}
	defer w.mu.Unlock()
	switch f {
	case FaultRefuse:
		w.record(p, f, false, providers.KeyLoginRefused)
		return providers.KeyLoginResult{Outcome: providers.KeyLoginRefused}, nil
	case FaultUnprovable:
		w.record(p, f, false, providers.KeyLoginUnprovable)
		return providers.KeyLoginResult{Outcome: providers.KeyLoginUnprovable}, nil
	case FaultUnreachable:
		w.record(p, f, false, "")
		return providers.KeyLoginResult{}, providers.NewError("ssh.unreachable", true, nil, nil)
	case FaultAfterWrite, FaultLateWrite:
		w.record(p, f, false, "")
		return providers.KeyLoginResult{}, providers.NewError("ssh.timeout", true, nil, nil)
	}
	out := providers.KeyLoginRefused
files:
	for _, file := range w.users[worldUser{target, req.OSUser}] {
		for _, l := range parse(w.files[worldFile{target, file}]).Lines {
			if l.Kind == linuxssh.LineKey && l.Fingerprint == fp && !hasOption(l, "cert-authority") {
				out = providers.KeyLoginAccepted
				break files
			}
		}
	}
	w.record(p, f, false, out)
	return providers.KeyLoginResult{Outcome: out}, nil
}
