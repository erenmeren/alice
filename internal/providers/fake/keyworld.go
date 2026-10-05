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
)

// KeyWorld models authorized_keys files of several targets (C5). A file is identified by its target
// and path; Put also records which users read it, so a shared file serves all of them (spec §13.3).
type KeyWorld struct {
	mu     sync.Mutex
	files  map[worldFile][]string
	users  map[worldUser][]string // (target, user) -> file paths the user's logins read
	owners map[worldFile]string   // file -> the user first Put for it: the account the helper resolves it to
	events []Event
	fault  func(FaultPoint) Fault
	n      int
	now    func() time.Time
	late   time.Duration
	queued []lateWrite
}

// lateWrite is a change a stalled call lands after it already answered (FaultLateWrite).
type lateWrite struct {
	due   time.Time
	apply func()
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
	N           int    // 1-based index over every Add, Remove and VerifyKeyLogin call of the world
	Method      string // "AddAuthorizedKey" | "RemoveAuthorizedKey" | "VerifyKeyLogin"
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
	// (SetLateDelay, default one minute): a stalled write that finishes after the caller gave up (S3).
	// Login: ssh.timeout.
	FaultLateWrite
)

// Event is one recorded call of the world.
type Event struct {
	FaultPoint
	Fault   Fault
	Changed bool
	Outcome providers.KeyLoginOutcome // logins
}

// SetClock sets the world's clock, which dates FaultLateWrite changes. Without one, a late write
// lands only through FlushLate.
func (w *KeyWorld) SetClock(now func() time.Time) {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.now = now
}

// SetLateDelay sets how long after its call a FaultLateWrite change lands (default one minute).
func (w *KeyWorld) SetLateDelay(d time.Duration) {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.late = d
}

// FlushLate lands every pending late write now.
func (w *KeyWorld) FlushLate() {
	w.mu.Lock()
	defer w.mu.Unlock()
	for _, q := range w.queued {
		q.apply()
	}
	w.queued = nil
}

// landLate lands the late writes that are due; the caller holds the lock.
func (w *KeyWorld) landLate() {
	if w.now == nil || len(w.queued) == 0 {
		return
	}
	now := w.now()
	rest := w.queued[:0]
	for _, q := range w.queued {
		if now.Before(q.due) {
			rest = append(rest, q)
			continue
		}
		q.apply()
	}
	w.queued = rest
}

// queueLate schedules apply for the late delay after now; the caller holds the lock.
func (w *KeyWorld) queueLate(apply func()) {
	d := w.late
	if d == 0 {
		d = time.Minute
	}
	var due time.Time
	if w.now != nil {
		due = w.now().Add(d)
	}
	w.queued = append(w.queued, lateWrite{due: due, apply: apply})
}

// NewKeyWorld returns an empty world without faults.
func NewKeyWorld() *KeyWorld {
	return &KeyWorld{files: map[worldFile][]string{}, users: map[worldUser][]string{}, owners: map[worldFile]string{}}
}

// Put sets a file's lines (verbatim) and records that osUser reads it. The first user put for a file
// is its owner, the account the real helper resolves it to: changes by any other user are refused
// (the real provider's owner rule, S10), while every recorded user's login reads it.
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

// SetFault installs the fault decision (nil: none).
func (w *KeyWorld) SetFault(f func(FaultPoint) Fault) {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.fault = f
}

func lineFingerprint(line string) string {
	pk, _, _, _, err := ssh.ParseAuthorizedKey([]byte(line))
	if err != nil {
		return ""
	}
	return ssh.FingerprintSHA256(pk)
}

func indexOf(lines []string, fp string) int {
	return slices.IndexFunc(lines, func(l string) bool { return fp != "" && lineFingerprint(l) == fp })
}

func digest(lines []string) string {
	sum := sha256.Sum256([]byte(strings.Join(lines, "\n")))
	return hex.EncodeToString(sum[:])
}

// begin numbers the call and asks the fault decision, under the lock.
func (w *KeyWorld) begin(p FaultPoint) (FaultPoint, Fault) {
	w.landLate()
	w.n++
	p.N = w.n
	f := FaultNone
	if w.fault != nil {
		f = w.fault(p)
	}
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

// checkOwner mirrors linuxssh's checkOwner: a file the helper resolved to one account refuses a
// change that names another (a file shared by several users is changed only as its owner).
func (w *KeyWorld) checkOwner(file worldFile, osUser string) error {
	if owner, ok := w.owners[file]; ok && owner != osUser {
		return providers.NewError("ssh.helper_refused", false, nil, map[string]string{"field": "os_user"})
	}
	return nil
}

// list returns every parseable line of the target's files as the accounts that read them see it.
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
			for i, l := range w.files[worldFile{target, file}] {
				pk, comment, opts, _, err := ssh.ParseAuthorizedKey([]byte(l))
				if err != nil {
					continue
				}
				out = append(out, providers.DiscoveredSSHKey{OSUser: u.user, FilePath: file, LineNo: i + 1,
					PublicKey:   strings.TrimSpace(string(ssh.MarshalAuthorizedKey(pk))),
					Fingerprint: ssh.FingerprintSHA256(pk), KeyType: pk.Type(), Comment: comment,
					Options: strings.Join(opts, ",")})
			}
		}
	}
	return out
}

func (w *KeyWorld) add(ctx context.Context, target uuid.UUID, req providers.AuthKeyChange, log providers.StepLogger) (providers.AuthKeyResult, error) {
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
	case FaultLateWrite:
		step(log, "write", providers.StepStarted)
		w.queueLate(func() {
			if cur := w.files[file]; indexOf(cur, fp) < 0 {
				w.files[file] = append(slices.Clone(cur), req.Line)
			}
		})
		w.record(p, f, false, "")
		return providers.AuthKeyResult{}, providers.NewError("ssh.timeout", true, nil, nil)
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
	next := append(slices.Clone(old), req.Line)
	w.files[file] = next
	u := worldUser{target, req.OSUser}
	if !slices.Contains(w.users[u], req.FilePath) {
		w.users[u] = append(w.users[u], req.FilePath)
	}
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
	w.mu.Lock()
	p, f := w.begin(FaultPoint{Method: "RemoveAuthorizedKey", Target: target, OSUser: req.OSUser, FilePath: req.FilePath, Fingerprint: req.Fingerprint})
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
	case FaultLateWrite:
		step(log, "write", providers.StepStarted)
		w.queueLate(func() {
			w.files[file] = slices.DeleteFunc(slices.Clone(w.files[file]), func(l string) bool { return lineFingerprint(l) == req.Fingerprint })
		})
		w.record(p, f, false, "")
		return providers.AuthKeyResult{}, providers.NewError("ssh.timeout", true, nil, nil)
	}
	if err := w.checkOwner(file, req.OSUser); err != nil {
		w.record(p, f, false, "")
		return providers.AuthKeyResult{}, err
	}
	next := slices.DeleteFunc(slices.Clone(old), func(l string) bool { return lineFingerprint(l) == req.Fingerprint })
	removed := len(old) - len(next)
	if removed == 0 {
		w.record(p, f, false, "")
		return providers.AuthKeyResult{OldSHA256: digest(old), NewSHA256: digest(old)}, nil
	}
	step(log, "write", providers.StepStarted)
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

func (w *KeyWorld) login(ctx context.Context, target uuid.UUID, req providers.KeyLoginRequest) (providers.KeyLoginResult, error) {
	if req.OSUser == "" || req.Key == nil {
		return providers.KeyLoginResult{}, providers.NewError("ssh.helper_refused", false, nil, map[string]string{"field": "os_user"})
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
	for _, file := range w.users[worldUser{target, req.OSUser}] {
		if indexOf(w.files[worldFile{target, file}], fp) >= 0 {
			out = providers.KeyLoginAccepted
			break
		}
	}
	w.record(p, f, false, out)
	return providers.KeyLoginResult{Outcome: out}, nil
}
