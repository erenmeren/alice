package linuxsshtest

import (
	"bytes"
	"crypto"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"io"
	"path"
	"slices"

	"alice/internal/providers/linuxssh/helperproto"
)

// This file ports the deployment half of cmd/alice-helper (deploy.go, journal.go, cleanup.go) to
// the emulated host: the same order of checks, the same journal writes at the same points, the
// same rollback rules. A comment names the helper function a block mirrors.

const (
	kindCert = "cert"
	kindKey  = "key"

	maxSteps = 64 // the helper's journal limit
	keptHead = 12
)

var (
	errChanged     = errors.New("the file was changed by someone else")
	errCannotWrite = errors.New("the file cannot be written")
	errJournalIO   = errors.New("the journal cannot be written")
	errBadJournal  = errors.New("the journal is not valid")
	errTarget      = errors.New("the file cannot be read")
)

// emuKilled is the panic that unwinds a transaction killed at a point (the helper's errKilled).
type emuKilled struct{}

type fileSnap struct {
	mode         uint32
	owner, group string
}

// emuJournal is the helper's journal (journal.go) without the fields only its sweep uses.
type emuJournal struct {
	op, phase                                    string
	certPath, keyPath                            string
	oldCertSHA, oldKeySHA, newCertSHA, newKeySHA string
	certMeta, keyMeta                            fileSnap
	failedStep, causeStep, errClass              string
	partial                                      bool
	prevRecord                                   string
	steps                                        []helperproto.NginxStep
}

func (j *emuJournal) clone() *emuJournal {
	c := *j
	c.steps = append([]helperproto.NginxStep{}, j.steps...)
	return &c
}

// opDir is an operation directory: its journal (nil before the first one is renamed in) and the
// backups of the old files.
type opDir struct {
	j               *emuJournal
	certBak, keyBak *secretBuf
}

func stagedName(op, kind string) string { return ".alice-" + op + "-" + kind }

func stepOK(name string) helperproto.NginxStep {
	return helperproto.NginxStep{Name: name, Status: "ok"}
}

func stepFailed(name, class string) helperproto.NginxStep {
	return helperproto.NginxStep{Name: name, Status: "failed", Error: class}
}

func trimSteps(steps []helperproto.NginxStep) []helperproto.NginxStep {
	limit := maxSteps - 8
	if len(steps) <= limit {
		return steps
	}
	return append(append([]helperproto.NginxStep{}, steps[:keptHead]...), steps[len(steps)-(limit-keptHead):]...)
}

func deployAnswer(j *emuJournal) helperproto.NginxDeployResponse {
	return helperproto.NginxDeployResponse{OK: true, Phase: j.phase, FailedStep: j.failedStep, CauseStep: j.causeStep, Error: j.errClass,
		Steps: append([]helperproto.NginxStep{}, j.steps...), BackupDir: helperproto.BackupRoot + "/" + j.op}
}

// ---- points, journal, pair records ------------------------------------------------------

// point runs at every named point of a transaction (the helper's s.point): a scheduled change by
// someone else happens, and a scheduled kill unwinds the transaction without any cleanup.
func (h *nginxHost) point(name string) {
	for i := 0; i < len(h.interfere); i++ {
		if f := h.interfere[i]; f.point == name {
			if f.killNginx {
				h.nginxKilled = true
			} else {
				h.setContent(f.path, f.content.bytes())
			}
			h.interfere = slices.Delete(h.interfere, i, i+1)
			i--
		}
	}
	if h.hangupAt == name {
		h.hangupAt, h.hangedUp = "", true
	}
	if h.killAt == name {
		h.killAt = ""
		panic(emuKilled{})
	}
}

// killedResponse is what a killed helper leaves for the client: nothing on stdout and a signal, or
// (KillAtWithExit137) the status 137 of a shell that did not exec it.
func (h *nginxHost) killedResponse() Response {
	if h.killExit137 {
		return Response{Exit: 137}
	}
	return Response{Signal: "KILL"}
}

// killedFrom turns the panic of a kill point into the killed answer and re-panics anything else.
func (h *nginxHost) killedFrom(r any) Response {
	if _, ok := r.(emuKilled); !ok {
		panic(r)
	}
	h.hangedUp = false
	return h.killedResponse()
}

// recoverKill is the deferred form of killedFrom for a command's answer.
func (h *nginxHost) recoverKill(resp *Response) {
	if r := recover(); r != nil {
		*resp = h.killedFrom(r)
	}
}

// consumeFaults ends the faults armed for one transaction (KillAt, KillAtWithExit137, HangupAfter,
// InterfereAt, FailJournalWrite): each applies to the next nginx-deploy, nginx-restore or
// cleanup of an Nginx operation, fired or not, and is gone after it.
func (h *nginxHost) consumeFaults() {
	h.killAt, h.killExit137, h.hangupAt, h.failJournal = "", false, "", ""
	h.interfere = nil
}

// writeJournal replaces the operation's journal (the helper's writeJournal): the new one is staged
// (a kill there leaves the old one), then renamed in.
func (h *nginxHost) writeJournal(op *opDir, j *emuJournal) error {
	if h.failJournal != "" && h.failJournal == j.phase {
		h.failJournal = ""
		return errJournalIO
	}
	h.point("journal " + j.phase + " staged")
	op.j = j.clone()
	h.point("journal " + j.phase + " renamed")
	return nil
}

func (h *nginxHost) pairRecord(j *emuJournal) string {
	return h.records[pairKey(j.certPath, j.keyPath)]
}

func (h *nginxHost) setPairRecord(j *emuJournal, op string) {
	k := pairKey(j.certPath, j.keyPath)
	if op == "" {
		delete(h.records, k)
		return
	}
	h.point("pair record staged")
	h.records[k] = op
	h.point("pair record renamed")
}

const maxRecordChain = 64

// latestOp resolves the pair record to the operation that last actually replaced files (the
// helper's latestOp): an operation whose journal says prepared or unchanged changed nothing.
func (h *nginxHost) latestOp(j *emuJournal) (op string, ok bool) {
	op = h.pairRecord(j)
	seen := map[string]bool{}
	for range maxRecordChain {
		if op == "" || op == j.op || seen[op] {
			return op, !seen[op]
		}
		seen[op] = true
		o := h.ops[op]
		if o == nil || o.j == nil {
			return op, false
		}
		if o.j.phase != helperproto.PhasePrepared && o.j.phase != helperproto.PhaseUnchanged {
			return op, true
		}
		op = o.j.prevRecord
	}
	return op, false
}

// superseded: j is not the operation that last replaced its pair's files, or that cannot be
// established (the helper's superseded).
func (h *nginxHost) superseded(j *emuJournal) bool {
	op, ok := h.latestOp(j)
	return !ok || (op != "" && op != j.op)
}

// releaseRecord hands the record back before a no-op operation is removed (the helper's).
func (h *nginxHost) releaseRecord(j *emuJournal) {
	if j.phase != helperproto.PhasePrepared && j.phase != helperproto.PhaseUnchanged {
		return
	}
	if h.pairRecord(j) == j.op {
		h.setPairRecord(j, j.prevRecord)
	}
}

// ---- files ----------------------------------------------------------------------------

// target is a certificate or key file read through the walk.
type target struct {
	path string
	data []byte
	meta fileSnap
}

// readTarget resolves and reads one file of the pair (the helper's readTarget); the kind of error
// is returned instead of an error value.
func (h *nginxHost) readTarget(p string) (*target, string) {
	switch wp := h.walkProblem(p); {
	case wp == helperproto.FileSpecialFS:
		return nil, "specialfs"
	case wp != "":
		return nil, "other"
	case !certName(path.Base(p)):
		return nil, "other"
	}
	data, ok := h.fileLocked(p)
	switch {
	case !ok:
		return nil, "enoent"
	case h.fileProblem(p) == helperproto.FileNotRegular:
		return nil, "notregular"
	case h.fileProblem(p) == helperproto.FileHardLinked:
		return nil, "unsafe"
	case len(data) > helperproto.MaxCertFileSize:
		return nil, "toolarge"
	}
	m := h.metaOf(p)
	return &target{path: p, data: append([]byte(nil), data...), meta: fileSnap{mode: m.mode & 0o777, owner: m.owner, group: m.group}}, ""
}

// targetResponse maps a readTarget error to the answer (the helper's targetError).
func targetResponse(kind string) Response {
	switch kind {
	case "enoent":
		return refuse(helperproto.ExitPrecondition, helperproto.CodeNotFound)
	case "unsafe":
		return refuse(helperproto.ExitRefused, helperproto.CodeUnsafeFile)
	case "notregular":
		return refuse(helperproto.ExitRefused, helperproto.CodeNotRegularFile)
	case "toolarge":
		return refuse(helperproto.ExitRefused, helperproto.CodeTooLarge)
	}
	return refuse(helperproto.ExitRefused, helperproto.CodePathNotAllowed)
}

func keyMode(old uint32) uint32 {
	if old&0o777 == 0o640 {
		return 0o640
	}
	return 0o600
}

func certMode(old uint32) uint32 { return old & 0o644 }

// replaceFile stages content next to t's file and renames it over the file (the helper's
// replaceFile): it cannot create files in a directory FailWriteIn lists, and refuses when the
// file (or, for the key, also the certificate) no longer holds what was read.
func (h *nginxHost) replaceFile(t *target, content []byte, mode uint32, meta fileSnap, staged string, restoring bool, also func() bool) (bool, error) {
	if h.failWriteDirs[path.Dir(t.path)] || (restoring && h.failRestore[t.path]) {
		return false, errCannotWrite
	}
	h.point("stage " + staged)
	h.point("staged " + staged)
	if cur, ok := h.fileLocked(t.path); !ok || !bytes.Equal(cur, t.data) || (also != nil && !also()) {
		return false, errChanged
	}
	h.setContent(t.path, content)
	m := h.metaOf(t.path)
	m.owner, m.group, m.mode = meta.owner, meta.group, mode
	h.point("renamed " + staged)
	return true, nil
}

// unchangedSince reports that p still holds what t read.
func (h *nginxHost) unchangedSince(t *target) bool {
	cur, ok := h.fileLocked(t.path)
	return ok && bytes.Equal(cur, t.data)
}

const (
	stateOld = iota
	stateNew
)

// fileState is the helper's fileState: stateOld or stateNew, errChanged when the file is missing
// or holds anything else, errTarget when it cannot be read.
func (h *nginxHost) fileState(p, oldSHA, newSHA string) (int, *target, error) {
	t, kind := h.readTarget(p)
	switch {
	case kind == "enoent":
		return 0, nil, errChanged
	case kind != "":
		return 0, nil, errTarget
	}
	switch sum(t.data) {
	case oldSHA:
		return stateOld, t, nil
	case newSHA:
		return stateNew, t, nil
	}
	return 0, nil, errChanged
}

const (
	fileUnknown  = -1
	stateForeign = -2
)

func (h *nginxHost) stateOf(p, oldSHA, newSHA string) int {
	state, _, err := h.fileState(p, oldSHA, newSHA)
	switch {
	case errors.Is(err, errChanged):
		return stateForeign
	case err != nil:
		return fileUnknown
	}
	return state
}

// restorable is the helper's restorable (readKeys true): nginx-restore could still act on a
// restore_failed operation.
func (h *nginxHost) restorable(j *emuJournal) bool {
	if h.superseded(j) {
		return false
	}
	cert := h.stateOf(j.certPath, j.oldCertSHA, j.newCertSHA)
	key := h.stateOf(j.keyPath, j.oldKeySHA, j.newKeySHA)
	if cert == fileUnknown || key == fileUnknown {
		return true
	}
	anyNew := (cert == stateNew && j.newCertSHA != j.oldCertSHA) || (key == stateNew && j.newKeySHA != j.oldKeySHA)
	anyForeign := cert == stateForeign || key == stateForeign
	if j.partial {
		return anyNew
	}
	return anyNew && !anyForeign
}

// keepForRecovery: an operation whose backups nginx-restore may still need (the helper's).
func (h *nginxHost) keepForRecovery(j *emuJournal) bool {
	switch j.phase {
	case helperproto.PhaseWriting, helperproto.PhaseRestoring:
		return !h.superseded(j)
	case helperproto.PhaseRestoreFailed:
		return h.restorable(j)
	}
	return false
}

// ---- nginx -t, reload ---------------------------------------------------------------------

func (h *nginxHost) configTest() (string, error) { return h.testConfig(true) }

// reload is systemctl reload plus is-active (the helper's reload): a failure leaves Nginx serving
// what it served; a success makes it serve the files now on disk (unless NoopReload).
func (h *nginxHost) reload() error {
	h.reloads++ // systemctl: independent of the nginx binary (SetNginxKilled does not touch it)
	if h.failReload > 0 {
		h.failReload--
		return errors.New("reload failed")
	}
	if !h.noopReload {
		if cfg, ok := h.liveConfig(); ok {
			for _, pr := range cfg.pairs() {
				for _, p := range []string{pr.Cert, pr.Key} {
					if c, ok := h.content[p]; ok {
						h.loaded[p] = c
					} else {
						delete(h.loaded, p)
					}
				}
			}
		}
	}
	for port := range h.afterActive { // the reload after the one that switched it on
		delete(h.other, port)
		delete(h.afterActive, port)
	}
	for port, sha := range h.after {
		h.other[port], h.afterActive[port] = sha, true
		delete(h.after, port)
	}
	return nil
}

// ---- restoreOp ------------------------------------------------------------------------------

type restoreFile struct {
	t                *target
	restore, foreign bool
	kind, path       string
	oldSHA, newSHA   string
	meta             fileSnap
	backup           *secretBuf
}

// restoreOp puts the backups back, tests and reloads (the helper's restoreOp, same order, same
// outcomes): a file holding neither content is someone else's; for nginx-restore (partial false)
// nothing is restored then, within the transaction's own rollback (partial true) the files this
// transaction wrote are put back.
func (h *nginxHost) restoreOp(op *opDir, j *emuJournal, partial bool) (*emuJournal, error) {
	j.steps = trimSteps(j.steps)
	partial = partial || j.partial
	failRestore := func(err error) (*emuJournal, error) {
		if !partial && errors.Is(err, errChanged) && j.phase == helperproto.PhaseRestoreFailed && j.errClass == helperproto.RestoreErrFileChanged {
			return j, err
		}
		j.steps = append(j.steps, stepFailed(helperproto.StepRestore, ""))
		j.phase, j.failedStep = helperproto.PhaseRestoreFailed, helperproto.StepRestore
		if errors.Is(err, errChanged) {
			j.errClass = helperproto.RestoreErrFileChanged
		}
		_ = h.writeJournal(op, j)
		return j, err
	}
	files := []*restoreFile{
		{kind: kindCert, path: j.certPath, oldSHA: j.oldCertSHA, newSHA: j.newCertSHA, meta: j.certMeta, backup: op.certBak},
		{kind: kindKey, path: j.keyPath, oldSHA: j.oldKeySHA, newSHA: j.newKeySHA, meta: j.keyMeta, backup: op.keyBak},
	}
	foreign := false
	for _, f := range files {
		state, t, err := h.fileState(f.path, f.oldSHA, f.newSHA)
		switch {
		case errors.Is(err, errChanged) && partial:
			f.foreign, foreign = true, true
			continue
		case err != nil:
			return failRestore(err)
		}
		f.t, f.restore = t, state == stateNew
	}
	if foreign {
		j.partial = true
		if !files[0].restore && !files[1].restore {
			if j.phase == helperproto.PhaseRestoreFailed && j.errClass == helperproto.RestoreErrFileChanged && j.failedStep == j.causeStep {
				return j, errChanged
			}
			j.phase, j.errClass, j.failedStep = helperproto.PhaseRestoreFailed, helperproto.RestoreErrFileChanged, j.causeStep
			_ = h.writeJournal(op, j)
			return j, errChanged
		}
	}
	j.phase = helperproto.PhaseRestoring
	_ = h.writeJournal(op, j)
	for _, f := range files {
		if !f.restore {
			continue
		}
		data := f.backup.bytes()
		var err error
		if f.backup == nil || sum(data) != f.oldSHA {
			err = errBadJournal
		} else {
			_, err = h.replaceFile(f.t, data, f.meta.mode, f.meta, stagedName(j.op, f.kind), true, nil)
		}
		if err != nil {
			return failRestore(err)
		}
	}
	j.steps = append(j.steps, stepOK(helperproto.StepRestore))
	h.point(helperproto.StepRestore)
	if foreign {
		j.phase, j.errClass, j.failedStep = helperproto.PhaseRestoreFailed, helperproto.RestoreErrFileChanged, j.causeStep
		_ = h.writeJournal(op, j)
		return j, nil
	}
	if class, err := h.configTest(); err != nil {
		j.steps = append(j.steps, stepFailed(helperproto.StepRollbackConfigTest, class))
		j.phase, j.failedStep, j.errClass = helperproto.PhaseRestoreFailed, helperproto.StepRollbackConfigTest, class
		_ = h.writeJournal(op, j)
		return j, nil
	}
	j.steps = append(j.steps, stepOK(helperproto.StepRollbackConfigTest))
	h.point(helperproto.StepRollbackConfigTest)
	if err := h.reload(); err != nil {
		j.steps = append(j.steps, stepFailed(helperproto.StepRollbackReload, ""))
		j.phase, j.failedStep = helperproto.PhaseRestoreFailed, helperproto.StepRollbackReload
		_ = h.writeJournal(op, j)
		return j, nil
	}
	j.steps = append(j.steps, stepOK(helperproto.StepRollbackReload))
	h.point(helperproto.StepRollbackReload)
	j.phase, j.failedStep = helperproto.PhaseRestored, j.causeStep
	if j.causeStep == "" {
		j.errClass = ""
	}
	_ = h.writeJournal(op, j)
	return j, nil
}

// fail records the failed step and rolls back within the transaction (the helper's fail).
func (h *nginxHost) fail(op *opDir, j *emuJournal, step, class string) *emuJournal {
	j.steps = append(j.steps, stepFailed(step, class))
	j.failedStep, j.causeStep, j.errClass = step, step, class
	j, _ = h.restoreOp(op, j, true)
	return j
}

// ---- content checks of stdin ------------------------------------------------------------------

// parseDeployInput accepts exactly a JSON object with the two string members cert_pem and
// key_pem, each once, in either order (the helper's strict hand parser; for the output of
// json.Marshal(helperproto.NginxDeployInput) it accepts the same inputs).
func parseDeployInput(raw []byte) (cert, key []byte, ok bool) {
	dec := json.NewDecoder(bytes.NewReader(raw))
	if t, err := dec.Token(); err != nil || t != json.Delim('{') {
		return nil, nil, false
	}
	var gotCert, gotKey bool
	for range 2 {
		kt, err := dec.Token()
		name, isStr := kt.(string)
		if err != nil || !isStr {
			return nil, nil, false
		}
		vt, err := dec.Token()
		val, isStr := vt.(string)
		if err != nil || !isStr {
			return nil, nil, false
		}
		switch {
		case name == "cert_pem" && !gotCert:
			cert, gotCert = []byte(val), true
		case name == "key_pem" && !gotKey:
			key, gotKey = []byte(val), true
		default:
			return nil, nil, false
		}
	}
	if t, err := dec.Token(); err != nil || t != json.Delim('}') {
		return nil, nil, false
	}
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		return nil, nil, false
	}
	return cert, key, true
}

var pemBegin = []byte("-----BEGIN ")

// pemBlocks decodes data as PEM blocks with nothing but white space around them (the helper's).
func pemBlocks(data []byte) ([]*pem.Block, bool) {
	var out []*pem.Block
	rest := data
	for {
		rest = bytes.TrimLeft(rest, " \t\r\n")
		if len(rest) == 0 {
			return out, true
		}
		if !bytes.HasPrefix(rest, pemBegin) {
			return out, false
		}
		b, next := pem.Decode(rest)
		if b == nil || bytes.Count(rest[:len(rest)-len(next)], pemBegin) != 1 {
			return out, false
		}
		out = append(out, b)
		rest = next
	}
}

// goodContent is the helper's checkDeployContent: a certificate chain (leaf first) and the
// unencrypted private key of its leaf.
func goodContent(certPEM, keyPEM []byte) bool {
	certs, ok := pemBlocks(certPEM)
	if !ok || len(certs) == 0 {
		return false
	}
	var leaf *x509.Certificate
	for i, b := range certs {
		if b.Type != "CERTIFICATE" || len(b.Headers) != 0 {
			return false
		}
		c, err := x509.ParseCertificate(b.Bytes)
		if err != nil {
			return false
		}
		if i == 0 {
			leaf = c
		}
	}
	keys, ok := pemBlocks(keyPEM)
	if !ok || len(keys) != 1 || len(keys[0].Headers) != 0 {
		return false
	}
	var (
		priv any
		err  error
	)
	switch keys[0].Type {
	case "PRIVATE KEY":
		priv, err = x509.ParsePKCS8PrivateKey(keys[0].Bytes)
	case "RSA PRIVATE KEY":
		priv, err = x509.ParsePKCS1PrivateKey(keys[0].Bytes)
	case "EC PRIVATE KEY":
		priv, err = x509.ParseECPrivateKey(keys[0].Bytes)
	default:
		return false
	}
	if err != nil {
		return false
	}
	signer, ok := priv.(crypto.Signer)
	if !ok {
		return false
	}
	pub, ok := signer.Public().(interface{ Equal(crypto.PublicKey) bool })
	return ok && pub.Equal(leaf.PublicKey)
}

// ---- nginx-deploy -------------------------------------------------------------------------

// nginxDeploy answers nginx-deploy (the helper's cmdNginxDeploy and deploy): every answer before the
// key file is replaced is a refusal with nothing changed; from the first rename on the answer is
// the operation's outcome. A killed helper prints nothing.
func (e *Emulator) nginxDeploy(args []string, stdin []byte) (resp Response) {
	e.mu.Lock()
	defer e.mu.Unlock()
	h := e.nginx()
	h.stdins = append(h.stdins, newSecret(stdin))
	defer h.consumeFaults()
	defer h.recoverKill(&resp)
	h.hangedUp = false
	resp = h.deployCommand(args, stdin)
	if h.hangedUp {
		h.hangedUp = false
		return Response{Hangup: true}
	}
	return resp
}

func (h *nginxHost) deployCommand(args []string, stdin []byte) Response {
	if len(args) != 10 || args[0] != "--op" || args[2] != "--cert" || args[4] != "--key" ||
		args[6] != "--expect-cert-sha256" || args[8] != "--content-sha256" {
		return refuse(helperproto.ExitRefused, helperproto.CodeUsage)
	}
	op, certPath, keyPath, expect, want := args[1], args[3], args[5], args[7], args[9]
	if !helperproto.ValidOpID(op) || !helperproto.ValidPath(certPath) || !helperproto.ValidPath(keyPath) ||
		certPath == "/" || keyPath == "/" || certPath == keyPath || !helperproto.ValidSHA256(expect) || expect == helperproto.AbsentSHA256 ||
		!helperproto.ValidSHA256(want) || want == helperproto.AbsentSHA256 {
		return refuse(helperproto.ExitRefused, helperproto.CodeInvalidArgument)
	}
	if h.locked {
		return refuse(helperproto.ExitFailed, helperproto.CodeBusy)
	}
	switch {
	case len(stdin) > helperproto.MaxDeployInput:
		return refuse(helperproto.ExitRefused, helperproto.CodeTooLarge)
	case sum(stdin) != want:
		return refuse(helperproto.ExitPrecondition, helperproto.CodeContentMismatch)
	}
	cert, key, ok := parseDeployInput(stdin)
	switch {
	case !ok:
		return refuse(helperproto.ExitRefused, helperproto.CodeBadContent)
	case len(cert) > helperproto.MaxCertFileSize || len(key) > helperproto.MaxCertFileSize:
		return refuse(helperproto.ExitRefused, helperproto.CodeTooLarge)
	case !goodContent(cert, key):
		return refuse(helperproto.ExitRefused, helperproto.CodeBadContent)
	}
	return h.deploy(op, certPath, keyPath, expect, cert, key)
}

// opCount is the number of operation directories that hold a journal.
func (h *nginxHost) opCount() int {
	n := 0
	for _, o := range h.ops {
		if o.j != nil {
			n++
		}
	}
	return n
}

// newOpDir creates the directory of a new operation unless the cap is reached.
func (h *nginxHost) newOpDir(op string) (*opDir, *Response) {
	if h.opCount() >= h.opsCap() {
		r := refuse(helperproto.ExitPrecondition, helperproto.CodeNoSpace)
		return nil, &r
	}
	o := &opDir{}
	h.ops[op] = o
	return o, nil
}

func (h *nginxHost) deploy(opID, certPath, keyPath, expect string, newCert, newKey []byte) Response {
	h.deploys++
	newCertSHA, newKeySHA := sum(newCert), sum(newKey)
	var (
		dir   = h.ops[opID]
		prior *emuJournal
	)
	if dir != nil && dir.j != nil {
		j := dir.j.clone()
		if j.certPath != certPath || j.keyPath != keyPath || j.newCertSHA != newCertSHA || j.newKeySHA != newKeySHA {
			return refuse(helperproto.ExitRefused, helperproto.CodeInvalidArgument)
		}
		switch j.phase {
		case helperproto.PhaseWriting, helperproto.PhaseRestoring:
			if h.superseded(j) {
				return refuse(helperproto.ExitPrecondition, helperproto.CodeSuperseded)
			}
			j, _ = h.restoreOp(dir, j, false)
			return answer(deployAnswer(j))
		case helperproto.PhasePrepared:
			prior = j
		default:
			return answer(deployAnswer(j))
		}
	}

	cfg, meta, err := h.nginxConfig()
	switch {
	case errors.Is(err, errNginxMissing):
		return refuse(helperproto.ExitPrecondition, helperproto.CodeNginxNotFound)
	case err != nil:
		return refuse(helperproto.ExitFailed, helperproto.CodeIOError)
	case !meta.valid:
		return refuse(helperproto.ExitPrecondition, helperproto.CodeConfigInvalid)
	case !cfg.HasPair(certPath, keyPath):
		return refuse(helperproto.ExitPrecondition, helperproto.CodeConfigChanged)
	}
	cert, kind := h.readTarget(certPath)
	if kind != "" {
		return targetResponse(kind)
	}
	key, kind := h.readTarget(keyPath)
	if kind != "" {
		return targetResponse(kind)
	}
	if sum(cert.data) != expect {
		return refuse(helperproto.ExitPrecondition, helperproto.CodeHashMismatch)
	}
	j := &emuJournal{op: opID, phase: helperproto.PhasePrepared, certPath: certPath, keyPath: keyPath,
		oldCertSHA: sum(cert.data), oldKeySHA: sum(key.data), newCertSHA: newCertSHA, newKeySHA: newKeySHA,
		certMeta: cert.meta, keyMeta: key.meta, steps: []helperproto.NginxStep{}}
	rec := h.pairRecord(j)
	j.prevRecord = rec
	if prior != nil && rec == opID {
		j.prevRecord = prior.prevRecord
	}
	if bytes.Equal(cert.data, newCert) && bytes.Equal(key.data, newKey) {
		// "Same cert already deployed": no write, no reload.
		j.phase = helperproto.PhaseUnchanged
		if dir == nil {
			var r *Response
			if dir, r = h.newOpDir(opID); r != nil {
				return *r
			}
		}
		_ = h.writeJournal(dir, j)
		return answer(deployAnswer(j))
	}
	need := int64(len(newCert)+len(newKey)) + helperproto.MinFreeBytes
	if h.free() < need {
		return refuse(helperproto.ExitPrecondition, helperproto.CodeNoSpace)
	}
	created := dir == nil
	if created {
		var r *Response
		if dir, r = h.newOpDir(opID); r != nil {
			return *r
		}
	}
	refuseDrop := func(resp Response) Response {
		if created {
			delete(h.ops, opID)
		}
		return resp
	}
	if h.free() < int64(len(cert.data)+len(key.data))+helperproto.MinFreeBytes {
		return refuseDrop(refuse(helperproto.ExitPrecondition, helperproto.CodeNoSpace))
	}

	// 1. The journal, then the backups (nothing is replaced yet: a failure is a refusal).
	if err := h.writeJournal(dir, j); err != nil {
		return refuseDrop(refuse(helperproto.ExitFailed, helperproto.CodeIOError))
	}
	dir.certBak = newSecret(cert.data)
	h.point("backup " + kindCert)
	dir.keyBak = newSecret(key.data)
	h.point("backup " + kindKey)
	j.steps = append(j.steps, stepOK(helperproto.StepBackup))
	h.point(helperproto.StepBackup)

	// 2. This operation becomes the pair's latest.
	h.setPairRecord(j, opID)
	back := func(resp Response, steps ...helperproto.NginxStep) Response {
		h.setPairRecord(j, j.prevRecord)
		if created {
			delete(h.ops, opID)
			return resp
		}
		b := j.clone()
		b.phase = helperproto.PhasePrepared
		b.steps = append(b.steps, steps...)
		_ = h.writeJournal(dir, b)
		return resp
	}

	j.phase = helperproto.PhaseWriting
	if err := h.writeJournal(dir, j); err != nil {
		return back(refuse(helperproto.ExitFailed, helperproto.CodeIOError))
	}

	// 3. The key, then the certificate.
	renamed, err := h.replaceFile(key, newKey, keyMode(j.keyMeta.mode), j.keyMeta, stagedName(opID, kindKey), false,
		func() bool { return h.unchangedSince(cert) })
	if err != nil && !renamed {
		resp := refuse(helperproto.ExitFailed, helperproto.CodeIOError)
		if errors.Is(err, errChanged) {
			resp = refuse(helperproto.ExitPrecondition, helperproto.CodeHashMismatch)
		}
		return back(resp, stepFailed(helperproto.StepWriteKey, ""))
	}
	j.steps = append(j.steps, stepOK(helperproto.StepWriteKey))
	h.point(helperproto.StepWriteKey)
	if _, err := h.replaceFile(cert, newCert, certMode(j.certMeta.mode), j.certMeta, stagedName(opID, kindCert), false, nil); err != nil {
		return answer(deployAnswer(h.fail(dir, j, helperproto.StepWriteCert, "")))
	}
	j.steps = append(j.steps, stepOK(helperproto.StepWriteCert))
	h.point(helperproto.StepWriteCert)

	// 4. nginx -t.
	if class, err := h.configTest(); err != nil {
		return answer(deployAnswer(h.fail(dir, j, helperproto.StepConfigTest, class)))
	}
	j.steps = append(j.steps, stepOK(helperproto.StepConfigTest))
	h.point(helperproto.StepConfigTest)

	// 5. Reload and is-active.
	if err := h.reload(); err != nil {
		return answer(deployAnswer(h.fail(dir, j, helperproto.StepReload, "")))
	}
	j.steps = append(j.steps, stepOK(helperproto.StepReload))
	h.point(helperproto.StepReload)
	j.phase = helperproto.PhaseCommitted
	if err := h.writeJournal(dir, j); err != nil {
		j.phase = helperproto.PhaseWriting
		return answer(deployAnswer(h.fail(dir, j, helperproto.StepJournal, "")))
	}
	return answer(deployAnswer(j))
}

// ---- nginx-restore, nginx-status ---------------------------------------------------------------

func (e *Emulator) nginxRestore(args []string) (resp Response) {
	if len(args) != 2 || args[0] != "--op" {
		return refuse(helperproto.ExitRefused, helperproto.CodeUsage)
	}
	if !helperproto.ValidOpID(args[1]) {
		return refuse(helperproto.ExitRefused, helperproto.CodeInvalidArgument)
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	h := e.nginx()
	defer h.consumeFaults()
	defer h.recoverKill(&resp)
	op := args[1]
	if h.locked {
		return refuse(helperproto.ExitFailed, helperproto.CodeBusy)
	}
	dir := h.ops[op]
	if dir == nil || dir.j == nil {
		return refuse(helperproto.ExitPrecondition, helperproto.CodeUnknownOp)
	}
	j := dir.j.clone()
	switch j.phase {
	case helperproto.PhasePrepared, helperproto.PhaseUnchanged, helperproto.PhaseRestored:
		return answer(helperproto.NginxRestoreResponse{OK: true, Phase: j.phase, FailedStep: j.failedStep, CauseStep: j.causeStep,
			Error: j.errClass, Steps: []helperproto.NginxStep{}})
	}
	if h.superseded(j) {
		return refuse(helperproto.ExitPrecondition, helperproto.CodeSuperseded)
	}
	j.steps = trimSteps(j.steps)
	before := len(j.steps)
	j, err := h.restoreOp(dir, j, false)
	if errors.Is(err, errChanged) {
		return refuse(helperproto.ExitPrecondition, helperproto.CodeHashMismatch)
	}
	return answer(helperproto.NginxRestoreResponse{OK: true, Phase: j.phase, FailedStep: j.failedStep, CauseStep: j.causeStep, Error: j.errClass,
		Steps: append([]helperproto.NginxStep{}, j.steps[min(before, len(j.steps)):]...)})
}

func (e *Emulator) nginxStatus(args []string) Response {
	if len(args) != 2 || args[0] != "--op" {
		return refuse(helperproto.ExitRefused, helperproto.CodeUsage)
	}
	op := args[1]
	if !helperproto.ValidOpID(op) {
		return refuse(helperproto.ExitRefused, helperproto.CodeInvalidArgument)
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	h := e.nginx()
	resp := helperproto.NginxStatusResponse{OK: true, Phase: helperproto.PhaseNone, Active: h.locked, BackupDir: helperproto.BackupRoot + "/" + op}
	dir := h.ops[op]
	if dir == nil || dir.j == nil {
		return answer(resp)
	}
	j := dir.j
	resp.Phase, resp.NewCertSHA256 = j.phase, j.newCertSHA
	resp.FailedStep, resp.CauseStep, resp.Error = j.failedStep, j.causeStep, j.errClass
	if t, kind := h.readTarget(j.certPath); kind == "" {
		resp.CurrentCertSHA256 = sum(t.data)
	}
	return answer(resp)
}

// cleanupOp is cleanup of an Nginx operation (the helper's cmdCleanup under the Nginx lock): BUSY
// while the lock is held, or while the operation is kept for recovery. ok is false for an
// operation the Nginx model does not know (the authorized_keys cleanup answers). The caller holds
// e.mu.
func (h *nginxHost) cleanupOp(op string) (resp Response, known bool) {
	dir := h.ops[op]
	if dir == nil {
		return Response{}, false
	}
	defer h.consumeFaults()
	defer func() {
		if r := recover(); r != nil {
			resp, known = h.killedFrom(r), true
		}
	}()
	if h.locked {
		return refuse(helperproto.ExitFailed, helperproto.CodeBusy), true
	}
	if dir.j != nil {
		if h.keepForRecovery(dir.j) {
			return refuse(helperproto.ExitFailed, helperproto.CodeBusy), true
		}
		h.releaseRecord(dir.j)
	}
	delete(h.ops, op)
	return answer(helperproto.CleanupResponse{OK: true, Removed: 1}), true
}
