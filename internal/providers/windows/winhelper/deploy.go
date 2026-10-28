package winhelper

import (
	"context"
	"crypto/sha1" //nolint:gosec // a certificate store's thumbprint is SHA-1
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"reflect"
	"slices"

	"alice/internal/providers/windows/winproto"
)

// Event ids of the Application log (W2 Ruling 13).
const (
	eventDeployed uint32 = 1001
	eventRestored uint32 = 1002
)

func precondition(code, msg string) error {
	return &helperError{exit: winproto.ExitPrecondition, code: code, message: msg}
}

func sum256(b []byte) string {
	s := sha256.Sum256(b)
	return hex.EncodeToString(s[:])
}

func sum1(b []byte) string {
	s := sha1.Sum(b) //nolint:gosec // a thumbprint
	return hex.EncodeToString(s[:])
}

func stepOK(name string) winproto.Step { return winproto.Step{Name: name, Status: winproto.StepOK} }

func stepFailed(name, class string) winproto.Step {
	return winproto.Step{Name: name, Status: winproto.StepFailed, Error: class}
}

// opArg reads the command line of a write subcommand: exactly "--op <operation id>" (Ruling 4).
func opArg(args []string, sub string) (string, error) {
	if len(args) != 2 || args[0] != winproto.ArgOp {
		return "", refused(winproto.CodeUsage, "usage: "+sub+" --op <operation id>")
	}
	if !winproto.ValidOpID(args[1]) {
		return "", refused(winproto.CodeInvalidArgument, "the operation id is not allowed")
	}
	return args[1], nil
}

// lockHelper checks the data directory and takes the helper lock (Ruling 8).
func lockHelper(ctx context.Context, h WriteHost) (func(), error) {
	if err := h.DataDirSafe(); err != nil {
		return nil, failed(winproto.CodeJournalFailed, "the helper's data directory cannot be trusted or written")
	}
	release, err := h.Lock(ctx)
	switch {
	case errors.Is(err, ErrBusy):
		return nil, failed(winproto.CodeBusy, "another certificate change is running on this server")
	case err != nil:
		return nil, failed(winproto.CodeIOError, "the helper lock cannot be taken")
	}
	return release, nil
}

// storeOf is the store a record names (MY for a NULL store name, W0 F2).
func storeOf(b winproto.SSLBinding) string {
	if b.Store == "" {
		return defaultStore
	}
	return b.Store
}

// storeCert reads a certificate of a store: its DER (nil when the store's copy does not decode),
// whether it has a usable key, whether the store holds it. Errors are the host's.
func storeCert(ctx context.Context, h WriteHost, store, sha1Hex string) (der []byte, usable, found bool, err error) {
	if !winproto.ValidSHA1(sha1Hex) {
		return nil, false, false, nil
	}
	c, found, err := h.Certificate(ctx, store, sha1Hex)
	if err != nil || !found {
		return nil, false, false, err
	}
	der, derr := base64.StdEncoding.DecodeString(c.DER)
	if derr != nil {
		der = nil
	}
	return der, c.HasKey && c.KeyProblem == "", true, nil
}

// certError is the refusal for a store read that failed before any change.
func certError(err error) error {
	if errors.Is(err, ErrStore) {
		return failed(winproto.CodeStoreError, "a certificate store could not be opened")
	}
	return failed(winproto.CodeIOError, "a certificate could not be read")
}

// sameRecord reports two records equal in every field (an empty and an absent Extended list alike).
func sameRecord(a, b winproto.SSLBinding) bool {
	if len(a.Extended) == 0 && len(b.Extended) == 0 {
		a.Extended, b.Extended = nil, nil
	}
	return reflect.DeepEqual(a, b)
}

// friendlyName is an imported certificate's friendly name (Ruling 9): "Alice <first SAN> <notAfter
// yyyy-mm-dd> <op8>".
func friendlyName(leaf *x509.Certificate, op string) string {
	name := "certificate"
	switch {
	case len(leaf.DNSNames) > 0:
		name = leaf.DNSNames[0]
	case len(leaf.IPAddresses) > 0:
		name = leaf.IPAddresses[0].String()
	case leaf.Subject.CommonName != "":
		name = leaf.Subject.CommonName
	}
	suffix := " " + leaf.NotAfter.UTC().Format("2006-01-02") + " " + op[:8]
	return "Alice " + cleanValue(name, winproto.MaxText-len("Alice ")-len(suffix)) + suffix
}

// interruptedLatest returns the binding's latest operation when it is another one whose journal says
// writing or restoring, or cannot be decoded ("" otherwise; cmd/alice-helper's rule, m1).
func interruptedLatest(h WriteHost, canonical, op string) (string, error) {
	latest, _, err := latestOp(h, journal{Op: op, Binding: canonical})
	if err != nil || latest == "" || latest == op {
		return "", err
	}
	other, found, err := readJournal(h, latest)
	switch {
	case errors.Is(err, errBadJournal):
		return latest, nil
	case err != nil:
		return "", err
	case found && (other.Phase == winproto.PhaseWriting || other.Phase == winproto.PhaseRestoring):
		return latest, nil
	}
	return "", nil
}

// cmdIISDeploy answers "iis-deploy --op <id>" with a winproto.DeployInput on stdin (design §6.3, W2
// Rulings 4, 8-13). Every refusal comes before gate.enter and changed nothing; after it the answer is
// the operation's phase, recorded in the journal (or OUTCOME_UNKNOWN when even the journal cannot be
// written, settle).
func cmdIISDeploy(ctx context.Context, c *call) (any, error) {
	op, err := opArg(c.args, winproto.SubIISDeploy)
	if err != nil {
		return nil, err
	}
	sec := newSecrets()
	defer sec.clear()
	req, err := parseDeployInput(c.input, sec)
	if err != nil {
		return nil, err
	}
	in, err := checkContent(req.chainPEM, req.keyPEM, sec)
	if err != nil {
		return nil, err
	}
	h := c.host
	release, err := lockHelper(ctx, h)
	if err != nil {
		return nil, err
	}
	defer release()
	if err := point(h, "deploy.locked"); err != nil {
		return nil, err
	}
	switch prior, found, err := readJournal(h, op); {
	case err != nil:
		return nil, failed(winproto.CodeIOError, "the journal of this operation cannot be read")
	case found && prior.Phase == winproto.PhaseFenced:
		return nil, precondition(winproto.CodeFenced, "this deployment was ended by Alice's recovery; it is not carried out")
	case found:
		return nil, precondition(winproto.CodeOperationExists, "this operation was carried out already")
	}
	switch pending, err := interruptedLatest(h, req.canonical, op); {
	case err != nil:
		return nil, failed(winproto.CodeIOError, "the record of the binding's latest operation cannot be read")
	case pending != "":
		return nil, recoveryPending(pending)
	}
	rec, err := readBindingState(h, req.canonical) // read again: latestOp read it, nothing changed it under the lock
	if err != nil {
		return nil, failed(winproto.CodeIOError, "the record of the binding's latest operation cannot be read")
	}
	b, found, err := h.Binding(ctx, req.loc)
	switch {
	case err != nil:
		return nil, failed(winproto.CodeIOError, "the binding could not be read")
	case !found:
		return nil, precondition(winproto.CodeBindingNotFound, "http.sys holds no such binding")
	}
	store := storeOf(b)
	prevDER := []byte(nil)
	if winproto.ValidSHA1(b.CertSHA1) && winproto.ValidStore(store) {
		var err error
		if prevDER, _, _, err = storeCert(ctx, h, store, b.CertSHA1); err != nil {
			return nil, certError(err)
		}
	}
	if prevDER == nil || sum256(prevDER) != req.expect {
		return nil, precondition(winproto.CodeHashMismatch, "the binding names another certificate than expected")
	}
	if !validRecord(b, req.canonical) {
		return nil, failed(winproto.CodeIOError, "the binding cannot be written back as it was read")
	}
	newSHA1, newSHA256 := sum1(in.leaf.Raw), sum256(in.leaf.Raw)
	_, usable, exists, err := storeCert(ctx, h, store, newSHA1)
	switch {
	case err != nil:
		return nil, certError(err)
	case exists && !usable:
		// Re-attaching a key to a certificate someone else put there is not Alice's call (Ruling 9).
		return nil, precondition(winproto.CodeKeyUnusable, "the certificate is in the store without a usable key")
	}
	prevRecord := rec.Op
	if prevRecord == op {
		prevRecord = ""
	}

	wctx, err := c.gate.enter()
	if err != nil {
		return nil, err
	}
	t := &deployTx{ctx: wctx, h: h, j: journal{Op: op, Phase: winproto.PhasePrepared, Binding: req.canonical, Locator: req.loc,
		Previous: cloneRecord(b), PreviousSHA1: b.CertSHA1, PreviousSHA256: req.expect, NewSHA1: newSHA1, NewSHA256: newSHA256,
		Store: store, Intermediates: []certRef{}, AliceImported: !exists, Existed: &exists, PrevRecord: prevRecord, Steps: []winproto.Step{},
		ForbiddenSPKI: req.spki, ForbiddenLeaf: req.leaf}, served: rec.Chain, chain: chainOf(in)}
	return t.run(in, sec)
}

func cloneRecord(b winproto.SSLBinding) winproto.SSLBinding {
	b.Extended = slices.Clone(b.Extended)
	return b
}

// deployTx is an iis-deploy after its gate: every outcome is recorded in its journal.
type deployTx struct {
	ctx    context.Context // the gate's write context
	h      WriteHost
	j      journal
	built  int
	served []string // the binding record's chain: what Alice's last committed bind left served
	chain  []string // this deployment's chain (chainOf)
}

// chainOf is a deployment's chain as the binding record keeps it: the DER SHA-256 of the leaf, then
// of each intermediate in the input's order.
func chainOf(in content) []string {
	out := []string{sum256(in.leaf.Raw)}
	for _, c := range in.intermediates {
		out = append(out, sum256(c.Raw))
	}
	return out
}

func (t *deployTx) answer() winproto.DeployResponse {
	j := t.j
	return winproto.DeployResponse{OK: true, Phase: j.Phase, FailedStep: j.FailedStep, CauseStep: j.CauseStep, Error: j.Error,
		Steps: slices.Clone(j.Steps), NewSHA1: j.NewSHA1, NewSHA256: j.NewSHA256, PreviousSHA1: j.PreviousSHA1,
		PreviousSHA256: j.PreviousSHA256, Store: j.Store, AliceImported: j.AliceImported, BuiltChainLength: t.built,
		CCSRefreshFailed: j.CCS != nil && j.CCS.RefreshFailed, RDPKeyACLLeft: j.RDP != nil && j.RDP.ACLLeft, RDPKeyGranted: j.RDP.granted()}
}

// write writes the journal and passes the point after it.
func (t *deployTx) write(pointName string) error {
	if err := writeJournal(t.h, t.j); err != nil {
		return err
	}
	return point(t.h, pointName)
}

// failUnbound records a step that failed while the record was untouched: the operation ends restored
// (nothing to put back).
func (t *deployTx) failUnbound(step, class string) (any, error) {
	t.j.Steps = append(t.j.Steps, stepFailed(step, class))
	t.j.Phase, t.j.FailedStep, t.j.CauseStep, t.j.Error, t.j.CauseError = winproto.PhaseRestored, step, step, class, class
	if err := writeJournal(t.h, t.j); err != nil {
		return nil, err
	}
	return t.answer(), nil
}

func storeClass(err error) string {
	if errors.Is(err, ErrKeyUnusable) {
		return winproto.ErrKeyUnusable
	}
	return winproto.ErrStore
}

func (t *deployTx) run(in content, sec *secrets) (any, error) {
	h, j := t.h, &t.j
	if err := writeJournal(h, *j); err != nil {
		return nil, err
	}
	// The binding record names this operation from the prepared journal on (a prepared operation
	// changed nothing; latestOp walks through it to prev_record).
	// The served chain is cleared with it (fix round 4): from here on an interruption leaves the
	// next deployment a same-hash write (an intermediate may have been added, or removed by someone).
	if err := writeBindingRecord(h, j.Binding, j.Op); err != nil {
		return nil, err
	}
	if err := point(h, "deploy.prepared"); err != nil {
		return nil, err
	}

	if !t.importChain(in) {
		return t.failUnbound(winproto.StepImportChain, winproto.ErrStore)
	}
	if err := t.write("deploy.import_chain"); err != nil {
		return nil, err
	}

	if class := t.importCertificate(in, sec); class != "" {
		return t.failUnbound(winproto.StepImportCertificate, class)
	}
	sec.clear() // nothing of the key is needed any more
	j.Steps = append(j.Steps, stepOK(winproto.StepImportCertificate))
	if err := t.write("deploy.import_certificate"); err != nil {
		return nil, err
	}
	// The chain the next write makes schannel serve (Ruling 16): leaf included, root excluded.
	if c, found, err := h.Certificate(t.ctx, j.Store, j.NewSHA1); err == nil && found {
		t.built = 1 + len(c.Chain)
	}

	// Ruling 10 (fix round 3): unchanged only when the record names the new certificate, no
	// intermediate was added, and Alice's last committed bind left this very chain served. Otherwise a
	// same-hash write makes schannel build the chain again (its cache, §6.4): after an interrupted
	// deployment that added an intermediate, a binding Alice never wrote, or another chain.
	if j.Previous.CertSHA1 == j.NewSHA1 && len(j.Intermediates) == 0 && slices.Equal(t.served, t.chain) {
		// Nothing was written to the record: the chain it serves is still the one read, so it goes back
		// (before the journal: a kill between leaves a prepared journal whose record keeps it, safe).
		if err := writeBindingState(h, bindingRecord{Binding: j.Binding, Op: j.Op, Chain: t.served}); err != nil {
			return nil, err
		}
		j.Phase = winproto.PhaseUnchanged
		if err := writeJournal(h, *j); err != nil {
			return nil, err
		}
		return t.answer(), nil
	}

	j.Phase = winproto.PhaseWriting
	if err := t.write("deploy.writing"); err != nil {
		return nil, err
	}
	next := cloneRecord(j.Previous)
	next.CertSHA1 = j.NewSHA1 // the store as read: a NULL store is written back NULL
	switch err := h.UpdateBinding(t.ctx, next); {
	case errors.Is(err, ErrKeyUnusable):
		// http.sys's 1312: the record is unchanged, nothing to restore (Ruling 10).
		return t.failUnbound(winproto.StepBind, winproto.ErrKeyUnusable)
	case errors.Is(err, ErrBindingNotFound):
		// The record went away under us: nothing was written and nothing can be put back.
		j.Steps = append(j.Steps, stepFailed(winproto.StepBind, winproto.ErrFileChanged))
		j.Phase, j.FailedStep, j.CauseStep = winproto.PhaseRestoreFailed, winproto.StepBind, winproto.StepBind
		j.Error, j.CauseError = winproto.ErrFileChanged, winproto.ErrFileChanged
		if err := writeJournal(h, *j); err != nil {
			return nil, err
		}
		return t.answer(), nil
	case err != nil:
		// Any other failure may come after part of the record changed (the host's Ex updates
		// follow the base update): restore whatever is not exactly the previous record.
		return t.selfRestore(winproto.StepBind, winproto.ErrIO)
	}
	if err := point(h, "deploy.bound"); err != nil {
		return nil, err
	}
	back, found, err := h.Binding(t.ctx, j.Locator)
	if err != nil || !found || !sameRecord(back, next) {
		return t.selfRestore(winproto.StepBind, winproto.ErrReadBack)
	}
	if err := point(h, "deploy.read_back"); err != nil {
		return nil, err
	}
	j.Steps = append(j.Steps, stepOK(winproto.StepBind))
	j.Phase = winproto.PhaseCommitted
	if err := writeJournal(h, *j); err != nil {
		// The journal must not say writing while the answer says committed: roll back.
		j.Phase = winproto.PhaseWriting
		return t.selfRestore(winproto.StepJournal, winproto.ErrIO)
	}
	// Best effort: without the chain the next deployment of this certificate writes once more.
	_ = writeBindingState(h, bindingRecord{Binding: j.Binding, Op: j.Op, Chain: t.chain})
	if err := point(h, "deploy.committed"); err != nil {
		return nil, err
	}
	h.Event(eventDeployed, eventText(*j, j.PreviousSHA256, j.NewSHA256))
	return t.answer(), nil
}

// importCertificate is the step import_certificate (Ruling 9): an existing copy with a usable key is
// used as is. It answers the failure's class, "" when the store holds the new certificate.
func (t *deployTx) importCertificate(in content, sec *secrets) string {
	h, j := t.h, &t.j
	if !j.AliceImported {
		return ""
	}
	password := sec.keep(NewPFXPassword())
	pfx, err := BuildPFX(in.leaf.Raw, in.pkcs8, password)
	if err != nil {
		return winproto.ErrStore
	}
	sec.keep(pfx)
	sha, existed, err := h.ImportPFX(t.ctx, j.Store, pfx, password, friendlyName(in.leaf, j.Op))
	clear(pfx)
	clear(password)
	if err != nil {
		return storeClass(err)
	}
	if existed {
		// Someone added the certificate after the check (W2's existing-copy race, W3 Ruling 5): the
		// store's copy is theirs, kept as it is and never recorded as Alice's. The "existed" record
		// stays what the check found; alice_imported false says the import was not Alice's.
		j.AliceImported = false
	}
	if sha != j.NewSHA1 {
		// A host that imported something else: record what it answered, so W3's cleanup finds it.
		if c, found, err := h.Certificate(t.ctx, j.Store, sha); err == nil && found && !existed {
			if der, err := base64.StdEncoding.DecodeString(c.DER); err == nil {
				_ = recordImport(h, importEntry{Op: j.Op, Store: j.Store, SHA1: sha, SHA256: sum256(der)})
			}
		}
		return winproto.ErrStore
	}
	if j.AliceImported {
		// Best effort: an entry missing only means W3's cleanup leaves the certificate alone.
		_ = recordImport(h, importEntry{Op: j.Op, Store: j.Store, SHA1: j.NewSHA1, SHA256: j.NewSHA256})
	}
	return ""
}

// importChain is the step import_chain: each intermediate into LocalMachine\CA, never replacing one
// (design §6.3 step 5), those added recorded. It reports false when one could not be added.
func (t *deployTx) importChain(in content) bool {
	for _, c := range in.intermediates {
		added, err := t.h.AddIntermediate(t.ctx, c.Raw)
		if err != nil {
			return false
		}
		if added {
			t.j.Intermediates = append(t.j.Intermediates, certRef{SHA1: sum1(c.Raw), SHA256: sum256(c.Raw)})
		}
	}
	t.j.Steps = append(t.j.Steps, stepOK(winproto.StepImportChain))
	return true
}

// selfRestore records the failed step and puts the previous record back under the guard (Ruling 12).
func (t *deployTx) selfRestore(step, class string) (any, error) {
	j := &t.j
	j.Steps = append(j.Steps, stepFailed(step, class))
	j.FailedStep, j.CauseStep, j.Error, j.CauseError = step, step, class, class
	g := guard{SPKI: j.ForbiddenSPKI, Leaf: j.ForbiddenLeaf}
	kind, err := planRestore(t.ctx, t.h, *j, g)
	if err != nil {
		kind = restoreUnreadable
		if errors.Is(err, ErrStore) {
			kind = restoreStoreError
		}
	}
	res, err := applyRestore(t.ctx, t.h, *j, kind, g)
	if err != nil {
		return nil, err
	}
	t.j = res
	return t.answer(), nil
}

// eventText is an event's text: operation, binding, old and new DER SHA-256, never key material.
func eventText(j journal, from, to string) string {
	return "operation " + j.Op + " binding " + j.Binding + " old " + from + " new " + to
}
