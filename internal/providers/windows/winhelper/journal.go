package winhelper

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/netip"
	"reflect"
	"slices"

	"alice/internal/providers/windows/winproto"
)

// errBadJournal: a state file that cannot be decoded or does not describe what its name says.
var errBadJournal = errors.New("winhelper: the journal is not valid")

// State file names under winproto.DataDir (WriteHost.ReadState and WriteState).
const (
	journalDir  = "journal/"
	bindingsDir = "bindings/"
	importsName = "imports.json"

	// MaxStateBytes bounds a state file the helper reads: a journal's previous record carries up to
	// MaxExtendedParams parameters of MaxExtendedBytes (base64), the import inventory maxImports entries.
	MaxStateBytes = 512 << 10
	// maxSteps bounds the steps a journal keeps (its validation refuses more): repeated restores of one
	// operation keep its deployment's steps and its latest attempts (trimSteps), as on Linux.
	maxSteps = 64
	// keptHead is how many of the first steps (the deployment's own) trimSteps never drops.
	keptHead = 12
	// maxImports bounds the import inventory; the oldest entries go first (W3's cleanup then leaves
	// those certificates alone, the safe side).
	maxImports = 1024
)

// trimSteps leaves room for one more restore (a few steps) under maxSteps: it keeps the first keptHead
// steps and the most recent ones.
func trimSteps(steps []winproto.Step) []winproto.Step {
	limit := maxSteps - 8
	if len(steps) <= limit {
		return steps
	}
	return append(append([]winproto.Step{}, steps[:keptHead]...), steps[len(steps)-(limit-keptHead):]...)
}

// certRef names a certificate by its store thumbprint and its DER SHA-256 (never its DER).
type certRef struct {
	SHA1   string `json:"sha1"`
	SHA256 string `json:"sha256"`
}

// journal is the record of one iis-deploy operation, journal/<op>.json (W2 Ruling 8): the state machine
// of cmd/alice-helper/journal.go with Windows fields. iis-status and iis-restore read it after any
// interruption. It holds the binding, the full previous record (base and Extended, written back byte
// for byte by a restore), hashes, the store and the guard's lists, never key material.
type journal struct {
	Op      string           `json:"op"`
	Phase   string           `json:"phase"`
	Binding string           `json:"binding"` // the locator's canonical text
	Locator winproto.Locator `json:"locator"`
	// Previous is the whole record as read before the change.
	Previous       winproto.SSLBinding `json:"previous"`
	PreviousSHA1   string              `json:"previous_sha1"`
	PreviousSHA256 string              `json:"previous_sha256"`
	NewSHA1        string              `json:"new_sha1"`
	NewSHA256      string              `json:"new_sha256"`
	// Store is the store the record names (MY for a NULL store name): both certificates are in it.
	Store string `json:"store"`
	// Intermediates are the certificates this operation added to LocalMachine\CA (never removed).
	Intermediates []certRef `json:"intermediates_added"`
	// AliceImported is false when the new certificate was in the store with a usable key already.
	AliceImported bool   `json:"alice_imported"`
	FailedStep    string `json:"failed_step"`
	CauseStep     string `json:"cause_step"`
	Error         string `json:"error"`
	// PrevRecord is the binding record (latest operation) before this operation took it over.
	PrevRecord string          `json:"prev_record"`
	Steps      []winproto.Step `json:"steps"`
	// ForbiddenSPKI and ForbiddenLeaf are the rollback guard iis-deploy received (R48): no restore of
	// this operation puts back a certificate they list.
	ForbiddenSPKI []string `json:"forbidden_spki_sha256"`
	ForbiddenLeaf []string `json:"forbidden_leaf_sha256"`
}

var journalPhases = []string{winproto.PhasePrepared, winproto.PhaseWriting, winproto.PhaseCommitted, winproto.PhaseUnchanged,
	winproto.PhaseRestoring, winproto.PhaseRestored, winproto.PhaseRestoreFailed, winproto.PhaseRestoreForbidden}

var stepNames = []string{winproto.StepImportChain, winproto.StepImportCertificate, winproto.StepBind, winproto.StepJournal, winproto.StepRestore}

var errorClasses = []string{winproto.ErrKeyUnusable, winproto.ErrReadBack, winproto.ErrStore, winproto.ErrFileChanged,
	winproto.ErrForbidden, winproto.ErrBackupMissing}

// validSHA256 reports 64 lower-case hex digits (helperproto's absent marker is not a hash here).
func validSHA256(s string) bool {
	if len(s) != 64 {
		return false
	}
	_, err := hex.DecodeString(s)
	return err == nil && s == asciiLower(s)
}

func validStep(s winproto.Step) bool {
	return slices.Contains(stepNames, s.Name) && (s.Status == winproto.StepOK || s.Status == winproto.StepFailed) &&
		(s.Error == "" || slices.Contains(errorClasses, s.Error))
}

// validRecord reports a previous record the journal may hold for the binding with canonical text
// canonical: the record's own key (type, IP or host, port; the host folded, the IP in canonical form)
// names that binding, so a restore that writes it back whole targets the same record; it names a valid
// SHA-1 in a valid (or NULL) store, its texts and Extended within the bounds.
func validRecord(b winproto.SSLBinding, canonical string) bool {
	for _, s := range []string{b.IP, b.Host, b.AppID, b.CTLIdentifier, b.CTLStore} {
		if len(s) > winproto.MaxText {
			return false
		}
	}
	return recordCanonical(b) == canonical && winproto.ValidSHA1(b.CertSHA1) &&
		(b.Store == "" || winproto.ValidStore(b.Store)) && winproto.ValidExtended(b.Extended)
}

// recordCanonical is the canonical text of an http.sys record as the host read it ("" when it has
// none: ccs, an unparsable IP, a host Alice does not deploy to).
func recordCanonical(b winproto.SSLBinding) string {
	app, _ := winproto.CanonicalAppID(b.AppID)
	l := winproto.Locator{Type: b.Type, Host: asciiLower(b.Host), Port: b.Port, AppID: app}
	if b.IP != "" {
		ip, err := netip.ParseAddr(b.IP)
		if err != nil {
			return ""
		}
		l.IP = ip.Unmap().String()
	}
	c, ok := l.Canonical()
	if !ok {
		return ""
	}
	return c
}

// valid reports a journal that describes operation op and that the helper may act on. A fence's
// tombstone (PhaseFenced) carries nothing but its operation and the binding record it may have handed
// back (Linux's rule).
func (j journal) valid(op string) bool {
	if !winproto.ValidOpID(op) || j.Op != op || (j.PrevRecord != "" && (!winproto.ValidOpID(j.PrevRecord) || j.PrevRecord == op)) {
		return false
	}
	if j.Phase == winproto.PhaseFenced {
		return reflect.DeepEqual(j, journal{Op: j.Op, Phase: j.Phase, PrevRecord: j.PrevRecord})
	}
	canonical, ok := j.Locator.Canonical()
	if !ok || canonical != j.Binding || !slices.Contains(journalPhases, j.Phase) || len(j.Steps) > maxSteps ||
		len(j.Intermediates) > winproto.MaxChainCerts {
		return false
	}
	if !validRecord(j.Previous, j.Binding) || j.Previous.CertSHA1 != j.PreviousSHA1 || !winproto.ValidSHA1(j.NewSHA1) ||
		!validSHA256(j.PreviousSHA256) || !validSHA256(j.NewSHA256) || !winproto.ValidStore(j.Store) {
		return false
	}
	for _, c := range j.Intermediates {
		if !winproto.ValidSHA1(c.SHA1) || !validSHA256(c.SHA256) {
			return false
		}
	}
	for _, s := range j.Steps {
		if !validStep(s) {
			return false
		}
	}
	for _, s := range []string{j.FailedStep, j.CauseStep} {
		if s != "" && !slices.Contains(stepNames, s) {
			return false
		}
	}
	return (j.Error == "" || slices.Contains(errorClasses, j.Error)) &&
		winproto.ValidForbidden(j.ForbiddenSPKI) && winproto.ValidForbidden(j.ForbiddenLeaf)
}

func journalName(op string) string { return journalDir + op + ".json" }

// decodeState decodes one bounded state file strictly: one JSON value, no unknown member.
func decodeState(data []byte, v any) error {
	if len(data) > MaxStateBytes {
		return errBadJournal
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil || dec.More() {
		return errBadJournal
	}
	return nil
}

// readJournal reads the journal of operation op; found is false when there is none. A journal that
// does not decode or is not valid for op is errBadJournal; a read failure is returned as it is.
func readJournal(h WriteHost, op string) (j journal, found bool, err error) {
	if !winproto.ValidOpID(op) {
		return j, false, errBadJournal
	}
	data, found, err := h.ReadState(journalName(op))
	if err != nil || !found {
		return j, false, err
	}
	if err := decodeState(data, &j); err != nil || !j.valid(op) {
		return journal{}, false, errBadJournal
	}
	return j, true, nil
}

// writeJournal replaces the journal durably (WriteState). A journal readJournal would refuse is never
// written: errBadJournal, and the previous journal stays.
func writeJournal(h WriteHost, j journal) error {
	if j.Steps == nil && j.Phase != winproto.PhaseFenced {
		j.Steps = []winproto.Step{}
	}
	if !j.valid(j.Op) {
		return errBadJournal
	}
	raw, err := json.Marshal(j)
	if err != nil {
		return err
	}
	return h.WriteState(journalName(j.Op), raw)
}

// bindingRecord is bindings/<hex SHA-256 of the canonical text>.json: the operation that last started
// changing the binding (Op "" when none). iis-restore rolls back only that operation; a record outlives
// every journal it makes unrestorable.
type bindingRecord struct {
	Binding string `json:"binding"`
	Op      string `json:"op"`
}

// bindingRecordName is a binding's record file name.
func bindingRecordName(canonical string) string {
	sum := sha256.Sum256([]byte(canonical))
	return bindingsDir + hex.EncodeToString(sum[:]) + ".json"
}

// readBindingRecord returns the operation recorded for the binding ("" when none). A record that does
// not decode, names another binding or an invalid operation is errBadJournal.
func readBindingRecord(h WriteHost, canonical string) (string, error) {
	data, found, err := h.ReadState(bindingRecordName(canonical))
	if err != nil || !found {
		return "", err
	}
	var r bindingRecord
	if err := decodeState(data, &r); err != nil || r.Binding != canonical || (r.Op != "" && !winproto.ValidOpID(r.Op)) {
		return "", errBadJournal
	}
	return r.Op, nil
}

// writeBindingRecord records op for the binding (op "" clears it), durably.
func writeBindingRecord(h WriteHost, canonical, op string) error {
	if op != "" && !winproto.ValidOpID(op) {
		return errBadJournal
	}
	raw, err := json.Marshal(bindingRecord{Binding: canonical, Op: op})
	if err != nil {
		return err
	}
	return h.WriteState(bindingRecordName(canonical), raw)
}

// maxRecordChain bounds the walk from a binding record through operations that changed nothing.
const maxRecordChain = 64

// changedNothing: a journal in this phase never changed the record.
func changedNothing(phase string) bool {
	return phase == winproto.PhasePrepared || phase == winproto.PhaseUnchanged || phase == winproto.PhaseFenced
}

// latestOp resolves j's binding record to the operation that last actually changed the record: an
// operation whose journal says prepared or unchanged, or a fence's tombstone, changed nothing, so the
// walk falls through to its prev_record. ok is false when that cannot be decided (a record naming an
// operation without a journal, an unreadable journal, a loop, a chain longer than maxRecordChain): the
// caller then treats every other operation as superseded. op "" with ok: no operation ever changed it.
func latestOp(h WriteHost, j journal) (op string, ok bool, err error) {
	op, err = readBindingRecord(h, j.Binding)
	if err != nil {
		return "", false, err
	}
	seen := map[string]bool{}
	for range maxRecordChain {
		if op == "" || op == j.Op || seen[op] {
			return op, !seen[op], nil
		}
		seen[op] = true
		other, found, err := readJournal(h, op)
		if err != nil || !found {
			return op, false, nil
		}
		if !changedNothing(other.Phase) {
			return op, true, nil
		}
		op = other.PrevRecord
	}
	return op, false, nil
}

// superseded reports that j is not the operation that last actually changed its binding (or that this
// cannot be established): iis-restore of it is SUPERSEDED.
func superseded(h WriteHost, j journal) (bool, error) {
	op, ok, err := latestOp(h, j)
	if err != nil {
		return false, err
	}
	return !ok || (op != "" && op != j.Op), nil
}

// handBack gives the binding record back to j's prev_record when it still names j (a fence of a
// prepared operation, which changed nothing). A tombstone has no binding and nothing to hand back.
func handBack(h WriteHost, j journal) error {
	if j.Binding == "" || !changedNothing(j.Phase) {
		return nil // an operation that changed the record keeps it (Linux's releaseRecord)
	}
	rec, err := readBindingRecord(h, j.Binding)
	if err != nil {
		return err
	}
	if rec != j.Op {
		return nil
	}
	return writeBindingRecord(h, j.Binding, j.PrevRecord)
}

// recoveryPending is the refusal of iis-deploy on a binding whose latest operation is interrupted
// (writing, restoring or unreadable): exit 3, nothing changed, PendingOp names it.
func recoveryPending(op string) error {
	return &helperError{exit: winproto.ExitPrecondition, code: winproto.CodeRecoveryPending,
		message: "an interrupted operation on this binding must be recovered first", pendingOp: op}
}

// importEntry is one certificate Alice imported (imports.json; W3's cleanup reads it).
type importEntry struct {
	Op     string `json:"op"`
	Store  string `json:"store"`
	SHA1   string `json:"sha1"`
	SHA256 string `json:"sha256"`
}

type importsFile struct {
	Imports []importEntry `json:"imports"`
}

func (e importEntry) valid() bool {
	return winproto.ValidOpID(e.Op) && winproto.ValidStore(e.Store) && winproto.ValidSHA1(e.SHA1) && validSHA256(e.SHA256)
}

// readImports reads the import inventory (empty when there is none).
func readImports(h WriteHost) (importsFile, error) {
	var f importsFile
	data, found, err := h.ReadState(importsName)
	if err != nil || !found {
		return importsFile{Imports: []importEntry{}}, err
	}
	if err := decodeState(data, &f); err != nil || len(f.Imports) > maxImports {
		return importsFile{}, errBadJournal
	}
	for _, e := range f.Imports {
		if !e.valid() {
			return importsFile{}, errBadJournal
		}
	}
	return f, nil
}

// recordImport adds a certificate to the import inventory once; past maxImports the oldest go.
func recordImport(h WriteHost, e importEntry) error {
	if !e.valid() {
		return errBadJournal
	}
	f, err := readImports(h)
	if err != nil {
		return err
	}
	if slices.Contains(f.Imports, e) {
		return nil
	}
	f.Imports = append(f.Imports, e)
	if len(f.Imports) > maxImports {
		f.Imports = slices.Clone(f.Imports[len(f.Imports)-maxImports:])
	}
	raw, err := json.Marshal(f)
	if err != nil {
		return err
	}
	return h.WriteState(importsName, raw)
}
