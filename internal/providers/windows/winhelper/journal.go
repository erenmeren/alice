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
	"strings"
	"time"

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
	// AliceImported is false when the new certificate was in the store with a usable key already, or
	// when ImportPFX met a copy someone added after that check (W3 Ruling 5).
	AliceImported bool `json:"alice_imported"`
	// Existed is the "existed" record (W3 Ruling 5), written with the prepared journal before any
	// import: true when the store held the new certificate with a usable key. nil only in a journal a
	// W2 helper wrote, which never makes a certificate count as Alice's.
	Existed    *bool  `json:"existed,omitempty"`
	FailedStep string `json:"failed_step"`
	CauseStep  string `json:"cause_step"`
	Error      string `json:"error"`
	// CauseError is the class of the failure that made the operation restore (CauseStep's), kept
	// apart from Error, which a failed restore overwrites: a later successful restore answers it.
	CauseError string `json:"cause_error"`
	// ForbiddenFinal: a restore was forbidden by more hashes than the lists can hold, so
	// restore_forbidden is final (re-sent restores answer it without a new check).
	ForbiddenFinal bool `json:"forbidden_final"`
	// PrevRecord is the binding record (latest operation) before this operation took it over.
	PrevRecord string          `json:"prev_record"`
	Steps      []winproto.Step `json:"steps"`
	// ForbiddenSPKI and ForbiddenLeaf are the rollback guard iis-deploy received (R48), grown by the
	// lists of every restore they forbade (so restore_forbidden only ever stays so): no restore of
	// this operation puts back a certificate they list.
	ForbiddenSPKI []string `json:"forbidden_spki_sha256"`
	ForbiddenLeaf []string `json:"forbidden_leaf_sha256"`

	// Kind is "" for a binding's journal and winproto.JournalKindCCS for a ccs-deploy (W5 Ruling 2);
	// only the latter has CCS. A CCS journal's Binding is its file record's key (ccsRecordKey), its
	// Locator, Previous and Store are empty, and the SHA-1 and SHA-256 fields name the leaves.
	Kind string      `json:"kind,omitempty"`
	CCS  *ccsJournal `json:"ccs,omitempty"`
	// RDP is an rdp-deploy's (kind winproto.JournalKindRDP, W6 Ruling 13): its Binding is
	// winproto.RDPCanonical, its Store MY (the import store), its Locator and Previous are empty.
	RDP *rdpJournal `json:"rdp,omitempty"`
}

// rdpJournal is what an RDP journal adds (W6 Ruling 13): where the previous certificate is
// (PreviousStore MY, or Remote Desktop when the value was absent: PreviousAbsent, the restore then
// deletes the value), the previous leaf's SPKI SHA-256 the guard checks, whether NETWORK SERVICE could
// read the new key before the operation (KeyReadHad, written before any grant; nil until the grant step
// read it) and whether a restore could not take this operation's grant back (ACLLeft).
type rdpJournal struct {
	PreviousStore      string `json:"previous_store"`
	PreviousAbsent     bool   `json:"previous_absent"`
	PreviousSPKISHA256 string `json:"previous_spki_sha256"`
	KeyReadHad         *bool  `json:"key_read_had"`
	ACLLeft            bool   `json:"acl_left,omitempty"`
	// Rebuild: set_listener deletes the value and sets it again, because the listener named the new
	// certificate already (Ruling 14 amended, F20); recorded with the writing journal, before the delete.
	Rebuild bool `json:"rebuild,omitempty"`
}

// valid reports RDP fields the helper may act on in phase: the previous store one of the two, the
// self-signed store exactly when the value was absent (Ruling 4), and KeyReadHad known from the grant
// step on (nil only in a journal that never reached it: prepared, or restored before it).
func (r rdpJournal) valid(phase string) bool {
	return (r.PreviousStore == defaultStore || r.PreviousStore == winproto.RDPStoreSelfSigned) &&
		r.PreviousAbsent == (r.PreviousStore == winproto.RDPStoreSelfSigned) && validSHA256(r.PreviousSPKISHA256) &&
		(r.KeyReadHad != nil || phase == winproto.PhasePrepared || phase == winproto.PhaseRestored) &&
		(!r.Rebuild || (!r.PreviousAbsent && phase != winproto.PhasePrepared))
}

// rdpNamesNew reports a listener value that is this operation's certificate: the new SHA-1, or, while
// the operation is not committed, an absent value its rebuild deleted (an interrupted delete-then-set:
// the restore sets the value back, iis-status names the new leaf). A committed operation's value
// deleted later was deleted by someone else.
func rdpNamesNew(j journal, value string) bool {
	return value == j.NewSHA1 || (value == "" && j.RDP.Rebuild && j.Phase != winproto.PhaseCommitted)
}

// rdpPreviousValue is the value a restore of an RDP journal writes back: "" (deleted) when it was absent.
func rdpPreviousValue(j journal) string {
	if j.RDP.PreviousAbsent {
		return ""
	}
	return j.PreviousSHA1
}

// ccsJournal is what a CCS journal adds (W5 Ruling 14): the folder as the registry named it, the
// names the helper derived from the host, the hashes of the file's bytes before and after (NewFileSHA256
// "" until the PFX is built, with the writing journal) and the SPKI SHA-256 of the previous leaf, which
// the guard checks (the backup's key is never read again).
type ccsJournal struct {
	Path               string `json:"path"`
	File               string `json:"file"`
	Host               string `json:"host"`
	Backup             string `json:"backup"`
	Temp               string `json:"temp"`
	PreviousFileSHA256 string `json:"previous_file_sha256"`
	NewFileSHA256      string `json:"new_file_sha256"`
	PreviousSPKISHA256 string `json:"previous_spki_sha256"`
	// RefreshFailed: the last RefreshCCSRecords of this operation (after its replace or its restore)
	// failed (ruling W5-10); answered as ccs_refresh_failed.
	RefreshFailed bool `json:"refresh_failed,omitempty"`
}

// ccsRecordKey is the file record's key of a CCS file: a binding record keyed by "ccs/<file>".
func ccsRecordKey(file string) string { return "ccs/" + file }

// ccsBackupName and ccsTempName are the backup and the temporary file of operation op in the CCS folder
// (Global Constraints: neither ends in .pfx, so IIS never serves them).
// The backup takes the operation's last 8 hex digits: a UUIDv7's first 8 are its time (ruling W5-2).
func ccsBackupName(file, op string) string { return file + ".alice-" + op[len(op)-8:] + ".bak" }
func ccsTempName(op string) string         { return ".alice-" + op + ".tmp" }

// valid reports CCS fields the helper may act on for operation op: the folder a supported local path,
// the file the host's (Ruling 5) and every name the one this operation derives, plain (plainName).
func (c ccsJournal) valid(op, phase string) bool {
	file, ok := winproto.CCSFileName(c.Host)
	return ok && file == c.File && winproto.ValidCCSPath(c.Path) && c.Backup == ccsBackupName(file, op) &&
		c.Temp == ccsTempName(op) && plainName(c.File) && plainName(c.Backup) && plainName(c.Temp) &&
		validSHA256(c.PreviousFileSHA256) && validSHA256(c.PreviousSPKISHA256) &&
		(validSHA256(c.NewFileSHA256) || (c.NewFileSHA256 == "" && phase != winproto.PhaseCommitted))
}

var journalPhases = []string{winproto.PhasePrepared, winproto.PhaseWriting, winproto.PhaseCommitted, winproto.PhaseUnchanged,
	winproto.PhaseRestoring, winproto.PhaseRestored, winproto.PhaseRestoreFailed, winproto.PhaseRestoreForbidden}

var stepNames = []string{winproto.StepImportChain, winproto.StepImportCertificate, winproto.StepBind, winproto.StepJournal, winproto.StepRestore,
	winproto.StepWriteFile, winproto.StepGrantKeyRead, winproto.StepSetListener}

var errorClasses = []string{winproto.ErrKeyUnusable, winproto.ErrReadBack, winproto.ErrStore, winproto.ErrFileChanged,
	winproto.ErrForbidden, winproto.ErrBackupMissing, winproto.ErrIO, winproto.ErrKeyACL}

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
	if !slices.Contains(journalPhases, j.Phase) || len(j.Steps) > maxSteps || len(j.Intermediates) > winproto.MaxChainCerts ||
		!winproto.ValidSHA1(j.NewSHA1) || !validSHA256(j.PreviousSHA256) || !validSHA256(j.NewSHA256) {
		return false
	}
	switch j.Kind {
	case "":
		canonical, ok := j.Locator.Canonical()
		if !ok || canonical != j.Binding || j.CCS != nil || j.RDP != nil || !validRecord(j.Previous, j.Binding) ||
			j.Previous.CertSHA1 != j.PreviousSHA1 || !winproto.ValidStore(j.Store) {
			return false
		}
	case winproto.JournalKindCCS:
		// No binding, no store import: the fields of W2 a CCS operation never has stay empty.
		if j.CCS == nil || j.RDP != nil || !j.CCS.valid(op, j.Phase) || j.Binding != ccsRecordKey(j.CCS.File) || j.Locator != (winproto.Locator{}) ||
			!reflect.DeepEqual(j.Previous, winproto.SSLBinding{}) || j.Store != "" || j.AliceImported || j.Existed != nil ||
			!winproto.ValidSHA1(j.PreviousSHA1) {
			return false
		}
	case winproto.JournalKindRDP:
		// One listener named in code, no http.sys record; the import store is My (Ruling 6).
		if j.RDP == nil || j.CCS != nil || !j.RDP.valid(j.Phase) || j.Binding != winproto.RDPCanonical || j.Locator != (winproto.Locator{}) ||
			!reflect.DeepEqual(j.Previous, winproto.SSLBinding{}) || j.Store != defaultStore || !winproto.ValidSHA1(j.PreviousSHA1) {
			return false
		}
	default:
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
	if (j.ForbiddenFinal && j.Phase != winproto.PhaseRestoreForbidden) || (j.CauseError != "" && j.CauseStep == "") ||
		(j.Existed != nil && *j.Existed && j.AliceImported) {
		return false
	}
	return (j.Error == "" || slices.Contains(errorClasses, j.Error)) && (j.CauseError == "" || slices.Contains(errorClasses, j.CauseError)) &&
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
//
// Chain is what schannel serves for the binding as far as Alice knows (fix rounds 3 and 4): the DER
// SHA-256s of the leaf and the intermediates of the last bind Alice committed, written with committed.
// It is cleared when a deployment takes the record (prepared, before any import or bind) and before
// every restore write, and put back only by a deployment that ends unchanged (it wrote nothing), so it
// is set only while the record is exactly what that committed bind left. iis-deploy answers unchanged
// only when it equals the deployment's chain (schannel serves the chain it built at the last write,
// W0 F5); otherwise a same-hash write rebuilds it. No key material: hashes of public certificates.
type bindingRecord struct {
	Binding string   `json:"binding"`
	Op      string   `json:"op"`
	Chain   []string `json:"chain,omitempty"`
}

// bindingRecordName is a binding's record file name.
func bindingRecordName(canonical string) string {
	sum := sha256.Sum256([]byte(canonical))
	return bindingsDir + hex.EncodeToString(sum[:]) + ".json"
}

// readBindingRecord returns the operation recorded for the binding ("" when none). A record that does
// not decode, names another binding or an invalid operation is errBadJournal.
func readBindingRecord(h WriteHost, canonical string) (string, error) {
	r, err := readBindingState(h, canonical)
	return r.Op, err
}

// readBindingState reads the binding's whole record (zero when there is none).
func readBindingState(h WriteHost, canonical string) (bindingRecord, error) {
	data, found, err := h.ReadState(bindingRecordName(canonical))
	if err != nil || !found {
		return bindingRecord{Binding: canonical}, err
	}
	var r bindingRecord
	if err := decodeState(data, &r); err != nil || !r.valid(canonical) {
		return bindingRecord{Binding: canonical}, errBadJournal
	}
	return r, nil
}

// valid: the record names canonical, a valid operation or none, and a chain of at most
// MaxChainCerts+1 DER SHA-256s (leaf and intermediates).
func (r bindingRecord) valid(canonical string) bool {
	if r.Binding != canonical || (r.Op != "" && !winproto.ValidOpID(r.Op)) || len(r.Chain) > winproto.MaxChainCerts+1 {
		return false
	}
	for _, s := range r.Chain {
		if !validSHA256(s) {
			return false
		}
	}
	return true
}

// writeBindingRecord records op for the binding (op "" clears it) with no served chain, durably.
func writeBindingRecord(h WriteHost, canonical, op string) error {
	return writeBindingState(h, bindingRecord{Binding: canonical, Op: op})
}

// clearChain drops the binding record's chain, keeping its operation (nothing when it has none).
func clearChain(h WriteHost, canonical string) error {
	r, err := readBindingState(h, canonical)
	if err != nil || r.Chain == nil {
		return err
	}
	r.Chain = nil
	return writeBindingState(h, r)
}

// writeBindingState replaces the binding's whole record, durably. A record readBindingState would
// refuse is never written.
func writeBindingState(h WriteHost, r bindingRecord) error {
	if !r.valid(r.Binding) {
		return errBadJournal
	}
	raw, err := json.Marshal(r)
	if err != nil {
		return err
	}
	return h.WriteState(bindingRecordName(r.Binding), raw)
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
	rec, err := readBindingState(h, j.Binding)
	if err != nil {
		return err
	}
	if rec.Op != j.Op {
		return nil
	}
	// The record is handed back as it is: a prepared operation took it without a chain (fix round 4),
	// so the next deployment makes one same-hash write; an unchanged one put back the chain it read.
	rec.Op = j.PrevRecord
	return writeBindingState(h, rec)
}

// recoveryPending is the refusal of iis-deploy on a binding whose latest operation is interrupted
// (writing, restoring or unreadable): exit 3, nothing changed, PendingOp names it.
func recoveryPending(op string) error {
	return &helperError{exit: winproto.ExitPrecondition, code: winproto.CodeRecoveryPending,
		message: "an interrupted operation on this binding must be recovered first", pendingOp: op}
}

// importEntry is one certificate Alice imported (imports.json; W3's cleanup reads it). UnboundSince is
// when a cleanup plan first found it unused (RFC 3339 UTC, the helper's clock; W3 Ruling 8), "" while
// it is used or was never planned (and in a W2 inventory).
type importEntry struct {
	Op           string `json:"op"`
	Store        string `json:"store"`
	SHA1         string `json:"sha1"`
	SHA256       string `json:"sha256"`
	UnboundSince string `json:"unbound_since,omitempty"`
}

type importsFile struct {
	Imports []importEntry `json:"imports"`
}

func (e importEntry) valid() bool {
	return winproto.ValidOpID(e.Op) && winproto.ValidStore(e.Store) && winproto.ValidSHA1(e.SHA1) && validSHA256(e.SHA256) &&
		(e.UnboundSince == "" || validStamp(e.UnboundSince))
}

// sameImport reports two entries that record one import (the age stamp aside).
func (e importEntry) sameImport(o importEntry) bool {
	return e.Op == o.Op && e.Store == o.Store && e.SHA1 == o.SHA1 && e.SHA256 == o.SHA256
}

// stampLayout is the form of a time the helper keeps in a state file: RFC 3339 in UTC, whole seconds.
const stampLayout = time.RFC3339

// stamp writes t as a state file keeps it.
func stamp(t time.Time) string { return t.UTC().Truncate(time.Second).Format(stampLayout) }

// validStamp reports a time written by stamp (exactly that text: UTC, "Z", whole seconds).
func validStamp(s string) bool {
	t, err := time.Parse(stampLayout, s)
	return err == nil && stamp(t) == s
}

// readImports reads the import inventory (empty when there is none).
func readImports(h WriteHost) (importsFile, error) {
	var f importsFile
	data, found, err := h.ReadState(importsName)
	if err != nil || !found {
		return importsFile{Imports: []importEntry{}}, err
	}
	if err := decodeState(data, &f); err != nil || !f.valid() {
		return importsFile{}, errBadJournal
	}
	if f.Imports == nil {
		f.Imports = []importEntry{}
	}
	return f, nil
}

// valid: at most maxImports entries, each valid.
func (f importsFile) valid() bool {
	if len(f.Imports) > maxImports {
		return false
	}
	for _, e := range f.Imports {
		if !e.valid() {
			return false
		}
	}
	return true
}

// writeImports replaces the import inventory durably. An inventory readImports would refuse is never
// written: errBadJournal, and the previous one stays.
func writeImports(h WriteHost, f importsFile) error {
	if !f.valid() {
		return errBadJournal
	}
	if f.Imports == nil {
		f.Imports = []importEntry{}
	}
	raw, err := json.Marshal(f)
	if err != nil {
		return err
	}
	return h.WriteState(importsName, raw)
}

// recordImport adds a certificate to the import inventory once (an entry recording the same import
// keeps its age stamp); past maxImports the oldest go.
func recordImport(h WriteHost, e importEntry) error {
	if !e.valid() {
		return errBadJournal
	}
	f, err := readImports(h)
	if err != nil {
		return err
	}
	if slices.ContainsFunc(f.Imports, e.sameImport) {
		return nil
	}
	f.Imports = append(f.Imports, e)
	if len(f.Imports) > maxImports {
		f.Imports = slices.Clone(f.Imports[len(f.Imports)-maxImports:])
	}
	return writeImports(h, f)
}

// journalFile is a journal file of journalDir as readJournals found it: J is its journal when OK.
// Neither OK nor Unread: the file could not be decoded (W3 Ruling 7: it keeps every candidate until
// pruning removes it after JournalRetention). Unread: it was not read, because the read failed or the
// listing was past maxJournalFiles; it keeps every candidate too and is never pruned (what it holds
// is unknown).
type journalFile struct {
	File   StateFile
	Op     string
	J      journal
	OK     bool
	Unread bool
}

// maxJournalFiles bounds how many journals one call reads (tests lower it); pruning keeps the
// directory far below it.
var maxJournalFiles = 4096

// readJournals reads the journals of journalDir (ListState), in the order of their names. Only a file
// named "<op>.json" is a journal: anything else (a temporary file of WriteState, a file someone put
// there) is never read as one and is left out. A journal that does not decode or that readJournal
// refuses is listed with OK false; one whose read fails, and every one past maxJournalFiles, with
// Unread (W3 Ruling 7: the cleanup keeps every candidate while one is listed so; the dump leaves them
// out). Only a listing failure is an error.
func readJournals(h WriteHost) ([]journalFile, error) {
	files, err := h.ListState(journalDir)
	if err != nil {
		return nil, err
	}
	slices.SortFunc(files, func(a, b StateFile) int { return strings.Compare(a.Name, b.Name) })
	out := make([]journalFile, 0, min(len(files), maxJournalFiles+1))
	for _, f := range files {
		op, ok := strings.CutSuffix(f.Name, ".json")
		if !ok || !winproto.ValidOpID(op) {
			continue
		}
		jf := journalFile{File: f, Op: op}
		if len(out) >= maxJournalFiles {
			jf.Unread = true
			out = append(out, jf)
			continue
		}
		j, found, err := readJournal(h, op)
		switch {
		case errors.Is(err, errBadJournal):
		case err != nil:
			jf.Unread = true
		case found:
			jf.J, jf.OK = j, true
		default:
			continue // removed since the listing
		}
		out = append(out, jf)
	}
	return out, nil
}
