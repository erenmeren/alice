package winhelper

// The Centralized Certificate Store subcommands (W5, R68): ccs-dump reads the CCS folder the registry
// names with the PFX password from standard input; ccs-deploy writes one file of it.

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"slices"
	"sort"
	"strings"
	"time"

	"alice/internal/providers/windows/winproto"
)

// ccsDumpBudget is how long ccs-dump reads files before it answers Truncated with what it has: part of
// the call budget, so the answer is sent before the budget ends (tests lower it).
var ccsDumpBudget = winproto.HelperBudget * 4 / 5

// parseCCSPassword decodes a CCSDumpInput strictly: one object with exactly the member "password" (a
// JSON string), nothing after it but white space. The password is copied only into the returned
// buffer, which the caller clears. Syntax is BAD_CONTENT; a password outside ValidCCSPassword is
// INVALID_ARGUMENT.
func parseCCSPassword(raw []byte) ([]byte, error) {
	bad := refused(winproto.CodeBadContent, "the input is not a CCS password")
	p := jsonScan{b: raw}
	if !p.lit('{') {
		return nil, bad
	}
	if name, ok := p.str(make([]byte, 0, 16), 16); !ok || string(name) != "password" || !p.lit(':') {
		return nil, bad
	}
	pw, ok := p.str(make([]byte, 0, len(raw)), len(raw))
	if !ok || !p.lit('}') {
		clear(pw[:cap(pw)])
		return nil, bad
	}
	p.ws()
	if p.i != len(p.b) {
		clear(pw[:cap(pw)])
		return nil, bad
	}
	if !winproto.ValidCCSPassword(pw) {
		clear(pw[:cap(pw)])
		return nil, refused(winproto.CodeInvalidArgument, "the CCS password is not allowed")
	}
	return pw, nil
}

// cmdCCSDump answers "ccs-dump" (elevated, no lock): the registry's CCS folder and, for a local one,
// each .pfx whose name gives a host, read with the password from stdin. A file that cannot be read or
// opened, or a list cut at MaxCCSFiles or at the budget, sets Truncated (Alice then marks nothing
// missing, W2 Ruling 18). The password buffer is cleared before the answer.
func cmdCCSDump(ctx context.Context, c *call) (any, error) {
	if len(c.args) != 0 {
		return nil, refused(winproto.CodeUsage, "ccs-dump takes no arguments")
	}
	pw, err := parseCCSPassword(c.input)
	if err != nil {
		return nil, err
	}
	defer clear(pw[:cap(pw)])
	h := c.host
	enabled, path, err := h.CCSConfig(ctx)
	if err != nil {
		return nil, failed(winproto.CodeIOError, "the CCS configuration could not be read")
	}
	d := winproto.CCSDumpResponse{OK: true, Enabled: enabled, Files: []winproto.CCSFile{}}
	if !enabled {
		return d, nil
	}
	d.Path = cleanValue(path, winproto.MaxText)
	if !winproto.ValidCCSPath(path) {
		return d, nil
	}
	entries, err := h.ListCCS(ctx, path)
	if errors.Is(err, ErrCCSFolderUnsupported) {
		return d, nil
	}
	if err != nil {
		return nil, failed(winproto.CodeIOError, "the CCS folder could not be read")
	}
	d.Local = true
	sort.Slice(entries, func(i, j int) bool { return entries[i].Name < entries[j].Name })
	end := h.Now().Add(ccsDumpBudget)
	for _, e := range entries {
		host, ok := winproto.CCSHost(e.Name)
		if !ok {
			d.Ignored++
			continue
		}
		if len(d.Files) == winproto.MaxCCSFiles || ctx.Err() != nil || !h.Now().Before(end) {
			// Past the cut nothing more is read, but the names are still judged: Ignored counts every
			// host-less name of the folder.
			d.Truncated = true
			continue
		}
		f, ok := readCCSFile(ctx, h, path, e, host, pw)
		if !ok {
			d.Truncated = true
			continue
		}
		if f.Name != "" {
			d.Files = append(d.Files, f)
		}
	}
	return d, nil
}

// readCCSFile reads and opens one file. ok is false when it cannot be read or opened, or its
// certificates are past the bounds; a file that vanished since the list, or that ReadCCS refuses as a
// reparse point or not a regular file, is the zero CCSFile (not listed).
func readCCSFile(ctx context.Context, h WriteHost, folder string, e CCSEntry, host string, pw []byte) (winproto.CCSFile, bool) {
	data, found, err := h.ReadCCS(ctx, folder, e.Name, winproto.MaxCCSFile)
	switch {
	case errors.Is(err, ErrCCSFileUnsupported):
		return winproto.CCSFile{}, true // a reparse point or not a regular file: not listed (W5 Ruling 4)
	case err != nil:
		return winproto.CCSFile{}, false
	case !found:
		return winproto.CCSFile{}, true
	}
	f := winproto.CCSFile{Name: e.Name, Host: host, Size: e.Size, ModifiedAt: e.ModTime.UTC().Format(time.RFC3339), Chain: []string{}}
	if len(data) > winproto.MaxCCSFile {
		f.Problem = winproto.CCSProblemTooLarge
		return f, true
	}
	sum := sha256.Sum256(data)
	f.FileSHA256 = hex.EncodeToString(sum[:])
	leaf, chain, problem, err := h.OpenPFX(data, pw)
	if err != nil {
		return winproto.CCSFile{}, false
	}
	switch problem {
	case "":
	case winproto.CCSProblemPasswordMismatch, winproto.CCSProblemNotPFX, winproto.CCSProblemNoKey:
		f.Problem = problem
		return f, true
	default:
		return winproto.CCSFile{}, false // a host's own words never reach the answer: an error for this file
	}
	if len(leaf) == 0 || len(leaf) > winproto.MaxCertDER || len(chain) > winproto.MaxChainCerts {
		return winproto.CCSFile{}, false
	}
	f.LeafDER = base64.StdEncoding.EncodeToString(leaf)
	for _, der := range chain {
		if len(der) == 0 || len(der) > winproto.MaxCertDER {
			return winproto.CCSFile{}, false
		}
		f.Chain = append(f.Chain, base64.StdEncoding.EncodeToString(der))
	}
	return f, true
}

// eventCCSWritten is the Application event of a CCS file written (W5 Ruling 14 step 9).
const eventCCSWritten uint32 = 1004

// plainName reports a name without ":" (an NTFS alternate data stream) and without a path separator.
// The helper joins only such names, which it derived itself, to the folder it read itself; CCSFileName
// already excludes both, this is the second line.
func plainName(name string) bool { return name != "" && !strings.ContainsAny(name, `:\/`) }

// sameFolder compares two CCS folders with ASCII case folded and one trailing backslash trimmed (W5
// Ruling 4).
func sameFolder(a, b string) bool {
	return asciiLower(strings.TrimSuffix(a, `\`)) == asciiLower(strings.TrimSuffix(b, `\`))
}

// ccsFileSum is the SHA-256 of a file of the CCS folder (found false when there is none). The bytes, a
// PFX, are cleared once hashed.
func ccsFileSum(ctx context.Context, h WriteHost, folder, name string) (sum string, found bool, err error) {
	data, found, err := h.ReadCCS(ctx, folder, name, winproto.MaxCCSFile)
	if err != nil || !found {
		return "", false, err
	}
	defer clear(data)
	return sum256(data), true, nil
}

// ccsRequest is ccs-deploy's decoded stdin. chainPEM, keyPEM and password are buffers of the call's
// secrets.
type ccsRequest struct {
	path, host, expect         string
	chainPEM, keyPEM, password []byte
	spki, leaf                 []string
}

// parseCCSDeployInput decodes ccs-deploy's stdin, winproto.CCSDeployInput: a JSON object with exactly
// the eight members (any order, each once, nothing else), by the strict hand parser of iis-deploy, so
// the key and the password are copied only into buffers of sec. Syntax is BAD_CONTENT; a host whose
// file name is not allowed, a folder that is not a supported local path, an expected hash, a password
// or a list that is not valid is INVALID_ARGUMENT.
func parseCCSDeployInput(raw []byte, sec *secrets) (ccsRequest, error) {
	var d ccsRequest
	bad := refused(winproto.CodeBadContent, "the input is not a CCS deployment")
	p := jsonScan{b: raw}
	seen := map[string]bool{}
	if !p.lit('{') {
		return d, bad
	}
	for i := 0; ; i++ {
		if i > 0 && !p.lit(',') {
			break
		}
		name, ok := p.str(make([]byte, 0, 32), 32)
		if !ok || !p.lit(':') || seen[string(name)] {
			return d, bad
		}
		seen[string(name)] = true
		var v []byte
		switch string(name) {
		case "path", "host", "expect_sha256":
			v, ok = p.str(make([]byte, 0, winproto.MaxText), winproto.MaxText)
			switch string(name) {
			case "path":
				d.path = string(v)
			case "host":
				d.host = string(v)
			default:
				d.expect = string(v)
			}
		case "chain_pem":
			d.chainPEM, ok = p.str(sec.keep(make([]byte, 0, len(raw))), len(raw))
		case "key_pem":
			d.keyPEM, ok = p.str(sec.keep(make([]byte, 0, len(raw))), len(raw))
		case "password":
			d.password, ok = p.str(sec.keep(make([]byte, 0, len(raw))), len(raw))
		case "forbidden_spki_sha256":
			d.spki, ok = p.hashList()
		case "forbidden_leaf_sha256":
			d.leaf, ok = p.hashList()
		default:
			ok = false
		}
		if !ok {
			return d, bad
		}
	}
	if len(seen) != 8 || !p.lit('}') {
		return d, bad
	}
	p.ws()
	if p.i != len(p.b) {
		return d, bad
	}
	file, ok := winproto.CCSFileName(d.host)
	if !ok || !plainName(file) || !winproto.ValidCCSPath(d.path) || !validSHA256(d.expect) || !winproto.ValidCCSPassword(d.password) ||
		!winproto.ValidForbidden(d.spki) || !winproto.ValidForbidden(d.leaf) {
		return d, refused(winproto.CodeInvalidArgument, "the host, the folder, the expected hash, the password or a forbidden list is not allowed")
	}
	return d, nil
}

// cmdCCSDeploy answers "ccs-deploy --op <id>" with a winproto.CCSDeployInput on stdin (W5 Ruling 14):
// the W2 transaction with the step write_file in place of the bind. Every refusal comes before
// gate.enter and changed nothing; the first durable write is the prepared journal, and after it the
// answer is the operation's phase (or OUTCOME_UNKNOWN, settle). Every name joined to the folder is one
// the helper derived from the host, and the folder is the one the registry names now.
func cmdCCSDeploy(ctx context.Context, c *call) (any, error) {
	op, err := opArg(c.args, winproto.SubCCSDeploy)
	if err != nil {
		return nil, err
	}
	sec := newSecrets()
	defer sec.clear()
	req, err := parseCCSDeployInput(c.input, sec)
	if err != nil {
		return nil, err
	}
	in, err := checkContent(req.chainPEM, req.keyPEM, sec)
	if err != nil {
		return nil, err
	}
	file, _ := winproto.CCSFileName(req.host)
	key := ccsRecordKey(file)
	h := c.host
	release, err := lockHelper(ctx, h)
	if err != nil {
		return nil, err
	}
	defer release()
	if err := point(h, "ccs.locked"); err != nil {
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
	switch pending, err := interruptedLatest(h, key, op); {
	case err != nil:
		return nil, failed(winproto.CodeIOError, "the record of the file's latest operation cannot be read")
	case pending != "":
		return nil, recoveryPending(pending)
	}
	rec, err := readBindingState(h, key)
	if err != nil {
		return nil, failed(winproto.CodeIOError, "the record of the file's latest operation cannot be read")
	}

	enabled, folder, err := h.CCSConfig(ctx)
	switch {
	case err != nil:
		return nil, failed(winproto.CodeIOError, "the CCS configuration could not be read")
	case !enabled:
		return nil, precondition(winproto.CodeCCSDisabled, "IIS has the Centralized Certificate Store turned off")
	case !winproto.ValidCCSPath(folder):
		return nil, precondition(winproto.CodeCCSPathUnsupported, "the CCS folder is not a local folder Alice manages")
	case !sameFolder(folder, req.path):
		return nil, precondition(winproto.CodeCCSPathChanged, "the CCS folder is not the one Alice discovered")
	}
	// The listing refuses a folder that is a reparse point (W5 Ruling 3).
	switch _, err := h.ListCCS(ctx, folder); {
	case errors.Is(err, ErrCCSFolderUnsupported):
		return nil, precondition(winproto.CodeCCSPathUnsupported, "the CCS folder is not a local folder Alice manages")
	case err != nil:
		return nil, failed(winproto.CodeIOError, "the CCS folder could not be read")
	}
	data, found, err := h.ReadCCS(ctx, folder, file, winproto.MaxCCSFile)
	switch {
	case errors.Is(err, ErrCCSFileUnsupported):
		return nil, refused(winproto.CodeInvalidArgument, "the CCS file is a reparse point or not a regular file")
	case err != nil:
		return nil, failed(winproto.CodeIOError, "the CCS file could not be read")
	case !found:
		return nil, precondition(winproto.CodeCCSFileNotFound, "the CCS folder holds no file for this host")
	}
	sec.keep(data)
	if len(data) > winproto.MaxCCSFile {
		return nil, refused(winproto.CodeInvalidArgument, "the CCS file is too large")
	}
	prevLeaf, prevChain, problem, err := h.OpenPFX(data, req.password)
	other := precondition(winproto.CodeHashMismatch, "the CCS file holds another certificate than expected")
	switch {
	case err != nil:
		return nil, failed(winproto.CodeIOError, "the CCS file could not be opened")
	case problem == winproto.CCSProblemPasswordMismatch:
		return nil, precondition(winproto.CodeCCSPasswordMismatch, "the CCS password does not open the file")
	case problem == winproto.CCSProblemNotPFX, problem == winproto.CCSProblemNoKey:
		return nil, other
	case problem != "":
		return nil, failed(winproto.CodeIOError, "the CCS file could not be opened")
	}
	prev, err := x509.ParseCertificate(prevLeaf)
	if err != nil || sum256(prevLeaf) != req.expect {
		return nil, other
	}
	intermediates := make([][]byte, 0, len(in.intermediates))
	for _, ic := range in.intermediates {
		intermediates = append(intermediates, ic.Raw)
	}
	newSHA1, newSHA256 := sum1(in.leaf.Raw), sum256(in.leaf.Raw)
	if newSHA256 == req.expect && slices.EqualFunc(prevChain, intermediates, bytes.Equal) {
		// The file holds this leaf and these intermediates already: nothing is written, not even a
		// journal (Ruling 14 step 3).
		return winproto.DeployResponse{OK: true, Phase: winproto.PhaseUnchanged, Steps: []winproto.Step{}, NewSHA1: newSHA1,
			NewSHA256: newSHA256, PreviousSHA1: sum1(prevLeaf), PreviousSHA256: req.expect}, nil
	}
	prevRecord := rec.Op
	if prevRecord == op {
		prevRecord = ""
	}

	wctx, err := c.gate.enter()
	if err != nil {
		return nil, err
	}
	t := &deployTx{ctx: wctx, h: h, j: journal{Op: op, Phase: winproto.PhasePrepared, Kind: winproto.JournalKindCCS, Binding: key,
		PreviousSHA1: sum1(prevLeaf), PreviousSHA256: req.expect, NewSHA1: newSHA1, NewSHA256: newSHA256, Intermediates: []certRef{},
		PrevRecord: prevRecord, Steps: []winproto.Step{}, ForbiddenSPKI: req.spki, ForbiddenLeaf: req.leaf,
		CCS: &ccsJournal{Path: folder, File: file, Host: req.host, Backup: ccsBackupName(file, op), Temp: ccsTempName(op),
			PreviousFileSHA256: sum256(data), PreviousSPKISHA256: spkiSHA256(prev.PublicKey, prev.RawSubjectPublicKeyInfo)}}}
	return t.runCCS(in, intermediates, req.password, sec)
}

// runCCS is ccs-deploy after its gate (Ruling 14 steps 4-9): every outcome is recorded in the journal.
// The F15 route (a) step (a same-record update of each linked ccs record after the replace) is not
// built: F15 is measured on a runner first.
func (t *deployTx) runCCS(in content, intermediates [][]byte, password []byte, sec *secrets) (any, error) {
	h, j := t.h, &t.j
	c := j.CCS
	if err := writeJournal(h, *j); err != nil {
		return nil, err
	}
	// The file record names this operation from the prepared journal on, as a binding record does.
	if err := writeBindingRecord(h, j.Binding, j.Op); err != nil {
		return nil, err
	}
	if err := point(h, "ccs.prepared"); err != nil {
		return nil, err
	}
	if !t.importChain(in) {
		return t.failUnbound(winproto.StepImportChain, winproto.ErrStore)
	}
	if err := t.write("ccs.import_chain"); err != nil {
		return nil, err
	}

	// write_file: the PFX under the CCS password, a temporary file in the folder, then ReplaceFileW
	// with the backup. The writing journal names the bytes this operation writes.
	pfx, err := BuildPFX(in.leaf.Raw, in.pkcs8, password, intermediates...)
	if err != nil {
		return t.failUnbound(winproto.StepWriteFile, winproto.ErrIO)
	}
	sec.keep(pfx)
	c.NewFileSHA256 = sum256(pfx)
	j.Phase = winproto.PhaseWriting
	if err := t.write("ccs.writing"); err != nil {
		return nil, err
	}
	if err := h.WriteCCSTemp(t.ctx, c.Path, c.Temp, pfx); err != nil {
		return t.unwritten()
	}
	if err := point(h, "ccs.temp_written"); err != nil {
		return nil, err
	}
	if err := h.ReplaceCCS(t.ctx, c.Path, c.File, c.Temp, c.Backup); err != nil {
		// ReplaceFileW can fail after it moved the file aside (ERROR_UNABLE_TO_MOVE_REPLACEMENT_2): only
		// a file that reads back as the previous bytes is untouched; anything else is restored.
		if sum, found, err := ccsFileSum(t.ctx, h, c.Path, c.File); err == nil && found && sum == c.PreviousFileSHA256 {
			return t.unwritten()
		}
		return t.selfRestore(winproto.StepWriteFile, winproto.ErrIO)
	}
	if err := point(h, "ccs.replaced"); err != nil {
		return nil, err
	}
	// Read back: the bytes are the PFX built, and the password opens them to the new leaf.
	back, found, err := h.ReadCCS(t.ctx, c.Path, c.File, winproto.MaxCCSFile)
	sec.keep(back)
	if err != nil || !found || sum256(back) != c.NewFileSHA256 {
		return t.selfRestore(winproto.StepWriteFile, winproto.ErrReadBack)
	}
	if leaf, _, problem, err := h.OpenPFX(back, password); err != nil || problem != "" || sum256(leaf) != j.NewSHA256 {
		return t.selfRestore(winproto.StepWriteFile, winproto.ErrReadBack)
	}
	if err := point(h, "ccs.read_back"); err != nil {
		return nil, err
	}
	j.Steps = append(j.Steps, stepOK(winproto.StepWriteFile))
	j.Phase = winproto.PhaseCommitted
	if err := writeJournal(h, *j); err != nil {
		// The journal must not say writing while the answer says committed: roll back.
		j.Phase = winproto.PhaseWriting
		return t.selfRestore(winproto.StepJournal, winproto.ErrIO)
	}
	if err := point(h, "ccs.committed"); err != nil {
		return nil, err
	}
	h.Event(eventCCSWritten, "ccs file "+c.File+" sha256 "+j.PreviousSHA256+" -> "+j.NewSHA256+" op "+j.Op)
	return t.answer(), nil
}

// unwritten ends a write_file that failed before the replace changed the file: the temporary file is
// removed (best effort; pruning removes it otherwise) and the operation ends restored, nothing written.
func (t *deployTx) unwritten() (any, error) {
	_ = t.h.RemoveCCS(t.ctx, t.j.CCS.Path, t.j.CCS.Temp)
	return t.failUnbound(winproto.StepWriteFile, winproto.ErrIO)
}
