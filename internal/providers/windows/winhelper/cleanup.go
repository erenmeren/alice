package winhelper

import (
	"bytes"
	"context"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"slices"
	"strings"
	"time"

	"alice/internal/providers/windows/winproto"
)

// eventRemoved is the Application event of a removed certificate (W3 Ruling 10).
const eventRemoved uint32 = 1003

// watchStores are the stores a watched certificate is looked up in (W3 Ruling 9).
var watchStores = []string{"My", "WebHosting"}

// cmdIISCleanup answers "iis-cleanup --plan" (a winproto.CleanupPlanInput on stdin) and "iis-cleanup
// --apply" (a winproto.CleanupApplyInput) (W3 Rulings 3-12). Both run under the helper lock and the
// write gate; every refusal comes before gate.enter and changed nothing, every failure after it is
// OUTCOME_UNKNOWN (settle).
func cmdIISCleanup(ctx context.Context, c *call) (any, error) {
	if len(c.args) != 1 || (c.args[0] != winproto.ArgPlan && c.args[0] != winproto.ArgApply) {
		return nil, refused(winproto.CodeUsage, "usage: iis-cleanup --plan | --apply")
	}
	if c.args[0] == winproto.ArgPlan {
		watch, err := parsePlanInput(c.input)
		if err != nil {
			return nil, err
		}
		return cleanupPlan(ctx, c, watch)
	}
	items, err := parseApplyInput(c.input)
	if err != nil {
		return nil, err
	}
	return cleanupApply(ctx, c, items)
}

// parsePlanInput decodes --plan's stdin: exactly {"watch": [...]}, each ref exactly its two members.
func parsePlanInput(raw []byte) ([]winproto.CleanupRef, error) {
	var in struct {
		Watch *[]winproto.CleanupRef `json:"watch"`
	}
	if !strictJSON(raw, &in, "watch", "sha1", "sha256") || in.Watch == nil {
		return nil, refused(winproto.CodeBadContent, "the input is not a cleanup plan request")
	}
	if len(*in.Watch) > winproto.MaxForbidden {
		return nil, refused(winproto.CodeInvalidArgument, "the watch list is too long")
	}
	for _, r := range *in.Watch {
		if !winproto.ValidSHA1(r.SHA1) || !winproto.ValidSHA256(r.SHA256) {
			return nil, refused(winproto.CodeInvalidArgument, "a watched certificate is not allowed")
		}
	}
	return *in.Watch, nil
}

// parseApplyInput decodes --apply's stdin: exactly {"remove": [...]}, 1 to MaxCleanupItems items, each
// exactly its four members and ValidCleanupItem.
func parseApplyInput(raw []byte) ([]winproto.CleanupItem, error) {
	var in struct {
		Remove *[]winproto.CleanupItem `json:"remove"`
	}
	if !strictJSON(raw, &in, "remove", "store", "sha1", "sha256", "reason") || in.Remove == nil {
		return nil, refused(winproto.CodeBadContent, "the input is not a cleanup request")
	}
	if len(*in.Remove) == 0 || len(*in.Remove) > winproto.MaxCleanupItems {
		return nil, refused(winproto.CodeInvalidArgument, "the number of certificates is not allowed")
	}
	for _, i := range *in.Remove {
		if !winproto.ValidCleanupItem(i) {
			return nil, refused(winproto.CodeInvalidArgument, "a certificate to remove is not allowed")
		}
	}
	return *in.Remove, nil
}

// strictJSON decodes raw into v: one JSON object, nothing but white space after it, no unknown
// member, no member twice and every member name exactly one of names (encoding/json alone takes the
// last of two members and matches names without regard to case).
func strictJSON(raw []byte, v any, names ...string) bool {
	if !membersKnown(raw, names) {
		return false
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	return dec.Decode(v) == nil && atEOF(dec)
}

// membersKnown walks raw's tokens: every object's member names are among names, each at most once.
func membersKnown(raw []byte, names []string) bool {
	type frame struct {
		object, wantName bool
		seen             map[string]bool
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	var stack []*frame
	for {
		tok, err := dec.Token()
		if errors.Is(err, io.EOF) {
			return len(stack) == 0
		}
		if err != nil {
			return false
		}
		var top *frame
		if len(stack) > 0 {
			top = stack[len(stack)-1]
		}
		switch t := tok.(type) {
		case json.Delim:
			switch t {
			case '{', '[':
				if top != nil && top.object {
					top.wantName = true // this value is the member's; the next token in top is a name
				}
				stack = append(stack, &frame{object: t == '{', wantName: true, seen: map[string]bool{}})
			default:
				stack = stack[:len(stack)-1]
			}
		default:
			switch {
			case top == nil || !top.object:
			case top.wantName:
				name, _ := t.(string)
				if top.seen[name] || !slices.Contains(names, name) {
					return false
				}
				top.seen[name], top.wantName = true, false
			default:
				top.wantName = true
			}
		}
	}
}

// cleanupState is what both halves of iis-cleanup read under the lock before judging (W3 Rulings 5-7).
type cleanupState struct {
	h          WriteHost
	now        time.Time
	bound      map[string]bool // SHA-1s any http.sys record names (any application, any store)
	rdp, winrm map[string]bool
	live       map[string]bool // SHA-1s a live journal names as previous or new
	unreadable bool            // a journal could not be decoded or read: every certificate is kept
	files      []journalFile
	journals   []journal // the journals that decoded
	imports    importsFile
}

// openCleanup checks the data directory, takes the lock and reads, in this order, every http.sys
// record, the RDP and WinRM listeners' thumbprints, the journals and the import inventory. Any failure
// is a refusal (nothing was written). The caller releases the lock.
func openCleanup(ctx context.Context, h WriteHost) (*cleanupState, func(), error) {
	release, err := lockHelper(ctx, h)
	if err != nil {
		return nil, nil, err
	}
	s, err := readCleanupState(ctx, h)
	if err != nil {
		release()
		return nil, nil, err
	}
	return s, release, nil
}

func readCleanupState(ctx context.Context, h WriteHost) (*cleanupState, error) {
	s := &cleanupState{h: h, now: h.Now(), bound: map[string]bool{}, rdp: map[string]bool{}, winrm: map[string]bool{},
		live: map[string]bool{}}
	records, err := h.SSLBindings(ctx)
	if err != nil {
		return nil, failed(winproto.CodeIOError, "the http.sys bindings could not be read")
	}
	// The list must be whole: a certificate missing from it would count as unused (Rulings 6 and 12,
	// an unreadable list removes nothing). The two marks the dump also reads as truncated: a record
	// the helper could not decode comes without a type (its certificate is unknown), and a table the
	// helper stopped reading holds more than MaxBindings records (it reads at most MaxBindings+1).
	perType := map[string]int{}
	for _, b := range records {
		if b.Type == "" {
			return nil, failed(winproto.CodeIOError, "an http.sys binding could not be read")
		}
		if perType[b.Type]++; perType[b.Type] > winproto.MaxBindings {
			return nil, failed(winproto.CodeIOError, "the http.sys bindings could not be read in full")
		}
		if b.CertSHA1 != "" {
			s.bound[asciiLower(b.CertSHA1)] = true
		}
	}
	p, err := h.ProtectedThumbprints(ctx)
	if err != nil {
		return nil, failed(winproto.CodeIOError, "the remote desktop and remote management certificates could not be read")
	}
	for _, t := range p.RDP {
		s.rdp[asciiLower(t)] = true
	}
	for _, t := range p.WinRM {
		s.winrm[asciiLower(t)] = true
	}
	if s.files, err = readJournals(h); err != nil {
		return nil, failed(winproto.CodeIOError, "the journals could not be listed")
	}
	for _, f := range s.files {
		if !f.OK {
			s.unreadable = true
			continue
		}
		s.journals = append(s.journals, f.J)
		switch f.J.Phase {
		case winproto.PhasePrepared, winproto.PhaseWriting, winproto.PhaseRestoring, winproto.PhaseRestoreFailed:
			s.live[f.J.PreviousSHA1], s.live[f.J.NewSHA1] = true, true
		}
	}
	if s.imports, err = readImports(h); err != nil {
		return nil, failed(winproto.CodeIOError, "the import inventory cannot be read")
	}
	return s, nil
}

// inUse is why a certificate must stay whoever imported it (Rulings 6 and 7), "" when nothing uses it.
func (s *cleanupState) inUse(sha1 string) string {
	switch {
	case s.bound[sha1]:
		return winproto.KeptBound
	case s.rdp[sha1]:
		return winproto.KeptRDP
	case s.winrm[sha1]:
		return winproto.KeptWinRM
	case s.live[sha1]:
		return winproto.KeptJournal
	case s.unreadable:
		return winproto.KeptJournalUnreadable
	}
	return ""
}

// storeCopy is a certificate as a store holds it: der is nil when its DER does not decode.
type storeCopy struct {
	cert winproto.StoreCertificate
	der  []byte
}

// readCopy reads a certificate of a store; found is false when the store has none. A read failure is
// the refusal certError makes (the caller answers it; after the gate settle makes it OUTCOME_UNKNOWN).
func (s *cleanupState) readCopy(ctx context.Context, store, sha1 string) (storeCopy, bool, error) {
	c, found, err := s.h.Certificate(ctx, store, sha1)
	if err != nil {
		return storeCopy{}, false, certError(err)
	}
	if !found {
		return storeCopy{}, false, nil
	}
	c.Store = store
	der, err := base64.StdEncoding.DecodeString(c.DER)
	if err != nil || len(der) == 0 {
		der = nil
	}
	return storeCopy{cert: c, der: der}, true, nil
}

// alice is rule 1 (Ruling 5) for a store copy: aliceImported over the inventory entries and journals
// that record this very DER (the SHA-1 alone could name another certificate).
func (s *cleanupState) alice(c storeCopy) bool {
	if c.der == nil {
		return false
	}
	sum := sum256(c.der)
	var imports importsFile
	for _, e := range s.imports.Imports {
		if e.SHA256 == sum {
			imports.Imports = append(imports.Imports, e)
		}
	}
	var journals []journal
	for _, j := range s.journals {
		if j.NewSHA256 == sum {
			journals = append(journals, j)
		}
	}
	return aliceImported(s.h, c.cert, imports, journals)
}

// notAfter is the certificate's expiry from its DER (zero when it does not parse).
func notAfter(der []byte) time.Time {
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		return time.Time{}
	}
	return leaf.NotAfter
}

// sameCert reports an inventory entry or journal naming the certificate of store (ASCII case folded)
// and SHA-1.
func sameCert(store, sha1, otherStore, otherSHA1 string) bool {
	return sha1 == otherSHA1 && asciiLower(store) == asciiLower(otherStore)
}

// since is a certificate's unbound_since from its inventory entries: the latest valid one (entries of
// one certificate are always stamped together), zero when none has one.
func (s *cleanupState) since(store, sha1 string) time.Time {
	var out time.Time
	for _, e := range s.imports.Imports {
		if !sameCert(store, sha1, e.Store, e.SHA1) || e.UnboundSince == "" {
			continue
		}
		if t, err := time.Parse(stampLayout, e.UnboundSince); err == nil && t.After(out) {
			out = t
		}
	}
	return out
}

// cleanupPlan is --plan (W3 Ruling 8): it stamps or clears unbound_since on every certificate Alice
// imported, drops the entries of certificates no store holds, adopts into the inventory those only a
// 0.3.0 journal names, answers the candidates and the watched certificates' verdicts, then prunes.
func cleanupPlan(ctx context.Context, c *call, watch []winproto.CleanupRef) (any, error) {
	s, release, err := openCleanup(ctx, c.host)
	if err != nil {
		return nil, err
	}
	defer release()
	resp := winproto.CleanupPlanResponse{OK: true, Candidates: []winproto.CleanupCandidate{}, Watched: []winproto.CleanupWatched{},
		Warnings: []string{}}
	if s.unreadable {
		resp.Warnings = append(resp.Warnings, winproto.WarnJournalUnreadable)
	}
	next, gone, changed, err := s.planImports(ctx, &resp)
	if err != nil {
		return nil, err
	}
	for _, r := range watch {
		if err := s.judgeWatched(ctx, r, &resp); err != nil {
			return nil, err
		}
	}
	var wctx context.Context
	if changed {
		if wctx, err = c.gate.enter(); err != nil {
			return nil, err
		}
		// An entry whose certificate is gone may be what a kill between a removal's steps left: its
		// bookkeeping is finished first (the chains, then the entry; both idempotent).
		for _, sum := range gone {
			if err := s.clearChains(sum); err != nil {
				return nil, err
			}
		}
		if err := writeImports(s.h, next); err != nil {
			return nil, failed(winproto.CodeIOError, "the import inventory could not be written")
		}
	}
	if resp.Pruned, err = s.prune(wctx, c.gate, &resp); err != nil {
		return nil, err
	}
	return resp, nil
}

// planImports judges every certificate Alice may have imported (inventory entries first, then 0.3.0
// journals whose import was Alice's) and returns the inventory as it must be written and the DER
// SHA-256s of the entries it drops because no store holds their certificate.
func (s *cleanupState) planImports(ctx context.Context, resp *winproto.CleanupPlanResponse) (importsFile, []string, bool, error) {
	type key struct{ store, sha1 string }
	type group struct {
		store, sha1 string
		entries     []int // indexes into s.imports.Imports
	}
	var groups []*group
	byKey := map[key]*group{}
	add := func(store, sha1 string) *group {
		k := key{asciiLower(store), sha1}
		if g := byKey[k]; g != nil {
			return g
		}
		g := &group{store: store, sha1: sha1}
		byKey[k] = g
		groups = append(groups, g)
		return g
	}
	for i, e := range s.imports.Imports {
		g := add(e.Store, e.SHA1)
		g.entries = append(g.entries, i)
	}
	for _, j := range s.journals {
		if j.Existed != nil && !*j.Existed && j.AliceImported {
			add(j.Store, j.NewSHA1)
		}
	}

	entries := slices.Clone(s.imports.Imports)
	drop := map[int]bool{}
	var gone []string
	var adopted []importEntry
	changed := false
	var candidates []winproto.CleanupCandidate
	for _, g := range groups {
		cp, found, err := s.readCopy(ctx, g.store, g.sha1)
		if err != nil {
			return importsFile{}, nil, false, err
		}
		if !found {
			for _, i := range g.entries {
				drop[i], changed = true, true
				if !slices.Contains(gone, entries[i].SHA256) {
					gone = append(gone, entries[i].SHA256)
				}
			}
			continue
		}
		if !s.alice(cp) {
			continue // kept not_alice; its entries stay as they are
		}
		sum := sum256(cp.der)
		if len(g.entries) == 0 {
			// Only a 0.3.0 journal names it (a kill between ImportPFX and the inventory, Ruling 5(b)): the
			// inventory adopts it, so it stays Alice's once that journal is fenced or pruned.
			for _, j := range s.journals {
				if j.Existed != nil && !*j.Existed && j.AliceImported && sameCert(g.store, g.sha1, j.Store, j.NewSHA1) &&
					j.NewSHA256 == sum && aliceFriendlyName(cp.cert.FriendlyName, j.Op) {
					adopted = append(adopted, importEntry{Op: j.Op, Store: j.Store, SHA1: g.sha1, SHA256: sum})
					break
				}
			}
		}
		set := func(v string) {
			for _, i := range g.entries {
				if entries[i].UnboundSince != v {
					entries[i].UnboundSince, changed = v, true
				}
			}
			for i := range adopted {
				if sameCert(g.store, g.sha1, adopted[i].Store, adopted[i].SHA1) {
					adopted[i].UnboundSince, changed = v, true
				}
			}
		}
		if s.inUse(g.sha1) != "" {
			set("") // used: the wait starts over when it is unused again (Ruling 8)
			continue
		}
		since := s.since(g.store, g.sha1)
		if since.IsZero() || since.After(s.now) {
			since = s.now // never stamped, or stamped in the helper's future: a clock that jumped back never shortens the wait
		}
		set(stamp(since))
		cand := winproto.CleanupCandidate{Store: g.store, SHA1: g.sha1, SHA256: sum,
			FriendlyName: cleanValue(cp.cert.FriendlyName, winproto.MaxText), UnboundSince: stamp(since)}
		if na := notAfter(cp.der); !na.IsZero() {
			cand.NotAfter = stamp(na)
			if na.Before(s.now) {
				cand.Eligible = winproto.CleanupExpired
			}
		}
		if cand.Eligible == "" && s.now.Sub(since) >= winproto.CleanupMinAge {
			cand.Eligible = winproto.CleanupAged
		}
		candidates = append(candidates, cand)
	}
	slices.SortFunc(candidates, func(a, b winproto.CleanupCandidate) int {
		return strings.Compare(a.UnboundSince+" "+asciiLower(a.Store)+" "+a.SHA1, b.UnboundSince+" "+asciiLower(b.Store)+" "+b.SHA1)
	})
	if len(candidates) > winproto.MaxCleanupCandidates {
		candidates, resp.Truncated = candidates[:winproto.MaxCleanupCandidates], true
	}
	resp.Candidates = append(resp.Candidates, candidates...)

	out := importsFile{Imports: make([]importEntry, 0, len(entries)+len(adopted))}
	for i, e := range entries {
		if !drop[i] {
			out.Imports = append(out.Imports, e)
		}
	}
	out.Imports = append(out.Imports, adopted...)
	if len(adopted) > 0 {
		changed = true
	}
	if len(out.Imports) > maxImports {
		out.Imports = slices.Clone(out.Imports[len(out.Imports)-maxImports:]) // the oldest go: left alone, the safe side
	}
	return out, gone, changed, nil
}

// judgeWatched adds the verdict on one watched certificate: one for each of watchStores holding it
// (its DER SHA-256 must be the one watched), or one absent.
func (s *cleanupState) judgeWatched(ctx context.Context, r winproto.CleanupRef, resp *winproto.CleanupPlanResponse) error {
	n := len(resp.Watched)
	for _, store := range watchStores {
		cp, found, err := s.readCopy(ctx, store, r.SHA1)
		if err != nil {
			return err
		}
		if !found || cp.der == nil || sum256(cp.der) != r.SHA256 {
			continue
		}
		w := winproto.CleanupWatched{Store: store, SHA1: r.SHA1, SHA256: r.SHA256, State: winproto.WatchRemovable}
		if !s.alice(cp) {
			w.State, w.Reason = winproto.WatchKept, winproto.KeptNotAlice
		} else if reason := s.inUse(r.SHA1); reason != "" {
			w.State, w.Reason = winproto.WatchKept, reason
		}
		resp.Watched = append(resp.Watched, w)
	}
	if len(resp.Watched) == n {
		resp.Watched = append(resp.Watched, winproto.CleanupWatched{SHA1: r.SHA1, SHA256: r.SHA256, State: winproto.WatchAbsent})
	}
	return nil
}

// prunable is a journal pruning removes: its name within journalDir, its file time and, for a CCS
// journal, its CCS fields.
type prunable struct {
	name string
	mod  time.Time
	ccs  *ccsJournal
}

// prune removes old journals (W3 Ruling 11, mirroring cmd/alice-helper's sweepBackups): final ones,
// prepared ones and fence tombstones older than JournalKeep, restore_failed and undecodable ones older
// than JournalRetention; never writing or restoring, never one that was not read, never one a binding
// record still needs; at most MaxPrunePerRun, the oldest first. When the binding records cannot all be
// read nothing is pruned and the plan warns binding_record_unreadable. The gate is entered before the
// first removal (unless the caller did: wctx is then the gate's context). A CCS journal goes after its
// temporary file and its backup (pruneCCS).
func (s *cleanupState) prune(wctx context.Context, g *gate, resp *winproto.CleanupPlanResponse) (int, error) {
	needed, ok := s.recordOps()
	if !ok {
		resp.Warnings = append(resp.Warnings, winproto.WarnBindingRecordUnreadable)
		return 0, nil
	}
	var victims []prunable
	for _, f := range s.files {
		if f.Unread || needed[f.Op] {
			continue
		}
		keep := winproto.JournalKeep
		switch {
		case !f.OK, f.J.Phase == winproto.PhaseRestoreFailed:
			keep = winproto.JournalRetention
		case f.J.Phase == winproto.PhaseWriting, f.J.Phase == winproto.PhaseRestoring:
			continue
		}
		if s.now.Sub(f.File.ModTime) > keep {
			victims = append(victims, prunable{name: f.File.Name, mod: f.File.ModTime, ccs: f.J.CCS})
		}
	}
	slices.SortFunc(victims, func(a, b prunable) int {
		if c := a.mod.Compare(b.mod); c != 0 {
			return c
		}
		return strings.Compare(a.name, b.name)
	})
	if len(victims) > winproto.MaxPrunePerRun {
		victims = victims[:winproto.MaxPrunePerRun]
	}
	pruned := 0
	for _, v := range victims {
		if wctx == nil {
			var err error
			if wctx, err = g.enter(); err != nil {
				return pruned, err
			}
		}
		if v.ccs != nil {
			done, err := s.pruneCCS(wctx, v.ccs)
			if err != nil {
				return pruned, err
			}
			if !done {
				continue
			}
		}
		// StateFile.Name is the name within journalDir; RemoveState takes the state name.
		if err := s.h.RemoveState(journalDir + v.name); err != nil {
			return pruned, failed(winproto.CodeIOError, "a journal could not be removed")
		}
		pruned++
	}
	return pruned, nil
}

// pruneCCS removes what a pruned CCS journal left in the CCS folder (W5 Ruling 16): its temporary file,
// then its backup when it holds the previous file's bytes (other bytes are someone's and stay). done
// is false when the backup cannot be read: the journal then stays for a later plan.
func (s *cleanupState) pruneCCS(ctx context.Context, c *ccsJournal) (done bool, err error) {
	sum, found, err := ccsFileSum(ctx, s.h, c.Path, c.Backup)
	if err != nil {
		return false, nil
	}
	if err := s.h.RemoveCCS(ctx, c.Path, c.Temp); err != nil {
		return false, failed(winproto.CodeIOError, "a temporary file of the CCS folder could not be removed")
	}
	if found && sum == c.PreviousFileSHA256 {
		if err := s.h.RemoveCCS(ctx, c.Path, c.Backup); err != nil {
			return false, failed(winproto.CodeIOError, "a backup of the CCS folder could not be removed")
		}
	}
	return true, nil
}

// recordFileName reports a name of bindingsDir a binding record may have ("<64 hex>.json"); anything
// else (a temporary file of WriteState, a file someone put there) is never read as one.
func recordFileName(name string) bool {
	hash, ok := strings.CutSuffix(name, ".json")
	return ok && validSHA256(hash)
}

// recordOps are the operations the binding records still need: each record's latest operation and,
// through journals that changed nothing (prepared, unchanged, fenced), the operation it falls back to
// (latestOp's walk). ok is false when a binding record cannot be listed, read or decoded: what it
// needs is then unknown.
func (s *cleanupState) recordOps() (map[string]bool, bool) {
	files, err := s.h.ListState(bindingsDir)
	if err != nil {
		return nil, false
	}
	byOp := map[string]journalFile{}
	for _, f := range s.files {
		byOp[f.Op] = f
	}
	needed := map[string]bool{}
	for _, f := range files {
		if !recordFileName(f.Name) {
			continue
		}
		data, found, err := s.h.ReadState(bindingsDir + f.Name)
		if err != nil {
			return nil, false
		}
		if !found {
			continue
		}
		var r bindingRecord
		if decodeState(data, &r) != nil || !r.valid(r.Binding) || bindingRecordName(r.Binding) != bindingsDir+f.Name {
			return nil, false
		}
		op := r.Op
		for range maxRecordChain {
			if op == "" || needed[op] {
				break
			}
			needed[op] = true
			jf, ok := byOp[op]
			if !ok || !jf.OK || !changedNothing(jf.J.Phase) {
				break
			}
			op = jf.J.PrevRecord
		}
	}
	return needed, true
}

// cleanupApply is --apply (W3 Rulings 3, 10): each item judged again now, under the lock; a removable
// one is removed key first, then the binding records' chains naming it, then its inventory entry,
// event 1003. Once the budget has ended no further item is started: the write gate's grace finishes
// the step under way, it never starts another (the answer is OUTCOME_UNKNOWN).
func cleanupApply(ctx context.Context, c *call, items []winproto.CleanupItem) (any, error) {
	s, release, err := openCleanup(ctx, c.host)
	if err != nil {
		return nil, err
	}
	defer release()
	resp := winproto.CleanupApplyResponse{OK: true, Results: make([]winproto.CleanupResult, 0, len(items))}
	var wctx context.Context
	for _, it := range items {
		if wctx != nil && ctx.Err() != nil {
			return nil, failed(winproto.CodeOutcomeUnknown, "the call took too long after the first change")
		}
		res, err := s.judgeItem(ctx, it)
		if err != nil {
			return nil, err
		}
		if res.Result == "" {
			if wctx == nil {
				if wctx, err = c.gate.enter(); err != nil {
					return nil, err
				}
			}
			if res, err = s.remove(wctx, it); err != nil {
				return nil, err
			}
		}
		resp.Results = append(resp.Results, res)
	}
	return resp, nil
}

// judgeItem decides one item now: a result with Result set is final; Result "" means remove it.
func (s *cleanupState) judgeItem(ctx context.Context, it winproto.CleanupItem) (winproto.CleanupResult, error) {
	res := winproto.CleanupResult{SHA256: it.SHA256}
	kept := func(reason string) (winproto.CleanupResult, error) {
		res.Result, res.Reason = winproto.CleanupKept, reason
		return res, nil
	}
	cp, found, err := s.readCopy(ctx, it.Store, it.SHA1)
	switch {
	case err != nil:
		return res, err
	case !found:
		res.Result = winproto.CleanupAbsent
		return res, nil
	case cp.der == nil || sum256(cp.der) != it.SHA256, !s.alice(cp):
		return kept(winproto.KeptNotAlice)
	}
	if reason := s.inUse(it.SHA1); reason != "" {
		return kept(reason)
	}
	switch it.Reason {
	case winproto.CleanupAged:
		since := s.since(it.Store, it.SHA1)
		if since.IsZero() || since.After(s.now) || s.now.Sub(since) < winproto.CleanupMinAge {
			return kept(winproto.KeptTooYoung)
		}
	case winproto.CleanupExpired:
		if na := notAfter(cp.der); na.IsZero() || !na.Before(s.now) {
			return kept(winproto.KeptTooYoung)
		}
	}
	return res, nil // incident: no age (Ruling 9)
}

// remove removes one judged certificate after the gate (Ruling 10 as amended: the chains before the
// entry). Every error is answered OUTCOME_UNKNOWN. A kill after the removal leaves the inventory
// naming a certificate the next plan finds absent; that plan clears the chains naming it and drops
// the entry (both idempotent).
func (s *cleanupState) remove(ctx context.Context, it winproto.CleanupItem) (winproto.CleanupResult, error) {
	removed, err := s.h.RemoveCertificate(ctx, it.Store, it.SHA1)
	if err != nil {
		return winproto.CleanupResult{}, failed(winproto.CodeIOError, "a certificate could not be removed")
	}
	if err := point(s.h, "cleanup.removed"); err != nil {
		return winproto.CleanupResult{}, err
	}
	if err := s.clearChains(it.SHA256); err != nil {
		return winproto.CleanupResult{}, err
	}
	kept := s.imports.Imports[:0:0]
	for _, e := range s.imports.Imports {
		if !sameCert(it.Store, it.SHA1, e.Store, e.SHA1) {
			kept = append(kept, e)
		}
	}
	if len(kept) != len(s.imports.Imports) {
		if err := writeImports(s.h, importsFile{Imports: kept}); err != nil {
			return winproto.CleanupResult{}, failed(winproto.CodeIOError, "the import inventory could not be written")
		}
		s.imports.Imports = kept
	}
	if !removed {
		return winproto.CleanupResult{SHA256: it.SHA256, Result: winproto.CleanupAbsent}, nil
	}
	s.h.Event(eventRemoved, "removed store "+it.Store+" sha1 "+it.SHA1+" sha256 "+it.SHA256+" reason "+it.Reason)
	return winproto.CleanupResult{SHA256: it.SHA256, Result: winproto.CleanupRemoved}, nil
}

// clearChains drops the chain of every binding record that names sum (Ruling 10: the next deployment
// of that certificate makes a same-hash write). A record that cannot be decoded is left alone (no
// deployment uses it either).
func (s *cleanupState) clearChains(sum string) error {
	files, err := s.h.ListState(bindingsDir)
	if err != nil {
		return failed(winproto.CodeIOError, "the binding records could not be listed")
	}
	for _, f := range files {
		if !recordFileName(f.Name) {
			continue
		}
		data, found, err := s.h.ReadState(bindingsDir + f.Name)
		if err != nil {
			return failed(winproto.CodeIOError, "a binding record could not be read")
		}
		var r bindingRecord
		if !found || decodeState(data, &r) != nil || !r.valid(r.Binding) || bindingRecordName(r.Binding) != bindingsDir+f.Name ||
			!slices.Contains(r.Chain, sum) {
			continue
		}
		r.Chain = nil
		if err := writeBindingState(s.h, r); err != nil {
			return failed(winproto.CodeIOError, "a binding record could not be written")
		}
	}
	return nil
}
