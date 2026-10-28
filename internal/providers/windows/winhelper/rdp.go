package winhelper

// The Remote Desktop subcommands (W6, R69): rdp-dump reads the RDP-Tcp listener and its current
// certificate; rdp-deploy sets the listener's certificate under the W2 journal, with a NETWORK SERVICE
// read grant on the new certificate's key. The listener, the value, the SID and the import store are
// the host's constants or this file's: no input names one (Rulings 8 and 10, WN-24).

import (
	"context"
	"crypto/x509"
	"encoding/base64"
	"slices"
	"strconv"

	"alice/internal/providers/windows/winproto"
)

// eventRDPSet is the Application event of an RDP certificate set (Global Constraints).
const eventRDPSet uint32 = 1005

// rdpCurrent reads the listener's current certificate by Ruling 4: the one the value names in My, or,
// while the value is absent, the single certificate of Remote Desktop. cur is nil when there is none,
// with its Store set to the store it was read from; count is how many certificates Remote Desktop holds
// (at most 2; 0 while the value is set, when that store is not read).
func rdpCurrent(ctx context.Context, h WriteHost, l RDPListener) (cur *winproto.StoreCertificate, count int, err error) {
	if l.CertSHA1 != "" {
		if !winproto.ValidSHA1(l.CertSHA1) {
			return nil, 0, nil
		}
		c, found, err := h.Certificate(ctx, defaultStore, l.CertSHA1)
		if err != nil || !found {
			return nil, 0, err
		}
		c.Store, c.SHA1 = defaultStore, l.CertSHA1
		return &c, 0, nil
	}
	certs, err := h.StoreCertificates(ctx, winproto.RDPStoreSelfSigned, 2)
	if err != nil {
		return nil, 0, err
	}
	if len(certs) != 1 {
		return nil, min(len(certs), 2), nil
	}
	c := certs[0]
	c.Store = winproto.RDPStoreSelfSigned
	return &c, 1, nil
}

// cmdRDPDump answers "rdp-dump" (elevated, no lock, no input; W6 Rulings 4, 5, 18): the listener's
// effective settings and its current certificate. A certificate the helper cannot send fails the dump
// (Alice then keeps what it knows and marks nothing missing).
func cmdRDPDump(ctx context.Context, c *call) (any, error) {
	if len(c.args) != 0 {
		return nil, refused(winproto.CodeUsage, "rdp-dump takes no arguments")
	}
	h := c.host
	l, err := h.RDPListener(ctx)
	if err != nil {
		return nil, failed(winproto.CodeIOError, "the Remote Desktop settings could not be read")
	}
	d := winproto.RDPDumpResponse{OK: true}
	if !l.Present {
		return d, nil
	}
	d.Present, d.Enabled, d.NLA, d.ValueSet, d.Port, d.SecurityLayer = true, l.Enabled, l.NLA, l.CertSHA1 != "", l.Port, l.SecurityLayer
	d.CertTemplate = cleanValue(l.CertTemplate, winproto.MaxText)
	cur, count, err := rdpCurrent(ctx, h, l)
	if err != nil {
		return nil, certError(err)
	}
	d.SelfSignedCount = count
	if cur != nil {
		cc, ok := cleanCertificate(*cur, cur.Store, cur.SHA1)
		if !ok || !winproto.ValidSHA1(cc.SHA1) {
			return nil, failed(winproto.CodeIOError, "a certificate could not be read")
		}
		certs := []winproto.StoreCertificate{cc}
		markAliceImported(h, certs)
		d.Certificate = &certs[0]
	}
	if ctx.Err() != nil {
		return nil, failed(winproto.CodeIOError, "the call took too long")
	}
	return d, nil
}

// cmdRDPDeploy answers "rdp-deploy --op <id>" with a winproto.RDPDeployInput on stdin (W6 Ruling 9):
// the W2 transaction with the steps grant_key_read and set_listener in place of the bind. Every refusal
// comes before gate.enter and changed nothing; the first durable write is the prepared journal, and
// after it the answer is the operation's phase (or OUTCOME_UNKNOWN, settle).
func cmdRDPDeploy(ctx context.Context, c *call) (any, error) {
	op, err := opArg(c.args, winproto.SubRDPDeploy)
	if err != nil {
		return nil, err
	}
	sec := newSecrets()
	defer sec.clear()
	req, err := parseRDPDeployInput(c.input, sec)
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
	if err := point(h, "rdp.locked"); err != nil {
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
	switch pending, err := interruptedLatest(h, winproto.RDPCanonical, op); {
	case err != nil:
		return nil, failed(winproto.CodeIOError, "the record of the listener's latest operation cannot be read")
	case pending != "":
		return nil, recoveryPending(pending)
	}
	rec, err := readBindingState(h, winproto.RDPCanonical)
	if err != nil {
		return nil, failed(winproto.CodeIOError, "the record of the listener's latest operation cannot be read")
	}

	l, err := h.RDPListener(ctx)
	switch {
	case err != nil:
		return nil, failed(winproto.CodeIOError, "the Remote Desktop settings could not be read")
	case !l.Present:
		return nil, precondition(winproto.CodeBindingNotFound, "the Remote Desktop listener RDP-Tcp does not exist")
	case !l.Enabled:
		return nil, precondition(winproto.CodeRDPDisabled, "Remote Desktop is turned off")
	case l.SecurityLayer == 0:
		return nil, precondition(winproto.CodeRDPTLSOff, "the Remote Desktop listener does not use TLS")
	}
	cur, _, err := rdpCurrent(ctx, h, l)
	if err != nil {
		return nil, certError(err)
	}
	var prevDER []byte
	if cur != nil {
		if prevDER, err = base64.StdEncoding.DecodeString(cur.DER); err != nil {
			prevDER = nil
		}
	}
	mismatch := precondition(winproto.CodeHashMismatch, "the Remote Desktop listener names another certificate than expected")
	if prevDER == nil || sum256(prevDER) != req.expect {
		return nil, mismatch
	}
	prev, err := x509.ParseCertificate(prevDER)
	if err != nil {
		return nil, mismatch
	}
	newSHA1, newSHA256 := sum1(in.leaf.Raw), sum256(in.leaf.Raw)
	copyOf, exists, err := h.Certificate(ctx, defaultStore, newSHA1)
	switch {
	case err != nil:
		return nil, certError(err)
	case exists && (!copyOf.HasKey || copyOf.KeyProblem != ""):
		return nil, precondition(winproto.CodeKeyUnusable, "the certificate is in the store without a usable key")
	case exists && (copyOf.KeyExportable || copyOf.ExportPolicyUnknown):
		// Security review I1: NETWORK SERVICE never gets read access to a key that can be exported (WN-23).
		return nil, precondition(winproto.CodeKeyUnusable,
			"the certificate is in the store with a private key that is exportable or whose export policy cannot be read")
	}
	prevStore := defaultStore
	if l.CertSHA1 == "" {
		prevStore = winproto.RDPStoreSelfSigned
	}
	prevRecord := rec.Op
	if prevRecord == op {
		prevRecord = ""
	}

	wctx, err := c.gate.enter()
	if err != nil {
		return nil, err
	}
	t := &deployTx{ctx: wctx, h: h, j: journal{Op: op, Phase: winproto.PhasePrepared, Kind: winproto.JournalKindRDP, Binding: winproto.RDPCanonical,
		PreviousSHA1: sum1(prevDER), PreviousSHA256: req.expect, NewSHA1: newSHA1, NewSHA256: newSHA256, Store: defaultStore,
		Intermediates: []certRef{}, AliceImported: !exists, Existed: &exists, PrevRecord: prevRecord, Steps: []winproto.Step{},
		ForbiddenSPKI: req.spki, ForbiddenLeaf: req.leaf,
		RDP: &rdpJournal{PreviousStore: prevStore, PreviousAbsent: l.CertSHA1 == "",
			PreviousSPKISHA256: spkiSHA256(prev.PublicKey, prev.RawSubjectPublicKeyInfo)}},
		served: rec.Chain, chain: chainOf(in)}
	return t.runRDP(in, sec, l.CertSHA1)
}

// runRDP is rdp-deploy after its gate (Ruling 9 steps 4-8): every outcome is recorded in the journal.
// current is the value the listener named before the gate. The only machine writes are W2's imports,
// the one ACE on the key of the certificate the listener gets (My, the new SHA-1) and the one value.
func (t *deployTx) runRDP(in content, sec *secrets, current string) (any, error) {
	h, j := t.h, &t.j
	if err := writeJournal(h, *j); err != nil {
		return nil, err
	}
	// The listener's record names this operation from the prepared journal on, as a binding record does.
	if err := writeBindingRecord(h, j.Binding, j.Op); err != nil {
		return nil, err
	}
	if err := point(h, "rdp.prepared"); err != nil {
		return nil, err
	}
	if !t.importChain(in) {
		return t.failUnbound(winproto.StepImportChain, winproto.ErrStore)
	}
	if err := t.write("rdp.import_chain"); err != nil {
		return nil, err
	}
	if class := t.importCertificate(in, sec); class != "" {
		return t.failUnbound(winproto.StepImportCertificate, class)
	}
	sec.clear() // nothing of the key is needed any more
	j.Steps = append(j.Steps, stepOK(winproto.StepImportCertificate))
	if err := t.write("rdp.import_certificate"); err != nil {
		return nil, err
	}
	if c, found, err := h.Certificate(t.ctx, j.Store, j.NewSHA1); err == nil && found {
		t.built = 1 + len(c.Chain)
	}

	// grant_key_read (Ruling 10): whether NETWORK SERVICE can read the key goes into the journal first.
	had, err := h.RDPKeyRead(t.ctx, j.Store, j.NewSHA1)
	if err != nil {
		return t.failUnbound(winproto.StepGrantKeyRead, winproto.ErrKeyACL)
	}
	r := *j.RDP
	r.KeyReadHad = &had
	j.RDP = &r
	if !had {
		// Ruling 12: the journal says writing (with key_read_had false) before the ACE exists, so a kill
		// after the grant leaves an operation iis-restore rolls back and revokes, never a prepared one a
		// fence would tombstone with the ACE in place.
		j.Phase = winproto.PhaseWriting
		if err := writeJournal(h, *j); err != nil {
			return nil, err
		}
		if err := h.SetRDPKeyRead(t.ctx, j.Store, j.NewSHA1, true); err != nil {
			// Whatever part of the grant was done is taken back (only ACEs of the grant's own mask, so a
			// NETWORK SERVICE ACE the key held before stays); the listener is untouched.
			r.ACLLeft = revokeKeyRead(t.ctx, h, j.Store, j.NewSHA1)
			return t.failUnbound(winproto.StepGrantKeyRead, winproto.ErrKeyACL)
		}
		if err := point(h, "rdp.granted"); err != nil {
			return nil, err
		}
	}
	j.Steps = append(j.Steps, stepOK(winproto.StepGrantKeyRead))
	if err := t.write("rdp.grant_key_read"); err != nil {
		return nil, err
	}

	// Ruling 14: unchanged only when the listener names the new certificate, NETWORK SERVICE could read
	// its key, no intermediate was added and the record's chain is this deployment's (W2 Ruling 10).
	if current == j.NewSHA1 && had && len(j.Intermediates) == 0 && slices.Equal(t.served, t.chain) {
		if err := writeBindingState(h, bindingRecord{Binding: j.Binding, Op: j.Op, Chain: t.served}); err != nil {
			return nil, err
		}
		j.Phase = winproto.PhaseUnchanged
		if err := writeJournal(h, *j); err != nil {
			return nil, err
		}
		return t.answer(), nil
	}

	// Ruling 14 amended (F20): a same-value rewrite does not make Schannel rebuild the served chain;
	// deleting the value and setting it again does. The writing journal records the rebuild before the
	// delete, so a restore reads an absent value as this operation's interrupted rebuild.
	rebuild := current == j.NewSHA1
	if rebuild {
		r := *j.RDP
		r.Rebuild = true
		j.RDP = &r
	}
	j.Phase = winproto.PhaseWriting
	if err := t.write("rdp.writing"); err != nil {
		return nil, err
	}
	if rebuild {
		if err := h.SetRDPCertificate(t.ctx, ""); err != nil {
			return t.selfRestore(winproto.StepSetListener, winproto.ErrIO)
		}
		if err := point(h, "rdp.deleted"); err != nil {
			return nil, err
		}
	}
	if err := h.SetRDPCertificate(t.ctx, j.NewSHA1); err != nil {
		return t.selfRestore(winproto.StepSetListener, winproto.ErrIO)
	}
	if err := point(h, "rdp.set"); err != nil {
		return nil, err
	}
	if l, err := h.RDPListener(t.ctx); err != nil || !l.Present || l.CertSHA1 != j.NewSHA1 {
		return t.selfRestore(winproto.StepSetListener, winproto.ErrReadBack)
	}
	if err := point(h, "rdp.read_back"); err != nil {
		return nil, err
	}
	j.Steps = append(j.Steps, stepOK(winproto.StepSetListener))
	j.Phase = winproto.PhaseCommitted
	if err := writeJournal(h, *j); err != nil {
		// The journal must not say writing while the answer says committed: roll back.
		j.Phase = winproto.PhaseWriting
		return t.selfRestore(winproto.StepJournal, winproto.ErrIO)
	}
	// Best effort: without the chain the next deployment of this certificate writes once more.
	_ = writeBindingState(h, bindingRecord{Binding: j.Binding, Op: j.Op, Chain: t.chain})
	if err := point(h, "rdp.committed"); err != nil {
		return nil, err
	}
	h.Event(eventRDPSet, "operation "+j.Op+" rdp "+winproto.RDPListenerName+" old "+j.PreviousSHA256+" new "+j.NewSHA256+
		" key_read_granted "+strconv.FormatBool(!had))
	return t.answer(), nil
}
