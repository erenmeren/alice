package winhelper

import (
	"context"

	"alice/internal/providers/windows/winproto"
)

// cmdIISStatus answers "iis-status --op <id>": the operation's journal (phase none when there is
// none) and whether another process holds the helper lock now (Active). It takes no lock and changes
// nothing (design §6.5, the Linux semantics).
func cmdIISStatus(ctx context.Context, c *call) (any, error) {
	op, err := opArg(c.args, winproto.SubIISStatus)
	if err != nil {
		return nil, err
	}
	resp := winproto.StatusResponse{OK: true, Phase: winproto.PhaseNone, Active: c.host.LockHeld()}
	j, found, err := readJournal(c.host, op)
	switch {
	case err != nil:
		return nil, failed(winproto.CodeIOError, "the journal of this operation cannot be read")
	case !found:
		return resp, nil
	}
	return statusOf(ctx, c.host, j, resp), nil
}

// statusOf fills a status answer from a journal; CurrentCertSHA256 is the DER SHA-256 of what the
// binding names now ("" when it cannot be read or its store lacks it; a tombstone names no binding),
// of the leaf a CCS file holds, or of the certificate the RDP listener names.
func statusOf(ctx context.Context, h WriteHost, j journal, resp winproto.StatusResponse) winproto.StatusResponse {
	resp.Phase, resp.NewCertSHA256 = j.Phase, j.NewSHA256
	resp.FailedStep, resp.CauseStep, resp.Error = j.FailedStep, j.CauseStep, j.Error
	if j.Phase == winproto.PhaseFenced {
		return resp
	}
	if c := j.CCS; c != nil {
		// A CCS file names its leaf by its bytes (W5 Ruling 15): the new leaf, the previous one, else "".
		switch sum, found, err := ccsFileSum(ctx, h, c.Path, c.File); {
		case err != nil || !found:
		case sum == c.NewFileSHA256:
			resp.CurrentCertSHA256 = j.NewSHA256
		case sum == c.PreviousFileSHA256:
			resp.CurrentCertSHA256 = j.PreviousSHA256
		}
		return resp
	}
	if j.RDP != nil {
		// The listener names its certificate by its value (W6 Ruling 11): the new leaf, the previous one
		// (the self-signed certificate while the value is absent, when it was), else "".
		// An interrupted rebuild's absent value names the new leaf, as the restore reads it (rdpNamesNew).
		if l, err := h.RDPListener(ctx); err == nil && l.Present {
			switch {
			case rdpNamesNew(j, l.CertSHA1):
				resp.CurrentCertSHA256 = j.NewSHA256
			case l.CertSHA1 == rdpPreviousValue(j):
				resp.CurrentCertSHA256 = j.PreviousSHA256
			}
		}
		return resp
	}
	if cur, found, err := h.Binding(ctx, j.Locator); err == nil && found {
		if der, _, found, err := storeCert(ctx, h, storeOf(cur), cur.CertSHA1); err == nil && found && der != nil {
			resp.CurrentCertSHA256 = sum256(der)
		}
	}
	return resp
}

// cmdIISFence fences an operation ("iis-fence --op <id>", the Linux semantics of nginx-fence) under the
// helper lock, so no iis-deploy runs meanwhile:
//
//	no journal          a tombstone (phase fenced) is written; answer fenced
//	fenced              nothing changes; answer fenced
//	prepared            the binding record is handed back to the operation before it, the tombstone
//	                    replaces the journal; answer fenced (nothing of the record was changed)
//	any other phase     nothing changes; the answer is iis-status's
//
// A later iis-deploy of a fenced operation is FENCED. Active is false (the fence holds the lock).
func cmdIISFence(ctx context.Context, c *call) (any, error) {
	op, err := opArg(c.args, winproto.SubIISFence)
	if err != nil {
		return nil, err
	}
	h := c.host
	release, err := lockHelper(ctx, h)
	if err != nil {
		return nil, err
	}
	defer release()
	resp := winproto.StatusResponse{OK: true, Phase: winproto.PhaseFenced}
	j, found, err := readJournal(h, op)
	if err != nil {
		return nil, failed(winproto.CodeIOError, "the journal of this operation cannot be read")
	}
	tomb := journal{Op: op, Phase: winproto.PhaseFenced}
	if found {
		switch j.Phase {
		case winproto.PhaseFenced:
			return resp, nil
		case winproto.PhasePrepared:
			tomb.PrevRecord = j.PrevRecord
		default:
			return statusOf(ctx, h, j, winproto.StatusResponse{OK: true}), nil
		}
	}
	if _, err := c.gate.enter(); err != nil {
		return nil, err
	}
	if found {
		// The record goes back first, so a crash before the tombstone leaves a consistent prepared one.
		if err := handBack(h, j); err != nil {
			return nil, err
		}
	}
	if err := writeJournal(h, tomb); err != nil {
		return nil, err
	}
	return resp, nil
}
