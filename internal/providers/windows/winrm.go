package windows

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strconv"
	"strings"

	"alice/internal/providers"
	"alice/internal/providers/linuxssh"
	"alice/internal/providers/tlspin"
	"alice/internal/providers/windows/winproto"
	"alice/internal/providers/windows/winrs"
)

// The WinRM transport (R71): every helper call is one WinRS shell on one TLS connection to the target's listener,
// signed in with NTLMv2 and pinned by the listener's SubjectPublicKeyInfo. The helper runs its forced-command entry
// with the line in SSH_ORIGINAL_COMMAND (Ruling 4), so everything after s.run is the SSH path's.

// The WS-Management fault codes Ruling 13 names: access denied at Create (5, until F31 measures it), and the program
// not found at Command (2, ERROR_FILE_NOT_FOUND, F29).
const (
	faultAccessDenied = 5
	faultFileNotFound = 2
)

// ntlmUser is the account name sent to NTLM (Ruling 6): the local form .\alice without its .\ (go-ntlmssp would send
// "." as the domain); every other form as typed, go-ntlmssp taking the part before the backslash as the domain.
func ntlmUser(username string) string {
	return strings.TrimPrefix(username, `.\`)
}

// winrmRun runs c through WinRS (Rulings 10, 12, 14): one slot of the shared pool, the password read for this call
// only (Ruling 8), the helper with the argument ssh and the line in SSH_ORIGINAL_COMMAND, stdin only in Send. The
// password is released, then the slot, on every path. Errors are mapped by winrmError and keep winrs.ErrNotSent when
// nothing reached the helper.
func (s *session) winrmRun(ctx context.Context, c linuxssh.HelperCommand) (linuxssh.Result, providers.HostKey, error) {
	sub := c.Subcommand()
	slot, err := s.pool.Slot(ctx, s.target)
	if err != nil {
		return linuxssh.Result{}, providers.HostKey{}, markNotSent(err)
	}
	defer slot()
	pw, release, err := s.winrmPassword(ctx)
	if err != nil {
		return linuxssh.Result{}, providers.HostKey{}, winrmPasswordRefusal(ctx, err, sub)
	}
	cl := winrs.Client{TLS: s.pin.TLSConfig(), User: ntlmUser(s.cfg.Username), Password: string(pw)}
	r, err := cl.Run(ctx, winrs.Call{Addr: net.JoinHostPort(s.cfg.Host, strconv.Itoa(s.cfg.Port)), Program: winproto.HelperPath,
		Args: []string{"ssh"}, Env: map[string]string{"SSH_ORIGINAL_COMMAND": c.Line()}, Stdin: c.Input(), Timeout: c.Timeout(),
		MaxOutput: c.MaxOutput()})
	release()
	if err != nil {
		return linuxssh.Result{}, providers.HostKey{}, winrmError(err, s.pin, ctx, sub)
	}
	return linuxssh.Result{Stdout: r.Stdout, ExitCode: r.ExitCode}, providers.TLSIdentity(r.PeerSPKI), nil
}

// winrmPassword is the server's WinRM password for one helper call (Ruling 8), as ccsPassword reads the CCS password:
// providers.ErrNoWinRMPassword for a source that cannot hold one. The caller calls release as soon as the call ends.
func (s *session) winrmPassword(ctx context.Context) (pw []byte, release func(), err error) {
	src, isSource := s.cred.(providers.WinRMPasswordSource)
	if !isSource {
		return nil, nil, providers.ErrNoWinRMPassword
	}
	pt, release, err := src.WinRMPassword(ctx, s.target)
	if err != nil {
		if release != nil {
			release()
		}
		return nil, nil, err
	}
	if release == nil {
		release = pt.Zero
	}
	return pt.Bytes(), release, nil
}

// winrmPasswordRefusal is a call's error when the password could not be read, before any dial (ccsPasswordRefusal's
// table): none set is windows.winrm_password_missing, a password that will never open internal.unexpected, both final;
// the end of ctx is ssh.timeout and any other failure windows.io_error, both retryable.
func winrmPasswordRefusal(ctx context.Context, err error, sub string) error {
	code, retryable := ReasonIOError, true
	switch {
	case errors.Is(err, providers.ErrNoWinRMPassword):
		code, retryable = ReasonWinRMPasswordMissing, false
	case ctx.Err() != nil:
		code = "ssh.timeout"
	case errors.Is(err, providers.ErrWinRMPasswordUnusable):
		code, retryable = reasonUnexpected, false
	}
	return providers.NewError(code, retryable, fmt.Errorf("%w (%w)", err, winrs.ErrNotSent), winrmParams(sub))
}

func winrmParams(sub string) map[string]string {
	return map[string]string{"subcommand": sub, "transport": TransportWinRM}
}

// winrmError maps a failed WinRS call (Ruling 13). Every error carries subcommand and transport=winrm, and keeps the
// winrs error, so winrs.ErrNotSent stays in the chain. A refused identity is the verifier's (the sighting recorded);
// a fault keeps its numeric code only; the helper missing at Command is ssh.helper_missing, which mapHelper names.
func winrmError(err error, v *tlspin.Verifier, ctx context.Context, sub string) error {
	params := winrmParams(sub)
	notSent := errors.Is(err, winrs.ErrNotSent)
	var fe *winrs.FaultError
	code, retryable := "ssh.unreachable", true // netaddr.ErrNotAllowed, the dial, TLS other than the identity
	switch {
	case errors.Is(err, tlspin.ErrIdentityRefused):
		pe := asProviderError(v.Refusal(ctx, err))
		for k, val := range params {
			pe.Params[k] = val
		}
		pe.Cause = errors.Join(pe.Cause, err)
		return pe
	case errors.Is(err, winrs.ErrAuthRefused):
		code, retryable = ReasonWinRMAuthRefused, false
	case errors.As(err, &fe) && notSent && fe.Code == faultAccessDenied:
		code, retryable = ReasonWinRMAuthRefused, false
	case errors.As(err, &fe) && !notSent && fe.Code == faultFileNotFound:
		code, retryable = "ssh.helper_missing", false
	case errors.As(err, &fe):
		code, retryable = ReasonWinRMFault, false
		params["wsman_code"] = strconv.FormatUint(uint64(fe.Code), 10)
	case errors.Is(err, winrs.ErrTimeout):
		code = "ssh.timeout"
	case errors.Is(err, winrs.ErrOutputTooLarge):
		code, retryable = "ssh.output_too_large", false
	case errors.Is(err, winrs.ErrProtocol):
		code, retryable = "ssh.protocol_error", false
	case errors.Is(err, winrs.ErrBadConfig):
		// A call Alice built wrong (port 5985, an empty user or password): never retried, nothing sent.
		code, retryable = reasonUnexpected, false
	}
	return providers.NewError(code, retryable, err, params)
}

// markNotSent adds winrs.ErrNotSent to the chain of an error raised before the command could reach the helper (no
// connection or slot), keeping its provider error on top, so runWrite treats it as a refusal on both transports.
func markNotSent(err error) error {
	pe := asProviderError(err)
	return &providers.Error{Code: pe.Code, Params: pe.Params, Retryable: pe.Retryable, Cause: fmt.Errorf("%w (%w)", err, winrs.ErrNotSent)}
}
