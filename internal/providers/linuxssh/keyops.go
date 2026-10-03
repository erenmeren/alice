package linuxssh

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"slices"
	"strconv"

	"github.com/google/uuid"

	"alice/internal/providers"
	"alice/internal/providers/linuxssh/helperproto"
)

// maxWriteAttempts bounds the re-read-and-retry loop after a concurrent change (spec §13.4).
const maxWriteAttempts = 3

// beforeAuthKeysWrite is a test hook (nil in production): it runs just before every authkeys-write.
var beforeAuthKeysWrite func(path string)

func step(log providers.StepLogger, name string, status string, params map[string]string) {
	if log != nil {
		log.Step(name, providers.StepStatus(status), params)
	}
}

func attemptParams(attempt int) map[string]string {
	return map[string]string{"attempt": strconv.Itoa(attempt)}
}

func failParams(attempt int, err error) map[string]string {
	p := attemptParams(attempt)
	var pe *providers.Error
	if errors.As(err, &pe) {
		p["reason"] = pe.Code
	}
	return p
}

func refusedRequest(field string) error {
	return providers.NewError("ssh.helper_refused", false, nil,
		map[string]string{"helper_code": helperproto.CodeInvalidArgument, "field": field})
}

// writeRefused reports whether err is a definite refusal by the helper (before it touched the
// file): everything except a connection or protocol failure and the helper's own I/O error.
func writeRefused(err error) bool {
	var pe *providers.Error
	if !errors.As(err, &pe) {
		return false
	}
	switch pe.Code {
	case "ssh.keys_managed_elsewhere", "ssh.file_changed":
		return true
	case "ssh.helper_refused":
		return pe.Params["helper_code"] != helperproto.CodeIOError
	}
	return false
}

// checkListedFor refuses a file that does not exist yet unless the helper lists it among the
// candidate files of the requested user: the missing file has no owner to compare, and the write
// would otherwise create another account's file labelled with the wrong user. When the user is not
// listed at all because the helper lists only its first 200 accounts (too_many_users), the refusal
// names that reason instead of the user name.
func (s *session) checkListedFor(ctx context.Context, req providers.AuthKeyChange) error {
	list, err := runHelper[helperproto.AuthKeysListResponse](ctx, s.conn, CmdAuthKeysList())
	if err != nil {
		return err
	}
	for _, u := range list.Users {
		if u.User != req.OSUser {
			continue
		}
		for _, f := range u.Files {
			if f.Path == req.FilePath {
				return nil
			}
		}
		return refusedRequest("os_user")
	}
	if slices.Contains(list.Warnings, helperproto.WarnTooManyUsers) {
		return providers.NewError("ssh.helper_refused", false, nil,
			map[string]string{"helper_code": helperproto.CodeInvalidArgument, "reason": helperproto.WarnTooManyUsers})
	}
	return refusedRequest("os_user")
}

// isUID0 reports whether user is a superuser account: root, or any account the helper lists with
// uid 0 (toor). The last key of such an account needs an administrator's confirmation.
func (s *session) isUID0(ctx context.Context, user string) (bool, error) {
	if user == "root" {
		return true, nil
	}
	list, err := runHelper[helperproto.AuthKeysListResponse](ctx, s.conn, CmdAuthKeysList())
	if err != nil {
		return false, err
	}
	for _, u := range list.Users {
		if u.User == user {
			return u.UID == 0, nil
		}
	}
	return false, nil
}

// transformFailed logs the refusal of the in-memory change as a failed precheck step.
func transformFailed(log providers.StepLogger, attempt int, err error) (providers.AuthKeyResult, bool, error) {
	step(log, "precheck", "failed", failParams(attempt, err))
	return providers.AuthKeyResult{}, false, err
}

// checkOwner refuses a file the helper resolved to another account than the request names: the
// last-key and root guards depend on OSUser being the file's real owner.
func checkOwner(owner, osUser string) error {
	if owner != osUser {
		return refusedRequest("os_user")
	}
	return nil
}

func hexSHA256(b []byte) string {
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:])
}

// checkAddLine refuses, before any remote command, a line that is not exactly one plain key line
// (AddLine rejects controls, bidi overrides and non-UTF-8) or that declares a certificate authority.
func checkAddLine(line string) error {
	ak, _, err := AuthorizedKeys{}.AddLine(line)
	if err != nil || len(ak.Lines) != 1 {
		return refusedRequest("line")
	}
	if hasOption(ak.Lines[0].Options, "cert-authority") {
		return refusedRequest("line")
	}
	return nil
}

// precheck validates the request locally (nothing outside the helper vocabulary is sent), refuses
// a protected key before any remote command, and refuses hosts whose keys come from
// AuthorizedKeysCommand (spec §13.2, §13.4 step 1).
func (s *session) precheck(ctx context.Context, req providers.AuthKeyChange, remove bool) error {
	switch {
	case req.OperationID == uuid.Nil:
		return refusedRequest("operation_id")
	case !helperproto.ValidUser(req.OSUser):
		return refusedRequest("os_user")
	case !helperproto.ValidPath(req.FilePath):
		return refusedRequest("file_path")
	case remove && req.Fingerprint == "":
		return refusedRequest("fingerprint")
	case !remove && req.Line == "":
		return refusedRequest("line")
	}
	if remove {
		// Alice's own key is refused whatever the caller passes (spec §6.6): the connection knows
		// the key it authenticated with.
		if own := s.conn.ClientFingerprint(); own != "" && own == req.Fingerprint {
			return providers.NewError("sshkey.own_key_protected", false, nil, map[string]string{"reason": "protected_fingerprint"})
		}
		for _, p := range req.ProtectedFingerprints {
			if p != "" && p == req.Fingerprint {
				return providers.NewError("sshkey.own_key_protected", false, nil, map[string]string{"reason": "protected_fingerprint"})
			}
		}
	} else if err := checkAddLine(req.Line); err != nil {
		return err
	}
	sum, _, err := s.sshd(ctx)
	if err != nil {
		return err
	}
	if sum.KeysManagedElsewhere {
		return providers.NewError("ssh.keys_managed_elsewhere", false, nil, nil)
	}
	return nil
}

// begin is the first thing every key operation does: the session must be open and the caller
// must not have given up (like Conn.Run: ssh.timeout wrapping the context error).
func (s *session) begin(ctx context.Context) error {
	if err := s.open(); err != nil {
		return err
	}
	if err := ctx.Err(); err != nil {
		return providers.NewError("ssh.timeout", true, err, nil)
	}
	return nil
}

// RemoveAuthorizedKey removes every line of the key's fingerprint from one file. Comment and
// unreadable lines and every other key stay byte-for-byte.
func (s *session) RemoveAuthorizedKey(ctx context.Context, req providers.AuthKeyChange, log providers.StepLogger) (providers.AuthKeyResult, error) {
	if err := s.begin(ctx); err != nil {
		return providers.AuthKeyResult{}, err
	}
	step(log, "precheck", "started", nil)
	if err := s.precheck(ctx, req, true); err != nil {
		step(log, "precheck", "failed", failParams(0, err))
		return providers.AuthKeyResult{}, err
	}
	step(log, "precheck", "ok", nil)
	for attempt := 1; attempt <= maxWriteAttempts; attempt++ {
		res, retry, err := s.removeOnce(ctx, req, log, attempt)
		if !retry {
			return res, err
		}
	}
	return providers.AuthKeyResult{}, providers.NewError("ssh.file_changed", true, nil,
		map[string]string{"attempts": strconv.Itoa(maxWriteAttempts)})
}

func (s *session) removeOnce(ctx context.Context, req providers.AuthKeyChange, log providers.StepLogger, attempt int) (providers.AuthKeyResult, bool, error) {
	step(log, "read", "started", attemptParams(attempt))
	content, h0, owner, exists, err := s.readFileOwner(ctx, req.FilePath)
	if err != nil {
		step(log, "read", "failed", failParams(attempt, err))
		return providers.AuthKeyResult{}, false, err
	}
	step(log, "read", "ok", attemptParams(attempt))
	if !exists {
		return providers.AuthKeyResult{OldSHA256: helperproto.AbsentSHA256, NewSHA256: helperproto.AbsentSHA256}, false, nil
	}
	if err := checkOwner(owner, req.OSUser); err != nil {
		return transformFailed(log, attempt, err)
	}
	ak, err := ParseAuthorizedKeys(content)
	if err != nil {
		return transformFailed(log, attempt, providers.NewError("sshkey.not_removable", false, err,
			map[string]string{"reason": "file_too_large"}))
	}
	for _, l := range ak.Lines {
		if l.Kind == LineKey && l.Fingerprint == req.Fingerprint && hasOption(l.Options, "cert-authority") {
			return transformFailed(log, attempt, providers.NewError("sshkey.not_removable", false, nil,
				map[string]string{"reason": "cert_authority"}))
		}
	}
	next, removed := ak.RemoveFingerprint(req.Fingerprint)
	if removed == 0 {
		return providers.AuthKeyResult{OldSHA256: h0, NewSHA256: h0}, false, nil
	}
	if next.CountKeys() == 0 {
		if req.OSUser == s.cfg.Username {
			return transformFailed(log, attempt, providers.NewError("sshkey.own_key_protected", false, nil,
				map[string]string{"reason": "last_key_of_connection_account"}))
		}
		if !req.AllowLastRootKey {
			uid0, err := s.isUID0(ctx, req.OSUser)
			if err != nil {
				return transformFailed(log, attempt, err)
			}
			if uid0 {
				return transformFailed(log, attempt, providers.NewError("sshkey.last_root_key", false, nil, nil))
			}
		}
	}
	return s.writeAndVerify(ctx, req, log, attempt, h0, next.Bytes(), removed)
}

// AddAuthorizedKey appends one key line (on its own line, also when the file lacks a trailing
// newline); a key already present by fingerprint changes nothing.
func (s *session) AddAuthorizedKey(ctx context.Context, req providers.AuthKeyChange, log providers.StepLogger) (providers.AuthKeyResult, error) {
	if err := s.begin(ctx); err != nil {
		return providers.AuthKeyResult{}, err
	}
	step(log, "precheck", "started", nil)
	if err := s.precheck(ctx, req, false); err != nil {
		step(log, "precheck", "failed", failParams(0, err))
		return providers.AuthKeyResult{}, err
	}
	step(log, "precheck", "ok", nil)
	for attempt := 1; attempt <= maxWriteAttempts; attempt++ {
		res, retry, err := s.addOnce(ctx, req, log, attempt)
		if !retry {
			return res, err
		}
	}
	return providers.AuthKeyResult{}, providers.NewError("ssh.file_changed", true, nil,
		map[string]string{"attempts": strconv.Itoa(maxWriteAttempts)})
}

func (s *session) addOnce(ctx context.Context, req providers.AuthKeyChange, log providers.StepLogger, attempt int) (providers.AuthKeyResult, bool, error) {
	step(log, "read", "started", attemptParams(attempt))
	content, h0, owner, exists, err := s.readFileOwner(ctx, req.FilePath)
	if err != nil {
		step(log, "read", "failed", failParams(attempt, err))
		return providers.AuthKeyResult{}, false, err
	}
	step(log, "read", "ok", attemptParams(attempt))
	if exists {
		if err := checkOwner(owner, req.OSUser); err != nil {
			return transformFailed(log, attempt, err)
		}
	} else if err := s.checkListedFor(ctx, req); err != nil {
		return transformFailed(log, attempt, err)
	}
	ak, err := ParseAuthorizedKeys(content)
	if err != nil {
		return transformFailed(log, attempt, providers.NewError("sshkey.not_removable", false, err,
			map[string]string{"reason": "file_too_large"}))
	}
	next, added, err := ak.AddLine(req.Line)
	if err != nil {
		return transformFailed(log, attempt, refusedRequest("line"))
	}
	if !added {
		return providers.AuthKeyResult{OldSHA256: h0, NewSHA256: h0}, false, nil
	}
	return s.writeAndVerify(ctx, req, log, attempt, h0, next.Bytes(), 0)
}

// writeAndVerify writes newContent if the file still has hash h0, then reads it back. retry is
// true only when the helper refused the write because the file changed (nothing was written).
func (s *session) writeAndVerify(ctx context.Context, req providers.AuthKeyChange, log providers.StepLogger,
	attempt int, h0 string, newContent []byte, removed int) (providers.AuthKeyResult, bool, error) {
	step(log, "write", "started", attemptParams(attempt))
	cmd, err := CmdAuthKeysWrite(req.FilePath, h0, req.OperationID, newContent)
	if err != nil {
		err = refusedRequest("content")
		step(log, "write", "failed", failParams(attempt, err))
		return providers.AuthKeyResult{}, false, err
	}
	if beforeAuthKeysWrite != nil {
		beforeAuthKeysWrite(req.FilePath)
	}
	wr, err := runHelper[helperproto.AuthKeysWriteResponse](ctx, s.conn, cmd)
	var pe *providers.Error
	if errors.As(err, &pe) && pe.Code == "ssh.file_changed" {
		step(log, "write", "failed", failParams(attempt, err))
		return providers.AuthKeyResult{}, true, err
	}
	want := hexSHA256(newContent)
	res := providers.AuthKeyResult{Changed: true, Removed: removed, OldSHA256: h0, NewSHA256: want}
	if err != nil {
		step(log, "write", "failed", failParams(attempt, err))
		if writeRefused(err) {
			return providers.AuthKeyResult{}, false, err // the helper refused: nothing was written
		}
		// The outcome is uncertain (the write may have happened): the caller must not retry blindly.
		return res, false, err
	}
	res.Backup = cleanValue(wr.Backup, 200)
	if wr.Owner != req.OSUser {
		// The file now belongs to another account than the request named: report it as a partial
		// result, never retried.
		err := providers.NewError("ssh.protocol_error", false, errors.New("linuxssh: the helper wrote another account's file"),
			map[string]string{"subcommand": helperproto.SubAuthKeysWrite, "field": "owner"})
		step(log, "write", "failed", failParams(attempt, err))
		return res, false, err
	}
	if wr.SHA256 != want {
		// The helper wrote something else than asked: the outcome is uncertain, never retried.
		err := providers.NewError("ssh.protocol_error", false, errors.New("linuxssh: written hash differs from the requested one"),
			map[string]string{"subcommand": helperproto.SubAuthKeysWrite})
		step(log, "write", "failed", failParams(attempt, err))
		return res, false, err
	}
	step(log, "write", "ok", attemptParams(attempt))
	step(log, "verify", "started", attemptParams(attempt))
	_, got, exists, err := s.readFile(ctx, req.FilePath)
	if err != nil {
		step(log, "verify", "failed", failParams(attempt, err))
		return res, false, err
	}
	res.Verified = exists && got == want
	if res.Verified {
		step(log, "verify", "ok", attemptParams(attempt))
	} else {
		step(log, "verify", "failed", map[string]string{"attempt": strconv.Itoa(attempt), "reason": "content_differs"})
	}
	return res, false, nil
}
