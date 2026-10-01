package linuxssh

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
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

func hexSHA256(b []byte) string {
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:])
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
		for _, p := range req.ProtectedFingerprints {
			if p != "" && p == req.Fingerprint {
				return providers.NewError("sshkey.own_key_protected", false, nil, map[string]string{"reason": "protected_fingerprint"})
			}
		}
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
	content, h0, exists, err := s.readFile(ctx, req.FilePath)
	if err != nil {
		step(log, "read", "failed", failParams(attempt, err))
		return providers.AuthKeyResult{}, false, err
	}
	step(log, "read", "ok", attemptParams(attempt))
	if !exists {
		return providers.AuthKeyResult{OldSHA256: helperproto.AbsentSHA256, NewSHA256: helperproto.AbsentSHA256}, false, nil
	}
	ak, err := ParseAuthorizedKeys(content)
	if err != nil {
		return providers.AuthKeyResult{}, false, providers.NewError("sshkey.not_removable", false, err,
			map[string]string{"reason": "file_too_large"})
	}
	for _, l := range ak.Lines {
		if l.Kind == LineKey && l.Fingerprint == req.Fingerprint && hasOption(l.Options, "cert-authority") {
			return providers.AuthKeyResult{}, false, providers.NewError("sshkey.not_removable", false, nil,
				map[string]string{"reason": "cert_authority"})
		}
	}
	next, removed := ak.RemoveFingerprint(req.Fingerprint)
	if removed == 0 {
		return providers.AuthKeyResult{OldSHA256: h0, NewSHA256: h0}, false, nil
	}
	if next.CountKeys() == 0 {
		if req.OSUser == s.cfg.Username {
			return providers.AuthKeyResult{}, false, providers.NewError("sshkey.own_key_protected", false, nil,
				map[string]string{"reason": "last_key_of_connection_account"})
		}
		if req.OSUser == "root" && !req.AllowLastRootKey {
			return providers.AuthKeyResult{}, false, providers.NewError("sshkey.last_root_key", false, nil, nil)
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
	content, h0, _, err := s.readFile(ctx, req.FilePath)
	if err != nil {
		step(log, "read", "failed", failParams(attempt, err))
		return providers.AuthKeyResult{}, false, err
	}
	step(log, "read", "ok", attemptParams(attempt))
	ak, err := ParseAuthorizedKeys(content)
	if err != nil {
		return providers.AuthKeyResult{}, false, providers.NewError("sshkey.not_removable", false, err,
			map[string]string{"reason": "file_too_large"})
	}
	next, added, err := ak.AddLine(req.Line)
	if err != nil {
		return providers.AuthKeyResult{}, false, refusedRequest("line")
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
		step(log, "write", "failed", attemptParams(attempt))
		return providers.AuthKeyResult{}, false, refusedRequest("content")
	}
	if beforeAuthKeysWrite != nil {
		beforeAuthKeysWrite(req.FilePath)
	}
	_, err = runHelper[helperproto.AuthKeysWriteResponse](ctx, s.conn, cmd)
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
