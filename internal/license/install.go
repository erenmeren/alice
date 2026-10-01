package license

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"strconv"
	"strings"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"alice/internal/audit"
	"alice/internal/platform/db"
)

// UploadResult describes an uploaded (or previewed) license.
type UploadResult struct {
	Payload        Payload
	KeyID          string
	Correction     bool  // replaces is set (R7)
	Pending        bool  // valid_from is still ahead (L-48)
	AlreadyExpired bool  // valid_until has passed; stored anyway (L-32, R36 item 8)
	Duplicate      bool  // this license is already installed; nothing changed
	Phase          Phase // the phase after the upload
}

// contentHash identifies a license independent of JSON formatting.
func contentHash(f File) []byte {
	h := sha256.New()
	h.Write(SignedBytes(f.Payload))
	h.Write(f.Signature)
	return h.Sum(nil)
}

// checkUpload runs spec §16.3 steps 1-5 on an upload against the started installation.
func (s *Service) checkUpload(raw []byte) (File, error) {
	return s.checkFile(raw, s.Snapshot().InstallationID)
}

// judge applies the replacement rules of §16.3 against the installed files: a duplicate is
// reported; a license older than the one in force (earlier issued_at) is refused unless it
// lasts longer (later valid_until) or is a correction (04-security.md §16.3).
func judge(f File, c computed, reading Reading) (UploadResult, error) {
	now := reading.Effective
	res := UploadResult{
		Payload:        f.Payload,
		KeyID:          f.KeyID,
		Correction:     f.Payload.Replaces != "",
		Pending:        f.Payload.ValidFrom.After(now),
		AlreadyExpired: !now.Before(f.Payload.ValidUntil),
		Phase:          c.snap.Eval.Phase,
	}
	hash := contentHash(f)
	for _, sf := range c.files {
		if bytes.Equal(sf.SHA256, hash) {
			res.Duplicate = true
			return res, nil
		}
	}
	if cur := c.snap.Eval.Current; cur != nil && !res.Correction &&
		f.Payload.IssuedAt.Before(cur.IssuedAt) && !f.Payload.ValidUntil.After(cur.ValidUntil) {
		return UploadResult{}, ErrOlderThanInstalled
	}
	all := append(append([]Installed(nil), c.installed...), Installed{Seq: nextSeq(c.files), KeyID: f.KeyID, Payload: f.Payload})
	res.Phase = evaluateInstallation(now, c.row, all).Phase
	return res, nil
}

func nextSeq(files []storedFile) int64 {
	if n := len(files); n > 0 {
		return files[n-1].Seq + 1
	}
	return 1
}

// Preview checks an upload exactly like Install and says what it would do, storing nothing.
func (s *Service) Preview(ctx context.Context, raw []byte) (UploadResult, error) {
	f, err := s.checkUpload(raw)
	if err != nil {
		return UploadResult{}, err
	}
	s.mu.Lock()
	_, _, jumpHeld := s.guard.PendingJump()
	s.mu.Unlock()
	reading := s.peek(jumpHeld && f.Payload.Replaces != "")
	c, err := s.compute(ctx, s.pool, reading, false)
	if err != nil {
		return UploadResult{}, err
	}
	return judge(f, c, reading)
}

// Install stores an uploaded license and puts it into effect at once (spec §16.3 step 7, §19.1).
// Uploads are serialized by the license row lock. A rejected upload is recorded in the history
// and the audit log ("license.upload.<reason>") and leaves the installed license untouched.
// by is the uploading user (uuid.Nil for none).
func (s *Service) Install(ctx context.Context, raw []byte, actor audit.Actor, by uuid.UUID) (UploadResult, error) {
	res, err := s.install(ctx, raw, actor, by)
	if err != nil {
		if isRejection(err) {
			s.recordRejection(ctx, actor, err)
		}
		return UploadResult{}, err
	}
	if !res.Duplicate {
		if s.uploadCommitted != nil {
			s.uploadCommitted()
		}
		// The upload has committed, so its evaluation no longer depends on the request: a
		// client that disconnects now must not leave the gate on the old state for an hour.
		// The next hourly evaluation repeats what this one misses.
		if err := s.Tick(context.WithoutCancel(ctx)); err != nil {
			s.log.Error("the evaluation after a license upload failed; the license is stored and the next evaluation applies it",
				"license_id", res.Payload.LicenseID, "error_type", fmt.Sprintf("%T", err))
		}
	}
	return res, nil
}

func isRejection(err error) bool {
	for _, e := range []error{ErrInvalid, ErrUnsupportedFormat, ErrUnknownKey, ErrRevokedKey, ErrWrongInstallation, ErrOlderThanInstalled} {
		if errors.Is(err, e) {
			return true
		}
	}
	return false
}

func (s *Service) install(ctx context.Context, raw []byte, actor audit.Actor, by uuid.UUID) (UploadResult, error) {
	f, err := s.checkUpload(raw)
	if err != nil {
		return UploadResult{}, err
	}
	var res UploadResult
	s.evalMu.Lock()
	defer s.evalMu.Unlock()
	g := s.working()
	err = db.InTx(ctx, s.pool, func(tx pgx.Tx) error {
		if _, err := s.loadInstallation(ctx, tx, true); err != nil {
			return err
		}
		// Under the row lock: a correction license accepts a held jump (L-61), and the
		// upload is judged at the time that applies once it is accepted, so the reported
		// phase is the one Allow enforces afterwards. The jump is accepted on the working
		// copy of the guard, which is published only once this transaction has committed.
		_, _, jumpHeld := g.PendingJump()
		acceptJump := jumpHeld && f.Payload.Replaces != ""
		reading := s.peek(acceptJump)
		c, err := s.compute(ctx, tx, reading, false)
		if err != nil {
			return err
		}
		if res, err = judge(f, c, reading); err != nil || res.Duplicate {
			return err
		}
		now := s.clock.Now().UTC()
		var uploadedBy *uuid.UUID
		if by != uuid.Nil {
			uploadedBy = &by
		}
		if _, err := tx.Exec(ctx, `INSERT INTO license_files (id, seq, sha256, raw_file, uploaded_at, uploaded_by)
VALUES ($1, $2, $3, $4, $5, $6)`, uuid.Must(uuid.NewV7()), nextSeq(c.files), contentHash(f), raw, now, uploadedBy); err != nil {
			return fmt.Errorf("store the license file: %w", err)
		}
		from := c.snap.Eval.Phase
		event, action := "renewed", "license.renewed"
		if c.snap.Eval.Current == nil {
			event, action = "installed", "license.activated"
		}
		p := f.Payload
		details := map[string]string{
			"license_id":  p.LicenseID,
			"customer":    p.Customer,
			"valid_from":  formatTime(p.ValidFrom),
			"valid_until": formatTime(p.ValidUntil),
			"max_targets": strconv.Itoa(p.MaxTargets),
			"key_id":      f.KeyID,
			"from_state":  string(from),
			"to_state":    string(res.Phase),
			"pending":     strconv.FormatBool(res.Pending),
			"correction":  strconv.FormatBool(res.Correction),
		}
		if p.Replaces != "" {
			details["replaces"] = p.Replaces
		}
		if len(p.Features) > 0 {
			details["features"] = strings.Join(p.Features, ",") // unknown features are listed, never used (L-47)
		}
		if _, err := insertHistory(ctx, tx, now, event, p.LicenseID, string(from), string(res.Phase), "", details); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `UPDATE license SET state = $1, updated_at = $2,
clock_jump = CASE WHEN $3 THEN NULL ELSE clock_jump END WHERE id = 1`, string(res.Phase), now, acceptJump); err != nil {
			return fmt.Errorf("update the license state: %w", err)
		}
		if _, err := s.audit.Append(ctx, tx, audit.Event{Actor: actor, Action: action, ObjectType: "license",
			ObjectID: p.LicenseID, Result: audit.Success, Details: details}); err != nil {
			return err
		}
		if acceptJump {
			g.AcceptJump() // L-61: the vendor confirmed the new time
			_, err := s.audit.Append(ctx, tx, audit.Event{Actor: actor, Action: "clock.jump_accepted", ObjectType: "license",
				ObjectID: p.LicenseID, Result: audit.Success, Details: map[string]string{"reason": "correction_license"}})
			return err
		}
		return nil
	})
	if err != nil {
		return UploadResult{}, err
	}
	s.publishGuard(g)
	return res, nil
}

// recordRejection writes the history row and the audit entry of a refused upload.
func (s *Service) recordRejection(ctx context.Context, actor audit.Actor, cause error) {
	reason := RejectReason(cause)
	details := map[string]string{"reason": reason}
	var inv *InvalidError
	if errors.As(cause, &inv) {
		details["problem"] = inv.Problem
	}
	var wi *WrongInstallationError
	if errors.As(cause, &wi) {
		details["expected_suffix"], details["got_suffix"] = wi.Expected, wi.Got
	}
	err := db.InTx(ctx, s.pool, func(tx pgx.Tx) error {
		if _, err := insertHistory(ctx, tx, s.clock.Now().UTC(), "rejected", "", "", "", "", details); err != nil {
			return err
		}
		_, err := s.audit.Append(ctx, tx, audit.Event{Actor: actor, Action: "license.upload." + reason,
			ObjectType: "license", Result: audit.Failure, Details: details})
		return err
	})
	if err != nil {
		s.log.Error("recording a refused license upload failed", "error_type", fmt.Sprintf("%T", err))
	}
}
