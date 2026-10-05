package sshkeys

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"regexp"
	"slices"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"alice/internal/audit"
	"alice/internal/inventory"
	"alice/internal/license"
	"alice/internal/platform/db"
	"alice/internal/platform/validate"
	"alice/internal/providers"
	"alice/internal/sshkeys/keymat"
)

// Bounds of a deploy's user and file (they must also be one of the scan's key files, which the
// helper bounds tighter).
const (
	maxOSUserBytes   = 256
	maxFilePathBytes = 4096
	// detachedTimeout bounds an audit row written after the request's transaction rolled back.
	detachedTimeout = 30 * time.Second
)

// errBadPayload: a sshkey.add payload without its fields or with a key id that is not a UUID. The
// queue's MAC makes this a bug, never input.
var errBadPayload = errors.New("sshkeys: the deploy job's payload is not valid")

// errForeignOptions: the payload's options are not exactly from= (canonical) and restrict (S7).
// The handler fails the job with its code.
var errForeignOptions = providers.NewError("ssh.helper_refused", false, nil, map[string]string{"field": "options"})

// closedReasonRE is a closed reason ("area.code"), the form of rotations.result_code.
var closedReasonRE = regexp.MustCompile(`^[a-z][a-z0-9_]{0,40}\.[a-z][a-z0-9_]{0,60}$`)

// denial is a refusal that protects access: audited (sshkey.deploy.denied) after the request's
// transaction has been rolled back.
type denial struct {
	reason string
	err    error
}

func (d *denial) Error() string { return d.err.Error() }
func (d *denial) Unwrap() error { return d.err }

// plainText reports whether s is valid UTF-8 without control, format or bidi characters.
func plainText(s string) bool {
	return utf8.ValidString(s) && !strings.ContainsFunc(s, func(r rune) bool {
		return unicode.IsControl(r) || unicode.Is(unicode.Cf, r) || unicode.Is(unicode.Bidi_Control, r)
	})
}

// checkDeployInput validates the request's fields and returns the line's options.
func checkDeployInput(in DeployInput) (string, validate.Errors) {
	var errs validate.Errors
	switch {
	case in.OSUser == "":
		errs.Add("os_user", validate.Required, nil)
	case len(in.OSUser) > maxOSUserBytes:
		errs.Add("os_user", validate.TooLong, map[string]string{"max": "256"})
	case !plainText(in.OSUser) || strings.ContainsAny(in.OSUser, " /"):
		errs.Add("os_user", validate.Pattern, nil)
	}
	switch {
	case in.FilePath == "":
		errs.Add("file_path", validate.Required, nil)
	case len(in.FilePath) > maxFilePathBytes:
		errs.Add("file_path", validate.TooLong, map[string]string{"max": "4096"})
	case !plainText(in.FilePath) || !strings.HasPrefix(in.FilePath, "/"):
		errs.Add("file_path", validate.Pattern, nil)
	}
	from := ""
	if strings.TrimSpace(in.From) != "" {
		var err error
		if from, err = keymat.FromOption(in.From); err != nil {
			errs.Add("from", validate.Pattern, nil)
		}
	}
	return deployOptions(from, in.Restrict), errs
}

// deployOptions are the only options a deploy writes: from= (canonical) and restrict (S7).
func deployOptions(from string, restrict bool) string {
	switch {
	case from != "" && restrict:
		return from + ",restrict"
	case restrict:
		return "restrict"
	}
	return from
}

// parseDeployOptions accepts exactly what deployOptions writes and returns it rebuilt (S7):
// anything else (another option, another order, a from= list that is not canonical) is refused.
func parseDeployOptions(opts string) (string, error) {
	rest, restrict := opts, false
	if rest == "restrict" {
		return deployOptions("", true), nil
	}
	if r, ok := strings.CutSuffix(rest, ",restrict"); ok {
		rest, restrict = r, true
	}
	if rest == "" {
		if restrict {
			return "", errForeignOptions
		}
		return "", nil
	}
	list, ok := strings.CutPrefix(rest, `from="`)
	if !ok {
		return "", errForeignOptions
	}
	list, ok = strings.CutSuffix(list, `"`)
	if !ok || strings.Contains(list, `"`) {
		return "", errForeignOptions
	}
	from, err := keymat.FromOption(list)
	if err != nil || from != rest {
		return "", errForeignOptions
	}
	out := deployOptions(from, restrict)
	if out != opts {
		return "", errForeignOptions
	}
	return out, nil
}

// filesOf returns one account's candidate key files of the last scan.
func filesOf(f inventory.Facts, user string) []string {
	for _, u := range f.KeyFiles {
		if u.OSUser == user {
			return u.Files
		}
	}
	return nil
}

// connectionFilesKnown reports whether the last scan listed the connection account's key files
// completely (providers.UserKeyFiles.Complete), exactly once. No entry, an incomplete one or a name
// listed twice is not known (review N1, N4). Known limitation (N2): there is no age bound; a list from
// an old scan stays complete, and a later change of sshd's settings is seen only after the next scan
// (which the helper re-checks at write time).
func connectionFilesKnown(f inventory.Facts, conn string) bool {
	seen, complete := 0, false
	for _, u := range f.KeyFiles {
		if u.OSUser == conn {
			seen++
			complete = u.Complete
		}
	}
	return seen == 1 && complete
}

// connectionUser is the account Alice signs in with on the target.
func connectionUser(t inventory.Target) string {
	if t.Username == "" {
		return inventory.ServiceUser
	}
	return t.Username
}

// deployCheck is what a deploy decided in its transaction.
type deployCheck struct {
	key       keyRow
	target    inventory.Target
	protected []string
}

// checkDeploy applies every deploy rule (spec §13.4; S7) in tx: the key is one Alice generated,
// not retired, never Alice's own key, not the new key of an unfinished rotation run; the server is ready for a key change for that user; neither
// the user nor the file belongs to Alice's connection account; the file is one of the user's key
// files as the last scan found them. Refusals that protect access are *denial.
func (s *Service) checkDeploy(ctx context.Context, tx pgx.Tx, keyID, targetID uuid.UUID, user, file string, lock bool) (deployCheck, error) {
	var c deployCheck
	var err error
	if c.key, err = readKeyRow(ctx, tx, keyID); err != nil {
		return c, err
	}
	if c.protected, err = inventory.ProtectedFingerprintsTx(ctx, tx); err != nil {
		return c, err
	}
	switch {
	case c.key.isPlatform || slices.Contains(c.protected, c.key.fingerprint):
		return c, &denial{reason: DenyOwnKey, err: ErrNotManaged}
	case c.key.privateKeyID == uuid.Nil:
		return c, ErrNotManaged
	case c.key.destroyed:
		return c, ErrDestroyed
	case c.key.retired:
		return c, ErrRetired
	}
	var inRun bool
	if err := tx.QueryRow(ctx, "SELECT EXISTS (SELECT 1 FROM rotations WHERE new_ssh_key_id = $1 AND status NOT IN "+finishedStatuses+")",
		keyID).Scan(&inRun); err != nil {
		return c, fmt.Errorf("sshkeys: read the key's rotations: %w", err)
	}
	if inRun {
		return c, ErrInRotation // a rollback of the run would remove the deployed line (N-m11)
	}
	if c.target, err = s.inv.TargetTx(ctx, tx, targetID, lock); err != nil {
		return c, err
	}
	if c.target.Type != inventory.TypeLinux && c.target.Type != inventory.TypeNginx {
		return c, inventory.ErrNotAServer
	}
	conn := connectionUser(c.target)
	if user == conn || slices.Contains(filesOf(c.target.Facts, conn), file) {
		return c, &denial{reason: DenyConnectionAccount, err: ErrConnectionAccount}
	}
	if !connectionFilesKnown(c.target.Facts, conn) {
		// S7 fails closed: without the connection account's complete file list Alice cannot know
		// whether the file is one its sshd reads.
		return c, &denial{reason: DenyConnectionFilesUnknown, err: ErrConnectionFilesUnknown}
	}
	if err := inventory.KeyChangeRefusal(c.target, user); err != nil {
		switch {
		case errors.Is(err, inventory.ErrKeysManagedElsewhere):
			return c, &denial{reason: DenyKeysManagedElsewhere, err: err}
		case errors.Is(err, inventory.ErrSSHDUnreadable):
			return c, &denial{reason: DenySSHDUnreadable, err: err}
		}
		return c, err
	}
	if !slices.Contains(filesOf(c.target.Facts, user), file) {
		return c, ErrNotAKeyFile
	}
	return c, nil
}

// deployDedupe is the sshkey.add dedupe key (C1): one live job per key, server, user and file.
func deployDedupe(keyID, targetID uuid.UUID, user, file string) string {
	sum := sha256.Sum256([]byte(user + "\n" + file))
	return JobDeploy + ":" + keyID.String() + ":" + targetID.String() + ":" + hex.EncodeToString(sum[:8])
}

func jobKind(a inventory.Actor) string {
	if a.UserID == uuid.Nil {
		return "system"
	}
	return "user"
}

// RequestDeploy validates and queues the deploy of a generated key to one user's key file on a
// server (spec §13.4). Everything is decided in one transaction that also queues the job and
// audits the request; refusals that protect access (Alice's own key, the connection account, keys
// served by a program, unread sshd settings) are audited sshkey.deploy.denied. The same deploy
// while queued is the same job; with other options it is inventory.ErrJobConflict.
func (s *Service) RequestDeploy(ctx context.Context, a inventory.Actor, in DeployInput) (uuid.UUID, error) {
	if err := s.license.Allow(license.ClassChange); err != nil {
		return uuid.Nil, err
	}
	options, errs := checkDeployInput(in)
	if len(errs) > 0 {
		return uuid.Nil, errs
	}
	var jobID uuid.UUID
	err := db.InTx(ctx, s.pool, func(tx pgx.Tx) error {
		c, err := s.checkDeploy(ctx, tx, in.KeyID, in.TargetID, in.OSUser, in.FilePath, true)
		if err != nil {
			return err
		}
		if _, err := keymat.Line(options, c.key.publicKey, c.key.comment); err != nil {
			return fmt.Errorf("sshkeys: build the key line: %w", err)
		}
		jobID, err = s.jobs.EnqueueTx(ctx, tx, inventory.JobRequest{Type: JobDeploy, TargetID: in.TargetID, Kind: jobKind(a),
			CreatedBy: a.UserID, CreatedByRole: string(a.Role), DedupeKey: deployDedupe(in.KeyID, in.TargetID, in.OSUser, in.FilePath),
			Payload: map[string]string{"ssh_key_id": in.KeyID.String(), "os_user": in.OSUser, "file_path": in.FilePath, "options": options}})
		if err != nil {
			return err
		}
		_, err = s.audit.Append(ctx, tx, audit.Event{Actor: a.Audit, Action: "sshkey.deploy_requested", ObjectType: "ssh_key",
			ObjectID: in.KeyID.String(), Result: audit.Success, Details: map[string]string{"ssh_key_id": in.KeyID.String(),
				"fingerprint": c.key.fingerprint, "target_id": in.TargetID.String(), "os_user": in.OSUser, "file_path": in.FilePath,
				"job_id": jobID.String()}})
		return err
	})
	var d *denial
	if errors.As(err, &d) {
		s.auditDetached(ctx, audit.Event{Actor: a.Audit, Action: "sshkey.deploy.denied", ObjectType: "ssh_key", ObjectID: in.KeyID.String(),
			Result: audit.Denied, Details: map[string]string{"reason": d.reason, "ssh_key_id": in.KeyID.String(),
				"target_id": in.TargetID.String(), "os_user": in.OSUser}})
		return uuid.Nil, d.err
	}
	if err != nil {
		return uuid.Nil, err
	}
	return jobID, nil
}

// auditDetached records a refusal in its own transaction (the request's was rolled back). The
// record does not depend on the request: a client that disconnects does not erase it.
func (s *Service) auditDetached(ctx context.Context, e audit.Event) {
	ctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), detachedTimeout)
	defer cancel()
	err := db.InTx(ctx, s.pool, func(tx pgx.Tx) error {
		_, err := s.audit.Append(ctx, tx, e)
		return err
	})
	if err != nil {
		s.log.Error("could not audit a refusal", "action", e.Action, "error_type", fmt.Sprintf("%T", err))
	}
}

// DeployJob reads a sshkey.add job's deploy again when the job runs: only the payload's ids and
// strings are taken from it, and every rule of RequestDeploy is applied again to the database's
// current state (S7: the options must be exactly from= and restrict). The line is rebuilt from the
// stored public key and comment. The first id is the job's (C9 passes it; the payload is the
// queue's, MAC-checked, so nothing here needs it).
func (s *Service) DeployJob(ctx context.Context, _, targetID uuid.UUID, payload map[string]string) (DeployJob, error) {
	rawKey, okKey := payload["ssh_key_id"]
	user, okUser := payload["os_user"]
	file, okFile := payload["file_path"]
	opts, okOpts := payload["options"]
	keyID, err := uuid.Parse(rawKey)
	if !okKey || !okUser || !okFile || !okOpts || err != nil {
		return DeployJob{}, errBadPayload
	}
	options, err := parseDeployOptions(opts)
	if err != nil {
		return DeployJob{}, err
	}
	var out DeployJob
	err = db.InTx(ctx, s.pool, func(tx pgx.Tx) error {
		c, err := s.checkDeploy(ctx, tx, keyID, targetID, user, file, false)
		if err != nil {
			return err
		}
		line, err := keymat.Line(options, c.key.publicKey, c.key.comment)
		if err != nil {
			return fmt.Errorf("sshkeys: build the key line: %w", err)
		}
		out = DeployJob{KeyID: keyID, TargetID: targetID, Fingerprint: c.key.fingerprint, OSUser: user, FilePath: file,
			Options: options, Comment: c.key.comment, Line: line, Protected: c.protected}
		return nil
	})
	var d *denial
	if errors.As(err, &d) {
		return DeployJob{}, d.err
	}
	if err != nil {
		return DeployJob{}, err
	}
	return out, nil
}

// FinishDeploy records a deploy's outcome (C9): a line that is in the file (verified, unverified,
// already present) becomes a location of the key (inventory.RecordKeyAddedTx, audited
// sshkey.added with verified); a failure is audited sshkey.add_failed with its closed reason.
// actor is the job's system actor; its RequestID is the job id.
func (s *Service) FinishDeploy(ctx context.Context, actor audit.Actor, d DeployJob, out DeployOutcome) error {
	switch out.Result {
	case DeployVerified, DeployUnverified, DeployAlreadyPresent:
		return s.storeTx(ctx, func(tx pgx.Tx) error { // claim-fenced (store request S-1, item 3)
			_, err := s.inv.RecordKeyAddedTx(ctx, tx, inventory.KeyAdded{SSHKeyID: d.KeyID, TargetID: d.TargetID, OSUser: d.OSUser,
				FilePath: d.FilePath, Options: d.Options, Comment: d.Comment, LineNo: out.LineNo, Actor: actor,
				Verified: out.Result == DeployVerified})
			return err
		})
	case DeployUndone, DeployFailed, DeployUndoFailed:
		reason := out.Reason
		if !closedReasonRE.MatchString(reason) {
			reason = "internal.unexpected"
		}
		return s.storeTx(ctx, func(tx pgx.Tx) error {
			_, err := s.audit.Append(ctx, tx, audit.Event{Actor: actor, Action: "sshkey.add_failed", ObjectType: "ssh_key",
				ObjectID: d.KeyID.String(), Result: audit.Failure, Details: map[string]string{"ssh_key_id": d.KeyID.String(),
					"target_id": d.TargetID.String(), "os_user": d.OSUser, "file_path": d.FilePath, "job_id": actor.RequestID,
					"reason": reason}})
			return err
		})
	}
	return fmt.Errorf("sshkeys: unknown deploy result %q", out.Result)
}
