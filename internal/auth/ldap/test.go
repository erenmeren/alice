package ldap

import (
	"context"
	"errors"
	"strconv"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"alice/internal/audit"
	"alice/internal/platform/db"
	"alice/internal/rbac"
	"alice/internal/secrets"
)

// TestResult is what Test sign-in shows: who the directory says the person is, the groups the group search found and
// the role the mappings would give (Role "" when no group is mapped). Nothing is stored.
type TestResult struct {
	Identity Identity
	Role     rbac.Role
}

// resultDetails are the audit details of a test: result ok or failed, and the reason and detail of a failure.
func resultDetails(d Directory, err error) (map[string]string, audit.Result) {
	details := map[string]string{"directory_id": d.ID.String(), "name": d.Name, "result": "ok"}
	if err == nil {
		return details, audit.Success
	}
	details["result"] = "failed"
	var le *LoginError
	if errors.As(err, &le) {
		details["reason"] = le.Reason
		if le.Detail != "" {
			details["detail"] = le.Detail
		}
	} else {
		details["reason"] = "error"
	}
	return details, audit.Failure
}

func (s *Service) record(ctx context.Context, e audit.Event) error {
	return db.InTx(ctx, s.pool, func(tx pgx.Tx) error {
		_, err := s.audit.Append(ctx, tx, e)
		return err
	})
}

// TestConnection binds as the directory's service account and searches the user base DN once, with the stored
// settings (also of a directory that is switched off). It returns nil or a *LoginError naming the reason and where
// it stopped, never the server's text. Every call is audited as ldap.directory_tested.
func (s *Service) TestConnection(ctx context.Context, a audit.Actor, id uuid.UUID) error {
	d, err := s.Directory(ctx, id)
	if err != nil {
		return err
	}
	checker, ok := s.client().(ConnectionChecker)
	if !ok {
		return ErrNoConnectionTest
	}
	testErr := func() error {
		ctx, cancel := context.WithTimeout(ctx, s.limits.verify)
		defer cancel()
		bind, err := s.bindPassword(ctx, d.ID)
		if err != nil {
			return err
		}
		defer bind.Zero()
		return checker.CheckConnection(ctx, d, bind)
	}()
	details, result := resultDetails(d, testErr)
	if err := s.record(ctx, audit.Event{Actor: a, Action: "ldap.directory_tested", ObjectType: "ldap_directory", ObjectID: id.String(),
		Result: result, Details: details}); err != nil {
		return err
	}
	return testErr
}

// TestSignIn runs a directory sign-in with the stored settings (also of a directory that is switched off) without
// signing anyone in: it returns the identity, the groups found and the role the mappings would give. Nothing is
// stored; the password is zeroed before it returns. A refused attempt is a *LoginError. Every call is audited as
// ldap.signin_tested with the result, the reason, the role and, only for a name the directory resolved (or found
// several times), the sign-in name.
func (s *Service) TestSignIn(ctx context.Context, a audit.Actor, id uuid.UUID, login string, password secrets.Plaintext) (TestResult, error) {
	return s.TestSignInGated(ctx, a, id, login, password, nil)
}

// TestSignInGated is TestSignIn with the Gate of VerifyGated between the user search and the user bind (the API's
// per-account lockout applies to a test as to a sign-in).
func (s *Service) TestSignInGated(ctx context.Context, a audit.Actor, id uuid.UUID, login string, password secrets.Plaintext,
	gate Gate,
) (TestResult, error) {
	defer password.Zero()
	d, err := s.Directory(ctx, id)
	if err != nil {
		return TestResult{}, err
	}
	var out TestResult
	testErr := checkCredentials(login, password).orNil()
	if testErr == nil {
		out.Identity, testErr = s.verify(withGate(ctx, d, login, gate), d, login, password)
	}
	details, result := resultDetails(d, testErr)
	if out.Identity.UniqueID != "" || details["reason"] == ReasonAmbiguousUser {
		// The name only when the directory resolved it (an entry was found, also with a wrong password) or several
		// entries carry it, cut to 128 runes, as for a refused sign-in (auth.RefuseLDAP): a typed name that matched
		// nothing may be a password pasted into the wrong field, and the audit log is append-only.
		name := login
		if out.Identity.Login != "" {
			name = out.Identity.Login
		}
		details["login"] = cutRunes(name, maxAuditLoginRunes)
	}
	if testErr == nil {
		role, ok, err := s.ResolveRole(ctx, d.ID, out.Identity.Groups)
		if err != nil {
			return TestResult{}, err
		}
		details["role"], details["group_count"] = "none", strconv.Itoa(len(out.Identity.Groups))
		if ok {
			out.Role, details["role"] = role, string(role)
		} else {
			// The password was right, but nobody with these groups may sign in: a failed test.
			details["reason"], details["result"], result = "no_access", "failed", audit.Failure
		}
	}
	if err := s.record(ctx, audit.Event{Actor: a, Action: "ldap.signin_tested", ObjectType: "ldap_directory", ObjectID: id.String(),
		Result: result, Details: details}); err != nil {
		return TestResult{}, err
	}
	if testErr != nil {
		return TestResult{}, testErr
	}
	return out, nil
}

// orNil turns a nil *LoginError into a nil error.
func (e *LoginError) orNil() error {
	if e == nil {
		return nil
	}
	return e
}

// maxAuditLoginRunes is the longest sign-in name an audit row records (the same cut as auth.RefuseLDAP).
const maxAuditLoginRunes = 128

// cutRunes cuts s to at most n runes.
func cutRunes(s string, n int) string {
	if r := []rune(s); len(r) > n {
		return string(r[:n])
	}
	return s
}
