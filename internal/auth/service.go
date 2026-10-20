package auth

import (
	"context"
	"errors"
	"log/slog"
	"net/netip"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"

	"alice/internal/audit"
	"alice/internal/platform/clock"
	"alice/internal/rbac"
	"alice/internal/secrets"
)

// Errors returned by the authentication service. Handlers map them to API error codes.
var (
	ErrInvalidCredentials     = errors.New("auth: invalid credentials")
	ErrUnauthenticated        = errors.New("auth: not authenticated")
	ErrMFAInvalid             = errors.New("auth: verification code invalid")
	ErrMFAAlreadyEnrolled     = errors.New("auth: MFA already enrolled")
	ErrCurrentPasswordInvalid = errors.New("auth: current password invalid")
	ErrAdminExists            = errors.New("auth: an administrator already exists")
	ErrNotFound               = errors.New("auth: not found")
	// ErrTryAgain means a credential check could not get the account lock in time
	// (lock_timeout); nothing was verified or counted and the caller may retry.
	ErrTryAgain = errors.New("auth: account busy, try again")
)

// Session and lockout limits (SEC-019, SEC-020).
const (
	SessionIdle     = 30 * time.Minute
	SessionAbsolute = 12 * time.Hour
	PendingLifetime = 5 * time.Minute
	StepUpWindow    = 5 * time.Minute
	DelayThreshold  = 5
	LockThreshold   = 10
	LockDuration    = 15 * time.Minute
	MaxDelay        = 60 * time.Second

	// credentialLockTimeout bounds how long a credential check waits for the account row lock.
	credentialLockTimeout = 5 * time.Second
)

// unknownUserName is recorded in the audit log instead of a username that does not
// exist, because people sometimes type their password into the username field.
const unknownUserName = "(unknown user)"

// Config holds the service dependencies.
type Config struct {
	Pool           *pgxpool.Pool
	Keyring        *secrets.Keyring
	Audit          *audit.Log
	Clock          clock.Clock
	Hasher         *Hasher      // PasswordParams in production
	RecoveryHasher *Hasher      // RecoveryCodeParams in production
	Notifier       Notifier     // nil: no lockout e-mail
	Log            *slog.Logger // nil: discarded
}

// Service implements local authentication, sessions, MFA, users and API tokens.
type Service struct {
	pool     *pgxpool.Pool
	keyring  *secrets.Keyring
	audit    *audit.Log
	clock    clock.Clock
	hasher   *Hasher
	recovery *Hasher
	notifier Notifier
	csrfKey  []byte
	log      *slog.Logger

	// credSlots bounds concurrent credential checks (password, TOTP, recovery code) to the
	// password hasher's concurrency. A check takes a slot before it takes a pool connection,
	// so a burst cannot exhaust the pool, and unknown, blocked and real accounts all wait
	// in this one queue.
	credSlots   chan struct{}
	lockTimeout time.Duration
	slotHook    func(acquired bool) // tests only
}

// NewService builds the service.
func NewService(c Config) *Service {
	return &Service{
		pool:     c.Pool,
		keyring:  c.Keyring,
		audit:    c.Audit,
		clock:    c.Clock,
		hasher:   c.Hasher,
		recovery: c.RecoveryHasher,
		notifier: c.Notifier,
		csrfKey:  c.Keyring.Derive(secrets.LabelCSRF),
		log:      logOrDiscard(c.Log),

		credSlots:   make(chan struct{}, c.Hasher.concurrency()),
		lockTimeout: credentialLockTimeout,
	}
}

func logOrDiscard(l *slog.Logger) *slog.Logger {
	if l == nil {
		return slog.New(slog.DiscardHandler)
	}
	return l
}

// checkSecret runs h.Verify. A stored hash that does not parse (a corrupted row) is a failed check, not an error: the
// same Argon2 work runs (DummyVerify), so the attempt is counted and answered like a wrong secret, and the row is
// logged for the operator (review I-7). what names the secret in the log line.
func (s *Service) checkSecret(ctx context.Context, h *Hasher, what string, userID uuid.UUID, encoded, secret string) (ok, rehash bool, err error) {
	ok, rehash, err = h.Verify(ctx, encoded, secret)
	if errors.Is(err, errMalformedHash) {
		s.log.ErrorContext(ctx, "stored "+what+" hash is malformed; the check counts as failed", "user_id", userID.String())
		h.DummyVerify(ctx, secret)
		return false, false, nil
	}
	return ok, rehash, err
}

// Meta describes the request that triggered an operation.
type Meta struct {
	IP        netip.Addr
	UserAgent string
	RequestID string
}

// User is the public view of an account. It never contains secrets.
type User struct {
	ID            uuid.UUID
	Username      string
	DisplayName   string
	Email         string
	Role          rbac.Role
	Locale        string
	Disabled      bool
	MFAEnrolled   bool
	LastLoginAt   *time.Time
	CreatedAt     time.Time
	AuthSource    string     // AuthLocal | AuthOIDC | AuthLDAP
	SSOProviderID *uuid.UUID // the identity provider of an SSO user, nil for a local user
	// LDAPDirectoryID is the directory of a directory user, nil for every other user.
	LDAPDirectoryID *uuid.UUID
	// LDAPUniqueID and LDAPLogin are a directory user's unique id at the directory and the sign-in name the directory
	// last returned (the keys of the directory sign-in lockout); empty for every other user. Never sent to clients.
	LDAPUniqueID string
	LDAPLogin    string
}

// Authentication sources of a user (users.auth_source).
const (
	AuthLocal = "local"
	AuthOIDC  = "oidc"
	AuthLDAP  = "ldap" // a directory user (LDAP or Active Directory sign-in)
)

// Principal is the authenticated caller of one request.
type Principal struct {
	Kind        rbac.SubjectKind
	UserID      uuid.UUID
	Username    string
	DisplayName string
	Role        rbac.Role
	Locale      string
	SessionHash []byte
	StepUpUntil time.Time
	TokenID     uuid.UUID
	Scope       rbac.Scope
	AuthSource  string // AuthLocal | AuthOIDC | AuthLDAP
	// LDAPDirectoryID is the directory of a directory user's session (uuid.Nil for every other principal); the
	// API runs a directory step-up against it, with the stored sign-in name LDAPLogin, and checks that the directory
	// answers for the same entry LDAPUniqueID ("" for every other principal).
	LDAPDirectoryID uuid.UUID
	LDAPUniqueID    string
	LDAPLogin       string
}

// Subject converts the principal into the input of rbac.Decide.
func (p Principal) Subject(now time.Time) rbac.Subject {
	return rbac.Subject{
		Kind:   p.Kind,
		Role:   p.Role,
		Scope:  p.Scope,
		StepUp: p.Kind == rbac.UserSession && now.Before(p.StepUpUntil),
	}
}

// Actor returns the audit actor for the principal.
func (p Principal) Actor(m Meta) audit.Actor {
	t := audit.ActorUser
	if p.Kind == rbac.APIToken {
		t = audit.ActorToken
	}
	return audit.Actor{Type: t, ID: p.UserID, Name: p.Username, IP: m.IP, RequestID: m.RequestID}
}

// LoginResult is the outcome of the password step.
type LoginResult struct {
	Status       string // "mfa_required" | "mfa_enrollment_required" | "signed_in" (SignInLDAP without MFA only)
	SessionToken string // pending session cookie value; the full session's for StatusSignedIn
	// Session is the full session of StatusSignedIn (a directory without mfa_required), nil otherwise.
	Session *SessionResult
}

// Login status values.
const (
	StatusMFARequired           = "mfa_required"
	StatusMFAEnrollmentRequired = "mfa_enrollment_required"
	StatusSignedIn              = "signed_in"
)

// MFAInput carries either a TOTP code or a recovery code.
type MFAInput struct{ Code, RecoveryCode string }

// SessionInfo describes the caller's current full session.
type SessionInfo struct {
	User          User
	CSRFToken     string
	ExpiresAt     time.Time
	IdleExpiresAt time.Time
	StepUpUntil   *time.Time
	AuthSource    string     // User.AuthSource
	SSOProviderID *uuid.UUID // User.SSOProviderID
}

// SessionResult is returned whenever a new full session is issued.
type SessionResult struct {
	Token         string
	Info          SessionInfo
	RecoveryCodes []string
}

func userActor(id uuid.UUID, name string, m Meta) audit.Actor {
	return audit.Actor{Type: audit.ActorUser, ID: id, Name: name, IP: m.IP, RequestID: m.RequestID}
}
