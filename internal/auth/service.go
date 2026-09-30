package auth

import (
	"errors"
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
	Hasher         *Hasher // PasswordParams in production
	RecoveryHasher *Hasher // RecoveryCodeParams in production
}

// Service implements local authentication, sessions, MFA, users and API tokens.
type Service struct {
	pool     *pgxpool.Pool
	keyring  *secrets.Keyring
	audit    *audit.Log
	clock    clock.Clock
	hasher   *Hasher
	recovery *Hasher
	csrfKey  []byte
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
		csrfKey:  c.Keyring.Derive(secrets.LabelCSRF),
	}
}

// Meta describes the request that triggered an operation.
type Meta struct {
	IP        netip.Addr
	UserAgent string
	RequestID string
}

// User is the public view of an account. It never contains secrets.
type User struct {
	ID          uuid.UUID
	Username    string
	DisplayName string
	Email       string
	Role        rbac.Role
	Locale      string
	Disabled    bool
	MFAEnrolled bool
	LastLoginAt *time.Time
	CreatedAt   time.Time
}

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
	Status       string // "mfa_required" | "mfa_enrollment_required"
	SessionToken string // pending session cookie value
}

// Login status values.
const (
	StatusMFARequired           = "mfa_required"
	StatusMFAEnrollmentRequired = "mfa_enrollment_required"
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
