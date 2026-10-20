// Package ldap is Alice's directory (LDAP and Active Directory) sign-in: the directories an Administrator configures
// (ldaps:// addresses, a read-only service account whose password is a settings secret, the user and group searches),
// their group-to-role mappings under the "SSO users may be Admin" switch, the network client (TLS verified, every
// connection through netaddr, no referrals, size and time limits) and Verify, which checks a sign-in name and password
// against a directory. Users, sessions and refusals are internal/auth's. Pure helpers (escaping, templates, names)
// live in ldapx. Spec: docs/superpowers/specs/2026-10-15-ldap-directory-signin-design.md.
package ldap

import (
	"context"
	"errors"
	"log/slog"
	"net"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"

	"alice/internal/audit"
	"alice/internal/auth"
	"alice/internal/auth/oidc/claims"
	"alice/internal/auth/ratelimit"
	"alice/internal/platform/clock"
	"alice/internal/rbac"
	"alice/internal/secrets"
)

// Limits (plan ruling 10 and 11).
const (
	MaxDirectories   = 3
	MaxMappings      = 200
	DialTimeout      = 10 * time.Second // one address: TCP connect and TLS handshake
	OperationTimeout = 15 * time.Second // one LDAP request (bind, search); also the searches' server-side time limit
	VerifyTimeout    = 30 * time.Second // a whole Verify, TestConnection or TestSignIn
	UserSizeLimit    = 2                // the user search: exactly one entry is wanted, two proves it is not unique
	GroupSizeLimit   = 1000             // the group search
	MaxPasswordBytes = 1024             // a longer password is refused before any traffic
	AllowAdminKey    = auth.SSOAllowAdminKey
)

// misconfiguredLogEvery is how often a failing service account bind is logged per directory.
const misconfiguredLogEvery = 10 * time.Minute

// Config holds the service's dependencies.
type Config struct {
	Pool    *pgxpool.Pool
	Keyring *secrets.Keyring
	Audit   *audit.Log
	Clock   clock.Clock
	Dial    func(ctx context.Context, network, addr string) (net.Conn, error) // nil: netaddr.DialContext
	Log     *slog.Logger
	// Auth ends the sessions and API tokens of a directory's users when the directory is switched off (EndDirectoryAccess).
	Auth *auth.Service
	// NewClient replaces the network client (tests of the callers); nil: the real client.
	NewClient func() Client
}

// timeouts are the client's limits; tests shorten them through export_test.go.
type timeouts struct{ dial, operation, verify time.Duration }

// Service manages directories and checks directory passwords.
type Service struct {
	pool      *pgxpool.Pool
	keyring   *secrets.Keyring
	audit     *audit.Log
	clock     clock.Clock
	dial      func(ctx context.Context, network, addr string) (net.Conn, error)
	log       *slog.Logger
	auth      *auth.Service
	newClient func() Client
	limits    timeouts
	logged    *ratelimit.Recent // directories whose failing service bind was logged in the last misconfiguredLogEvery
}

// New builds the service.
func New(c Config) *Service {
	log := c.Log
	if log == nil {
		log = slog.New(slog.DiscardHandler)
	}
	return &Service{pool: c.Pool, keyring: c.Keyring, audit: c.Audit, clock: c.Clock, dial: c.Dial, log: log, auth: c.Auth, newClient: c.NewClient,
		limits: timeouts{dial: DialTimeout, operation: OperationTimeout, verify: VerifyTimeout},
		logged: ratelimit.NewRecent(c.Clock, misconfiguredLogEvery, 100)}
}

// client is the network client: the real one unless Config.NewClient replaces it.
func (s *Service) client() Client {
	if s.newClient != nil {
		return s.newClient()
	}
	return &netClient{dial: s.dial, limits: s.limits}
}

// secretKey is the setting_secrets key of a directory's service account password.
func secretKey(id uuid.UUID) string { return "ldap.directory." + id.String() + ".bind_password" }

// userID is the actor's user ID for created_by: a user actor's ID, else NULL.
func userID(a audit.Actor) any {
	if a.Type == audit.ActorUser && a.ID != uuid.Nil {
		return a.ID
	}
	return nil
}

// Identity is a directory user whose password the directory just accepted.
type Identity struct {
	UniqueID    string // lower-case hex of the unique id attribute's bytes (ldapx.UniqueID)
	Login       string // the sign-in name attribute's value as the directory holds it (the typed name if it has none)
	DisplayName string
	Email       string
	Groups      []string // the group search's values: DNs or the group name attribute, exactly as returned
}

// Verify checks a sign-in name and password against a directory: it loads the directory and its service account
// password, refuses a disabled directory, an invalid sign-in name and an empty password before any network traffic,
// then binds as the service account, finds exactly one user entry, binds as that entry with the password and reads
// its groups. Failures are *LoginError with the closed reasons of errors.go; a missing directory is ErrNotFound.
// A wrong password for an entry the directory found also returns that entry's UniqueID and Login (nothing else),
// so that the caller can record the refusal against the person; every other failure returns an empty Identity.
// The whole call is bounded by VerifyTimeout. Verify zeroes password before it returns, and holds no database
// transaction while it talks to the directory.
func (s *Service) Verify(ctx context.Context, directoryID uuid.UUID, login string, password secrets.Plaintext) (Identity, Directory, error) {
	return s.VerifyGated(ctx, directoryID, login, password, nil)
}

// Gate is asked, after the user search found exactly one entry and before Alice binds as it, whether that entry (named
// by its unique id) may be tried. A non-nil error refuses the attempt without the bind, as bad_credentials with the
// detail account_locked (and the entry's identity, like a wrong password).
type Gate func(uniqueID string) error

type gateKey struct{}

// RunGate is what a Client calls after its user search found the one entry and before it binds as it with the user's
// password: it runs the gate of the VerifyGated call (none: nil). On an error the Client must not bind, and returns
// the entry together with the error.
func RunGate(ctx context.Context, e Entry) error {
	g, _ := ctx.Value(gateKey{}).(func(Entry) error)
	if g == nil {
		return nil
	}
	return g(e)
}

// VerifyGated is Verify with a Gate between the user search and the user bind (the API's per-account lockout): a
// locked account is never bound to, whichever spelling of its name found it.
func (s *Service) VerifyGated(ctx context.Context, directoryID uuid.UUID, login string, password secrets.Plaintext, gate Gate) (Identity, Directory, error) {
	defer password.Zero()
	d, err := s.Directory(ctx, directoryID)
	if err != nil {
		return Identity{}, Directory{}, err
	}
	if !d.Enabled {
		return Identity{}, d, refuse(ReasonDisabled, "", nil)
	}
	if lerr := checkCredentials(login, password); lerr != nil {
		return Identity{}, d, lerr
	}
	id, err := s.verify(withGate(ctx, d, login, gate), d, login, password)
	return id, d, err
}

// withGate puts gate (nil: none) into ctx for RunGate, turning the entry into its unique id first.
func withGate(ctx context.Context, d Directory, login string, gate Gate) context.Context {
	if gate == nil {
		return ctx
	}
	return context.WithValue(ctx, gateKey{}, func(e Entry) error {
		id, err := identityOf(d, e, login)
		if err != nil {
			return err
		}
		if err := gate(id.UniqueID); err != nil {
			return refuse(ReasonBadCredentials, DetailLocked, err)
		}
		return nil
	})
}

// checkCredentials refuses, before any traffic, a sign-in name that cannot be sent (login_invalid) and an empty or
// oversized password (bad_credentials: an LDAP bind with an empty password is an anonymous bind and usually
// succeeds).
func checkCredentials(login string, password secrets.Plaintext) *LoginError {
	if !validLogin(login) {
		return refuse(ReasonLoginInvalid, DetailLoginName, nil)
	}
	if n := len(password.Bytes()); n == 0 || n > MaxPasswordBytes {
		return refuse(ReasonBadCredentials, DetailPassword, nil)
	}
	return nil
}

// verify runs the directory exchange for an enabled directory.
func (s *Service) verify(ctx context.Context, d Directory, login string, password secrets.Plaintext) (Identity, error) {
	ctx, cancel := context.WithTimeout(ctx, s.limits.verify)
	defer cancel()
	bind, err := s.bindPassword(ctx, d.ID)
	if err != nil {
		return Identity{}, err
	}
	defer bind.Zero()
	c := s.client()
	entry, err := c.Authenticate(ctx, d, bind, login, password)
	if err != nil {
		s.noteMisconfigured(d, err)
		return refusedIdentity(d, entry, login, err), err
	}
	id, err := identityOf(d, entry, login)
	if err != nil {
		return Identity{}, err
	}
	groups, err := c.Groups(ctx, d, bind, entry, id.Login)
	if err != nil {
		s.noteMisconfigured(d, err)
		return Identity{}, err
	}
	id.Groups = groups
	return id, nil
}

// refusedIdentity is what a refused Verify returns of the entry: its unique id and sign-in name when the directory
// found exactly one entry and refused its password (bad_credentials with an entry), so that the refusal can be
// recorded against that person; nothing for every other failure (an unknown name, several entries, the network).
func refusedIdentity(d Directory, entry Entry, login string, err error) Identity {
	var le *LoginError
	if entry.DN == "" || !errors.As(err, &le) || le.Reason != ReasonBadCredentials {
		return Identity{}
	}
	id, idErr := identityOf(d, entry, login)
	if idErr != nil {
		return Identity{}
	}
	return Identity{UniqueID: id.UniqueID, Login: id.Login}
}

// bindPassword unseals a directory's service account password; the caller zeroes it. A missing secret is
// directory_misconfigured.
func (s *Service) bindPassword(ctx context.Context, id uuid.UUID) (secrets.Plaintext, error) {
	p, ok, err := s.keyring.GetSetting(ctx, s.pool, secretKey(id))
	if err != nil {
		return secrets.Plaintext{}, err
	}
	if !ok {
		return secrets.Plaintext{}, refuse(ReasonMisconfigured, DetailNoSecret, nil)
	}
	return p, nil
}

// noteMisconfigured logs a refused service account bind once per misconfiguredLogEvery and directory: the person
// signing in is never told, the Administrator finds it in the log and with Test connection.
func (s *Service) noteMisconfigured(d Directory, err error) {
	var le *LoginError
	if !errors.As(err, &le) || le.Reason != ReasonMisconfigured || le.Detail != DetailServiceBind || s.logged.Contains(d.ID.String()) {
		return
	}
	s.logged.Add(d.ID.String())
	s.log.Warn("ldap: the directory refused its service account; check the bind DN and password with Test connection",
		"directory_id", d.ID.String(), "directory", d.Name)
}

// ResolveRole is the role the directory's group mappings give these groups under the "SSO users may be Admin"
// switch (claims.ResolveRole: the highest mapped role, Administrator capped at Operator while the switch is off).
// ok is false when no group is mapped: nobody gets a role by default.
func (s *Service) ResolveRole(ctx context.Context, directoryID uuid.UUID, groups []string) (rbac.Role, bool, error) {
	mappings, err := mappingsFor(ctx, s.pool, directoryID)
	if err != nil {
		return "", false, err
	}
	allow, err := s.adminAllowed(ctx, s.pool)
	if err != nil {
		return "", false, err
	}
	role, ok := claims.ResolveRole(groups, mappings, allow)
	return role, ok, nil
}
