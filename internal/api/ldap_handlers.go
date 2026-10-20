package api

import (
	"context"
	"errors"
	"net/http"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/google/uuid"
	"golang.org/x/text/cases"
	"golang.org/x/text/unicode/norm"

	"alice/internal/auth"
	"alice/internal/auth/ldap"
	"alice/internal/auth/ldap/ldapx"
	"alice/internal/auth/ratelimit"
	"alice/internal/license"
	"alice/internal/platform/validate"
	"alice/internal/rbac"
	"alice/internal/secrets"
)

// ldapRefusalFloor is the least time a refused directory sign-in takes, measured from the start of the request on the
// server's clock. The service already binds once for an unknown name, so that an unknown name and a wrong password
// cost the same round trips (Task 3); what that dummy bind cannot equalise is Active Directory's forwarding of a wrong
// password to the PDC emulator, which makes a real account's refusal slower than an unknown one's. Every refusal
// (except a rate limit and a malformed body, which are answered at once and say nothing about a user) is held to this
// floor; a refusal that took longer is not held further.
const ldapRefusalFloor = 1500 * time.Millisecond

// Body limits of the directory password routes: the sign-in form's limits (maxLoginUsername, maxLoginPassword runes)
// in a body of at most maxDirectoryPasswordBody bytes (1,024 runes of up to 6 bytes each when escaped, and the name).
const (
	maxDirectoryPasswordBody = 16 << 10
	maxDirectoryBody         = 160 << 10 // a PEM authority of at most 64 KiB, JSON-escaped, and short fields
	maxTOTPCode              = 16
)

// ldapSignInRoutes are the directory sign-in (LDAP and Active Directory, Task 5): the sign-in page's list, the sign-in
// (the sign-in form's limit per address plus ldapLockout per directory and name) and a directory user's step-up.
func (s *server) ldapSignInRoutes() []route {
	return []route{
		{method: http.MethodGet, pattern: "/api/v1/auth/ldap/directories", scope: scopeNone, perm: rbac.Public, handler: s.ldapPublicDirectories},
		{method: http.MethodPost, pattern: "/api/v1/auth/ldap/{id}/login", scope: scopeNone, perm: rbac.Public, limit: limitLogin, lic: license.ClassAlways,
			handler: s.ldapLogin},
		{method: http.MethodPost, pattern: "/api/v1/auth/ldap/stepup", scope: scopeSelf, perm: rbac.Session, limit: limitMFA, lic: license.ClassAlways,
			handler: s.ldapStepUp},
	}
}

// ldapRoutes are the directory administration: directories, their group mappings, Test connection and Test sign-in.
// Every one is sso.manage (an Administrator's browser session with step-up, never an API token) and works in lock.
func (s *server) ldapRoutes() []route {
	return []route{
		{method: http.MethodGet, pattern: "/api/v1/ldap/directories", scope: scopePlatform, perm: rbac.SSOManage, handler: s.listDirectories},
		{method: http.MethodPost, pattern: "/api/v1/ldap/directories", scope: scopePlatform, perm: rbac.SSOManage, lic: license.ClassAlways, handler: s.createDirectory},
		{method: http.MethodGet, pattern: "/api/v1/ldap/directories/{id}", scope: scopePlatform, perm: rbac.SSOManage, handler: s.getDirectory},
		{method: http.MethodPatch, pattern: "/api/v1/ldap/directories/{id}", scope: scopePlatform, perm: rbac.SSOManage, lic: license.ClassAlways, handler: s.updateDirectory},
		{method: http.MethodDelete, pattern: "/api/v1/ldap/directories/{id}", scope: scopePlatform, perm: rbac.SSOManage, lic: license.ClassAlways, handler: s.deleteDirectory},
		{method: http.MethodPost, pattern: "/api/v1/ldap/directories/{id}/actions/test-connection", scope: scopePlatform, perm: rbac.SSOManage, limit: limitDirectoryTest,
			lic: license.ClassAlways, handler: s.testDirectoryConnection},
		{method: http.MethodPost, pattern: "/api/v1/ldap/directories/{id}/actions/test-signin", scope: scopePlatform, perm: rbac.SSOManage, limit: limitDirectoryTest,
			lic: license.ClassAlways, handler: s.testDirectorySignIn},
		{method: http.MethodGet, pattern: "/api/v1/ldap/group-mappings", scope: scopePlatform, perm: rbac.SSOManage, handler: s.listDirectoryMappings},
		{method: http.MethodPost, pattern: "/api/v1/ldap/group-mappings", scope: scopePlatform, perm: rbac.SSOManage, lic: license.ClassAlways,
			handler: s.createDirectoryMapping},
		{method: http.MethodDelete, pattern: "/api/v1/ldap/group-mappings/{id}", scope: scopePlatform, perm: rbac.SSOManage, lic: license.ClassAlways,
			handler: s.deleteDirectoryMapping},
	}
}

// ldapLoginKey is the ldapLockout key of a sign-in name at a directory: NFKC, Unicode case folding, NFKC again, every
// run of white space inside the name made one space and the ends trimmed, cut to ldapx.MaxLoginRunes. So "ADA", "ada",
// the full-width "ＡＤＡ", the decomposed "Çağla" and "John  Smith" with two spaces share one budget, close to how a
// directory's string preparation compares names (RFC 4518); spellings that still differ (aliases such as a UPN and
// the sAMAccountName) are caught by the per-account key. Callers pass only names ldapx.ValidLoginName accepts (which
// refuses the code points a directory maps to nothing).
func ldapLoginKey(directoryID uuid.UUID, login string) string {
	folded := norm.NFKC.String(cases.Fold().String(norm.NFKC.String(login)))
	runes := []rune(strings.Join(strings.FieldsFunc(folded, unicode.IsSpace), " "))
	if len(runes) > ldapx.MaxLoginRunes {
		runes = runes[:ldapx.MaxLoginRunes]
	}
	return directoryID.String() + "\x00" + string(runes)
}

// ldapAccountKey is the ldapAccountLockout key of a directory entry: its unique id at its directory.
func ldapAccountKey(directoryID uuid.UUID, uniqueID string) string {
	return directoryID.String() + "\x00" + uniqueID
}

// directoryAttempt holds the lockout reservations of one directory password attempt: the name key, reserved before
// any traffic, and the account key, reserved by gate between the user search and the user bind. Each reservation is
// settled exactly once by settle; the handlers defer release, which settles (neutrally) whatever no other path did,
// also on a panic or a cancelled request.
//
// When settling locks a key, the lockout's start is recorded (auth.ldap.lockout) for r, naming the entry the gate saw
// (uniqueID) and the sign-in name login under the rule of auth.ldap.denied.
type directoryAttempt struct {
	s           *server
	r           *http.Request
	directoryID uuid.UUID
	login       string // the sign-in name the attempt sent
	name        *ratelimit.Reservation
	mu          sync.Mutex
	account     *ratelimit.Reservation
	uniqueID    string // the entry the gate reserved, once it ran
}

// errAccountLocked: the gate refused an entry whose account key is locked (or has its attempts in flight).
var errAccountLocked = errors.New("api: the directory account is locked for sign-in")

// gate is the ldap.Gate of the attempt: it reserves the account key of the entry the user search found.
func (a *directoryAttempt) gate(uniqueID string) error {
	res, ok, _ := a.s.ldapAccountLockout.Reserve(ldapAccountKey(a.directoryID, uniqueID))
	a.mu.Lock()
	a.uniqueID = uniqueID // the entry the directory found, for the lockout's audit row
	if !ok {
		a.mu.Unlock()
		return errAccountLocked
	}
	prev := a.account
	a.account = res
	a.mu.Unlock()
	prev.Release() // a client that asked twice: the earlier slot never reached a bind
	return nil
}

// settle settles both reservations for the attempt's outcome: nil succeeds (clears both keys), a failed guess
// (countsAsFailure) fails both, a locked account (the gate refused: account_locked) fails the name and releases the
// account, anything else (the directory could not be used, a refusal after a correct password) releases both. Failing
// the name for a locked account makes another name of that account behave exactly like an unknown name (429 after
// three tries), so the lockout's answers do not tell an alias of a locked account from a name nobody has.
func (a *directoryAttempt) settle(err error) {
	a.mu.Lock()
	account, uniqueID := a.account, a.uniqueID
	a.mu.Unlock()
	var locked []string
	if gateRefused(err) {
		if a.name.Fail() {
			locked = append(locked, "name")
		}
		account.Release()
	} else {
		for i, r := range []*ratelimit.Reservation{a.name, account} {
			switch {
			case err == nil:
				r.Succeed()
			case countsAsFailure(err):
				if r.Fail() {
					locked = append(locked, [...]string{"name", "account"}[i])
				}
			default:
				r.Release()
			}
		}
	}
	if len(locked) > 0 && a.r != nil {
		a.s.recordDirectoryLockout(a.r, auth.LDAPIdentity{DirectoryID: a.directoryID, UniqueID: uniqueID, Login: a.login}, strings.Join(locked, ","))
	}
}

// recordDirectoryLockout writes auth.ldap.lockout (on a context the client cannot cancel); a failure to write is
// logged, never shown to the person.
func (s *server) recordDirectoryLockout(r *http.Request, id auth.LDAPIdentity, scope string) {
	if err := s.deps.Auth.RecordLDAPLockout(context.WithoutCancel(r.Context()), id, scope, int(ldapLockoutFor/time.Minute), s.meta(r)); err != nil {
		s.deps.Log.Error("recording a directory sign-in lockout failed", append([]any{"request_id", RequestID(r.Context())}, errorAttrs(err)...)...)
	}
}

// gateRefused reports whether err is the gate's refusal of a locked account.
func gateRefused(err error) bool {
	var le *ldap.LoginError
	return errors.As(err, &le) && le.Detail == ldap.DetailLocked
}

// release settles, without counting, whatever is still reserved.
func (a *directoryAttempt) release() { a.settle(errors.New("api: attempt ended")) }

// countsAsFailure reports whether a refusal is a failed guess for ldapLockout: the directory (or the password check
// before it) refused the name and password, found several entries, or accepted a password whose groups give no role.
func countsAsFailure(err error) bool {
	var le *ldap.LoginError
	if errors.As(err, &le) {
		if le.Detail == ldap.DetailLocked {
			return false // refused before the bind: no guess was made
		}
		return le.Reason == ldap.ReasonBadCredentials || le.Reason == ldap.ReasonAmbiguousUser
	}
	return errors.Is(err, errNoAccess)
}

// passwordBodyErrors checks a sign-in name and password against the sign-in form's limits.
func passwordBodyErrors(req *directoryPasswordBody, v *validate.Errors) {
	if utf8.RuneCountInString(req.Username) > maxLoginUsername {
		v.Add("username", validate.TooLong, map[string]string{"max": strconv.Itoa(maxLoginUsername)})
	}
	if utf8.RuneCount(req.Password) > maxLoginPassword {
		v.Add("password", validate.TooLong, map[string]string{"max": strconv.Itoa(maxLoginPassword)})
	}
}

// ldapPublicDirectories lists the enabled directories for the sign-in page: their ID and name only.
func (s *server) ldapPublicDirectories(w http.ResponseWriter, r *http.Request) {
	ds, err := s.deps.LDAP.PublicDirectories(r.Context())
	if err != nil {
		s.fail(w, r, err)
		return
	}
	out := make([]publicDirectoryDTO, 0, len(ds))
	for _, d := range ds {
		out = append(out, publicDirectoryDTO{ID: d.ID, Name: d.Name})
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": out})
}

// ldapLogin signs a person in with a directory password. The limits come first (the sign-in form's per address in the
// guard, then ldapLockout per directory and sign-in name, before any directory traffic and for unknown names too; a
// locked name is answered at once with 429); then the directory checks the password (no transaction is open), the
// group mappings give the role, and auth.SignInLDAP opens the session. A lockout key is made only for an existing,
// enabled directory and a name ldapx.ValidLoginName accepts, so made-up directory IDs or names cannot fill the table. The answer and the cookies are the sign-in form's: {status, csrf_token} with a
// pending session for MFA, or a full session when the directory does not ask for MFA (status signed_in). Every
// refusal that could say something about the person is the one ALC-LDAP-0001, recorded by RefuseLDAP with its reason
// and held to ldapRefusalFloor.
func (s *server) ldapLogin(w http.ResponseWriter, r *http.Request) {
	start := s.deps.Clock.Now()
	id, ok := pathUUID(r, "id")
	if !ok {
		s.writeError(w, r, ErrNotFound)
		return
	}
	var req directoryPasswordBody
	defer req.zero()
	if !s.decodeExact(w, r, &req, maxDirectoryPasswordBody, "username", "password") {
		return
	}
	var v validate.Errors
	passwordBodyErrors(&req, &v)
	if err := v.Err(); err != nil {
		s.fail(w, r, err)
		return
	}
	known, err := s.deps.LDAP.Directory(r.Context(), id)
	switch {
	case errors.Is(err, ldap.ErrNotFound):
		s.refuseDirectorySignIn(w, r, start, auth.LDAPIdentity{DirectoryID: id}, err)
		return
	case err != nil:
		s.fail(w, r, err)
		return
	}
	att := &directoryAttempt{s: s, r: r, directoryID: id, login: req.Username}
	defer att.release()
	if known.Enabled && ldapx.ValidLoginName(req.Username) {
		res, ok, retry := s.ldapLockout.Reserve(ldapLoginKey(id, req.Username))
		if !ok {
			s.writeRateLimited(w, r, retry)
			return
		}
		att.name = res
	}
	m := s.meta(r)
	ident, dir, err := s.deps.LDAP.VerifyGated(r.Context(), id, req.Username, secrets.NewPlaintext(req.Password), att.gate)
	req.zero()
	if err != nil {
		att.settle(err)
		s.refuseDirectorySignIn(w, r, start, auth.LDAPIdentity{DirectoryID: id, UniqueID: ident.UniqueID, Login: loginOf(ident, req.Username)}, err)
		return
	}
	full := auth.LDAPIdentity{DirectoryID: id, UniqueID: ident.UniqueID, Login: ident.Login, DisplayName: ident.DisplayName, Email: ident.Email}
	role, mapped, err := s.deps.LDAP.ResolveRole(r.Context(), id, ident.Groups)
	switch {
	case err != nil:
		s.fail(w, r, err)
		return
	case !mapped:
		att.settle(errNoAccess)
		s.refuseDirectorySignIn(w, r, start, full, errNoAccess)
		return
	}
	res, err := s.deps.Auth.SignInLDAP(r.Context(), full, role, dir.MFARequired, m)
	if err != nil {
		att.settle(err)
		s.refuseDirectorySignIn(w, r, start, full, err)
		return
	}
	att.settle(nil)
	s.issueSessionCookie(w, res.SessionToken) // a pending session (MFA routes only) or, with status signed_in, a full one
	writeJSON(w, http.StatusOK, map[string]string{"status": res.Status, "csrf_token": s.deps.Auth.CSRFToken(res.SessionToken)})
}

// errNoAccess: the directory accepted the password, but none of the person's groups is mapped to a role.
var errNoAccess = errors.New("api: no group of the directory user is mapped")

// loginOf is the sign-in name a refusal names: the directory's own value for a resolved entry, else the typed name
// (RefuseLDAP records it only for a resolved entry or several entries).
func loginOf(ident ldap.Identity, typed string) string {
	if ident.Login != "" {
		return ident.Login
	}
	return typed
}

// directoryRefusal is the audit reason and the answer of a refused directory sign-in or step-up; ok is false for an
// error that is not a refusal (a database failure), which fail answers.
func directoryRefusal(err error) (reason string, ec ErrorCode, ok bool) {
	var le *ldap.LoginError
	switch {
	case errors.As(err, &le):
		return le.Reason, ldapLoginCode(le), true
	case errors.Is(err, errNoAccess):
		return "no_access", ErrLDAPSignInRefused, true
	case errors.Is(err, auth.ErrLDAPEmailInUse):
		return "email_in_use", ErrLDAPSignInRefused, true
	case errors.Is(err, auth.ErrLDAPUserDisabled):
		return "user_disabled", ErrLDAPSignInRefused, true
	case errors.Is(err, auth.ErrLDAPUserLocked):
		return "locked", ErrLDAPSignInRefused, true
	case errors.Is(err, auth.ErrLDAPDirectoryDisabled):
		// Switched off after the directory checked the password: answered like a switched-off directory.
		return ldap.ReasonDisabled, ErrLDAPDirectoryUnavailable, true
	case errors.Is(err, auth.ErrLDAPIdentityInvalid):
		return "identity_invalid", ErrLDAPSignInRefused, true
	case errors.Is(err, auth.ErrLDAPOtherUser):
		return "stepup_other_user", ErrLDAPSignInRefused, true
	}
	return "", ErrorCode{}, false
}

// refuseDirectorySignIn answers a refused directory sign-in: RefuseLDAP records it (on a context the client cannot
// cancel), the answer waits until ldapRefusalFloor has passed since start, then the generic refusal (or, for a
// directory that is unreachable, misconfigured, switched off or missing, ALC-LDAP-0002) is written. A missing
// directory is not recorded: there is no directory to record it against.
func (s *server) refuseDirectorySignIn(w http.ResponseWriter, r *http.Request, start time.Time, id auth.LDAPIdentity, err error) {
	reason, ec, ok := directoryRefusal(err)
	switch {
	case errors.Is(err, ldap.ErrNotFound):
		ec = ErrLDAPDirectoryUnavailable
	case !ok:
		s.fail(w, r, err)
		return
	default:
		s.recordDirectoryRefusal(r, id, reason)
	}
	s.holdRefusal(r.Context(), start)
	s.writeError(w, r, ec)
}

// recordDirectoryRefusal writes auth.ldap.denied; a failure to write is logged, never shown to the person.
func (s *server) recordDirectoryRefusal(r *http.Request, id auth.LDAPIdentity, reason string) {
	if err := s.deps.Auth.RefuseLDAP(context.WithoutCancel(r.Context()), id, reason, s.meta(r)); err != nil {
		s.deps.Log.Error("recording a refused directory sign-in failed", append([]any{"request_id", RequestID(r.Context())}, errorAttrs(err)...)...)
	}
}

// holdRefusal waits on the server's clock until ldapRefusalFloor has passed since start, or until the request ends.
func (s *server) holdRefusal(ctx context.Context, start time.Time) {
	wait := s.ldapRefusalFloor - s.deps.Clock.Now().Sub(start)
	if wait <= 0 {
		return
	}
	select {
	case <-s.deps.Clock.After(wait):
	case <-ctx.Done():
	}
}

// ldapStepUp is a directory user's step-up ("Confirm it's you"): the directory checks the password again for the
// sign-in name Alice stored at the last sign-in (the caller cannot name another), the answer must be the session
// user's own entry, the groups give the role again, and, when the directory asks for MFA, the authenticator code is
// checked too. ldapLockout applies as at the sign-in. A user who does not sign in through a directory is refused with
// 409 ALC-LDAP-0008. Every refusal of the password, the entry or the user is recorded by RefuseLDAP with the session
// user as the actor (and never another entry's identity), held to ldapRefusalFloor and answered ALC-LDAP-0001 (or
// ALC-LDAP-0002 for a directory that cannot be used); a wrong code is ALC-AUTH-0006, recorded by StepUpLDAP.
func (s *server) ldapStepUp(w http.ResponseWriter, r *http.Request) {
	start := s.deps.Clock.Now()
	var req directoryPasswordBody
	defer req.zero()
	if !s.decodeExact(w, r, &req, maxDirectoryPasswordBody, "password", "code") {
		return
	}
	var v validate.Errors
	passwordBodyErrors(&req, &v)
	if len(req.Code) > maxTOTPCode {
		v.Add("code", validate.TooLong, map[string]string{"max": strconv.Itoa(maxTOTPCode)})
	}
	if err := v.Err(); err != nil {
		s.fail(w, r, err)
		return
	}
	p := principalFrom(r.Context())
	if p.AuthSource != auth.AuthLDAP || p.LDAPDirectoryID == uuid.Nil || p.LDAPUniqueID == "" || !ldapx.ValidLoginName(p.LDAPLogin) {
		s.writeError(w, r, ErrLDAPNotDirectoryUser)
		return
	}
	id := p.LDAPDirectoryID
	self := auth.LDAPIdentity{DirectoryID: id, UniqueID: p.LDAPUniqueID, Login: p.LDAPLogin}
	att := &directoryAttempt{s: s, r: r, directoryID: id, login: p.LDAPLogin}
	defer att.release()
	res, ok, retry := s.ldapLockout.Reserve(ldapLoginKey(id, p.LDAPLogin))
	if !ok {
		s.writeRateLimited(w, r, retry)
		return
	}
	att.name = res
	ident, dir, err := s.deps.LDAP.VerifyGated(r.Context(), id, p.LDAPLogin, secrets.NewPlaintext(req.Password), att.gate)
	req.zero()
	if err != nil {
		att.settle(err)
		s.refuseDirectorySignIn(w, r, start, self, err)
		return
	}
	if ident.UniqueID != p.LDAPUniqueID {
		// The stored name now finds another entry (renamed or reused in the directory): not this person.
		att.settle(auth.ErrLDAPOtherUser)
		s.refuseDirectorySignIn(w, r, start, self, auth.ErrLDAPOtherUser)
		return
	}
	full := auth.LDAPIdentity{DirectoryID: id, UniqueID: ident.UniqueID, Login: ident.Login, DisplayName: ident.DisplayName, Email: ident.Email}
	role, mapped, err := s.deps.LDAP.ResolveRole(r.Context(), id, ident.Groups)
	switch {
	case err != nil:
		s.fail(w, r, err)
		return
	case !mapped:
		att.settle(errNoAccess)
		s.refuseDirectorySignIn(w, r, start, self, errNoAccess)
		return
	}
	stepped, err := s.deps.Auth.StepUpLDAP(r.Context(), p, full, role, req.Code, dir.MFARequired, s.meta(r))
	if _, _, refusal := directoryRefusal(err); refusal {
		att.settle(err)
		s.refuseDirectorySignIn(w, r, start, self, err)
		return
	}
	if err != nil {
		// A wrong code (counted by StepUpLDAP) or a failure: the password was right, so neither key counts it.
		s.fail(w, r, err)
		return
	}
	att.settle(nil)
	s.rotated.Add(sessionTokenFrom(r))     // a late 401 for the old cookie must not delete the new one
	s.issueSessionCookie(w, stepped.Token) // session ID is regenerated on step-up (SEC-019)
	writeJSON(w, http.StatusOK, sessionJSON(stepped.Info, nil))
}

func (s *server) writeDirectory(w http.ResponseWriter, status int, d ldap.Directory) {
	w.Header().Set("ETag", etag(d.Version))
	writeJSON(w, status, directoryJSON(d))
}

func (s *server) listDirectories(w http.ResponseWriter, r *http.Request) {
	ds, err := s.deps.LDAP.Directories(r.Context())
	if err != nil {
		s.fail(w, r, err)
		return
	}
	out := make([]directoryDTO, 0, len(ds))
	for _, d := range ds {
		out = append(out, directoryJSON(d))
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": out})
}

// createDirectory adds a directory. It is created switched off unless the body says enabled true; MFA is on unless the
// body says mfa_required false. Nothing is dialled: Test connection checks the settings.
func (s *server) createDirectory(w http.ResponseWriter, r *http.Request) {
	var req directoryBody
	defer req.zero()
	if !s.decodeExact(w, r, &req, maxDirectoryBody, directoryKeys...) {
		return
	}
	in := ldap.DirectoryInput{Name: req.Name.Value, Addresses: req.Addresses.Value, UserBaseDN: req.UserBaseDN.Value,
		UserFilter: req.UserFilter.Value, LoginAttribute: req.LoginAttribute.Value, UniqueIDAttribute: req.UniqueIDAttribute.Value,
		DisplayNameAttribute: req.DisplayNameAttribute.Value, EmailAttribute: req.EmailAttribute.Value, BindDN: req.BindDN.Value,
		GroupBaseDN: req.GroupBaseDN.Value, GroupFilter: req.GroupFilter.Value, GroupNameAttribute: req.GroupNameAttribute.Value,
		CAPEM: req.CAPEM.Value, MFARequired: req.MFARequired.ptr(), Enabled: req.Enabled.Value}
	if req.BindPassword.set {
		in.BindPassword = secrets.NewPlaintext(req.BindPassword.secretText)
	}
	d, err := s.deps.LDAP.CreateDirectory(r.Context(), principalFrom(r.Context()).Actor(s.meta(r)), in)
	req.zero()
	if err != nil {
		s.fail(w, r, err)
		return
	}
	s.writeDirectory(w, http.StatusCreated, d)
}

func (s *server) getDirectory(w http.ResponseWriter, r *http.Request) {
	id, ok := pathUUID(r, "id")
	if !ok {
		s.writeError(w, r, ErrNotFound)
		return
	}
	d, err := s.deps.LDAP.Directory(r.Context(), id)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	s.writeDirectory(w, http.StatusOK, d)
}

// updateDirectory changes the given fields (If-Match required). An omitted bind_password keeps the stored one; a change
// that would send it to another server or account (a new address, bind DN, unique id attribute or authority) needs it
// again (the service's validation error).
func (s *server) updateDirectory(w http.ResponseWriter, r *http.Request) {
	id, ok := pathUUID(r, "id")
	if !ok {
		s.writeError(w, r, ErrNotFound)
		return
	}
	version, ok := ifMatch(r)
	if !ok {
		s.writeError(w, r, ErrPreconditionFailed)
		return
	}
	var req directoryBody
	defer req.zero()
	if !s.decodeExact(w, r, &req, maxDirectoryBody, directoryKeys...) {
		return
	}
	patch := ldap.DirectoryPatch{Name: req.Name.ptr(), Addresses: req.Addresses.ptr(), UserBaseDN: req.UserBaseDN.ptr(),
		UserFilter: req.UserFilter.ptr(), LoginAttribute: req.LoginAttribute.ptr(), UniqueIDAttribute: req.UniqueIDAttribute.ptr(),
		DisplayNameAttribute: req.DisplayNameAttribute.ptr(), EmailAttribute: req.EmailAttribute.ptr(), BindDN: req.BindDN.ptr(),
		GroupBaseDN: req.GroupBaseDN.ptr(), GroupFilter: req.GroupFilter.ptr(), GroupNameAttribute: req.GroupNameAttribute.ptr(),
		CAPEM: req.CAPEM.ptr(), MFARequired: req.MFARequired.ptr(), Enabled: req.Enabled.ptr()}
	if req.BindPassword.set {
		bind := secrets.NewPlaintext(req.BindPassword.secretText)
		patch.BindPassword = &bind
	}
	d, err := s.deps.LDAP.UpdateDirectory(r.Context(), principalFrom(r.Context()).Actor(s.meta(r)), id, version, patch)
	req.zero()
	if err != nil {
		s.fail(w, r, err)
		return
	}
	s.writeDirectory(w, http.StatusOK, d)
}

// deleteDirectory removes a directory (If-Match required). A directory people have signed in through is refused (409
// ALC-LDAP-0003): switch it off instead.
func (s *server) deleteDirectory(w http.ResponseWriter, r *http.Request) {
	id, ok := pathUUID(r, "id")
	if !ok {
		s.writeError(w, r, ErrNotFound)
		return
	}
	version, ok := ifMatch(r)
	if !ok {
		s.writeError(w, r, ErrPreconditionFailed)
		return
	}
	if err := s.deps.LDAP.DeleteDirectory(r.Context(), principalFrom(r.Context()).Actor(s.meta(r)), id, version); err != nil {
		s.fail(w, r, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// testParams are the params of a failed test: the closed reason and where it stopped, never the server's text.
func testParams(le *ldap.LoginError) map[string]string {
	params := map[string]string{"reason": le.Reason, "detail": "-"}
	if le.Detail != "" {
		params["detail"] = le.Detail
	}
	return params
}

// testDirectoryConnection binds as the directory's service account and searches the user base DN once (empty body or
// {}). A failure is 422 ALC-LDAP-0004 with the reason and where it stopped; every run is audited.
func (s *server) testDirectoryConnection(w http.ResponseWriter, r *http.Request) {
	id, ok := pathUUID(r, "id")
	if !ok {
		s.writeError(w, r, ErrNotFound)
		return
	}
	if !s.decodeExactOptional(w, r, &struct{}{}, maxActionBody) {
		return
	}
	err := s.deps.LDAP.TestConnection(r.Context(), principalFrom(r.Context()).Actor(s.meta(r)), id)
	var le *ldap.LoginError
	switch {
	case errors.As(err, &le):
		s.writeErrorWith(w, r, ErrLDAPConnectionTestFailed, testParams(le), nil)
	case err != nil:
		s.fail(w, r, err)
	default:
		writeJSON(w, http.StatusOK, map[string]string{"result": "ok"})
	}
}

// testDirectorySignIn runs a directory sign-in with the stored settings without signing anyone in: the answer shows
// the identity, the groups found and the role the mappings would give. The password is never stored and is zeroed on
// every path. A refused attempt is 422 ALC-LDAP-0006 with the reason and where it stopped; every run is audited.
func (s *server) testDirectorySignIn(w http.ResponseWriter, r *http.Request) {
	id, ok := pathUUID(r, "id")
	if !ok {
		s.writeError(w, r, ErrNotFound)
		return
	}
	var req directoryPasswordBody
	defer req.zero()
	if !s.decodeExact(w, r, &req, maxDirectoryPasswordBody, "username", "password") {
		return
	}
	var v validate.Errors
	passwordBodyErrors(&req, &v)
	if err := v.Err(); err != nil {
		s.fail(w, r, err)
		return
	}
	// The sign-in's lockouts apply to a test too (the same keys and settle rules): a test sends the name and password to
	// the directory like a sign-in, so a locked name is not tested (429), a locked account is never bound to, a failed
	// test counts, a test that gives a role clears the counts, and one without a role is neutral. Reserve makes a key
	// only for the attempt; a released attempt of a made-up directory ID or name leaves nothing behind.
	att := &directoryAttempt{s: s, r: r, directoryID: id, login: req.Username}
	defer att.release()
	if ldapx.ValidLoginName(req.Username) {
		res, ok, retry := s.ldapLockout.Reserve(ldapLoginKey(id, req.Username))
		if !ok {
			s.writeRateLimited(w, r, retry)
			return
		}
		att.name = res
	}
	res, err := s.deps.LDAP.TestSignInGated(r.Context(), principalFrom(r.Context()).Actor(s.meta(r)), id, req.Username,
		secrets.NewPlaintext(req.Password), att.gate)
	req.zero()
	var le *ldap.LoginError
	switch {
	case errors.As(err, &le):
		att.settle(err)
		s.writeErrorWith(w, r, ErrLDAPSignInTestFailed, testParams(le), nil)
	case err != nil:
		s.fail(w, r, err)
	case res.Role == "":
		att.release() // the password was right; no role is neither a guess nor a success
		writeJSON(w, http.StatusOK, directoryTestJSON(res))
	default:
		att.settle(nil)
		writeJSON(w, http.StatusOK, directoryTestJSON(res))
	}
}

// directoryQuery reads the required ?directory_id of the mapping routes; it answers 422 itself.
func (s *server) directoryQuery(w http.ResponseWriter, r *http.Request) (uuid.UUID, bool) {
	raw := r.URL.Query().Get("directory_id")
	var v validate.Errors
	id := optionalUUID(raw, "directory_id", &v)
	if raw == "" {
		v.Add("directory_id", validate.Required, nil)
	}
	if err := v.Err(); err != nil {
		s.fail(w, r, err)
		return uuid.Nil, false
	}
	return id, true
}

func (s *server) listDirectoryMappings(w http.ResponseWriter, r *http.Request) {
	directoryID, ok := s.directoryQuery(w, r)
	if !ok {
		return
	}
	ms, err := s.deps.LDAP.Mappings(r.Context(), directoryID)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	out := make([]directoryMappingDTO, 0, len(ms))
	for _, m := range ms {
		out = append(out, directoryMappingJSON(m))
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": out})
}

// createDirectoryMapping gives the members of a directory group a role. Mapping a group to Administrator needs "SSO
// users may be Admin" switched on (409 ALC-SSO-0002); too many mappings is a field error on group.
func (s *server) createDirectoryMapping(w http.ResponseWriter, r *http.Request) {
	var req struct {
		DirectoryID string `json:"directory_id"`
		Group       string `json:"group"`
		Role        string `json:"role"`
	}
	if !s.decodeExact(w, r, &req, maxActionBody, "directory_id", "group", "role") {
		return
	}
	var v validate.Errors
	directoryID := optionalUUID(req.DirectoryID, "directory_id", &v)
	if req.DirectoryID == "" {
		v.Add("directory_id", validate.Required, nil)
	}
	role, ok := rbac.ParseRole(req.Role)
	if !ok {
		v.Add("role", validate.OneOf, map[string]string{"values": "admin, operator, auditor"})
	}
	if err := v.Err(); err != nil {
		s.fail(w, r, err)
		return
	}
	m, err := s.deps.LDAP.CreateMapping(r.Context(), principalFrom(r.Context()).Actor(s.meta(r)), directoryID, req.Group, role)
	if errors.Is(err, ldap.ErrTooMany) {
		s.fail(w, r, validate.Errors{{Field: "group", Code: validate.OutOfRange, Params: map[string]string{"min": "1", "max": strconv.Itoa(ldap.MaxMappings)}}})
		return
	}
	if err != nil {
		s.fail(w, r, err)
		return
	}
	writeJSON(w, http.StatusCreated, directoryMappingJSON(m))
}

// deleteDirectoryMapping removes a group mapping of the directory named by ?directory_id. The service deletes by
// mapping alone, so the handler first checks that this directory holds it (another directory's mapping is not found).
func (s *server) deleteDirectoryMapping(w http.ResponseWriter, r *http.Request) {
	id, ok := pathUUID(r, "id")
	if !ok {
		s.writeError(w, r, ErrNotFound)
		return
	}
	directoryID, ok := s.directoryQuery(w, r)
	if !ok {
		return
	}
	ms, err := s.deps.LDAP.Mappings(r.Context(), directoryID)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	if !slices.ContainsFunc(ms, func(m ldap.Mapping) bool { return m.ID == id }) {
		s.writeError(w, r, ErrNotFound)
		return
	}
	if err := s.deps.LDAP.DeleteMapping(r.Context(), principalFrom(r.Context()).Actor(s.meta(r)), id); err != nil {
		s.fail(w, r, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}
