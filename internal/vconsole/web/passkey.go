package web

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"sync"
	"time"

	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"
	"github.com/jackc/pgx/v5"

	"alice/internal/platform/clock"
	"alice/internal/vconsole/webuser"
)

// Ceremony state lives in memory: the service runs as a single instance (plan ruling 1) and a
// lost ceremony only means pressing the button again.
const (
	ceremonyTTL  = 5 * time.Minute
	kindRegister = "register"
	kindLogin    = "login"
)

var errBusy = errors.New("web: too many ceremonies in progress")

// Generic answers: the client learns only that it failed, never why.
var (
	enrollFailed = map[string]string{"error": "enrollment failed"}
	loginFailed  = map[string]string{"error": "login failed"}
)

type ceremony struct {
	kind    string
	session webauthn.SessionData
	userID  int64  // registration: the user the code belongs to
	code    string // registration: consumed only when the ceremony succeeds
	expires time.Time
}

type ceremonies struct {
	mu  sync.Mutex
	clk clock.Clock
	max int
	m   map[string]ceremony
}

func newCeremonies(clk clock.Clock, maxEntries int) *ceremonies {
	return &ceremonies{clk: clk, max: maxEntries, m: map[string]ceremony{}}
}

// put stores c for ceremonyTTL under a new random ID. Expired entries are pruned first; when the
// store is still full the caller gets errBusy, which bounds memory under a flood of begins.
func (cs *ceremonies) put(c ceremony) (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("web: random: %w", err)
	}
	id := base64.RawURLEncoding.EncodeToString(b)
	cs.mu.Lock()
	defer cs.mu.Unlock()
	now := cs.clk.Now()
	for k, v := range cs.m {
		if !now.Before(v.expires) {
			delete(cs.m, k)
		}
	}
	if len(cs.m) >= cs.max {
		return "", errBusy
	}
	c.expires = now.Add(ceremonyTTL)
	cs.m[id] = c
	return id, nil
}

// take removes and returns the ceremony; it is gone after one attempt whatever the outcome, so a
// captured response cannot be replayed against it.
func (cs *ceremonies) take(id, kind string) (ceremony, bool) {
	cs.mu.Lock()
	defer cs.mu.Unlock()
	c, ok := cs.m[id]
	if !ok {
		return ceremony{}, false
	}
	delete(cs.m, id)
	if c.kind != kind || !cs.clk.Now().Before(c.expires) {
		return ceremony{}, false
	}
	return c, true
}

// setCeremonyCookie sets the ceremony cookie (s.ceremonyCookie: "__Host-vceremony" for https
// origins, "vceremony" otherwise). The __Host- prefix requires Path=/.
func (s *Server) setCeremonyCookie(w http.ResponseWriter, id string, maxAge int) {
	http.SetCookie(w, &http.Cookie{ //nolint:gosec // G124: Secure is false only for the http://localhost origin, where browsers would drop it
		Name: s.ceremonyCookie, Value: id, Path: "/", MaxAge: maxAge,
		HttpOnly: true, Secure: s.secure, SameSite: http.SameSiteStrictMode,
	})
}

// takeCeremony consumes the ceremony named by the request's cookie and clears the cookie.
func (s *Server) takeCeremony(w http.ResponseWriter, r *http.Request, kind string) (ceremony, bool) {
	c, err := r.Cookie(s.ceremonyCookie)
	if err != nil {
		return ceremony{}, false
	}
	s.setCeremonyCookie(w, "", -1)
	return s.ceremonies.take(c.Value, kind)
}

// userHandle is the WebAuthn user handle: the user's ID as 8 big-endian bytes. It is stable and
// carries no personal data.
func userHandle(id int64) []byte {
	return binary.BigEndian.AppendUint64(nil, uint64(id)) //nolint:gosec // G115: IDs are positive identity values
}

func userIDFromHandle(h []byte) (int64, bool) {
	if len(h) != 8 {
		return 0, false
	}
	return int64(binary.BigEndian.Uint64(h)), true //nolint:gosec // G115: round trip of userHandle
}

// waUser adapts a web user and their stored passkeys to the library's User.
type waUser struct {
	u     webuser.User
	creds []webauthn.Credential
}

func (a *waUser) WebAuthnID() []byte                         { return userHandle(a.u.ID) }
func (a *waUser) WebAuthnName() string                       { return a.u.Name }
func (a *waUser) WebAuthnDisplayName() string                { return a.u.Name }
func (a *waUser) WebAuthnCredentials() []webauthn.Credential { return a.creds }

func (s *Server) loadWAUser(r *http.Request, u webuser.User) (*waUser, error) {
	stored, err := webuser.Credentials(r.Context(), s.cfg.Pool, u.ID)
	if err != nil {
		return nil, err
	}
	a := &waUser{u: u}
	for _, sc := range stored {
		var c webauthn.Credential
		if err := json.Unmarshal(sc.JSON, &c); err != nil {
			return nil, fmt.Errorf("web: stored credential: %w", err)
		}
		a.creds = append(a.creds, c)
	}
	return a, nil
}

// limitBody caps the request body before the library or a decoder reads it.
func limitBody(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, maxJSONBody)
}

// registerBegin checks the enrollment code (without consuming it) and returns creation options.
func (s *Server) registerBegin(w http.ResponseWriter, r *http.Request) {
	limitBody(w, r)
	var in struct {
		Code string `json:"code"`
	}
	if err := json.NewDecoder(r.Body).Decode(&in); err != nil || in.Code == "" || len(in.Code) > 128 {
		writeJSON(w, http.StatusBadRequest, enrollFailed)
		return
	}
	if s.cfg.Pool == nil {
		writeJSON(w, http.StatusBadRequest, enrollFailed)
		return
	}
	u, err := webuser.LookupEnrollment(r.Context(), s.cfg.Pool, in.Code, s.cfg.Clock.Now())
	if err != nil {
		s.fail(w, "register begin", err, enrollFailed)
		return
	}
	a, err := s.loadWAUser(r, u)
	if err != nil {
		s.fail(w, "register begin", err, enrollFailed)
		return
	}
	// Exclude the user's existing passkeys so the same authenticator is not registered twice.
	excl := make([]protocol.CredentialDescriptor, 0, len(a.creds))
	for _, c := range a.creds {
		excl = append(excl, c.Descriptor())
	}
	creation, sess, err := s.wa.BeginRegistration(a, webauthn.WithExclusions(excl))
	if err != nil {
		s.fail(w, "register begin", err, enrollFailed)
		return
	}
	id, err := s.ceremonies.put(ceremony{kind: kindRegister, session: *sess, userID: u.ID, code: in.Code})
	if err != nil {
		s.log.Warn("web: register begin", "err", err)
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "busy, try again shortly"})
		return
	}
	s.setCeremonyCookie(w, id, int(ceremonyTTL.Seconds()))
	writeJSON(w, http.StatusOK, creation)
}

// registerFinish verifies the attestation, then consumes the code and stores the passkey in one
// transaction: a failed ceremony or a failed insert leaves the code usable.
func (s *Server) registerFinish(w http.ResponseWriter, r *http.Request) {
	limitBody(w, r)
	c, ok := s.takeCeremony(w, r, kindRegister)
	if !ok || s.cfg.Pool == nil {
		writeJSON(w, http.StatusBadRequest, enrollFailed)
		return
	}
	ctx := r.Context()
	now := s.cfg.Clock.Now()
	u, err := webuser.LookupEnrollment(ctx, s.cfg.Pool, c.code, now)
	if err != nil || u.ID != c.userID {
		s.fail(w, "register finish", err, enrollFailed)
		return
	}
	a, err := s.loadWAUser(r, u)
	if err != nil {
		s.fail(w, "register finish", err, enrollFailed)
		return
	}
	cred, err := s.wa.FinishRegistration(a, c.session, r)
	if err != nil {
		s.fail(w, "register finish", err, enrollFailed)
		return
	}
	raw, err := json.Marshal(cred)
	if err != nil {
		s.fail(w, "register finish", err, enrollFailed)
		return
	}
	// Not inActorTx: nobody is signed in yet, so the service acts as itself.
	tx, err := s.cfg.Pool.Begin(ctx)
	if err != nil {
		s.fail(w, "register finish", err, enrollFailed)
		return
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if err := webuser.ConsumeEnrollment(ctx, tx, c.code, now); err != nil {
		s.fail(w, "register finish", err, enrollFailed)
		return
	}
	if err := webuser.AddCredential(ctx, tx, u.ID, cred.ID, raw); err != nil {
		s.fail(w, "register finish", err, enrollFailed)
		return
	}
	if err := tx.Commit(ctx); err != nil {
		s.fail(w, "register finish", err, enrollFailed)
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"redirect": "/login"})
}

// loginBegin starts a discoverable login: the authenticator offers the user's passkey, no name is
// typed. It does not touch the database.
func (s *Server) loginBegin(w http.ResponseWriter, r *http.Request) {
	assertion, sess, err := s.wa.BeginDiscoverableLogin()
	if err != nil {
		s.fail(w, "login begin", err, loginFailed)
		return
	}
	id, err := s.ceremonies.put(ceremony{kind: kindLogin, session: *sess})
	if err != nil {
		s.log.Warn("web: login begin", "err", err)
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "busy, try again shortly"})
		return
	}
	s.setCeremonyCookie(w, id, int(ceremonyTTL.Seconds()))
	writeJSON(w, http.StatusOK, assertion)
}

// errLogin is what the user lookup reports for every refusal; the cause stays in the server log.
var errLogin = errors.New("web: unknown, mismatched or disabled user")

// loginFinish verifies the assertion, refuses disabled users, stores the new sign counter, starts
// a session and audits the sign-in, all as the person (inActorTx).
func (s *Server) loginFinish(w http.ResponseWriter, r *http.Request) {
	limitBody(w, r)
	c, ok := s.takeCeremony(w, r, kindLogin)
	if !ok || s.cfg.Pool == nil {
		writeJSON(w, http.StatusBadRequest, loginFailed)
		return
	}
	ctx := r.Context()
	var who webuser.User
	handler := func(rawID, handle []byte) (webauthn.User, error) {
		id, ok := userIDFromHandle(handle)
		if !ok {
			return nil, errLogin
		}
		// UserByCredential also returns disabled users; they are refused here, with the same
		// answer as an unknown credential.
		u, err := webuser.UserByCredential(ctx, s.cfg.Pool, rawID)
		if err != nil {
			if errors.Is(err, webuser.ErrNotFound) {
				return nil, errLogin
			}
			return nil, err
		}
		if u.ID != id || u.Disabled {
			return nil, errLogin
		}
		a, err := s.loadWAUser(r, u)
		if err != nil {
			return nil, err
		}
		who = u
		return a, nil
	}
	cred, err := s.wa.FinishDiscoverableLogin(handler, c.session, r)
	if err != nil {
		s.fail(w, "login finish", err, loginFailed)
		return
	}
	// A counter that went backwards means the key may have been copied: refuse rather than guess.
	if cred.Authenticator.CloneWarning {
		s.fail(w, "login finish", errors.New("web: sign counter went backwards (possible cloned authenticator)"), loginFailed)
		return
	}
	raw, err := json.Marshal(cred)
	if err != nil {
		s.fail(w, "login finish", err, loginFailed)
		return
	}
	now := s.cfg.Clock.Now()
	var token string
	err = s.inActorTx(ctx, who, func(tx pgx.Tx) error {
		if err := webuser.UpdateCredential(ctx, tx, cred.ID, raw, now); err != nil {
			return err
		}
		var err error
		if token, err = webuser.NewSession(ctx, tx, who.ID, now); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `SELECT web_audit_login($1)`, who.Name); err != nil {
			return fmt.Errorf("web: audit login: %w", err)
		}
		return nil
	})
	if err != nil {
		s.fail(w, "login finish", err, loginFailed)
		return
	}
	http.SetCookie(w, s.sessionCookie(token, int(webuser.SessionAbsolute.Seconds())))
	writeJSON(w, http.StatusOK, map[string]string{"redirect": "/"})
}

// fail logs the cause (never a token or code: none of the errors here carry one) and sends the
// generic answer.
func (s *Server) fail(w http.ResponseWriter, step string, err error, answer map[string]string) {
	if err == nil {
		err = errLogin
	}
	var perr *protocol.Error
	if errors.As(err, &perr) {
		s.log.Info("web: "+step+" refused", "err", perr.Type, "details", perr.Details)
	} else {
		s.log.Info("web: "+step+" refused", "err", err)
	}
	writeJSON(w, http.StatusBadRequest, answer)
}
