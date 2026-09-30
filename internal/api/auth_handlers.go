package api

import (
	"net/http"

	"alice/internal/auth"
	"alice/internal/platform/validate"
	"alice/internal/rbac"
)

// authRoutes implement sign-in, MFA and the signed-in user's own account
// (spec §9.2, SEC-006..SEC-009, SEC-018, SEC-019).
func (s *server) authRoutes() []route {
	return []route{
		{method: http.MethodPost, pattern: "/api/v1/auth/login", perm: rbac.Public, limit: limitLogin, handler: s.authLogin},
		{method: http.MethodPost, pattern: "/api/v1/auth/mfa/enroll", perm: rbac.MFAPending, handler: s.authEnroll},
		{method: http.MethodPost, pattern: "/api/v1/auth/mfa/verify", perm: rbac.MFAPending, limit: limitMFA, handler: s.authVerify},
		{method: http.MethodGet, pattern: "/api/v1/auth/session", perm: rbac.Session, handler: s.authSession},
		{method: http.MethodPost, pattern: "/api/v1/auth/logout", perm: rbac.Session, handler: s.authLogout},
		{method: http.MethodPost, pattern: "/api/v1/auth/stepup", perm: rbac.Session, limit: limitMFA, handler: s.authStepUp},
		{method: http.MethodPost, pattern: "/api/v1/auth/password", perm: rbac.Session, limit: limitLogin, handler: s.authPassword},
		{method: http.MethodPost, pattern: "/api/v1/auth/recovery-codes", perm: rbac.SessionStepUp, handler: s.authRecoveryCodes},
		{method: http.MethodPut, pattern: "/api/v1/auth/locale", perm: rbac.Session, handler: s.authLocale},
	}
}

func (s *server) authLogin(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}
	if !s.decode(w, r, &req) {
		return
	}
	res, err := s.deps.Auth.Login(r.Context(), req.Username, req.Password, s.meta(r))
	if err != nil {
		s.fail(w, r, err)
		return
	}
	setSessionCookie(w, res.SessionToken) // pending session: only MFA routes accept it
	// The MFA enroll/verify calls that follow are cookie-authenticated POSTs, so
	// the client needs the CSRF token bound to the pending session.
	writeJSON(w, http.StatusOK, map[string]string{"status": res.Status, "csrf_token": s.deps.Auth.CSRFToken(res.SessionToken)})
}

func (s *server) authEnroll(w http.ResponseWriter, r *http.Request) {
	e, err := s.deps.Auth.EnrollMFA(r.Context(), principalFrom(r.Context()), s.meta(r))
	if err != nil {
		s.fail(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, enrollmentJSON(e))
}

func (s *server) authVerify(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Code         string `json:"code"`
		RecoveryCode string `json:"recovery_code"`
	}
	if !s.decode(w, r, &req) {
		return
	}
	if req.Code == "" && req.RecoveryCode == "" {
		var v validate.Errors
		v.Add("code", validate.Required, nil)
		s.fail(w, r, v)
		return
	}
	res, err := s.deps.Auth.VerifyMFA(r.Context(), principalFrom(r.Context()), auth.MFAInput{Code: req.Code, RecoveryCode: req.RecoveryCode}, s.meta(r))
	if err != nil {
		s.fail(w, r, err)
		return
	}
	setSessionCookie(w, res.Token) // new session ID after MFA (fixation defence)
	writeJSON(w, http.StatusOK, sessionJSON(res.Info, res.RecoveryCodes))
}

func (s *server) authSession(w http.ResponseWriter, r *http.Request) {
	si, err := s.deps.Auth.SessionInfo(r.Context(), principalFrom(r.Context()), sessionTokenFrom(r))
	if err != nil {
		s.fail(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, sessionJSON(si, nil))
}

func (s *server) authLogout(w http.ResponseWriter, r *http.Request) {
	if err := s.deps.Auth.Logout(r.Context(), principalFrom(r.Context()), s.meta(r)); err != nil {
		s.fail(w, r, err)
		return
	}
	clearSessionCookie(w)
	noContent(w)
}

func (s *server) authStepUp(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Code string `json:"code"`
	}
	if !s.decode(w, r, &req) {
		return
	}
	res, err := s.deps.Auth.StepUp(r.Context(), principalFrom(r.Context()), req.Code, s.meta(r))
	if err != nil {
		s.fail(w, r, err)
		return
	}
	setSessionCookie(w, res.Token) // session ID is regenerated on step-up (SEC-019)
	writeJSON(w, http.StatusOK, sessionJSON(res.Info, nil))
}

func (s *server) authPassword(w http.ResponseWriter, r *http.Request) {
	var req struct {
		CurrentPassword string `json:"current_password"`
		NewPassword     string `json:"new_password"`
	}
	if !s.decode(w, r, &req) {
		return
	}
	res, err := s.deps.Auth.ChangePassword(r.Context(), principalFrom(r.Context()), req.CurrentPassword, req.NewPassword, s.meta(r))
	if err != nil {
		s.fail(w, r, err)
		return
	}
	setSessionCookie(w, res.Token) // every other session was revoked
	writeJSON(w, http.StatusOK, sessionJSON(res.Info, nil))
}

func (s *server) authRecoveryCodes(w http.ResponseWriter, r *http.Request) {
	codes, err := s.deps.Auth.RegenerateRecoveryCodes(r.Context(), principalFrom(r.Context()), s.meta(r))
	if err != nil {
		s.fail(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string][]string{"recovery_codes": codes})
}

func (s *server) authLocale(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Locale string `json:"locale"`
	}
	if !s.decode(w, r, &req) {
		return
	}
	if err := s.deps.Auth.SetLocale(r.Context(), principalFrom(r.Context()), req.Locale); err != nil {
		s.fail(w, r, err)
		return
	}
	noContent(w)
}
