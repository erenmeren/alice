package api

import (
	"errors"
	"net/http"

	"alice/internal/license"
	"alice/internal/rbac"
	"alice/internal/setup"
)

// setupRoutes serve the first-run wizard (spec §18.5). Until an administrator
// exists only the setup session can use them; afterwards starting a session
// answers 404 and the remaining steps (recovery passphrase, license choice, completion) need
// the signed-in administrator with a fresh step-up: settings.manage, the same
// check setup.Service repeats for both.
func (s *server) setupRoutes() []route {
	return []route{
		{method: http.MethodGet, pattern: "/api/v1/setup/status", perm: rbac.Public, handler: s.setupStatus},
		{method: http.MethodPost, pattern: "/api/v1/setup/session", perm: rbac.Public, limit: limitLogin, lic: license.ClassAlways, handler: s.setupStartSession},
		{method: http.MethodPut, pattern: "/api/v1/setup/language", perm: rbac.Setup, lic: license.ClassAlways, handler: s.setupLanguage},
		{method: http.MethodPost, pattern: "/api/v1/setup/admin/enrollment", perm: rbac.Setup, lic: license.ClassAlways, handler: s.setupEnrollment},
		{method: http.MethodPost, pattern: "/api/v1/setup/admin", perm: rbac.Setup, limit: limitMFA, lic: license.ClassAlways, handler: s.setupCreateAdmin},
		{method: http.MethodPost, pattern: "/api/v1/setup/recovery-passphrase", perm: rbac.SettingsManage, lic: license.ClassAlways, handler: s.setupRecoveryPassphrase},
		{method: http.MethodPost, pattern: "/api/v1/setup/evaluation", perm: rbac.SettingsManage, lic: license.ClassAlways, handler: s.setupEvaluation},
		{method: http.MethodPost, pattern: "/api/v1/setup/complete", perm: rbac.SettingsManage, lic: license.ClassAlways, handler: s.setupComplete},
	}
}

func (s *server) setupStatus(w http.ResponseWriter, r *http.Request) {
	st, err := s.deps.Setup.Status(r.Context())
	if err != nil {
		s.fail(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, setupStatusJSON(st))
}

func (s *server) setupStartSession(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Code string `json:"code"`
	}
	if !s.decode(w, r, &req) {
		return
	}
	m := s.meta(r)
	token, err := s.deps.Setup.StartSession(r.Context(), req.Code, m)
	if err != nil {
		var locked *setup.LockedError
		if errors.Is(err, setup.ErrCodeInvalid) || errors.As(err, &locked) {
			// Spec §18.5: every attempt is logged. The code itself never is.
			s.deps.Log.Warn("setup code rejected", "request_id", m.RequestID, "ip", m.IP.String())
		}
		s.fail(w, r, err)
		return
	}
	s.deps.Log.Info("setup session started", "request_id", m.RequestID, "ip", m.IP.String())
	setSetupCookie(w, token)
	writeJSON(w, http.StatusOK, map[string]string{"csrf_token": s.deps.Auth.CSRFToken(token)})
}

func (s *server) setupLanguage(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Language string `json:"language"`
	}
	if !s.decode(w, r, &req) {
		return
	}
	if err := s.deps.Setup.SetLanguage(r.Context(), setupTokenFrom(r), req.Language); err != nil {
		s.fail(w, r, err)
		return
	}
	noContent(w)
}

func (s *server) setupEnrollment(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Username    string `json:"username"`
		DisplayName string `json:"display_name"`
		Email       string `json:"email"`
		Password    string `json:"password"`
	}
	if !s.decode(w, r, &req) {
		return
	}
	e, err := s.deps.Setup.BeginAdminEnrollment(r.Context(), setupTokenFrom(r), setup.AdminInput{
		Username: req.Username, DisplayName: req.DisplayName, Email: req.Email, Password: req.Password,
	})
	if err != nil {
		s.fail(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, enrollmentJSON(e))
}

func (s *server) setupCreateAdmin(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Code string `json:"code"`
	}
	if !s.decode(w, r, &req) {
		return
	}
	res, err := s.deps.Setup.CreateAdmin(r.Context(), setupTokenFrom(r), req.Code, s.meta(r))
	if err != nil {
		s.fail(w, r, err)
		return
	}
	setSessionCookie(w, res.Token)
	clearSetupCookie(w)
	writeJSON(w, http.StatusOK, sessionJSON(res.Info, res.RecoveryCodes))
}

func (s *server) setupRecoveryPassphrase(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Passphrase        string `json:"passphrase"`
		PassphraseConfirm string `json:"passphrase_confirm"`
	}
	if !s.decode(w, r, &req) {
		return
	}
	if err := s.deps.Setup.SetRecoveryPassphrase(r.Context(), principalFrom(r.Context()), s.meta(r), req.Passphrase, req.PassphraseConfirm); err != nil {
		s.fail(w, r, err)
		return
	}
	noContent(w)
}

func (s *server) setupEvaluation(w http.ResponseWriter, r *http.Request) {
	st, err := s.deps.Setup.ChooseEvaluation(r.Context(), principalFrom(r.Context()), s.meta(r))
	if err != nil {
		s.fail(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, setupStatusJSON(st))
}

func (s *server) setupComplete(w http.ResponseWriter, r *http.Request) {
	st, err := s.deps.Setup.Complete(r.Context(), principalFrom(r.Context()), s.meta(r))
	if err != nil {
		s.fail(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, setupStatusJSON(st))
}
