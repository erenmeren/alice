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
		{method: http.MethodGet, pattern: "/api/v1/setup/status", scope: scopeNone, perm: rbac.Public, handler: s.setupStatus},
		{method: http.MethodPost, pattern: "/api/v1/setup/session", scope: scopeNone, perm: rbac.Public, limit: limitLogin, lic: license.ClassAlways, handler: s.setupStartSession},
		{method: http.MethodPut, pattern: "/api/v1/setup/language", scope: scopeNone, perm: rbac.Setup, lic: license.ClassAlways, handler: s.setupLanguage},
		{method: http.MethodPost, pattern: "/api/v1/setup/admin/enrollment", scope: scopeNone, perm: rbac.Setup, lic: license.ClassAlways, handler: s.setupEnrollment},
		{method: http.MethodPost, pattern: "/api/v1/setup/admin", scope: scopeNone, perm: rbac.Setup, limit: limitMFA, lic: license.ClassAlways, handler: s.setupCreateAdmin},
		{method: http.MethodPost, pattern: "/api/v1/setup/recovery-passphrase", scope: scopePlatform, perm: rbac.SettingsManage, lic: license.ClassAlways, handler: s.setupRecoveryPassphrase},
		{method: http.MethodPost, pattern: "/api/v1/setup/evaluation", scope: scopePlatform, perm: rbac.SettingsManage, lic: license.ClassAlways, handler: s.setupEvaluation},
		{method: http.MethodPost, pattern: "/api/v1/setup/complete", scope: scopePlatform, perm: rbac.SettingsManage, lic: license.ClassAlways, handler: s.setupComplete},
		// Phase 8 (C12): the wizard's HTTPS and mail steps. After completion both answer the status and change nothing (S-39).
		{method: http.MethodPost, pattern: "/api/v1/setup/https/keep-temporary", scope: scopePlatform, perm: rbac.SettingsManage, lic: license.ClassAlways,
			handler: s.setupKeepTemporary},
		{method: http.MethodPost, pattern: "/api/v1/setup/mail/skip", scope: scopePlatform, perm: rbac.SettingsManage, lic: license.ClassAlways, handler: s.setupSkipMail},
	}
}

// setupStatus answers the wizard's state. Once setup is complete an anonymous caller learns only that and the default
// language (S-18, R43 row 47); a signed-in caller still gets every step. The session is looked up passively (the idle
// timeout does not slide); a failed lookup counts as anonymous.
func (s *server) setupStatus(w http.ResponseWriter, r *http.Request) {
	st, err := s.deps.Setup.Status(r.Context())
	if err != nil {
		s.fail(w, r, err)
		return
	}
	if st.Completed && !s.signedIn(r) {
		writeJSON(w, http.StatusOK, publicSetupStatusDTO{Completed: true, DefaultLocale: st.DefaultLocale})
		return
	}
	writeJSON(w, http.StatusOK, setupStatusJSON(st))
}

// signedIn reports whether the request carries a session cookie of a signed-in user (not a pending login, not a
// token, not the wizard's cookie).
func (s *server) signedIn(r *http.Request) bool {
	tok := sessionTokenFrom(r)
	if tok == "" {
		return false
	}
	p, err := s.deps.Auth.AuthenticatePassive(r.Context(), tok)
	return err == nil && p.Kind == rbac.UserSession
}

func (s *server) setupKeepTemporary(w http.ResponseWriter, r *http.Request) {
	if !s.decodeExactOptional(w, r, &struct{}{}, maxActionBody) {
		return
	}
	st, err := s.deps.Setup.KeepTemporaryCertificate(r.Context(), principalFrom(r.Context()), s.meta(r))
	if err != nil {
		s.fail(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, setupStatusJSON(st))
}

func (s *server) setupSkipMail(w http.ResponseWriter, r *http.Request) {
	if !s.decodeExactOptional(w, r, &struct{}{}, maxActionBody) {
		return
	}
	st, err := s.deps.Setup.SkipMail(r.Context(), principalFrom(r.Context()), s.meta(r))
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
	s.issueSetupCookie(w, token)
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
	s.issueSessionCookie(w, res.Token)
	s.recent.Remove(setupTokenFrom(r))
	clearSetupCookie(w)
	writeJSON(w, http.StatusOK, s.sessionAnswer(r, res.Info, res.RecoveryCodes))
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
