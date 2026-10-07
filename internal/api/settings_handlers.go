package api

import (
	"encoding/json"
	"errors"
	"net/http"
	"regexp"
	"strconv"
	"time"

	"alice/internal/license"
	"alice/internal/notify"
	"alice/internal/platform/settings"
	"alice/internal/rbac"
	"alice/internal/secrets"
)

// settingsRoutes are Alice's own settings (C13, Phase 7): the mail server, the test e-mail and the certificate trust
// (F-62), who receives e-mails, the expiry thresholds and the general settings. Every one is settings.manage (an
// Administrator's browser session with step-up) and works in lock (platform administration, ClassAlways). A change
// needs the strong If-Match of the version it was based on; "0" names a value never saved.
func (s *server) settingsRoutes() []route {
	return []route{
		{method: http.MethodGet, pattern: "/api/v1/settings/smtp", perm: rbac.SettingsManage, handler: s.getSMTP},
		{method: http.MethodPut, pattern: "/api/v1/settings/smtp", perm: rbac.SettingsManage, lic: license.ClassAlways, handler: s.putSMTP},
		{method: http.MethodDelete, pattern: "/api/v1/settings/smtp", perm: rbac.SettingsManage, lic: license.ClassAlways, handler: s.deleteSMTP},
		{method: http.MethodPost, pattern: "/api/v1/settings/smtp/actions/test", perm: rbac.SettingsManage, limit: limitTestMail,
			lic: license.ClassAlways, handler: s.testMail},
		{method: http.MethodPost, pattern: "/api/v1/settings/smtp/actions/trust", perm: rbac.SettingsManage, lic: license.ClassAlways, handler: s.trustSMTP},
		{method: http.MethodPost, pattern: "/api/v1/settings/smtp/actions/untrust", perm: rbac.SettingsManage, lic: license.ClassAlways,
			handler: s.untrustSMTP},
		{method: http.MethodGet, pattern: "/api/v1/settings/notifications", perm: rbac.SettingsManage, handler: s.getRecipients},
		{method: http.MethodPut, pattern: "/api/v1/settings/notifications", perm: rbac.SettingsManage, lic: license.ClassAlways, handler: s.putRecipients},
		{method: http.MethodGet, pattern: "/api/v1/settings/alerts", perm: rbac.SettingsManage, handler: s.getThresholds},
		{method: http.MethodPut, pattern: "/api/v1/settings/alerts", perm: rbac.SettingsManage, lic: license.ClassAlways, handler: s.putThresholds},
		{method: http.MethodGet, pattern: "/api/v1/settings/general", perm: rbac.SettingsManage, handler: s.getGeneral},
		{method: http.MethodPut, pattern: "/api/v1/settings/general", perm: rbac.SettingsManage, lic: license.ClassAlways, handler: s.putGeneral},
	}
}

// Body caps of the settings changes (SEC-023): the mail settings carry a CA bundle of at most 64 KiB, which JSON
// escapes (line breaks as two bytes); the recipients at most 20 addresses.
const (
	maxSMTPBody       = 160 << 10
	maxRecipientsBody = 16 << 10
	maxSettingsBody   = 4 << 10
)

var settingsIfMatchRE = regexp.MustCompile(`^"(0|[1-9][0-9]{0,9})"$`)

// settingsVersion reads the strong If-Match of a settings change; "0" names "never saved" (C13).
func settingsVersion(r *http.Request) (int, bool) {
	m := settingsIfMatchRE.FindStringSubmatch(r.Header.Get("If-Match"))
	if m == nil {
		return 0, false
	}
	n, err := strconv.Atoi(m[1])
	return n, err == nil
}

// settingsChange reads the If-Match of a settings change before anything else; it answers 412 itself when it is
// missing or not a single strong validator.
func (s *server) settingsChange(w http.ResponseWriter, r *http.Request) (int, bool) {
	version, ok := settingsVersion(r)
	if !ok {
		s.writeError(w, r, ErrPreconditionFailed)
	}
	return version, ok
}

func (s *server) getSMTP(w http.ResponseWriter, r *http.Request) {
	st, configured, err := s.deps.Mail.SMTP(r.Context())
	if err != nil {
		s.fail(w, r, err)
		return
	}
	s.writeSMTP(w, st, configured)
}

func (s *server) writeSMTP(w http.ResponseWriter, st notify.SMTPSettings, configured bool) {
	w.Header().Set("ETag", etag(st.Version))
	writeJSON(w, http.StatusOK, smtpJSON(st, configured))
}

// smtpBody is the mail settings change. The password is a secretText the handler zeroes: absent or null keeps the
// stored one, "" removes it, any other value replaces it (C13). It never appears in an answer (S-08).
type smtpBody struct {
	Host     string      `json:"host"`
	Port     int         `json:"port"`
	TLSMode  string      `json:"tls_mode"`
	From     string      `json:"from"`
	Username string      `json:"username"`
	Password *secretText `json:"password"`
	CAPEM    string      `json:"ca_pem"`
}

func (b *smtpBody) zero() {
	if b.Password != nil {
		b.Password.zero()
	}
}

// putSMTP stores the mail settings. The service validates every field (a user name without a stored or new password is
// a 422 on password) and zeroes the password too; the handler zeroes its own copy on every path.
func (s *server) putSMTP(w http.ResponseWriter, r *http.Request) {
	version, ok := s.settingsChange(w, r)
	if !ok {
		return
	}
	var req smtpBody
	defer req.zero()
	if !s.decodeExact(w, r, &req, maxSMTPBody, "host", "port", "tls_mode", "from", "username", "password", "ca_pem") {
		return
	}
	in := notify.SMTPInput{Host: req.Host, Port: req.Port, TLSMode: req.TLSMode, From: req.From, Username: req.Username, CAPEM: req.CAPEM}
	if req.Password != nil {
		pw := secrets.NewPlaintext(*req.Password)
		in.Password = &pw
	}
	st, err := s.deps.Mail.SaveSMTP(r.Context(), principalFrom(r.Context()).Actor(s.meta(r)), version, in)
	req.zero()
	if err != nil {
		s.fail(w, r, err)
		return
	}
	s.writeSMTP(w, st, true)
}

func (s *server) deleteSMTP(w http.ResponseWriter, r *http.Request) {
	version, ok := s.settingsChange(w, r)
	if !ok {
		return
	}
	if err := s.deps.Mail.DeleteSMTP(r.Context(), principalFrom(r.Context()).Actor(s.meta(r)), version); err != nil {
		s.fail(w, r, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// testMail sends a test e-mail now (owner step 1). Limited to 5 per minute per user (limitTestMail). An untrusted
// certificate answers ALC-NTF-0005 with the fingerprint, subject and expiry of the certificate the server presented,
// so the page can offer "Trust this certificate" (F-62); no other text of the mail server reaches the answer (F-63).
func (s *server) testMail(w http.ResponseWriter, r *http.Request) {
	var req struct {
		To string `json:"to"`
	}
	if !s.decodeExact(w, r, &req, maxActionBody, "to") {
		return
	}
	p := principalFrom(r.Context())
	err := s.deps.Mail.TestMail(r.Context(), p.Actor(s.meta(r)), req.To, p.Locale)
	var ce *notify.CertError
	if errors.As(err, &ce) {
		s.writeErrorWith(w, r, ErrSMTPUntrusted, map[string]string{"fingerprint": ce.Cert.Fingerprint, "subject": ce.Cert.Subject,
			"not_after": ce.Cert.NotAfter.UTC().Format(time.RFC3339)}, nil)
		return
	}
	if err != nil {
		s.fail(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]bool{"sent": true})
}

// trustSMTP pins the certificate a failed test e-mail saw on the configured server within the last hour (F-62).
func (s *server) trustSMTP(w http.ResponseWriter, r *http.Request) {
	version, ok := s.settingsChange(w, r)
	if !ok {
		return
	}
	var req struct {
		Fingerprint string `json:"fingerprint"`
	}
	if !s.decodeExact(w, r, &req, maxActionBody, "fingerprint") {
		return
	}
	st, err := s.deps.Mail.Trust(r.Context(), principalFrom(r.Context()).Actor(s.meta(r)), version, req.Fingerprint)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	s.writeSMTP(w, st, true)
}

// untrustSMTP drops the pinned certificate; the body is empty or {}.
func (s *server) untrustSMTP(w http.ResponseWriter, r *http.Request) {
	version, ok := s.settingsChange(w, r)
	if !ok {
		return
	}
	if !s.decodeExactOptional(w, r, &struct{}{}, maxActionBody) {
		return
	}
	st, err := s.deps.Mail.Untrust(r.Context(), principalFrom(r.Context()).Actor(s.meta(r)), version)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	s.writeSMTP(w, st, true)
}

func (s *server) getRecipients(w http.ResponseWriter, r *http.Request) {
	rc, err := s.deps.Mail.Recipients(r.Context())
	if err != nil {
		s.fail(w, r, err)
		return
	}
	w.Header().Set("ETag", etag(rc.Version))
	writeJSON(w, http.StatusOK, recipientsJSON(rc))
}

// putRecipients sets who receives every e-mail Alice sends to Administrators. Each address is an object with exactly the
// keys email and locale (C13); the service validates the values.
func (s *server) putRecipients(w http.ResponseWriter, r *http.Request) {
	version, ok := s.settingsChange(w, r)
	if !ok {
		return
	}
	var req struct {
		Administrators bool              `json:"administrators"`
		Addresses      []json.RawMessage `json:"addresses"`
	}
	if !s.decodeExact(w, r, &req, maxRecipientsBody, "administrators", "addresses") {
		return
	}
	in := notify.Recipients{Administrators: req.Administrators}
	for _, raw := range req.Addresses {
		var a addressDTO
		if _, ok := scanKeys(raw, func(k []byte, earlier []string) (string, bool) { return exactKey(k, addressKeys, earlier) }); !ok ||
			json.Unmarshal(raw, &a) != nil {
			s.writeError(w, r, ErrBadRequest)
			return
		}
		in.Addresses = append(in.Addresses, notify.Address{Email: a.Email, Locale: a.Locale})
	}
	rc, err := s.deps.Mail.SaveRecipients(r.Context(), principalFrom(r.Context()).Actor(s.meta(r)), version, in)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	w.Header().Set("ETag", etag(rc.Version))
	writeJSON(w, http.StatusOK, recipientsJSON(rc))
}

var addressKeys = []string{"email", "locale"}

func (s *server) getThresholds(w http.ResponseWriter, r *http.Request) {
	th, err := s.deps.Alerts.Thresholds(r.Context())
	if err != nil {
		s.fail(w, r, err)
		return
	}
	w.Header().Set("ETag", etag(th.Version))
	writeJSON(w, http.StatusOK, thresholdsJSON(th))
}

// putThresholds stores the expiry thresholds; the service validates them (validate.Errors on thresholds_days).
func (s *server) putThresholds(w http.ResponseWriter, r *http.Request) {
	version, ok := s.settingsChange(w, r)
	if !ok {
		return
	}
	var req struct {
		Days []int `json:"thresholds_days"`
	}
	if !s.decodeExact(w, r, &req, maxSettingsBody, "thresholds_days") {
		return
	}
	th, err := s.deps.Alerts.SaveThresholds(r.Context(), principalFrom(r.Context()).Actor(s.meta(r)), version, req.Days)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	w.Header().Set("ETag", etag(th.Version))
	writeJSON(w, http.StatusOK, thresholdsJSON(th))
}

func (s *server) getGeneral(w http.ResponseWriter, r *http.Request) {
	g, err := s.deps.Mail.General(r.Context())
	if err != nil {
		s.fail(w, r, err)
		return
	}
	w.Header().Set("ETag", etag(g.Version))
	writeJSON(w, http.StatusOK, generalJSON(g))
}

// putGeneral stores Alice's own address (public_url, used in e-mails and as the single sign-on return address) and how
// long retired SSH private keys are kept.
func (s *server) putGeneral(w http.ResponseWriter, r *http.Request) {
	version, ok := s.settingsChange(w, r)
	if !ok {
		return
	}
	var req struct {
		PublicURL string `json:"public_url"`
		Days      int    `json:"retired_key_retention_days"`
	}
	if !s.decodeExact(w, r, &req, maxSettingsBody, "public_url", "retired_key_retention_days") {
		return
	}
	g, err := s.deps.Mail.SaveGeneral(r.Context(), principalFrom(r.Context()).Actor(s.meta(r)), version,
		settings.General{PublicURL: req.PublicURL, RetiredKeyRetentionDays: req.Days})
	if err != nil {
		s.fail(w, r, err)
		return
	}
	w.Header().Set("ETag", etag(g.Version))
	writeJSON(w, http.StatusOK, generalJSON(g))
}
