package api

import (
	"encoding/base64"
	"net/http"
	"time"

	"github.com/google/uuid"

	"alice/internal/auth"
	"alice/internal/setup"
)

// userDTO is the wire form of auth.User.
type userDTO struct {
	ID          string     `json:"id"`
	Username    string     `json:"username"`
	DisplayName string     `json:"display_name"`
	Email       string     `json:"email"`
	Role        string     `json:"role"`
	Locale      string     `json:"locale"`
	Disabled    bool       `json:"disabled"`
	MFAEnrolled bool       `json:"mfa_enrolled"`
	LastLoginAt *time.Time `json:"last_login_at"`
	CreatedAt   time.Time  `json:"created_at"`
	// AuthSource is how the person signs in (local, oidc or ldap); SSOProviderID is the identity provider of an SSO user
	// (C10), LDAPDirectoryID the directory of a directory user.
	AuthSource      string     `json:"auth_source"`
	SSOProviderID   *uuid.UUID `json:"sso_provider_id"`
	LDAPDirectoryID *uuid.UUID `json:"ldap_directory_id"`
}

func userJSON(u auth.User) userDTO {
	var last *time.Time
	if u.LastLoginAt != nil {
		t := u.LastLoginAt.UTC()
		last = &t
	}
	return userDTO{
		ID:          u.ID.String(),
		Username:    u.Username,
		DisplayName: u.DisplayName,
		Email:       u.Email,
		Role:        string(u.Role),
		Locale:      u.Locale,
		Disabled:    u.Disabled,
		MFAEnrolled: u.MFAEnrolled,
		LastLoginAt: last,
		CreatedAt:   u.CreatedAt.UTC(),

		AuthSource:      authSource(u.AuthSource),
		SSOProviderID:   u.SSOProviderID,
		LDAPDirectoryID: u.LDAPDirectoryID,
	}
}

// authSource is a user's sign-in source; a user stored before single sign-on existed is local.
func authSource(s string) string {
	if s == "" {
		return auth.AuthLocal
	}
	return s
}

// sessionDTO is the wire form of auth.SessionInfo; RecoveryCodes is present
// only right after MFA enrollment or admin creation.
type sessionDTO struct {
	User          userDTO    `json:"user"`
	CSRFToken     string     `json:"csrf_token"`
	ExpiresAt     time.Time  `json:"expires_at"`
	IdleExpiresAt time.Time  `json:"idle_expires_at"`
	StepUpUntil   *time.Time `json:"stepup_until"`
	RecoveryCodes []string   `json:"recovery_codes,omitempty"`
}

func sessionJSON(si auth.SessionInfo, recoveryCodes []string) sessionDTO {
	var stepUp *time.Time
	if si.StepUpUntil != nil {
		t := si.StepUpUntil.UTC()
		stepUp = &t
	}
	return sessionDTO{
		User:          userJSON(si.User),
		CSRFToken:     si.CSRFToken,
		ExpiresAt:     si.ExpiresAt.UTC(),
		IdleExpiresAt: si.IdleExpiresAt.UTC(),
		StepUpUntil:   stepUp,
		RecoveryCodes: recoveryCodes,
	}
}

// enrollmentDTO carries a new TOTP secret. It is shown once (SEC-007).
type enrollmentDTO struct {
	Secret     string `json:"secret"`
	OTPAuthURI string `json:"otpauth_uri"`
	QRPNG      string `json:"qr_png"`
}

func enrollmentJSON(e auth.TOTPEnrollment) enrollmentDTO {
	return enrollmentDTO{Secret: e.Secret, OTPAuthURI: e.URI, QRPNG: base64.StdEncoding.EncodeToString(e.QRPNG)}
}

type setupStatusDTO struct {
	AdminExists           bool   `json:"admin_exists"`
	RecoveryPassphraseSet bool   `json:"recovery_passphrase_set"`
	LicenseChosen         bool   `json:"license_chosen"`
	Completed             bool   `json:"completed"`
	DefaultLocale         string `json:"default_locale"`
	// Phase 8 (C11, C12): the HTTPS and mail steps and the step the wizard resumes at.
	HTTPSChosen bool   `json:"https_chosen"`
	MailChosen  bool   `json:"mail_chosen"`
	NextStep    string `json:"next_step"`
}

func setupStatusJSON(st setup.Status) setupStatusDTO {
	return setupStatusDTO{
		AdminExists:           st.AdminExists,
		RecoveryPassphraseSet: st.RecoveryPassphraseSet,
		LicenseChosen:         st.LicenseChosen,
		Completed:             st.Completed,
		DefaultLocale:         st.DefaultLocale,
		HTTPSChosen:           st.HTTPSChosen,
		MailChosen:            st.MailChosen,
		NextStep:              st.NextStep,
	}
}

// noContent answers 204 without a body.
func noContent(w http.ResponseWriter) {
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusNoContent)
}
