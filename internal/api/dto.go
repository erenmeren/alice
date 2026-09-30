package api

import (
	"encoding/base64"
	"net/http"
	"time"

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
	}
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
	Completed             bool   `json:"completed"`
	DefaultLocale         string `json:"default_locale"`
}

func setupStatusJSON(st setup.Status) setupStatusDTO {
	return setupStatusDTO{
		AdminExists:           st.AdminExists,
		RecoveryPassphraseSet: st.RecoveryPassphraseSet,
		Completed:             st.Completed,
		DefaultLocale:         st.DefaultLocale,
	}
}

// noContent answers 204 without a body.
func noContent(w http.ResponseWriter) {
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusNoContent)
}
