package auth

import (
	"net/mail"
	"regexp"
	"strconv"
	"strings"
	"unicode/utf8"

	"alice/internal/platform/validate"
)

// usernameRE allows ASCII letters, digits, dot, underscore and dash. Case is kept as typed;
// the citext column makes uniqueness and login case-insensitive. Non-ASCII letters such as
// "İ" are rejected so the Turkish-I casing problem cannot reach identifiers.
var usernameRE = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{1,63}$`)

const (
	maxDisplayName = 100
	maxEmail       = 254
	maxTokenName   = 100
)

// ValidateProfile checks the user-editable account fields.
func ValidateProfile(username, displayName, email string) validate.Errors {
	var v validate.Errors
	switch {
	case username == "":
		v.Add("username", validate.Required, nil)
	case !usernameRE.MatchString(username):
		v.Add("username", validate.Pattern, nil)
	}
	validateDisplayName(&v, displayName)
	validateEmail(&v, email)
	return v
}

func validateDisplayName(v *validate.Errors, name string) {
	switch {
	case strings.TrimSpace(name) == "":
		v.Add("display_name", validate.Required, nil)
	case utf8.RuneCountInString(name) > maxDisplayName:
		v.Add("display_name", validate.TooLong, map[string]string{"max": strconv.Itoa(maxDisplayName)})
	}
}

func validateEmail(v *validate.Errors, email string) {
	if email == "" {
		return
	}
	if len(email) > maxEmail {
		v.Add("email", validate.TooLong, map[string]string{"max": strconv.Itoa(maxEmail)})
		return
	}
	addr, err := mail.ParseAddress(email)
	if err != nil || addr.Address != email {
		v.Add("email", validate.Email, nil)
	}
}
