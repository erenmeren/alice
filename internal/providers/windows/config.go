package windows

import (
	"maps"
	"regexp"

	"alice/internal/platform/validate"
	"alice/internal/providers"
	"alice/internal/providers/linuxssh"
)

// DefaultUser is the Windows account the setup script creates when the administrator names none.
const DefaultUser = "alice"

// userRE is the account rule of R60 Ruling 1: an optional NetBIOS domain of at most 15 characters and
// a backslash, then a SAM account name of at most 20. The name is stored and sent as typed (Windows
// compares account names without case).
var userRE = regexp.MustCompile(`^([A-Za-z0-9][A-Za-z0-9-]{0,14}\\)?[A-Za-z0-9][A-Za-z0-9._-]{0,19}$`)

// ValidUser reports whether s is an account name a Windows target may use (alice, CORP\alice-svc).
func ValidUser(s string) bool { return userRE.MatchString(s) }

// ParseConfig reads a Windows target's configuration: host and port follow the Linux rules (one
// shared check, linuxssh.ParseConfig); username is DefaultUser when absent and must be ValidUser,
// kept verbatim (Ruling 1). No network.
func ParseConfig(cfg providers.TargetConfig) (linuxssh.Config, []validate.FieldError) {
	rest := maps.Clone(cfg)
	delete(rest, "username")
	c, base := linuxssh.ParseConfig(rest)
	errs := validate.Errors(base)
	c.Username = DefaultUser
	if v, ok := cfg["username"]; ok && v != nil {
		u, _ := v.(string)
		if ValidUser(u) {
			c.Username = u
		} else {
			errs.Add("username", validate.Pattern, nil)
		}
	}
	if len(errs) == 0 {
		return c, nil
	}
	return c, []validate.FieldError(errs)
}
