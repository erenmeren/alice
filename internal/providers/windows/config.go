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

// ConfigCertificateCleanup is the per-server switch of the certificate cleanup (R62 W3 Ruling 13):
// providers.ConfigCertificateCleanup.
const ConfigCertificateCleanup = providers.ConfigCertificateCleanup

// CleanupEnabled reads the switch (providers.CertificateCleanupEnabled): true when it is absent or null, else its
// value; a value that is not a boolean (ParseConfig refuses it, so it is never stored) reads false, the side that
// removes nothing.
func CleanupEnabled(cfg providers.TargetConfig) bool { return providers.CertificateCleanupEnabled(cfg) }

// ParseConfig reads a Windows target's configuration: host and port follow the Linux rules (one
// shared check, linuxssh.ParseConfig); username is DefaultUser when absent and must be ValidUser,
// kept verbatim (Ruling 1); certificate_cleanup, when present and not null, must be a boolean (it is
// not part of the connection: CleanupEnabled reads it). No network.
func ParseConfig(cfg providers.TargetConfig) (linuxssh.Config, []validate.FieldError) {
	rest := maps.Clone(cfg)
	delete(rest, "username")
	delete(rest, ConfigCertificateCleanup)
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
	if v, ok := cfg[ConfigCertificateCleanup]; ok && v != nil {
		if _, isBool := v.(bool); !isBool {
			errs.Add(ConfigCertificateCleanup, validate.OneOf, map[string]string{"values": "true, false"})
		}
	}
	if len(errs) == 0 {
		return c, nil
	}
	return c, []validate.FieldError(errs)
}
