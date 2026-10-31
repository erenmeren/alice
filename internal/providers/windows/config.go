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

// localUserRE is the form .\<SAM name> of a local account, which a WinRM target also takes (R71 Ruling 6); the NTLM
// exchange sends it without the .\ (ntlmUser).
var localUserRE = regexp.MustCompile(`^\.\\[A-Za-z0-9][A-Za-z0-9._-]{0,19}$`)

// ValidUser reports whether s is an account name a Windows target may use (alice, CORP\alice-svc).
func ValidUser(s string) bool { return userRE.MatchString(s) }

// The transports of a Windows target (R71 Ruling 2): OpenSSH with the forced command (the default), or WinRM over
// HTTPS with NTLMv2. The transport is fixed when the target is created (Ruling 3).
const (
	TransportSSH   = "ssh"
	TransportWinRM = "winrm"
	// DefaultWinRMPort is the port of a WinRM target that names none: the HTTPS listener's.
	DefaultWinRMPort = 5986
)

// Config is a Windows target's configuration: the SSH fields (Host is also the address of later probes) and the
// transport.
type Config struct {
	linuxssh.Config
	Transport string // TransportSSH or TransportWinRM
}

// ParseConfig reads a Windows target's configuration: host and port follow the Linux rules (one
// shared check, linuxssh.ParseConfig); username is DefaultUser when absent and must be ValidUser,
// kept verbatim (Ruling 1). transport is TransportSSH when absent; under TransportWinRM the port is
// DefaultWinRMPort when absent and the local form .\<SAM name> is also accepted (R71 Ruling 6). No
// network.
func ParseConfig(cfg providers.TargetConfig) (Config, []validate.FieldError) {
	rest := maps.Clone(cfg)
	delete(rest, "username")
	delete(rest, "transport")
	sc, base := linuxssh.ParseConfig(rest)
	errs := validate.Errors(base)
	c := Config{Config: sc, Transport: TransportSSH}
	if v, ok := cfg["transport"]; ok && v != nil {
		switch tr, _ := v.(string); tr {
		case TransportSSH, TransportWinRM:
			c.Transport = tr
		default:
			errs.Add("transport", validate.OneOf, map[string]string{"values": TransportSSH + ", " + TransportWinRM})
		}
	}
	if p, ok := cfg["port"]; c.Transport == TransportWinRM && (!ok || p == nil) {
		c.Port = DefaultWinRMPort
	}
	if c.Transport == TransportWinRM && c.Port == 5985 {
		errs.Add("port", validate.Pattern, nil) // WinRM's plain-HTTP port, never dialled (Ruling 12)
	}
	c.Username = DefaultUser
	if v, ok := cfg["username"]; ok && v != nil {
		u, _ := v.(string)
		if ValidUser(u) || (c.Transport == TransportWinRM && localUserRE.MatchString(u)) {
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
