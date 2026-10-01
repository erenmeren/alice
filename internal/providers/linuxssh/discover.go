package linuxssh

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"regexp"
	"strconv"

	"alice/internal/providers"
	"alice/internal/providers/linuxssh/helperproto"
	"alice/internal/providers/linuxssh/sshdconf"
)

var warningCodeRE = regexp.MustCompile(`^[a-z][a-z_]{0,39}$`)

// warn builds a warning; kv are parameter name/value pairs (values are cleaned remote text).
func warn(code string, kv ...string) providers.Warning {
	w := providers.Warning{Code: code, Params: map[string]string{}}
	for i := 0; i+1 < len(kv); i += 2 {
		w.Params[kv[i]] = cleanValue(kv[i+1], maxFactLength)
	}
	return w
}

// runHelper runs one helper command and decodes its answer.
func runHelper[T any](ctx context.Context, c *Conn, cmd HelperCommand) (T, error) {
	res, err := c.Run(ctx, cmd)
	if err != nil {
		var zero T
		return zero, err
	}
	return DecodeHelper[T](res, cmd.Subcommand())
}

func weakHostKey(keyType string, bits int) bool {
	return keyType == "ssh-dss" || (keyType == "ssh-rsa" && bits < 2048)
}

func isSet(v string) bool { return v != "" && v != "none" }

// sshd reads the effective sshd settings (spec §13.2). When sshd -T fails the defaults apply and
// the warning says so.
func (s *session) sshd(ctx context.Context) (providers.SSHDSummary, []providers.Warning, error) {
	d, err := runHelper[helperproto.SSHDDumpResponse](ctx, s.conn, CmdSSHDDump())
	if err != nil {
		return providers.SSHDSummary{}, nil, err
	}
	if d.Fallback {
		return providers.SSHDSummary{
			AuthorizedKeysFile:    append([]string(nil), sshdconf.DefaultAuthorizedKeysFile...),
			AuthorizedKeysCommand: "none",
		}, []providers.Warning{warn(helperproto.WarnSSHDUnreadable)}, nil
	}
	cfg, err := sshdconf.Parse([]byte(d.Config))
	if err != nil {
		return providers.SSHDSummary{}, nil, providers.NewError("ssh.protocol_error", false, err,
			map[string]string{"subcommand": helperproto.SubSSHDDump})
	}
	sum := providers.SSHDSummary{
		Read:                   true,
		PubkeyAuthentication:   cleanValue(cfg.PubkeyAuthentication, maxFactLength),
		PasswordAuthentication: cleanValue(cfg.PasswordAuthentication, maxFactLength),
		PermitRootLogin:        cleanValue(cfg.PermitRootLogin, maxFactLength),
		AuthorizedKeysCommand:  cleanValue(cfg.AuthorizedKeysCommand, maxFactLength),
		// Parse fills OpenSSH's default when the keyword is absent; "AuthorizedKeysFile none"
		// stays an empty list (no file is read).
		AuthorizedKeysFile: []string{},
	}
	for _, f := range cfg.AuthorizedKeysFile {
		sum.AuthorizedKeysFile = append(sum.AuthorizedKeysFile, cleanValue(f, maxFactLength))
	}
	if sum.AuthorizedKeysCommand == "" {
		sum.AuthorizedKeysCommand = "none"
	}
	var warns []providers.Warning
	sum.KeysManagedElsewhere = sum.AuthorizedKeysCommand != "none"
	if sum.KeysManagedElsewhere {
		warns = append(warns, warn("keys_managed_elsewhere"))
	}
	sum.CertificatesInUse = isSet(cfg.TrustedUserCAKeys) || isSet(cfg.AuthorizedPrincipalsFile)
	if sum.CertificatesInUse {
		warns = append(warns, warn("certificates_in_use"))
	}
	if sum.PubkeyAuthentication == "no" {
		warns = append(warns, warn("pubkey_disabled"))
	}
	return sum, warns, nil
}

// readFile reads one authorized_keys file through the helper. exists is false when the file does
// not exist (helper code NOT_FOUND; the hash is then helperproto.AbsentSHA256); the content's
// SHA-256 is checked against the helper's.
func (s *session) readFile(ctx context.Context, path string) ([]byte, string, bool, error) {
	content, sum, _, exists, err := s.readFileOwner(ctx, path)
	return content, sum, exists, err
}

// readFileOwner is readFile that also returns the account the helper resolved the file to.
func (s *session) readFileOwner(ctx context.Context, path string) (content []byte, sum, owner string, exists bool, err error) {
	cmd, err := CmdAuthKeysRead(path)
	if err != nil {
		return nil, "", "", false, providers.NewError("ssh.helper_refused", false, err,
			map[string]string{"subcommand": helperproto.SubAuthKeysRead, "helper_code": helperproto.CodeInvalidArgument})
	}
	r, err := runHelper[helperproto.AuthKeysReadResponse](ctx, s.conn, cmd)
	if isHelperCode(err, helperproto.CodeNotFound) {
		return nil, helperproto.AbsentSHA256, "", false, nil
	}
	if err != nil {
		return nil, "", "", false, err
	}
	content, err = base64.StdEncoding.DecodeString(r.ContentB64)
	if err != nil {
		return nil, "", "", false, providers.NewError("ssh.protocol_error", false, err,
			map[string]string{"subcommand": helperproto.SubAuthKeysRead})
	}
	h := sha256.Sum256(content)
	sum = hex.EncodeToString(h[:])
	if sum != r.SHA256 {
		return nil, "", "", false, providers.NewError("ssh.protocol_error", false, errors.New("linuxssh: content does not match its hash"),
			map[string]string{"subcommand": helperproto.SubAuthKeysRead})
	}
	if r.Owner == "" {
		return nil, "", "", false, providers.NewError("ssh.protocol_error", false, errors.New("linuxssh: helper answered without an owner"),
			map[string]string{"subcommand": helperproto.SubAuthKeysRead})
	}
	return content, sum, r.Owner, true, nil
}

// isHelperCode reports whether err is the helper refusing with code.
func isHelperCode(err error, code string) bool {
	var pe *providers.Error
	return errors.As(err, &pe) && pe.Code == "ssh.helper_refused" && pe.Params["helper_code"] == code
}

// fileWarning is the warning code of a file ParseAuthorizedKeys refused.
func fileWarning(err error) string {
	if errors.Is(err, ErrAuthorizedKeysTooLarge) {
		return "file_too_large"
	}
	return "file_unparseable"
}

// fileUnreadable reports whether a read error affects only that file: the helper refused it on a
// healthy connection and the caller has not given up. Anything else (a timeout, a broken
// connection, a cancelled context, a garbled answer) fails the whole discovery.
func (s *session) fileUnreadable(ctx context.Context, err error) bool {
	var pe *providers.Error
	return ctx.Err() == nil && s.conn.Healthy() && errors.As(err, &pe) && pe.Code == "ssh.helper_refused"
}

// Discover reads the host keys, the sshd settings and, when asked, every authorized_keys file the
// helper lists (spec §13.2, §13.3). One unreadable file makes the result partial (inventory never
// marks keys missing from files it did not read); skipped files are only reported. A listed file
// that does not exist counts as read: it holds no keys, so its former keys may be marked missing.
func (s *session) Discover(ctx context.Context, req providers.DiscoverRequest) (providers.DiscoveryResult, error) {
	if err := s.open(); err != nil {
		return providers.DiscoveryResult{}, err
	}
	var res providers.DiscoveryResult
	hk, err := runHelper[helperproto.HostKeysResponse](ctx, s.conn, CmdHostKeys())
	if err != nil {
		return providers.DiscoveryResult{}, err
	}
	for _, k := range hk.Keys {
		res.HostKeys = append(res.HostKeys, providers.DiscoveredHostKey{
			KeyType: cleanValue(k.Type, 64), Bits: k.Bits, Fingerprint: cleanValue(k.Fingerprint, 128),
			Weak: weakHostKey(k.Type, k.Bits),
		})
	}
	sum, warns, err := s.sshd(ctx)
	if err != nil {
		return providers.DiscoveryResult{}, err
	}
	res.SSHD = sum
	res.Warnings = append(res.Warnings, warns...)
	if !req.SSHKeys {
		return res, nil
	}
	list, err := runHelper[helperproto.AuthKeysListResponse](ctx, s.conn, CmdAuthKeysList())
	if err != nil {
		return providers.DiscoveryResult{}, err
	}
	for _, w := range list.Warnings {
		// sshd_unreadable is derived below, globally from sshd-dump and per user from the list.
		if warningCodeRE.MatchString(w) && w != helperproto.WarnSSHDUnreadable {
			res.Warnings = append(res.Warnings, warn(w))
		}
	}
	for _, u := range list.Users {
		if u.SSHDUnreadable && res.SSHD.Read {
			// A Match block could not be evaluated for this user: the listed files come from the
			// global configuration and may not be the ones sshd reads.
			res.Warnings = append(res.Warnings, warn(helperproto.WarnSSHDUnreadable, "user", u.User))
		}
		if isSet(u.AuthorizedKeysCommand) && !res.SSHD.KeysManagedElsewhere {
			// The files are listed, but sshd also asks a program for this user's keys (F-35).
			res.Warnings = append(res.Warnings, warn("keys_managed_elsewhere", "user", u.User))
		}
		for _, f := range u.Files {
			if err := s.discoverFile(ctx, u, f, &res); err != nil {
				return providers.DiscoveryResult{}, err
			}
		}
	}
	return res, nil
}

// discoverFile adds one listed file to res.
func (s *session) discoverFile(ctx context.Context, u helperproto.UserFiles, f helperproto.FileInfo, res *providers.DiscoveryResult) error {
	switch {
	case f.Unsupported || !helperproto.ValidUser(u.User) || !helperproto.ValidPath(f.Path):
		res.Warnings = append(res.Warnings, warn(helperproto.WarnUnsupportedPath, "user", u.User, "path", f.Path))
		return nil
	case !f.Exists:
		res.ReadFiles = append(res.ReadFiles, f.Path)
		return nil
	case f.TooLarge:
		res.Warnings = append(res.Warnings, warn("file_too_large", "user", u.User, "path", f.Path))
		return nil
	}
	if !f.StrictModesOK {
		res.Warnings = append(res.Warnings, warn("strict_modes", "user", u.User, "path", f.Path))
	}
	content, _, exists, err := s.readFile(ctx, f.Path)
	if err != nil {
		if !s.fileUnreadable(ctx, err) {
			return err
		}
		res.Partial = true
		res.Warnings = append(res.Warnings, warn("file_unreadable", "user", u.User, "path", f.Path))
		return nil
	}
	if !exists {
		res.ReadFiles = append(res.ReadFiles, f.Path) // removed since it was listed
		return nil
	}
	ak, err := ParseAuthorizedKeys(content)
	if err != nil {
		res.Warnings = append(res.Warnings, warn(fileWarning(err), "user", u.User, "path", f.Path))
		return nil
	}
	keys, bad := ak.Keys(u.User, f.Path)
	res.SSHKeys = append(res.SSHKeys, keys...)
	res.UnreadableLines = append(res.UnreadableLines, bad...)
	if len(bad) > 0 {
		res.Warnings = append(res.Warnings, warn("unreadable_line", "user", u.User, "path", f.Path, "count", strconv.Itoa(len(bad))))
	}
	res.ReadFiles = append(res.ReadFiles, f.Path)
	return nil
}
