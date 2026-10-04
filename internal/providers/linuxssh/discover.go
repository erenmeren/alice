package linuxssh

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"regexp"
	"slices"
	"strconv"
	"time"

	"alice/internal/providers"
	"alice/internal/providers/linuxssh/helperproto"
	"alice/internal/providers/linuxssh/sshdconf"
)

var warningCodeRE = regexp.MustCompile(`^[a-z][a-z_]{0,39}$`)

// Bounds of one SSH-key discovery (AUD-04(a): the helper's answer is the server's, so nothing it
// lists decides how much work or memory a discovery costs). maxDiscoverUsers is the spec's scan
// bound (§13.2: 200 users, the helper's own); the others have no number in the spec and are set
// well above a real server's: authorized_keys files read (and listed entries looked at), keys and
// unreadable lines kept, warnings kept. A discovery cut at a bound is partial (inventory marks
// keys missing only in the files it read) and carries list_truncated.
const (
	maxDiscoverUsers    = 200
	maxDiscoverFiles    = 1000
	maxDiscoverKeys     = 10000
	maxDiscoverWarnings = 500
)

// discoverBudget bounds the time spent reading authorized_keys files: once it has passed no
// further file is read (the one in flight finishes within its own command budget), and the result
// is partial. A per-job deadline for discovery jobs as a whole belongs to the jobs layer
// (targetjobs); this one bounds the part a hostile server can make long. Tests lower it.
var discoverBudget = 10 * time.Minute

// errDiscoveryCut: a file's keys would exceed maxDiscoverKeys; it is not read into the result.
var errDiscoveryCut = errors.New("linuxssh: the discovery reached its key bound")

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
	r, err := s.readFileOwner(ctx, path)
	return r.content, r.sum, r.exists, err
}

// fileRead is one authkeys-read answer: the content and its hash, and the account (with its uid,
// protocol 6) the helper resolved the file to. exists is false for a file that does not exist
// (sum is then helperproto.AbsentSHA256).
type fileRead struct {
	content    []byte
	sum, owner string
	uid        int
	exists     bool
}

// readFileOwner is readFile that also returns the account the helper resolved the file to and its
// uid. A missing uid reads as 0: the last-root-key guard then asks for confirmation (fail-safe).
func (s *session) readFileOwner(ctx context.Context, path string) (fileRead, error) {
	cmd, err := CmdAuthKeysRead(path)
	if err != nil {
		return fileRead{}, providers.NewError("ssh.helper_refused", false, err,
			map[string]string{"subcommand": helperproto.SubAuthKeysRead, "helper_code": helperproto.CodeInvalidArgument})
	}
	r, err := runHelper[helperproto.AuthKeysReadResponse](ctx, s.conn, cmd)
	if isHelperCode(err, helperproto.CodeNotFound) {
		return fileRead{sum: helperproto.AbsentSHA256}, nil
	}
	if err != nil {
		return fileRead{}, err
	}
	content, err := base64.StdEncoding.DecodeString(r.ContentB64)
	if err != nil {
		return fileRead{}, providers.NewError("ssh.protocol_error", false, err,
			map[string]string{"subcommand": helperproto.SubAuthKeysRead})
	}
	h := sha256.Sum256(content)
	sum := hex.EncodeToString(h[:])
	if sum != r.SHA256 {
		return fileRead{}, providers.NewError("ssh.protocol_error", false, errors.New("linuxssh: content does not match its hash"),
			map[string]string{"subcommand": helperproto.SubAuthKeysRead})
	}
	if r.Owner == "" {
		return fileRead{}, providers.NewError("ssh.protocol_error", false, errors.New("linuxssh: helper answered without an owner"),
			map[string]string{"subcommand": helperproto.SubAuthKeysRead})
	}
	return fileRead{content: content, sum: sum, owner: r.Owner, uid: r.UID, exists: true}, nil
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
	list, err := s.listAuthKeys(ctx)
	if err != nil {
		return providers.DiscoveryResult{}, err
	}
	// Carry 1: the account list lets inventory tell a deleted OS user from a user whose file could
	// not be read. An absent or false accounts_complete is unknown, and so is a list that had to be
	// repaired (an invalid name dropped) or cut at the bound.
	res.AccountsComplete = list.AccountsComplete
	for _, a := range list.Accounts {
		if !helperproto.ValidAccount(a) {
			res.AccountsComplete = false
			continue
		}
		res.Accounts = append(res.Accounts, a)
	}
	slices.Sort(res.Accounts)
	res.Accounts = slices.Compact(res.Accounts)
	// The helper already says false for these; Alice does not rely on it alone. A list that
	// misses root (or is empty) comes from a broken or hostile helper: every real /etc/passwd has root.
	if slices.Contains(list.Warnings, helperproto.WarnTooManyUsers) || slices.Contains(list.Warnings, helperproto.WarnDirectoryUsers) ||
		slices.Contains(list.Warnings, helperproto.WarnAccountsNUL) || !slices.Contains(res.Accounts, "root") {
		res.AccountsComplete = false
	}
	if len(res.Accounts) > helperproto.MaxAccountNames {
		res.Accounts, res.AccountsComplete = res.Accounts[:helperproto.MaxAccountNames], false
	}
	// AUD-03: what the helper could not list is shown, by uid only, and the list is not complete.
	if len(list.Unlisted) > 0 {
		res.AccountsComplete = false
	}
	res.Warnings = append(res.Warnings, unlistedWarnings(list.Unlisted)...)
	for _, w := range list.Warnings {
		// sshd_unreadable is derived below, globally from sshd-dump and per user from the list.
		if warningCodeRE.MatchString(w) && w != helperproto.WarnSSHDUnreadable {
			res.Warnings = append(res.Warnings, warn(w))
		}
	}
	users, cut, stop := list.Users, false, false
	cutUID := -1 // the uid of the first user whose files were not read because of a bound (M5)
	if list.Truncated {
		// S8: the helper left users out to keep its answer within its bound.
		cut, res.AccountsComplete = true, false
		if list.TruncatedFromUID != nil {
			cutUID = *list.TruncatedFromUID
		}
	}
	if len(users) > maxDiscoverUsers {
		if cutUID < 0 {
			cutUID = users[maxDiscoverUsers].UID
		}
		users, cut, res.AccountsComplete = users[:maxDiscoverUsers], true, false
	}
	// S6: a listed name that is not an account name (only a broken or hostile helper lists one) is
	// shown by uid only; its files are not read.
	users = slices.DeleteFunc(slices.Clone(users), func(u helperproto.UserFiles) bool {
		if helperproto.ValidAccount(u.User) {
			return false
		}
		res.AccountsComplete = false
		res.Warnings = appendUnlisted(res.Warnings, helperproto.WarnAccountNameUnsupported, u.UID)
		return true
	})
	for _, u := range users {
		if u.UID == 0 {
			res.UID0Users = append(res.UID0Users, u.User)
		}
	}
	slices.Sort(res.UID0Users)
	start, entries := s.conn.clock.Now(), 0
	for _, u := range users {
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
			if stop || entries >= maxDiscoverFiles || s.conn.clock.Now().Sub(start) > discoverBudget {
				if !stop && cutUID < 0 {
					cutUID = u.UID
				}
				cut, stop = true, true
				break
			}
			entries++
			err := s.discoverFile(ctx, u, f, &res)
			if errors.Is(err, errDiscoveryCut) {
				if cutUID < 0 {
					cutUID = u.UID
				}
				cut, stop = true, true
				break
			}
			if err != nil {
				return providers.DiscoveryResult{}, err
			}
		}
	}
	if len(res.Warnings) >= maxDiscoverWarnings {
		res.Warnings, cut = res.Warnings[:maxDiscoverWarnings-1], true
	}
	if cut {
		res.Partial = true
		if cutUID >= 0 {
			res.Warnings = append(res.Warnings, warn(providers.WarnListTruncated, "uid", strconv.Itoa(cutUID)))
		} else {
			res.Warnings = append(res.Warnings, warn(providers.WarnListTruncated))
		}
	}
	return res, nil
}

// unlistedWarnings turns the helper's unlisted entries into warnings (AUD-03): at most
// helperproto.MaxUnlistedAccounts of them, each with its uid only; an unknown reason or a negative
// uid (a broken or hostile helper) is dropped. The list is cut at the bound first, so a hostile
// answer costs bounded work.
func unlistedWarnings(unlisted []helperproto.UnlistedAccount) []providers.Warning {
	if len(unlisted) > helperproto.MaxUnlistedAccounts {
		unlisted = unlisted[:helperproto.MaxUnlistedAccounts]
	}
	var out []providers.Warning
	for _, u := range unlisted {
		code := helperproto.WarnAccountNameUnsupported // an unknown reason (a broken helper) reads as a name
		switch u.Reason {
		case helperproto.UnlistedHome:
			code = helperproto.WarnAccountHomeUnsupported
		case helperproto.UnlistedID:
			code = helperproto.WarnAccountIDUnsupported
		}
		uid := u.UID
		if u.Reason != helperproto.UnlistedName && u.Reason != helperproto.UnlistedHome && u.Reason != helperproto.UnlistedID {
			uid = -1 // the uid of an entry Alice cannot classify is not shown
		}
		out = appendUnlisted(out, code, uid)
	}
	return out
}

// appendUnlisted adds the warning for an entry that could not be listed: with its uid, or, when
// the uid is negative (only a broken or hostile helper sends one), once without it (M6): the list
// is then incomplete, and the warning says why.
func appendUnlisted(ws []providers.Warning, code string, uid int) []providers.Warning {
	if uid >= 0 {
		return append(ws, warn(code, "uid", strconv.Itoa(uid)))
	}
	w := warn(code)
	if slices.ContainsFunc(ws, func(x providers.Warning) bool { return x.Code == code && len(x.Params) == 0 }) {
		return ws
	}
	return append(ws, w)
}

// inlineContent returns a listed file's inline content (AUD-22): the helper read it for its hash,
// so it must be exactly that and no larger than a file the helper reads; anything else fails the
// discovery as a protocol error.
func inlineContent(f helperproto.FileInfo) ([]byte, error) {
	raw, err := base64.StdEncoding.DecodeString(f.ContentB64)
	h := sha256.Sum256(raw)
	if err != nil || len(raw) > helperproto.MaxAuthorizedKeysSize || hex.EncodeToString(h[:]) != f.SHA256 {
		return nil, providers.NewError("ssh.protocol_error", false, errors.New("linuxssh: inline content does not match its hash"),
			map[string]string{"subcommand": helperproto.SubAuthKeysList})
	}
	return raw, nil
}

// discoverFile adds one listed file to res. A file listed with its content (inline, protocol 6)
// needs no authkeys-read; the others are read.
func (s *session) discoverFile(ctx context.Context, u helperproto.UserFiles, f helperproto.FileInfo, res *providers.DiscoveryResult) error {
	switch {
	case f.Unsupported || !helperproto.ValidPath(f.Path):
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
	var content []byte
	if f.Inline {
		c, err := inlineContent(f)
		if err != nil {
			return err
		}
		content = c
	} else {
		c, _, exists, err := s.readFile(ctx, f.Path)
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
		content = c
	}
	ak, err := ParseAuthorizedKeys(content)
	if err != nil {
		res.Warnings = append(res.Warnings, warn(fileWarning(err), "user", u.User, "path", f.Path))
		return nil
	}
	keys, bad := ak.Keys(u.User, f.Path)
	if len(res.SSHKeys)+len(res.UnreadableLines)+len(keys)+len(bad) > maxDiscoverKeys {
		return errDiscoveryCut // not read into the result: not in ReadFiles, nothing of it marked missing
	}
	res.SSHKeys = append(res.SSHKeys, keys...)
	res.UnreadableLines = append(res.UnreadableLines, bad...)
	if len(bad) > 0 {
		res.Warnings = append(res.Warnings, warn("unreadable_line", "user", u.User, "path", f.Path, "count", strconv.Itoa(len(bad))))
	}
	res.ReadFiles = append(res.ReadFiles, f.Path)
	return nil
}
