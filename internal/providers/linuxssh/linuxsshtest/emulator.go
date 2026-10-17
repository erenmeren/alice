package linuxsshtest

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"slices"
	"sort"
	"strconv"
	"strings"
	"sync"

	"golang.org/x/crypto/ssh"

	"alice/internal/providers/linuxssh/helperproto"
	"alice/internal/providers/linuxssh/sshdconf"
)

// DefaultSSHD is the sshd -T text the emulator answers by default (OpenSSH defaults).
const DefaultSSHD = `port 22
pubkeyauthentication yes
passwordauthentication no
permitrootlogin prohibit-password
authorizedkeysfile .ssh/authorized_keys .ssh/authorized_keys2
authorizedkeyscommand none
strictmodes yes
hostkey /etc/ssh/ssh_host_ed25519_key
`

// DefaultOSRelease is what "cat /etc/os-release" answers by default.
const DefaultOSRelease = "PRETTY_NAME=\"Ubuntu 22.04.4 LTS\"\nNAME=\"Ubuntu\"\nVERSION_ID=\"22.04\"\nID=ubuntu\n"

type emuUser struct {
	name string
	uid  int
	home string
}

// Emulator answers alice-helper command lines the way the real helper does (cmd/alice-helper):
// the same JSON shapes, exit codes, error codes and argument checks, with the users and files
// given to it. It models the helper's decisions, not the filesystem: a file is "unsupported"
// (hard-linked, foreign owner, escaping its directory) or "insecure" because a test says so.
type Emulator struct {
	mu          sync.Mutex
	users       []emuUser
	files       map[string][]byte
	sshd        string
	userSSHD    map[string]*string // per-user "sshd -T -C user=…" text; "" makes it fail
	osRelease   string
	protocol    int
	missing     bool
	insecure    map[string]bool
	unsupported map[string]bool
	failRead    map[string]bool
	failWrite   map[string]bool
	owners      map[string]string
	hostKeys    []helperproto.HostKeyInfo
	beforeWrite func(path string)
	writes      []string
	backups     map[string]int // operation id -> backups written
	maxUsers    int            // accounts listed at most (the helper's 200 when 0)
	accounts    *accountList   // SetAccounts: the /etc/passwd names authkeys-list reports (derived from users when nil)
	nx          *nginxHost     // the emulated Nginx (nginx.go); created on first use
	ax          *apacheHost    // the emulated Apache (apache.go); created on first use
	acmeWeb     *acmeState     // the emulated HTTP-01 webroot (acme.go); created on first use
}

type accountList struct {
	names    []string
	complete bool
}

// SetAccounts sets the account names authkeys-list reports in "accounts" and whether it says
// "accounts_complete". Without it the emulator reports its users plus daemon and nobody, sorted,
// as complete, as the helper does for a readable /etc/passwd.
func (e *Emulator) SetAccounts(names []string, complete bool) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.accounts = &accountList{names: append([]string(nil), names...), complete: complete}
}

// SetMaxUsers makes the emulator list at most n accounts (in uid order) and warn
// too_many_users when there are more, as the helper does above 200.
func (e *Emulator) SetMaxUsers(n int) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.maxUsers = n
}

// NewEmulator returns an emulator with the users root, deploy (uid 1001) and alice-svc (uid 998,
// the SUDO_USER the real helper always lists) and no authorized_keys files.
func NewEmulator() *Emulator {
	return &Emulator{
		users: []emuUser{
			{name: "root", uid: 0, home: "/root"},
			{name: "deploy", uid: 1001, home: "/home/deploy"},
			{name: "alice-svc", uid: 998, home: "/var/lib/alice-svc"},
		},
		files:       map[string][]byte{},
		sshd:        DefaultSSHD,
		userSSHD:    map[string]*string{},
		osRelease:   DefaultOSRelease,
		protocol:    helperproto.Protocol,
		insecure:    map[string]bool{},
		unsupported: map[string]bool{},
		failRead:    map[string]bool{},
		failWrite:   map[string]bool{},
		owners:      map[string]string{},
		backups:     map[string]int{},
		hostKeys: []helperproto.HostKeyInfo{{
			Type: "ssh-ed25519", Bits: 256, Fingerprint: "SHA256:emulatedHostKey00000000000000000000000000000",
			Path: "/etc/ssh/ssh_host_ed25519_key.pub",
		}},
	}
}

// SetFile stores a file (an authorized_keys file of one of the users).
func (e *Emulator) SetFile(path string, content []byte) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.files[path] = append([]byte(nil), content...)
}

// File returns a stored file.
func (e *Emulator) File(path string) ([]byte, bool) {
	e.mu.Lock()
	defer e.mu.Unlock()
	c, ok := e.files[path]
	return append([]byte(nil), c...), ok
}

// SetSSHD sets the sshd -T text; "" makes sshd -T fail (the helper then answers fallback and
// treats every user as unreadable).
func (e *Emulator) SetSSHD(config string) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.sshd = config
}

// SetUserSSHD sets the "sshd -T -C user=<user>" text of one user (a Match block applies to it);
// "" makes that call fail, so the helper reports the user as sshd_unreadable.
func (e *Emulator) SetUserSSHD(user, config string) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.userSSHD[user] = &config
}

// SetOSRelease sets the answer of "cat /etc/os-release".
func (e *Emulator) SetOSRelease(text string) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.osRelease = text
}

// SetProtocol sets the protocol "version" answers.
func (e *Emulator) SetProtocol(p int) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.protocol = p
}

// SetHelperMissing makes every helper command fail like a server without alice-helper or sudoers.
func (e *Emulator) SetHelperMissing(missing bool) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.missing = missing
}

// AddUser adds an account with a home directory. Like the helper (protocol 6, AUD-03), a user
// whose name is not a helperproto.ValidAccount is reported in unlisted (reason name), a user whose
// home helperproto.CleanHome refuses is reported there too (reason home), and the others are
// listed with the cleaned home. The emulator has no shells: every user counts as one the helper
// would scan (the helper reports a bad home only for those).
func (e *Emulator) AddUser(name string, uid int, home string) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.users = append(e.users, emuUser{name: name, uid: uid, home: home})
}

// SetInsecure reports path as failing sshd's StrictModes checks (writes are refused).
func (e *Emulator) SetInsecure(path string) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.insecure[path] = true
}

// SetUnsupported makes path a candidate the helper refuses to read or write (a hard link or a
// file owned by another user): it is listed with unsupported=true and reads answer UNSAFE_FILE.
func (e *Emulator) SetUnsupported(path string) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.unsupported[path] = true
}

// SetOwner makes read and write answers for path name owner instead of the resolved account
// ("" simulates a helper that leaves the owner out).
func (e *Emulator) SetOwner(path, owner string) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.owners[path] = owner
}

func (e *Emulator) ownerLocked(path, resolved string) string {
	if o, ok := e.owners[path]; ok {
		return o
	}
	return resolved
}

// FailWrite makes authkeys-write of path fail with IO_ERROR (the outcome is then uncertain).
func (e *Emulator) FailWrite(path string) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.failWrite[path] = true
}

// FailRead makes authkeys-read of path fail with IO_ERROR. The file is then also listed without
// its content (not inline): it stands for a file the helper could hash but not return, so a
// discovery reads it with authkeys-read (and reports file_unreadable).
func (e *Emulator) FailRead(path string) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.failRead[path] = true
}

// SetHostKeys sets the answer of "hostkeys".
func (e *Emulator) SetHostKeys(keys []helperproto.HostKeyInfo) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.hostKeys = append([]helperproto.HostKeyInfo(nil), keys...)
}

// BeforeWrite runs fn with the path of every authkeys-write, before the hash comparison (F-38).
func (e *Emulator) BeforeWrite(fn func(path string)) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.beforeWrite = fn
}

// Writes returns the paths authkeys-write changed, in order.
func (e *Emulator) Writes() []string {
	e.mu.Lock()
	defer e.mu.Unlock()
	return append([]string(nil), e.writes...)
}

// Handler answers command lines.
func (e *Emulator) Handler() Handler { return e.handle }

func answer(v any) Response {
	b, err := json.Marshal(v)
	if err != nil {
		return refuse(helperproto.ExitFailed, helperproto.CodeIOError)
	}
	return Response{Stdout: append(b, '\n')}
}

func refuse(exit int, code string) Response {
	b, _ := json.Marshal(helperproto.ErrorResponse{OK: false, Code: code, Message: "refused by the emulator"})
	return Response{Stdout: append(b, '\n'), Exit: exit}
}

func sum(b []byte) string {
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:])
}

// flagTokens are the constant flag names of the command constructors (everything else is a
// quoted value).
var flagTokens = map[string]bool{
	"--expect-sha256": true, "--content-sha256": true, "--op": true, // protocol 3
	"--cert": true, "--key": true, "--expect-cert-sha256": true, // protocol 4: nginx-deploy
	"--addr": true, "--port": true, "--sni": true, "--key-type": true, // protocol 4: tls-probe
	"--token": true, // protocol 7: acme-challenge-put and -rm
}

func isFlagToken(f string) bool { return flagTokens[f] }

// shellFields splits like a POSIX shell for the quoting the constructors use: fields are separated
// by spaces outside single quotes; quoted marks a field that had a quote.
type lineField struct {
	text   string
	quoted bool
}

func shellFields(s string) (fields []lineField, ok bool) {
	var cur strings.Builder
	has, quoted, inQuote := false, false, false
	flush := func() {
		if has {
			fields = append(fields, lineField{cur.String(), quoted})
		}
		cur.Reset()
		has, quoted = false, false
	}
	for _, r := range s {
		switch {
		case r == '\'':
			inQuote, has, quoted = !inQuote, true, true
		case r == ' ' && !inQuote:
			flush()
		default:
			cur.WriteRune(r)
			has = true
		}
	}
	flush()
	return fields, !inQuote
}

// parseLine splits "[sudo -n ]<helper> <sub> <args>" and unquotes the arguments like the remote
// shell would. valid is false when an argument is not a constant flag or a quoted ValidArg (the
// Phase 3 subcommands refuse such a line before anything else); the arguments are kept as the
// shell would pass them, so the Nginx subcommands validate them themselves like the helper. ok is
// false for anything that is not a helper command line.
func parseLine(cmd string) (sudo bool, sub string, args []string, valid bool, ok bool) {
	rest := cmd
	if r, found := strings.CutPrefix(rest, "sudo -n "); found {
		sudo, rest = true, r
	}
	r, found := strings.CutPrefix(rest, helperproto.HelperPath+" ")
	if !found {
		return false, "", nil, false, false
	}
	fields, closed := shellFields(r)
	if len(fields) == 0 {
		return sudo, "", nil, false, true
	}
	sub = fields[0].text
	valid = closed
	for _, f := range fields[1:] {
		args = append(args, f.text)
		if f.quoted && helperproto.ValidArg(f.text) || !f.quoted && isFlagToken(f.text) {
			continue
		}
		valid = false
	}
	return sudo, sub, args, valid, true
}

func (e *Emulator) handle(cmd string, stdin []byte) Response {
	if cmd == "cat /etc/os-release" {
		e.mu.Lock()
		defer e.mu.Unlock()
		return Response{Stdout: []byte(e.osRelease)}
	}
	sudo, sub, args, valid, ok := parseLine(cmd)
	if !ok {
		return Response{Stderr: []byte("sh: command not found\n"), Exit: 127}
	}
	e.mu.Lock()
	missing := e.missing
	e.mu.Unlock()
	if missing {
		if sudo {
			return Response{Stderr: []byte("sudo: a password is required\n"), Exit: 1}
		}
		return Response{Stderr: []byte("sh: " + helperproto.HelperPath + ": not found\n"), Exit: 127}
	}
	if isNginxSub(sub) {
		return e.handleNginx(sudo, sub, args, stdin)
	}
	if isApacheSub(sub) {
		return e.handleApache(sudo, sub, args)
	}
	if isACMESub(sub) {
		return e.handleACME(sudo, sub, args, stdin)
	}
	if sub == helperproto.SubTLSProbe {
		if sudo {
			return sudoRefusal() // sudoers does not list it: the probe runs unprivileged
		}
		return e.tlsProbe(args)
	}
	if !valid {
		return refuse(helperproto.ExitRefused, helperproto.CodeInvalidArgument)
	}
	if sub != helperproto.SubVersion && !sudo {
		return refuse(helperproto.ExitRefused, helperproto.CodeNotRoot)
	}
	noArgs := func(r func() Response) Response {
		if len(args) != 0 {
			return refuse(helperproto.ExitRefused, helperproto.CodeUsage)
		}
		return r()
	}
	switch sub {
	case helperproto.SubVersion:
		return noArgs(func() Response {
			e.mu.Lock()
			p := e.protocol
			e.mu.Unlock()
			return answer(helperproto.VersionResponse{OK: true, Helper: helperproto.Version, Protocol: p})
		})
	case helperproto.SubSSHDDump:
		return noArgs(func() Response {
			e.mu.Lock()
			cfg := e.sshd
			e.mu.Unlock()
			return answer(helperproto.SSHDDumpResponse{OK: true, Config: cfg, Fallback: cfg == ""})
		})
	case helperproto.SubHostKeys:
		return noArgs(func() Response {
			e.mu.Lock()
			keys := append([]helperproto.HostKeyInfo{}, e.hostKeys...)
			e.mu.Unlock()
			return answer(helperproto.HostKeysResponse{OK: true, Keys: keys})
		})
	case helperproto.SubAuthKeysList:
		return noArgs(func() Response {
			e.mu.Lock()
			defer e.mu.Unlock()
			return answer(e.listLocked())
		})
	case helperproto.SubAuthKeysRead:
		return e.read(args)
	case helperproto.SubAuthKeysWrite:
		return e.write(args, stdin)
	case helperproto.SubCleanup:
		return e.cleanup(args)
	default:
		return refuse(helperproto.ExitRefused, helperproto.CodeUnknownSubcommand)
	}
}

// emuScan is the helper's scan: per user, its effective configuration and its listed paths.
type emuScan struct {
	users    []emuUserScan
	command  string
	warnings []string
	unlisted []helperproto.UnlistedAccount // AUD-03: the users the helper could not list
}

type emuUserScan struct {
	user       emuUser
	paths      []string // valid helper paths, in pattern order, without duplicates
	command    string
	unreadable bool
}

func (s *emuScan) warn(code string) {
	if !slices.Contains(s.warnings, code) {
		s.warnings = append(s.warnings, code)
	}
}

func parseOrNil(text string) (sshdconf.Config, bool) {
	if text == "" {
		return sshdconf.Config{}, false
	}
	cfg, err := sshdconf.Parse([]byte(text))
	return cfg, err == nil
}

// scanLocked computes, like the helper, the authorized_keys paths of every user from the
// AuthorizedKeysFile patterns of the sshd configuration (the defaults when sshd -T fails, and
// then every user is unreadable). A pattern whose expansion the helper vocabulary refuses only
// adds the global unsupported_path warning.
func (e *Emulator) scanLocked() emuScan {
	s := emuScan{warnings: []string{}}
	global, gok := parseOrNil(e.sshd)
	if !gok {
		global = sshdconf.Config{AuthorizedKeysFile: sshdconf.DefaultAuthorizedKeysFile, AuthorizedKeysCommand: "none"}
		s.warn(helperproto.WarnSSHDUnreadable)
	}
	s.command = global.AuthorizedKeysCommand
	s.unlisted = []helperproto.UnlistedAccount{}
	report := func(uid int, reason string) {
		if len(s.unlisted) < helperproto.MaxUnlistedAccounts {
			s.unlisted = append(s.unlisted, helperproto.UnlistedAccount{UID: uid, Reason: reason})
		}
	}
	users := make([]emuUser, 0, len(e.users))
	seen := map[string]bool{}
	for _, u := range e.users {
		if seen[u.name] || strings.HasPrefix(u.name, "+") || strings.HasPrefix(u.name, "-") {
			continue // the first entry of a name is the account (getpwnam); NIS-compat entries are none
		}
		seen[u.name] = true
		if !helperproto.ValidAccount(u.name) {
			report(u.uid, helperproto.UnlistedName)
			continue
		}
		home, ok := helperproto.CleanHome(u.home)
		if !ok {
			report(u.uid, helperproto.UnlistedHome)
			continue
		}
		u.home = home
		users = append(users, u)
	}
	sort.SliceStable(users, func(i, j int) bool {
		if users[i].uid != users[j].uid {
			return users[i].uid < users[j].uid
		}
		return users[i].name < users[j].name
	})
	limit := e.maxUsers
	if limit <= 0 {
		limit = 200
	}
	if len(users) > limit {
		users = users[:limit]
		s.warn(helperproto.WarnTooManyUsers)
	}
	for _, u := range users {
		cfg := global
		us := emuUserScan{user: u, unreadable: !gok}
		if text, ok := e.userSSHD[u.name]; ok && gok {
			if uc, ok := parseOrNil(*text); ok {
				cfg = uc
			} else {
				us.unreadable = true
				s.warn(helperproto.WarnSSHDUnreadable)
			}
		}
		us.command = cfg.AuthorizedKeysCommand
		for _, pat := range cfg.AuthorizedKeysFile {
			p, err := sshdconf.Expand(pat, u.name, u.home, u.uid)
			if err != nil || !helperproto.ValidPath(p) {
				s.warn(helperproto.WarnUnsupportedPath)
				continue
			}
			if !slices.Contains(us.paths, p) {
				us.paths = append(us.paths, p)
			}
		}
		s.users = append(s.users, us)
	}
	return s
}

func (e *Emulator) listLocked() helperproto.AuthKeysListResponse {
	s := e.scanLocked()
	resp := helperproto.AuthKeysListResponse{OK: true, Users: []helperproto.UserFiles{}, AuthorizedKeysCommand: s.command, Warnings: s.warnings,
		Accounts: []string{}, Unlisted: append([]helperproto.UnlistedAccount{}, s.unlisted...)}
	if e.accounts != nil {
		resp.Accounts, resp.AccountsComplete = append(resp.Accounts, e.accounts.names...), e.accounts.complete
	} else {
		names := []string{"daemon", "nobody"}
		for _, u := range e.users {
			if helperproto.ValidAccount(u.name) {
				names = append(names, u.name)
			}
		}
		slices.Sort(names)
		// Like the helper: not complete when it listed fewer accounts than exist, skipped directory
		// users, or could not list an entry (AUD-03).
		resp.Accounts = slices.Compact(names)
		resp.AccountsComplete = !slices.Contains(s.warnings, helperproto.WarnTooManyUsers) &&
			!slices.Contains(s.warnings, helperproto.WarnDirectoryUsers) && len(s.unlisted) == 0
	}
	inline := helperproto.MaxListInline // like the helper: content of the files it read, within the budget
	for _, us := range s.users {
		u := us.user
		uf := helperproto.UserFiles{User: u.name, UID: u.uid, Home: u.home, Files: []helperproto.FileInfo{},
			SSHDUnreadable: us.unreadable, AuthorizedKeysCommand: us.command}
		for _, path := range us.paths {
			fi := helperproto.FileInfo{Path: path}
			c, exists := e.files[path]
			switch {
			case e.unsupported[path]:
				fi.Exists, fi.Unsupported = true, true
			case !exists:
				fi.StrictModesOK = !e.insecure[path]
			default:
				fi.Exists, fi.Size, fi.Mode, fi.Owner = true, int64(len(c)), "0600", u.name
				fi.TooLarge = len(c) > helperproto.MaxAuthorizedKeysSize
				if !fi.TooLarge {
					fi.SHA256 = sum(c) // the helper hashes only files it would read
					if !e.failRead[path] && len(c) <= inline {
						fi.Inline, fi.ContentB64 = true, base64.StdEncoding.EncodeToString(c)
						inline -= len(c)
					}
				}
				fi.StrictModesOK = !e.insecure[path]
			}
			uf.Files = append(uf.Files, fi)
		}
		resp.Users = append(resp.Users, uf)
	}
	return helperproto.FitList(resp) // like the helper: the answer stays within MaxListOutput (S8)
}

// AcceptsLogin reports whether one of user's candidate files (as authkeys-list resolves them) holds
// key, as sshd would decide for a plain key line: a cert-authority line never matches, and a user
// the helper does not list has no files.
func (e *Emulator) AcceptsLogin(user string, key ssh.PublicKey) bool {
	e.mu.Lock()
	defer e.mu.Unlock()
	want := key.Marshal()
	for _, us := range e.scanLocked().users {
		if us.user.name != user {
			continue
		}
		for _, p := range us.paths {
			for _, line := range bytes.Split(e.files[p], []byte("\n")) {
				pk, _, opts, _, err := ssh.ParseAuthorizedKey(line)
				if err != nil || hasCertAuthority(opts) {
					continue
				}
				if bytes.Equal(pk.Marshal(), want) {
					return true
				}
			}
		}
	}
	return false
}

// hasCertAuthority reports a cert-authority option; sshd compares option names without regard to case.
func hasCertAuthority(opts []string) bool {
	for _, o := range opts {
		name, _, _ := strings.Cut(o, "=")
		if strings.EqualFold(strings.TrimSpace(name), "cert-authority") {
			return true
		}
	}
	return false
}

// findLocked returns the user scan that lists path.
func (e *Emulator) findLocked(path string) (emuUserScan, bool) {
	for _, us := range e.scanLocked().users {
		if slices.Contains(us.paths, path) {
			return us, true
		}
	}
	return emuUserScan{}, false
}

func (e *Emulator) read(args []string) Response {
	if len(args) != 1 {
		return refuse(helperproto.ExitRefused, helperproto.CodeUsage)
	}
	path := args[0]
	if !helperproto.ValidPath(path) {
		return refuse(helperproto.ExitRefused, helperproto.CodeInvalidArgument)
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	us, listed := e.findLocked(path)
	c, exists := e.files[path]
	switch {
	case !listed:
		return refuse(helperproto.ExitRefused, helperproto.CodePathNotAllowed)
	case e.unsupported[path]:
		return refuse(helperproto.ExitRefused, helperproto.CodeUnsafeFile)
	case e.failRead[path]:
		return refuse(helperproto.ExitFailed, helperproto.CodeIOError)
	case !exists:
		return refuse(helperproto.ExitPrecondition, helperproto.CodeNotFound)
	case len(c) > helperproto.MaxAuthorizedKeysSize:
		return refuse(helperproto.ExitRefused, helperproto.CodeTooLarge)
	default:
		return answer(helperproto.AuthKeysReadResponse{OK: true, Path: path, SHA256: sum(c), ContentB64: base64.StdEncoding.EncodeToString(c), Owner: e.ownerLocked(path, us.user.name), UID: us.user.uid})
	}
}

func (e *Emulator) write(args []string, stdin []byte) Response {
	if len(args) != 7 || args[1] != "--expect-sha256" || args[3] != "--content-sha256" || args[5] != "--op" {
		return refuse(helperproto.ExitRefused, helperproto.CodeUsage)
	}
	path, expect, want, op := args[0], args[2], args[4], args[6]
	if !helperproto.ValidPath(path) || !helperproto.ValidSHA256(expect) || want == helperproto.AbsentSHA256 ||
		!helperproto.ValidSHA256(want) || !helperproto.ValidOpID(op) {
		return refuse(helperproto.ExitRefused, helperproto.CodeInvalidArgument)
	}
	if len(stdin) > helperproto.MaxAuthorizedKeysSize {
		return refuse(helperproto.ExitRefused, helperproto.CodeTooLarge)
	}
	if sum(stdin) != want {
		return refuse(helperproto.ExitPrecondition, helperproto.CodeContentMismatch)
	}
	e.mu.Lock()
	hook := e.beforeWrite
	us, listed := e.findLocked(path)
	owner := us.user.name
	if o, ok := e.owners[path]; ok {
		owner = o
	}
	unsupported, insecure, failW := e.unsupported[path], e.insecure[path], e.failWrite[path]
	e.mu.Unlock()
	switch {
	case !listed:
		return refuse(helperproto.ExitRefused, helperproto.CodePathNotAllowed)
	case us.unreadable:
		return refuse(helperproto.ExitPrecondition, helperproto.CodeSSHDFailed)
	case us.command != "" && us.command != "none":
		return refuse(helperproto.ExitRefused, helperproto.CodeAuthorizedKeysCommand)
	case unsupported:
		return refuse(helperproto.ExitRefused, helperproto.CodeUnsafeFile)
	case insecure:
		return refuse(helperproto.ExitRefused, helperproto.CodeInsecurePermissions)
	case failW:
		return refuse(helperproto.ExitFailed, helperproto.CodeIOError)
	}
	if hook != nil {
		hook(path)
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	current := helperproto.AbsentSHA256
	if c, ok := e.files[path]; ok {
		current = sum(c)
	}
	if current != expect {
		return refuse(helperproto.ExitPrecondition, helperproto.CodeHashMismatch)
	}
	e.files[path] = append([]byte(nil), stdin...)
	e.writes = append(e.writes, path)
	e.backups[op]++
	return answer(helperproto.AuthKeysWriteResponse{OK: true, SHA256: sum(stdin),
		Backup: helperproto.BackupRoot + "/" + op + "/" + strconv.Itoa(e.backups[op]) + ".bak", Owner: owner})
}

func (e *Emulator) cleanup(args []string) Response {
	if len(args) != 2 || args[0] != "--op" {
		return refuse(helperproto.ExitRefused, helperproto.CodeUsage)
	}
	if !helperproto.ValidOpID(args[1]) {
		return refuse(helperproto.ExitRefused, helperproto.CodeInvalidArgument)
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	if r, ok := e.nginx().cleanupOp(args[1]); ok {
		return r
	}
	removed := 0
	if e.backups[args[1]] > 0 {
		removed = 1
		delete(e.backups, args[1])
	}
	return answer(helperproto.CleanupResponse{OK: true, Removed: removed})
}
