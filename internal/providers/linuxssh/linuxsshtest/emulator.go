package linuxsshtest

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"slices"
	"sort"
	"strconv"
	"strings"
	"sync"

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

// AddUser adds an account with a home directory. Like the helper, users with a name or home the
// helper vocabulary refuses are never listed.
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

// FailRead makes authkeys-read of path fail with IO_ERROR.
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

// parseLine splits "[sudo -n ]<helper> <sub> <args>" and unquotes the arguments like the remote
// shell would; it reports ok=false for anything that is not a helper command line.
func parseLine(cmd string) (sudo bool, sub string, args []string, valid bool, ok bool) {
	rest := cmd
	if r, found := strings.CutPrefix(rest, "sudo -n "); found {
		sudo, rest = true, r
	}
	r, found := strings.CutPrefix(rest, helperproto.HelperPath+" ")
	if !found {
		return false, "", nil, false, false
	}
	fields := strings.Split(r, " ")
	sub = fields[0]
	valid = true
	for _, f := range fields[1:] {
		if f == "--expect-sha256" || f == "--op" {
			args = append(args, f)
			continue
		}
		if len(f) < 2 || f[0] != '\'' || f[len(f)-1] != '\'' || !helperproto.ValidArg(f[1:len(f)-1]) {
			valid = false
			continue
		}
		args = append(args, f[1:len(f)-1])
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
	users := make([]emuUser, 0, len(e.users))
	for _, u := range e.users {
		if helperproto.ValidUser(u.name) && helperproto.ValidPath(u.home) {
			users = append(users, u)
		}
	}
	sort.SliceStable(users, func(i, j int) bool {
		if users[i].uid != users[j].uid {
			return users[i].uid < users[j].uid
		}
		return users[i].name < users[j].name
	})
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
	resp := helperproto.AuthKeysListResponse{OK: true, Users: []helperproto.UserFiles{}, AuthorizedKeysCommand: s.command, Warnings: s.warnings}
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
				}
				fi.StrictModesOK = !e.insecure[path]
			}
			uf.Files = append(uf.Files, fi)
		}
		resp.Users = append(resp.Users, uf)
	}
	return resp
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
		return answer(helperproto.AuthKeysReadResponse{OK: true, Path: path, SHA256: sum(c), ContentB64: base64.StdEncoding.EncodeToString(c), Owner: e.ownerLocked(path, us.user.name)})
	}
}

func (e *Emulator) write(args []string, stdin []byte) Response {
	if len(args) != 5 || args[1] != "--expect-sha256" || args[3] != "--op" {
		return refuse(helperproto.ExitRefused, helperproto.CodeUsage)
	}
	path, expect, op := args[0], args[2], args[4]
	if !helperproto.ValidPath(path) || !helperproto.ValidSHA256(expect) || !helperproto.ValidOpID(op) {
		return refuse(helperproto.ExitRefused, helperproto.CodeInvalidArgument)
	}
	if len(stdin) > helperproto.MaxAuthorizedKeysSize {
		return refuse(helperproto.ExitRefused, helperproto.CodeTooLarge)
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
	removed := 0
	if e.backups[args[1]] > 0 {
		removed = 1
		delete(e.backups, args[1])
	}
	return answer(helperproto.CleanupResponse{OK: true, Removed: removed})
}
