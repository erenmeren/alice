package linuxsshtest

import (
	"path"
	"slices"
	"sort"
	"strings"

	"alice/internal/providers/linuxssh/helperproto"
	"alice/internal/providers/nginx/nginxconf"
)

// This file is the emulated Nginx host of the fake SSH server: the state and the exported API.
// The answers of the Nginx subcommands are computed from that state by ports of the helper's own
// code paths (nginx_dump.go, nginx_deploy.go, nginx_probe.go), so the emulator's decisions stay
// the real helper's: the configuration text is parsed by the real parser
// (internal/providers/nginx/nginxconf), the dump is authenticated against the emulated files the
// way cmd/alice-helper does, and a deployment runs through the helper's journal state machine.
// The fidelity test in cmd/alice-helper (emulator_fidelity_test.go) runs the same scenarios
// against the real helper and compares the answers.
//
// Key material never prints: file contents, backups and deploy inputs live behind *secretBuf
// pointers, which fmt prints as an address wherever they are nested (an unexported field of a
// struct is not redacted by a String method, a pointer is never expanded below the top level).

// NginxSite is one server block that serves TLS with one certificate and key pair.
type NginxSite struct {
	Names    []string
	Port     int
	Default  bool
	CertPath string
	KeyPath  string
	// Addr is the address of the listen directive ("" = any address). An addition to the plan's
	// struct: tls-probe connects to an address, and a site answers only on its own.
	Addr string
}

// secretBuf holds bytes that may be key material. It is always used through a pointer.
type secretBuf struct{ b []byte }

func newSecret(b []byte) *secretBuf { return &secretBuf{b: append([]byte(nil), b...)} }

func (s *secretBuf) bytes() []byte {
	if s == nil {
		return nil
	}
	return s.b
}

// emuFile is the metadata of a file of the emulated host: who owns it, its mode and how the
// root-controlled walk of the helper sees it.
type emuFile struct {
	owner, group string
	mode         uint32
	problem      string // "", not_root_controlled, special_filesystem, not_regular or hard_linked
	// resolved is where root's links lead ("" = the path itself): SetNginxFileResolved.
	resolved string
}

// emuServer is one server block the emulated configuration holds: a site, or an entry the helper
// reports as unsupported.
type emuServer struct {
	site         NginxSite
	unsupported  bool
	raw, reason  string
	streamServer bool
}

// nginxHost is the Nginx part of the emulated server.
type nginxHost struct {
	installed   bool
	profileOff  bool // the nginx sudoers profile is NOT installed (the default is installed)
	version     string
	confPath    string
	confPathSet bool

	servers []emuServer
	phantom map[string]bool       // files only AddUnsupported entries name
	content map[string]*secretBuf // certificate, key and configuration files that exist
	meta    map[string]*emuFile
	confs   map[string]bool // configuration files whose content a test set (overrides the generated text)
	loaded  map[string]*secretBuf

	configInvalid string
	dumpText      *string // replaces what nginx -T prints
	nginxKilled   bool
	freeBytes     int64
	freeSet       bool
	dumpBudget    int
	maxOps        int
	maxFences     int // SetMaxNginxFences (the helper's maxNginxFences when 0)

	failTest      int
	failReload    int
	noopReload    bool
	notRunning    bool // SetNginxNotRunning: systemctl is-active fails (and so does a reload)
	other         map[int]string
	after         map[int]string
	afterActive   map[int]bool
	failWriteDirs map[string]bool
	failRestore   map[string]bool
	failJournal   string
	interfere     []interference
	killAt        string
	killExit137   bool
	faultsFor     string // ArmFaultsFor: the subcommand the armed faults wait for ("" = the next one)
	hangupAt      string
	hangedUp      bool
	locked        bool
	probeFails    bool
	reloads       int
	deploys       int
	fences        int // nginx-fence calls that reached the helper (FenceCount)
	stdins        []*secretBuf

	ops     map[string]*opDir
	records map[string]string // pair -> the operation that last started replacing its files
}

// interference is a change by someone else that happens when the transaction reaches a point.
type interference struct {
	point, path string
	content     *secretBuf
	killNginx   bool
}

func (e *Emulator) nginx() *nginxHost {
	if e.nx == nil {
		e.nx = &nginxHost{
			content: map[string]*secretBuf{}, meta: map[string]*emuFile{}, confs: map[string]bool{}, loaded: map[string]*secretBuf{},
			other: map[int]string{}, after: map[int]string{}, afterActive: map[int]bool{}, failWriteDirs: map[string]bool{},
			failRestore: map[string]bool{}, phantom: map[string]bool{}, ops: map[string]*opDir{}, records: map[string]string{},
		}
	}
	return e.nx
}

const (
	defaultConfPath  = "/etc/nginx/nginx.conf"
	defaultFreeBytes = int64(1 << 30)
)

func (h *nginxHost) confPathOrDefault() string {
	if h.confPathSet {
		return h.confPath
	}
	return defaultConfPath
}

func (h *nginxHost) confDir() string { return path.Dir(h.confPathOrDefault()) }

func (h *nginxHost) free() int64 {
	if h.freeSet {
		return h.freeBytes
	}
	return defaultFreeBytes
}

func (h *nginxHost) fencesCap() int {
	if h.maxFences > 0 {
		return h.maxFences
	}
	return 10000
}

func (h *nginxHost) opsCap() int {
	if h.maxOps > 0 {
		return h.maxOps
	}
	return 1000
}

// metaOf returns the metadata of a path, creating the default (root, root, 0600 for a key and
// 0644 otherwise) when there is none.
func (h *nginxHost) metaOf(p string) *emuFile {
	m, ok := h.meta[p]
	if !ok {
		m = &emuFile{owner: "root", group: "root", mode: 0o644}
		if strings.HasSuffix(p, ".key") {
			m.mode = 0o600
		}
		h.meta[p] = m
	}
	return m
}

func (h *nginxHost) setContent(p string, b []byte) {
	h.metaOf(p)
	h.content[p] = newSecret(b)
}

// EnableNginx installs Nginx of the given version at /usr/sbin/nginx. The sudoers profile for the
// Nginx subcommands is installed by default and independent of this (SetNginxProfile).
func (e *Emulator) EnableNginx(version string) {
	e.mu.Lock()
	defer e.mu.Unlock()
	h := e.nginx()
	h.installed, h.version = true, version
}

// SetNginxProfile installs (true, the default) or removes the sudoers profile of the Nginx
// subcommands: without it sudo refuses every nginx-* subcommand (exit 1).
func (e *Emulator) SetNginxProfile(installed bool) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.nginx().profileOff = !installed
}

// AddSite adds a server block with one certificate and key pair: the configuration, both files
// and the served leaf (as if Nginx had been reloaded).
func (e *Emulator) AddSite(s NginxSite, certPEM, keyPEM []byte) {
	e.mu.Lock()
	defer e.mu.Unlock()
	h := e.nginx()
	h.servers = append(h.servers, emuServer{site: s})
	h.setContent(s.CertPath, certPEM)
	h.setContent(s.KeyPath, keyPEM)
	h.loaded[s.CertPath] = h.content[s.CertPath]
	h.loaded[s.KeyPath] = h.content[s.KeyPath]
}

// Unsupported reasons AddUnsupported can produce through the real parser (nginxconf.Reason*).
var unsupportedReasons = []string{nginxconf.ReasonVariable, nginxconf.ReasonDataValue, nginxconf.ReasonEngineKey, nginxconf.ReasonKeyMissing,
	nginxconf.ReasonPasswordFile, nginxconf.ReasonPathNotAllowed, nginxconf.ReasonStream, nginxconf.ReasonCombinedFile, nginxconf.ReasonConfigFileWritable}

// AddUnsupported adds a server block whose pair nginx-dump reports as unsupported with reason:
// raw is the argument of its ssl_certificate directive, which the dump returns as "raw". The
// configuration text is built so that the real parser (and, for config_file_writable, the
// helper's marking) arrives at that reason. A "stream" entry is a server of a stream block (the
// dump then warns stream_tls); config_file_writable puts the block in a configuration file that
// users other than root can write (its own file, so no other pair is affected). Stream servers
// have no names.
func (e *Emulator) AddUnsupported(names []string, port int, raw, reason string) {
	if !slices.Contains(unsupportedReasons, reason) {
		panic("linuxsshtest: AddUnsupported: unknown reason " + reason)
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	h := e.nginx()
	h.servers = append(h.servers, emuServer{site: NginxSite{Names: names, Port: port}, unsupported: true, raw: raw, reason: reason,
		streamServer: reason == nginxconf.ReasonStream})
	h.phantom[raw] = true
	h.phantom["/etc/nginx/ssl/unsupported.key"] = true
	if reason == nginxconf.ReasonConfigFileWritable {
		m := h.metaOf(h.confDir() + "/conf.d/writable.conf")
		m.mode = 0o666
	}
}

// SetNginxFile changes (or creates) a certificate, key or configuration file outside Alice: the
// content is replaced and Nginx is not reloaded.
func (e *Emulator) SetNginxFile(p string, content []byte) {
	e.mu.Lock()
	defer e.mu.Unlock()
	h := e.nginx()
	h.setContent(p, content)
	if h.isConfigPath(p) {
		h.confs[p] = true
	}
}

// SetNginxConfig sets the text of a configuration file (replacing the generated one, or adding a
// file; one outside conf.d must be included by another file's include directive).
func (e *Emulator) SetNginxConfig(p, content string) {
	e.mu.Lock()
	defer e.mu.Unlock()
	h := e.nginx()
	h.setContent(p, []byte(content))
	h.confs[p] = true
}

// RemoveNginxFile deletes a file of the emulated host (a configuration file override included).
func (e *Emulator) RemoveNginxFile(p string) {
	e.mu.Lock()
	defer e.mu.Unlock()
	h := e.nginx()
	delete(h.content, p)
	if h.isConfigPath(p) {
		h.confs[p] = true // removed, not regenerated
	}
}

// NginxFile returns the content of a certificate, key or configuration file (nil when it does
// not exist). Generated configuration files are included.
func (e *Emulator) NginxFile(p string) []byte {
	e.mu.Lock()
	defer e.mu.Unlock()
	h := e.nginx()
	if b, ok := h.fileLocked(p); ok {
		return append([]byte(nil), b...)
	}
	return nil
}

// SetNginxFileMode sets the owner, group and permission bits of a file ("root" is root; an owner
// that is not a name is a number, as the helper prints an unknown uid).
func (e *Emulator) SetNginxFileMode(p, owner, group string, mode uint32) {
	e.mu.Lock()
	defer e.mu.Unlock()
	m := e.nginx().metaOf(p)
	m.owner, m.group, m.mode = owner, group, mode&0o7777
}

// SetFileProblem makes the helper's root-controlled walk refuse (or see) a file: problem is
// not_root_controlled and special_filesystem (a directory on the path: the walk fails), not_regular
// or hard_linked (the file itself); "" clears it. nginx-dump reports the problem and
// nginx-deploy refuses the file. missing, too_large, not_a_certificate, leaf_unreadable and
// bad_name follow from the file's absence, size, content and name: RemoveNginxFile, a content over
// helperproto.MaxCertFileSize, a file without CERTIFICATE blocks, a file whose first CERTIFICATE
// block is not a certificate, a name without a certificate extension.
func (e *Emulator) SetFileProblem(p, problem string) {
	if !slices.Contains([]string{"", helperproto.FileNotRootControlled, helperproto.FileSpecialFS, helperproto.FileNotRegular, helperproto.FileHardLinked}, problem) {
		panic("linuxsshtest: SetFileProblem: unsupported problem " + problem)
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	e.nginx().metaOf(p).problem = problem
}

// SetNginxFileResolved makes the file at p a root-owned link that resolves to resolved (a path
// the helper's argument vocabulary may not carry, such as an acme.sh "*.example.test" directory).
// nginx-dump reports it (resolved, symlinked; name_not_allowed when the vocabulary cannot carry
// it) and nginx-deploy refuses it with PATH_NOT_ALLOWED before writing anything (A1-I1).
func (e *Emulator) SetNginxFileResolved(p, resolved string) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.nginx().metaOf(p).resolved = resolved
}

// resolvedOf is where the file at p resolves to.
func (h *nginxHost) resolvedOf(p string) string {
	if m := h.meta[p]; m != nil && m.resolved != "" {
		return m.resolved
	}
	return p
}

// SetNginxConfPath sets the --conf-path nginx -V reports ("" = a build without one, which the
// helper refuses as unsupported / no_conf_path; a relative path likewise).
func (e *Emulator) SetNginxConfPath(p string) {
	e.mu.Lock()
	defer e.mu.Unlock()
	h := e.nginx()
	h.confPath, h.confPathSet = p, true
}

// SetNginxDump replaces what nginx -T prints (the helper's tests do the same to present a
// forged, truncated or odd dump); the helper's checks then run on it. A forged dump is also the way
// to reach what real Nginx never shows: the emulated nginx -T fails on a pair file that is missing,
// does not load or does not match, as real Nginx does, so a dump with such a file (a "missing" or
// "not_a_certificate" problem, a deploy racing a file change) needs SetNginxDump(NginxDumpText()).
func (e *Emulator) SetNginxDump(text string) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.nginx().dumpText = &text
}

// ClearNginxDump makes nginx -T print the emulated configuration files again.
func (e *Emulator) ClearNginxDump() {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.nginx().dumpText = nil
}

// SetConfigInvalid makes nginx -T and nginx -t fail with an error of that class (syntax,
// key_mismatch, file_missing, cert_load or key_load, the classes the helper derives from nginx's
// text); "" makes the configuration valid again. The classes untrusted and unsupported are never
// nginx's: they come from the helper's checks of the dump and the files (SetNginxDump,
// SetFileProblem, SetNginxConfPath).
func (e *Emulator) SetConfigInvalid(class string) {
	if !slices.Contains([]string{"", helperproto.ConfigErrSyntax, helperproto.ConfigErrKeyMismatch, helperproto.ConfigErrFileMissing,
		helperproto.ConfigErrCertLoad, helperproto.ConfigErrKeyLoad}, class) {
		panic("linuxsshtest: SetConfigInvalid: not a class of nginx's own errors: " + class)
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	e.nginx().configInvalid = class
}

// SetNginxKilled makes every run of the nginx binary (-V, -T, -t) time out or die by a signal:
// nginx-dump and nginx-test answer IO_ERROR, and a deployment's nginx -t fails its step with an
// empty class. systemctl (the reload) is unaffected: FailReload makes that fail.
func (e *Emulator) SetNginxKilled(on bool) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.nginx().nginxKilled = on
}

// FailConfigTest makes the next n "nginx -t" inside a deploy (its config_test step and the
// rollback's) fail with class syntax.
func (e *Emulator) FailConfigTest(n int) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.nginx().failTest = n
}

// FailReload makes the next n reloads fail (a deploy's and its rollback's alike).
func (e *Emulator) FailReload(n int) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.nginx().failReload = n
}

// NoopReload makes reload "succeed" while Nginx keeps serving the files it loaded before (F-05).
func (e *Emulator) NoopReload(on bool) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.nginx().noopReload = on
}

// SetNginxNotRunning makes "systemctl is-active nginx" fail (Nginx stopped, or no systemctl): the
// helper refuses nginx-deploy with NGINX_NOT_RUNNING before writing anything (A1 m3); a reload
// fails too.
func (e *Emulator) SetNginxNotRunning(on bool) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.nginx().notRunning = on
}

// ServeOther makes something else answer on port with the given leaf (a load balancer, F-06);
// "" ends it.
func (e *Emulator) ServeOther(port int, leafSHA256 string) {
	e.mu.Lock()
	defer e.mu.Unlock()
	h := e.nginx()
	if leafSHA256 == "" {
		delete(h.other, port)
		return
	}
	h.other[port] = leafSHA256
}

// ServeOtherAfterReload makes something else answer on port from the next successful reload on,
// until the reload after it.
func (e *Emulator) ServeOtherAfterReload(port int, leafSHA256 string) {
	e.mu.Lock()
	defer e.mu.Unlock()
	h := e.nginx()
	h.after[port] = leafSHA256
	delete(h.afterActive, port)
}

// SetFreeBytes sets the free space of every file system; nginx-deploy answers NO_SPACE below
// what it needs (F-10).
func (e *Emulator) SetFreeBytes(n int64) {
	e.mu.Lock()
	defer e.mu.Unlock()
	h := e.nginx()
	h.freeBytes, h.freeSet = n, true
}

// SetNginxDumpBudget sets the largest nginx-dump answer (the helper's 16 MiB when 0).
func (e *Emulator) SetNginxDumpBudget(n int) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.nginx().dumpBudget = n
}

// SetMaxNginxOps sets how many operation directories the server keeps (the helper's 1000 when
// 0); a new operation beyond it answers NO_SPACE.
func (e *Emulator) SetMaxNginxOps(n int) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.nginx().maxOps = n
}

// SetMaxNginxFences sets how many fence tombstones the server keeps (the helper's 10000 when 0); a
// fence beyond it answers NO_SPACE. Tombstones do not count against SetMaxNginxOps.
func (e *Emulator) SetMaxNginxFences(n int) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.nginx().maxFences = n
}

// CorruptNginxJournal makes op's journal unreadable (a journal an older helper wrote for a path the
// vocabulary cannot carry, A1-I1): nginx-status, nginx-restore, nginx-fence, cleanup and a deploy
// of op answer IO_ERROR, and op blocks its pair as pending when it is the pair's latest.
func (e *Emulator) CorruptNginxJournal(op string) {
	e.mu.Lock()
	defer e.mu.Unlock()
	if o := e.nginx().ops[op]; o != nil && o.j != nil {
		o.unreadable = true
	}
}

// FailWriteIn makes nginx-deploy and nginx-restore unable to create files in dir (IO_ERROR when
// the key's directory is unwritable before anything changed, F-12; a failed step after it; a
// failed restore). "" lifts every such directory.
func (e *Emulator) FailWriteIn(dir string) {
	e.mu.Lock()
	defer e.mu.Unlock()
	h := e.nginx()
	if dir == "" {
		h.failWriteDirs = map[string]bool{}
		return
	}
	h.failWriteDirs[dir] = true
}

// FailRestoreFile makes writing path fail during a rollback (restore_failed, failed step
// restore; with the certificate restored first and the key failing, a mixed pair). "" lifts it.
func (e *Emulator) FailRestoreFile(p string) {
	e.mu.Lock()
	defer e.mu.Unlock()
	h := e.nginx()
	if p == "" {
		h.failRestore = map[string]bool{}
		return
	}
	h.failRestore[p] = true
}

// FailJournalWrite makes the next write of a journal in the given phase (prepared, writing or
// committed) fail: a refusal for the first two, the journal step's rollback for committed.
func (e *Emulator) FailJournalWrite(phase string) {
	if !slices.Contains([]string{helperproto.PhasePrepared, helperproto.PhaseWriting, helperproto.PhaseCommitted, helperproto.PhaseRestoring, helperproto.PhaseFenced}, phase) {
		panic("linuxsshtest: FailJournalWrite: the helper answers a failed journal write only in the phases prepared, writing, committed and restoring, not " + phase)
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	e.nginx().failJournal = phase
}

// InterfereAt makes someone else replace path with content when a transaction reaches point (a
// point name of the helper: backup, write_key, write_cert, config_test, reload, ...): a file
// changed during a deployment. Armed transaction faults (InterfereAt, KillAt, KillAtWithExit137,
// HangupAfter, FailJournalWrite) apply to the next nginx-deploy, nginx-restore or Nginx cleanup only
// and are consumed by it, fired or not (a refusal before the transaction leaves none behind).
func (e *Emulator) InterfereAt(point, p string, content []byte) {
	e.mu.Lock()
	defer e.mu.Unlock()
	h := e.nginx()
	h.interfere = append(h.interfere, interference{point: point, path: p, content: newSecret(content)})
}

// KillAtWithExit137 is KillAt with the other way a killed helper ends: no signal, exit status 137
// (the remote shell did not exec the helper and it was SIGKILLed) and empty stdout. Alice's
// DecodeHelper maps it to ssh.helper_missing; the Nginx provider must still treat it as an
// uncertain outcome, never as a refusal.
func (e *Emulator) KillAtWithExit137(point string) {
	e.mu.Lock()
	defer e.mu.Unlock()
	h := e.nginx()
	h.killAt, h.killExit137 = point, true
}

// KillNginxAt makes every run of nginx die from the moment a transaction reaches point (a point
// name of the helper, e.g. write_cert: its nginx -t is then killed); SetNginxKilled(false) ends it.
func (e *Emulator) KillNginxAt(point string) {
	e.mu.Lock()
	defer e.mu.Unlock()
	h := e.nginx()
	h.interfere = append(h.interfere, interference{point: point, killNginx: true})
}

// HangupAfter makes the connection drop when a nginx-deploy reaches step: the helper completes the
// whole transaction on its own (it ignores SIGHUP and SIGPIPE) and its answer is lost (F-08).
func (e *Emulator) HangupAfter(step string) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.nginx().hangupAt = step
}

// KillAt kills the helper at the named point of the next nginx-deploy or nginx-restore, once. The
// names are the helper's: the steps backup, write_key, write_cert, config_test, reload, restore,
// rollback_config_test and rollback_reload, and the finer points "journal <phase> staged",
// "journal <phase> renamed", "backup cert", "backup key", "pair record staged", "pair record
// renamed", "stage <file>", "staged <file>" and "renamed <file>" (<file> is ".alice-<op>-key" or
// "-cert"). A killed helper prints nothing and ends by a signal; its journal, backups and files are
// exactly as the helper leaves them at that point (D13).
func (e *Emulator) KillAt(point string) {
	e.mu.Lock()
	defer e.mu.Unlock()
	h := e.nginx()
	h.killAt, h.killExit137 = point, false
}

// ArmFaultsFor makes the faults armed so far and until that command (KillAt, KillAtWithExit137,
// HangupAfter, InterfereAt, FailJournalWrite, and the counts of FailConfigTest and FailReload, and
// FailRestoreFile) wait for the next command of subcommand sub (helperproto.SubNginxDeploy,
// SubNginxRestore or SubCleanup): a transaction command of another subcommand runs without them and
// leaves them armed. A test of a provider call that sends several commands (a deployment and its
// inline nginx-restore) arms a fault for the later one this way. "" goes back to the default: the
// next transaction command takes the faults.
func (e *Emulator) ArmFaultsFor(sub string) {
	if !slices.Contains([]string{"", helperproto.SubNginxDeploy, helperproto.SubNginxRestore, helperproto.SubCleanup, helperproto.SubNginxFence}, sub) {
		panic("linuxsshtest: ArmFaultsFor: not a transaction subcommand: " + sub)
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	e.nginx().faultsFor = sub
}

// heldFaults are the faults a transaction command of another subcommand than ArmFaultsFor's runs
// without.
type heldFaults struct {
	killAt, hangupAt, failJournal string
	killExit137                   bool
	interfere                     []interference
	failTest, failReload          int
	failRestore                   map[string]bool
}

// holdFaults is called at the start of a transaction command of subcommand sub: when the armed
// faults wait for another subcommand they are put aside for this command and the returned
// function puts them back (defer it before consumeFaults); otherwise the command takes them.
func (h *nginxHost) holdFaults(sub string) func() {
	if h.faultsFor == "" || h.faultsFor == sub {
		h.faultsFor = ""
		return func() {}
	}
	held := heldFaults{killAt: h.killAt, hangupAt: h.hangupAt, failJournal: h.failJournal, killExit137: h.killExit137,
		interfere: h.interfere, failTest: h.failTest, failReload: h.failReload, failRestore: h.failRestore}
	h.killAt, h.hangupAt, h.failJournal, h.killExit137, h.interfere = "", "", "", false, nil
	h.failTest, h.failReload, h.failRestore = 0, 0, map[string]bool{}
	return func() {
		h.killAt, h.hangupAt, h.failJournal, h.killExit137, h.interfere = held.killAt, held.hangupAt, held.failJournal, held.killExit137, held.interfere
		h.failTest, h.failReload, h.failRestore = held.failTest, held.failReload, held.failRestore
	}
}

// HoldLock makes another process hold the Nginx lock: nginx-deploy, nginx-restore and the cleanup
// of an Nginx operation answer BUSY, and nginx-status reports active.
func (e *Emulator) HoldLock(on bool) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.nginx().locked = on
}

// LocalProbeFails makes tls-probe answer PROBE_FAILED.
func (e *Emulator) LocalProbeFails(on bool) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.nginx().probeFails = on
}

// Served is the hex SHA-256 of the leaf Nginx serves on port for sni after its last successful
// reload ("" when nothing answers); sni "" or "_" sends no name.
func (e *Emulator) Served(port int, sni string) string {
	e.mu.Lock()
	defer e.mu.Unlock()
	if s, ok := e.nginx().servedLocked("", port, sni, helperproto.ProbeAny); ok {
		return s.leafSHA
	}
	return ""
}

// ProbeServed is what a TLS handshake with the emulated host at addr:port with sni ("" or "_":
// none) and keyType (helperproto.ProbeAny, ProbeRSA or ProbeECDSA) shows, selected like Nginx
// (and like the emulated tls-probe): a listen on another specific address does not answer at addr;
// addr "" connects to any. It returns the served leaf's hex SHA-256 and the number of certificates
// presented; ok is false when nothing answers or the handshake would fail. Test probers that stand
// for Alice's own probe pass the address Alice connects to.
func (e *Emulator) ProbeServed(addr string, port int, sni, keyType string) (leafSHA256 string, chainLength int, ok bool) {
	e.mu.Lock()
	defer e.mu.Unlock()
	s, ok := e.nginx().servedLocked(addr, port, sni, keyType)
	return s.leafSHA, s.chain, ok
}

// Reloads counts the reloads Nginx was asked for (successful or not).
func (e *Emulator) Reloads() int {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.nginx().reloads
}

// FenceCount returns how many nginx-fence calls reached the helper (AUD-05).
func (e *Emulator) FenceCount() int {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.nginx().fences
}

// DeployCount counts the nginx-deploy calls that reached the transaction (past the argument,
// lock and content checks).
func (e *Emulator) DeployCount() int {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.nginx().deploys
}

// DeployStdins returns the stdin of every nginx-deploy the helper was run with (tests assert the
// key went only there). The emulator keeps them behind pointers so that formatting its state
// never prints them.
func (e *Emulator) DeployStdins() [][]byte {
	e.mu.Lock()
	defer e.mu.Unlock()
	h := e.nginx()
	out := make([][]byte, 0, len(h.stdins))
	for _, s := range h.stdins {
		out = append(out, append([]byte(nil), s.bytes()...))
	}
	return out
}

// SweepOperation removes an operation's directory (journal and backups) as the helper's backup
// sweep does once its retention has passed: nginx-status then answers phase none for it. The
// files of the pair stay as they are.
func (e *Emulator) SweepOperation(op string) {
	e.mu.Lock()
	defer e.mu.Unlock()
	delete(e.nginx().ops, op)
}

// NginxPhase is the phase of an operation's journal ("" when there is none).
func (e *Emulator) NginxPhase(op string) string {
	e.mu.Lock()
	defer e.mu.Unlock()
	if o := e.nginx().ops[op]; o != nil && o.j != nil {
		return o.j.phase
	}
	return ""
}

// isConfigPath reports a path under the configuration directory with a configuration file name.
func (h *nginxHost) isConfigPath(p string) bool {
	return p == h.confPathOrDefault() || strings.HasSuffix(p, ".conf") && strings.HasPrefix(p, h.confDir()+"/")
}

// pairKey names a pair's record the way the helper does (its two resolved paths).
func pairKey(cert, key string) string { return cert + "\x00" + key }

// sortedKeys returns the keys of a map in order.
func sortedKeys[V any](m map[string]V) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func isNginxSub(sub string) bool {
	switch sub {
	case helperproto.SubNginxDump, helperproto.SubNginxTest, helperproto.SubNginxDeploy, helperproto.SubNginxRestore, helperproto.SubNginxStatus,
		helperproto.SubNginxFence:
		return true
	}
	return false
}

func sudoRefusal() Response {
	return Response{Stderr: []byte("sudo: a password is required\n"), Exit: 1}
}

// sudoersAllows mirrors the narrowed nginx sudoers lines (setup.go's sudoersNginxOnly): an exact
// subcommand word, flags in the helper's order, an operation id of 36 characters and hashes of 64
// (fnmatch "?" runs); only the paths are "/*" wildcards. A line that does not match never reaches
// the helper: sudo refuses it.
func sudoersAllows(sub string, args []string) bool {
	switch sub {
	case helperproto.SubNginxDump, helperproto.SubNginxTest, helperproto.SubApacheDump:
		return len(args) == 0
	case helperproto.SubNginxRestore, helperproto.SubNginxStatus, helperproto.SubNginxFence:
		return len(args) == 2 && args[0] == "--op" && len(args[1]) == 36
	case helperproto.SubNginxDeploy:
		return len(args) == 10 && args[0] == "--op" && len(args[1]) == 36 && args[2] == "--cert" && strings.HasPrefix(args[3], "/") &&
			args[4] == "--key" && strings.HasPrefix(args[5], "/") && args[6] == "--expect-cert-sha256" && len(args[7]) == 64 &&
			args[8] == "--content-sha256" && len(args[9]) == 64
	}
	return false
}

// handleNginx answers the five privileged Nginx subcommands: sudo (the profile, the sudoers
// patterns) first, then the helper (it refuses a call without root, then validates its own
// arguments).
func (e *Emulator) handleNginx(sudo bool, sub string, args []string, stdin []byte) Response {
	e.mu.Lock()
	off := e.nginx().profileOff
	e.mu.Unlock()
	if sudo && (off || !sudoersAllows(sub, args)) {
		return sudoRefusal()
	}
	if !sudo {
		return refuse(helperproto.ExitRefused, helperproto.CodeNotRoot)
	}
	switch sub {
	case helperproto.SubNginxDump:
		return e.nginxDump(args)
	case helperproto.SubNginxTest:
		return e.nginxTest(args)
	case helperproto.SubNginxDeploy:
		return e.nginxDeploy(args, stdin)
	case helperproto.SubNginxRestore:
		return e.nginxRestore(args)
	case helperproto.SubNginxFence:
		return e.nginxFence(args)
	default:
		return e.nginxStatus(args)
	}
}

// NginxDumpText is what nginx -T prints for the emulated host now (tests that forge a dump start
// from it).
func (e *Emulator) NginxDumpText() string {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.nginx().dumpOutput()
}
