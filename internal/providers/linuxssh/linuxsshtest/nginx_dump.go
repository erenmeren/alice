package linuxsshtest

import (
	"bytes"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"path"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"

	"alice/internal/providers/linuxssh/helperproto"
	"alice/internal/providers/nginx/nginxconf"
)

// ---- configuration text ------------------------------------------------------------------

// confFile is one configuration file as nginx -T prints it.
type confFile struct{ path, content string }

// serverBlock renders one server block of the emulated configuration.
func serverBlock(s emuServer) string {
	var b strings.Builder
	b.WriteString("server {\n")
	listen := strconv.Itoa(s.site.Port)
	if s.site.Addr != "" {
		listen = s.site.Addr + ":" + listen
	}
	b.WriteString("    listen " + listen + " ssl")
	if s.site.Default {
		b.WriteString(" default_server")
	}
	b.WriteString(";\n")
	if len(s.site.Names) > 0 && !s.streamServer {
		b.WriteString("    server_name " + strings.Join(s.site.Names, " ") + ";\n")
	}
	cert, key := s.site.CertPath, s.site.KeyPath
	extra := ""
	if s.unsupported {
		cert = s.raw
		if cert == "" {
			cert = "/etc/nginx/ssl/unsupported.crt"
		}
		key = "/etc/nginx/ssl/unsupported.key"
		switch s.reason {
		case nginxconf.ReasonCombinedFile:
			key = cert
		case nginxconf.ReasonEngineKey:
			key = "engine:pkcs11:id"
		case nginxconf.ReasonKeyMissing:
			key = ""
		case nginxconf.ReasonPasswordFile:
			extra = "    ssl_password_file /etc/nginx/ssl/password.txt;\n"
		}
	}
	b.WriteString("    ssl_certificate " + cert + ";\n")
	if key != "" {
		b.WriteString("    ssl_certificate_key " + key + ";\n")
	}
	b.WriteString(extra)
	b.WriteString("}\n")
	return b.String()
}

// blocksText puts server blocks at lines 1, 11, 21, ... of a file after its header lines (the
// "line" of nginx-dump), padding with comment lines.
func blocksText(servers []emuServer, header string) string {
	var b strings.Builder
	b.WriteString(header)
	line := 1 + strings.Count(header, "\n")
	for i, s := range servers {
		for want := 1 + strings.Count(header, "\n") + 10*i; line < want; line++ {
			b.WriteString("#\n")
		}
		blk := serverBlock(s)
		b.WriteString(blk)
		line += strings.Count(blk, "\n")
	}
	return b.String()
}

// generated returns the generated configuration files (before test overrides), keyed by path.
func (h *nginxHost) generated() map[string]string {
	dir := h.confDir()
	var plain, writable, stream []emuServer
	for _, s := range h.servers {
		switch {
		case s.streamServer:
			stream = append(stream, s)
		case s.unsupported && s.reason == nginxconf.ReasonConfigFileWritable:
			writable = append(writable, s)
		default:
			plain = append(plain, s)
		}
	}
	out := map[string]string{}
	main := "events {\n}\nhttp {\n    include " + dir + "/conf.d/*.conf;\n}\n"
	if len(stream) > 0 {
		main += "include " + dir + "/stream.d/*.conf;\n"
	}
	out[h.confPathOrDefault()] = main
	if len(plain) > 0 {
		out[dir+"/conf.d/emu.conf"] = blocksText(plain, "")
	}
	if len(writable) > 0 {
		out[dir+"/conf.d/writable.conf"] = blocksText(writable, "")
	}
	if len(stream) > 0 {
		out[dir+"/stream.d/emu.conf"] = blocksText(stream, "stream {\n") + "}\n"
	}
	return out
}

// confFiles returns the configuration files in the order nginx -T prints them: the main file,
// then the included ones (conf.d, stream.d, others) each in name order.
func (h *nginxHost) confFiles() []confFile {
	all := h.generated()
	for p := range h.confs {
		if b, ok := h.content[p]; ok {
			all[p] = string(b.bytes())
		} else {
			delete(all, p)
		}
	}
	main := h.confPathOrDefault()
	order := []string{}
	if _, ok := all[main]; ok {
		order = append(order, main)
	}
	rest := sortedKeys(all)
	dir := h.confDir()
	for _, prefix := range []string{dir + "/conf.d/", dir + "/stream.d/", ""} {
		for _, p := range rest {
			if p != main && !slices.Contains(order, p) && strings.HasPrefix(p, prefix) {
				order = append(order, p)
			}
		}
	}
	out := make([]confFile, 0, len(order))
	for _, p := range order {
		out = append(out, confFile{p, all[p]})
	}
	return out
}

// fileLocked returns the content of any file of the host, generated configuration included. A
// configuration file a test removed stays removed.
func (h *nginxHost) fileLocked(p string) ([]byte, bool) {
	if b, ok := h.content[p]; ok {
		return b.bytes(), true
	}
	if h.confs[p] {
		return nil, false
	}
	if g, ok := h.generated()[p]; ok {
		return []byte(g), true
	}
	return nil, false
}

// dumpOutput is what nginx -T prints: each file under its marker, followed by a line feed.
func (h *nginxHost) dumpOutput() string {
	if h.dumpText != nil {
		return *h.dumpText
	}
	var b strings.Builder
	for _, c := range h.confFiles() {
		b.WriteString("# configuration file " + c.path + ":\n" + c.content + "\n")
	}
	return b.String()
}

// ---- nginx -V, -T, -t ---------------------------------------------------------------------

var (
	errNginxMissing = errors.New("nginx is not installed")
	errNginxKilled  = errors.New("nginx timed out or was killed")
)

// configError is why a dump is refused: a class, a reason and the file when it can be carried.
type configError struct{ class, reason, file string }

func untrusted(reason, file string) *configError {
	return &configError{class: helperproto.ConfigErrUntrusted, reason: reason, file: carried(file)}
}

func unsupportedConf(reason, file string) *configError {
	return &configError{class: helperproto.ConfigErrUnsupported, reason: reason, file: carried(file)}
}

// carried is a configuration file name as it may be returned (the helper's carried).
func carried(file string) string {
	if !strings.HasPrefix(file, "/") || !helperproto.ValidArg(file) {
		return ""
	}
	if c := filepath.Clean(file); helperproto.ValidPath(c) {
		return c
	}
	return ""
}

// parseError maps a parser error to its class and reason (the helper's parseError).
func parseError(err error) *configError {
	switch {
	case errors.Is(err, nginxconf.ErrTooLarge), errors.Is(err, nginxconf.ErrLineTooLong):
		return unsupportedConf(helperproto.ConfigReasonTooLarge, "")
	case errors.Is(err, nginxconf.ErrTooComplex), errors.Is(err, nginxconf.ErrTooDeep):
		return unsupportedConf(helperproto.ConfigReasonTooComplex, "")
	case errors.Is(err, nginxconf.ErrIncludeLoop):
		return unsupportedConf(helperproto.ConfigReasonIncludeLoop, "")
	case errors.Is(err, nginxconf.ErrNUL):
		return unsupportedConf(helperproto.ConfigReasonNULByte, "")
	case errors.Is(err, nginxconf.ErrDuplicateFile):
		return untrusted(helperproto.ConfigReasonDuplicateFile, "")
	}
	return &configError{class: helperproto.ConfigErrSyntax}
}

// nginxMeta is what nginxConfig learned besides the parse (the helper's nginxMeta).
type nginxMeta struct {
	version, confPath string
	valid             bool
	class, reason     string
	file              string
	writable          []string
}

// parsedVersion is the version nginx -V prints when it is one the helper accepts.
func (h *nginxHost) parsedVersion() string {
	v := h.version
	versionChar := func(r rune) bool {
		return r >= '0' && r <= '9' || r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r == '.' || r == '-' || r == '+'
	}
	if len(v) > 40 || strings.ContainsFunc(v, func(r rune) bool { return !versionChar(r) }) {
		return ""
	}
	return v
}

// parsedConfPath is the --conf-path nginx -V prints when it is an absolute clean helper path.
func (h *nginxHost) parsedConfPath() string {
	p := h.confPathOrDefault()
	if !helperproto.ValidPath(p) || p == "/" {
		return ""
	}
	return p
}

// nginxConfig is the helper's nginxConfig on the emulated host: nginx -V and -T, the parse, the
// authentication of every section against the files, and the marking of pairs in writable files.
func (h *nginxHost) nginxConfig() (nginxconf.Config, nginxMeta, error) {
	var meta nginxMeta
	invalid := func(e *configError) (nginxconf.Config, nginxMeta, error) {
		meta.valid, meta.class, meta.reason, meta.file, meta.writable = false, e.class, e.reason, e.file, nil
		return nginxconf.Config{}, meta, nil
	}
	if !h.installed {
		return nginxconf.Config{}, meta, errNginxMissing
	}
	if h.nginxKilled {
		return nginxconf.Config{}, meta, errNginxKilled
	}
	meta.version, meta.confPath = h.parsedVersion(), h.parsedConfPath()
	if h.configInvalid != "" {
		return invalid(&configError{class: h.configInvalid})
	}
	// Real nginx -T loads the pair files like nginx -t: a missing file, a certificate that does not
	// load or a key that does not match fail it (class file_missing, cert_load, key_load,
	// key_mismatch). The races the helper's own checks guard against (a file changing between nginx
	// -T and the helper's read) exist only with a forged dump: SetNginxDump(NginxDumpText()).
	if h.dumpText == nil {
		if c := h.pairsFailure(); c != "" {
			return invalid(&configError{class: c})
		}
	}
	out := h.dumpOutput()
	switch {
	case len(out) > helperproto.MaxNginxConfig:
		return invalid(unsupportedConf(helperproto.ConfigReasonTooLarge, ""))
	case meta.confPath == "":
		return invalid(unsupportedConf(helperproto.ConfigReasonNoConfPath, ""))
	}
	cfg, err := nginxconf.Parse([]byte(out), filepath.Dir(meta.confPath))
	if err != nil {
		return invalid(parseError(err))
	}
	writable, cerr := h.authenticate(cfg.Sections, meta.confPath)
	if cerr != nil {
		return invalid(cerr)
	}
	meta.valid, meta.writable = true, writable
	refuseWritable(&cfg, writable)
	return cfg, meta, nil
}

// authenticate is the helper's authenticate: every section must be the exact content of the file
// it names (read through the root-controlled walk) followed by a line feed.
func (h *nginxHost) authenticate(secs []nginxconf.Section, confPath string) ([]string, *configError) {
	writable := []string{}
	named := 0
	masked := func(e *configError) *configError {
		if len(writable) > 0 {
			return untrusted(helperproto.ConfigReasonChanged, writable[0])
		}
		return e
	}
	for _, sec := range secs {
		if sec.File == "" {
			if len(bytes.TrimSpace(sec.Body)) > 0 {
				return nil, untrusted(helperproto.ConfigReasonUnexpectedText, "")
			}
			continue
		}
		if !strings.HasPrefix(sec.File, "/") || !helperproto.ValidArg(sec.File) {
			return nil, masked(unsupportedConf(helperproto.ConfigReasonNameNotAllowed, ""))
		}
		if named++; named == 1 && filepath.Clean(sec.File) != confPath {
			return nil, untrusted(helperproto.ConfigReasonWrongFirstFile, sec.File)
		}
		if named > 1 && !sec.Included {
			return nil, masked(untrusted(helperproto.ConfigReasonChanged, ""))
		}
		m, reason := h.sameContent(sec.File, sec.Body)
		if reason != "" {
			return nil, masked(untrusted(reason, sec.File))
		}
		if m.owner != "root" || m.mode&0o022 != 0 {
			writable = append(writable, sec.File)
		}
	}
	if named == 0 {
		return nil, untrusted(helperproto.ConfigReasonWrongFirstFile, "")
	}
	return writable, nil
}

// sameContent is the helper's sameContent: the file holds exactly body without its final line feed
// (a hard-linked file is accepted: the read is only a comparison).
func (h *nginxHost) sameContent(name string, body []byte) (*emuFile, string) {
	if len(body) == 0 || body[len(body)-1] != '\n' {
		return nil, helperproto.ConfigReasonChanged
	}
	name = filepath.Clean(name)
	m := h.meta[name]
	if m != nil {
		switch m.problem { // the walk of the directories fails
		case helperproto.FileNotRootControlled:
			return nil, helperproto.ConfigReasonNotRootControlled
		case helperproto.FileSpecialFS:
			return nil, helperproto.ConfigReasonSpecialFS
		}
	}
	got, ok := h.fileLocked(name)
	if !ok {
		return nil, helperproto.ConfigReasonMissing
	}
	m = h.metaOf(name)
	if m.problem == helperproto.FileNotRegular {
		return nil, helperproto.ConfigReasonNotRegular
	}
	if !bytes.Equal(got, body[:len(body)-1]) {
		return nil, helperproto.ConfigReasonChanged
	}
	return m, ""
}

// refuseWritable is the helper's refuseWritable (S1).
func refuseWritable(cfg *nginxconf.Config, writable []string) {
	if len(writable) == 0 {
		return
	}
	bad := func(f string) bool { return f != "" && slices.Contains(writable, f) }
	for i := range cfg.Servers {
		sv := &cfg.Servers[i]
		server := slices.ContainsFunc(sv.Files, bad)
		for j := range sv.Pairs {
			p := &sv.Pairs[j]
			if p.Unsupported == "" && (server || slices.ContainsFunc(p.Files, bad)) {
				p.Unsupported = nginxconf.ReasonConfigFileWritable
			}
		}
	}
}

// ---- nginx -t ---------------------------------------------------------------------------

// testConfig is "nginx -t" on the host: "" when valid, else the class of the error. err is set
// (class "") when nginx is missing or was killed. inDeploy consumes FailConfigTest.
func (h *nginxHost) testConfig(inDeploy bool) (class string, err error) {
	switch {
	case !h.installed:
		return "", errNginxMissing
	case h.nginxKilled:
		return "", errNginxKilled
	case h.configInvalid != "":
		return h.configInvalid, errors.New("nginx -t failed")
	case inDeploy && h.failTest > 0:
		h.failTest--
		return helperproto.ConfigErrSyntax, errors.New("nginx -t failed")
	}
	if _, ok := h.liveConfig(); !ok {
		return helperproto.ConfigErrSyntax, errors.New("nginx -t failed")
	}
	if c := h.pairsFailure(); c != "" {
		return c, errors.New("nginx -t failed")
	}
	return "", nil
}

// pairsFailure is the class of the first pair whose files nginx cannot load, "" when all load (or
// the configuration does not parse: that is a syntax error, reported elsewhere). Real Nginx loads
// every ssl_certificate and ssl_certificate_key in "nginx -t" and in "nginx -T" alike.
func (h *nginxHost) pairsFailure() string {
	cfg, ok := h.liveConfig()
	if !ok {
		return ""
	}
	for _, p := range cfg.pairs() {
		if h.phantomPair(p) {
			continue
		}
		if c := h.pairClass(p.Cert, p.Key); c != "" {
			return c
		}
	}
	return ""
}

// liveConfig parses the configuration files as they are on the host (what nginx loads: not a dump
// a test forged); ok is false when they do not parse.
func (h *nginxHost) liveConfig() (liveCfg, bool) {
	var b strings.Builder
	for _, c := range h.confFiles() {
		b.WriteString("# configuration file " + c.path + ":\n" + c.content + "\n")
	}
	cfg, err := nginxconf.Parse([]byte(b.String()), h.confDir())
	if err != nil {
		return liveCfg{}, false
	}
	return liveCfg{cfg}, true
}

type liveCfg struct{ nginxconf.Config }

// phantomPair: a pair of an AddUnsupported entry whose files the emulator does not have (it never
// created them): nginx -t cannot say anything about it.
func (h *nginxHost) phantomPair(p nginxconf.Pair) bool {
	for _, x := range []string{p.Cert, p.Key} {
		if _, ok := h.fileLocked(x); !ok && h.phantom[x] {
			return true
		}
	}
	return false
}

// pairs are the pairs of every server block whose two paths are known (a variable, an engine key
// or a missing key leaves nothing to load).
func (c liveCfg) pairs() []nginxconf.Pair {
	var out []nginxconf.Pair
	for _, sv := range c.Servers {
		for _, p := range sv.Pairs {
			if p.Cert != "" && p.Key != "" {
				out = append(out, p)
			}
		}
	}
	return out
}

// pairClass is the class nginx -t gives a pair: the files must exist, load and match.
func (h *nginxHost) pairClass(certPath, keyPath string) string {
	cert, cok := h.fileLocked(certPath)
	key, kok := h.fileLocked(keyPath)
	if !cok || !kok {
		return helperproto.ConfigErrFileMissing
	}
	ders := certDERs(cert)
	if len(ders) == 0 {
		return helperproto.ConfigErrCertLoad
	}
	for _, d := range ders { // OpenSSL fails the whole chain file on a block that is not a certificate
		if _, err := x509.ParseCertificate(d); err != nil {
			return helperproto.ConfigErrCertLoad
		}
	}
	if _, err := tlsPair(cert, key); err != nil {
		if errors.Is(err, errKeyLoad) {
			return helperproto.ConfigErrKeyLoad
		}
		if errors.Is(err, errCertLoad) {
			return helperproto.ConfigErrCertLoad
		}
		return helperproto.ConfigErrKeyMismatch
	}
	return ""
}

// ---- nginx-dump and nginx-test -----------------------------------------------------------------

func (e *Emulator) nginxDump(args []string) Response {
	if len(args) != 0 {
		return refuse(helperproto.ExitRefused, helperproto.CodeUsage)
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	h := e.nginx()
	cfg, meta, err := h.nginxConfig()
	switch {
	case errors.Is(err, errNginxMissing):
		return refuse(helperproto.ExitPrecondition, helperproto.CodeNginxNotFound)
	case err != nil:
		return refuse(helperproto.ExitFailed, helperproto.CodeIOError)
	}
	resp := helperproto.NginxDumpResponse{OK: true, Version: meta.version, ConfPath: meta.confPath, ConfigValid: meta.valid,
		ConfigError: meta.class, ConfigErrorReason: meta.reason, ConfigErrorFile: meta.file, Servers: []helperproto.NginxServer{},
		Files: []helperproto.NginxFile{}, Warnings: append([]string{}, cfg.Warnings...), Writable: append([]string{}, meta.writable...)}
	if !meta.valid {
		return answer(resp)
	}
	warn := func(code string) {
		if !slices.Contains(resp.Warnings, code) {
			resp.Warnings = append(resp.Warnings, code)
		}
	}
	if len(resp.Writable) > 0 {
		warn(helperproto.WarnConfigFileWritable)
	}
	for _, sv := range cfg.Servers {
		resp.Servers = append(resp.Servers, toWire(sv))
	}
	budget := h.dumpBudget
	if budget <= 0 {
		budget = helperproto.NginxDumpOutput
	}
	n, pemBytes := 0, 0
	for _, p := range cfg.CertPaths() {
		if n++; n > helperproto.MaxNginxFiles {
			warn(helperproto.WarnTooManyFiles)
			break
		}
		fi, dropped := h.describeCert(p)
		if dropped {
			warn(helperproto.WarnCertificateBlockDropped)
		}
		if pemBytes += len(fi.PEM); pemBytes > budget {
			return refuse(helperproto.ExitFailed, helperproto.CodeOutputTooLarge)
		}
		resp.Files = append(resp.Files, fi)
	}
	for _, p := range cfg.KeyPaths() {
		if n++; n > helperproto.MaxNginxFiles {
			warn(helperproto.WarnTooManyFiles)
			break
		}
		fi, open := h.describeKey(p)
		if open {
			warn(helperproto.WarnKeyGroupOpen)
		}
		resp.Files = append(resp.Files, fi)
	}
	b, err := json.Marshal(resp)
	if err != nil || len(b)+1 > budget {
		return refuse(helperproto.ExitFailed, helperproto.CodeOutputTooLarge)
	}
	return Response{Stdout: append(b, '\n')}
}

// toWire converts a parsed server block (the helper's toWire).
func toWire(sv nginxconf.Server) helperproto.NginxServer {
	out := helperproto.NginxServer{File: clean(sv.File, 4096), Line: sv.Line, Names: []string{}, Listens: []helperproto.NginxListen{},
		Pairs: []helperproto.NginxPair{}, Stream: sv.Stream}
	for _, n := range sv.Names {
		out.Names = append(out.Names, clean(n, 253))
	}
	for _, l := range nginxconf.SSLListens(sv) {
		out.Listens = append(out.Listens, helperproto.NginxListen{Addr: clean(l.Addr, 253), Port: l.Port, DefaultServer: l.DefaultServer})
	}
	for _, p := range sv.Pairs {
		wp := helperproto.NginxPair{Cert: p.Cert, Key: p.Key, Inherited: p.Inherited, Unsupported: p.Unsupported}
		if p.Unsupported != "" {
			wp.Raw = cleanRunes(p.CertRaw, 200)
		}
		out.Pairs = append(out.Pairs, wp)
	}
	return out
}

// clean drops control characters and invalid UTF-8 and cuts s to at most maxBytes on a rune
// boundary (the helper's clean).
func clean(s string, maxBytes int) string {
	s = strings.Map(func(r rune) rune {
		if unicode.IsControl(r) || r == utf8.RuneError {
			return -1
		}
		return r
	}, strings.ToValidUTF8(s, ""))
	for len(s) > maxBytes {
		_, size := utf8.DecodeLastRuneInString(s)
		s = s[:len(s)-size]
	}
	return s
}

// cleanRunes is clean with a limit in runes.
func cleanRunes(s string, maxRunes int) string {
	s = clean(s, len(s))
	if r := []rune(s); len(r) > maxRunes {
		return string(r[:maxRunes])
	}
	return s
}

var certExtensions = []string{".pem", ".crt", ".cer", ".cert", ".key", ".chained", ".fullchain"}

func certName(name string) bool {
	for _, ext := range certExtensions {
		if len(name) > len(ext) && strings.HasSuffix(name, ext) {
			return true
		}
	}
	return false
}

// walkProblem is the error of the root-controlled walk to p (before its last element), as a
// helperproto.File* code ("" when the walk succeeds).
func (h *nginxHost) walkProblem(p string) string {
	if m := h.meta[p]; m != nil && (m.problem == helperproto.FileNotRootControlled || m.problem == helperproto.FileSpecialFS) {
		return m.problem
	}
	return ""
}

// fileProblem is the problem the file itself has once the walk succeeded: not_regular and
// hard_linked from the flag, "" otherwise.
func (h *nginxHost) fileProblem(p string) string {
	if m := h.meta[p]; m != nil && (m.problem == helperproto.FileNotRegular || m.problem == helperproto.FileHardLinked) {
		return m.problem
	}
	return ""
}

func modeString(m uint32) string { return fmt.Sprintf("%04o", m&0o777) }

// describeCert is the helper's describeCert on the emulated file.
func (h *nginxHost) describeCert(p string) (fi helperproto.NginxFile, dropped bool) {
	fi = helperproto.NginxFile{Path: p, Kind: "cert"}
	if wp := h.walkProblem(p); wp != "" {
		fi.Exists, fi.Problem = true, wp
		return fi, false
	}
	fi.Resolved = h.resolvedOf(p)
	fi.Symlinked = fi.Resolved != p
	if !helperproto.ValidPath(fi.Resolved) {
		fi.Exists, fi.Problem, fi.FreeBytes = true, helperproto.FileNameNotAllowed, h.free()
		return fi, false
	}
	if !certName(path.Base(p)) {
		fi.Exists, fi.Problem, fi.FreeBytes = true, helperproto.FileBadName, h.free()
		return fi, false
	}
	fi.FreeBytes = h.free()
	data, exists := h.fileLocked(p)
	switch {
	case !exists:
		fi.Problem = helperproto.FileMissing
		return fi, false
	case h.fileProblem(p) != "":
		fi.Exists, fi.Problem = true, h.fileProblem(p)
		return fi, false
	}
	m := h.metaOf(p)
	fi.Exists, fi.Size = true, int64(len(data))
	fi.Mode, fi.Owner, fi.Group = modeString(m.mode), m.owner, m.group
	if len(data) > helperproto.MaxCertFileSize {
		fi.Problem = helperproto.FileTooLarge
		return fi, false
	}
	fi.SHA256 = sum(data)
	blocks, dropped, firstDropped := certPEMBlocks(data)
	switch {
	case blocks == "":
		fi.Problem = helperproto.FileNotACertificate
	case firstDropped:
		fi.Problem, blocks = helperproto.FileLeafUnreadable, ""
	}
	fi.PEM = blocks
	return fi, dropped
}

// describeKey is the helper's describeKey: only the file's attributes, never its content.
func (h *nginxHost) describeKey(p string) (fi helperproto.NginxFile, open bool) {
	fi = helperproto.NginxFile{Path: p, Kind: "key"}
	if wp := h.walkProblem(p); wp != "" {
		fi.Exists, fi.Problem = true, wp
		return fi, false
	}
	fi.Resolved, fi.FreeBytes = h.resolvedOf(p), h.free()
	fi.Symlinked = fi.Resolved != p
	data, exists := h.fileLocked(p)
	if !exists {
		fi.Problem = helperproto.FileMissing
		return fi, false
	}
	m := h.metaOf(p)
	fi.Exists, fi.Size = true, int64(len(data))
	fi.Mode, fi.Owner, fi.Group = modeString(m.mode), m.owner, m.group
	switch {
	case !helperproto.ValidPath(fi.Resolved):
		fi.Problem = helperproto.FileNameNotAllowed
	case !certName(path.Base(p)):
		fi.Problem = helperproto.FileBadName
	case m.problem == helperproto.FileNotRegular:
		fi.Problem = helperproto.FileNotRegular
	case m.problem == helperproto.FileHardLinked:
		fi.Problem = helperproto.FileHardLinked
	case len(data) > helperproto.MaxCertFileSize:
		fi.Problem = helperproto.FileTooLarge
	}
	return fi, fi.Problem == "" && keyOpen(m)
}

// keyOpen is the helper's keyOpen: owned by a user other than root, readable by a group other than
// root's or by others.
func keyOpen(m *emuFile) bool {
	return m.owner != "root" || (m.mode&0o040 != 0 && m.group != "root") || m.mode&0o004 != 0
}

var (
	pemCertBegin = []byte("-----BEGIN CERTIFICATE-----")
	pemCertEnd   = []byte("-----END CERTIFICATE-----")
)

// certPEMBlocks is the helper's certBlocks: the X.509 certificates of data re-encoded as
// CERTIFICATE blocks, whether a block was dropped, and whether it was the first one. A private key
// is never returned.
func certPEMBlocks(data []byte) (blocks string, dropped, firstDropped bool) {
	var b bytes.Buffer
	drop := func(first bool) {
		dropped = true
		firstDropped = firstDropped || first
	}
	for rest, first := data, true; ; first = false {
		i := bytes.Index(rest, pemCertBegin)
		if i < 0 {
			break
		}
		rest = rest[i:]
		end := bytes.Index(rest, pemCertEnd)
		if end < 0 {
			drop(first)
			break
		}
		blk, _ := pem.Decode(rest[:end+len(pemCertEnd)])
		rest = rest[end+len(pemCertEnd):]
		if blk == nil {
			drop(first)
			continue
		}
		if _, err := x509.ParseCertificate(blk.Bytes); err != nil || blk.Type != "CERTIFICATE" || len(blk.Headers) != 0 {
			drop(first)
			continue
		}
		_ = pem.Encode(&b, &pem.Block{Type: "CERTIFICATE", Bytes: blk.Bytes})
	}
	return b.String(), dropped, firstDropped
}

func (e *Emulator) nginxTest(args []string) Response {
	if len(args) != 0 {
		return refuse(helperproto.ExitRefused, helperproto.CodeUsage)
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	class, err := e.nginx().testConfig(false)
	switch {
	case errors.Is(err, errNginxMissing):
		return refuse(helperproto.ExitPrecondition, helperproto.CodeNginxNotFound)
	case errors.Is(err, errNginxKilled):
		return refuse(helperproto.ExitFailed, helperproto.CodeIOError)
	case err != nil:
		return answer(helperproto.NginxTestResponse{OK: true, Valid: false, Error: class})
	}
	return answer(helperproto.NginxTestResponse{OK: true, Valid: true})
}
