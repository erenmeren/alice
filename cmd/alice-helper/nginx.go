//go:build linux

package main

import (
	"bytes"
	"context"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"golang.org/x/sys/unix"

	"alice/internal/providers/linuxssh/helperproto"
	"alice/internal/providers/nginx/nginxconf"
)

// The fixed programs of the nginx subcommands (spec §12.1, R38 item 5).
const (
	nginxPath     = "/usr/sbin/nginx"
	systemctlPath = "/usr/bin/systemctl"
	stderrLimit   = 64 << 10
	// programTimeout bounds one run of an external program (within the command budget).
	programTimeout = 30 * time.Second
	// childUmask is the umask of nginx and systemctl (S8): files nginx -t creates (a missing log
	// file) get the usual modes, not the helper's own 077.
	childUmask = 0o022
)

// runProgram runs a fixed program with a fixed minimal environment, no shell, no stdin, "/" as its
// directory and umask 022, for at most programTimeout. stdout is capped at outLimit (errTooLarge
// over it), stderr at stderrLimit (kept only for classification, never returned to Alice).
func runProgram(ctx context.Context, path string, outLimit int, args ...string) ([]byte, []byte, error) {
	ctx, cancel := context.WithTimeout(ctx, programTimeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, path, args...) //nolint:gosec // G204: a fixed absolute program with fixed arguments
	cmd.Env = []string{"PATH=/usr/sbin:/usr/bin:/sbin:/bin", "LANG=C"}
	cmd.Dir = "/"
	cmd.Stdin = nil
	cmd.WaitDelay = time.Second // a child that keeps the pipes open does not hold the helper
	out := &capWriter{max: outLimit}
	errOut := &capWriter{max: stderrLimit}
	cmd.Stdout, cmd.Stderr = out, errOut
	// The umask is process-wide; the helper starts no goroutine that creates files meanwhile.
	old := unix.Umask(childUmask)
	err := cmd.Start()
	unix.Umask(old)
	if err == nil {
		err = cmd.Wait()
		var exit *exec.ExitError
		switch {
		case ctx.Err() != nil:
			err = fmt.Errorf("%w: %w", errProgramKilled, ctx.Err())
		case errors.As(err, &exit) && !exit.Exited():
			err = fmt.Errorf("%w: %w", errProgramKilled, err) // ended by a signal, not by its own exit
		}
	}
	if out.over {
		return nil, errOut.buf, errTooLarge
	}
	return out.buf, errOut.buf, err
}

// errProgramKilled: the program timed out or was killed by a signal. Its answer says nothing about
// the configuration: the subcommand fails with IO_ERROR (retryable).
var errProgramKilled = errors.New("the program timed out or was killed")

// classifyNginxError reduces nginx's error text to a class (never the text: it names files and
// may quote configuration).
func classifyNginxError(stderr []byte) string {
	s := string(stderr)
	switch {
	case strings.Contains(s, "key values mismatch"):
		return helperproto.ConfigErrKeyMismatch
	case strings.Contains(s, "No such file or directory"):
		return helperproto.ConfigErrFileMissing
	case strings.Contains(s, "cannot load certificate key"), strings.Contains(s, "SSL_CTX_use_PrivateKey"), strings.Contains(s, "PEM_read_bio_PrivateKey"):
		return helperproto.ConfigErrKeyLoad
	case strings.Contains(s, "cannot load certificate"), strings.Contains(s, "PEM_read_bio_X509"), strings.Contains(s, "SSL_CTX_use_certificate"):
		return helperproto.ConfigErrCertLoad
	default:
		return helperproto.ConfigErrSyntax
	}
}

// dumpMeta is what nginxConfig (apacheConfig) learned besides the parse. valid is false (with
// class) when nginx -T (Apache's DUMP_* runs) failed, or the configuration cannot be trusted or
// parsed; writable lists the configuration files a user other than root can change (their pairs
// are unsupported, S1).
type dumpMeta struct {
	version  string
	confPath string
	valid    bool
	class    string
	reason   string // a helperproto.ConfigReason* for ConfigErrUntrusted and ConfigErrUnsupported
	file     string // the configuration file the reason is about ("" when unknown or not carried)
	writable []string
}

// configError is why a dump is refused: a class, a reason and the file when it can be carried.
type configError struct {
	class, reason, file string
}

func (e *configError) Error() string { return e.class + ": " + e.reason }

func untrusted(reason, file string) *configError {
	return &configError{class: helperproto.ConfigErrUntrusted, reason: reason, file: carried(file)}
}

func unsupported(reason, file string) *configError {
	return &configError{class: helperproto.ConfigErrUnsupported, reason: reason, file: carried(file)}
}

// carried is a configuration file name as it may be returned: a clean absolute helper path, or "".
func carried(file string) string {
	if !strings.HasPrefix(file, "/") || !helperproto.ValidArg(file) {
		return ""
	}
	if c := filepath.Clean(file); helperproto.ValidPath(c) {
		return c
	}
	return ""
}

// parseError maps a parser error to its class and reason.
func parseError(err error) *configError {
	switch {
	case errors.Is(err, nginxconf.ErrTooLarge), errors.Is(err, nginxconf.ErrLineTooLong):
		return unsupported(helperproto.ConfigReasonTooLarge, "")
	case errors.Is(err, nginxconf.ErrTooComplex), errors.Is(err, nginxconf.ErrTooDeep):
		return unsupported(helperproto.ConfigReasonTooComplex, "")
	case errors.Is(err, nginxconf.ErrIncludeLoop):
		return unsupported(helperproto.ConfigReasonIncludeLoop, "")
	case errors.Is(err, nginxconf.ErrNUL):
		return unsupported(helperproto.ConfigReasonNULByte, "")
	case errors.Is(err, nginxconf.ErrDuplicateFile):
		return untrusted(helperproto.ConfigReasonDuplicateFile, "")
	}
	return &configError{class: helperproto.ConfigErrSyntax}
}

var errNginxMissing = errors.New("nginx is not installed")

// nginxConfig runs "nginx -V" and "nginx -T", parses the dump and authenticates it: every section
// must be the exact content of the file it names, read through resolveRoot (the markers are not
// authenticated: a file could contain a forged one). An invalid, unsupported or untrusted
// configuration is not an error: meta.valid is false and the Config is empty, never partial.
// Every pair that a configuration file writable by a user other than root holds (its server
// block, a file spliced into it, or one of its directives) is marked unsupported (S1).
func (s *sys) nginxConfig(ctx context.Context) (nginxconf.Config, dumpMeta, error) {
	var meta dumpMeta
	invalid := func(e *configError) (nginxconf.Config, dumpMeta, error) {
		meta.valid, meta.class, meta.reason, meta.file, meta.writable = false, e.class, e.reason, e.file, nil
		return nginxconf.Config{}, meta, nil
	}
	// An nginx binary a user other than root can change never runs (Ruling 15): untrusted
	// not_root_controlled naming it, whichever run meets it.
	var pe *programError
	_, verr, err := s.runNginx(ctx, "-V")
	switch {
	case errors.As(err, &pe):
		return invalid(untrusted(helperproto.ConfigReasonNotRootControlled, pe.path))
	case missingProgram(err):
		return nginxconf.Config{}, meta, errNginxMissing
	case err != nil:
		return nginxconf.Config{}, meta, err
	}
	meta.version, meta.confPath = parseNginxV(verr)
	out, terr, err := s.runNginx(ctx, "-T")
	switch {
	case errors.As(err, &pe):
		return invalid(untrusted(helperproto.ConfigReasonNotRootControlled, pe.path))
	case missingProgram(err):
		return nginxconf.Config{}, meta, errNginxMissing
	case errors.Is(err, errProgramKilled):
		return nginxconf.Config{}, meta, err // says nothing about the configuration
	case errors.Is(err, errTooLarge):
		return invalid(unsupported(helperproto.ConfigReasonTooLarge, ""))
	case err != nil:
		return invalid(&configError{class: classifyNginxError(terr)})
	case meta.confPath == "":
		// A relative or missing --conf-path: the configuration prefix is unknown, so relative
		// include and certificate paths cannot be resolved. Unsupported, not an empty host.
		return invalid(unsupported(helperproto.ConfigReasonNoConfPath, ""))
	}
	cfg, err := nginxconf.Parse(out, filepath.Dir(meta.confPath))
	if err != nil {
		return invalid(parseError(err))
	}
	writable, cerr := s.authenticate(cfg.Sections, meta.confPath)
	if cerr != nil {
		return invalid(cerr)
	}
	meta.valid, meta.writable = true, writable
	refuseWritable(&cfg, writable)
	return cfg, meta, nil
}

func missingProgram(err error) bool {
	return errors.Is(err, fs.ErrNotExist) || errors.Is(err, exec.ErrNotFound)
}

// authenticate compares every section of the dump with the file it names: nginx prints each file
// followed by a line feed, so the body must be exactly the file's content and "\n". The file is
// read through walkRoot (every directory and link root's, no link a user made is followed, no
// pseudo or FUSE file system). It refuses an anonymous section that is not blank (text before the
// first marker), a first section that is not the configuration file, a name that is not a valid
// absolute path, a file that cannot be read that way, and any difference; the error says why and
// which file (after a file a user can write, always "changed" naming that file). It returns the files a user other than root can write (owner other than root, or
// writable by group or others), in dump order.
func (s *sys) authenticate(secs []nginxconf.Section, confPath string) ([]string, *configError) {
	writable := []string{}
	named := 0
	// Once a file a user can write has been printed, everything after it may be a section that
	// user forged (a marker naming any path, with the user's file rewritten after nginx -T to match
	// its own section). Every later failure then reads the same, "changed" naming the user's file:
	// the reason must not tell whether a root-only path exists or what it is.
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
			return nil, masked(unsupported(helperproto.ConfigReasonNameNotAllowed, ""))
		}
		if named++; named == 1 && filepath.Clean(sec.File) != confPath {
			return nil, untrusted(helperproto.ConfigReasonWrongFirstFile, sec.File)
		}
		// Every file after the first is printed because an include of an earlier file matched it.
		// A section no include reaches is a forged marker: refused before its name is looked up,
		// so nothing about that path (does it exist, what does it hold) shows in the answer.
		if named > 1 && !sec.Included {
			return nil, masked(untrusted(helperproto.ConfigReasonChanged, ""))
		}
		st, reason := s.sameContent(sec.File, sec.Body)
		if reason != "" {
			return nil, masked(untrusted(reason, sec.File))
		}
		if s.userWritable(st) {
			writable = append(writable, sec.File)
		}
	}
	if named == 0 {
		return nil, untrusted(helperproto.ConfigReasonWrongFirstFile, "")
	}
	return writable, nil
}

// sameContent reports (reason "") that the file name holds exactly body without its final line
// feed, and returns the file's stat; otherwise a helperproto.ConfigReason*. A hard-linked file is
// accepted here: the read is only a comparison and nothing of it is returned.
func (s *sys) sameContent(name string, body []byte) (unix.Stat_t, string) {
	var st unix.Stat_t
	if len(body) == 0 || body[len(body)-1] != '\n' {
		return st, helperproto.ConfigReasonChanged
	}
	want := body[:len(body)-1]
	rf, err := s.walkRoot(name)
	if err != nil {
		return st, walkReason(err)
	}
	defer rf.close()
	f, st, err := rf.openLinked(true)
	if err != nil {
		return st, walkReason(err)
	}
	defer func() { _ = f.Close() }()
	if st.Size != int64(len(want)) {
		return st, helperproto.ConfigReasonChanged
	}
	got, err := io.ReadAll(io.LimitReader(f, int64(len(want))+1))
	if err != nil || !bytes.Equal(got, want) {
		return st, helperproto.ConfigReasonChanged
	}
	return st, ""
}

// walkReason maps a walk or open error of a configuration file to a helperproto.ConfigReason*.
func walkReason(err error) string {
	switch {
	case errors.Is(err, unix.ENOENT):
		return helperproto.ConfigReasonMissing
	case errors.Is(err, errSpecialFS):
		return helperproto.ConfigReasonSpecialFS
	case errors.Is(err, errNotRootControlled), errors.Is(err, errEscaped):
		return helperproto.ConfigReasonNotRootControlled
	}
	return helperproto.ConfigReasonNotRegular // not a regular file, ENOTDIR, a link loop
}

// refuseWritable marks every supported pair unsupported when a file that holds its server block,
// anything spliced into it, or its ssl_certificate or ssl_certificate_key directive, or a file
// whose include brought any of these in, is writable by a user other than root (S1): that user
// could name, or activate, any root-controlled file as the pair.
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

// parseNginxV reads the version and --conf-path from "nginx -V" (stderr). confPath is "" when the
// build names no --conf-path (nginx then uses a path relative to its prefix) or a relative or
// unclean one: such a configuration is unsupported.
func parseNginxV(b []byte) (version, confPath string) {
	for _, line := range strings.Split(string(b), "\n") {
		if v, ok := strings.CutPrefix(line, "nginx version: "); ok {
			v, _, _ = strings.Cut(v, " ")
			if i := strings.LastIndex(v, "/"); i >= 0 {
				version = v[i+1:]
			}
		}
		if rest, ok := strings.CutPrefix(line, "configure arguments:"); ok {
			for _, arg := range strings.Fields(rest) {
				if p, ok := strings.CutPrefix(arg, "--conf-path="); ok {
					confPath = p
				}
			}
		}
	}
	versionChar := func(r rune) bool {
		return r >= '0' && r <= '9' || r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r == '.' || r == '-' || r == '+'
	}
	if len(version) > 40 || strings.ContainsFunc(version, func(r rune) bool { return !versionChar(r) }) {
		version = ""
	}
	if !helperproto.ValidPath(confPath) || confPath == "/" {
		confPath = ""
	}
	return version, confPath
}

// dumpBudget is the largest nginx-dump or apache-dump answer (S11); tests lower it.
var dumpBudget = helperproto.ServerDumpOutput

func cmdNginxDump(ctx context.Context, s *sys, args []string) (any, error) {
	if len(args) != 0 {
		return nil, refused(helperproto.CodeUsage, "nginx-dump takes no arguments")
	}
	s.syslog(helperproto.SubNginxDump, "")
	cfg, meta, err := s.nginxConfig(ctx)
	switch {
	case errors.Is(err, errNginxMissing):
		return nil, precondition(helperproto.CodeNginxNotFound, "nginx is not installed at /usr/sbin/nginx")
	case err != nil:
		return nil, failed(helperproto.CodeIOError, "nginx could not be run to the end")
	}
	resp := helperproto.ServerDumpResponse{OK: true, Version: meta.version, ConfPath: meta.confPath, ConfigValid: meta.valid,
		ConfigError: meta.class, ConfigErrorReason: meta.reason, ConfigErrorFile: meta.file, Servers: []helperproto.DumpServer{}, Files: []helperproto.DumpFile{},
		Warnings: append([]string{}, cfg.Warnings...), Writable: append([]string{}, meta.writable...)}
	if !meta.valid {
		return resp, nil
	}
	for _, sv := range cfg.Servers {
		resp.Servers = append(resp.Servers, toWire(sv))
	}
	return s.finishDump(resp, cfg.CertPaths(), cfg.KeyPaths())
}

// finishDump completes a valid dump of nginx-dump or apache-dump: it warns about writable
// configuration files, describes every certificate file (read, CERTIFICATE blocks only) and key
// file (stat only) of the supported pairs, at most MaxServerFiles of them, and encodes the answer
// within dumpBudget.
func (s *sys) finishDump(resp helperproto.ServerDumpResponse, certs, keys []string) (any, error) {
	warn := func(code string) {
		if !slices.Contains(resp.Warnings, code) {
			resp.Warnings = append(resp.Warnings, code)
		}
	}
	if len(resp.Writable) > 0 {
		warn(helperproto.WarnConfigFileWritable)
	}
	names := map[int]string{}
	if accts, err := s.accounts(); err == nil {
		names = owners(accts)
	}
	groups := s.groupNames()
	n, pemBytes := 0, 0
	for _, p := range certs {
		if n++; n > helperproto.MaxServerFiles {
			warn(helperproto.WarnTooManyFiles)
			break
		}
		fi, dropped := s.describeCert(p, names, groups)
		if dropped {
			warn(helperproto.WarnCertificateBlockDropped)
		}
		if pemBytes += len(fi.PEM); pemBytes > dumpBudget {
			return nil, failed(helperproto.CodeOutputTooLarge, "the certificates do not fit in one answer")
		}
		resp.Files = append(resp.Files, fi)
	}
	for _, p := range keys {
		if n++; n > helperproto.MaxServerFiles {
			warn(helperproto.WarnTooManyFiles)
			break
		}
		fi, open := s.describeKey(p, names, groups)
		if open {
			warn(helperproto.WarnKeyGroupOpen)
		}
		resp.Files = append(resp.Files, fi)
	}
	b, err := json.Marshal(resp)
	if err != nil {
		return nil, failed(helperproto.CodeIOError, "the answer could not be encoded")
	}
	if len(b)+1 > dumpBudget {
		return nil, failed(helperproto.CodeOutputTooLarge, "the answer does not fit the limit")
	}
	return json.RawMessage(b), nil
}

// toWire converts a parsed server block; slices are never nil (empty arrays on the wire).
func toWire(sv nginxconf.Server) helperproto.DumpServer {
	out := helperproto.DumpServer{File: clean(sv.File, 4096), Line: sv.Line, Names: []string{}, Listens: []helperproto.DumpListen{},
		Pairs: []helperproto.DumpPair{}, Stream: sv.Stream}
	for _, n := range sv.Names {
		out.Names = append(out.Names, clean(n, 253))
	}
	for _, l := range nginxconf.SSLListens(sv) {
		out.Listens = append(out.Listens, helperproto.DumpListen{Addr: clean(l.Addr, 253), Port: l.Port, DefaultServer: l.DefaultServer})
	}
	for _, p := range sv.Pairs {
		wp := helperproto.DumpPair{Cert: p.Cert, Key: p.Key, Inherited: p.Inherited, Unsupported: p.Unsupported}
		if p.Unsupported != "" {
			wp.Raw = cleanRunes(p.CertRaw, 200)
		}
		out.Pairs = append(out.Pairs, wp)
	}
	return out
}

// clean drops control characters and invalid UTF-8 and cuts s to at most max bytes on a rune
// boundary.
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

// describeCert reads a certificate file through resolveRoot and returns its certificate blocks.
// dropped reports blocks labelled CERTIFICATE that are not X.509 certificates (S9). A file whose
// first such block is dropped is leaf_unreadable, with no blocks (REM-4).
func (s *sys) describeCert(p string, names, groups map[int]string) (fi helperproto.DumpFile, dropped bool) {
	fi = helperproto.DumpFile{Path: p, Kind: "cert"}
	rf, err := s.resolveRoot(p)
	if errors.Is(err, errNotRegular) {
		err = s.dirProblem(p, err)
	}
	if err != nil {
		fi.Exists = !errors.Is(err, unix.ENOENT)
		fi.Problem = problemOf(err)
		return fi, false
	}
	defer rf.close()
	fi.Resolved, fi.Symlinked = rf.resolved, rf.symlinked
	if !helperproto.ValidPath(rf.resolved) {
		// A1-I1: never read, replaced or journaled (readTarget refuses it): unsupported.
		fi.Exists, fi.Problem = true, helperproto.FileNameNotAllowed
		fi.FreeBytes, _ = s.statfs(rf.dirfd)
		return fi, false
	}
	if !certName(rf.name) {
		fi.Exists, fi.Problem = true, helperproto.FileBadName
		fi.FreeBytes, _ = s.statfs(rf.dirfd)
		return fi, false
	}
	f, st, err := rf.open()
	fi.FreeBytes, _ = s.statfs(rf.dirfd)
	if err != nil {
		fi.Exists = !errors.Is(err, unix.ENOENT)
		fi.Problem = problemOf(err)
		return fi, false
	}
	defer func() { _ = f.Close() }()
	fi.Exists, fi.Size = true, st.Size
	fi.Mode, fi.Owner, fi.Group = fmt.Sprintf("%04o", st.Mode&0o777), ownerName(names, int(st.Uid)), ownerName(groups, int(st.Gid))
	if st.Size > helperproto.MaxCertFileSize {
		fi.Problem = helperproto.FileTooLarge
		return fi, false
	}
	// One buffer of the file's size (plus one byte to see growth), cleared afterwards: the file may
	// also hold a private key, and io.ReadAll's growth would leave copies nobody clears.
	buf := make([]byte, st.Size+1)
	defer clear(buf)
	n, err := io.ReadFull(f, buf)
	if !errors.Is(err, io.ErrUnexpectedEOF) && !errors.Is(err, io.EOF) {
		fi.Problem = helperproto.FileUnreadable // a read error, or the file grew since fstat
		return fi, false
	}
	data := buf[:n]
	fi.SHA256 = hexSHA(data)
	blocks, dropped, firstDropped := certBlocks(data)
	switch {
	case blocks == "":
		fi.Problem = helperproto.FileNotACertificate
	case firstDropped:
		// REM-4: the next certificate (an intermediate) must not reach Alice as the leaf.
		fi.Problem, blocks = helperproto.FileLeafUnreadable, ""
	}
	fi.PEM = blocks
	return fi, dropped
}

// dirProblem refines the walk error errNotRegular of a path that ends at a directory (a crt
// folder haproxy-dump could not list, final review M3): when the directory itself is not
// root-controlled (owner, group or other write bit) or lies on a pseudo or FUSE file system, that
// is the problem to report (openRootDir's error), so the admin is pointed at its owner or mode
// rather than told it is not a regular file. Otherwise err stays.
func (s *sys) dirProblem(p string, err error) error {
	fd, _, derr := s.openRootDir(p)
	switch {
	case derr == nil:
		_ = unix.Close(fd)
	case errors.Is(derr, errNotRootControlled), errors.Is(derr, errSpecialFS):
		return derr
	}
	return err
}

var (
	pemCertBegin = []byte("-----BEGIN CERTIFICATE-----")
	pemCertEnd   = []byte("-----END CERTIFICATE-----")
)

// certBlocks returns the X.509 certificates of data, re-encoded as CERTIFICATE blocks, whether
// a block was dropped (not a certificate, or with PEM headers), and whether the first CERTIFICATE
// block (the leaf Nginx serves) was among them (firstDropped, REM-4). Only the text from a
// CERTIFICATE begin line to the next CERTIFICATE end line is handed to pem.Decode. A private key
// elsewhere in the file is never decoded; one inside that span (an unterminated CERTIFICATE block,
// then a key, then a certificate) can be decoded by pem.Decode's retry, and is then dropped by the
// type and X.509 checks and its bytes cleared. A private key is never returned.
func certBlocks(data []byte) (blocks string, dropped, firstDropped bool) {
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
			clear(blk.Bytes) // whatever it was (a key labelled CERTIFICATE), it does not stay in memory
			drop(first)
			continue
		}
		_ = pem.Encode(&b, &pem.Block{Type: "CERTIFICATE", Bytes: blk.Bytes})
	}
	return b.String(), dropped, firstDropped
}

// describeKey stats a key file through resolveRoot. Its content is never opened or read: only
// fstatat's owner, group, mode, size, type and link count. open reports a key file that keyOpen
// finds exposed (S10).
func (s *sys) describeKey(p string, names, groups map[int]string) (fi helperproto.DumpFile, open bool) {
	fi = helperproto.DumpFile{Path: p, Kind: "key"}
	rf, err := s.resolveRoot(p)
	if err != nil {
		fi.Exists = !errors.Is(err, unix.ENOENT)
		fi.Problem = problemOf(err)
		return fi, false
	}
	defer rf.close()
	fi.Resolved, fi.Symlinked = rf.resolved, rf.symlinked
	fi.FreeBytes, _ = s.statfs(rf.dirfd)
	var st unix.Stat_t
	if err := unix.Fstatat(rf.dirfd, rf.name, &st, unix.AT_SYMLINK_NOFOLLOW); err != nil {
		fi.Exists = !errors.Is(err, unix.ENOENT)
		fi.Problem = problemOf(err)
		return fi, false
	}
	fi.Exists, fi.Size = true, st.Size
	fi.Mode, fi.Owner, fi.Group = fmt.Sprintf("%04o", st.Mode&0o777), ownerName(names, int(st.Uid)), ownerName(groups, int(st.Gid))
	switch {
	case !helperproto.ValidPath(rf.resolved):
		fi.Problem = helperproto.FileNameNotAllowed // A1-I1, as describeCert
	case !certName(rf.name):
		fi.Problem = helperproto.FileBadName
	case st.Mode&unix.S_IFMT != unix.S_IFREG:
		fi.Problem = helperproto.FileNotRegular
	case st.Nlink != 1:
		fi.Problem = helperproto.FileHardLinked
	case st.Size > helperproto.MaxCertFileSize:
		fi.Problem = helperproto.FileTooLarge
	}
	return fi, fi.Problem == "" && keyOpen(st, s.rootUID, s.rootGID)
}

// keyOpen reports a key file owned by a user other than root, or readable by a group other than
// root's or by others (S10: a deployment keeps owner, group and a 0640 mode).
func keyOpen(st unix.Stat_t, rootUID, rootGID int) bool {
	return int(st.Uid) != rootUID || (st.Mode&0o040 != 0 && int(st.Gid) != rootGID) || st.Mode&0o004 != 0
}

func ownerName(names map[int]string, uid int) string {
	if n := names[uid]; n != "" {
		return n
	}
	return fmt.Sprint(uid)
}

func cmdNginxTest(ctx context.Context, s *sys, args []string) (any, error) {
	if len(args) != 0 {
		return nil, refused(helperproto.CodeUsage, "nginx-test takes no arguments")
	}
	s.syslog(helperproto.SubNginxTest, "")
	_, stderr, err := s.runNginx(ctx, "-t")
	switch {
	case missingProgram(err):
		return nil, precondition(helperproto.CodeNginxNotFound, "nginx is not installed at /usr/sbin/nginx")
	case errors.Is(err, errProgramKilled):
		return nil, failed(helperproto.CodeIOError, "nginx could not be run to the end")
	case errors.Is(err, errProgramUntrusted):
		// The binary can be changed by a user other than root (Ruling 15): it did not run.
		return helperproto.NginxTestResponse{OK: true, Valid: false, Error: helperproto.ConfigErrUntrusted}, nil
	case err != nil:
		return helperproto.NginxTestResponse{OK: true, Valid: false, Error: classifyNginxError(stderr)}, nil
	}
	return helperproto.NginxTestResponse{OK: true, Valid: true}, nil
}
