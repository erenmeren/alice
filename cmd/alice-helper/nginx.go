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
	}
	if out.over {
		return nil, errOut.buf, errTooLarge
	}
	return out.buf, errOut.buf, err
}

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

// nginxMeta is what nginxConfig learned besides the parse. valid is false (with class) when
// nginx -T failed, or the dump cannot be trusted or parsed; writable lists the configuration files
// a user other than root can change (their pairs are unsupported, S1).
type nginxMeta struct {
	version  string
	confPath string
	valid    bool
	class    string
	writable []string
}

var errNginxMissing = errors.New("nginx is not installed")

// nginxConfig runs "nginx -V" and "nginx -T", parses the dump and authenticates it: every section
// must be the exact content of the file it names, read through resolveRoot (the markers are not
// authenticated: a file could contain a forged one). An invalid, unsupported or untrusted
// configuration is not an error: meta.valid is false and the Config is empty, never partial.
// Every pair that a configuration file writable by a user other than root holds (its server
// block, a file spliced into it, or one of its directives) is marked unsupported (S1).
func (s *sys) nginxConfig(ctx context.Context) (nginxconf.Config, nginxMeta, error) {
	var meta nginxMeta
	invalid := func(class string) (nginxconf.Config, nginxMeta, error) {
		meta.valid, meta.class, meta.writable = false, class, nil
		return nginxconf.Config{}, meta, nil
	}
	_, verr, err := s.runNginx(ctx, "-V")
	if missingProgram(err) {
		return nginxconf.Config{}, meta, errNginxMissing
	}
	if err != nil {
		return nginxconf.Config{}, meta, err
	}
	meta.version, meta.confPath = parseNginxV(verr)
	out, terr, err := s.runNginx(ctx, "-T")
	switch {
	case missingProgram(err):
		return nginxconf.Config{}, meta, errNginxMissing
	case errors.Is(err, errTooLarge):
		return invalid(helperproto.ConfigErrSyntax)
	case err != nil:
		return invalid(classifyNginxError(terr))
	case meta.confPath == "":
		// A relative or missing --conf-path: the configuration prefix is unknown, so relative
		// include and certificate paths cannot be resolved. Unsupported, not an empty host.
		return invalid(helperproto.ConfigErrSyntax)
	}
	cfg, err := nginxconf.Parse(out, filepath.Dir(meta.confPath))
	if err != nil {
		return invalid(helperproto.ConfigErrSyntax)
	}
	writable, err := s.authenticate(cfg.Sections, meta.confPath)
	if err != nil {
		return invalid(helperproto.ConfigErrSyntax)
	}
	meta.valid, meta.writable = true, writable
	refuseWritable(&cfg, writable)
	return cfg, meta, nil
}

func missingProgram(err error) bool {
	return errors.Is(err, fs.ErrNotExist) || errors.Is(err, exec.ErrNotFound)
}

// errUntrusted: the dump does not match the files it names.
var errUntrusted = errors.New("the nginx -T dump does not match the configuration files")

// authenticate compares every section of the dump with the file it names: nginx prints each file
// followed by a line feed, so the body must be exactly the file's content and "\n". The file is
// read through walkRoot (every directory and link root's, no link a user made is followed). It
// refuses an anonymous section that is not blank (text before the first marker), a first section
// that is not the configuration file, a name that is not a valid absolute path, a file that cannot
// be read that way, and any difference. It returns the files a user other than root can write
// (owner other than root, or writable by group or others), in dump order.
func (s *sys) authenticate(secs []nginxconf.Section, confPath string) ([]string, error) {
	writable := []string{}
	named := 0
	for _, sec := range secs {
		if sec.File == "" {
			if len(bytes.TrimSpace(sec.Body)) > 0 {
				return nil, errUntrusted
			}
			continue
		}
		if named++; named == 1 && filepath.Clean(sec.File) != confPath {
			return nil, errUntrusted
		}
		st, err := s.sameContent(sec.File, sec.Body)
		if err != nil {
			return nil, err
		}
		if int(st.Uid) != s.rootUID || st.Mode&0o022 != 0 {
			writable = append(writable, sec.File)
		}
	}
	if named == 0 {
		return nil, errUntrusted
	}
	return writable, nil
}

// sameContent reports (as a nil error) that the file name holds exactly body without its final
// line feed, and returns the file's stat.
func (s *sys) sameContent(name string, body []byte) (unix.Stat_t, error) {
	var st unix.Stat_t
	if len(body) == 0 || body[len(body)-1] != '\n' {
		return st, errUntrusted
	}
	want := body[:len(body)-1]
	rf, err := s.walkRoot(name)
	if err != nil {
		return st, errUntrusted
	}
	defer rf.close()
	f, st, err := rf.open()
	if err != nil {
		return st, errUntrusted
	}
	defer func() { _ = f.Close() }()
	if st.Size != int64(len(want)) {
		return st, errUntrusted
	}
	got, err := io.ReadAll(io.LimitReader(f, int64(len(want))+1))
	if err != nil || !bytes.Equal(got, want) {
		return st, errUntrusted
	}
	return st, nil
}

// refuseWritable marks every supported pair unsupported when a file that holds its server block,
// anything spliced into it, or its ssl_certificate or ssl_certificate_key directive is writable
// by a user other than root (S1): that user could name any root-controlled file as the pair.
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
			if p.Unsupported == "" && (server || bad(p.CertFile) || bad(p.KeyFile)) {
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

// dumpBudget is the largest nginx-dump answer (S11); tests lower it.
var dumpBudget = helperproto.NginxDumpOutput

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
		return nil, failed(helperproto.CodeIOError, "nginx could not be run")
	}
	resp := helperproto.NginxDumpResponse{OK: true, Version: meta.version, ConfPath: meta.confPath, ConfigValid: meta.valid,
		ConfigError: meta.class, Servers: []helperproto.NginxServer{}, Files: []helperproto.NginxFile{},
		Warnings: append([]string{}, cfg.Warnings...), Writable: append([]string{}, meta.writable...)}
	if !meta.valid {
		return resp, nil
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
	names := map[int]string{}
	if accts, err := s.accounts(); err == nil {
		names = owners(accts)
	}
	n, pemBytes := 0, 0
	for _, p := range cfg.CertPaths() {
		if n++; n > helperproto.MaxNginxFiles {
			warn(helperproto.WarnTooManyFiles)
			break
		}
		fi, dropped := s.describeCert(p, names)
		if dropped {
			warn(helperproto.WarnCertificateBlockDropped)
		}
		if pemBytes += len(fi.PEM); pemBytes > dumpBudget {
			return nil, failed(helperproto.CodeOutputTooLarge, "the certificates do not fit in one answer")
		}
		resp.Files = append(resp.Files, fi)
	}
	for _, p := range cfg.KeyPaths() {
		if n++; n > helperproto.MaxNginxFiles {
			warn(helperproto.WarnTooManyFiles)
			break
		}
		resp.Files = append(resp.Files, s.describeKey(p, names))
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
// dropped reports blocks labelled CERTIFICATE that are not X.509 certificates (S9).
func (s *sys) describeCert(p string, names map[int]string) (fi helperproto.NginxFile, dropped bool) {
	fi = helperproto.NginxFile{Path: p, Kind: "cert"}
	rf, err := s.resolveRoot(p)
	if err != nil {
		fi.Exists = !errors.Is(err, unix.ENOENT)
		fi.Problem = problemOf(err)
		return fi, false
	}
	defer rf.close()
	fi.Resolved, fi.Symlinked = rf.resolved, rf.symlinked
	fi.FreeBytes, _ = s.statfs(rf.dirfd)
	if !certName(rf.name) {
		fi.Exists, fi.Problem = true, helperproto.FileBadName
		return fi, false
	}
	f, st, err := rf.open()
	if err != nil {
		fi.Exists = !errors.Is(err, unix.ENOENT)
		fi.Problem = problemOf(err)
		return fi, false
	}
	defer func() { _ = f.Close() }()
	fi.Exists, fi.Size = true, st.Size
	fi.Mode, fi.Owner = fmt.Sprintf("%04o", st.Mode&0o777), ownerName(names, int(st.Uid))
	if st.Size > helperproto.MaxCertFileSize {
		fi.Problem = helperproto.FileTooLarge
		return fi, false
	}
	data, err := io.ReadAll(io.LimitReader(f, helperproto.MaxCertFileSize+1))
	defer clear(data) // the file may also hold a private key
	if err != nil || len(data) > helperproto.MaxCertFileSize {
		fi.Problem = helperproto.FileUnreadable
		return fi, false
	}
	fi.SHA256 = hexSHA(data)
	blocks, dropped := certBlocks(data)
	if blocks == "" {
		fi.Problem = helperproto.FileNotACertificate
	}
	fi.PEM = blocks
	return fi, dropped
}

var (
	pemCertBegin = []byte("-----BEGIN CERTIFICATE-----")
	pemCertEnd   = []byte("-----END CERTIFICATE-----")
)

// certBlocks returns the X.509 certificates of data, re-encoded as CERTIFICATE blocks, and whether
// a block labelled CERTIFICATE was dropped (not a certificate, or with PEM headers). Only the text
// between a CERTIFICATE begin line and the next CERTIFICATE end line is ever decoded, so a private
// key in the same file is never decoded, copied or returned.
func certBlocks(data []byte) (string, bool) {
	var b bytes.Buffer
	dropped := false
	for rest := data; ; {
		i := bytes.Index(rest, pemCertBegin)
		if i < 0 {
			break
		}
		rest = rest[i:]
		end := bytes.Index(rest, pemCertEnd)
		if end < 0 {
			dropped = true
			break
		}
		blk, _ := pem.Decode(rest[:end+len(pemCertEnd)])
		rest = rest[end+len(pemCertEnd):]
		if blk == nil || blk.Type != "CERTIFICATE" || len(blk.Headers) != 0 {
			dropped = true
			continue
		}
		if _, err := x509.ParseCertificate(blk.Bytes); err != nil {
			dropped = true
			continue
		}
		_ = pem.Encode(&b, &pem.Block{Type: "CERTIFICATE", Bytes: blk.Bytes})
	}
	return b.String(), dropped
}

// describeKey stats a key file through resolveRoot. Its content is never opened or read: only
// fstatat's owner, mode, size, type and link count.
func (s *sys) describeKey(p string, names map[int]string) helperproto.NginxFile {
	fi := helperproto.NginxFile{Path: p, Kind: "key"}
	rf, err := s.resolveRoot(p)
	if err != nil {
		fi.Exists = !errors.Is(err, unix.ENOENT)
		fi.Problem = problemOf(err)
		return fi
	}
	defer rf.close()
	fi.Resolved, fi.Symlinked = rf.resolved, rf.symlinked
	fi.FreeBytes, _ = s.statfs(rf.dirfd)
	var st unix.Stat_t
	if err := unix.Fstatat(rf.dirfd, rf.name, &st, unix.AT_SYMLINK_NOFOLLOW); err != nil {
		fi.Exists = !errors.Is(err, unix.ENOENT)
		fi.Problem = problemOf(err)
		return fi
	}
	fi.Exists, fi.Size = true, st.Size
	fi.Mode, fi.Owner = fmt.Sprintf("%04o", st.Mode&0o777), ownerName(names, int(st.Uid))
	switch {
	case !certName(rf.name):
		fi.Problem = helperproto.FileBadName
	case st.Mode&unix.S_IFMT != unix.S_IFREG:
		fi.Problem = helperproto.FileNotRegular
	case st.Nlink != 1:
		fi.Problem = helperproto.FileHardLinked
	case st.Size > helperproto.MaxCertFileSize:
		fi.Problem = helperproto.FileTooLarge
	}
	return fi
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
	case err != nil:
		return helperproto.NginxTestResponse{OK: true, Valid: false, Error: classifyNginxError(stderr)}, nil
	}
	return helperproto.NginxTestResponse{OK: true, Valid: true}, nil
}
