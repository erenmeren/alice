//go:build linux

package main

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"slices"
	"strings"

	"golang.org/x/sys/unix"

	"alice/internal/providers/haproxyconf"
	"alice/internal/providers/linuxssh/helperproto"
)

// The fixed paths of haproxy-dump (Ruling 2; the program is haproxyPath). The helper never reads
// /etc/default/haproxy, /etc/sysconfig/haproxy or the systemd unit, and never reads conf.d: it
// only says when conf.d may hold configuration (config_dir_not_read, C14).
const (
	haproxyConfPath = "/etc/haproxy/haproxy.cfg"
	haproxyConfDir  = "/etc/haproxy/conf.d"
)

// haproxyReadBudget bounds the bytes haproxy-dump reads together: haproxy.cfg, each distinct
// crt-list once, and the names of the crt directories it lists (Ruling 4); tests lower it.
var haproxyReadBudget = helperproto.MaxServerConfig

var errHAProxyMissing = errors.New("haproxy is not installed")

// haproxyParseError maps a haproxyconf error to its class and reason (as apacheParseError).
func haproxyParseError(err error) *configError {
	switch {
	case errors.Is(err, haproxyconf.ErrTooLarge), errors.Is(err, haproxyconf.ErrLineTooLong):
		return unsupported(helperproto.ConfigReasonTooLarge, "")
	case errors.Is(err, haproxyconf.ErrTooComplex), errors.Is(err, haproxyconf.ErrTooDeep):
		return unsupported(helperproto.ConfigReasonTooComplex, "")
	case errors.Is(err, haproxyconf.ErrNUL):
		return unsupported(helperproto.ConfigReasonNULByte, "")
	}
	return &configError{class: helperproto.ConfigErrSyntax}
}

// haproxyValid reports whether "haproxy -c" accepted the configuration: exit 0, or exit 2
// ("Configuration file has no error but will not start (no listener)", D3).
func haproxyValid(err error) bool {
	var exit interface{ ExitCode() int }
	return err == nil || (errors.As(err, &exit) && exit.ExitCode() == 2)
}

// haproxyConfig runs "haproxy -v", reads haproxy.cfg, runs "haproxy -c -f /etc/haproxy/haproxy.cfg"
// (Ruling 3) unless haproxy.cfg can be changed by a user other than root (final review M4), then
// reads its crt-lists and its crt directories (Ruling 4) and evaluates them with
// haproxyconf.Parse, then ResolveKeys. An invalid, unsupported or untrusted configuration is not an
// error: meta.valid is false and the Config is empty, never partial; after an invalid "-c" nothing
// more is read. When haproxy.cfg can be changed by a user other than root, "-c" is not run and
// nothing it names is read, listed or opened (review I1: Input.Writable). When it or a read crt-list can, every pair becomes
// config_file_writable (MarkWritable, instead of ResolveKeys: no certificate file is opened) and
// every later failure reads "changed" naming that file; the entries of a writable crt-list are
// not looked at (re-review R1). A crt-list that cannot be read is an untrusted configuration,
// unless it is absent or not a regular file and every naming of it lies in an uncertain region
// (review I2: a conditional pair and config_file_not_read). Nothing is written.
func (s *sys) haproxyConfig(ctx context.Context) (haproxyconf.Config, dumpMeta, error) {
	var meta dumpMeta
	invalid := func(e *configError) (haproxyconf.Config, dumpMeta, error) {
		meta.valid, meta.class, meta.reason, meta.file, meta.writable = false, e.class, e.reason, e.file, nil
		return haproxyconf.Config{}, meta, nil
	}
	var pe *programError
	out, _, err := s.runHAProxy(ctx, "-v")
	switch {
	case errors.As(err, &pe):
		return invalid(untrusted(helperproto.ConfigReasonNotRootControlled, pe.path))
	case missingProgram(err):
		return haproxyconf.Config{}, meta, errHAProxyMissing
	case err != nil:
		return haproxyconf.Config{}, meta, err
	}
	if meta.version = haproxyconf.ParseV(out); meta.version == "" {
		return haproxyconf.Config{}, meta, errHAProxyMissing // no "HAProxy version <v>": not HAProxy
	}
	meta.confPath = haproxyConfPath

	// Final review M4: haproxy.cfg is read (and its owner and mode checked) before "-c". One that
	// cannot be read safely is reported as such, and "-c" is not run on it.
	r := &haproxyReader{s: s}
	data, cerr := r.readFile(haproxyConfPath)
	if cerr != nil {
		return invalid(cerr)
	}
	// Review I1: a haproxy.cfg a user other than root can change makes the helper read nothing
	// beyond it (no crt-list, no listing, no certificate): Parse gets Writable and turns every
	// crt and crt-list argument into a config_file_writable pair of the text as written.
	r.cfgWritable = len(r.writable) > 0
	if !r.cfgWritable {
		// Final review M4: "-c" is never run on a haproxy.cfg a user other than root can change.
		// It would load, as root and when Alice chooses, every file that user names (and run its
		// lua-load), and its verdict would tell that user whether a root-only path is a loadable
		// certificate (KI-41). Such a configuration's answer is its config_file_writable pairs.
		// stderr is never used: it names files and may quote configuration.
		_, _, err = s.runHAProxy(ctx, "-c", "-f", haproxyConfPath)
		switch {
		case errors.As(err, &pe):
			return invalid(untrusted(helperproto.ConfigReasonNotRootControlled, pe.path))
		case missingProgram(err):
			return haproxyconf.Config{}, meta, errHAProxyMissing
		case errors.Is(err, errProgramKilled):
			return haproxyconf.Config{}, meta, err // says nothing about the configuration
		case errors.Is(err, errTooLarge):
			return invalid(unsupported(helperproto.ConfigReasonTooLarge, ""))
		case !haproxyValid(err):
			return invalid(&configError{class: helperproto.ConfigErrSyntax})
		}
	}
	cfg, err := haproxyconf.Parse(haproxyconf.Input{Path: haproxyConfPath, Data: data, Version: meta.version,
		ReadFile: r.readList, ReadDir: r.readDir, Writable: r.cfgWritable, WritableFile: r.isWritable})
	if err != nil {
		var ce *configError
		switch {
		case errors.As(err, &ce):
			// A read failure, masked when it happened; masked again here for one Parse cached
			// before a writable file was read (re-review R3).
			return invalid(r.masked(ce))
		case len(r.writable) > 0:
			// As for a read failure after a writable file: the user's configuration could have
			// named any root-only file, so the reason must not describe it.
			return invalid(untrusted(helperproto.ConfigReasonChanged, r.writable[0]))
		}
		return invalid(haproxyParseError(err))
	}
	if len(r.writable) > 0 {
		// A user other than root can change the configuration: every pair is config_file_writable
		// and no certificate file it names is opened, not even to resolve a key (keyInCert would
		// tell that user whether a root-only file holds a private key). MarkWritable clears the
		// pending pairs, so they carry no key path; ResolveKeys is not called.
		haproxyconf.MarkWritable(&cfg)
	} else {
		// Until ResolveKeys runs no pair is supported (haproxyconf's pending pairs). It asks once
		// per distinct certificate; past MaxServerFiles (what finishDump describes) nothing is
		// read (review M2) and the answer is KeyUnknown, so that pair stays conditional rather
		// than given a guessed companion key (final review M1).
		asked := 0
		haproxyconf.ResolveKeys(&cfg, func(p string) haproxyconf.KeyAnswer {
			if asked++; asked > helperproto.MaxServerFiles {
				return haproxyconf.KeyUnknown
			}
			if s.keyInCert(p) {
				return haproxyconf.KeyInCert
			}
			return haproxyconf.KeyNotInCert
		})
	}
	meta.valid, meta.writable = true, r.writable
	return cfg, meta, nil
}

// haproxyReader reads the files haproxyconf.Parse asks for, within haproxyReadBudget together,
// and records the ones a user other than root can write (owner other than root, or writable by
// group or others). Once such a file has been read, any later failure reads "changed" naming it
// (Apache's masking): that user's configuration must not tell whether a root-only path exists or
// what it is.
type haproxyReader struct {
	s        *sys
	total    int
	writable []string
	// cfgWritable: haproxy.cfg itself is writable, so nothing it names is read (review I1;
	// Parse does not ask, and readList and readDir refuse if it did).
	cfgWritable bool
}

// errNamedByWritable refuses a read named by a writable haproxy.cfg (never reached: Parse does not
// ask when Input.Writable is set).
var errNamedByWritable = errors.New("named by a haproxy.cfg a user other than root can change")

// soft wraps the failure of a crt-list that is absent or not a regular file with
// haproxyconf.ErrNotRead, so that Parse makes a naming in an uncertain region one conditional
// pair (review I2). Every other failure stays hard (re-review R2): a file that is not
// root-controlled (a list in /tmp) may be loaded with certificates another user chose if HAProxy
// takes that region, and must read untrusted; so do masked failures ("changed" after a writable
// file) and bounds.
func (r *haproxyReader) soft(e *configError) error {
	if len(r.writable) == 0 && e.class == helperproto.ConfigErrUntrusted &&
		(e.reason == helperproto.ConfigReasonMissing || e.reason == helperproto.ConfigReasonNotRegular) {
		return fmt.Errorf("%w: %w", haproxyconf.ErrNotRead, e)
	}
	return e
}

// isWritable is Parse's WritableFile: a crt-list readList read that a user other than root can
// change (re-review R1).
func (r *haproxyReader) isWritable(p string) bool { return slices.Contains(r.writable, p) }

// readList is Parse's ReadFile: a crt-list through readFile.
func (r *haproxyReader) readList(p string) ([]byte, error) {
	if r.cfgWritable {
		return nil, errNamedByWritable
	}
	b, cerr := r.readFile(p)
	if cerr != nil {
		return nil, r.soft(cerr)
	}
	return b, nil
}

func (r *haproxyReader) masked(e *configError) *configError {
	if len(r.writable) > 0 {
		return untrusted(helperproto.ConfigReasonChanged, r.writable[0])
	}
	return e
}

// readFile reads haproxy.cfg or a crt-list through walkRoot (readConfigFile), at most
// haproxyconf.MaxInput bytes.
func (r *haproxyReader) readFile(p string) ([]byte, *configError) {
	b, st, cerr := r.s.readConfigFile(p, min(haproxyconf.MaxInput, haproxyReadBudget-r.total))
	if cerr != nil {
		return nil, r.masked(cerr)
	}
	r.total += len(b)
	if r.s.userWritable(st) {
		r.writable = append(r.writable, p)
	}
	return b, nil
}

// readDir is Parse's ReadDir: listRootDir, with the names of all listings counted in the read
// budget (Task 5 carry: 256 directories of 4096 long names must not reach Parse). A directory that
// walked but cannot be listed is untrusted "changed" naming it (review M3: a read error, as
// readConfigFile names one); too many entries is unsupported too_complex.
func (r *haproxyReader) readDir(p string) ([]string, bool, error) {
	if r.cfgWritable {
		return nil, false, errNamedByWritable
	}
	names, isDir, err := r.s.listRootDir(p)
	switch {
	case errors.Is(err, errTooManyEntries), errors.Is(err, errTooManyDirLinks):
		return nil, false, r.masked(unsupported(helperproto.ConfigReasonTooComplex, ""))
	case err != nil:
		return nil, false, r.masked(untrusted(helperproto.ConfigReasonChanged, p))
	}
	for _, n := range names {
		if r.total += len(n); r.total > haproxyReadBudget {
			return nil, false, r.masked(unsupported(helperproto.ConfigReasonTooLarge, ""))
		}
	}
	return names, isDir, nil
}

// keyInCert reports whether the certificate file p holds a private key (Ruling 12): HAProxy then
// takes the key from it and never looks for a companion file. The file is read with describeCert's
// rules (resolveRoot, a helper path, a certificate name, one link, at most MaxCertFileSize); a file
// that cannot be read so answers false. Only the answer leaves: the buffer is cleared.
func (s *sys) keyInCert(p string) bool {
	rf, err := s.resolveRoot(p)
	if err != nil {
		return false
	}
	defer rf.close()
	if !helperproto.ValidPath(rf.resolved) || !certName(rf.name) {
		return false
	}
	f, st, err := rf.open()
	if err != nil {
		return false
	}
	defer func() { _ = f.Close() }()
	if st.Size > helperproto.MaxCertFileSize {
		return false
	}
	buf := make([]byte, st.Size+1)
	defer clear(buf)
	n, err := io.ReadFull(f, buf)
	if !errors.Is(err, io.ErrUnexpectedEOF) && !errors.Is(err, io.EOF) {
		return false // a read error, or the file grew since fstat
	}
	return hasPrivateKeyLine(buf[:n])
}

var (
	pemBeginPrefix = []byte("-----BEGIN ")
	pemKeySuffix   = []byte("PRIVATE KEY-----")
)

// hasPrivateKeyLine reports whether a line of data is "-----BEGIN [A-Z ]*PRIVATE KEY-----" (a line
// may end in CR LF): PRIVATE KEY, RSA PRIVATE KEY, EC PRIVATE KEY, ENCRYPTED PRIVATE KEY.
func hasPrivateKeyLine(data []byte) bool {
	for len(data) > 0 {
		line := data
		if i := bytes.IndexByte(data, '\n'); i >= 0 {
			line, data = data[:i], data[i+1:]
		} else {
			data = nil
		}
		line = bytes.TrimSuffix(line, []byte("\r"))
		if len(line) < len(pemBeginPrefix)+len(pemKeySuffix) || !bytes.HasPrefix(line, pemBeginPrefix) || !bytes.HasSuffix(line, pemKeySuffix) {
			continue
		}
		mid := line[len(pemBeginPrefix) : len(line)-len(pemKeySuffix)]
		if !bytes.ContainsFunc(mid, func(r rune) bool { return (r < 'A' || r > 'Z') && r != ' ' }) {
			return true
		}
	}
	return false
}

// confDirUnread reports whether /etc/haproxy/conf.d may hold configuration haproxy-dump does not
// read (Ruling 2, C14: Rocky 9's unit loads it). It is false only when conf.d is absent, is not a
// directory, or is a directory that can be listed safely (openRootDir) and holds no regular entry
// (or link HAProxy may load, linkLoadable) named *.cfg. A conf.d that exists but cannot be listed safely (not root's,
// writable by group or others, on a pseudo file system, too many entries) is true: an empty page
// must never stand without a reason.
func (s *sys) confDirUnread() bool {
	fd, resolved, err := s.openRootDir(haproxyConfDir)
	switch {
	case errors.Is(err, unix.ENOENT), errors.Is(err, unix.ENOTDIR), errors.Is(err, errNotDirectory):
		return false
	case err != nil:
		return true
	}
	defer func() { _ = unix.Close(fd) }()
	names, err := s.rootDirNames(fd, resolved)
	if err != nil {
		return true
	}
	return slices.ContainsFunc(names, func(n string) bool { return strings.HasSuffix(n, ".cfg") })
}

// cmdHAProxyDump answers haproxy-dump: the TLS binds of the frontends and listens of
// /etc/haproxy/haproxy.cfg and the certificate and key files of their supported pairs, described
// as nginx-dump describes them. It takes no arguments and writes nothing.
func cmdHAProxyDump(ctx context.Context, s *sys, args []string) (any, error) {
	if len(args) != 0 {
		return nil, refused(helperproto.CodeUsage, "haproxy-dump takes no arguments")
	}
	s.syslog(helperproto.SubHAProxyDump, "")
	s.dirLinks = 0 // maxDirLinks is per dump
	cfg, meta, err := s.haproxyConfig(ctx)
	switch {
	case errors.Is(err, errHAProxyMissing):
		return nil, precondition(helperproto.CodeSoftwareNotFound, "HAProxy is not installed at /usr/sbin/haproxy")
	case err != nil:
		return nil, failed(helperproto.CodeIOError, "HAProxy could not be run to the end")
	}
	resp := helperproto.ServerDumpResponse{OK: true, Version: meta.version, ConfPath: meta.confPath, ConfigValid: meta.valid,
		ConfigError: meta.class, ConfigErrorReason: meta.reason, ConfigErrorFile: meta.file, Servers: []helperproto.DumpServer{}, Files: []helperproto.DumpFile{},
		Warnings: []string{}, Writable: append([]string{}, meta.writable...)}
	if !meta.valid {
		return resp, nil
	}
	resp.Warnings = append(resp.Warnings, cfg.Warnings...)
	certs, keys := cfg.CertPaths(), cfg.KeyPaths()
	resp.Servers = make([]helperproto.DumpServer, 0, len(cfg.Servers))
	for _, sv := range cfg.Servers {
		resp.Servers = append(resp.Servers, haproxyconf.ToWire(sv))
	}
	cfg = haproxyconf.Config{} // Parse's servers are not needed any more: the collector may take them
	if s.confDirUnread() {
		resp.Warnings = append(resp.Warnings, helperproto.WarnConfigDirNotRead)
	}
	return s.finishDump(resp, certs, keys)
}
