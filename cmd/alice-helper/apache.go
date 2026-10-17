//go:build linux

package main

import (
	"context"
	"errors"
	"io"
	"io/fs"
	"os"

	"golang.org/x/sys/unix"

	"alice/internal/providers/apacheconf"
	"alice/internal/providers/linuxssh/helperproto"
)

// The control programs of apache-dump (Ruling 5). Debian and Ubuntu: apache2ctl, which sources
// /etc/apache2/envvars and passes every argument to apache2. RHEL family: httpd itself, because
// its apachectl refuses extra arguments; /usr/sbin/apachectl is never run.
const (
	apache2ctlPath = "/usr/sbin/apache2ctl"
	httpdPath      = "/usr/sbin/httpd"
)

// apacheCtlPaths are the control programs in order of preference; tests point them elsewhere.
var apacheCtlPaths = []string{apache2ctlPath, httpdPath}

// apacheReadBudget bounds the bytes of all configuration files apache-dump reads together (each
// distinct file once); tests lower it.
var apacheReadBudget = helperproto.MaxServerConfig

var errApacheMissing = errors.New("apache is not installed")

// runApacheCtl runs the first control program of apacheCtlPaths that lstat finds, through
// runProgram (fixed environment, "/" as its directory, umask 022, 30 s, stdout capped at
// MaxServerConfig, stderr at 64 KiB). Neither present is an fs.ErrNotExist error.
func runApacheCtl(ctx context.Context, args ...string) ([]byte, []byte, error) {
	for _, p := range apacheCtlPaths {
		_, err := os.Lstat(p)
		switch {
		case errors.Is(err, fs.ErrNotExist):
			continue
		case err != nil:
			return nil, nil, err
		}
		return runProgram(ctx, p, helperproto.MaxServerConfig, args...)
	}
	return nil, nil, &fs.PathError{Op: "lstat", Path: apache2ctlPath, Err: fs.ErrNotExist}
}

// apacheParseError maps an apacheconf error to its class and reason (as parseError for nginx).
func apacheParseError(err error) *configError {
	switch {
	case errors.Is(err, apacheconf.ErrTooLarge), errors.Is(err, apacheconf.ErrLineTooLong):
		return unsupported(helperproto.ConfigReasonTooLarge, "")
	case errors.Is(err, apacheconf.ErrTooComplex), errors.Is(err, apacheconf.ErrTooDeep):
		return unsupported(helperproto.ConfigReasonTooComplex, "")
	case errors.Is(err, apacheconf.ErrNUL):
		return unsupported(helperproto.ConfigReasonNULByte, "")
	case errors.Is(err, apacheconf.ErrName):
		return unsupported(helperproto.ConfigReasonNameNotAllowed, "")
	case errors.Is(err, apacheconf.ErrIncludeMismatch):
		return untrusted(helperproto.ConfigReasonChanged, "")
	case errors.Is(err, apacheconf.ErrOutput):
		return untrusted(helperproto.ConfigReasonUnexpectedText, "")
	}
	return &configError{class: helperproto.ConfigErrSyntax}
}

// apacheRun runs one "-D DUMP_<what> -t" of the control program. A missing program is
// errApacheMissing and a killed or timed-out run its error (neither says anything about the
// configuration). Output over the cap is unsupported too_large, and a non-zero exit is an invalid
// configuration of class syntax (Ruling 5: for a later run, the configuration changed between
// the runs); stderr is never used.
func (s *sys) apacheRun(ctx context.Context, what string) ([]byte, *configError, error) {
	out, _, err := s.runApache(ctx, "-D", "DUMP_"+what, "-t")
	switch {
	case missingProgram(err):
		return nil, nil, errApacheMissing
	case errors.Is(err, errProgramKilled):
		return nil, nil, err
	case errors.Is(err, errTooLarge):
		return nil, unsupported(helperproto.ConfigReasonTooLarge, ""), nil
	case err != nil:
		return nil, &configError{class: helperproto.ConfigErrSyntax}, nil
	}
	return out, nil, nil
}

// apacheConfig runs the control program four times ("-V", then DUMP_INCLUDES, DUMP_MODULES and
// DUMP_RUN_CFG), reads every file of the include tree through walkRoot, and evaluates the
// configuration with apacheconf.Parse. An invalid, unsupported or untrusted configuration is not
// an error: meta.valid is false and the Config is empty, never partial. When any loaded file can
// be changed by a user other than root, every supported pair becomes config_file_writable
// (Ruling 7: Define and Include reach the whole configuration). Nothing is written.
func (s *sys) apacheConfig(ctx context.Context) (apacheconf.Config, dumpMeta, error) {
	var meta dumpMeta
	invalid := func(e *configError) (apacheconf.Config, dumpMeta, error) {
		meta.valid, meta.class, meta.reason, meta.file, meta.writable = false, e.class, e.reason, e.file, nil
		return apacheconf.Config{}, meta, nil
	}
	out, _, err := s.runApache(ctx, "-V")
	switch {
	case missingProgram(err):
		return apacheconf.Config{}, meta, errApacheMissing
	case err != nil:
		return apacheconf.Config{}, meta, err
	}
	meta.version, meta.confPath = apacheconf.ParseV(out)
	if meta.version == "" {
		return apacheconf.Config{}, meta, errApacheMissing // no "Server version: Apache/<v>": not Apache
	}

	// A failed run stops the dump: the later runs are not made (Ruling 5).
	var outs [3][]byte
	for i, what := range []string{"INCLUDES", "MODULES", "RUN_CFG"} {
		out, cerr, err := s.apacheRun(ctx, what)
		if err != nil {
			return apacheconf.Config{}, meta, err
		}
		if cerr != nil {
			return invalid(cerr)
		}
		outs[i] = out
	}
	tree, err := apacheconf.ParseIncludes(outs[0])
	if err != nil {
		return invalid(apacheParseError(err))
	}
	mods, err := apacheconf.ParseModules(outs[1])
	if err != nil {
		return invalid(apacheParseError(err))
	}
	run, err := apacheconf.ParseRunConfig(outs[2])
	if err != nil {
		return invalid(apacheParseError(err))
	}

	if meta.confPath == "" {
		// -V names no valid configuration file: the tree's root cannot be checked.
		return invalid(unsupported(helperproto.ConfigReasonNoConfPath, ""))
	}
	if tree[0].Path != meta.confPath {
		return invalid(untrusted(helperproto.ConfigReasonWrongFirstFile, tree[0].Path))
	}
	files, writable, cerr := s.readApacheFiles(tree)
	if cerr != nil {
		return invalid(cerr)
	}
	cfg, err := apacheconf.Parse(apacheconf.Input{Includes: tree, Files: files, Modules: mods, Run: run, Version: meta.version})
	if err != nil {
		if len(writable) > 0 {
			// As for a read failure after a writable file (readApacheFiles): the user's Include
			// could have brought in any root-only file, so the reason must not describe it.
			return invalid(untrusted(helperproto.ConfigReasonChanged, writable[0]))
		}
		return invalid(apacheParseError(err))
	}
	meta.valid, meta.writable = true, writable
	if len(writable) > 0 {
		apacheconf.MarkWritable(&cfg)
	}
	return cfg, meta, nil
}

// readApacheFiles reads every distinct file of the include tree, in tree order, through walkRoot
// (every directory and link root's, no link a user made is followed, no pseudo or FUSE file
// system), at most apacheReadBudget bytes together. It returns the contents by path and the files
// a user other than root can write (owner other than root, or writable by group or others). Once
// such a file has been read, any later failure reads "changed" naming it: that user's Include
// must not tell whether a root-only path exists or what it is.
func (s *sys) readApacheFiles(tree []apacheconf.Included) (map[string][]byte, []string, *configError) {
	files := make(map[string][]byte, len(tree))
	writable := []string{}
	masked := func(e *configError) *configError {
		if len(writable) > 0 {
			return untrusted(helperproto.ConfigReasonChanged, writable[0])
		}
		return e
	}
	total := 0
	for _, e := range tree {
		if _, done := files[e.Path]; done {
			continue // Apache reads a file listed twice twice; Parse gets its content once
		}
		data, st, cerr := s.readApacheFile(e.Path, apacheReadBudget-total)
		if cerr != nil {
			return nil, nil, masked(cerr)
		}
		total += len(data)
		files[e.Path] = data
		if int(st.Uid) != s.rootUID || st.Mode&0o022 != 0 {
			writable = append(writable, e.Path)
		}
	}
	return files, writable, nil
}

// readApacheFile reads one configuration file of at most room bytes. A file that changes size
// while it is read is untrusted "changed".
func (s *sys) readApacheFile(name string, room int) ([]byte, unix.Stat_t, *configError) {
	var st unix.Stat_t
	rf, err := s.walkRoot(name)
	if err != nil {
		return nil, st, untrusted(walkReason(err), name)
	}
	defer rf.close()
	f, st, err := rf.openLinked(true)
	if err != nil {
		return nil, st, untrusted(walkReason(err), name)
	}
	defer func() { _ = f.Close() }()
	if st.Size > int64(room) {
		return nil, st, unsupported(helperproto.ConfigReasonTooLarge, "")
	}
	// One buffer of the file's size plus one byte to see growth (no io.ReadAll doubling).
	buf := make([]byte, st.Size+1)
	n, err := io.ReadFull(f, buf)
	if (!errors.Is(err, io.ErrUnexpectedEOF) && !errors.Is(err, io.EOF)) || int64(n) != st.Size {
		return nil, st, untrusted(helperproto.ConfigReasonChanged, name) // a read error, or it changed size
	}
	return buf[:n], st, nil
}

// cmdApacheDump answers apache-dump: the TLS virtual hosts of the configuration Apache loads and
// the certificate and key files of their supported pairs, described as nginx-dump describes them.
// It takes no arguments and writes nothing.
func cmdApacheDump(ctx context.Context, s *sys, args []string) (any, error) {
	if len(args) != 0 {
		return nil, refused(helperproto.CodeUsage, "apache-dump takes no arguments")
	}
	s.syslog(helperproto.SubApacheDump, "")
	cfg, meta, err := s.apacheConfig(ctx)
	switch {
	case errors.Is(err, errApacheMissing):
		return nil, precondition(helperproto.CodeSoftwareNotFound, "Apache is not installed at /usr/sbin/apache2ctl or /usr/sbin/httpd")
	case err != nil:
		return nil, failed(helperproto.CodeIOError, "Apache could not be run to the end")
	}
	resp := helperproto.ServerDumpResponse{OK: true, Version: meta.version, ConfPath: meta.confPath, ConfigValid: meta.valid,
		ConfigError: meta.class, ConfigErrorReason: meta.reason, ConfigErrorFile: meta.file, Servers: []helperproto.DumpServer{}, Files: []helperproto.DumpFile{},
		Warnings: []string{}, Writable: append([]string{}, meta.writable...)}
	if !meta.valid {
		return resp, nil
	}
	for _, sv := range cfg.Servers {
		resp.Servers = append(resp.Servers, apacheconf.ToWire(sv))
	}
	return s.finishDump(resp, cfg.CertPaths(), cfg.KeyPaths())
}
