package linuxsshtest

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"path"
	"slices"
	"strings"

	"alice/internal/providers/haproxyconf"
	"alice/internal/providers/linuxssh/helperproto"
)

// This file ports cmd/alice-helper/haproxy.go to the emulated host, in the helper's call order:
// "haproxy -v", "haproxy -c", haproxy.cfg, Parse (reading the crt-lists and crt directories it
// names), then MarkWritable (when a file it read can be changed by a user other than root; nothing
// is opened) or ResolveKeys, then the describe loop. The real haproxyconf parser decides
// everything the helper's parser decides. The describe loop is the emulator's own, written to
// behave exactly as finishDump does. Not modelled: "-c" does not look at certificate files or
// server names, so a missing certificate is a "missing" place here, as it is for Apache.

var errHAProxyMissing = errors.New("haproxy is not installed")
var errHAProxyKilled = errors.New("haproxy timed out or was killed")

// haproxyParseError maps a haproxyconf error to its class and reason (the helper's).
func haproxyParseError(err error) *configError {
	switch {
	case errors.Is(err, haproxyconf.ErrTooLarge), errors.Is(err, haproxyconf.ErrLineTooLong):
		return unsupportedConf(helperproto.ConfigReasonTooLarge, "")
	case errors.Is(err, haproxyconf.ErrTooComplex), errors.Is(err, haproxyconf.ErrTooDeep):
		return unsupportedConf(helperproto.ConfigReasonTooComplex, "")
	case errors.Is(err, haproxyconf.ErrNUL):
		return unsupportedConf(helperproto.ConfigReasonNULByte, "")
	}
	return &configError{class: helperproto.ConfigErrSyntax}
}

// haproxyReader is the helper's haproxyReader on the emulated file table.
type haproxyReader struct {
	x           *haproxyHost
	h           *nginxHost
	total       int
	writable    []string
	cfgWritable bool
}

var errNamedByWritable = errors.New("named by a haproxy.cfg a user other than root can change")

func (r *haproxyReader) masked(e *configError) *configError {
	if len(r.writable) > 0 {
		return untrusted(helperproto.ConfigReasonChanged, r.writable[0])
	}
	return e
}

// readFile is the helper's readFile: haproxy.cfg or a crt-list through the root-controlled walk.
func (r *haproxyReader) readFile(p string) ([]byte, *configError) {
	if m := r.h.meta[p]; m != nil {
		switch m.problem {
		case helperproto.FileNotRootControlled:
			return nil, r.masked(untrusted(helperproto.ConfigReasonNotRootControlled, p))
		case helperproto.FileSpecialFS:
			return nil, r.masked(untrusted(helperproto.ConfigReasonSpecialFS, p))
		}
	}
	data, ok := r.x.confText(r.h, p)
	if !ok {
		return nil, r.masked(untrusted(helperproto.ConfigReasonMissing, p))
	}
	m := r.h.metaOf(p)
	if m.problem == helperproto.FileNotRegular {
		return nil, r.masked(untrusted(helperproto.ConfigReasonNotRegular, p))
	}
	if len(data) > min(haproxyconf.MaxInput, helperproto.MaxServerConfig-r.total) {
		return nil, r.masked(unsupportedConf(helperproto.ConfigReasonTooLarge, ""))
	}
	r.total += len(data)
	if m.owner != "root" || m.mode&0o022 != 0 {
		r.writable = append(r.writable, p)
	}
	return data, nil
}

// soft wraps the failure of a crt-list that is absent or not a regular file with ErrNotRead.
func (r *haproxyReader) soft(e *configError) error {
	if len(r.writable) == 0 && e.class == helperproto.ConfigErrUntrusted &&
		(e.reason == helperproto.ConfigReasonMissing || e.reason == helperproto.ConfigReasonNotRegular) {
		return fmt.Errorf("%w: %w", haproxyconf.ErrNotRead, e)
	}
	return e
}

func (r *haproxyReader) isWritable(p string) bool { return slices.Contains(r.writable, p) }

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

// readDir is the helper's readDir over listRootDir: the regular files directly in p. A directory
// that does not exist, or whose walk fails, is not a directory (listRootDir answers so).
func (r *haproxyReader) readDir(p string) ([]string, bool, error) {
	if r.cfgWritable {
		return nil, false, errNamedByWritable
	}
	if m := r.h.meta[p]; m != nil && (m.problem == helperproto.FileNotRootControlled || m.problem == helperproto.FileSpecialFS) {
		return nil, false, nil
	}
	prefix := strings.TrimSuffix(p, "/") + "/"
	isDir, scanned := false, 0
	var names []string
	for f := range r.h.content {
		rest, ok := strings.CutPrefix(f, prefix)
		if !ok {
			continue
		}
		isDir = true
		if strings.Contains(rest, "/") {
			continue
		}
		if scanned++; scanned > haproxyconf.MaxDirEntries {
			return nil, false, r.masked(unsupportedConf(helperproto.ConfigReasonTooComplex, ""))
		}
		if m := r.h.meta[f]; m == nil || m.problem != helperproto.FileNotRegular {
			names = append(names, rest)
		}
	}
	slices.Sort(names)
	for _, n := range names {
		if r.total += len(n); r.total > helperproto.MaxServerConfig {
			return nil, false, r.masked(unsupportedConf(helperproto.ConfigReasonTooLarge, ""))
		}
	}
	return names, isDir, nil
}

// keyInCert is the helper's keyInCert on the emulated file: a readable certificate name with a
// private key line.
func (h *nginxHost) keyInCert(p string) bool {
	if wp := h.walkProblem(p); wp != "" || !helperproto.ValidPath(h.resolvedOf(p)) || !certName(path.Base(p)) || h.fileProblem(p) != "" {
		return false
	}
	data, ok := h.fileLocked(p)
	if !ok || len(data) > helperproto.MaxCertFileSize {
		return false
	}
	return hasPrivateKeyLine(data)
}

var (
	pemBeginPrefix = []byte("-----BEGIN ")
	pemKeySuffix   = []byte("PRIVATE KEY-----")
)

// hasPrivateKeyLine is the helper's: a line "-----BEGIN [A-Z ]*PRIVATE KEY-----".
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

// confDirUnread is the helper's: conf.d holds a regular file named *.cfg.
func (h *nginxHost) confDirUnread() bool {
	for f := range h.content {
		if rest, ok := strings.CutPrefix(f, haproxyConfDir+"/"); ok && !strings.Contains(rest, "/") && strings.HasSuffix(rest, ".cfg") &&
			h.metaOf(f).problem != helperproto.FileNotRegular {
			return true
		}
	}
	return false
}

// haproxyConfig is the helper's haproxyConfig on the emulated host.
func (x *haproxyHost) haproxyConfig(h *nginxHost) (haproxyconf.Config, nginxMeta, error) {
	var meta nginxMeta
	invalid := func(e *configError) (haproxyconf.Config, nginxMeta, error) {
		meta.valid, meta.class, meta.reason, meta.file, meta.writable = false, e.class, e.reason, e.file, nil
		return haproxyconf.Config{}, meta, nil
	}
	if !x.installed {
		return haproxyconf.Config{}, meta, errHAProxyMissing
	}
	if x.killed {
		return haproxyconf.Config{}, meta, errHAProxyKilled
	}
	if meta.version = haproxyconf.ParseV([]byte(x.vOutput())); meta.version == "" {
		return haproxyconf.Config{}, meta, errHAProxyMissing
	}
	meta.confPath = haproxyConfPath
	if x.invalid {
		return invalid(&configError{class: helperproto.ConfigErrSyntax})
	}
	r := &haproxyReader{x: x, h: h}
	data, cerr := r.readFile(haproxyConfPath)
	if cerr != nil {
		return invalid(cerr)
	}
	r.cfgWritable = len(r.writable) > 0
	cfg, err := haproxyconf.Parse(haproxyconf.Input{Path: haproxyConfPath, Data: data, Version: meta.version,
		ReadFile: r.readList, ReadDir: r.readDir, Writable: r.cfgWritable, WritableFile: r.isWritable})
	if err != nil {
		var ce *configError
		switch {
		case errors.As(err, &ce):
			return invalid(r.masked(ce))
		case len(r.writable) > 0:
			return invalid(untrusted(helperproto.ConfigReasonChanged, r.writable[0]))
		}
		return invalid(haproxyParseError(err))
	}
	if len(r.writable) > 0 {
		haproxyconf.MarkWritable(&cfg)
	} else {
		asked := 0
		haproxyconf.ResolveKeys(&cfg, func(p string) bool {
			if asked++; asked > helperproto.MaxServerFiles {
				return false
			}
			return h.keyInCert(p)
		})
	}
	meta.valid, meta.writable = true, r.writable
	return cfg, meta, nil
}

func (e *Emulator) haproxyDump(args []string) Response {
	if len(args) != 0 {
		return refuse(helperproto.ExitRefused, helperproto.CodeUsage)
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	h := e.nginx()
	cfg, meta, err := e.haproxy().haproxyConfig(h)
	switch {
	case errors.Is(err, errHAProxyMissing):
		return refuse(helperproto.ExitPrecondition, helperproto.CodeSoftwareNotFound)
	case err != nil:
		return refuse(helperproto.ExitFailed, helperproto.CodeIOError)
	}
	resp := helperproto.ServerDumpResponse{OK: true, Version: meta.version, ConfPath: meta.confPath, ConfigValid: meta.valid,
		ConfigError: meta.class, ConfigErrorReason: meta.reason, ConfigErrorFile: meta.file, Servers: []helperproto.DumpServer{},
		Files: []helperproto.DumpFile{}, Warnings: []string{}, Writable: append([]string{}, meta.writable...)}
	if !meta.valid {
		return answer(resp)
	}
	resp.Warnings = append(resp.Warnings, cfg.Warnings...)
	for _, sv := range cfg.Servers {
		resp.Servers = append(resp.Servers, haproxyconf.ToWire(sv))
	}
	warn := func(code string) {
		if !slices.Contains(resp.Warnings, code) {
			resp.Warnings = append(resp.Warnings, code)
		}
	}
	if h.confDirUnread() {
		warn(helperproto.WarnConfigDirNotRead)
	}
	if len(resp.Writable) > 0 {
		warn(helperproto.WarnConfigFileWritable)
	}
	budget := h.dumpBudget
	if budget <= 0 {
		budget = helperproto.ServerDumpOutput
	}
	n, pemBytes := 0, 0
	for _, p := range cfg.CertPaths() {
		if n++; n > helperproto.MaxServerFiles {
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
		if n++; n > helperproto.MaxServerFiles {
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
