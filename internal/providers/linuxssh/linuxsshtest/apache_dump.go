package linuxsshtest

import (
	"encoding/json"
	"errors"
	"slices"

	"alice/internal/providers/apacheconf"
	"alice/internal/providers/linuxssh/helperproto"
)

// This file ports cmd/alice-helper/apache.go to the emulated host. The control program's output
// is rendered from the state (apache.go) and the real apacheconf parser decides everything the
// helper's parser decides. The describe loop is the emulator's own (the helper's finishDump is
// not shared with it), written to behave exactly as finishDump does.

var errApacheMissing = errors.New("apache is not installed")
var errApacheKilled = errors.New("apache timed out or was killed")

// apacheParseError maps an apacheconf error to its class and reason (the helper's apacheParseError).
func apacheParseError(err error) *configError {
	switch {
	case errors.Is(err, apacheconf.ErrTooLarge), errors.Is(err, apacheconf.ErrLineTooLong):
		return unsupportedConf(helperproto.ConfigReasonTooLarge, "")
	case errors.Is(err, apacheconf.ErrTooComplex), errors.Is(err, apacheconf.ErrTooDeep):
		return unsupportedConf(helperproto.ConfigReasonTooComplex, "")
	case errors.Is(err, apacheconf.ErrNUL):
		return unsupportedConf(helperproto.ConfigReasonNULByte, "")
	case errors.Is(err, apacheconf.ErrName):
		return unsupportedConf(helperproto.ConfigReasonNameNotAllowed, "")
	case errors.Is(err, apacheconf.ErrIncludeMismatch):
		return untrusted(helperproto.ConfigReasonChanged, "")
	case errors.Is(err, apacheconf.ErrOutput):
		return untrusted(helperproto.ConfigReasonUnexpectedText, "")
	}
	return &configError{class: helperproto.ConfigErrSyntax}
}

// apacheConfig is the helper's apacheConfig on the emulated host.
func (a *apacheHost) apacheConfig(h *nginxHost) (apacheconf.Config, nginxMeta, error) {
	var meta nginxMeta
	invalid := func(e *configError) (apacheconf.Config, nginxMeta, error) {
		meta.valid, meta.class, meta.reason, meta.file, meta.writable = false, e.class, e.reason, e.file, nil
		return apacheconf.Config{}, meta, nil
	}
	if !a.installed {
		return apacheconf.Config{}, meta, errApacheMissing
	}
	if a.killed {
		return apacheconf.Config{}, meta, errApacheKilled
	}
	meta.version, meta.confPath = apacheconf.ParseV([]byte(a.vOutput()))
	if meta.version == "" {
		return apacheconf.Config{}, meta, errApacheMissing
	}
	if a.invalid {
		return invalid(&configError{class: helperproto.ConfigErrSyntax})
	}
	tree, err := apacheconf.ParseIncludes([]byte(a.includesOutput()))
	if err != nil {
		return invalid(apacheParseError(err))
	}
	mods, err := apacheconf.ParseModules([]byte(apacheModulesOutput))
	if err != nil {
		return invalid(apacheParseError(err))
	}
	run, err := apacheconf.ParseRunConfig([]byte(apacheRunCfgOutput))
	if err != nil {
		return invalid(apacheParseError(err))
	}
	if meta.confPath == "" {
		return invalid(unsupportedConf(helperproto.ConfigReasonNoConfPath, ""))
	}
	if tree[0].Path != meta.confPath {
		return invalid(untrusted(helperproto.ConfigReasonWrongFirstFile, tree[0].Path))
	}
	files, writable, cerr := a.readFiles(h, tree)
	if cerr != nil {
		return invalid(cerr)
	}
	cfg, err := apacheconf.Parse(apacheconf.Input{Includes: tree, Files: files, Modules: mods, Run: run, Version: meta.version})
	if err != nil {
		if len(writable) > 0 {
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

// readFiles is the helper's readApacheFiles: every distinct file of the tree through the
// root-controlled walk; a file another user can write is listed, and any later failure reads
// "changed" naming the first one.
func (a *apacheHost) readFiles(h *nginxHost, tree []apacheconf.Included) (map[string][]byte, []string, *configError) {
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
			continue
		}
		m := h.meta[e.Path]
		if m != nil {
			switch m.problem {
			case helperproto.FileNotRootControlled:
				return nil, nil, masked(untrusted(helperproto.ConfigReasonNotRootControlled, e.Path))
			case helperproto.FileSpecialFS:
				return nil, nil, masked(untrusted(helperproto.ConfigReasonSpecialFS, e.Path))
			}
		}
		data, ok := a.confText(h, e.Path)
		if !ok {
			return nil, nil, masked(untrusted(helperproto.ConfigReasonMissing, e.Path))
		}
		if m = h.metaOf(e.Path); m.problem == helperproto.FileNotRegular {
			return nil, nil, masked(untrusted(helperproto.ConfigReasonNotRegular, e.Path))
		}
		if len(data) > helperproto.MaxServerConfig-total {
			return nil, nil, masked(unsupportedConf(helperproto.ConfigReasonTooLarge, ""))
		}
		total += len(data)
		files[e.Path] = data
		if m.owner != "root" || m.mode&0o022 != 0 {
			writable = append(writable, e.Path)
		}
	}
	return files, writable, nil
}

func (e *Emulator) apacheDump(args []string) Response {
	if len(args) != 0 {
		return refuse(helperproto.ExitRefused, helperproto.CodeUsage)
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	h := e.nginx()
	cfg, meta, err := e.apache().apacheConfig(h)
	switch {
	case errors.Is(err, errApacheMissing):
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
	warn := func(code string) {
		if !slices.Contains(resp.Warnings, code) {
			resp.Warnings = append(resp.Warnings, code)
		}
	}
	if len(resp.Writable) > 0 {
		warn(helperproto.WarnConfigFileWritable)
	}
	for _, sv := range cfg.Servers {
		resp.Servers = append(resp.Servers, apacheconf.ToWire(sv))
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
