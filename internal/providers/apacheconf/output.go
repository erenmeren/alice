package apacheconf

import (
	"bytes"
	"fmt"
	"iter"
	"strings"

	"alice/internal/providers/linuxssh/helperproto"
)

// ParseV reads the version and the main configuration file from "-V". version is the <v> of the
// first "Server version: Apache/<v> (<os>)" line (the " (<os>)" part is optional), "" when it is
// longer than 40 characters or holds a character outside [A-Za-z0-9.+-]. confPath is
// -D SERVER_CONFIG_FILE, joined to -D HTTPD_ROOT when relative; it is "" unless the result is a
// valid helper path other than "/" (a relative or unclean root gives ""). Output with a CR, or
// larger than MaxInput, gives ("", ""). Only the lines it uses are copied.
func ParseV(out []byte) (version, confPath string) {
	if len(out) > MaxInput || bytes.IndexByte(out, '\r') >= 0 {
		return "", ""
	}
	var root, file string
	var seenVersion, seenRoot, seenFile bool
	for _, ln := range outputLines(out) {
		if v, ok := bytes.CutPrefix(ln, []byte("Server version: ")); ok {
			if !seenVersion {
				seenVersion = true
				if v, ok = bytes.CutPrefix(v, []byte("Apache/")); ok {
					v, _, _ = bytes.Cut(v, []byte(" ("))
					if validVersion(v) {
						version = string(v)
					}
				}
			}
			continue
		}
		if v, ok := compiledDefine(ln, "HTTPD_ROOT"); ok && !seenRoot {
			seenRoot, root = true, v
		}
		if v, ok := compiledDefine(ln, "SERVER_CONFIG_FILE"); ok && !seenFile {
			seenFile, file = true, v
		}
	}
	switch {
	case strings.HasPrefix(file, "/"):
		confPath = file
	case file != "" && root == "/":
		confPath = "/" + file
	case file != "" && helperproto.ValidPath(root):
		confPath = root + "/" + file
	}
	if !helperproto.ValidPath(confPath) || confPath == "/" {
		confPath = ""
	}
	return version, confPath
}

// compiledDefine reads a ` -D NAME="value"` line of "-V". A value longer than a helper path is
// returned as "" (it cannot be one).
func compiledDefine(ln []byte, name string) (string, bool) {
	v, ok := bytes.CutPrefix(ln, []byte(` -D `+name+`="`))
	if !ok {
		return "", false
	}
	if v, ok = bytes.CutSuffix(v, []byte(`"`)); !ok {
		return "", false
	}
	if len(v) > maxPath {
		return "", true
	}
	return string(v), true
}

// validVersion is nginx's version rule: 1 to 40 characters of [A-Za-z0-9.+-].
func validVersion(v []byte) bool {
	if len(v) == 0 || len(v) > 40 {
		return false
	}
	for i := 0; i < len(v); i++ {
		if c := v[i]; c != '.' && c != '-' && c != '+' && (c == '_' || !identByte(c)) {
			return false
		}
	}
	return true
}

// Included is one entry of the include tree. Parent is the index of the file whose Include or
// IncludeOptional directive loaded it (-1 for the root, the main configuration file), Line the
// line number of that directive in the parent (0 for the root; for a directive continued over
// several lines, Apache reports the last one).
type Included struct {
	Path   string
	Parent int
	Line   int
}

const includesHeader = "Included configuration files:"

// ParseIncludes reads "-D DUMP_INCLUDES -t": the header, then one line per file in read order,
// indented by 2+2k spaces at include depth k, "(*)" for the root (exactly once, first) or "(<n>)"
// for a file loaded at line n of its parent, one space and an absolute clean path. Depth grows by
// at most 1 per line; the parent is the nearest earlier entry one level up. A line exactly
// "Syntax OK" is skipped; anything else is ErrOutput, and more than MaxFiles entries is
// ErrTooComplex. A line that is well-formed but names a path the helper does not accept
// (helperproto.ValidPath: a space, a "." or ".." segment, over 4096 bytes) is ErrName: Apache
// can load such a file, the helper cannot read it. It stops at the first bad line and copies
// only the paths it returns.
func ParseIncludes(out []byte) ([]Included, error) {
	if err := checkOutput(out); err != nil {
		return nil, err
	}
	var (
		res    []Included
		last   []int // last[k]: index of the latest entry at depth k
		header bool
		total  int
	)
	for n, ln := range outputLines(out) {
		total = n
		if !header {
			if string(ln) != includesHeader {
				return nil, outputErr(n)
			}
			header = true
			continue
		}
		if string(ln) == "Syntax OK" {
			continue
		}
		indent := len(ln) - len(bytes.TrimLeft(ln, " "))
		if indent < 2 || indent%2 != 0 {
			return nil, outputErr(n)
		}
		depth := (indent - 2) / 2
		tag, path, ok := bytes.Cut(ln[indent:], []byte(" "))
		if !ok || len(path) == 0 || path[0] != '/' || bytes.IndexByte(path, 0) >= 0 {
			return nil, outputErr(n)
		}
		e := Included{Parent: -1}
		switch {
		case string(tag) == "(*)":
			if depth != 0 || len(res) != 0 {
				return nil, outputErr(n)
			}
		case depth == 0 || len(res) == 0 || depth > len(last):
			// a numbered entry at the root's level, before the root, or more than one level
			// below the previous entry
			return nil, outputErr(n)
		default:
			line, ok := includeLine(tag)
			if !ok {
				return nil, outputErr(n)
			}
			if depth > MaxDepth {
				return nil, ErrTooDeep
			}
			e.Parent, e.Line = last[depth-1], line
		}
		if len(path) > maxPath || !helperproto.ValidPath(string(path)) {
			return nil, fmt.Errorf("%w (line %d)", ErrName, n)
		}
		if len(res) >= MaxFiles {
			return nil, ErrTooComplex
		}
		e.Path = string(path)
		last = append(last[:depth], len(res))
		res = append(res, e)
	}
	if len(res) == 0 {
		return nil, outputErr(total + 1)
	}
	return res, nil
}

// includeLine reads "(<n>)": a positive decimal of at most 9 digits without a leading zero.
func includeLine(tag []byte) (int, bool) {
	s, ok := bytes.CutPrefix(tag, []byte("("))
	if !ok {
		return 0, false
	}
	if s, ok = bytes.CutSuffix(s, []byte(")")); !ok || len(s) == 0 || len(s) > 9 || s[0] == '0' {
		return 0, false
	}
	n := 0
	for _, c := range s {
		if c < '0' || c > '9' {
			return 0, false
		}
		n = n*10 + int(c-'0')
	}
	return n, true
}

// Modules is "-D DUMP_MODULES -t": Static holds the modules compiled in. The shared modules it lists
// are not kept: Parse follows LoadModule in read order from the static set (Ruling 8), so what
// Apache had loaded by the end of the configuration says nothing about an earlier <IfModule>.
type Modules struct {
	Static map[string]bool
}

// ParseModules reads "-D DUMP_MODULES -t": the header "Loaded Modules:", then one line
// " <name> (static)" or " <name> (shared)" per module. A name is 1 to 255 characters of
// [A-Za-z0-9_.-]. Anything else is ErrOutput; more than MaxModules module lines is ErrTooComplex.
func ParseModules(out []byte) (Modules, error) {
	if err := checkOutput(out); err != nil {
		return Modules{}, err
	}
	m := Modules{Static: map[string]bool{}}
	header := false
	for n, ln := range outputLines(out) {
		if !header {
			if string(ln) != "Loaded Modules:" {
				return Modules{}, outputErr(n)
			}
			header = true
			continue
		}
		if n-1 > MaxModules {
			return Modules{}, ErrTooComplex
		}
		rest, ok := bytes.CutPrefix(ln, []byte(" "))
		if !ok {
			return Modules{}, outputErr(n)
		}
		name, kind, _ := bytes.Cut(rest, []byte(" "))
		if !validModule(name) {
			return Modules{}, outputErr(n)
		}
		switch string(kind) {
		case "(static)":
			m.Static[string(name)] = true
		case "(shared)":
		default:
			return Modules{}, outputErr(n)
		}
	}
	if !header {
		return Modules{}, outputErr(1)
	}
	return m, nil
}

func validModule(name []byte) bool {
	if len(name) == 0 || len(name) > 255 {
		return false
	}
	for _, c := range name {
		if !identByte(c) && c != '.' && c != '-' {
			return false
		}
	}
	return true
}

// RunConfig is the part of "-D DUMP_RUN_CFG -t" the parser uses. ServerRoot is "" when the output
// names none. Defines holds the defines in effect after the configuration was read, without
// DUMP_RUN_CFG and the other DUMP_* defines of the dump runs.
type RunConfig struct {
	ServerRoot string
	Defines    map[string]string
}

// ParseRunConfig reads "-D DUMP_RUN_CFG -t": the line `ServerRoot: "<path>"` (at most once; the
// path must be a valid helper path once trailing slashes are removed) and the lines
// "Define: NAME" and "Define: NAME=VALUE" (NAME is not empty and has no white space; VALUE is the
// rest of the line). Every other line is ignored. More than MaxDefines Define lines is
// ErrTooComplex.
func ParseRunConfig(out []byte) (RunConfig, error) {
	if err := checkOutput(out); err != nil {
		return RunConfig{}, err
	}
	rc := RunConfig{Defines: map[string]string{}}
	seenRoot := false
	defines := 0
	for n, ln := range outputLines(out) {
		if v, ok := bytes.CutPrefix(ln, []byte("ServerRoot: ")); ok {
			root, ok := bytes.CutPrefix(v, []byte(`"`))
			if ok {
				root, ok = bytes.CutSuffix(root, []byte(`"`))
			}
			if trimmed := bytes.TrimRight(root, "/"); len(trimmed) > 0 {
				root = trimmed
			} else if len(root) > 0 {
				root = []byte("/")
			}
			if seenRoot || !ok || len(root) > maxPath || !helperproto.ValidPath(string(root)) {
				return RunConfig{}, outputErr(n)
			}
			seenRoot, rc.ServerRoot = true, string(root)
			continue
		}
		if v, ok := bytes.CutPrefix(ln, []byte("Define: ")); ok {
			if defines++; defines > MaxDefines {
				return RunConfig{}, ErrTooComplex
			}
			name, value, _ := bytes.Cut(v, []byte("="))
			if len(name) == 0 || bytes.ContainsAny(name, " \t\v\f") {
				return RunConfig{}, outputErr(n)
			}
			if !bytes.HasPrefix(name, []byte("DUMP_")) {
				rc.Defines[string(name)] = string(value)
			}
		}
	}
	return rc, nil
}

// moduleFiles maps the source file names of the core and MPM modules, which do not follow the
// mod_<x>.c pattern, to their module names.
var moduleFiles = map[string]string{
	"core.c":      "core_module",
	"http_core.c": "http_module",
	"prefork.c":   "mpm_prefork_module",
	"worker.c":    "mpm_worker_module",
	"event.c":     "mpm_event_module",
}

// ModuleName maps an <IfModule> argument (without "!") to the module name DUMP_MODULES and
// LoadModule use: "<x>_module" is kept, "mod_<x>.c" becomes "<x>_module", and the core and MPM
// source names come from a fixed table. x is one or more of [A-Za-z0-9_]; matching is
// case-sensitive, as in Apache. Any other argument gives ("", false).
func ModuleName(arg string) (string, bool) {
	if m, ok := moduleFiles[arg]; ok {
		return m, true
	}
	if x, ok := strings.CutSuffix(arg, "_module"); ok && ident(x) {
		return arg, true
	}
	if x, ok := strings.CutPrefix(arg, "mod_"); ok {
		if x, ok = strings.CutSuffix(x, ".c"); ok && ident(x) {
			return x + "_module", true
		}
	}
	return "", false
}

func ident(s string) bool {
	if s == "" {
		return false
	}
	for i := 0; i < len(s); i++ {
		if !identByte(s[i]) {
			return false
		}
	}
	return true
}

func identByte(c byte) bool {
	return c >= '0' && c <= '9' || c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c == '_'
}

// outputLines yields the lines of tool output (numbered from 1, without the "\n") as sub-slices
// of out, without copying; a final newline does not start an empty line.
func outputLines(out []byte) iter.Seq2[int, []byte] {
	return func(yield func(int, []byte) bool) {
		for n, pos := 1, 0; pos < len(out); n++ {
			ln := out[pos:]
			if end := bytes.IndexByte(ln, '\n'); end >= 0 {
				ln = ln[:end]
			}
			pos += len(ln) + 1
			if !yield(n, ln) {
				return
			}
		}
	}
}

// checkOutput refuses tool output larger than MaxInput, and output with a CR: Apache writes LF
// line ends only.
func checkOutput(out []byte) error {
	if len(out) > MaxInput {
		return ErrTooLarge
	}
	if i := bytes.IndexByte(out, '\r'); i >= 0 {
		return outputErr(bytes.Count(out[:i], []byte("\n")) + 1)
	}
	return nil
}

func outputErr(line int) error { return fmt.Errorf("%w (line %d)", ErrOutput, line) }
