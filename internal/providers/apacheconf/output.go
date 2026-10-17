package apacheconf

import (
	"fmt"
	"strconv"
	"strings"

	"alice/internal/providers/linuxssh/helperproto"
)

// ParseV reads the version and the main configuration file from "-V". version is the <v> of the
// first "Server version: Apache/<v> (<os>)" line (the " (<os>)" part is optional), "" when it is
// longer than 40 characters or holds a character outside [A-Za-z0-9.+-]. confPath is
// -D SERVER_CONFIG_FILE, joined to -D HTTPD_ROOT when relative; it is "" unless the result is a
// valid helper path other than "/" (a relative or unclean root gives "").
func ParseV(out []byte) (version, confPath string) {
	var root, file string
	var seenVersion, seenRoot, seenFile bool
	for _, ln := range strings.Split(string(out), "\n") {
		ln = strings.TrimSuffix(ln, "\r")
		if v, ok := strings.CutPrefix(ln, "Server version: "); ok {
			if !seenVersion {
				seenVersion = true
				if v, ok = strings.CutPrefix(v, "Apache/"); ok {
					v, _, _ = strings.Cut(v, " (")
					version = v
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
	if !validVersion(version) {
		version = ""
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

// compiledDefine reads a ` -D NAME="value"` line of "-V".
func compiledDefine(ln, name string) (string, bool) {
	v, ok := strings.CutPrefix(ln, ` -D `+name+`="`)
	if !ok {
		return "", false
	}
	return strings.CutSuffix(v, `"`)
}

// validVersion is nginx's version rule: 1 to 40 characters of [A-Za-z0-9.+-].
func validVersion(v string) bool {
	if v == "" || len(v) > 40 {
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
// "Syntax OK" is skipped; anything else is ErrOutput.
func ParseIncludes(out []byte) ([]Included, error) {
	if len(out) > MaxInput {
		return nil, ErrTooLarge
	}
	lines := outputLines(out)
	if len(lines) == 0 || lines[0] != includesHeader {
		return nil, outputErr(1)
	}
	var (
		res  []Included
		last []int // last[k]: index of the latest entry at depth k
	)
	for n, ln := range lines[1:] {
		if ln == "Syntax OK" {
			continue
		}
		indent := len(ln) - len(strings.TrimLeft(ln, " "))
		if indent < 2 || indent%2 != 0 {
			return nil, outputErr(n + 2)
		}
		depth := (indent - 2) / 2
		tag, path, ok := strings.Cut(ln[indent:], " ")
		if !ok || !helperproto.ValidPath(path) {
			return nil, outputErr(n + 2)
		}
		e := Included{Path: path, Parent: -1}
		switch {
		case tag == "(*)":
			if depth != 0 || len(res) != 0 {
				return nil, outputErr(n + 2)
			}
		case depth == 0 || len(res) == 0 || depth > len(last):
			// a numbered entry at the root's level, before the root, or more than one level
			// below the previous entry
			return nil, outputErr(n + 2)
		default:
			line, ok := includeLine(tag)
			if !ok {
				return nil, outputErr(n + 2)
			}
			if depth > MaxDepth {
				return nil, ErrTooDeep
			}
			e.Parent, e.Line = last[depth-1], line
		}
		if len(res) >= MaxFiles {
			return nil, ErrTooComplex
		}
		last = append(last[:depth], len(res))
		res = append(res, e)
	}
	if len(res) == 0 {
		return nil, outputErr(len(lines))
	}
	return res, nil
}

// includeLine reads "(<n>)": a positive decimal of at most 9 digits without a leading zero.
func includeLine(tag string) (int, bool) {
	s, ok := strings.CutPrefix(tag, "(")
	if !ok {
		return 0, false
	}
	if s, ok = strings.CutSuffix(s, ")"); !ok || s == "" || len(s) > 9 || s[0] == '0' {
		return 0, false
	}
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return 0, false
		}
	}
	n, err := strconv.Atoi(s)
	return n, err == nil
}

// Modules is "-D DUMP_MODULES -t": Static holds the modules compiled in, Loaded every module
// (compiled in and loaded with LoadModule).
type Modules struct {
	Static, Loaded map[string]bool
}

// ParseModules reads "-D DUMP_MODULES -t": the header "Loaded Modules:", then one line
// " <name> (static)" or " <name> (shared)" per module. A name is 1 to 255 characters of
// [A-Za-z0-9_.-]. Anything else is ErrOutput.
func ParseModules(out []byte) (Modules, error) {
	m := Modules{Static: map[string]bool{}, Loaded: map[string]bool{}}
	if len(out) > MaxInput {
		return Modules{}, ErrTooLarge
	}
	lines := outputLines(out)
	if len(lines) == 0 || lines[0] != "Loaded Modules:" {
		return Modules{}, outputErr(1)
	}
	for n, ln := range lines[1:] {
		rest, ok := strings.CutPrefix(ln, " ")
		if !ok {
			return Modules{}, outputErr(n + 2)
		}
		name, kind, _ := strings.Cut(rest, " ")
		if !validModule(name) {
			return Modules{}, outputErr(n + 2)
		}
		switch kind {
		case "(static)":
			m.Static[name] = true
		case "(shared)":
		default:
			return Modules{}, outputErr(n + 2)
		}
		m.Loaded[name] = true
	}
	return m, nil
}

func validModule(name string) bool {
	if name == "" || len(name) > 255 {
		return false
	}
	for i := 0; i < len(name); i++ {
		if c := name[i]; !identByte(c) && c != '.' && c != '-' {
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
// rest of the line). Every other line is ignored.
func ParseRunConfig(out []byte) (RunConfig, error) {
	if len(out) > MaxInput {
		return RunConfig{}, ErrTooLarge
	}
	rc := RunConfig{Defines: map[string]string{}}
	seenRoot := false
	for n, ln := range outputLines(out) {
		ln = strings.TrimSuffix(ln, "\r")
		if v, ok := strings.CutPrefix(ln, "ServerRoot: "); ok {
			root, ok := unquote(v)
			if trimmed := strings.TrimRight(root, "/"); trimmed != "" {
				root = trimmed
			} else if root != "" {
				root = "/"
			}
			if seenRoot || !ok || !helperproto.ValidPath(root) {
				return RunConfig{}, outputErr(n + 1)
			}
			seenRoot, rc.ServerRoot = true, root
			continue
		}
		if v, ok := strings.CutPrefix(ln, "Define: "); ok {
			name, value, _ := strings.Cut(v, "=")
			if name == "" || strings.ContainsAny(name, " \t\v\f\r") {
				return RunConfig{}, outputErr(n + 1)
			}
			if !strings.HasPrefix(name, "DUMP_") {
				rc.Defines[name] = value
			}
		}
	}
	return rc, nil
}

func unquote(s string) (string, bool) {
	if len(s) < 2 || s[0] != '"' || s[len(s)-1] != '"' {
		return "", false
	}
	return s[1 : len(s)-1], true
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

// outputLines splits tool output into lines; a final newline does not start an empty line.
func outputLines(out []byte) []string {
	if len(out) == 0 {
		return nil
	}
	return strings.Split(strings.TrimSuffix(string(out), "\n"), "\n")
}

func outputErr(line int) error { return fmt.Errorf("%w (line %d)", ErrOutput, line) }
