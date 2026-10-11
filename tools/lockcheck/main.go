// Command lockcheck refuses anything but package data in the dependency lockfiles. It is the
// secret-scan substitute for files that are too large and too regular to review by eye
// (R43 row 38): a token pasted into web/package-lock.json or go.sum, a download from a host other
// than the npm registry, or an integrity value that is not a SHA-512 digest fails the check.
//
//	go run ./tools/lockcheck web/package-lock.json go.sum
//
// A file named go.sum is read as a Go checksum file; any other file as an npm lockfile (version 3).
// Messages carry the file and line and never repeat a value.
package main

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
)

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintln(os.Stderr, "usage: lockcheck FILE...")
		os.Exit(2)
	}
	n := 0
	for _, p := range os.Args[1:] {
		for _, m := range Check(p) {
			fmt.Fprintln(os.Stderr, m)
			n++
		}
	}
	if n > 0 {
		fmt.Fprintf(os.Stderr, "lockcheck: %d problem(s); a lockfile may hold package data only\n", n)
		os.Exit(1)
	}
}

var (
	goSumRe     = regexp.MustCompile(`^\S+ v\S+(/go\.mod)? h1:[A-Za-z0-9+/]{43}=$`)
	integrityRe = regexp.MustCompile(`^sha512-[A-Za-z0-9+/]+={0,2}$`)
	resolvedRe  = regexp.MustCompile(`^https://registry\.npmjs\.org/[A-Za-z0-9@/._~+-]+$`)
	versionRe   = regexp.MustCompile(`^[0-9]+\.[0-9]+\.[0-9]+(?:[-+][0-9A-Za-z.+-]+)?$`)
	rangeRe     = regexp.MustCompile(`^[A-Za-z0-9@/._+\-^~<>=| *:]{0,200}$`)
	nameRe      = regexp.MustCompile(`^(?:@[a-z0-9][a-z0-9._-]*/)?[A-Za-z0-9][A-Za-z0-9._-]*$`)
	pkgPathRe   = regexp.MustCompile(`^(?:|[A-Za-z0-9@/._-]+)$`)
	licenseRe   = regexp.MustCompile(`^[A-Za-z0-9.+() -]{1,200}$`)
	urlRe       = regexp.MustCompile(`^https://[A-Za-z0-9.-]+(?:/[A-Za-z0-9@/._~+%-]*)?(?:\?[A-Za-z0-9_=.-]{1,60})?(?:#[A-Za-z0-9_.-]{1,100})?$`)
	relPathRe   = regexp.MustCompile(`^[A-Za-z0-9@/._-]+$`)
	wordRe      = regexp.MustCompile(`^[A-Za-z0-9!._-]{1,40}$`)
)

var topKeys = set("name", "version", "lockfileVersion", "requires", "packages")

// pkgKeys are the keys npm writes for one package (plus workspaces, which only the root entry has).
var pkgKeys = set("version", "resolved", "integrity", "dev", "optional", "peer", "devOptional", "license",
	"engines", "dependencies", "devDependencies", "optionalDependencies", "peerDependencies",
	"peerDependenciesMeta", "bin", "funding", "cpu", "os", "libc", "hasInstallScript", "deprecated",
	"inBundle", "bundleDependencies", "link", "name", "workspaces")

func set(v ...string) map[string]bool {
	m := make(map[string]bool, len(v))
	for _, s := range v {
		m[s] = true
	}
	return m
}

// Check returns one message per problem in the lockfile at path.
func Check(path string) []string {
	//nolint:gosec // path is a repository file named on the command line
	data, err := os.ReadFile(path)
	if err != nil {
		return []string{path + ": " + err.Error()}
	}
	name := path
	if filepath.Base(path) == "go.sum" {
		return checkGoSum(name, data)
	}
	return checkNPM(name, data)
}

func checkGoSum(file string, data []byte) []string {
	var out []string
	sc := bufio.NewScanner(bytes.NewReader(data))
	sc.Buffer(make([]byte, 0, 64*1024), 1<<20)
	for n := 1; sc.Scan(); n++ {
		if !goSumRe.MatchString(sc.Text()) {
			out = append(out, fmt.Sprintf("%s:%d: not a \"module version h1:<hash>\" line", file, n))
		}
	}
	if err := sc.Err(); err != nil {
		out = append(out, file+": "+err.Error())
	}
	return out
}

// node is a JSON value with the line it starts on.
type node struct {
	line int
	kind byte // 'o' object, 'a' array, 's' string, 'b' bool, 'n' number or null
	str  string
	keys []string // object keys in order
	kids map[string]*node
	arr  []*node
}

type parser struct {
	dec  *json.Decoder
	data []byte
}

func (p *parser) lineAt(off int64) int {
	return bytes.Count(p.data[:min(int(off), len(p.data))], []byte("\n")) + 1
}

func (p *parser) value() (*node, error) {
	tok, err := p.dec.Token()
	if err != nil {
		return nil, err
	}
	// The offset after a token points past it; for a start line the end of a scalar is close
	// enough, and delimiters are one byte long.
	n := &node{line: p.lineAt(p.dec.InputOffset())}
	switch t := tok.(type) {
	case json.Delim:
		if t == '{' {
			n.kind, n.kids = 'o', map[string]*node{}
			for p.dec.More() {
				k, err := p.dec.Token()
				if err != nil {
					return nil, err
				}
				key, _ := k.(string)
				child, err := p.value()
				if err != nil {
					return nil, err
				}
				n.keys = append(n.keys, key)
				n.kids[key] = child
			}
		} else {
			n.kind = 'a'
			for p.dec.More() {
				child, err := p.value()
				if err != nil {
					return nil, err
				}
				n.arr = append(n.arr, child)
			}
		}
		if _, err := p.dec.Token(); err != nil { // the closing delimiter
			return nil, err
		}
	case string:
		n.kind, n.str = 's', t
	case bool:
		n.kind = 'b'
	default:
		n.kind = 'n'
	}
	return n, nil
}

type report struct {
	file string
	out  []string
}

func (r *report) add(line int, format string, a ...any) {
	r.out = append(r.out, fmt.Sprintf("%s:%d: %s", r.file, line, fmt.Sprintf(format, a...)))
}

func checkNPM(file string, data []byte) []string {
	p := &parser{dec: json.NewDecoder(bytes.NewReader(data)), data: data}
	root, err := p.value()
	if err == nil {
		if _, e := p.dec.Token(); !errors.Is(e, io.EOF) {
			err = errors.New("data after the JSON document")
		}
	}
	if err != nil {
		return []string{file + ": not valid JSON: " + err.Error()}
	}
	r := &report{file: file}
	if root.kind != 'o' {
		r.add(root.line, "the lockfile is not a JSON object")
		return r.out
	}
	for _, k := range root.keys {
		kid := root.kids[k]
		if !topKeys[k] {
			r.add(kid.line, "top-level key %q is not part of an npm lockfile", k)
		}
	}
	if v := root.kids["lockfileVersion"]; v == nil || v.kind != 'n' {
		r.add(root.line, "lockfileVersion is missing")
	}
	for _, k := range []string{"name", "version"} {
		if v := root.kids[k]; v != nil && (v.kind != 's' || !(map[string]*regexp.Regexp{"name": nameRe, "version": versionRe})[k].MatchString(v.str)) {
			r.add(v.line, "%s has an unexpected shape", k)
		}
	}
	if v := root.kids["requires"]; v != nil && v.kind != 'b' {
		r.add(v.line, "requires has an unexpected shape")
	}
	pk := root.kids["packages"]
	if pk == nil || pk.kind != 'o' {
		r.add(root.line, "packages is missing")
		return r.out
	}
	for _, path := range pk.keys {
		entry := pk.kids[path]
		if !pkgPathRe.MatchString(path) {
			r.add(entry.line, "package path has an unexpected shape")
		}
		checkPackage(r, entry)
	}
	return r.out
}

func checkPackage(r *report, e *node) {
	if e.kind != 'o' {
		r.add(e.line, "package entry is not an object")
		return
	}
	for _, k := range e.keys {
		v := e.kids[k]
		if !pkgKeys[k] {
			r.add(v.line, "package key %q is not one npm writes", k)
			continue
		}
		switch k {
		case "version":
			expectString(r, v, k, func(s string) bool { return versionRe.MatchString(s) })
		case "resolved":
			expectString(r, v, k, func(s string) bool { return resolvedRe.MatchString(s) })
		case "integrity":
			expectString(r, v, k, func(s string) bool { return integrityRe.MatchString(s) })
		case "license":
			expectString(r, v, k, func(s string) bool { return licenseRe.MatchString(s) })
		case "name":
			expectString(r, v, k, func(s string) bool { return nameRe.MatchString(s) })
		case "deprecated":
			expectString(r, v, k, func(s string) bool { return !strings.ContainsAny(s, "\x00") && len(s) <= 2000 })
		case "dev", "optional", "peer", "devOptional", "hasInstallScript", "inBundle", "link":
			if v.kind != 'b' {
				r.add(v.line, "%s is not a boolean", k)
			}
		case "dependencies", "devDependencies", "optionalDependencies", "peerDependencies", "engines":
			checkMap(r, v, k, nameOrEngine, rangeRe.MatchString)
		case "peerDependenciesMeta":
			checkPeerMeta(r, v)
		case "bin":
			checkBin(r, v)
		case "funding":
			checkFunding(r, v)
		case "cpu", "os", "libc", "workspaces", "bundleDependencies":
			checkStringList(r, v, k)
		}
	}
}

func nameOrEngine(s string) bool { return nameRe.MatchString(s) }

func expectString(r *report, v *node, key string, ok func(string) bool) {
	if v.kind != 's' || !ok(v.str) {
		r.add(v.line, "%s has an unexpected shape", key)
	}
}

func checkMap(r *report, v *node, key string, keyOK, valOK func(string) bool) {
	if v.kind != 'o' {
		r.add(v.line, "%s is not an object", key)
		return
	}
	for _, k := range v.keys {
		kid := v.kids[k]
		if !keyOK(k) || kid.kind != 's' || !valOK(kid.str) {
			r.add(kid.line, "%s has an entry of an unexpected shape", key)
		}
	}
}

func checkPeerMeta(r *report, v *node) {
	if v.kind != 'o' {
		r.add(v.line, "peerDependenciesMeta is not an object")
		return
	}
	for _, k := range v.keys {
		kid := v.kids[k]
		if !nameRe.MatchString(k) || kid.kind != 'o' || len(kid.keys) != 1 || kid.keys[0] != "optional" || kid.kids["optional"].kind != 'b' {
			r.add(kid.line, "peerDependenciesMeta has an entry of an unexpected shape")
		}
	}
}

func checkBin(r *report, v *node) {
	switch v.kind {
	case 's':
		if !relPathRe.MatchString(v.str) {
			r.add(v.line, "bin has an unexpected shape")
		}
	case 'o':
		checkMap(r, v, "bin", func(s string) bool { return nameRe.MatchString(s) || wordRe.MatchString(s) }, relPathRe.MatchString)
	default:
		r.add(v.line, "bin has an unexpected shape")
	}
}

func checkStringList(r *report, v *node, key string) {
	if v.kind != 'a' {
		r.add(v.line, "%s is not a list", key)
		return
	}
	for _, it := range v.arr {
		if it.kind != 's' || (!wordRe.MatchString(it.str) && !relPathRe.MatchString(it.str) && !strings.Contains(it.str, "*")) {
			r.add(it.line, "%s has an item of an unexpected shape", key)
		}
	}
}

// checkFunding accepts what npm copies from package.json: a URL, {type, url} or a list of both.
func checkFunding(r *report, v *node) {
	switch v.kind {
	case 's':
		if !urlRe.MatchString(v.str) {
			r.add(v.line, "funding has an unexpected shape")
		}
	case 'o':
		keys := append([]string(nil), v.keys...)
		sort.Strings(keys)
		for _, k := range keys {
			kid := v.kids[k]
			switch {
			case k == "url" && kid.kind == 's' && urlRe.MatchString(kid.str):
			case k == "type" && kid.kind == 's' && wordRe.MatchString(kid.str):
			default:
				r.add(kid.line, "funding has a field of an unexpected shape")
			}
		}
		if v.kids["url"] == nil {
			r.add(v.line, "funding has no url")
		}
	case 'a':
		for _, it := range v.arr {
			checkFunding(r, it)
		}
	default:
		r.add(v.line, "funding has an unexpected shape")
	}
}
