// Command notices writes THIRD_PARTY_NOTICES.md for a release package (C5, spec §17.6): the
// license text of every Go module linked into the given binaries (read from their build
// information and the module cache), of the Go standard library, and of every npm package of
// web/package-lock.json that is not a development dependency (the packages bundled into the web
// UI). A Go module without a license file fails the tool; an npm package without one is listed with
// the license its package.json declares.
//
//	go run ./tools/notices -binaries bin/alice,bin/alice-helper-linux-amd64 \
//	  -lockfile web/package-lock.json -node-modules web/node_modules -out bin/THIRD_PARTY_NOTICES.md
package main

import (
	"bufio"
	"bytes"
	"context"
	"debug/buildinfo"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"unicode"
)

func main() { os.Exit(run(os.Args[1:], os.Stderr)) }

func run(args []string, stderr io.Writer) int {
	fs := flag.NewFlagSet("notices", flag.ContinueOnError)
	fs.SetOutput(stderr)
	binaries := fs.String("binaries", "", "comma-separated Go binaries")
	lockfile := fs.String("lockfile", "", "web/package-lock.json")
	nodeModules := fs.String("node-modules", "", "web/node_modules")
	out := fs.String("out", "", "THIRD_PARTY_NOTICES.md to write")
	modCache := fs.String("modcache", "", "Go module cache (default: go env GOMODCACHE)")
	goRoot := fs.String("goroot", "", "Go installation (default: go env GOROOT)")
	if fs.Parse(args) != nil || fs.NArg() != 0 || *binaries == "" || *lockfile == "" || *nodeModules == "" || *out == "" {
		fs.Usage()
		return 2
	}
	if err := generate(*binaries, *lockfile, *nodeModules, *out, *modCache, *goRoot); err != nil {
		_, _ = fmt.Fprintln(stderr, "notices:", err)
		return 1
	}
	return 0
}

func generate(binaries, lockfile, nodeModules, out, modCache, goRoot string) error {
	in := input{ModCache: modCache, GoRoot: goRoot, NodeModules: nodeModules}
	var err error
	if in.ModCache == "" {
		if in.ModCache, err = goEnv("GOMODCACHE"); err != nil {
			return err
		}
	}
	if in.GoRoot == "" {
		if in.GoRoot, err = goEnv("GOROOT"); err != nil {
			return err
		}
	}
	var lists [][]module
	for _, b := range strings.Split(binaries, ",") {
		bi, err := buildinfo.ReadFile(b)
		if err != nil {
			return fmt.Errorf("%s: %w", b, err)
		}
		text := bi.String()
		lists = append(lists, parseBuildInfo(text))
		if in.GoVersion == "" {
			in.GoVersion = bi.GoVersion
		}
	}
	in.Modules = mergeModules(lists...)
	if in.Npm, err = npmPackages(lockfile); err != nil {
		return err
	}
	var buf bytes.Buffer
	if err := render(&buf, in); err != nil {
		return err
	}
	return os.WriteFile(out, buf.Bytes(), 0o644) //nolint:gosec // G306: a public notices file
}

func goEnv(name string) (string, error) {
	out, err := exec.CommandContext(context.Background(), "go", "env", name).Output() //nolint:gosec // G204: a fixed variable name
	if err != nil {
		return "", fmt.Errorf("go env %s: %w", name, err)
	}
	return strings.TrimSpace(string(out)), nil
}

// module is one linked Go module.
type module struct{ Path, Version string }

// parseBuildInfo reads the module lines of "go version -m" output (or debug/buildinfo's String):
// each "dep" line, replaced by the "=>" line after it when there is one.
func parseBuildInfo(text string) []module {
	var out []module
	s := bufio.NewScanner(strings.NewReader(text))
	for s.Scan() {
		f := strings.Split(strings.TrimLeftFunc(s.Text(), unicode.IsSpace), "\t")
		switch {
		case len(f) >= 3 && f[0] == "dep":
			out = append(out, module{Path: f[1], Version: f[2]})
		case len(f) >= 2 && f[0] == "=>" && len(out) > 0:
			m := module{Path: f[1]}
			if len(f) >= 3 {
				m.Version = f[2]
			}
			out[len(out)-1] = m
		}
	}
	return out
}

// goVersionOf returns the Go version of the first line of "go version -m" output.
func goVersionOf(text string) string {
	first, _, _ := strings.Cut(text, "\n")
	f := strings.Fields(first)
	if len(f) == 0 {
		return ""
	}
	return f[len(f)-1]
}

// mergeModules joins module lists, keeping the first occurrence of each module.
func mergeModules(lists ...[]module) []module {
	seen := map[module]bool{}
	var out []module
	for _, l := range lists {
		for _, m := range l {
			if !seen[m] {
				seen[m] = true
				out = append(out, m)
			}
		}
	}
	return out
}

// npmPackage is one package of the lockfile that the web build may bundle.
type npmPackage struct {
	Key, Name, Version, License, Author string
	Optional                            bool
}

// npmPackages lists the lockfile packages without "dev": true, sorted by their node_modules path.
func npmPackages(lockfile string) ([]npmPackage, error) {
	raw, err := os.ReadFile(lockfile) //nolint:gosec // G304: path from the Makefile
	if err != nil {
		return nil, err
	}
	var lock struct {
		Packages map[string]struct {
			Version  string          `json:"version"`
			License  json.RawMessage `json:"license"`
			Author   json.RawMessage `json:"author"`
			Dev      bool            `json:"dev"`
			Optional bool            `json:"optional"`
		} `json:"packages"`
	}
	if err := json.Unmarshal(raw, &lock); err != nil {
		return nil, fmt.Errorf("%s: %w", lockfile, err)
	}
	var out []npmPackage
	for key, p := range lock.Packages {
		if key == "" || p.Dev || !strings.HasPrefix(key, "node_modules/") {
			continue
		}
		name := key[strings.LastIndex(key, "node_modules/")+len("node_modules/"):]
		out = append(out, npmPackage{Key: key, Name: name, Version: p.Version, License: jsonText(p.License),
			Author: jsonText(p.Author), Optional: p.Optional})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Key < out[j].Key })
	return out, nil
}

// jsonText returns a JSON string's value, or the "name" of an object such as {"name": ...}.
func jsonText(raw json.RawMessage) string {
	var s string
	if json.Unmarshal(raw, &s) == nil {
		return s
	}
	var o struct {
		Name string `json:"name"`
		Type string `json:"type"`
	}
	if json.Unmarshal(raw, &o) == nil {
		if o.Name != "" {
			return o.Name
		}
		return o.Type
	}
	return ""
}

// input is everything render needs.
type input struct {
	GoVersion, GoRoot, ModCache, NodeModules string
	Modules                                  []module
	Npm                                      []npmPackage
}

// escapePath is the module cache's case encoding: an upper-case letter becomes "!" and its
// lower-case form.
func escapePath(p string) string {
	var b strings.Builder
	for _, r := range p {
		if unicode.IsUpper(r) {
			b.WriteByte('!')
			r = unicode.ToLower(r)
		}
		b.WriteRune(r)
	}
	return b.String()
}

// licenseFiles returns the license and notice files at the top of dir, sorted.
func licenseFiles(dir string) ([]string, error) {
	list, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}
	var out []string
	for _, d := range list {
		if d.IsDir() {
			continue
		}
		name := d.Name()
		for _, prefix := range []string{"LICENSE", "LICENCE", "COPYING", "NOTICE", "PATENTS", "UNLICENSE"} {
			if len(name) >= len(prefix) && strings.EqualFold(name[:len(prefix)], prefix) {
				out = append(out, filepath.Join(dir, d.Name()))
				break
			}
		}
	}
	sort.Strings(out)
	return out, nil
}

// fence returns a Markdown code fence longer than any run of backticks in text.
func fence(text string) string {
	longest, run := 0, 0
	for _, r := range text {
		if r == '`' {
			run++
			longest = max(longest, run)
		} else {
			run = 0
		}
	}
	return strings.Repeat("`", max(3, longest+1))
}

func writeTexts(w io.Writer, files []string) error {
	for _, f := range files {
		raw, err := os.ReadFile(f) //nolint:gosec // G304: a license file found in the module cache or node_modules
		if err != nil {
			return err
		}
		text := strings.TrimRight(strings.ReplaceAll(string(raw), "\r\n", "\n"), "\n")
		fc := fence(text)
		if _, err := fmt.Fprintf(w, "%s:\n\n%stext\n%s\n%s\n\n", filepath.Base(f), fc, text, fc); err != nil {
			return err
		}
	}
	return nil
}

// render writes the notices document.
func render(w io.Writer, in input) error {
	var b bytes.Buffer
	b.WriteString("# Third-party notices\n\nAlice includes the software listed below. Each section names the component and its version " +
		"and gives the license text that the component ships with.\n\n## Go\n\n")
	goLicense := filepath.Join(in.GoRoot, "LICENSE")
	fmt.Fprintf(&b, "### Go standard library %s\n\n", in.GoVersion)
	if err := writeTexts(&b, []string{goLicense}); err != nil {
		return fmt.Errorf("the Go standard library license: %w", err)
	}
	for _, m := range in.Modules {
		dir := filepath.Join(in.ModCache, filepath.FromSlash(escapePath(m.Path))+"@"+escapePath(m.Version))
		files, err := licenseFiles(dir)
		if err != nil {
			return fmt.Errorf("module %s %s is not in the module cache (%w); run go mod download", m.Path, m.Version, err)
		}
		if len(files) == 0 {
			return fmt.Errorf("module %s %s has no license file in %s", m.Path, m.Version, dir)
		}
		fmt.Fprintf(&b, "### %s %s\n\n", m.Path, m.Version)
		if err := writeTexts(&b, files); err != nil {
			return err
		}
	}
	if len(in.Npm) > 0 {
		b.WriteString("## Web UI (npm packages)\n\n")
	}
	for _, p := range in.Npm {
		dir := filepath.Join(in.NodeModules, filepath.FromSlash(strings.TrimPrefix(p.Key, "node_modules/")))
		if _, err := os.Stat(dir); errors.Is(err, fs.ErrNotExist) {
			if p.Optional {
				continue // an optional package for another platform: not installed, not bundled
			}
			return fmt.Errorf("npm package %s %s is not installed in %s; run make web-install", p.Name, p.Version, in.NodeModules)
		}
		files, err := licenseFiles(dir)
		if err != nil {
			return err
		}
		fmt.Fprintf(&b, "### %s %s\n\n", p.Name, p.Version)
		if len(files) == 0 {
			if p.License == "" {
				return fmt.Errorf("npm package %s %s has neither a license file nor a declared license", p.Name, p.Version)
			}
			line := fmt.Sprintf("License: %s (as declared in its package.json; the package ships no license file).", p.License)
			if p.Author != "" {
				line += " Author: " + p.Author
			}
			b.WriteString(line + "\n\n")
			continue
		}
		if err := writeTexts(&b, files); err != nil {
			return err
		}
	}
	_, err := w.Write(b.Bytes())
	return err
}
