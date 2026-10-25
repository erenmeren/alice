// Command matrixcheck proves that every ID of the test matrices of the quality specification
// (sections 23 to 25: L-, F-, S-, R-, A-, O-, X-, SR-, WIN-, HB- and FX- rows) is accounted for: it names tests that
// exist, an owner step, or a ruling that defers it, or it is listed as a gap.
//
//	go run ./tools/matrixcheck -spec 06-quality.md -map test/matrix/traceability.json -doc docs/security/traceability.md [-strict] [-update]
//
// The map is a JSON list of {"id","status","tests","owner","ruling","note"} entries. Status is
// test (tests lists "<package directory>:<TestName>", or "<file>:<text>" for a TypeScript test or
// a script: the file must exist and contain the text), partial (tests as for test, which prove
// only part of the row; note says what is missing, and ruling or owner accounts for it), owner
// (owner names the walkthrough step), deferred (ruling names the ruling) or gap (note says what is
// missing). The check always fails on a missing, unknown, duplicate or malformed entry and on a
// stale generated document. A named test that does not exist yet is counted as pending; with
// -strict it is an error, and so is every gap and every partial entry without a ruling or an owner
// step. -update rewrites the document.
package main

import (
	"bufio"
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
)

// Entry is one line of the traceability map.
type Entry struct {
	ID     string   `json:"id"`
	Status string   `json:"status"`
	Tests  []string `json:"tests,omitempty"`
	Owner  string   `json:"owner,omitempty"`
	Ruling string   `json:"ruling,omitempty"`
	Note   string   `json:"note,omitempty"`
}

// Result is the outcome of one check.
type Result struct {
	IDs, ByTests, Partial, Pending, Owner, Deferred, Gaps int
	Errors                                                []string
	Doc                                                   string
}

// Summary is the line printed on success.
func (r Result) Summary() string {
	return fmt.Sprintf("matrix-check: %d IDs, %d by tests, %d partial, %d pending, %d owner, %d deferred, %d gaps",
		r.IDs, r.ByTests, r.Partial, r.Pending, r.Owner, r.Deferred, r.Gaps)
}

func main() {
	spec := flag.String("spec", "docs/superpowers/specs/alice-v1/06-quality.md", "quality specification")
	mapPath := flag.String("map", "test/matrix/traceability.json", "traceability map")
	docPath := flag.String("doc", "docs/security/traceability.md", "generated document")
	root := flag.String("root", ".", "repository root (tests and web files are looked up here)")
	strict := flag.Bool("strict", false, "pending tests and gaps are errors")
	update := flag.Bool("update", false, "rewrite the generated document")
	flag.Parse()

	res, err := Run(*root, *spec, *mapPath, *strict)
	if err != nil {
		fmt.Fprintln(os.Stderr, "matrix-check:", err)
		os.Exit(1)
	}
	if *update {
		if err := os.WriteFile(*docPath, []byte(res.Doc), 0o644); err != nil { //nolint:gosec // a document in the repository
			fmt.Fprintln(os.Stderr, "matrix-check:", err)
			os.Exit(1)
		}
	} else if cur, err := os.ReadFile(*docPath); err != nil || string(cur) != res.Doc { //nolint:gosec // path from a flag
		res.Errors = append(res.Errors, *docPath+" is not current; run matrixcheck with -update")
	}
	for _, e := range res.Errors {
		fmt.Fprintln(os.Stderr, e)
	}
	if len(res.Errors) > 0 {
		fmt.Fprintf(os.Stderr, "matrix-check: %d problem(s)\n", len(res.Errors))
		os.Exit(1)
	}
	fmt.Fprintln(os.Stdout, res.Summary())
}

var (
	idRowRe    = regexp.MustCompile(`^\|\s*((?:SR|WIN|HB|FX|CAN|[LFSRAOX])-\d+)\s*\|`)
	sectionRe  = regexp.MustCompile(`^##\s+(\d+)\.`)
	testFnRe   = regexp.MustCompile(`(?m)^func ((?:Test|Fuzz|Benchmark|Example)\w*)\(`)
	testNameRe = regexp.MustCompile(`^(?:Test|Fuzz)\w+$`)
)

// SpecIDs returns the matrix IDs of sections 23 to 25 in order, each with the first words of its
// row, and the first duplicate if any.
func SpecIDs(r io.Reader) (ids []string, titles map[string]string, err error) {
	titles = map[string]string{}
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 0, 1<<20), 1<<24)
	in := false
	for sc.Scan() {
		line := sc.Text()
		if m := sectionRe.FindStringSubmatch(line); m != nil {
			in = m[1] == "23" || m[1] == "24" || m[1] == "25"
			continue
		}
		if !in {
			continue
		}
		if m := idRowRe.FindStringSubmatch(line); m != nil {
			if _, dup := titles[m[1]]; dup {
				return nil, nil, fmt.Errorf("the specification lists %s twice", m[1])
			}
			cells := strings.Split(line, "|")
			t := ""
			if len(cells) > 2 {
				t = cells[2]
			}
			if len(cells) > 5 { // setup | action | result: name the first two
				t += " / " + cells[3]
			}
			titles[m[1]] = oneLine(t, 120)
			ids = append(ids, m[1])
		}
	}
	return ids, titles, sc.Err()
}

func oneLine(s string, max int) string {
	s = strings.Join(strings.Fields(strings.ReplaceAll(s, "|", "/")), " ")
	s = strings.NewReplacer("`", "", "<", "&lt;", ">", "&gt;").Replace(s)
	r := []rune(s)
	if len(r) > max {
		s = strings.TrimSpace(string(r[:max])) + "..."
	}
	return s
}

// goTests lists the test function names per directory (slash-separated, relative to root).
func goTests(root string) (map[string]map[string]bool, error) {
	out := map[string]map[string]bool{}
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			switch d.Name() {
			case ".git", "node_modules", ".claude", ".superpowers", "dist", "bin":
				if path != root {
					return filepath.SkipDir
				}
			}
			return nil
		}
		if !strings.HasSuffix(d.Name(), "_test.go") {
			return nil
		}
		b, err := os.ReadFile(path) //nolint:gosec // walking the repository
		if err != nil {
			return err
		}
		rel, _ := filepath.Rel(root, filepath.Dir(path))
		rel = filepath.ToSlash(rel)
		if out[rel] == nil {
			out[rel] = map[string]bool{}
		}
		for _, m := range testFnRe.FindAllSubmatch(b, -1) {
			out[rel][string(m[1])] = true
		}
		return nil
	})
	return out, err
}

// Run checks the map against the specification and the tests under root.
func Run(root, specPath, mapPath string, strict bool) (Result, error) {
	var res Result
	sf, err := os.Open(specPath) //nolint:gosec // path from a flag
	if err != nil {
		return res, err
	}
	defer sf.Close() //nolint:errcheck // read only
	ids, titles, err := SpecIDs(sf)
	if err != nil {
		return res, err
	}
	raw, err := os.ReadFile(mapPath) //nolint:gosec // path from a flag
	if err != nil {
		return res, err
	}
	var entries []Entry
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&entries); err != nil {
		return res, fmt.Errorf("%s: %w", mapPath, err)
	}
	tests, err := goTests(root)
	if err != nil {
		return res, err
	}
	return evaluate(root, ids, titles, entries, tests, strict), nil
}

func evaluate(root string, ids []string, titles map[string]string, entries []Entry, tests map[string]map[string]bool, strict bool) Result {
	var res Result
	res.IDs = len(ids)
	inSpec := map[string]bool{}
	for _, id := range ids {
		inSpec[id] = true
	}
	byID := map[string]Entry{}
	for _, e := range entries {
		switch {
		case !inSpec[e.ID]:
			res.Errors = append(res.Errors, fmt.Sprintf("%s: the specification has no such ID", e.ID))
			continue
		case byID[e.ID].ID != "":
			res.Errors = append(res.Errors, fmt.Sprintf("%s: listed twice", e.ID))
			continue
		}
		byID[e.ID] = e
	}
	for _, id := range ids {
		e, ok := byID[id]
		if !ok {
			res.Errors = append(res.Errors, fmt.Sprintf("%s: no entry in the traceability map", id))
			continue
		}
		errs := validate(e)
		res.Errors = append(res.Errors, errs...)
		if len(errs) > 0 {
			continue
		}
		switch e.Status {
		case "test", "partial":
			if e.Status == "partial" && strict && e.Ruling == "" && e.Owner == "" {
				res.Errors = append(res.Errors, fmt.Sprintf("%s: partial without a ruling or owner step: %s", id, e.Note))
			}
			missing := missingTests(root, e.Tests, tests)
			if len(missing) == 0 {
				if e.Status == "partial" {
					res.Partial++
				} else {
					res.ByTests++
				}
				continue
			}
			res.Pending++
			if strict {
				for _, m := range missing {
					res.Errors = append(res.Errors, fmt.Sprintf("%s: test %s does not exist", id, m))
				}
			}
		case "owner":
			res.Owner++
		case "deferred":
			res.Deferred++
		case "gap":
			res.Gaps++
			if strict {
				res.Errors = append(res.Errors, fmt.Sprintf("%s: gap: %s", id, e.Note))
			}
		}
	}
	sort.Strings(res.Errors)
	res.Doc = render(ids, titles, byID)
	return res
}

func validate(e Entry) []string {
	var out []string
	bad := func(format string, a ...any) {
		out = append(out, e.ID+": "+fmt.Sprintf(format, a...))
	}
	switch e.Status {
	case "test", "partial":
		if len(e.Tests) == 0 {
			bad("status %s without tests", e.Status)
		}
		if e.Status == "partial" && e.Note == "" {
			bad("status partial without note")
		}
		for _, t := range e.Tests {
			dir, name, ok := strings.Cut(t, ":")
			if !ok || dir == "" || name == "" {
				bad("test %q is not <directory>:<name>", t)
			} else if !isFile(dir) && !testNameRe.MatchString(name) {
				bad("test name %q is not a Test or Fuzz function", name)
			}
		}
	case "owner":
		if e.Owner == "" {
			bad("status owner without owner")
		}
	case "deferred":
		if e.Ruling == "" {
			bad("status deferred without ruling")
		}
	case "gap":
		if e.Note == "" {
			bad("status gap without note")
		}
	default:
		bad("unknown status %q", e.Status)
	}
	return out
}

// isFile reports whether the left side of a test reference names a file (its last element has an
// extension: a TypeScript test, a shell script) instead of a Go package directory.
func isFile(p string) bool {
	return strings.Contains(filepath.Base(p), ".")
}

func missingTests(root string, named []string, tests map[string]map[string]bool) []string {
	var out []string
	for _, t := range named {
		dir, name, _ := strings.Cut(t, ":")
		if isFile(dir) {
			b, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(dir))) //nolint:gosec // repository file
			if err != nil || !bytes.Contains(b, []byte(name)) {
				out = append(out, t)
			}
			continue
		}
		if !tests[filepath.ToSlash(filepath.Clean(dir))][name] {
			out = append(out, t)
		}
	}
	return out
}

func render(ids []string, titles map[string]string, byID map[string]Entry) string {
	var b strings.Builder
	b.WriteString("# Traceability of the test matrices\n\n")
	b.WriteString("Generated by `go run ./tools/matrixcheck -update` from `test/matrix/traceability.json` and the\n")
	b.WriteString("matrices of sections 23 to 25 of `docs/superpowers/specs/alice-v1/06-quality.md`. Do not edit by hand.\n")
	b.WriteString("Status: `test` (named automated tests), `partial` (the named tests prove part of the row; the\n")
	b.WriteString("evidence says what is missing and which ruling or owner step covers it), `owner` (proven by an\n")
	b.WriteString("owner step), `deferred` (a ruling defers it), `gap` (nothing proves it yet).\n\n")
	counts := map[string]int{}
	for _, id := range ids {
		counts[byID[id].Status]++
	}
	fmt.Fprintf(&b, "%d IDs: %d test, %d partial, %d owner, %d deferred, %d gap.\n\n", len(ids), counts["test"], counts["partial"], counts["owner"], counts["deferred"], counts["gap"])
	b.WriteString("| ID | Case | Status | Evidence |\n| --- | --- | --- | --- |\n")
	for _, id := range ids {
		e := byID[id]
		var ev []string
		for _, t := range e.Tests {
			ev = append(ev, "`"+t+"`")
		}
		if e.Owner != "" {
			ev = append(ev, "owner step: "+e.Owner)
		}
		if e.Ruling != "" {
			ev = append(ev, "ruling: "+e.Ruling)
		}
		if e.Note != "" {
			ev = append(ev, oneLine(e.Note, 400))
		}
		fmt.Fprintf(&b, "| %s | %s | %s | %s |\n", id, titles[id], e.Status, strings.Join(ev, "<br>"))
	}
	return b.String()
}
