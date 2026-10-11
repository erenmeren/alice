// Command docscheck keeps the guides honest. It fails when
//
//   - a command named in a fenced block or in inline code of a guide does not exist: an
//     "alicectl <command>", an "alice <command>", a "--flag" of install.sh or alice-update.sh, or a
//     "make <target>" that the scripts' usage text, the alice usage text or the Makefile does not
//     list;
//
//   - a relative link of a guide points to a file (or a heading of a Markdown file) that is not there;
//
//   - a line of tools/docscheck/required.txt ("<file><TAB><required text>") names a file that is
//     missing or does not contain its text. Those lines pin the sentences that carry a security
//     promise (S-23, S-26), so an edit of a guide cannot silently drop them.
//
//     go run ./tools/docscheck [-root DIR]
//
// Scope: docs/**/*.md except the plans, specifications and reviews (docs/superpowers,
// docs/security/reviews), SECURITY-REPORT.md and, from its Phase 8 entry on, CHANGELOG.md.
package main

import (
	"bufio"
	"flag"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"unicode"
)

func main() {
	root := flag.String("root", ".", "repository root")
	flag.Parse()
	problems := Check(*root)
	for _, p := range problems {
		fmt.Fprintln(os.Stderr, p)
	}
	if len(problems) > 0 {
		fmt.Fprintf(os.Stderr, "docscheck: %d problem(s)\n", len(problems))
		os.Exit(1)
	}
}

// Check returns one message per problem found under root.
func Check(root string) []string {
	var out []string
	known, err := loadKnown(root)
	if err != nil {
		return []string{"docscheck: " + err.Error()}
	}
	files, err := guideFiles(root)
	if err != nil {
		return []string{"docscheck: " + err.Error()}
	}
	for _, f := range files {
		out = append(out, checkGuide(root, f, known)...)
	}
	out = append(out, checkRequired(root)...)
	sort.Strings(out)
	return out
}

// known is what the guides may name.
type known struct {
	alicectl   map[string]bool // commands
	alice      map[string]bool // commands
	flags      map[string]map[string]bool
	makeTarget map[string]bool
}

var (
	usageBlockRe = regexp.MustCompile(`(?s)<<'USAGE'\n(.*?)\nUSAGE\n`)
	flagRe       = regexp.MustCompile(`--[a-z][a-z0-9-]*`)
	cmdLineRe    = regexp.MustCompile(`^  ([a-z][a-z-]*)\b`)
	aliceUsageRe = regexp.MustCompile("(?s)const usage = `(.*?)`")
	targetRe     = regexp.MustCompile(`^([A-Za-z0-9_.%/ -]+?)\s*::?\s*(?:[^=]|$)`)
)

func loadKnown(root string) (*known, error) {
	k := &known{alicectl: map[string]bool{"help": true}, alice: map[string]bool{}, flags: map[string]map[string]bool{}, makeTarget: map[string]bool{}}
	for _, name := range []string{"install.sh", "alice-update.sh", "alicectl"} {
		b, err := os.ReadFile(filepath.Join(root, "deploy", "release", name)) //nolint:gosec // repository file
		if err != nil {
			return nil, err
		}
		m := usageBlockRe.FindSubmatch(b)
		if m == nil {
			return nil, fmt.Errorf("deploy/release/%s has no usage text (<<'USAGE' ... USAGE)", name)
		}
		set := map[string]bool{}
		for _, f := range flagRe.FindAllString(string(m[1]), -1) {
			set[f] = true
		}
		k.flags[name] = set
		if name == "alicectl" {
			for _, l := range strings.Split(string(m[1]), "\n") {
				if c := cmdLineRe.FindStringSubmatch(l); c != nil {
					k.alicectl[c[1]] = true
				}
			}
		}
	}
	b, err := os.ReadFile(filepath.Join(root, "cmd", "alice", "main.go")) //nolint:gosec // repository file
	if err != nil {
		return nil, err
	}
	m := aliceUsageRe.FindSubmatch(b)
	if m == nil {
		return nil, fmt.Errorf("cmd/alice/main.go has no usage constant")
	}
	for _, l := range strings.Split(string(m[1]), "\n") {
		if c := cmdLineRe.FindStringSubmatch(l); c != nil {
			k.alice[c[1]] = true
		}
	}
	mk, err := os.ReadFile(filepath.Join(root, "Makefile")) //nolint:gosec // repository file
	if err != nil {
		return nil, err
	}
	for _, l := range strings.Split(string(mk), "\n") {
		if strings.HasPrefix(l, "\t") || strings.HasPrefix(l, "#") || strings.HasPrefix(l, ".") {
			continue
		}
		if c := targetRe.FindStringSubmatch(l); c != nil && !strings.Contains(l, ":=") && !strings.Contains(l, "?=") {
			for _, t := range strings.Fields(c[1]) {
				k.makeTarget[t] = true
			}
		}
	}
	return k, nil
}

// guideFiles lists the Markdown files in scope, relative to root, slash separated.
func guideFiles(root string) ([]string, error) {
	var out []string
	err := filepath.WalkDir(filepath.Join(root, "docs"), func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, _ := filepath.Rel(root, p)
		rel = filepath.ToSlash(rel)
		if d.IsDir() {
			if rel == "docs/superpowers" || rel == "docs/security/reviews" {
				return filepath.SkipDir
			}
			return nil
		}
		if strings.HasSuffix(rel, ".md") {
			out = append(out, rel)
		}
		return nil
	})
	if err != nil && !os.IsNotExist(err) {
		return nil, err
	}
	for _, f := range []string{"SECURITY-REPORT.md", "CHANGELOG.md"} {
		if _, err := os.Stat(filepath.Join(root, f)); err == nil {
			out = append(out, f)
		}
	}
	sort.Strings(out)
	return out, nil
}

type line struct {
	n      int
	text   string
	fenced bool
}

// readGuide returns the lines of a guide in scope (for CHANGELOG.md only its Phase 8 entry) and
// whether each is inside a fenced block.
func readGuide(path, rel string) ([]line, error) {
	f, err := os.Open(path) //nolint:gosec // repository file
	if err != nil {
		return nil, err
	}
	defer f.Close() //nolint:errcheck // read only
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 1<<20), 1<<24)
	var out []line
	fenced, inScope := false, rel != "CHANGELOG.md"
	for n := 1; sc.Scan(); n++ {
		t := sc.Text()
		if rel == "CHANGELOG.md" && !fenced && strings.HasPrefix(t, "## ") {
			inScope = strings.Contains(t, "Phase 8")
		}
		trim := strings.TrimSpace(t)
		if strings.HasPrefix(trim, "```") || strings.HasPrefix(trim, "~~~") {
			fenced = !fenced
			continue
		}
		if inScope {
			out = append(out, line{n: n, text: t, fenced: fenced})
		}
	}
	return out, sc.Err()
}

var (
	inlineRe  = regexp.MustCompile("`([^`\n]+)`")
	linkRe    = regexp.MustCompile(`\[[^\]]*\]\(([^)\s]+)(?:\s+"[^"]*")?\)`)
	headingRe = regexp.MustCompile(`^#{1,6}\s+(.*?)\s*#*\s*$`)
	ctlCmdRe  = regexp.MustCompile(`(?:^|\s|/)alicectl\s+([a-z][a-z-]*)`)
	makeCmdRe = regexp.MustCompile(`(?:^|&&|;|\|\||\|)\s*(?:sudo\s+)?make\s+(?:-[A-Za-z]+\s+(?:\S+\s+)?)*([A-Za-z0-9_.-]+)`)
	scriptRe  = regexp.MustCompile(`(?:^|\s|/)(install\.sh|alice-update\.sh)\b`)
)

func checkGuide(root, rel string, k *known) []string {
	lines, err := readGuide(filepath.Join(root, filepath.FromSlash(rel)), rel)
	if err != nil {
		return []string{rel + ": " + err.Error()}
	}
	var out []string
	for _, l := range lines {
		for _, c := range commandsOf(l) {
			out = append(out, checkCommand(rel, l.n, c, k)...)
		}
		if l.fenced {
			continue
		}
		for _, m := range linkRe.FindAllStringSubmatch(stripInline(l.text), -1) {
			if msg := checkLink(root, rel, m[1]); msg != "" {
				out = append(out, fmt.Sprintf("%s:%d: %s", rel, l.n, msg))
			}
		}
	}
	return out
}

// stripInline removes inline code spans, so a link-like text in code is not a link.
func stripInline(s string) string { return inlineRe.ReplaceAllString(s, " ") }

// commandsOf returns the command texts of one line: the whole line inside a fenced block (shell
// prompts and comments removed), the content of each inline code span elsewhere.
func commandsOf(l line) []string {
	if l.fenced {
		t := strings.TrimSpace(l.text)
		t = strings.TrimPrefix(t, "$ ")
		t = strings.TrimSpace(t)
		if t == "" || strings.HasPrefix(t, "#") {
			return nil
		}
		if i := strings.Index(t, " #"); i > 0 {
			t = t[:i]
		}
		return []string{t}
	}
	var out []string
	for _, m := range inlineRe.FindAllStringSubmatch(l.text, -1) {
		out = append(out, strings.TrimPrefix(strings.TrimSpace(m[1]), "$ "))
	}
	return out
}

func checkCommand(rel string, n int, c string, k *known) []string {
	var out []string
	bad := func(format string, a ...any) {
		out = append(out, fmt.Sprintf("%s:%d: %s", rel, n, fmt.Sprintf(format, a...)))
	}
	for _, m := range ctlCmdRe.FindAllStringSubmatch(c, -1) {
		if !k.alicectl[m[1]] {
			bad("alicectl %s: not a command in the alicectl usage text", m[1])
		}
	}
	for _, m := range ctlCmdRe.FindAllStringIndex(c, -1) {
		for _, f := range flagRe.FindAllString(afterCommand(c[m[0]:]), -1) {
			if !k.flags["alicectl"][f] {
				bad("alicectl %s: not an option in the alicectl usage text", f)
			}
		}
	}
	for _, w := range aliceWords(c) {
		if !k.alice[w] {
			bad("alice %s: not a command in the alice usage text", w)
		}
	}
	for _, m := range scriptRe.FindAllStringSubmatchIndex(c, -1) {
		script := c[m[2]:m[3]]
		for _, f := range flagRe.FindAllString(afterCommand(c[m[3]:]), -1) {
			if !k.flags[script][f] {
				bad("%s %s: not an option in its usage text", script, f)
			}
		}
	}
	for _, m := range makeCmdRe.FindAllStringSubmatch(c, -1) {
		if !strings.Contains(m[1], "=") && !k.makeTarget[m[1]] {
			bad("make %s: not a target of the Makefile", m[1])
		}
	}
	return out
}

// afterCommand cuts text at the next shell separator, so the options of a following command are
// not read as the options of this one.
func afterCommand(s string) string {
	for _, sep := range []string{"&&", "||", ";", "|"} {
		if i := strings.Index(s, sep); i >= 0 {
			s = s[:i]
		}
	}
	return s
}

// aliceWords returns the word after each "alice" that is the Alice binary: at the start of a
// command, behind sudo, an environment assignment or a path, or the command run in the Compose
// service alice ("exec alice alice admin unlock"). The service name itself is not a command.
func aliceWords(c string) []string {
	var out []string
	for from := 0; ; {
		i := strings.Index(c[from:], "alice")
		if i < 0 {
			return out
		}
		i += from
		from = i + len("alice")
		end := from
		if end < len(c) && c[end] != ' ' && c[end] != '\t' {
			continue // alice-update.sh, alice_data, alice:dev, ...
		}
		tokStart := strings.LastIndexAny(c[:i], " \t") + 1
		isBinary := false
		switch {
		case tokStart < i:
			isBinary = strings.HasSuffix(c[tokStart:i], "/") // ./alice, /usr/local/bin/alice
		default:
			isBinary = isCommandStart(c, i) || previousToken(c, i) == "alice"
		}
		if !isBinary {
			continue
		}
		rest := strings.TrimLeft(c[from:], " \t")
		j := 0
		for j < len(rest) && (rest[j] >= 'a' && rest[j] <= 'z' || rest[j] == '-' && j > 0) {
			j++
		}
		if j > 0 && rest[0] != '-' && rest[:j] != "alice" {
			out = append(out, rest[:j])
		}
	}
}

func previousToken(s string, at int) string {
	f := strings.Fields(s[:at])
	if len(f) == 0 {
		return ""
	}
	return f[len(f)-1]
}

// isCommandStart reports whether position at begins a command: the start of the text or the first
// word after a shell separator, sudo or an environment assignment.
func isCommandStart(s string, at int) bool {
	before := strings.TrimRightFunc(s[:at], unicode.IsSpace)
	if before == "" {
		return true
	}
	for _, sep := range []string{"&&", "||", ";", "|", "(", "sudo"} {
		if strings.HasSuffix(before, sep) {
			return true
		}
	}
	last := previousToken(s, at)
	return strings.Contains(last, "=") && !strings.HasPrefix(last, "-")
}

func checkLink(root, rel, target string) string {
	switch {
	case strings.Contains(target, "://"), strings.HasPrefix(target, "mailto:"), target == "":
		return ""
	}
	path, frag, _ := strings.Cut(target, "#")
	file := rel
	if path != "" {
		if strings.HasPrefix(path, "/") {
			file = filepath.ToSlash(filepath.Clean(strings.TrimPrefix(path, "/")))
		} else {
			file = filepath.ToSlash(filepath.Join(filepath.Dir(rel), path))
		}
		if strings.HasPrefix(file, "../") {
			return fmt.Sprintf("link %q leaves the repository", target)
		}
		st, err := os.Stat(filepath.Join(root, filepath.FromSlash(file)))
		if err != nil {
			return fmt.Sprintf("link %q: %s does not exist", target, file)
		}
		if st.IsDir() {
			return ""
		}
	}
	if frag == "" || !strings.HasSuffix(file, ".md") {
		return ""
	}
	hs, err := headingAnchors(filepath.Join(root, filepath.FromSlash(file)))
	if err != nil {
		return fmt.Sprintf("link %q: %v", target, err)
	}
	if !hs[strings.Map(unicode.ToLower, frag)] {
		return fmt.Sprintf("link %q: no heading #%s in %s", target, frag, file)
	}
	return ""
}

// headingAnchors returns the GitHub-style anchors of the headings outside fenced blocks.
func headingAnchors(path string) (map[string]bool, error) {
	b, err := os.ReadFile(path) //nolint:gosec // repository file
	if err != nil {
		return nil, err
	}
	out := map[string]bool{}
	seen := map[string]int{}
	fenced := false
	for _, l := range strings.Split(string(b), "\n") {
		if strings.HasPrefix(strings.TrimSpace(l), "```") {
			fenced = !fenced
			continue
		}
		if fenced {
			continue
		}
		m := headingRe.FindStringSubmatch(l)
		if m == nil {
			continue
		}
		s := slug(m[1])
		if n := seen[s]; n > 0 {
			out[fmt.Sprintf("%s-%d", s, n)] = true
		} else {
			out[s] = true
		}
		seen[s]++
	}
	return out, nil
}

var mdLinkTextRe = regexp.MustCompile(`\[([^\]]*)\]\([^)]*\)`)

func slug(h string) string {
	h = mdLinkTextRe.ReplaceAllString(h, "$1")
	h = strings.NewReplacer("`", "", "*", "").Replace(strings.Map(unicode.ToLower, h))
	var b strings.Builder
	for _, r := range h {
		switch {
		case unicode.IsLetter(r) || unicode.IsDigit(r) || r == '_' || r == '-':
			b.WriteRune(r)
		case r == ' ':
			b.WriteByte('-')
		}
	}
	return b.String()
}

func checkRequired(root string) []string {
	const rel = "tools/docscheck/required.txt"
	b, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(rel))) //nolint:gosec // repository file
	if err != nil {
		return []string{rel + ": " + err.Error()}
	}
	var out []string
	for n, l := range strings.Split(string(b), "\n") {
		if strings.TrimSpace(l) == "" || strings.HasPrefix(l, "#") {
			continue
		}
		file, text, ok := strings.Cut(l, "\t")
		if !ok || file == "" || text == "" {
			out = append(out, fmt.Sprintf("%s:%d: not \"<file><TAB><required text>\"", rel, n+1))
			continue
		}
		c, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(file))) //nolint:gosec // repository file
		switch {
		case err != nil:
			out = append(out, fmt.Sprintf("%s:%d: %s does not exist", rel, n+1, file))
		case !strings.Contains(normalize(string(c)), normalize(text)):
			out = append(out, fmt.Sprintf("%s:%d: %s no longer contains %q", rel, n+1, file, text))
		}
	}
	return out
}

// normalize folds runs of white space, so a required sentence survives re-wrapping.
func normalize(s string) string { return strings.Join(strings.Fields(s), " ") }
