// Command pincheck fails when an external build input is named by a mutable tag instead of an
// immutable identifier (audit AUD-09). It needs no network: it reads the files and compares text.
//
//	go run ./tools/pincheck [root]
//
// What it scans (root defaults to the current directory):
//
//   - GitHub workflows and local composite actions: every uses: is owner/repo[/path]@<40 hex> with
//     a "# v1.2.3" comment on the same line; ./local paths are in the repository and pass;
//     docker:// references need @sha256:.
//   - Every Dockerfile (Dockerfile, Dockerfile.*, *.Dockerfile): the "# syntax=" frontend, every
//     FROM and every COPY --from= / RUN --mount from= that names an image instead of an earlier
//     stage. "scratch" passes. FROM ${ARG} is resolved through the ARG default and fails when it
//     has none.
//   - Every Compose file (docker-compose*.yml, compose*.yml): image: of a service without build:.
//   - The Makefile and shell scripts: every docker run must name a pinned image (@sha256:), one of
//     the pinned Makefile variables, the locally built alice: image, or an image read from an
//     already running container (see runImageOK). The Makefile's GITLEAKS_IMAGE and TRIVY_IMAGE
//     must themselves be pinned.
//   - Go sources: Image: "..." and postgres.Run(ctx, "...") literals must be pinned, and every
//     PostgreSQL literal must equal the image of the postgres service in deploy/docker-compose.yml.
//
// Not scanned, by decision (docs/dev/dependency-updates.md): Go tools (version-pinned, covered by
// the module checksum database), the testcontainers Ryuk image (chosen by the library, not named
// here) and Playwright's browser download.
package main

import (
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"go.yaml.in/yaml/v3"
)

func main() {
	root := "."
	if len(os.Args) > 1 {
		root = os.Args[1]
	}
	problems := check(root)
	for _, p := range problems {
		fmt.Fprintln(os.Stderr, p)
	}
	if len(problems) > 0 {
		fmt.Fprintf(os.Stderr, "pincheck: %d unpinned reference(s); see docs/dev/dependency-updates.md\n", len(problems))
		os.Exit(1)
	}
}

var (
	digestRe    = regexp.MustCompile(`@sha256:[0-9a-f]{64}(?:$|[^0-9a-f])`)
	actionSHARe = regexp.MustCompile(`^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+(?:/[^@\s]+)?@[0-9a-f]{40}$`)
	versionRe   = regexp.MustCompile(`^#\s*v\d+(?:\.\d+)*\s*$`)
	usesRe      = regexp.MustCompile(`^\s*(?:-\s+)?uses:\s*(.*)$`)
	fromRe      = regexp.MustCompile(`(?i)^\s*FROM\s+(.*)$`)
	argRe       = regexp.MustCompile(`(?i)^\s*ARG\s+([A-Za-z_][A-Za-z0-9_]*)(?:=(.*))?$`)
	copyFromRe  = regexp.MustCompile(`(?i)^\s*(?:COPY|RUN)\b.*?--(?:from|mount=[^\s]*?\bfrom)=([^\s,]+)`)
	syntaxRe    = regexp.MustCompile(`(?i)^#\s*syntax\s*=\s*(\S+)`)
	goImageRe   = regexp.MustCompile(`\bImage:\s*"([^"]+)"`)
	pgRunRe     = regexp.MustCompile(`postgres\.Run\(\s*[A-Za-z_][A-Za-z0-9_.]*\s*,\s*"([^"]+)"`)
	makeVarRe   = regexp.MustCompile(`^(GITLEAKS_IMAGE|TRIVY_IMAGE)\s*[?:]?=\s*(\S+)`)
)

// skipDirs are never scanned: VCS data, dependencies, build output, and the working areas of the
// agents and plans (which hold copies of the repository).
var skipDirs = map[string]bool{
	".git": true, "node_modules": true, ".claude": true, ".superpowers": true,
	"bin": true, "dist": true, "vendor": true, "playwright-report": true, "test-results": true,
	"pincheck": true, // tools/pincheck holds deliberately unpinned samples in its tests
}

// runImageOK are the image operands a docker run may use besides a digest-pinned reference.
// $(GITLEAKS_IMAGE) and $(TRIVY_IMAGE) are Makefile variables this tool requires to be pinned.
// alice: is the image this repository builds itself. {{.Config.Image}} is the image of a container
// that is already running (deploy/dev/check-hardening.sh re-runs the target's own image).
var runImageOK = []string{"$(GITLEAKS_IMAGE)", "$(TRIVY_IMAGE)", " alice:", "{{.Config.Image}}"}

// check returns one message per unpinned reference found under root.
func check(root string) []string {
	var out []string
	var goFiles []string
	//nolint:gosec // root is the repository path given on the command line
	walkErr := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, _ := filepath.Rel(root, path)
		rel = filepath.ToSlash(rel)
		if d.IsDir() {
			if skipDirs[d.Name()] && rel != "." {
				return filepath.SkipDir
			}
			return nil
		}
		name := d.Name()
		switch {
		case isWorkflow(rel):
			out = append(out, checkWorkflow(path, rel)...)
		case name == "Dockerfile" || strings.HasPrefix(name, "Dockerfile.") || strings.HasSuffix(name, ".Dockerfile"):
			out = append(out, checkDockerfile(path, rel)...)
		case isCompose(name):
			out = append(out, checkCompose(path, rel)...)
		case name == "Makefile":
			out = append(out, checkMakefile(path, rel)...)
			out = append(out, checkDockerRun(path, rel)...)
		case strings.HasSuffix(name, ".sh"):
			out = append(out, checkDockerRun(path, rel)...)
		case strings.HasSuffix(name, ".go"):
			goFiles = append(goFiles, path)
		}
		return nil
	})
	if walkErr != nil {
		out = append(out, "pincheck: "+walkErr.Error())
	}
	out = append(out, checkGo(root, goFiles)...)
	sort.Strings(out)
	return out
}

func isWorkflow(rel string) bool {
	ext := filepath.Ext(rel)
	if ext != ".yml" && ext != ".yaml" {
		return false
	}
	return strings.HasPrefix(rel, ".github/workflows/") || (strings.HasPrefix(rel, ".github/actions/") && (strings.HasSuffix(rel, "/action.yml") || strings.HasSuffix(rel, "/action.yaml")))
}

func isCompose(name string) bool {
	ext := filepath.Ext(name)
	if ext != ".yml" && ext != ".yaml" {
		return false
	}
	return strings.HasPrefix(name, "docker-compose") || strings.HasPrefix(name, "compose")
}

func readLines(path string) ([]string, error) {
	b, err := os.ReadFile(path) //nolint:gosec // paths come from walking the repository
	if err != nil {
		return nil, err
	}
	return strings.Split(strings.ReplaceAll(string(b), "\r\n", "\n"), "\n"), nil
}

// joinContinued joins backslash-continued lines into one logical line and keeps the number of the
// first physical line.
type logical struct {
	n    int
	text string
}

func joinContinued(lines []string) []logical {
	var out []logical
	for i := 0; i < len(lines); i++ {
		start := i + 1
		text := lines[i]
		for strings.HasSuffix(strings.TrimRight(text, " \t"), "\\") && i+1 < len(lines) {
			text = strings.TrimSuffix(strings.TrimRight(text, " \t"), "\\") + " " + strings.TrimSpace(lines[i+1])
			i++
		}
		out = append(out, logical{start, text})
	}
	return out
}

func checkWorkflow(path, rel string) []string {
	lines, err := readLines(path)
	if err != nil {
		return []string{rel + ": " + err.Error()}
	}
	var out []string
	for i, line := range lines {
		m := usesRe.FindStringSubmatch(line)
		if m == nil {
			continue
		}
		val, comment := splitComment(m[1])
		val = unquote(stripAnchor(val))
		if val == "" || strings.HasPrefix(val, "*") {
			continue // an alias of an anchor whose definition is checked where it is written
		}
		pos := fmt.Sprintf("%s:%d", rel, i+1)
		switch {
		case strings.HasPrefix(val, "./") || strings.HasPrefix(val, "../"):
			// a path inside this repository
		case strings.HasPrefix(val, "docker://"):
			if !digestRe.MatchString(val) {
				out = append(out, fmt.Sprintf("%s: uses %s is not pinned by @sha256:<digest>", pos, val))
			}
		case !actionSHARe.MatchString(val):
			out = append(out, fmt.Sprintf("%s: uses %s is not pinned by a full 40-character commit SHA", pos, val))
		case !versionRe.MatchString(comment):
			out = append(out, fmt.Sprintf("%s: uses %s lacks a trailing \"# v1.2.3\" version comment", pos, val))
		}
	}
	return out
}

// splitComment splits a YAML scalar line tail into its value and a trailing "# comment".
func splitComment(s string) (value, comment string) {
	s = strings.TrimSpace(s)
	if len(s) > 0 && (s[0] == '"' || s[0] == '\'') {
		if end := strings.IndexByte(s[1:], s[0]); end >= 0 {
			return s[:end+2], strings.TrimSpace(s[end+2:])
		}
	}
	if i := strings.Index(s, " #"); i >= 0 {
		return strings.TrimSpace(s[:i]), strings.TrimSpace(s[i+1:])
	}
	if strings.HasPrefix(s, "#") {
		return "", s
	}
	return s, ""
}

func stripAnchor(s string) string {
	s = strings.TrimSpace(s)
	for strings.HasPrefix(s, "&") || strings.HasPrefix(s, "!") {
		i := strings.IndexAny(s, " \t")
		if i < 0 {
			return ""
		}
		s = strings.TrimSpace(s[i:])
	}
	return s
}

func unquote(s string) string {
	if len(s) >= 2 && (s[0] == '"' || s[0] == '\'') && s[len(s)-1] == s[0] {
		return s[1 : len(s)-1]
	}
	return s
}

func checkDockerfile(path, rel string) []string {
	lines, err := readLines(path)
	if err != nil {
		return []string{rel + ": " + err.Error()}
	}
	var out []string
	var stages []string
	args := map[string]string{}
	seenFrom := false
	for i, line := range lines {
		if m := syntaxRe.FindStringSubmatch(strings.TrimSpace(line)); m != nil && !digestRe.MatchString(m[1]) {
			out = append(out, fmt.Sprintf("%s:%d: syntax frontend %s is not pinned by @sha256:<digest>", rel, i+1, m[1]))
		}
	}
	for _, l := range joinContinued(lines) {
		text := strings.TrimSpace(l.text)
		if text == "" || strings.HasPrefix(text, "#") {
			continue
		}
		pos := fmt.Sprintf("%s:%d", rel, l.n)
		if m := argRe.FindStringSubmatch(text); m != nil && !seenFrom {
			args[m[1]] = unquote(strings.TrimSpace(m[2]))
			continue
		}
		if m := fromRe.FindStringSubmatch(text); m != nil {
			seenFrom = true
			image, stage := parseFrom(m[1])
			if isStage(stages, image) || strings.EqualFold(image, "scratch") {
				// an earlier stage of this file, or the empty image
			} else if resolved, ok := resolveArgs(image, args); !ok {
				out = append(out, fmt.Sprintf("%s: FROM %s uses a build argument without a default; the base cannot be checked", pos, image))
			} else if !digestRe.MatchString(resolved) && !strings.EqualFold(resolved, "scratch") && !isStage(stages, resolved) {
				out = append(out, fmt.Sprintf("%s: FROM %s is not pinned by @sha256:<digest>", pos, image))
			}
			if stage != "" {
				stages = append(stages, stage)
			}
			// a later FROM or --from= may name this stage
			continue
		}
		if m := copyFromRe.FindStringSubmatch(text); m != nil {
			ref := m[1]
			if _, numeric := atoi(ref); numeric || isStage(stages, ref) {
				continue
			}
			if !digestRe.MatchString(ref) {
				out = append(out, fmt.Sprintf("%s: --from=%s names an image that is not pinned by @sha256:<digest>", pos, ref))
			}
		}
	}
	return out
}

func isStage(stages []string, name string) bool {
	for _, s := range stages {
		if strings.EqualFold(s, name) {
			return true
		}
	}
	return false
}

func atoi(s string) (int, bool) {
	n := 0
	if s == "" {
		return 0, false
	}
	for _, r := range s {
		if r < '0' || r > '9' {
			return 0, false
		}
		n = n*10 + int(r-'0')
	}
	return n, true
}

// parseFrom returns the image and the stage name of the operands of a FROM instruction.
func parseFrom(operands string) (image, stage string) {
	f := strings.Fields(operands)
	for len(f) > 0 && strings.HasPrefix(f[0], "--") {
		f = f[1:]
	}
	if len(f) == 0 {
		return "", ""
	}
	image = f[0]
	if len(f) >= 3 && strings.EqualFold(f[1], "AS") {
		stage = f[2]
	}
	return image, stage
}

var argRefRe = regexp.MustCompile(`\$\{([A-Za-z_][A-Za-z0-9_]*)(?::?-([^}]*))?\}|\$([A-Za-z_][A-Za-z0-9_]*)`)

// resolveArgs substitutes ARG defaults into image; ok is false when a reference has no default.
func resolveArgs(image string, args map[string]string) (string, bool) {
	ok := true
	res := argRefRe.ReplaceAllStringFunc(image, func(m string) string {
		sm := argRefRe.FindStringSubmatch(m)
		name := sm[1]
		if name == "" {
			name = sm[3]
		}
		if v, found := args[name]; found && v != "" {
			return v
		}
		if sm[2] != "" {
			return sm[2]
		}
		ok = false
		return m
	})
	return res, ok
}

type composeSvc struct {
	Image string `yaml:"image"`
	Build any    `yaml:"build"`
}

func checkCompose(path, rel string) []string {
	raw, err := os.ReadFile(path) //nolint:gosec // paths come from walking the repository
	if err != nil {
		return []string{rel + ": " + err.Error()}
	}
	var doc struct {
		Services map[string]composeSvc `yaml:"services"`
	}
	if err := yaml.Unmarshal(raw, &doc); err != nil {
		return []string{rel + ": " + err.Error()}
	}
	var out []string
	for name, svc := range doc.Services {
		if svc.Build != nil || svc.Image == "" {
			continue // built here, or no image at all (an override file)
		}
		if !digestRe.MatchString(svc.Image) {
			out = append(out, fmt.Sprintf("%s: service %s image %s is not pinned by @sha256:<digest>", rel, name, svc.Image))
		}
	}
	return out
}

func checkMakefile(path, rel string) []string {
	lines, err := readLines(path)
	if err != nil {
		return []string{rel + ": " + err.Error()}
	}
	found := map[string]bool{}
	var out []string
	for _, l := range joinContinued(lines) {
		m := makeVarRe.FindStringSubmatch(l.text)
		if m == nil {
			continue
		}
		found[m[1]] = true
		if !digestRe.MatchString(m[2]) {
			out = append(out, fmt.Sprintf("%s:%d: %s is not pinned by @sha256:<digest>", rel, l.n, m[1]))
		}
	}
	for _, v := range []string{"GITLEAKS_IMAGE", "TRIVY_IMAGE"} {
		if !found[v] {
			out = append(out, fmt.Sprintf("%s: %s is not defined; the tool images must be pinned variables", rel, v))
		}
	}
	return out
}

// checkDockerRun checks each docker run statement of a Makefile or shell script, continuation lines
// joined: it must carry an image operand from runImageOK or a digest-pinned reference.
func checkDockerRun(path, rel string) []string {
	lines, err := readLines(path)
	if err != nil {
		return []string{rel + ": " + err.Error()}
	}
	var out []string
	for _, l := range joinContinued(lines) {
		text := strings.TrimSpace(l.text)
		if strings.HasPrefix(text, "#") {
			continue
		}
		idx := strings.Index(text, "docker run")
		if idx < 0 {
			continue
		}
		stmt := text[idx:]
		ok := digestRe.MatchString(stmt)
		for _, allowed := range runImageOK {
			if strings.Contains(stmt, allowed) {
				ok = true
			}
		}
		if !ok {
			if len(stmt) > 90 {
				stmt = stmt[:90] + "..."
			}
			out = append(out, fmt.Sprintf("%s:%d: %q uses an image that is not pinned (use a digest, $(GITLEAKS_IMAGE), $(TRIVY_IMAGE) or alice:)", rel, l.n, stmt))
		}
	}
	return out
}

func checkGo(root string, files []string) []string {
	var out []string
	want := composePostgres(root)
	for _, path := range files {
		b, err := os.ReadFile(path) //nolint:gosec // paths come from walking the repository
		if err != nil {
			out = append(out, path+": "+err.Error())
			continue
		}
		rel, _ := filepath.Rel(root, path)
		rel = filepath.ToSlash(rel)
		for i, line := range strings.Split(string(b), "\n") {
			for _, m := range goImageRe.FindAllStringSubmatch(line, -1) {
				if !digestRe.MatchString(m[1]) {
					out = append(out, fmt.Sprintf("%s:%d: container image %s is not pinned by @sha256:<digest>", rel, i+1, m[1]))
				}
			}
			for _, m := range pgRunRe.FindAllStringSubmatch(line, -1) {
				switch {
				case !digestRe.MatchString(m[1]):
					out = append(out, fmt.Sprintf("%s:%d: PostgreSQL image %s is not pinned by @sha256:<digest>", rel, i+1, m[1]))
				case want != "" && m[1] != want:
					out = append(out, fmt.Sprintf("%s:%d: PostgreSQL image %s differs from deploy/docker-compose.yml (%s); they are updated together", rel, i+1, m[1], want))
				}
			}
		}
	}
	return out
}

// composePostgres returns the image of the postgres service in deploy/docker-compose.yml, or "".
func composePostgres(root string) string {
	raw, err := os.ReadFile(filepath.Join(root, "deploy", "docker-compose.yml")) //nolint:gosec // fixed path under root
	if err != nil {
		return ""
	}
	var doc struct {
		Services map[string]composeSvc `yaml:"services"`
	}
	if yaml.Unmarshal(raw, &doc) != nil {
		return ""
	}
	return doc.Services["postgres"].Image
}
