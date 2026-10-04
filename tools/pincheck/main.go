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
//     The YAML is also parsed: a job's container: and services.<name>.image: need @sha256:, and
//     every run: script is checked like a shell script (docker run / docker create, docker://).
//   - Every Dockerfile (Dockerfile, Dockerfile.*, *.Dockerfile, and the same forms of Containerfile,
//     in any letter case):
//     the "# syntax=" frontend, every
//     FROM and every COPY --from= / RUN --mount from= that names an image instead of an earlier
//     stage. "scratch" passes. FROM ${ARG} is resolved through the ARG default and fails when it
//     has none.
//   - Every Compose file (docker-compose*.yml, compose*.yml, and any other YAML file whose top-level
//     services: entries carry image: or build:): image: of a service without build:.
//   - The Makefile and shell scripts: the IMAGE operand of every docker run / docker create /
//     docker pull (options skipped, continuation lines joined, a trailing # comment ignored) must be
//     pinned (@sha256:),
//     one of the pinned Makefile variables, the locally built alice: image, or an image read from an
//     already running container (see imageOperandOK). The Makefile's GITLEAKS_IMAGE and TRIVY_IMAGE
//     must themselves be pinned.
//   - Go sources: Image: "..." and postgres.Run(ctx, "...") literals (also split over lines) must be
//     pinned, and every PostgreSQL literal must equal the image of the postgres service in
//     deploy/docker-compose.yml.
//
// docker compose run names a service, not an image: the service's image: is checked in its Compose
// file, so the operand of docker compose run is not an image reference and is not checked here.
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
	digestRe     = regexp.MustCompile(`@sha256:[0-9a-f]{64}(?:$|[^0-9a-f])`)
	actionSHARe  = regexp.MustCompile(`^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+(?:/[^@\s]+)?@[0-9a-f]{40}$`)
	versionRe    = regexp.MustCompile(`^#\s*v\d+(?:\.\d+)*\s*$`)
	usesRe       = regexp.MustCompile(`^\s*(?:-\s+)?uses:\s*(.*)$`)
	fromRe       = regexp.MustCompile(`(?i)^\s*FROM\s+(.*)$`)
	argRe        = regexp.MustCompile(`(?i)^\s*ARG\s+([A-Za-z_][A-Za-z0-9_]*)(?:=(.*))?$`)
	copyFromRe   = regexp.MustCompile(`(?i)^\s*(?:COPY|RUN)\b.*?--(?:from|mount=[^\s]*?\bfrom)=([^\s,]+)`)
	syntaxRe     = regexp.MustCompile(`(?i)^#\s*syntax\s*=\s*(\S+)`)
	goImageRe    = regexp.MustCompile(`\bImage:\s*"([^"]+)"`)
	pgRunRe      = regexp.MustCompile(`postgres\.Run\(\s*[A-Za-z_][A-Za-z0-9_.]*\s*,\s*"([^"]+)"`)
	makeVarRe    = regexp.MustCompile(`^(GITLEAKS_IMAGE|TRIVY_IMAGE)\s*[?:]?=\s*(\S+)`)
	dockerRunRe  = regexp.MustCompile(`\bdocker\s+(?:container\s+)?(?:run|create)\b`)
	dockerPullRe = regexp.MustCompile(`\bdocker\s+(?:image\s+)?pull\b`)
	dockerURLRe  = regexp.MustCompile(`docker://[^\s'"]+`)
	spaceRe      = regexp.MustCompile(`\s+`)
)

// skipDirs are never scanned: VCS data, dependencies, build output, and the working areas of the
// agents and plans (which hold copies of the repository).
var skipDirs = map[string]bool{
	".git": true, "node_modules": true, ".claude": true, ".superpowers": true,
	"bin": true, "dist": true, "vendor": true, "playwright-report": true, "test-results": true,
	"pincheck": true, // tools/pincheck holds deliberately unpinned samples in its tests
}

// imageOperandOK reports whether the image operand of a docker run / docker create may be used: a
// digest-pinned reference; $(GITLEAKS_IMAGE) or $(TRIVY_IMAGE), Makefile variables this tool requires
// to be pinned; alice:<tag>, the image this repository builds itself; or the image of a container
// that is already running, read with docker inspect -f '{{.Config.Image}}' (deploy/dev/check-hardening.sh
// re-runs the SSH target's own image). Only the operand itself counts: an alice: volume name or a
// digest elsewhere on the line does not.
func imageOperandOK(op string) bool {
	op = unquote(op)
	switch {
	case op == "":
		return false
	case digestRe.MatchString(op):
		return true
	case op == "$(GITLEAKS_IMAGE)" || op == "$(TRIVY_IMAGE)":
		return true
	case strings.HasPrefix(op, "alice:") && len(op) > len("alice:"):
		return true
	case strings.HasPrefix(op, "$(docker inspect ") && strings.HasSuffix(op, ")") && strings.Contains(op, "'{{.Config.Image}}'"):
		return true
	}
	return false
}

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
		case isDockerfile(name):
			out = append(out, checkDockerfile(path, rel)...)
		case isCompose(name) || looksLikeCompose(path, name):
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

// isDockerfile reports whether name is a Dockerfile or Containerfile name, in any letter case
// (Dockerfile, dockerfile, Dockerfile.dev, app.Dockerfile, app.dockerfile, ...).
func isDockerfile(name string) bool {
	for _, base := range []string{"Dockerfile", "Containerfile"} {
		n, b := len(name), len(base)
		switch {
		case strings.EqualFold(name, base):
			return true
		case n > b+1 && strings.EqualFold(name[:b+1], base+"."):
			return true
		case n > b+1 && strings.EqualFold(name[n-b-1:], "."+base):
			return true
		}
	}
	return false
}

// looksLikeCompose reports whether a YAML file not named like a Compose file still is one: its
// top-level services: mapping has an entry with image: or build:.
func looksLikeCompose(path, name string) bool {
	ext := filepath.Ext(name)
	if ext != ".yml" && ext != ".yaml" {
		return false
	}
	raw, err := os.ReadFile(path) //nolint:gosec // paths come from walking the repository
	if err != nil {
		return false
	}
	var doc struct {
		Services map[string]map[string]any `yaml:"services"`
	}
	if yaml.Unmarshal(raw, &doc) != nil {
		return false
	}
	for _, svc := range doc.Services {
		_, image := svc["image"]
		_, build := svc["build"]
		if image || build {
			return true
		}
	}
	return false
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
	return append(out, checkWorkflowYAML(path, rel)...)
}

// checkWorkflowYAML checks what a workflow or composite action pulls besides uses:: each job's
// container: and services.<name>.image:, and docker run / docker create / docker:// in run: scripts.
func checkWorkflowYAML(path, rel string) []string {
	raw, err := os.ReadFile(path) //nolint:gosec // paths come from walking the repository
	if err != nil {
		return []string{rel + ": " + err.Error()}
	}
	var root yaml.Node
	if err := yaml.Unmarshal(raw, &root); err != nil {
		return []string{rel + ": " + err.Error()}
	}
	if len(root.Content) == 0 {
		return nil
	}
	doc := deref(root.Content[0])
	var out []string
	checkSteps := func(steps *yaml.Node) {
		if steps == nil || steps.Kind != yaml.SequenceNode {
			return
		}
		for _, step := range steps.Content {
			if run := mapGet(deref(step), "run"); run != nil && run.Kind == yaml.ScalarNode {
				first := run.Line
				if run.Style&(yaml.LiteralStyle|yaml.FoldedStyle) != 0 {
					first++ // the script starts on the line after the | or > indicator
				}
				out = append(out, checkScript(rel, first, strings.Split(run.Value, "\n"))...)
			}
		}
	}
	if jobs := mapGet(doc, "jobs"); jobs != nil && jobs.Kind == yaml.MappingNode {
		for i := 0; i+1 < len(jobs.Content); i += 2 {
			name, job := jobs.Content[i].Value, deref(jobs.Content[i+1])
			if c := mapGet(job, "container"); c != nil {
				out = append(out, checkImageNode(rel, "job "+name+" container", c)...)
			}
			if svcs := mapGet(job, "services"); svcs != nil && svcs.Kind == yaml.MappingNode {
				for j := 0; j+1 < len(svcs.Content); j += 2 {
					out = append(out, checkImageNode(rel, "job "+name+" service "+svcs.Content[j].Value, svcs.Content[j+1])...)
				}
			}
			checkSteps(mapGet(job, "steps"))
		}
	}
	if runs := mapGet(doc, "runs"); runs != nil {
		checkSteps(mapGet(runs, "steps"))
	}
	return out
}

// checkImageNode checks a container: or service value: either the image string itself or a
// mapping with image:.
func checkImageNode(rel, what string, n *yaml.Node) []string {
	n = deref(n)
	if n.Kind == yaml.MappingNode {
		n = mapGet(n, "image")
		if n == nil {
			return nil
		}
	}
	if n.Kind != yaml.ScalarNode {
		return nil
	}
	pos := fmt.Sprintf("%s:%d", rel, n.Line)
	switch {
	case strings.Contains(n.Value, "${{"):
		return []string{fmt.Sprintf("%s: %s image %s is an expression; name a pinned image", pos, what, n.Value)}
	case !digestRe.MatchString(n.Value):
		return []string{fmt.Sprintf("%s: %s image %s is not pinned by @sha256:<digest>", pos, what, n.Value)}
	}
	return nil
}

func deref(n *yaml.Node) *yaml.Node {
	for n != nil && n.Kind == yaml.AliasNode {
		n = n.Alias
	}
	return n
}

// mapGet returns the value of key in a mapping node, or nil.
func mapGet(n *yaml.Node, key string) *yaml.Node {
	n = deref(n)
	if n == nil || n.Kind != yaml.MappingNode {
		return nil
	}
	for i := 0; i+1 < len(n.Content); i += 2 {
		if n.Content[i].Value == key {
			return deref(n.Content[i+1])
		}
	}
	return nil
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

// checkDockerRun checks each docker run / docker create statement of a Makefile or shell script.
func checkDockerRun(path, rel string) []string {
	lines, err := readLines(path)
	if err != nil {
		return []string{rel + ": " + err.Error()}
	}
	return checkScript(rel, 1, lines)
}

// checkScript checks the shell lines of a script whose first line is line first of rel:
// continuation lines are joined, a trailing comment is dropped, white space is collapsed, and the
// image operand of every docker run / docker create must pass imageOperandOK; every docker://
// reference needs a digest.
func checkScript(rel string, first int, lines []string) []string {
	var out []string
	for _, l := range joinContinued(lines) {
		text := spaceRe.ReplaceAllString(strings.TrimSpace(stripShellComment(l.text)), " ")
		pos := fmt.Sprintf("%s:%d", rel, first+l.n-1)
		for _, loc := range dockerRunRe.FindAllStringIndex(text, -1) {
			op := imageOperand(text[loc[1]:])
			if imageOperandOK(op) {
				continue
			}
			stmt := text[loc[0]:]
			if len(stmt) > 90 {
				stmt = stmt[:90] + "..."
			}
			out = append(out, fmt.Sprintf("%s: %q uses an image that is not pinned (use a digest, $(GITLEAKS_IMAGE), $(TRIVY_IMAGE) or alice:)", pos, stmt))
		}
		for _, loc := range dockerPullRe.FindAllStringIndex(text, -1) {
			if op := pullOperand(text[loc[1]:]); !imageOperandOK(op) {
				out = append(out, fmt.Sprintf("%s: docker pull %s is not pinned (use a digest, $(GITLEAKS_IMAGE), $(TRIVY_IMAGE) or alice:)", pos, op))
			}
		}
		for _, ref := range dockerURLRe.FindAllString(text, -1) {
			if !digestRe.MatchString(ref) {
				out = append(out, fmt.Sprintf("%s: %s is not pinned by @sha256:<digest>", pos, ref))
			}
		}
	}
	return out
}

// runFlagsWithoutValue are the docker run / docker create options that take no value; every other
// option without "=" takes the next word. An unknown option without a value therefore swallows the
// image and the check fails closed on the next word.
var runFlagsWithoutValue = map[string]bool{
	"--rm": true, "--detach": true, "--interactive": true, "--tty": true, "--init": true,
	"--privileged": true, "--read-only": true, "--publish-all": true, "--no-healthcheck": true,
	"--oom-kill-disable": true, "--sig-proxy": true, "--disable-content-trust": true, "--quiet": true,
	"--help": true, "--use-api-socket": true,
}

var shortFlagsRe = regexp.MustCompile(`^-[ditPq]+$`)

// imageOperand returns the image operand of the words after "docker run" / "docker create", or "".
func imageOperand(rest string) string {
	words := shellWords(rest)
	for i := 0; i < len(words); i++ {
		w := words[i]
		switch {
		case !strings.HasPrefix(w, "-"):
			return w
		case strings.Contains(w, "=") || runFlagsWithoutValue[w] || shortFlagsRe.MatchString(w):
		default:
			i++ // the option's value
		}
	}
	return ""
}

// pullFlagsWithoutValue are the docker pull options that take no value; every other option
// without "=" (--platform) takes the next word.
var pullFlagsWithoutValue = map[string]bool{
	"--all-tags": true, "-a": true, "--disable-content-trust": true, "--quiet": true, "-q": true,
}

// pullOperand returns the image operand of the words after "docker pull", or "".
func pullOperand(rest string) string {
	words := shellWords(rest)
	for i := 0; i < len(words); i++ {
		w := words[i]
		switch {
		case !strings.HasPrefix(w, "-"):
			return w
		case strings.Contains(w, "=") || pullFlagsWithoutValue[w]:
		default:
			i++ // the option's value
		}
	}
	return ""
}

// stripShellComment removes a "#" comment that starts a word outside quotes.
func stripShellComment(s string) string {
	quote := byte(0)
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case quote != 0:
			if c == '\\' && quote == '"' {
				i++
			} else if c == quote {
				quote = 0
			}
		case c == '\\':
			i++
		case c == '\'' || c == '"':
			quote = c
		case c == '#' && (i == 0 || s[i-1] == ' ' || s[i-1] == '\t'):
			return s[:i]
		}
	}
	return s
}

// shellWords splits the start of a shell statement into words, keeping quotes and $(...) inside a
// word, and stops at the end of the statement (; | & ) < >).
func shellWords(s string) []string {
	var words []string
	i := 0
	for i < len(s) {
		for i < len(s) && (s[i] == ' ' || s[i] == '\t') {
			i++
		}
		if i >= len(s) || strings.IndexByte(";|&)<>", s[i]) >= 0 {
			break
		}
		start := i
		i = scanWord(s, i)
		words = append(words, s[start:i])
	}
	return words
}

func scanWord(s string, i int) int {
	for i < len(s) {
		c := s[i]
		switch {
		case c == ' ' || c == '\t' || strings.IndexByte(";|&)<>", c) >= 0:
			return i
		case c == '\\':
			i += 2
		case c == '\'':
			j := strings.IndexByte(s[i+1:], '\'')
			if j < 0 {
				return len(s)
			}
			i += j + 2
		case c == '"':
			i = scanDouble(s, i+1)
		case c == '$' && i+1 < len(s) && s[i+1] == '(':
			i = scanParen(s, i+2)
		default:
			i++
		}
	}
	return min(i, len(s))
}

// scanDouble returns the index after the closing quote of a double-quoted string starting at i.
func scanDouble(s string, i int) int {
	for i < len(s) {
		switch {
		case s[i] == '\\':
			i += 2
		case s[i] == '"':
			return i + 1
		case s[i] == '$' && i+1 < len(s) && s[i+1] == '(':
			i = scanParen(s, i+2)
		default:
			i++
		}
	}
	return len(s)
}

// scanParen returns the index after the ")" that closes a $( or ( opened before i.
func scanParen(s string, i int) int {
	for i < len(s) {
		switch s[i] {
		case '\\':
			i += 2
		case '\'':
			j := strings.IndexByte(s[i+1:], '\'')
			if j < 0 {
				return len(s)
			}
			i += j + 2
		case '"':
			i = scanDouble(s, i+1)
		case '(':
			i = scanParen(s, i+1)
		case ')':
			return i + 1
		default:
			i++
		}
	}
	return len(s)
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
		src := string(b)
		// Whole-file matching: a literal on the line after "Image:" or "postgres.Run(ctx," counts.
		lineOf := func(idx int) int { return 1 + strings.Count(src[:idx], "\n") }
		for _, m := range goImageRe.FindAllStringSubmatchIndex(src, -1) {
			if img := src[m[2]:m[3]]; !digestRe.MatchString(img) {
				out = append(out, fmt.Sprintf("%s:%d: container image %s is not pinned by @sha256:<digest>", rel, lineOf(m[2]), img))
			}
		}
		for _, m := range pgRunRe.FindAllStringSubmatchIndex(src, -1) {
			img := src[m[2]:m[3]]
			switch {
			case !digestRe.MatchString(img):
				out = append(out, fmt.Sprintf("%s:%d: PostgreSQL image %s is not pinned by @sha256:<digest>", rel, lineOf(m[2]), img))
			case want != "" && img != want:
				out = append(out, fmt.Sprintf("%s:%d: PostgreSQL image %s differs from deploy/docker-compose.yml (%s); they are updated together", rel, lineOf(m[2]), img, want))
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
