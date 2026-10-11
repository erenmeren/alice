// Command releasebuild stages, packs and checks Alice release packages (C5; spec §17.5, §18.1,
// SEC-107). It is run by make release, make release-pack, make release-test and
// make release-keycheck.
//
//	releasebuild stage -version V -out DIR -keys DIR ... [-test] [-allow-draft]
//	    Write the package tree DIR/alice/ with SHA256SUMS (unsigned).
//	releasebuild pack -stage DIR -out DIR
//	    After SHA256SUMS.sig exists: alice-<v>.tar.gz (deterministic) and alice-<v>.tar.gz.sha256.
//	releasebuild keycheck -release DIR -license FILE
//	    The release public keys are production keys and none of them is a license key (S-12).
//
// The stage refuses symbolic links among its inputs (S-7). Without -test every release key must
// be an rk-YYYY-NN key and the set must equal deploy/release/keys/; -test accepts rk-test-NN keys,
// only for a release candidate, and writes TEST_SIGNED=1 (S-11, R43 row 43). Without -allow-draft
// (the production path) a missing SECURITY-REPORT.md or guide, an empty or failing gates log and
// the draft license text are refused; with it they become placeholders that say so (M-6, R43 row
// 51). Tasks 17 and 18 and the vendor replace those placeholders with the real files.
package main

import (
	"archive/tar"
	"bufio"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"alice/internal/license"
	"alice/internal/license/issuer"
	"alice/internal/platform/db"
)

// draftLicense is the text of deploy/release/LICENSE.txt until the vendor replaces it (M-6).
const draftLicense = "Licensed to the customer under the terms of the signed order form; see your vendor."

// checklistUnsigned is the last line of RELEASE-CHECKLIST-SIGNED.txt until the vendor signs it.
const checklistUnsigned = "Signed: <empty until the vendor signs the checklist>"

// requiredGuides are the guides every customer package carries (spec §21; written by Task 17).
var requiredGuides = []string{"README.md", "api.md", "backup-restore.md", "install-guide.md", "security-overview.md", "upgrade.md"}

var (
	versionRe   = regexp.MustCompile(`^[0-9]+\.[0-9]+\.[0-9]+(-rc\.[0-9]+)?$`)
	rcVersionRe = regexp.MustCompile(`^[0-9]+\.[0-9]+\.[0-9]+-rc\.[0-9]+$`)
	commitRe    = regexp.MustCompile(`^[0-9a-f]{40}$`)
	imageRefRe  = regexp.MustCompile(`^[a-z0-9][a-z0-9._/-]{0,127}:[A-Za-z0-9._-]{1,128}$`)
	imageIDRe   = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)
)

// images is what the stage needs from Docker; tests replace it.
type images interface {
	ID(ref string) (string, error)
	Save(ref, path string) error
}

// dockerImages runs the docker CLI.
type dockerImages struct{}

func (dockerImages) ID(ref string) (string, error) {
	out, err := exec.CommandContext(context.Background(), "docker", "image", "inspect", "--format", "{{.Id}}", ref).Output() //nolint:gosec // G204: an image reference checked by imageRefRe
	if err != nil {
		return "", fmt.Errorf("docker image inspect %s: %w", ref, err)
	}
	return strings.TrimSpace(string(out)), nil
}

func (dockerImages) Save(ref, path string) error {
	cmd := exec.CommandContext(context.Background(), "docker", "save", "-o", path, ref) //nolint:gosec // G204: an image reference checked by imageRefRe
	cmd.Stdout, cmd.Stderr = os.Stderr, os.Stderr
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("docker save %s: %w", ref, err)
	}
	return nil
}

var newImages = func() images { return dockerImages{} }

func main() { os.Exit(run(os.Args[1:], os.Stdout, os.Stderr)) }

const usage = `Usage:
  releasebuild stage -version V -out DIR -keys DIR -alice-image REF -postgres-image REF -sbom DIR -notices FILE
                     -helper DIR -commit SHA -build-time RFC3339 -gates-log FILE -license FILE
                     -min-upgrade-from V [-root DIR] [-production-keys DIR] [-test] [-allow-draft]
  releasebuild pack -stage DIR -out DIR
  releasebuild keycheck -release DIR -license FILE
`

func run(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		_, _ = fmt.Fprint(stderr, usage)
		return 2
	}
	fs := flag.NewFlagSet("releasebuild "+args[0], flag.ContinueOnError)
	fs.SetOutput(stderr)
	var err error
	switch args[0] {
	case "stage":
		var c stageConfig
		fs.StringVar(&c.Root, "root", ".", "repository root (deploy/release, docs, CHANGELOG.md, SECURITY-REPORT.md, migrations)")
		fs.StringVar(&c.Version, "version", "", "release version x.y.z or x.y.z-rc.N")
		fs.StringVar(&c.Out, "out", "", "stage directory to create (the package is written to OUT/alice)")
		fs.StringVar(&c.Keys, "keys", "", "directory with the release public keys rk-*.pem")
		fs.StringVar(&c.ProductionKeys, "production-keys", "", "committed production keys (default ROOT/deploy/release/keys)")
		fs.StringVar(&c.AliceImage, "alice-image", "", "alice image reference")
		fs.StringVar(&c.PostgresImage, "postgres-image", "", "postgres image reference")
		fs.StringVar(&c.SBOM, "sbom", "", "directory with the three CycloneDX SBOMs")
		fs.StringVar(&c.Notices, "notices", "", "THIRD_PARTY_NOTICES.md")
		fs.StringVar(&c.Helper, "helper", "", "directory with the alice-helper binaries and alice-helper.sha256")
		fs.StringVar(&c.Commit, "commit", "", "40-hex commit")
		fs.StringVar(&c.BuildTime, "build-time", "", "RFC 3339 build time")
		fs.StringVar(&c.GatesLog, "gates-log", "", "bin/release-gates.log written by make release-gates")
		fs.StringVar(&c.License, "license", "", "Alice's license terms (licenses/LICENSE)")
		fs.StringVar(&c.MinUpgradeFrom, "min-upgrade-from", "", "oldest version that may update to this one")
		fs.BoolVar(&c.Test, "test", false, "test package: accept rk-test-NN keys, write TEST_SIGNED=1 (release candidates only)")
		fs.BoolVar(&c.AllowDraft, "allow-draft", false, "test package: placeholders for the security report, guides, gates log and license")
		if fs.Parse(args[1:]) != nil || fs.NArg() != 0 || c.Version == "" || c.Out == "" || c.Keys == "" {
			_, _ = fmt.Fprint(stderr, usage)
			return 2
		}
		if err = stage(c, newImages()); err == nil {
			_, _ = fmt.Fprintf(stdout, "Staged %s. Sign %s offline (licensectl release-sign), then make release-pack.\n",
				filepath.Join(c.Out, "alice"), filepath.Join(c.Out, "alice", "SHA256SUMS"))
		}
	case "pack":
		stageDir := fs.String("stage", "", "stage directory (holding alice/)")
		out := fs.String("out", "", "directory for alice-<v>.tar.gz and its .sha256")
		if fs.Parse(args[1:]) != nil || fs.NArg() != 0 || *stageDir == "" || *out == "" {
			_, _ = fmt.Fprint(stderr, usage)
			return 2
		}
		var tarPath string
		if tarPath, err = pack(*stageDir, *out); err == nil {
			_, _ = fmt.Fprintf(stdout, "Packed %s and %s.sha256. Sign the .sha256 offline (licensectl release-sign).\n", tarPath, tarPath)
		}
	case "keycheck":
		rel := fs.String("release", "", "directory with the release public keys")
		lic := fs.String("license", "", "the license key set (internal/license/keys/production.json)")
		if fs.Parse(args[1:]) != nil || fs.NArg() != 0 || *rel == "" || *lic == "" {
			_, _ = fmt.Fprint(stderr, usage)
			return 2
		}
		var msg string
		if msg, err = keycheck(*rel, *lic); err == nil {
			_, _ = fmt.Fprintln(stdout, msg)
		}
	default:
		_, _ = fmt.Fprint(stderr, usage)
		return 2
	}
	if err != nil {
		_, _ = fmt.Fprintln(stderr, "releasebuild "+args[0]+":", err)
		return 1
	}
	return 0
}

// stageConfig holds the inputs of a stage.
type stageConfig struct {
	Root, Out, Version, Keys, ProductionKeys string
	AliceImage, PostgresImage                string
	SBOM, Notices, Helper, GatesLog, License string
	Commit, BuildTime, MinUpgradeFrom        string
	AllowDraft, Test                         bool
}

// entry is one file of the package: copied from src, or written from data.
type entry struct {
	dst  string
	src  string
	data []byte
	mode os.FileMode
}

// regularFile fails unless path is a regular file (not a symbolic link, S-7).
func regularFile(p string) error {
	info, err := os.Lstat(p) //nolint:gosec // G703: an input path of the release build
	if err != nil {
		return err
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("%s is a symbolic link; the stage packages regular files only", p)
	}
	if !info.Mode().IsRegular() {
		return fmt.Errorf("%s is not a regular file", p)
	}
	return nil
}

// directory fails unless p is a directory (not a symbolic link to one).
func directory(p string) error {
	info, err := os.Lstat(p) //nolint:gosec // G703: an input path of the release build
	if err != nil {
		return err
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("%s is a symbolic link; the stage reads real directories only", p)
	}
	if !info.IsDir() {
		return fmt.Errorf("%s is not a directory", p)
	}
	return nil
}

// underRoot checks that every component of rel below root is a real directory or, at the end, a
// regular file, and returns the joined path.
func underRoot(root, rel string) (string, error) {
	parts := strings.Split(rel, "/")
	p := root
	for i, part := range parts {
		p = filepath.Join(p, part)
		if i < len(parts)-1 {
			if err := directory(p); err != nil {
				return "", err
			}
		}
	}
	return p, regularFile(p)
}

func (c *stageConfig) validate() error {
	switch {
	case !versionRe.MatchString(c.Version):
		return fmt.Errorf("version %q is not x.y.z or x.y.z-rc.N", c.Version)
	case c.AllowDraft && !c.Test:
		return errors.New("-allow-draft is for test packages only (-test); a customer release carries every real input")
	case c.Test && !rcVersionRe.MatchString(c.Version):
		return fmt.Errorf("a test-signed package must be a release candidate (x.y.z-rc.N), not %s", c.Version)
	case !versionRe.MatchString(c.MinUpgradeFrom):
		return fmt.Errorf("-min-upgrade-from %q is not a version", c.MinUpgradeFrom)
	case !commitRe.MatchString(c.Commit):
		return fmt.Errorf("-commit %q is not a 40-character commit hash", c.Commit)
	case !imageRefRe.MatchString(c.AliceImage) || !imageRefRe.MatchString(c.PostgresImage):
		return fmt.Errorf("image references %q and %q must look like name:tag", c.AliceImage, c.PostgresImage)
	}
	if _, err := time.Parse(time.RFC3339, c.BuildTime); err != nil {
		return fmt.Errorf("-build-time %q is not an RFC 3339 time", c.BuildTime)
	}
	if c.ProductionKeys == "" {
		c.ProductionKeys = filepath.Join(c.Root, "deploy", "release", "keys")
	}
	return nil
}

// stage writes the package tree cfg.Out/alice. Everything is checked before the first byte is
// written; the tree is built in a temporary directory beside cfg.Out and renamed into place, so a
// refused or failed stage leaves nothing behind.
func stage(cfg stageConfig, img images) error {
	if err := cfg.validate(); err != nil {
		return err
	}
	if _, err := os.Lstat(cfg.Out); err == nil {
		return fmt.Errorf("%s already exists; remove it first", cfg.Out)
	}
	entries, keyID, err := plan(cfg)
	if err != nil {
		return err
	}
	schema, err := schemaVersion(cfg.Root)
	if err != nil {
		return err
	}

	parent := filepath.Dir(cfg.Out)
	if err := os.MkdirAll(parent, 0o755); err != nil { //nolint:gosec // G301: the release output directory is world-readable (C2)
		return err
	}
	tmp, err := os.MkdirTemp(parent, "."+filepath.Base(cfg.Out)+".partial-")
	if err != nil {
		return err
	}
	ok := false
	defer func() {
		if !ok {
			_ = os.RemoveAll(tmp)
		}
	}()
	pkg := filepath.Join(tmp, "alice")
	for _, e := range entries {
		if err := writeEntry(pkg, e); err != nil {
			return err
		}
	}
	ids, err := saveImages(cfg, img, pkg)
	if err != nil {
		return err
	}
	release := fmt.Sprintf("VERSION=%s\nMIN_UPGRADE_FROM=%s\nSCHEMA_VERSION=%d\nALICE_IMAGE=%s\nALICE_IMAGE_ID=%s\nALICE_IMAGE_DIGEST=%s\n"+
		"POSTGRES_IMAGE=%s\nPOSTGRES_IMAGE_ID=%s\nPOSTGRES_IMAGE_DIGEST=%s\nBUILD_COMMIT=%s\nBUILD_TIME=%s\nRELEASE_KEY_ID=%s\n",
		cfg.Version, cfg.MinUpgradeFrom, schema, cfg.AliceImage, ids[0].config, ids[0].digest,
		cfg.PostgresImage, ids[1].config, ids[1].digest, cfg.Commit, cfg.BuildTime, keyID)
	if cfg.Test {
		release += "TEST_SIGNED=1\n"
	}
	if err := writeEntry(pkg, entry{dst: "RELEASE", data: []byte(release), mode: 0o644}); err != nil {
		return err
	}
	sums, err := checksums(pkg)
	if err != nil {
		return err
	}
	if err := writeEntry(pkg, entry{dst: "SHA256SUMS", data: sums, mode: 0o644}); err != nil {
		return err
	}
	if err := os.Chmod(tmp, 0o755); err != nil { //nolint:gosec // G302: a package directory is world-readable by design (C2)
		return err
	}
	if err := os.Rename(tmp, cfg.Out); err != nil {
		return err
	}
	ok = true
	return nil
}

// plan lists every file of the package except the images, RELEASE and SHA256SUMS, after checking
// that each input exists and is a regular file. It returns the release key ID for RELEASE.
func plan(cfg stageConfig) ([]entry, string, error) {
	var entries []entry
	add := func(dst, src string, mode os.FileMode) {
		entries = append(entries, entry{dst: dst, src: src, mode: mode})
	}
	if err := directory(cfg.Root); err != nil {
		return nil, "", err
	}
	for _, f := range []struct {
		src, dst string
		mode     os.FileMode
	}{
		{"deploy/release/install.sh", "install.sh", 0o755},
		{"deploy/release/alice-update.sh", "alice-update.sh", 0o755},
		{"deploy/release/alicectl", "alicectl", 0o755},
		{"deploy/release/lib/alice-lib.sh", "lib/alice-lib.sh", 0o644},
		{"deploy/release/postgres/initdb/10-alice-roles.sh", "lib/initdb/10-alice-roles.sh", 0o644},
		{"deploy/release/docker-compose.yml", "docker-compose.yml", 0o644},
		{"deploy/release/env.template", ".env.template", 0o644},
		{"CHANGELOG.md", "CHANGELOG.md", 0o644},
	} {
		p, err := underRoot(cfg.Root, f.src)
		if err != nil {
			return nil, "", err
		}
		add(f.dst, p, f.mode)
	}
	entries = append(entries, entry{dst: "VERSION", data: []byte(cfg.Version + "\n"), mode: 0o644})

	// SECURITY-REPORT.md (Task 18): required in production, a placeholder in a draft.
	report := filepath.Join(cfg.Root, "SECURITY-REPORT.md")
	if _, err := os.Lstat(report); errors.Is(err, fs.ErrNotExist) {
		if !cfg.AllowDraft {
			return nil, "", errors.New("SECURITY-REPORT.md is missing; a customer release needs it (only make release-test packages a placeholder)")
		}
		entries = append(entries, entry{dst: "SECURITY-REPORT.md", data: []byte("SECURITY-REPORT.md: not part of this test package\n"), mode: 0o644})
	} else if p, err := underRoot(cfg.Root, "SECURITY-REPORT.md"); err != nil {
		return nil, "", err
	} else {
		add("SECURITY-REPORT.md", p, 0o644)
	}

	docs, err := docEntries(cfg)
	if err != nil {
		return nil, "", err
	}
	entries = append(entries, docs...)

	// Alice's own license terms: the draft text only in a draft.
	if err := regularFile(cfg.License); err != nil {
		return nil, "", err
	}
	lic, err := os.ReadFile(cfg.License)
	if err != nil {
		return nil, "", err
	}
	if !cfg.AllowDraft && strings.TrimSpace(string(lic)) == draftLicense {
		return nil, "", fmt.Errorf("%s still holds the draft text; the vendor replaces it with the license terms before a customer release", cfg.License)
	}
	entries = append(entries, entry{dst: "licenses/LICENSE", data: lic, mode: 0o644})
	if err := regularFile(cfg.Notices); err != nil {
		return nil, "", err
	}
	add("licenses/THIRD_PARTY_NOTICES.md", cfg.Notices, 0o644)

	checklist, err := checklistFile(cfg)
	if err != nil {
		return nil, "", err
	}
	entries = append(entries, entry{dst: "RELEASE-CHECKLIST-SIGNED.txt", data: checklist, mode: 0o644})

	keys, keyID, err := keyEntries(cfg)
	if err != nil {
		return nil, "", err
	}
	entries = append(entries, keys...)

	helper, err := helperEntries(cfg.Helper)
	if err != nil {
		return nil, "", err
	}
	entries = append(entries, helper...)

	if err := directory(cfg.SBOM); err != nil {
		return nil, "", err
	}
	for _, name := range []string{"alice", "postgres", "source"} {
		f := name + "-" + cfg.Version + ".cdx.json"
		if err := regularFile(filepath.Join(cfg.SBOM, f)); err != nil {
			return nil, "", err
		}
		add("sbom/"+f, filepath.Join(cfg.SBOM, f), 0o644)
	}
	return entries, keyID, nil
}

// docEntries returns the top-level docs/*.md files and the required guides (placeholders in a
// draft, M-6).
func docEntries(cfg stageConfig) ([]entry, error) {
	dir := filepath.Join(cfg.Root, "docs")
	if err := directory(dir); err != nil {
		return nil, err
	}
	list, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}
	var out []entry
	have := map[string]bool{}
	for _, d := range list {
		if !strings.HasSuffix(d.Name(), ".md") || d.IsDir() {
			continue
		}
		p := filepath.Join(dir, d.Name())
		if err := regularFile(p); err != nil {
			return nil, err
		}
		have[d.Name()] = true
		out = append(out, entry{dst: "docs/" + d.Name(), src: p, mode: 0o644})
	}
	for _, g := range requiredGuides {
		if have[g] {
			continue
		}
		if !cfg.AllowDraft {
			return nil, fmt.Errorf("docs/%s is missing; a customer release carries every guide of spec §21", g)
		}
		out = append(out, entry{dst: "docs/" + g, data: []byte("docs/" + g + ": not part of this test package\n"), mode: 0o644})
	}
	return out, nil
}

// checklistFile writes RELEASE-CHECKLIST-SIGNED.txt from the gates log of make release-gates: a
// first line "commit\t<40 hex>" naming the commit the gates ran on (Task 12 review I-5), then one
// line "<gate>\t<exit status>\t<tool version>" per gate. It never claims a gate that did not run:
// the production stage refuses a log of another commit; a draft keeps it and names that commit.
func checklistFile(cfg stageConfig) ([]byte, error) {
	var b bytes.Buffer
	fmt.Fprintf(&b, "Alice %s release checklist\nCommit: %s\n", cfg.Version, cfg.Commit)
	raw, err := readGatesLog(cfg.GatesLog)
	if err != nil {
		return nil, err
	}
	var lines []string
	for _, l := range strings.Split(string(raw), "\n") {
		if strings.TrimSpace(l) != "" {
			lines = append(lines, l)
		}
	}
	gatesCommit := ""
	if len(lines) > 0 {
		if c, ok := strings.CutPrefix(lines[0], "commit\t"); ok && commitRe.MatchString(c) {
			gatesCommit, lines = c, lines[1:]
		} else if !cfg.AllowDraft {
			return nil, fmt.Errorf("the gates log %q does not start with the line commit\\t<40 hex>; run make release-gates again", cfg.GatesLog)
		}
	}
	if gatesCommit != "" && gatesCommit != cfg.Commit && !cfg.AllowDraft {
		return nil, fmt.Errorf("the gates log %s was recorded on commit %s, not %s; run make release-gates on this commit", cfg.GatesLog, gatesCommit, cfg.Commit)
	}
	if len(lines) == 0 {
		if !cfg.AllowDraft {
			return nil, fmt.Errorf("the gates log %q is missing or empty; run make release-gates before make release", cfg.GatesLog)
		}
		b.WriteString("No gate was recorded for this package.\n")
	} else {
		if gatesCommit == "" {
			b.WriteString("Gates recorded by make release-gates on an unrecorded commit:\n")
		} else {
			fmt.Fprintf(&b, "Gates recorded by make release-gates on commit %s:\n", gatesCommit)
		}
		for _, l := range lines {
			f := strings.Split(l, "\t")
			if len(f) != 3 || f[0] == "" {
				return nil, fmt.Errorf("the gates log line %q is not <gate>\\t<exit status>\\t<tool version>", l)
			}
			status, err := strconv.Atoi(f[1])
			if err != nil {
				return nil, fmt.Errorf("the gates log line %q has no exit status", l)
			}
			if status != 0 && !cfg.AllowDraft {
				return nil, fmt.Errorf("gate %s exited with %d; a customer release needs every gate to pass", f[0], status)
			}
			fmt.Fprintf(&b, "  %s: exit %d (%s)\n", f[0], status, f[2])
		}
	}
	b.WriteString(checklistUnsigned + "\n")
	return b.Bytes(), nil
}

// readGatesLog returns the gates log, or nothing when it does not exist.
func readGatesLog(p string) ([]byte, error) {
	if p == "" {
		return nil, nil
	}
	if _, err := os.Lstat(p); errors.Is(err, fs.ErrNotExist) {
		return nil, nil
	}
	if err := regularFile(p); err != nil {
		return nil, err
	}
	return os.ReadFile(p) //nolint:gosec // G304: path from the Makefile
}

// releaseKeys reads the rk-*.pem files of dir: name, content and public key, sorted by name.
type releaseKeyFile struct {
	id   string
	raw  []byte
	pub  ed25519.PublicKey
	name string
}

func readReleaseKeys(dir string, test bool) ([]releaseKeyFile, error) {
	if err := directory(dir); err != nil {
		return nil, err
	}
	list, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}
	var out []releaseKeyFile
	for _, d := range list {
		name := d.Name()
		if !strings.HasPrefix(name, "rk-") || !strings.HasSuffix(name, ".pem") {
			continue
		}
		p := filepath.Join(dir, name)
		if err := regularFile(p); err != nil {
			return nil, err
		}
		raw, err := os.ReadFile(p) //nolint:gosec // G304: a key directory named on the command line
		if err != nil {
			return nil, err
		}
		id, pub, err := issuer.ParseReleasePublicKey(raw)
		if err != nil {
			return nil, fmt.Errorf("%s is not a release public key: %w", p, err)
		}
		if id+".pem" != name {
			return nil, fmt.Errorf("%s says key-id %s; the file must be named after its key ID", p, id)
		}
		if !issuer.IsReleaseKeyID(id, test) {
			return nil, fmt.Errorf("%s is the test key %s; only make release-test (-test) packages a test key", p, id)
		}
		out = append(out, releaseKeyFile{id: id, raw: raw, pub: pub, name: name})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].name < out[j].name })
	return out, nil
}

// keyEntries returns release-keys/ and the RELEASE_KEY_ID (the newest key). Without -test the
// set must equal the committed production keys.
func keyEntries(cfg stageConfig) ([]entry, string, error) {
	keys, err := readReleaseKeys(cfg.Keys, cfg.Test)
	if err != nil {
		return nil, "", err
	}
	if len(keys) == 0 {
		return nil, "", fmt.Errorf("%s holds no release public key rk-*.pem", cfg.Keys)
	}
	if !cfg.Test {
		committed, err := readReleaseKeys(cfg.ProductionKeys, false)
		if err != nil {
			return nil, "", err
		}
		same := len(committed) == len(keys)
		for i := 0; same && i < len(keys); i++ {
			same = keys[i].name == committed[i].name && bytes.Equal(keys[i].raw, committed[i].raw)
		}
		if !same {
			return nil, "", fmt.Errorf("the release keys in %s differ from the committed ones in deploy/release/keys (%s)", cfg.Keys, cfg.ProductionKeys)
		}
	}
	var out []entry
	for _, k := range keys {
		out = append(out, entry{dst: "release-keys/" + k.name, data: k.raw, mode: 0o644})
	}
	return out, keys[len(keys)-1].id, nil
}

var helperFiles = []string{"alice-helper-linux-amd64", "alice-helper-linux-arm64"}

// helperEntries returns helper/ after checking the binaries against alice-helper.sha256.
func helperEntries(dir string) ([]entry, error) {
	if err := directory(dir); err != nil {
		return nil, err
	}
	sumsPath := filepath.Join(dir, "alice-helper.sha256")
	if err := regularFile(sumsPath); err != nil {
		return nil, err
	}
	raw, err := os.ReadFile(sumsPath) //nolint:gosec // G304: path from the Makefile
	if err != nil {
		return nil, err
	}
	want := map[string]string{}
	for _, l := range strings.Split(strings.TrimSpace(string(raw)), "\n") {
		if sum, name, ok := strings.Cut(l, "  "); ok {
			want[name] = sum
		}
	}
	out := []entry{{dst: "helper/alice-helper.sha256", src: sumsPath, mode: 0o644}}
	for _, name := range helperFiles {
		p := filepath.Join(dir, name)
		if err := regularFile(p); err != nil {
			return nil, err
		}
		got, err := fileSHA256(p)
		if err != nil {
			return nil, err
		}
		if want[name] != got {
			return nil, fmt.Errorf("%s does not match alice-helper.sha256; run make helper", p)
		}
		out = append(out, entry{dst: "helper/" + name, src: p, mode: 0o644})
	}
	return out, nil
}

// schemaVersion is the newest migration of root/migrations (RELEASE SCHEMA_VERSION).
func schemaVersion(root string) (int64, error) {
	dir := filepath.Join(root, "migrations")
	if err := directory(dir); err != nil {
		return 0, err
	}
	v, err := db.LatestVersion(os.DirFS(dir))
	if err != nil {
		return 0, err
	}
	if v < 1 {
		return 0, fmt.Errorf("%s holds no migration", dir)
	}
	return v, nil
}

// imageIDs are the two identifiers of one saved image (I-1): the config digest, which a classic
// image store reports as .Id after docker load, and the manifest or index digest, which a
// containerd image store reports. RELEASE carries both (ALICE_IMAGE_ID / ALICE_IMAGE_DIGEST) and
// the install and update scripts accept either.
type imageIDs struct{ config, digest string }

// saveImages writes images/alice-<v>.tar, images/postgres-<v>.tar and images/images.sha256 and
// returns the identifiers of the two images, read from the saved tars. The ID the build engine
// reports must be one of them.
func saveImages(cfg stageConfig, img images, pkg string) ([2]imageIDs, error) {
	var ids [2]imageIDs
	dir := filepath.Join(pkg, "images")
	if err := mkdirs(dir); err != nil {
		return ids, err
	}
	var sums strings.Builder
	for i, im := range []struct{ ref, file string }{
		{cfg.AliceImage, "alice-" + cfg.Version + ".tar"},
		{cfg.PostgresImage, "postgres-" + cfg.Version + ".tar"},
	} {
		id, err := img.ID(im.ref)
		if err != nil {
			return ids, err
		}
		if !imageIDRe.MatchString(id) {
			return ids, fmt.Errorf("the ID %q of %s is not sha256:<64 hex>", id, im.ref)
		}
		p := filepath.Join(dir, im.file)
		if err := img.Save(im.ref, p); err != nil {
			return ids, err
		}
		if err := os.Chmod(p, 0o644); err != nil { //nolint:gosec // G302: package files are world-readable (C2)
			return ids, err
		}
		got, err := savedImageIDs(p)
		if err != nil {
			return ids, fmt.Errorf("%s: %w", im.file, err)
		}
		if id != got.config && id != got.digest {
			return ids, fmt.Errorf("docker reports %s for %s, which is neither the config digest %s nor the manifest digest %s of the saved image",
				id, im.ref, got.config, got.digest)
		}
		sum, err := fileSHA256(p)
		if err != nil {
			return ids, err
		}
		sums.WriteString(sum + "  " + im.file + "\n")
		ids[i] = got
	}
	if err := writeEntry(pkg, entry{dst: "images/images.sha256", data: []byte(sums.String()), mode: 0o644}); err != nil {
		return ids, err
	}
	return ids, nil
}

// savedImageIDs reads manifest.json ([0].Config, "blobs/sha256/<hex>" or "<hex>.json") and
// index.json (manifests[0].digest) of a docker save tar. Each must name exactly one image.
func savedImageIDs(p string) (imageIDs, error) {
	var out imageIDs
	f, err := os.Open(p) //nolint:gosec // G304: an image tar of the new stage
	if err != nil {
		return out, err
	}
	defer func() { _ = f.Close() }()
	var manifest []struct{ Config string }
	var index struct {
		Manifests []struct{ Digest string } `json:"manifests"`
	}
	var haveManifest, haveIndex bool
	tr := tar.NewReader(f)
	for {
		h, err := tr.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return out, err
		}
		switch strings.TrimPrefix(h.Name, "./") {
		case "manifest.json":
			if err := json.NewDecoder(io.LimitReader(tr, 1<<20)).Decode(&manifest); err != nil {
				return out, fmt.Errorf("manifest.json: %w", err)
			}
			haveManifest = true
		case "index.json":
			if err := json.NewDecoder(io.LimitReader(tr, 1<<20)).Decode(&index); err != nil {
				return out, fmt.Errorf("index.json: %w", err)
			}
			haveIndex = true
		}
	}
	if !haveManifest || len(manifest) != 1 {
		return out, errors.New("the saved image has no manifest.json naming exactly one image")
	}
	if !haveIndex || len(index.Manifests) != 1 {
		return out, errors.New("the saved image has no index.json naming exactly one image (docker save of Docker 25 or later)")
	}
	hexID := strings.TrimSuffix(strings.TrimPrefix(manifest[0].Config, "blobs/sha256/"), ".json")
	out.config, out.digest = "sha256:"+hexID, index.Manifests[0].Digest
	if !imageIDRe.MatchString(out.config) || !imageIDRe.MatchString(out.digest) {
		return out, fmt.Errorf("the saved image names %q and %q, not sha256:<64 hex>", manifest[0].Config, out.digest)
	}
	return out, nil
}

func mkdirs(dir string) error {
	if err := os.MkdirAll(dir, 0o755); err != nil { //nolint:gosec // G301: package directories are world-readable (C2)
		return err
	}
	return os.Chmod(dir, 0o755) //nolint:gosec // G302: package directories are world-readable (C2)
}

// writeEntry writes one package file with its mode, independent of the umask.
func writeEntry(pkg string, e entry) (err error) {
	dst := filepath.Join(pkg, filepath.FromSlash(e.dst))
	for d := filepath.Dir(dst); ; d = filepath.Dir(d) {
		if err := mkdirs(d); err != nil {
			return err
		}
		if d == pkg || len(d) <= len(pkg) {
			break
		}
	}
	f, err := os.OpenFile(dst, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600) //nolint:gosec // G304: inside the new stage
	if err != nil {
		return err
	}
	defer func() {
		if cerr := f.Close(); err == nil {
			err = cerr
		}
	}()
	if e.src != "" {
		in, err := os.Open(e.src) //nolint:gosec // G304: a checked input of the stage
		if err != nil {
			return err
		}
		defer func() { _ = in.Close() }()
		if _, err := io.Copy(f, in); err != nil {
			return err
		}
	} else if _, err := f.Write(e.data); err != nil {
		return err
	}
	return f.Chmod(e.mode)
}

func fileSHA256(p string) (string, error) {
	f, err := os.Open(p) //nolint:gosec // G304: a file of the stage or its inputs
	if err != nil {
		return "", err
	}
	defer func() { _ = f.Close() }()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

// packageFiles lists the regular files under pkg (slash paths, sorted) and its directories; any
// other kind of entry is refused.
func packageFiles(pkg string) (files, dirs []string, err error) {
	err = filepath.WalkDir(pkg, func(p string, d fs.DirEntry, err error) error { //nolint:gosec // G703: the stage directory of the release build
		if err != nil {
			return err
		}
		rel, _ := filepath.Rel(pkg, p)
		rel = filepath.ToSlash(rel)
		info, err := os.Lstat(p)
		if err != nil {
			return err
		}
		switch {
		case info.Mode()&os.ModeSymlink != 0:
			return fmt.Errorf("%s is a symbolic link; a package holds regular files only", rel)
		case info.IsDir():
			if rel != "." {
				dirs = append(dirs, rel)
			}
		case info.Mode().IsRegular():
			files = append(files, rel)
		default:
			return fmt.Errorf("%s is not a regular file", rel)
		}
		return nil
	})
	sort.Strings(files)
	sort.Strings(dirs)
	return files, dirs, err
}

// checksums returns SHA256SUMS: one "<hex>  <path>" line per file, sorted by path, without
// SHA256SUMS and SHA256SUMS.sig.
func checksums(pkg string) ([]byte, error) {
	files, _, err := packageFiles(pkg)
	if err != nil {
		return nil, err
	}
	var b bytes.Buffer
	for _, f := range files {
		if f == "SHA256SUMS" || f == "SHA256SUMS.sig" {
			continue
		}
		sum, err := fileSHA256(filepath.Join(pkg, filepath.FromSlash(f)))
		if err != nil {
			return nil, err
		}
		b.WriteString(sum + "  " + f + "\n")
	}
	return b.Bytes(), nil
}

// verifyStage checks a signed stage as install.sh would (S-7 order): the signature of SHA256SUMS
// by a key of its release-keys/, then every checksum, then that the files are exactly the listed ones.
func verifyStage(pkg string) error {
	sums, err := os.ReadFile(filepath.Join(pkg, "SHA256SUMS")) //nolint:gosec // G304: the stage named on the command line
	if err != nil {
		return err
	}
	sig, err := os.ReadFile(filepath.Join(pkg, "SHA256SUMS.sig")) //nolint:gosec // G304: the stage named on the command line
	if errors.Is(err, fs.ErrNotExist) {
		return errors.New("the stage is not signed: SHA256SUMS.sig is missing (sign SHA256SUMS offline first)")
	}
	if err != nil {
		return err
	}
	keys, err := readReleaseKeys(filepath.Join(pkg, "release-keys"), true)
	if err != nil {
		return err
	}
	verified := false
	for _, k := range keys {
		if len(sig) == ed25519.SignatureSize && ed25519.Verify(k.pub, sums, sig) {
			verified = true
		}
	}
	if !verified {
		return errors.New("the SHA256SUMS signature does not verify with a key of release-keys/")
	}
	files, _, err := packageFiles(pkg)
	if err != nil {
		return err
	}
	want, err := checksums(pkg)
	if err != nil {
		return err
	}
	if !bytes.Equal(want, sums) {
		listed := map[string]string{}
		for _, l := range strings.Split(strings.TrimSpace(string(sums)), "\n") {
			sum, name, _ := strings.Cut(l, "  ")
			listed[name] = sum
		}
		for _, f := range files {
			if f == "SHA256SUMS" || f == "SHA256SUMS.sig" {
				continue
			}
			if _, ok := listed[f]; !ok {
				return fmt.Errorf("%s is not listed in SHA256SUMS", f)
			}
		}
		for _, l := range strings.Split(strings.TrimSpace(string(want)), "\n") {
			sum, name, _ := strings.Cut(l, "  ")
			if listed[name] != sum {
				return fmt.Errorf("%s changed after SHA256SUMS was written", name)
			}
		}
		return errors.New("SHA256SUMS does not match the stage")
	}
	return nil
}

// releaseValue reads KEY= from RELEASE.
func releaseValue(pkg, key string) (string, error) {
	f, err := os.Open(filepath.Join(pkg, "RELEASE")) //nolint:gosec // G304: the stage named on the command line
	if err != nil {
		return "", err
	}
	defer func() { _ = f.Close() }()
	s := bufio.NewScanner(f)
	for s.Scan() {
		if v, ok := strings.CutPrefix(s.Text(), key+"="); ok {
			return v, nil
		}
	}
	return "", fmt.Errorf("RELEASE has no %s", key)
}

// pack writes outDir/alice-<v>.tar.gz and its .sha256 from a signed stage. The archive is
// deterministic: entries sorted, every time BUILD_TIME, owner root (0/0), modes 0755 for
// directories and executables and 0644 for the rest, a gzip header without name or time.
func pack(stageDir, outDir string) (string, error) {
	pkg := filepath.Join(stageDir, "alice")
	if err := directory(pkg); err != nil {
		return "", err
	}
	if err := verifyStage(pkg); err != nil {
		return "", err
	}
	raw, err := os.ReadFile(filepath.Join(pkg, "VERSION")) //nolint:gosec // G304: the stage named on the command line
	if err != nil {
		return "", err
	}
	version := strings.TrimSpace(string(raw))
	if !versionRe.MatchString(version) {
		return "", fmt.Errorf("VERSION %q is not a version", version)
	}
	bt, err := releaseValue(pkg, "BUILD_TIME")
	if err != nil {
		return "", err
	}
	mtime, err := time.Parse(time.RFC3339, bt)
	if err != nil {
		return "", fmt.Errorf("RELEASE BUILD_TIME %q: %w", bt, err)
	}
	files, dirs, err := packageFiles(pkg)
	if err != nil {
		return "", err
	}
	name := "alice-" + version + ".tar.gz"
	tarPath, sumPath := filepath.Join(outDir, name), filepath.Join(outDir, name+".sha256")
	for _, p := range []string{tarPath, sumPath, sumPath + ".sig"} {
		if _, err := os.Lstat(p); err == nil { //nolint:gosec // G703: output paths of the release build
			return "", fmt.Errorf("%s already exists; remove it first", p)
		}
	}
	if err := os.MkdirAll(outDir, 0o755); err != nil { //nolint:gosec // G301: the release output directory is world-readable
		return "", err
	}
	sum, err := writeTarball(tarPath, pkg, files, dirs, mtime)
	if err != nil {
		_ = os.Remove(tarPath) //nolint:gosec // G703: the package this call was writing
		return "", err
	}
	f, err := os.OpenFile(sumPath, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o644) //nolint:gosec // G302,G304: the public checksum file
	if err != nil {
		return "", err
	}
	if _, err := fmt.Fprintf(f, "%s  %s\n", sum, name); err != nil {
		_ = f.Close()
		return "", err
	}
	return tarPath, f.Close()
}

func writeTarball(tarPath, pkg string, files, dirs []string, mtime time.Time) (sum string, err error) {
	out, err := os.OpenFile(tarPath, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o644) //nolint:gosec // G302,G304: the public package
	if err != nil {
		return "", err
	}
	defer func() {
		if cerr := out.Close(); err == nil {
			err = cerr
		}
	}()
	h := sha256.New()
	zw, err := gzip.NewWriterLevel(io.MultiWriter(out, h), gzip.BestCompression)
	if err != nil {
		return "", err
	}
	tw := tar.NewWriter(zw)
	type item struct {
		name string
		dir  bool
	}
	items := []item{{name: "alice/", dir: true}}
	for _, d := range dirs {
		items = append(items, item{name: "alice/" + d + "/", dir: true})
	}
	for _, f := range files {
		items = append(items, item{name: "alice/" + f})
	}
	sort.Slice(items, func(i, j int) bool { return items[i].name < items[j].name })
	for _, it := range items {
		hdr := &tar.Header{Name: it.name, ModTime: mtime, Uname: "root", Gname: "root", Format: tar.FormatUSTAR}
		if it.dir {
			hdr.Typeflag, hdr.Mode = tar.TypeDir, 0o755
			if err := tw.WriteHeader(hdr); err != nil {
				return "", err
			}
			continue
		}
		p := filepath.Join(pkg, filepath.FromSlash(strings.TrimPrefix(it.name, "alice/")))
		info, err := os.Lstat(p) //nolint:gosec // G703: a verified file of the stage
		if err != nil {
			return "", err
		}
		hdr.Typeflag, hdr.Size, hdr.Mode = tar.TypeReg, info.Size(), 0o644
		if info.Mode().Perm()&0o100 != 0 {
			hdr.Mode = 0o755
		}
		if err := tw.WriteHeader(hdr); err != nil {
			return "", err
		}
		if err := copyFile(tw, p); err != nil {
			return "", err
		}
	}
	if err := tw.Close(); err != nil {
		return "", err
	}
	if err := zw.Close(); err != nil {
		return "", err
	}
	if err := out.Sync(); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

func copyFile(w io.Writer, p string) error {
	f, err := os.Open(p) //nolint:gosec // G304: a verified file of the stage
	if err != nil {
		return err
	}
	defer func() { _ = f.Close() }()
	_, err = io.Copy(w, f)
	return err
}

// keycheck checks the release keys of releaseDir (production IDs only) against the license key
// set: compromise of one key must not compromise the other (spec §16.7, SEC-107, S-12).
func keycheck(releaseDir, licenseFile string) (string, error) {
	rel, err := readReleaseKeys(releaseDir, false)
	if err != nil {
		return "", err
	}
	if len(rel) == 0 {
		return "", fmt.Errorf("%s holds no release public key rk-*.pem", releaseDir)
	}
	raw, err := os.ReadFile(licenseFile) //nolint:gosec // G304: path from the Makefile
	if err != nil {
		return "", err
	}
	ks, err := license.ParseKeySet(raw)
	if err != nil {
		return "", err
	}
	for _, r := range rel {
		for _, l := range ks.Keys() {
			if bytes.Equal(r.pub, l.Key) {
				return "", fmt.Errorf("release key %s is the license key %s; the two must be separate keys (spec §16.7)", r.id, l.ID)
			}
		}
	}
	var ids []string
	for _, r := range rel {
		ids = append(ids, r.id+" "+issuer.ReleaseFingerprint(r.pub))
	}
	return fmt.Sprintf("release-keycheck: release keys (%s) and the %d license key(s) are disjoint", strings.Join(ids, ", "), ks.Len()), nil
}
