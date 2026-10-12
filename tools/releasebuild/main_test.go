package main

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"alice/internal/license/issuer"
)

const (
	testCommit    = "0123456789abcdef0123456789abcdef01234567"
	testBuildTime = "2026-10-11T08:00:00Z"
)

// fakeImages stands in for docker. Save writes a small docker-save tar (manifest.json with the
// config digest, index.json with the manifest digest); ID returns what the engine would report:
// the manifest digest on a containerd image store (the default here), the config digest on a
// classic store (classic), or something else (id).
type fakeImages struct {
	saved   []string
	classic bool
	id      string
	noIndex bool
}

func fakeDigest(kind, ref string) string {
	sum := sha256.Sum256([]byte(kind + " " + ref))
	return "sha256:" + hex.EncodeToString(sum[:])
}

func (f *fakeImages) ID(ref string) (string, error) {
	switch {
	case f.id != "":
		return f.id, nil
	case f.classic:
		return fakeDigest("config", ref), nil
	}
	return fakeDigest("index", ref), nil
}

func (f *fakeImages) Save(ref, path string) error {
	f.saved = append(f.saved, ref)
	var b bytes.Buffer
	tw := tar.NewWriter(&b)
	add := func(name, body string) {
		_ = tw.WriteHeader(&tar.Header{Name: name, Mode: 0o644, Size: int64(len(body)), Typeflag: tar.TypeReg})
		_, _ = tw.Write([]byte(body))
	}
	cfg := strings.TrimPrefix(fakeDigest("config", ref), "sha256:")
	add("blobs/sha256/"+cfg, "{}")
	add("manifest.json", `[{"Config":"blobs/sha256/`+cfg+`","RepoTags":["`+ref+`"],"Layers":[]}]`)
	if !f.noIndex {
		add("index.json", `{"schemaVersion":2,"manifests":[{"mediaType":"application/vnd.oci.image.index.v1+json","digest":"`+
			fakeDigest("index", ref)+`","size":1}]}`)
	}
	if err := tw.Close(); err != nil {
		return err
	}
	return os.WriteFile(path, b.Bytes(), 0o600)
}

func write(t *testing.T, path, content string, mode os.FileMode) {
	t.Helper()
	require.NoError(t, os.MkdirAll(filepath.Dir(path), 0o755))
	require.NoError(t, os.WriteFile(path, []byte(content), mode))
}

func releaseKey(t *testing.T, dir, id string) ed25519.PrivateKey {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(nil)
	require.NoError(t, err)
	raw, err := issuer.EncodeReleasePublicKey(id, pub)
	require.NoError(t, err)
	write(t, filepath.Join(dir, id+".pem"), string(raw), 0o644)
	return priv
}

var requiredGuideNames = []string{"README.md", "api.md", "backup-restore.md", "install-guide.md", "security-overview.md", "upgrade.md"}

// fixture builds every input of the production stage in a temporary repository root and returns
// the configuration that stages it, and the release private key.
func fixture(t *testing.T) (stageConfig, ed25519.PrivateKey) {
	t.Helper()
	root := t.TempDir()
	for name, content := range map[string]string{
		"deploy/release/install.sh":                        "#!/usr/bin/env bash\necho install\n",
		"deploy/release/alice-update.sh":                   "#!/usr/bin/env bash\necho update\n",
		"deploy/release/alicectl":                          "#!/usr/bin/env bash\necho ctl\n",
		"deploy/release/lib/alice-lib.sh":                  "# lib\n",
		"deploy/release/postgres/initdb/10-alice-roles.sh": "# roles\n",
		"deploy/release/docker-compose.yml":                "services: {}\n",
		"deploy/release/env.template":                      "ALICE_PORT=443\n",
		"deploy/release/LICENSE.txt":                       "Alice license terms of Example Vendor.\n",
		"deploy/release/keys/README.md":                    "public keys\n",
		"docs/operator-guide.md":                           "# Operator\n",
		"docs/release-checklist.md":                        "# Vendor gate (final review B M-7)\n",
		"docs/notes.txt":                                   "not a guide\n",
		"docs/dev/inner.md":                                "not top level\n",
		"CHANGELOG.md":                                     "# Changelog\n",
		"SECURITY-REPORT.md":                               "# Security report\n",
		"migrations/00001_init.sql":                        "-- +goose Up\n",
		"migrations/00012_phase8.sql":                      "-- +goose Up\n",
		"bin/THIRD_PARTY_NOTICES.md":                       "# Notices\n",
		"bin/IMAGE_NOTICES.md":                             imageNotices("alice:1.0.0", "alice-postgres:1.0.0"),
		"bin/release-gates.log":                            fullGatesLog(testCommit),
		"bin/sbom/alice-1.0.0.cdx.json":                    "{}\n",
		"bin/sbom/postgres-1.0.0.cdx.json":                 "{}\n",
		"bin/sbom/source-1.0.0.cdx.json":                   "{}\n",
		"bin/helper/alice-helper-linux-amd64":              "amd64 binary",
		"bin/helper/alice-helper-linux-arm64":              "arm64 binary",
	} {
		write(t, filepath.Join(root, name), content, 0o644)
	}
	for _, g := range requiredGuideNames {
		write(t, filepath.Join(root, "docs", g), "# "+g+"\n", 0o644)
	}
	sums := ""
	for _, a := range []string{"amd64", "arm64"} {
		sum := sha256.Sum256([]byte(a + " binary"))
		sums += hex.EncodeToString(sum[:]) + "  alice-helper-linux-" + a + "\n"
	}
	write(t, filepath.Join(root, "bin/helper/alice-helper.sha256"), sums, 0o644)
	priv := releaseKey(t, filepath.Join(root, "deploy/release/keys"), "rk-2026-01")
	return stageConfig{
		Root: root, Out: filepath.Join(t.TempDir(), "alice-1.0.0"), Version: "1.0.0",
		Keys: filepath.Join(root, "deploy/release/keys"), AliceImage: "alice:1.0.0", PostgresImage: "alice-postgres:1.0.0",
		SBOM: filepath.Join(root, "bin/sbom"), Notices: filepath.Join(root, "bin/THIRD_PARTY_NOTICES.md"),
		ImageNotices: filepath.Join(root, "bin/IMAGE_NOTICES.md"),
		Helper:       filepath.Join(root, "bin/helper"), Commit: testCommit, BuildTime: testBuildTime,
		GatesLog: filepath.Join(root, "bin/release-gates.log"), License: filepath.Join(root, "deploy/release/LICENSE.txt"),
		MinUpgradeFrom: "1.0.0-rc.1",
	}, priv
}

// listFiles returns the regular files under dir (relative, sorted) with their modes.
func listFiles(t *testing.T, dir string) map[string]os.FileMode {
	t.Helper()
	out := map[string]os.FileMode{}
	require.NoError(t, filepath.WalkDir(dir, func(p string, d fs.DirEntry, err error) error {
		require.NoError(t, err)
		info, err := os.Lstat(p)
		require.NoError(t, err)
		rel, _ := filepath.Rel(dir, p)
		if d.IsDir() {
			assert.Equal(t, os.FileMode(0o755), info.Mode().Perm(), rel)
			return nil
		}
		require.True(t, info.Mode().IsRegular(), rel)
		out[filepath.ToSlash(rel)] = info.Mode().Perm()
		return nil
	}))
	return out
}

func readFile(t *testing.T, path string) string {
	t.Helper()
	b, err := os.ReadFile(path)
	require.NoError(t, err)
	return string(b)
}

func TestStageLayout(t *testing.T) {
	cfg, _ := fixture(t)
	img := &fakeImages{}
	require.NoError(t, stage(cfg, img))
	assert.Equal(t, []string{"alice:1.0.0", "alice-postgres:1.0.0"}, img.saved)

	pkg := filepath.Join(cfg.Out, "alice")
	files := listFiles(t, pkg)
	want := []string{
		".env.template", "CHANGELOG.md", "RELEASE", "RELEASE-CHECKLIST-SIGNED.txt", "SECURITY-REPORT.md", "SHA256SUMS", "VERSION",
		"alice-update.sh", "alicectl", "docker-compose.yml",
		"docs/README.md", "docs/api.md", "docs/backup-restore.md", "docs/install-guide.md", "docs/operator-guide.md",
		"docs/security-overview.md", "docs/upgrade.md",
		"helper/alice-helper-linux-amd64", "helper/alice-helper-linux-arm64", "helper/alice-helper.sha256",
		"images/alice-1.0.0.tar", "images/images.sha256", "images/postgres-1.0.0.tar",
		"install.sh", "lib/alice-lib.sh", "lib/initdb/10-alice-roles.sh",
		"licenses/IMAGE_NOTICES.md", "licenses/LICENSE", "licenses/THIRD_PARTY_NOTICES.md",
		"release-keys/rk-2026-01.pem",
		"sbom/alice-1.0.0.cdx.json", "sbom/postgres-1.0.0.cdx.json", "sbom/source-1.0.0.cdx.json",
	}
	got := make([]string, 0, len(files))
	for f, mode := range files {
		got = append(got, f)
		wantMode := os.FileMode(0o644)
		if f == "install.sh" || f == "alice-update.sh" || f == "alicectl" {
			wantMode = 0o755
		}
		assert.Equal(t, wantMode, mode, f)
	}
	sort.Strings(got)
	assert.Equal(t, want, got)

	assert.Equal(t, "ALICE_PORT=443\n", readFile(t, filepath.Join(pkg, ".env.template")))
	assert.Equal(t, "# roles\n", readFile(t, filepath.Join(pkg, "lib/initdb/10-alice-roles.sh")))
	assert.Equal(t, "Alice license terms of Example Vendor.\n", readFile(t, filepath.Join(pkg, "licenses/LICENSE")))
	assert.Equal(t, "1.0.0\n", readFile(t, filepath.Join(pkg, "VERSION")))

	assert.Equal(t, wantRelease, readFile(t, filepath.Join(pkg, "RELEASE")))

	checklist := readFile(t, filepath.Join(pkg, "RELEASE-CHECKLIST-SIGNED.txt"))
	assert.Contains(t, checklist, "Commit: "+testCommit)
	assert.Contains(t, checklist, "Gates recorded by make release-gates on commit "+testCommit+":\n")
	assert.Contains(t, checklist, "  ci: exit 0 (go1.27.2, golangci-lint v2.14.0)\n")
	assert.Contains(t, checklist, "  release-keycheck: exit 0 (go1.27.2)\n")
	assert.Contains(t, checklist, "\nSigned: <empty until the vendor signs the checklist>\n")
	assert.NotContains(t, checklist, "No gate was recorded")

	// images.sha256 covers both image files.
	imgSums := readFile(t, filepath.Join(pkg, "images/images.sha256"))
	assert.Equal(t, sumLine(t, pkg, "images/alice-1.0.0.tar", "alice-1.0.0.tar")+sumLine(t, pkg, "images/postgres-1.0.0.tar", "postgres-1.0.0.tar"), imgSums)

	// SHA256SUMS: sorted, complete, excluding itself and its signature, and correct (sha256sum -c).
	sums := strings.Split(strings.TrimSuffix(readFile(t, filepath.Join(pkg, "SHA256SUMS")), "\n"), "\n")
	var names []string
	for _, line := range sums {
		hexSum, name, ok := strings.Cut(line, "  ")
		require.True(t, ok, line)
		assert.Equal(t, sumLine(t, pkg, name, name), hexSum+"  "+name+"\n")
		names = append(names, name)
	}
	assert.True(t, sort.StringsAreSorted(names))
	var wantNames []string
	for _, w := range want {
		if w != "SHA256SUMS" {
			wantNames = append(wantNames, w)
		}
	}
	assert.Equal(t, wantNames, names)
	cmd := exec.Command("sha256sum", "-c", "--strict", "--quiet", "SHA256SUMS")
	cmd.Dir = pkg
	out, err := cmd.CombinedOutput()
	require.NoError(t, err, string(out))

	// The stage never overwrites an earlier one.
	require.ErrorContains(t, stage(cfg, &fakeImages{}), "already exists")
}

// imageNotices is a minimal IMAGE_NOTICES.md of tools/notices images for the two images.
func imageNotices(alice, postgres string) string {
	return "# Third-party notices of the container images\n\n## Container image `" + alice + "`\n\n## Container image `" + postgres +
		"`\n\n## Written offer of source code\n\n## License texts in the images\n"
}

// Final review B I-1: the package carries the notices of the two images it ships (licenses/IMAGE_NOTICES.md, written
// by tools/notices images), and the stage refuses notices that are missing, or that are not those of these images or
// lack the written source offer, in a test package too.
func TestStageNeedsTheImageNotices(t *testing.T) {
	for name, content := range map[string]string{
		"other images":  imageNotices("alice:0.9.0", "alice-postgres:0.9.0"),
		"no offer":      strings.Replace(imageNotices("alice:1.0.0", "alice-postgres:1.0.0"), "## Written offer of source code", "", 1),
		"only one":      strings.Replace(imageNotices("alice:1.0.0", "alice-postgres:1.0.0"), "## Container image `alice-postgres:1.0.0`", "", 1),
		"not the notes": "# Notices\n",
	} {
		for _, draft := range []bool{false, true} {
			cfg, _ := fixture(t)
			if draft {
				cfg = draftFixture(t)
			}
			write(t, cfg.ImageNotices, content, 0o644)
			require.ErrorContains(t, stage(cfg, &fakeImages{}), "IMAGE_NOTICES", name)
			assert.NoDirExists(t, cfg.Out, name)
		}
	}
	cfg, _ := fixture(t)
	require.NoError(t, os.Remove(cfg.ImageNotices))
	require.Error(t, stage(cfg, &fakeImages{}))
	assert.NoDirExists(t, cfg.Out)

	cfg, _ = fixture(t)
	require.NoError(t, stage(cfg, &fakeImages{}))
	assert.Equal(t, imageNotices("alice:1.0.0", "alice-postgres:1.0.0"), readFile(t, filepath.Join(cfg.Out, "alice/licenses/IMAGE_NOTICES.md")))
}

// I-1: RELEASE carries both identifiers of each image, taken from the saved tar: the config
// digest (what a classic image store reports as .Id after docker load) and the manifest or index
// digest (what a containerd image store reports).
var wantRelease = "VERSION=1.0.0\nMIN_UPGRADE_FROM=1.0.0-rc.1\nSCHEMA_VERSION=12\nALICE_IMAGE=alice:1.0.0\n" +
	"ALICE_IMAGE_ID=" + fakeDigest("config", "alice:1.0.0") + "\nALICE_IMAGE_DIGEST=" + fakeDigest("index", "alice:1.0.0") +
	"\nPOSTGRES_IMAGE=alice-postgres:1.0.0\nPOSTGRES_IMAGE_ID=" + fakeDigest("config", "alice-postgres:1.0.0") +
	"\nPOSTGRES_IMAGE_DIGEST=" + fakeDigest("index", "alice-postgres:1.0.0") +
	"\nBUILD_COMMIT=" + testCommit + "\nBUILD_TIME=" + testBuildTime + "\nRELEASE_KEY_ID=rk-2026-01\n"

func TestStageRecordsBothImageIdentifiers(t *testing.T) {
	// The build engine reports the config digest (classic store): the same RELEASE.
	cfg, _ := fixture(t)
	require.NoError(t, stage(cfg, &fakeImages{classic: true}))
	assert.Equal(t, wantRelease, readFile(t, filepath.Join(cfg.Out, "alice", "RELEASE")))

	// The engine reports an ID that is neither identifier of the saved tar: refused.
	cfg, _ = fixture(t)
	require.ErrorContains(t, stage(cfg, &fakeImages{id: "sha256:" + strings.Repeat("9", 64)}), "neither")
	assert.NoDirExists(t, cfg.Out)

	// A saved tar without index.json (a docker save without the OCI layout): refused.
	cfg, _ = fixture(t)
	require.ErrorContains(t, stage(cfg, &fakeImages{classic: true, noIndex: true}), "index.json")
	assert.NoDirExists(t, cfg.Out)
}

func sumLine(t *testing.T, dir, rel, name string) string {
	t.Helper()
	sum := sha256.Sum256([]byte(readFile(t, filepath.Join(dir, rel))))
	return hex.EncodeToString(sum[:]) + "  " + name + "\n"
}

// The production path (make release) refuses whatever a test package may lack (M-6, R43 row 51).
func TestStageRefusesAMissingInput(t *testing.T) {
	for name, change := range map[string]func(t *testing.T, cfg *stageConfig){
		"no SECURITY-REPORT.md": func(t *testing.T, cfg *stageConfig) {
			require.NoError(t, os.Remove(filepath.Join(cfg.Root, "SECURITY-REPORT.md")))
		},
		"no gates log":        func(t *testing.T, cfg *stageConfig) { require.NoError(t, os.Remove(cfg.GatesLog)) },
		"empty gates log":     func(t *testing.T, cfg *stageConfig) { write(t, cfg.GatesLog, "", 0o644) },
		"failed gate":         func(t *testing.T, cfg *stageConfig) { write(t, cfg.GatesLog, "lint\t1\tv2\n", 0o644) },
		"malformed gates log": func(t *testing.T, cfg *stageConfig) { write(t, cfg.GatesLog, "lint passed\n", 0o644) },
		"placeholder LICENSE": func(t *testing.T, cfg *stageConfig) { write(t, cfg.License, draftLicense+"\n", 0o644) },
		"missing guide": func(t *testing.T, cfg *stageConfig) {
			require.NoError(t, os.Remove(filepath.Join(cfg.Root, "docs/install-guide.md")))
		},
		"no CHANGELOG.md": func(t *testing.T, cfg *stageConfig) {
			require.NoError(t, os.Remove(filepath.Join(cfg.Root, "CHANGELOG.md")))
		},
		"no install.sh": func(t *testing.T, cfg *stageConfig) {
			require.NoError(t, os.Remove(filepath.Join(cfg.Root, "deploy/release/install.sh")))
		},
		"no env.template": func(t *testing.T, cfg *stageConfig) {
			require.NoError(t, os.Remove(filepath.Join(cfg.Root, "deploy/release/env.template")))
		},
		"no roles script": func(t *testing.T, cfg *stageConfig) {
			require.NoError(t, os.Remove(filepath.Join(cfg.Root, "deploy/release/postgres/initdb/10-alice-roles.sh")))
		},
		"no notices": func(t *testing.T, cfg *stageConfig) { require.NoError(t, os.Remove(cfg.Notices)) },
		"no source SBOM": func(t *testing.T, cfg *stageConfig) {
			require.NoError(t, os.Remove(filepath.Join(cfg.SBOM, "source-1.0.0.cdx.json")))
		},
		"no arm64 helper": func(t *testing.T, cfg *stageConfig) {
			require.NoError(t, os.Remove(filepath.Join(cfg.Helper, "alice-helper-linux-arm64")))
		},
		"helper checksum differs": func(t *testing.T, cfg *stageConfig) {
			write(t, filepath.Join(cfg.Helper, "alice-helper-linux-amd64"), "changed", 0o644)
		},
		"no release key": func(t *testing.T, cfg *stageConfig) {
			require.NoError(t, os.Remove(filepath.Join(cfg.Keys, "rk-2026-01.pem")))
		},
		"bad version":     func(_ *testing.T, cfg *stageConfig) { cfg.Version = "1.0" },
		"bad commit":      func(_ *testing.T, cfg *stageConfig) { cfg.Commit = "abc" },
		"bad build time":  func(_ *testing.T, cfg *stageConfig) { cfg.BuildTime = "yesterday" },
		"bad min upgrade": func(_ *testing.T, cfg *stageConfig) { cfg.MinUpgradeFrom = "one" },
		"no migrations": func(t *testing.T, cfg *stageConfig) {
			require.NoError(t, os.RemoveAll(filepath.Join(cfg.Root, "migrations")))
		},
		"bad image name": func(_ *testing.T, cfg *stageConfig) { cfg.AliceImage = "Alice Image" },
		"stale gates log": func(t *testing.T, cfg *stageConfig) {
			write(t, cfg.GatesLog, "commit\t"+strings.Repeat("f", 40)+"\nlint\t0\tv2\n", 0o644)
		},
		"gates log without commit": func(t *testing.T, cfg *stageConfig) { write(t, cfg.GatesLog, "lint\t0\tv2\n", 0o644) },
		"gates log with only a commit": func(t *testing.T, cfg *stageConfig) {
			write(t, cfg.GatesLog, "commit\t"+testCommit+"\n", 0o644)
		},
		"gates log with a failed gate among all": func(t *testing.T, cfg *stageConfig) {
			write(t, cfg.GatesLog, strings.Replace(fullGatesLog(testCommit), "testssl\t0\t", "testssl\t1\t", 1), 0o644)
		},
	} {
		t.Run(name, func(t *testing.T) {
			cfg, _ := fixture(t)
			change(t, &cfg)
			err := stage(cfg, &fakeImages{})
			require.Error(t, err)
			assert.NoDirExists(t, cfg.Out, "a refused stage leaves nothing behind")
		})
	}
}

// M-6, R43 row 51: a test package (make release-test: -allow-draft) carries placeholders for what
// Tasks 17 and 18 and the vendor provide later, and says so.
func TestStageDraftPlaceholders(t *testing.T) {
	cfg := draftFixture(t)
	require.NoError(t, os.Remove(filepath.Join(cfg.Root, "SECURITY-REPORT.md")))
	require.NoError(t, os.Remove(cfg.GatesLog))
	require.NoError(t, os.Remove(filepath.Join(cfg.Root, "docs/install-guide.md")))
	write(t, cfg.License, draftLicense+"\n", 0o644)
	cfg.AllowDraft = true
	require.NoError(t, stage(cfg, &fakeImages{}))
	pkg := filepath.Join(cfg.Out, "alice")
	assert.Equal(t, "SECURITY-REPORT.md: not part of this test package\n", readFile(t, filepath.Join(pkg, "SECURITY-REPORT.md")))
	assert.Equal(t, "docs/install-guide.md: not part of this test package\n", readFile(t, filepath.Join(pkg, "docs/install-guide.md")))
	assert.Equal(t, "# upgrade.md\n", readFile(t, filepath.Join(pkg, "docs/upgrade.md")), "an existing guide is copied")
	assert.Equal(t, draftLicense+"\n", readFile(t, filepath.Join(pkg, "licenses/LICENSE")))
	checklist := readFile(t, filepath.Join(pkg, "RELEASE-CHECKLIST-SIGNED.txt"))
	assert.Contains(t, checklist, "No gate was recorded for this package.\n")
	assert.Contains(t, checklist, "Signed: <empty until the vendor signs the checklist>\n")
	assert.NotContains(t, checklist, "exit 0")

	// A draft stage still copies a gates log when there is one, and never claims more: it names
	// the commit the gates ran on, which may differ from the package's.
	cfg2 := draftFixture(t)
	other := strings.Repeat("f", 40)
	write(t, cfg2.GatesLog, "commit\t"+other+"\nlint\t0\tv2\n", 0o644)
	require.NoError(t, stage(cfg2, &fakeImages{}))
	checklist = readFile(t, filepath.Join(cfg2.Out, "alice", "RELEASE-CHECKLIST-SIGNED.txt"))
	assert.Contains(t, checklist, "Commit: "+testCommit+"\n")
	assert.Contains(t, checklist, "Gates recorded by make release-gates on commit "+other+":\n")
	assert.Contains(t, checklist, "lint: exit 0 (v2)")
	assert.NotContains(t, checklist, "test: exit")

	// A draft with a log that names no commit says so.
	cfg3 := draftFixture(t)
	write(t, cfg3.GatesLog, "lint\t0\tv2\n", 0o644)
	require.NoError(t, stage(cfg3, &fakeImages{}))
	checklist = readFile(t, filepath.Join(cfg3.Out, "alice", "RELEASE-CHECKLIST-SIGNED.txt"))
	assert.Contains(t, checklist, "Gates recorded by make release-gates on an unrecorded commit:\n")
}

// draftFixture is the fixture as make release-test stages it: -test -allow-draft, a release
// candidate, a test key.
func draftFixture(t *testing.T) stageConfig {
	t.Helper()
	cfg, _ := fixture(t)
	cfg.Test, cfg.AllowDraft, cfg.Version = true, true, "1.0.0-rc.1"
	cfg.Keys = t.TempDir()
	releaseKey(t, cfg.Keys, "rk-test-01")
	for _, f := range []string{"alice", "postgres", "source"} {
		write(t, filepath.Join(cfg.SBOM, f+"-1.0.0-rc.1.cdx.json"), "{}\n", 0o644)
	}
	return cfg
}

// S-7: the stage never packages a symbolic link.
func TestStageRefusesSymlinks(t *testing.T) {
	for name, link := range map[string]func(cfg stageConfig) (target, linkPath string){
		"script": func(cfg stageConfig) (string, string) {
			return filepath.Join(cfg.Root, "deploy/release/alicectl"), filepath.Join(cfg.Root, "deploy/release/install.sh")
		},
		"guide": func(cfg stageConfig) (string, string) {
			return "/etc/hostname", filepath.Join(cfg.Root, "docs/extra.md")
		},
		"release key": func(cfg stageConfig) (string, string) {
			return filepath.Join(cfg.Keys, "rk-2026-01.pem"), filepath.Join(cfg.Keys, "rk-2026-02.pem")
		},
		"sbom": func(cfg stageConfig) (string, string) {
			return filepath.Join(cfg.SBOM, "alice-1.0.0.cdx.json"), filepath.Join(cfg.SBOM, "source-1.0.0.cdx.json")
		},
		"keys directory": func(cfg stageConfig) (string, string) {
			return cfg.Keys, filepath.Join(cfg.Root, "keys-link")
		},
	} {
		t.Run(name, func(t *testing.T) {
			cfg, _ := fixture(t)
			target, linkPath := link(cfg)
			_ = os.Remove(linkPath)
			require.NoError(t, os.Symlink(target, linkPath))
			if name == "keys directory" {
				cfg.Keys = linkPath
			}
			err := stage(cfg, &fakeImages{})
			require.ErrorContains(t, err, "symbolic link")
			assert.NoDirExists(t, cfg.Out)
		})
	}
}

// S-11: test keys only with -test (which writes TEST_SIGNED=1), production keys only as committed.
func TestStageRefusesTestKeysWithoutTestFlag(t *testing.T) {
	cfg, _ := fixture(t)
	testKeys := t.TempDir()
	releaseKey(t, testKeys, "rk-test-01")
	cfg.Keys = testKeys
	cfg.Version = "1.0.0-rc.1"
	require.ErrorContains(t, stage(cfg, &fakeImages{}), "rk-test-01")

	// Another key with a production ID, not the committed one: refused.
	cfg, _ = fixture(t)
	other := t.TempDir()
	releaseKey(t, other, "rk-2026-01")
	cfg.Keys = other
	require.ErrorContains(t, stage(cfg, &fakeImages{}), "deploy/release/keys")
	// An extra production key beside the committed one: refused.
	cfg, _ = fixture(t)
	other = t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(other, "rk-2026-01.pem"), []byte(readFile(t, filepath.Join(cfg.Keys, "rk-2026-01.pem"))), 0o644))
	releaseKey(t, other, "rk-2026-02")
	cfg.Keys = other
	require.ErrorContains(t, stage(cfg, &fakeImages{}), "deploy/release/keys")
	// A key file whose name is not its key ID: refused.
	cfg, _ = fixture(t)
	require.NoError(t, os.Rename(filepath.Join(cfg.Keys, "rk-2026-01.pem"), filepath.Join(cfg.Keys, "rk-2026-09.pem")))
	require.ErrorContains(t, stage(cfg, &fakeImages{}), "rk-2026-09")

	// With -test: accepted, marked, and only for a release candidate.
	cfg, _ = fixture(t)
	cfg.Keys = testKeys
	cfg.Test = true
	require.ErrorContains(t, stage(cfg, &fakeImages{}), "-rc.N")
	cfg.Version = "1.0.0-rc.1"
	for _, f := range []string{"alice", "postgres", "source"} {
		write(t, filepath.Join(cfg.SBOM, f+"-1.0.0-rc.1.cdx.json"), "{}\n", 0o644)
	}
	require.NoError(t, stage(cfg, &fakeImages{}))
	release := readFile(t, filepath.Join(cfg.Out, "alice", "RELEASE"))
	assert.Contains(t, release, "\nRELEASE_KEY_ID=rk-test-01\nTEST_SIGNED=1\n")
	assert.FileExists(t, filepath.Join(cfg.Out, "alice", "release-keys", "rk-test-01.pem"))
}

func signStage(t *testing.T, cfg stageConfig, priv ed25519.PrivateKey) {
	t.Helper()
	sums := filepath.Join(cfg.Out, "alice", "SHA256SUMS")
	data, err := os.ReadFile(sums)
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(sums+".sig", ed25519.Sign(priv, data), 0o644))
}

func TestPackIsDeterministic(t *testing.T) {
	cfg, priv := fixture(t)
	require.NoError(t, stage(cfg, &fakeImages{}))
	signStage(t, cfg, priv)

	outA, outB := t.TempDir(), t.TempDir()
	tarA, err := pack(cfg.Out, outA)
	require.NoError(t, err)
	// Different modification times and umask on disk do not change the package.
	require.NoError(t, os.Chtimes(filepath.Join(cfg.Out, "alice", "VERSION"), testTime(t, "2030-01-01T00:00:00Z"), testTime(t, "2030-01-01T00:00:00Z")))
	tarB, err := pack(cfg.Out, outB)
	require.NoError(t, err)
	assert.Equal(t, filepath.Join(outA, "alice-1.0.0.tar.gz"), tarA)
	a, b := readFile(t, tarA), readFile(t, tarB)
	assert.Equal(t, a, b, "two packs of one stage are byte for byte equal")

	sum := sha256.Sum256([]byte(a))
	assert.Equal(t, hex.EncodeToString(sum[:])+"  alice-1.0.0.tar.gz\n", readFile(t, tarA+".sha256"))

	entries := tarEntries(t, tarA)
	require.NotEmpty(t, entries)
	assert.Equal(t, "alice/", entries[0].name)
	names := make([]string, len(entries))
	for i, e := range entries {
		names[i] = e.name
		assert.Equal(t, testBuildTime, e.mtime, e.name)
		assert.Equal(t, "0 0 root root", e.owner, e.name)
	}
	assert.True(t, sort.StringsAreSorted(names), names)
	assert.Contains(t, names, "alice/SHA256SUMS.sig")
	assert.Contains(t, names, "alice/lib/initdb/")
	assert.Contains(t, names, "alice/.env.template")
	modes := map[string]string{}
	for _, e := range entries {
		modes[e.name] = e.mode
	}
	assert.Equal(t, "0755", modes["alice/install.sh"])
	assert.Equal(t, "0644", modes["alice/RELEASE"])
	assert.Equal(t, "0755", modes["alice/helper/"])

	// gzip header: no name, no time (bytes 4..7 are the MTIME field).
	raw := []byte(a)
	assert.Equal(t, []byte{0, 0, 0, 0}, raw[4:8])
	assert.Zero(t, raw[3]&0x08, "no FNAME")

	// The outer files are never overwritten.
	_, err = pack(cfg.Out, outA)
	require.ErrorContains(t, err, "already exists")
}

func testTime(t *testing.T, s string) time.Time {
	t.Helper()
	tm, err := time.Parse(time.RFC3339, s)
	require.NoError(t, err)
	return tm
}

type tarEntry struct{ name, mtime, owner, mode string }

func tarEntries(t *testing.T, path string) []tarEntry {
	t.Helper()
	f, err := os.Open(path)
	require.NoError(t, err)
	defer func() { _ = f.Close() }()
	zr, err := gzip.NewReader(f)
	require.NoError(t, err)
	tr := tar.NewReader(zr)
	var out []tarEntry
	for {
		h, err := tr.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		require.NoError(t, err)
		out = append(out, tarEntry{
			name: h.Name, mtime: h.ModTime.UTC().Format(time.RFC3339),
			owner: fmt.Sprintf("%d %d %s %s", h.Uid, h.Gid, h.Uname, h.Gname), mode: fmt.Sprintf("%04o", h.Mode),
		})
	}
	return out
}

func TestPackRefusesAnUnsignedStage(t *testing.T) {
	cfg, priv := fixture(t)
	require.NoError(t, stage(cfg, &fakeImages{}))
	_, err := pack(cfg.Out, t.TempDir())
	require.ErrorContains(t, err, "SHA256SUMS.sig")

	// A signature by another key: refused.
	_, otherPriv, err := ed25519.GenerateKey(nil)
	require.NoError(t, err)
	signStage(t, cfg, otherPriv)
	_, err = pack(cfg.Out, t.TempDir())
	require.ErrorContains(t, err, "signature")

	// Signed correctly, but a file changed after signing: refused.
	require.NoError(t, os.Remove(filepath.Join(cfg.Out, "alice", "SHA256SUMS.sig")))
	signStage(t, cfg, priv)
	write(t, filepath.Join(cfg.Out, "alice", "docs", "README.md"), "changed\n", 0o644)
	_, err = pack(cfg.Out, t.TempDir())
	require.ErrorContains(t, err, "docs/README.md")
	write(t, filepath.Join(cfg.Out, "alice", "docs", "README.md"), "# README.md\n", 0o644)
	// An unlisted file: refused.
	write(t, filepath.Join(cfg.Out, "alice", "lib", "initdb", "20-extra.sh"), "x\n", 0o644)
	_, err = pack(cfg.Out, t.TempDir())
	require.ErrorContains(t, err, "20-extra.sh")
	require.NoError(t, os.Remove(filepath.Join(cfg.Out, "alice", "lib", "initdb", "20-extra.sh")))
	// A symbolic link: refused.
	require.NoError(t, os.Symlink("/etc/passwd", filepath.Join(cfg.Out, "alice", "docs", "x.md")))
	_, err = pack(cfg.Out, t.TempDir())
	require.ErrorContains(t, err, "symbolic link")
	require.NoError(t, os.Remove(filepath.Join(cfg.Out, "alice", "docs", "x.md")))
	_, err = pack(cfg.Out, t.TempDir())
	require.NoError(t, err)
}

// S-11: a test-signed package is only ever a release candidate; the Makefile refuses before it
// builds anything.
func TestReleaseTestNeedsAnRCVersion(t *testing.T) {
	cmd := exec.Command("make", "-s", "release-test", "VERSION=1.0.0")
	cmd.Dir = filepath.Join("..", "..")
	out, err := cmd.CombinedOutput()
	var exitErr *exec.ExitError
	require.ErrorAs(t, err, &exitErr, string(out))
	assert.Equal(t, 2, exitErr.ExitCode())
	assert.Equal(t, "make release-test needs VERSION=x.y.z-rc.N (a test-signed package is never a customer version)", strings.SplitN(string(out), "\n", 2)[0])
	assert.NotContains(t, string(out), "go run", "nothing was built")
}

// S-12: the release and license public key sets are disjoint.
func TestReleaseAndLicenseKeysAreDisjoint(t *testing.T) {
	relDir := t.TempDir()
	priv := releaseKey(t, relDir, "rk-2026-01")
	licenseFile := filepath.Join(t.TempDir(), "production.json")
	other, _, err := ed25519.GenerateKey(nil)
	require.NoError(t, err)
	keySet := func(pub ed25519.PublicKey) string {
		return fmt.Sprintf(`{"keys": [{"key_id": "vk-2026-01", "public_key": %q, "status": "active"}]}`, base64.StdEncoding.EncodeToString(pub))
	}
	write(t, licenseFile, keySet(other), 0o644)
	var out bytes.Buffer
	require.Equal(t, 0, run([]string{"keycheck", "-release", relDir, "-license", licenseFile}, &out, &out), out.String())
	assert.Contains(t, out.String(), "disjoint")

	write(t, licenseFile, keySet(priv.Public().(ed25519.PublicKey)), 0o644)
	out.Reset()
	assert.Equal(t, 1, run([]string{"keycheck", "-release", relDir, "-license", licenseFile}, &out, &out))
	assert.Contains(t, out.String(), "rk-2026-01")
	assert.Contains(t, out.String(), "vk-2026-01")

	// The committed key set of this repository (no license key yet) passes; a test key in the
	// release directory and an unreadable license key set do not.
	write(t, licenseFile, `{"keys": []}`, 0o644)
	out.Reset()
	require.Equal(t, 0, run([]string{"keycheck", "-release", relDir, "-license", licenseFile}, &out, &out), out.String())
	releaseKey(t, relDir, "rk-test-01")
	out.Reset()
	assert.Equal(t, 1, run([]string{"keycheck", "-release", relDir, "-license", licenseFile}, &out, &out))
	assert.Contains(t, out.String(), "rk-test-01")
	require.NoError(t, os.Remove(filepath.Join(relDir, "rk-test-01.pem")))
	write(t, licenseFile, `{"keys": [`, 0o644)
	out.Reset()
	assert.Equal(t, 1, run([]string{"keycheck", "-release", relDir, "-license", licenseFile}, &out, &out))
	empty := t.TempDir()
	out.Reset()
	assert.Equal(t, 1, run([]string{"keycheck", "-release", empty, "-license", licenseFile}, &out, &out))
}

func TestCommandLine(t *testing.T) {
	var out bytes.Buffer
	for _, args := range [][]string{nil, {"other"}, {"stage", "-bogus"}, {"pack"}, {"keycheck"}} {
		out.Reset()
		assert.Equal(t, 2, run(args, &out, &out), args)
	}

	// stage and pack through the command line, with the docker stand-in.
	cfg, priv := fixture(t)
	img := &fakeImages{}
	newImages = func() images { return img }
	t.Cleanup(func() { newImages = func() images { return dockerImages{} } })
	args := []string{"stage", "-root", cfg.Root, "-version", cfg.Version, "-out", cfg.Out, "-keys", cfg.Keys,
		"-alice-image", cfg.AliceImage, "-postgres-image", cfg.PostgresImage, "-sbom", cfg.SBOM, "-notices", cfg.Notices,
		"-image-notices", cfg.ImageNotices,
		"-helper", cfg.Helper, "-commit", cfg.Commit, "-build-time", cfg.BuildTime, "-gates-log", cfg.GatesLog,
		"-license", cfg.License, "-min-upgrade-from", cfg.MinUpgradeFrom}
	out.Reset()
	require.Equal(t, 0, run(args, &out, &out), out.String())
	assert.Contains(t, out.String(), "SHA256SUMS")
	out.Reset()
	assert.Equal(t, 1, run(args, &out, &out), "the stage exists")
	signStage(t, cfg, priv)
	dest := t.TempDir()
	out.Reset()
	require.Equal(t, 0, run([]string{"pack", "-stage", cfg.Out, "-out", dest}, &out, &out), out.String())
	assert.FileExists(t, filepath.Join(dest, "alice-1.0.0.tar.gz.sha256"))
	out.Reset()
	assert.Equal(t, 1, run([]string{"pack", "-stage", cfg.Out, "-out", dest}, &out, &out))
}

// makeIn runs make in the repository root and returns its output and exit code.
func makeIn(t *testing.T, args ...string) (string, int) {
	t.Helper()
	cmd := exec.Command("make", args...)
	cmd.Dir = filepath.Join("..", "..")
	out, err := cmd.CombinedOutput()
	if err == nil {
		return string(out), 0
	}
	var exitErr *exec.ExitError
	require.ErrorAs(t, err, &exitErr, string(out))
	return string(out), exitErr.ExitCode()
}

// I-2: make release never deletes or replaces outputs of the same VERSION (a signed package
// among them); it refuses before it builds anything.
func TestReleaseRefusesExistingOutputs(t *testing.T) {
	for _, name := range []string{"alice-1.0.0/alice/SHA256SUMS.sig", "sbom-1.0.0/alice-1.0.0.cdx.json", "alice-1.0.0.tar.gz",
		"alice-1.0.0.tar.gz.sha256", "alice-1.0.0.tar.gz.sha256.sig"} {
		t.Run(name, func(t *testing.T) {
			dir := t.TempDir()
			write(t, filepath.Join(dir, name), "signed\n", 0o644)
			out, code := makeIn(t, "-s", "release", "VERSION=1.0.0", "RELEASE_DIR="+dir)
			assert.Equal(t, 2, code, out)
			assert.Equal(t, "make release: outputs of 1.0.0 already exist in "+dir+"; it never replaces them (make release-test removes those of a test package)",
				strings.SplitN(out, "\n", 2)[0])
			assert.NotContains(t, out, "go ", "nothing was built")
			assert.Equal(t, "signed\n", readFile(t, filepath.Join(dir, name)))
		})
	}
}

// I-2: make release-test removes only the outputs of a test package; a stage without
// TEST_SIGNED=1 (signed with the production key) is kept.
func TestReleaseTestKeepsAProductionStage(t *testing.T) {
	dir, keyDir := t.TempDir(), t.TempDir()
	write(t, filepath.Join(dir, "alice-1.0.0-rc.1/alice/RELEASE"), "VERSION=1.0.0-rc.1\nRELEASE_KEY_ID=rk-2026-01\n", 0o644)
	out, code := makeIn(t, "-s", "release-test", "VERSION=1.0.0-rc.1", "RELEASE_DIR="+dir, "RELEASE_TEST_KEY="+keyDir)
	assert.Equal(t, 2, code, out)
	assert.Equal(t, "make release-test: "+dir+"/alice-1.0.0-rc.1 is not a test package (no TEST_SIGNED=1); remove it by hand if it is not needed",
		strings.SplitN(out, "\n", 2)[0])
	assert.FileExists(t, filepath.Join(dir, "alice-1.0.0-rc.1/alice/RELEASE"))
	assert.NoFileExists(t, filepath.Join(keyDir, "test-release.key"), "nothing was built")
}

// I-6: make release inspects the image it ships (alice:$(VERSION)) with make image-check, which
// also compares the helper checksums embedded in the image with bin/alice-helper.sha256 (the
// file the stage checks the bundled helper against), before it saves the image.
func TestReleaseChecksTheShippedImage(t *testing.T) {
	out, code := makeIn(t, "-n", "release", "VERSION=1.0.0", "RELEASE_DIR="+t.TempDir())
	require.Equal(t, 0, code, out)
	check := strings.Index(out, "./deploy/dev/check-image.sh 1.0.0")
	build := strings.Index(out, "-t alice:1.0.0 .")
	stageAt := strings.Index(out, "releasebuild stage")
	require.NotEqual(t, -1, check, out)
	require.NotEqual(t, -1, build, out)
	assert.Less(t, build, check)
	assert.Less(t, check, stageAt)
	assert.Contains(t, out, "HELPER_SHA256_AMD64=")
}

// I-5: the gates log names the commit its gates ran on (first line "commit\t<40 hex>"); the
// production stage refuses a log of another commit.
func TestStageRefusesAStaleGatesLog(t *testing.T) {
	cfg, _ := fixture(t)
	other := strings.Repeat("f", 40)
	write(t, cfg.GatesLog, "commit\t"+other+"\nlint\t0\tv2\n", 0o644)
	require.ErrorContains(t, stage(cfg, &fakeImages{}), "the gates log "+cfg.GatesLog+" was recorded on commit "+other+", not "+testCommit)
	write(t, cfg.GatesLog, "lint\t0\tv2\n", 0o644)
	require.ErrorContains(t, stage(cfg, &fakeImages{}), "does not start with the line commit")
	write(t, cfg.GatesLog, "commit\tabc\nlint\t0\tv2\n", 0o644)
	require.ErrorContains(t, stage(cfg, &fakeImages{}), "does not start with the line commit")
	assert.NoDirExists(t, cfg.Out)
}

// Task 15 review I-1: the production stage requires every gate of releaseGates, each exactly once
// with exit 0; a skipped gate (RELEASE_GATES_SKIP writes "<gate>\tskipped\t-"), a missing one, a
// repeated one and one it does not know are refused. A draft lists a skipped gate as skipped.
func TestStageRequiresEveryGate(t *testing.T) {
	full := fullGatesLog(testCommit)
	for name, tc := range map[string]struct{ log, want string }{
		"missing gate": {
			log:  strings.Replace(full, "zap-baseline\t0\tzap\n", "", 1),
			want: "the gates log " + "%s" + " has no line for gate zap-baseline",
		},
		"only one gate": {
			log:  "commit\t" + testCommit + "\nci\t0\tgo1.27.2\n",
			want: "has no line for gate matrix-check",
		},
		"skipped gate": {
			log:  strings.Replace(full, "release-keycheck\t0\tgo1.27.2", "release-keycheck\tskipped\t-", 1),
			want: "gate release-keycheck was skipped; a customer release needs every gate to run and pass",
		},
		"repeated gate": {
			log:  full + "ci\t0\tgo1.27.2\n",
			want: "the gates log line for gate ci appears more than once",
		},
		"tree changed during the run": {
			log:  full + "tree-unchanged\t1\t-\n",
			want: "gate tree-unchanged exited with 1",
		},
		"unknown gate": {
			log:  full + "lint\t0\tv2\n",
			want: "the gates log names gate lint, which is not a release gate",
		},
	} {
		t.Run(name, func(t *testing.T) {
			cfg, _ := fixture(t)
			write(t, cfg.GatesLog, tc.log, 0o644)
			want := tc.want
			if strings.Contains(want, "%s") {
				want = fmt.Sprintf(want, cfg.GatesLog)
			}
			require.ErrorContains(t, stage(cfg, &fakeImages{}), want)
			assert.NoDirExists(t, cfg.Out)
		})
	}

	cfg := draftFixture(t)
	write(t, cfg.GatesLog, strings.Replace(full, "release-keycheck\t0\tgo1.27.2", "release-keycheck\tskipped\t-", 1), 0o644)
	require.NoError(t, stage(cfg, &fakeImages{}))
	checklist := readFile(t, filepath.Join(cfg.Out, "alice", "RELEASE-CHECKLIST-SIGNED.txt"))
	assert.Contains(t, checklist, "  release-keycheck: skipped\n")
	assert.Contains(t, checklist, "  ci: exit 0 (go1.27.2, golangci-lint v2.14.0)\n")
}

// The gate list is defined once: deploy/dev/release-gates.sh runs what releasebuild gates prints.
func TestGatesCommandPrintsTheGateList(t *testing.T) {
	var out bytes.Buffer
	require.Equal(t, 0, run([]string{"gates"}, &out, &out))
	assert.Equal(t, "ci\nmatrix-check\nreproducible-check\ntest-release\ntest-systemd\nzap-baseline\ntestssl\ntest-backup-cycle\ne2e-browsers\nrelease-keycheck\n", out.String())
	out.Reset()
	assert.Equal(t, 2, run([]string{"gates", "extra"}, &out, &out))
}

// fullGatesLog is a gates log of commit with every release gate passed.
func fullGatesLog(commit string) string {
	return "commit\t" + commit + "\n" +
		"ci\t0\tgo1.27.2, golangci-lint v2.14.0\n" +
		"matrix-check\t0\tgo1.27.2\n" +
		"reproducible-check\t0\tgo1.27.2\n" +
		"test-release\t0\tgo1.27.2, docker 29.0.0\n" +
		"test-systemd\t0\tgo1.27.2, ubuntu 22.04 systemd\n" +
		"zap-baseline\t0\tzap\n" +
		"testssl\t0\ttestssl\n" +
		"test-backup-cycle\t0\tgo1.27.2\n" +
		"e2e-browsers\t0\tplaywright 1.60.0\n" +
		"release-keycheck\t0\tgo1.27.2\n"
}

// I-3: -allow-draft (placeholders, failing gates accepted) only for a test package; a draft
// stage with the production key is what the ceremony would sign.
func TestStageRefusesADraftWithoutTest(t *testing.T) {
	cfg, _ := fixture(t)
	cfg.AllowDraft = true
	require.ErrorContains(t, stage(cfg, &fakeImages{}), "-allow-draft is for test packages only (-test)")
	assert.NoDirExists(t, cfg.Out)
	var out bytes.Buffer
	assert.Equal(t, 1, run([]string{"stage", "-allow-draft", "-root", cfg.Root, "-version", "1.0.0", "-out", cfg.Out, "-keys", cfg.Keys}, &out, &out))
	assert.Contains(t, out.String(), "-allow-draft is for test packages only")
}

// I-4: a broken-update package is never a customer version, whichever key signs it, and the
// offline (production-key) build never replaces an existing package of its version.
func TestBrokenReleaseRefusals(t *testing.T) {
	script := filepath.Join("..", "..", "deploy", "dev", "build-broken-release.sh")
	runScript := func(args ...string) (string, int) {
		out, err := exec.Command(script, args...).CombinedOutput()
		if err == nil {
			return string(out), 0
		}
		var exitErr *exec.ExitError
		require.ErrorAs(t, err, &exitErr, string(out))
		return string(out), exitErr.ExitCode()
	}
	dir, key := t.TempDir(), t.TempDir()
	for _, sign := range []string{"offline", "test"} {
		out, code := runScript("1.0.1", "fail", sign, dir, key)
		assert.Equal(t, 2, code, out)
		assert.Equal(t, "build-broken-release.sh: SIGN="+sign+" needs VERSION=x.y.z-rc.N (a broken package is never a customer version)\n", out)
	}
	for _, name := range []string{"alice-1.0.1-rc.1", "sbom-1.0.1-rc.1", "alice-1.0.1-rc.1.tar.gz", "alice-1.0.1-rc.1.tar.gz.sha256",
		"alice-1.0.1-rc.1.tar.gz.sha256.sig"} {
		d := t.TempDir()
		write(t, filepath.Join(d, name), "signed\n", 0o644)
		out, code := runScript("1.0.1-rc.1", "fail", "offline", d, key)
		assert.Equal(t, 2, code, out)
		assert.Equal(t, "build-broken-release.sh: "+filepath.Join(d, name)+" already exists; a package is never replaced (choose the next -rc.N)\n", out)
		assert.Equal(t, "signed\n", readFile(t, filepath.Join(d, name)))
	}
}

// Review minor 2: the committed key set is always ROOT/deploy/release/keys; no flag points the
// production comparison elsewhere.
func TestStageHasNoProductionKeysFlag(t *testing.T) {
	var out bytes.Buffer
	assert.Equal(t, 2, run([]string{"stage", "-production-keys", t.TempDir(), "-version", "1.0.0", "-out", t.TempDir(), "-keys", t.TempDir()}, &out, &out))
	assert.Contains(t, out.String(), "flag provided but not defined: -production-keys")
}

// Review minor 12: a source swapped for a symbolic link after the plan is not followed.
func TestWriteEntryNeverFollowsALink(t *testing.T) {
	dir := t.TempDir()
	link := filepath.Join(dir, "link")
	require.NoError(t, os.Symlink("/etc/hostname", link))
	require.Error(t, writeEntry(filepath.Join(dir, "pkg"), entry{dst: "x", src: link, mode: 0o644}))
}
