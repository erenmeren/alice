package main

import (
	"archive/tar"
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// rootfsTar writes a docker-export-like tar: files (path → content) and symbolic links (path → target).
func rootfsTar(t *testing.T, path string, files, links map[string]string) {
	t.Helper()
	var b bytes.Buffer
	w := tar.NewWriter(&b)
	for name, body := range files {
		require.NoError(t, w.WriteHeader(&tar.Header{Name: name, Mode: 0o644, Size: int64(len(body)), Typeflag: tar.TypeReg}))
		_, err := w.Write([]byte(body))
		require.NoError(t, err)
	}
	for name, target := range links {
		require.NoError(t, w.WriteHeader(&tar.Header{Name: name, Linkname: target, Mode: 0o777, Typeflag: tar.TypeSymlink}))
	}
	require.NoError(t, w.Close())
	write(t, path, b.String())
}

// The SBOMs are what Trivy writes (make sbom): an Alpine image with GPL, MIT and unlicensed parts and a Go binary,
// and a Debian (distroless) image whose packages carry copyright files and whose base-files ships common-licenses.
const pgSBOM = `{"bomFormat":"CycloneDX","metadata":{"component":{"name":"alice-postgres:1.0.0"}},"components":[
 {"type":"operating-system","name":"alpine","version":"3.24.2"},
 {"type":"application","name":"usr/local/bin/gosu"},
 {"type":"library","name":"busybox","version":"1.37.0-r31","purl":"pkg:apk/alpine/busybox@1.37.0-r31?arch=x86_64&distro=3.24.2",
  "licenses":[{"license":{"id":"GPL-2.0-only"}}],
  "properties":[{"name":"aquasecurity:trivy:SrcName","value":"busybox"},{"name":"aquasecurity:trivy:SrcVersion","value":"1.37.0-r31"}]},
 {"type":"library","name":"libgcc","version":"15.2.0-r5","purl":"pkg:apk/alpine/libgcc@15.2.0-r5?arch=x86_64&distro=3.24.2",
  "licenses":[{"license":{"id":"GPL-2.0-or-later"}},{"license":{"id":"LGPL-2.1-or-later"}}],
  "properties":[{"name":"aquasecurity:trivy:SrcName","value":"gcc"},{"name":"aquasecurity:trivy:SrcVersion","value":"15.2.0-r5"}]},
 {"type":"library","name":"musl","version":"1.2.6-r2","purl":"pkg:apk/alpine/musl@1.2.6-r2?arch=x86_64&distro=3.24.2",
  "licenses":[{"license":{"id":"MIT"}}]},
 {"type":"library","name":".postgresql-rundeps","version":"20260917","purl":"pkg:apk/alpine/.postgresql-rundeps@20260917?arch=noarch"},
 {"type":"library","name":"golang.org/x/sys","version":"v0.1.0","purl":"pkg:golang/golang.org/x/sys@v0.1.0"},
 {"type":"library","name":"stdlib","version":"v1.24.6","purl":"pkg:golang/stdlib@v1.24.6"}
]}`

const aliceSBOM = `{"bomFormat":"CycloneDX","metadata":{"component":{"name":"alice:1.0.0"}},"components":[
 {"type":"operating-system","name":"debian","version":"12.15"},
 {"type":"application","name":"usr/local/bin/alice"},
 {"type":"library","name":"base-files","version":"12.4+deb12u15","purl":"pkg:deb/debian/base-files@12.4%2Bdeb12u15?arch=amd64",
  "licenses":[{"license":{"id":"GPL-2.0-or-later"}}],
  "properties":[{"name":"aquasecurity:trivy:SrcName","value":"base-files"},{"name":"aquasecurity:trivy:SrcVersion","value":"12.4+deb12u15"}]},
 {"type":"library","name":"tzdata","version":"2026b-0+deb12u1","purl":"pkg:deb/debian/tzdata@2026b-0%2Bdeb12u1?arch=all",
  "licenses":[{"license":{"name":"public-domain"}}]},
 {"type":"library","name":"alice","purl":"pkg:golang/alice"},
 {"type":"library","name":"golang.org/x/crypto","version":"v0.43.0","purl":"pkg:golang/golang.org/x/crypto@v0.43.0"},
 {"type":"library","name":"stdlib","version":"v1.27.2","purl":"pkg:golang/stdlib@v1.27.2"}
]}`

func imageFixture(t *testing.T) (dir string, images []imageInput, goNotices string) {
	t.Helper()
	dir = t.TempDir()
	write(t, filepath.Join(dir, "pg.cdx.json"), pgSBOM)
	write(t, filepath.Join(dir, "alice.cdx.json"), aliceSBOM)
	rootfsTar(t, filepath.Join(dir, "pg.tar"), map[string]string{
		"usr/local/bin/gosu":     "gosu binary",
		"usr/local/bin/postgres": "postgres binary",
		"usr/local/bin/psql":     "psql binary",
		"bin/busybox":            "busybox binary",
	}, nil)
	rootfsTar(t, filepath.Join(dir, "alice.tar"), map[string]string{
		"usr/local/bin/alice":                  "alice binary",
		"usr/share/doc/base-files/copyright":   "base-files copyright text",
		"usr/share/doc/tzdata/copyright":       "tzdata is in the public domain",
		"usr/share/common-licenses/GPL-2":      "GNU GENERAL PUBLIC LICENSE Version 2 (text)",
		"usr/share/common-licenses/GPL-3":      "GNU GENERAL PUBLIC LICENSE Version 3 (text)",
		"usr/share/common-licenses/LGPL-2.1":   "GNU LESSER GENERAL PUBLIC LICENSE Version 2.1 (text)",
		"usr/share/common-licenses/Apache-2.0": "Apache License 2.0 (text)",
	}, map[string]string{"usr/share/common-licenses/GPL": "GPL-3"})
	goNotices = filepath.Join(dir, "THIRD_PARTY_NOTICES.md")
	write(t, goNotices, "# Third-party notices\n\n## Go\n\n### Go standard library go1.27.2\n\n### golang.org/x/crypto v0.43.0\n\n")
	images = []imageInput{
		{Ref: "alice:1.0.0", SBOM: filepath.Join(dir, "alice.cdx.json"), Rootfs: filepath.Join(dir, "alice.tar")},
		{Ref: "alice-postgres:1.0.0", SBOM: filepath.Join(dir, "pg.cdx.json"), Rootfs: filepath.Join(dir, "pg.tar")},
	}
	return dir, images, goNotices
}

// Final review B I-1: the package ships both images, so their notices come with it: every package of each image's
// SBOM with its declared license, the license texts the images carry (Debian copyright files, the common-licenses
// texts that the declared SPDX licenses name, wherever in the package they are), a statement where nothing could be
// derived, and a written offer of the source of every GPL/LGPL component with the source package the SBOM names.
func TestImageNotices(t *testing.T) {
	_, images, goNotices := imageFixture(t)
	var out bytes.Buffer
	require.NoError(t, renderImages(&out, images, goNotices))
	doc := out.String()
	for _, want := range []string{
		"## Container image `alice:1.0.0`",
		"## Container image `alice-postgres:1.0.0`",
		"Operating system: alpine 3.24.2",
		"Operating system: debian 12.15",
		// Declared licenses and where the text is.
		"| busybox | 1.37.0-r31 | GPL-2.0-only | busybox 1.37.0-r31 | [GPL-2](#text-alice-1-0-0-usr-share-common-licenses-gpl-2) |",
		"| libgcc | 15.2.0-r5 | GPL-2.0-or-later, LGPL-2.1-or-later | gcc 15.2.0-r5 | [GPL-2](#text-alice-1-0-0-usr-share-common-licenses-gpl-2), [LGPL-2.1](#text-alice-1-0-0-usr-share-common-licenses-lgpl-2-1) |",
		"| musl | 1.2.6-r2 | MIT |  | not in the images |",
		"| .postgresql-rundeps | 20260917 | not declared in the SBOM |  | not in the images |",
		"| base-files | 12.4+deb12u15 | GPL-2.0-or-later | base-files 12.4+deb12u15 | [/usr/share/doc/base-files/copyright](#text-alice-1-0-0-usr-share-doc-base-files-copyright), [GPL-2](#text-alice-1-0-0-usr-share-common-licenses-gpl-2) |",
		"| tzdata | 2026b-0+deb12u1 | public-domain |  | [/usr/share/doc/tzdata/copyright](#text-alice-1-0-0-usr-share-doc-tzdata-copyright) |",
		// Go modules: Alice's own are in THIRD_PARTY_NOTICES.md, another binary's are not.
		"| golang.org/x/crypto | v0.43.0 | not declared in the SBOM |  | in THIRD_PARTY_NOTICES.md |",
		"| stdlib | v1.27.2 | not declared in the SBOM |  | in THIRD_PARTY_NOTICES.md |",
		"| alice |  | not declared in the SBOM |  | Alice itself: licenses/LICENSE |",
		"| golang.org/x/sys | v0.1.0 | not declared in the SBOM |  | not in the images |",
		"| stdlib | v1.24.6 | not declared in the SBOM |  | not in the images |",
		// What no SBOM component describes.
		"`/usr/local/bin/postgres`, `/usr/local/bin/psql`",
		// The texts, each once, with anchors.
		"<a id=\"text-alice-1-0-0-usr-share-common-licenses-gpl-2\"></a>",
		"GNU GENERAL PUBLIC LICENSE Version 2 (text)",
		"base-files copyright text",
		// The written offer lists the GPL/LGPL components with their source packages.
		"## Written offer of source code",
		"| alice-postgres:1.0.0 | busybox 1.37.0-r31 | GPL-2.0-only | busybox 1.37.0-r31 | Alpine aports, branch 3.24-stable (https://gitlab.alpinelinux.org/alpine/aports/-/tree/3.24-stable), package busybox |",
		"| alice:1.0.0 | base-files 12.4+deb12u15 | GPL-2.0-or-later | base-files 12.4+deb12u15 | https://snapshot.debian.org/package/base-files/12.4%2Bdeb12u15/ |",
	} {
		assert.Contains(t, doc, want)
	}
	assert.NotContains(t, doc, "`/usr/local/bin/gosu`", "gosu is an SBOM component")
	assert.NotContains(t, doc, "`/usr/local/bin/alice`", "alice is an SBOM component")
	assert.Equal(t, 1, strings.Count(doc, "GNU GENERAL PUBLIC LICENSE Version 2 (text)"), "a text is written once")
	assert.NotContains(t, doc, "GNU GENERAL PUBLIC LICENSE Version 3 (text)", "only texts that a component names")
	_, offer, _ := strings.Cut(doc, "## Written offer of source code")
	offer, _, _ = strings.Cut(offer, "## License texts in the images")
	assert.NotContains(t, offer, "musl")
	assert.NotContains(t, offer, "tzdata")

	// Deterministic.
	var again bytes.Buffer
	require.NoError(t, renderImages(&again, images, goNotices))
	assert.Equal(t, doc, again.String())
}

// The tool fails rather than writing notices that would be empty or wrong.
func TestImageNoticesRefuseBadInput(t *testing.T) {
	dir, images, goNotices := imageFixture(t)
	write(t, filepath.Join(dir, "empty.cdx.json"), `{"bomFormat":"CycloneDX","components":[]}`)
	bad := append([]imageInput(nil), images...)
	bad[0].SBOM = filepath.Join(dir, "empty.cdx.json")
	require.ErrorContains(t, renderImages(&bytes.Buffer{}, bad, goNotices), "no components")
	bad[0] = images[0]
	bad[0].Rootfs = filepath.Join(dir, "missing.tar")
	require.Error(t, renderImages(&bytes.Buffer{}, bad, goNotices))
	require.Error(t, renderImages(&bytes.Buffer{}, images, filepath.Join(dir, "missing.md")))
}

func TestImagesCommand(t *testing.T) {
	dir, images, goNotices := imageFixture(t)
	out := filepath.Join(dir, "IMAGE_NOTICES.md")
	var stderr bytes.Buffer
	args := []string{"images", "-go-notices", goNotices, "-out", out}
	for _, im := range images {
		args = append(args, "-image", im.Ref+"="+im.SBOM+","+im.Rootfs)
	}
	require.Equal(t, 0, run(args, &stderr), stderr.String())
	b, err := os.ReadFile(out)
	require.NoError(t, err)
	assert.Contains(t, string(b), "## Written offer of source code")
	assert.Equal(t, 2, run([]string{"images", "-out", out}, &stderr), "no image")
	assert.Equal(t, 2, run([]string{"images", "-go-notices", goNotices, "-out", out, "-image", "alice:1.0.0"}, &stderr), "malformed -image")
}
