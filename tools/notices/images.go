package main

// The "images" command writes IMAGE_NOTICES.md (final review B I-1): the package redistributes both container images
// as files, so it carries their notices. Everything comes from the image's CycloneDX SBOM (make sbom, Trivy) and from
// the image's own files (docker export): each package with the license its SBOM declares, the license texts the
// images carry (Debian copyright files, Alpine /usr/share/licenses, and the Debian common-licenses texts that a
// declared SPDX license names), a statement wherever no text could be derived, the files no SBOM component
// describes, and a written offer of the source of every GPL/LGPL component with the source package the SBOM names.
// Nothing is filled in from outside the images: a license text that is not in them is reported as missing.
//
//	go run ./tools/notices images -go-notices bin/THIRD_PARTY_NOTICES.md -out bin/IMAGE_NOTICES.md \
//	  -image alice:1.0.0=sbom/alice-1.0.0.cdx.json,alice-rootfs.tar \
//	  -image alice-postgres:1.0.0=sbom/postgres-1.0.0.cdx.json,postgres-rootfs.tar

import (
	"archive/tar"
	"bytes"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/url"
	"os"
	"path"
	"regexp"
	"sort"
	"strings"
)

// imageInput is one image: its reference, its SBOM and an export of its file system.
type imageInput struct{ Ref, SBOM, Rootfs string }

type imageFlags []imageInput

func (f *imageFlags) String() string { return fmt.Sprint(*f) }

func (f *imageFlags) Set(v string) error {
	ref, files, ok := strings.Cut(v, "=")
	sbom, rootfs, ok2 := strings.Cut(files, ",")
	if !ok || !ok2 || ref == "" || sbom == "" || rootfs == "" {
		return errors.New("want REF=SBOM,ROOTFS")
	}
	*f = append(*f, imageInput{Ref: ref, SBOM: sbom, Rootfs: rootfs})
	return nil
}

func runImages(args []string, stderr io.Writer) int {
	fs := flag.NewFlagSet("notices images", flag.ContinueOnError)
	fs.SetOutput(stderr)
	var images imageFlags
	fs.Var(&images, "image", "REF=SBOM,ROOTFS: an image reference, its CycloneDX SBOM and a tar of its file system (repeat)")
	goNotices := fs.String("go-notices", "", "THIRD_PARTY_NOTICES.md of Alice's binaries (its Go modules are not repeated)")
	out := fs.String("out", "", "IMAGE_NOTICES.md to write")
	if fs.Parse(args) != nil || fs.NArg() != 0 || len(images) == 0 || *goNotices == "" || *out == "" {
		fs.Usage()
		return 2
	}
	var b bytes.Buffer
	if err := renderImages(&b, images, *goNotices); err != nil {
		_, _ = fmt.Fprintln(stderr, "notices images:", err)
		return 1
	}
	if err := os.WriteFile(*out, b.Bytes(), 0o644); err != nil { //nolint:gosec // G306: a public notices file
		_, _ = fmt.Fprintln(stderr, "notices images:", err)
		return 1
	}
	return 0
}

// cdxComponent is the part of a CycloneDX component the notices use.
type cdxComponent struct {
	Type     string `json:"type"`
	Name     string `json:"name"`
	Version  string `json:"version"`
	Purl     string `json:"purl"`
	Licenses []struct {
		License struct {
			ID   string `json:"id"`
			Name string `json:"name"`
		} `json:"license"`
		Expression string `json:"expression"`
	} `json:"licenses"`
	Properties []struct {
		Name  string `json:"name"`
		Value string `json:"value"`
	} `json:"properties"`
}

func (c cdxComponent) property(name string) string {
	for _, p := range c.Properties {
		if p.Name == name {
			return p.Value
		}
	}
	return ""
}

func (c cdxComponent) licenses() []string {
	var out []string
	for _, l := range c.Licenses {
		switch {
		case l.License.ID != "":
			out = append(out, l.License.ID)
		case l.License.Name != "":
			out = append(out, l.License.Name)
		case l.Expression != "":
			out = append(out, l.Expression)
		}
	}
	return out
}

func (c cdxComponent) source() string {
	if n := c.property("aquasecurity:trivy:SrcName"); n != "" {
		return strings.TrimSpace(n + " " + c.property("aquasecurity:trivy:SrcVersion"))
	}
	return ""
}

func readSBOM(p string) ([]cdxComponent, error) {
	raw, err := os.ReadFile(p) //nolint:gosec // G304: a path from the Makefile
	if err != nil {
		return nil, err
	}
	var doc struct {
		Components []cdxComponent `json:"components"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		return nil, fmt.Errorf("%s: %w", p, err)
	}
	if len(doc.Components) == 0 {
		return nil, fmt.Errorf("%s: the SBOM has no components", p)
	}
	return doc.Components, nil
}

// rootfs is what the notices read of an image's file system.
type rootfs struct {
	files    map[string]string // license-related files by path (no leading slash)
	links    map[string]string // symbolic links among them: path → resolved path
	localBin []string          // the entries of usr/local/bin
}

const maxLicenseFile = 4 << 20

func licensePath(p string) bool {
	switch {
	case strings.HasPrefix(p, "usr/share/common-licenses/"), strings.HasPrefix(p, "usr/share/licenses/"):
		return true
	case strings.HasPrefix(p, "usr/share/doc/") && strings.HasSuffix(p, "/copyright"):
		return strings.Count(p, "/") == 4
	}
	return false
}

func readRootfs(p string) (rootfs, error) {
	fs := rootfs{files: map[string]string{}, links: map[string]string{}}
	f, err := os.Open(p) //nolint:gosec // G304: a path from the Makefile
	if err != nil {
		return fs, err
	}
	defer func() { _ = f.Close() }()
	tr := tar.NewReader(f)
	for {
		h, err := tr.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return fs, fmt.Errorf("%s: %w", p, err)
		}
		name := strings.TrimPrefix(strings.TrimPrefix(h.Name, "./"), "/")
		if dir, base := path.Split(name); dir == "usr/local/bin/" && base != "" && h.Typeflag != tar.TypeDir {
			fs.localBin = append(fs.localBin, name)
		}
		if !licensePath(name) {
			continue
		}
		switch h.Typeflag {
		case tar.TypeReg:
			b, err := io.ReadAll(io.LimitReader(tr, maxLicenseFile+1))
			if err != nil {
				return fs, fmt.Errorf("%s: %s: %w", p, name, err)
			}
			if len(b) > maxLicenseFile {
				return fs, fmt.Errorf("%s: %s is larger than %d bytes", p, name, maxLicenseFile)
			}
			fs.files[name] = string(b)
		case tar.TypeSymlink:
			t := h.Linkname
			if !strings.HasPrefix(t, "/") {
				t = path.Join(path.Dir(name), t) //nolint:gosec // G305: a lookup key in memory; nothing is written to disk
			}
			fs.links[name] = strings.TrimPrefix(path.Clean(t), "/")
		}
	}
	sort.Strings(fs.localBin)
	return fs, nil
}

// text returns the content of a license file, following links within the file set.
func (fs rootfs) text(p string) (string, bool) {
	for range 8 {
		if t, ok := fs.links[p]; ok {
			p = t
			continue
		}
		s, ok := fs.files[p]
		return s, ok
	}
	return "", false
}

// commonLicense maps a declared SPDX license to the Debian common-licenses file that holds its text. Licenses whose
// text names a copyright holder (BSD, MIT and the like) are not mapped: the generic file is not their text.
func commonLicense(id string) string {
	for _, m := range []struct{ prefix, file string }{
		{"LGPL-2.0", "LGPL-2"}, {"LGPL-2.1", "LGPL-2.1"}, {"LGPL-3.0", "LGPL-3"},
		{"GPL-1.0", "GPL-1"}, {"GPL-2.0", "GPL-2"}, {"GPL-3.0", "GPL-3"},
		{"GFDL-1.2", "GFDL-1.2"}, {"GFDL-1.3", "GFDL-1.3"},
		{"Apache-2.0", "Apache-2.0"}, {"MPL-1.1", "MPL-1.1"}, {"MPL-2.0", "MPL-2.0"}, {"CC0-1.0", "CC0-1.0"},
		{"Artistic-1.0", "Artistic"},
	} {
		if id == m.prefix || strings.HasPrefix(id, m.prefix+"-") || strings.HasPrefix(id, m.prefix+"+") {
			return m.file
		}
	}
	return ""
}

func copyleft(ids []string) bool {
	for _, id := range ids {
		if strings.Contains(id, "GPL") { // SPDX identifiers: GPL-*, LGPL-*, AGPL-*
			return true
		}
	}
	return false
}

var slugRe = regexp.MustCompile(`[^a-z0-9]+`)

func anchor(ref, p string) string {
	lower := strings.Map(func(r rune) rune { // ASCII only: image references and paths
		if r >= 'A' && r <= 'Z' {
			return r + 'a' - 'A'
		}
		return r
	}, ref+"-"+p)
	return "text-" + strings.Trim(slugRe.ReplaceAllString(lower, "-"), "-")
}

func cell(s string) string { return strings.ReplaceAll(s, "|", `\|`) }

// textRef is one license text of one image the notices point to.
type textRef struct{ ref, path, label string }

type loaded struct {
	in    imageInput
	comps []cdxComponent
	fs    rootfs
}

// renderImages writes IMAGE_NOTICES.md.
func renderImages(w io.Writer, inputs []imageInput, goNoticesPath string) error {
	goRaw, err := os.ReadFile(goNoticesPath) //nolint:gosec // G304: a path from the Makefile
	if err != nil {
		return err
	}
	goNotices := string(goRaw)
	var all []loaded
	for _, in := range inputs {
		comps, err := readSBOM(in.SBOM)
		if err != nil {
			return err
		}
		fs, err := readRootfs(in.Rootfs)
		if err != nil {
			return err
		}
		all = append(all, loaded{in: in, comps: comps, fs: fs})
	}
	// findCommon looks for a common-licenses text in the image itself first, then in the other images of the package.
	findCommon := func(self int, file string) (textRef, bool) {
		order := append([]int{self}, func() []int {
			var o []int
			for i := range all {
				if i != self {
					o = append(o, i)
				}
			}
			return o
		}()...)
		for _, i := range order {
			p := "usr/share/common-licenses/" + file
			if _, ok := all[i].fs.text(p); ok {
				return textRef{ref: all[i].in.Ref, path: p, label: file}, true
			}
		}
		return textRef{}, false
	}

	var b bytes.Buffer
	b.WriteString("# Third-party notices of the container images\n\n" +
		"This package carries two container images as files (`images/`). This document lists what they contain, from each " +
		"image's SBOM (`sbom/`, written by Trivy) and the image's own files: every package with the license its SBOM " +
		"declares, and where its license text is. The license texts the images carry follow the tables. Where a cell says " +
		"\"not in the images\", neither the SBOM nor the images' files give the text, and none is added here. The Go modules " +
		"and npm packages of Alice's own binaries are in `THIRD_PARTY_NOTICES.md` beside this file.\n\n")
	used := map[string]textRef{}
	type offer struct{ ref, comp, lic, src, where string }
	var offers []offer
	for i, l := range all {
		fmt.Fprintf(&b, "## Container image `%s`\n\n", l.in.Ref)
		described := map[string]bool{}
		var rows []cdxComponent
		for _, c := range l.comps {
			switch c.Type {
			case "operating-system":
				fmt.Fprintf(&b, "Operating system: %s %s\n\n", c.Name, c.Version)
			case "application":
				described[strings.TrimPrefix(c.Name, "/")] = true
			default:
				rows = append(rows, c)
			}
		}
		sort.SliceStable(rows, func(a, z int) bool {
			if rows[a].Name != rows[z].Name {
				return rows[a].Name < rows[z].Name
			}
			return rows[a].Version < rows[z].Version
		})
		b.WriteString("| Package | Version | Declared license (SBOM) | Source package | License text |\n|---|---|---|---|---|\n")
		for _, c := range rows {
			ids := c.licenses()
			declared := strings.Join(ids, ", ")
			if declared == "" {
				declared = "not declared in the SBOM"
			}
			var texts []string
			link := func(t textRef) {
				a := anchor(t.ref, t.path)
				used[a] = t
				texts = append(texts, "["+t.label+"](#"+a+")")
			}
			switch {
			case strings.HasPrefix(c.Purl, "pkg:golang/"):
				switch {
				case c.Name == "alice":
					texts = append(texts, "Alice itself: licenses/LICENSE")
				case c.Name == "stdlib" && strings.Contains(goNotices, "### Go standard library go"+strings.TrimPrefix(c.Version, "v")+"\n"),
					c.Name != "stdlib" && strings.Contains(goNotices, "### "+c.Name+" "+c.Version+"\n"):
					texts = append(texts, "in THIRD_PARTY_NOTICES.md")
				}
			case strings.HasPrefix(c.Purl, "pkg:deb/"):
				p := "usr/share/doc/" + c.Name + "/copyright"
				if _, ok := l.fs.text(p); ok {
					link(textRef{ref: l.in.Ref, path: p, label: "/" + p})
				}
			case strings.HasPrefix(c.Purl, "pkg:apk/"):
				var ps []string
				for p := range l.fs.files {
					if strings.HasPrefix(p, "usr/share/licenses/"+c.Name+"/") {
						ps = append(ps, p)
					}
				}
				sort.Strings(ps)
				for _, p := range ps {
					link(textRef{ref: l.in.Ref, path: p, label: "/" + p})
				}
			}
			if !strings.HasPrefix(c.Purl, "pkg:golang/") {
				seen := map[string]bool{}
				for _, id := range ids {
					if f := commonLicense(id); f != "" && !seen[f] {
						seen[f] = true
						if t, ok := findCommon(i, f); ok {
							link(t)
						}
					}
				}
			}
			where := strings.Join(texts, ", ")
			if where == "" {
				where = "not in the images"
			}
			fmt.Fprintf(&b, "| %s | %s | %s | %s | %s |\n", cell(c.Name), cell(c.Version), cell(declared), cell(c.source()), where)
			if copyleft(ids) {
				offers = append(offers, offer{ref: l.in.Ref, comp: strings.TrimSpace(c.Name + " " + c.Version), lic: declared,
					src: c.source(), where: sourceLocation(c)})
			}
		}
		var undescribed []string
		for _, p := range l.fs.localBin {
			if !described[p] {
				undescribed = append(undescribed, "`/"+p+"`")
			}
		}
		b.WriteString("\nFiles in `/usr/local/bin` that no component of the SBOM describes (software the image's maintainers " +
			"installed outside its package manager): ")
		if len(undescribed) == 0 {
			b.WriteString("none.\n\n")
		} else {
			b.WriteString(strings.Join(undescribed, ", ") + ". No license is derived for them here: the SBOM does not " +
				"describe them, and their license text is not among the image's files listed below.\n\n")
		}
	}

	b.WriteString("## Written offer of source code\n\n")
	if len(offers) == 0 {
		b.WriteString("No component of the images declares a GPL or LGPL license.\n\n")
	} else {
		b.WriteString("The components below are licensed under the GNU General Public License or the GNU Lesser General " +
			"Public License. For at least three years from the date on which the vendor last distributed this package, the " +
			"vendor named in `licenses/LICENSE` will give anyone who asks a complete machine-readable copy of the " +
			"corresponding source code of these components, on a medium customarily used for software interchange, for a " +
			"charge no more than the cost of physically performing the distribution. Ask through the support contact of " +
			"your license agreement and name the package version (`VERSION`) and the component. Each component's " +
			"distribution also publishes its source where the table says.\n\n" +
			"| Image | Component | Declared license (SBOM) | Source package | Source published by the distribution |\n|---|---|---|---|---|\n")
		for _, o := range offers {
			fmt.Fprintf(&b, "| %s | %s | %s | %s | %s |\n", cell(o.ref), cell(o.comp), cell(o.lic), cell(o.src), cell(o.where))
		}
		b.WriteString("\n")
	}

	b.WriteString("## License texts in the images\n\n")
	keys := make([]string, 0, len(used))
	for k := range used {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		t := used[k]
		var text string
		for _, l := range all {
			if l.in.Ref == t.ref {
				text, _ = l.fs.text(t.path)
			}
		}
		text = strings.TrimRight(strings.ReplaceAll(text, "\r\n", "\n"), "\n")
		fc := fence(text)
		fmt.Fprintf(&b, "<a id=\"%s\"></a>\n\n### %s: /%s\n\n%stext\n%s\n%s\n\n", k, t.ref, t.path, fc, text, fc)
	}
	_, err = w.Write(b.Bytes())
	return err
}

// sourceLocation says where the component's distribution publishes its source, from the package URL and the source
// package the SBOM names.
func sourceLocation(c cdxComponent) string {
	src, ver := c.property("aquasecurity:trivy:SrcName"), c.property("aquasecurity:trivy:SrcVersion")
	if src == "" {
		src, ver = c.Name, c.Version
	}
	u, err := url.Parse(c.Purl)
	distro := ""
	if err == nil {
		distro = u.Query().Get("distro")
	}
	switch {
	case strings.HasPrefix(c.Purl, "pkg:deb/debian/"):
		return "https://snapshot.debian.org/package/" + url.PathEscape(src) + "/" + url.QueryEscape(ver) + "/"
	case strings.HasPrefix(c.Purl, "pkg:apk/alpine/"):
		parts := strings.Split(distro, ".")
		if len(parts) >= 2 {
			branch := parts[0] + "." + parts[1] + "-stable"
			return "Alpine aports, branch " + branch + " (https://gitlab.alpinelinux.org/alpine/aports/-/tree/" + branch + "), package " + src
		}
		return "Alpine aports (https://gitlab.alpinelinux.org/alpine/aports), package " + src
	case strings.HasPrefix(c.Purl, "pkg:golang/"):
		return "the Go module " + c.Name + "@" + c.Version
	}
	return "not known from the SBOM; ask the vendor (offer above)"
}
