package web

import (
	"embed"
	"fmt"
	"html/template"
	"io/fs"
	"path"
)

// The UI is compiled in so that a deployment is one binary and what is served cannot drift from
// what was reviewed.
//
//go:embed templates/*.html
var templateFiles embed.FS

//go:embed static
var staticFiles embed.FS

// staticFS is the static directory as the root of the files served under /static/.
func staticFS() (fs.FS, error) {
	sub, err := fs.Sub(staticFiles, "static")
	if err != nil {
		return nil, fmt.Errorf("web: static files: %w", err)
	}
	return sub, nil
}

// parsePages parses every template except layout.html as a page set together with layout.html,
// keyed by file name without extension ("login", "enroll", ...). Each page defines "title" and
// "content"; a new page file is picked up without changes here.
func parsePages() (map[string]*template.Template, error) {
	names, err := fs.Glob(templateFiles, "templates/*.html")
	if err != nil {
		return nil, fmt.Errorf("web: templates: %w", err)
	}
	pages := make(map[string]*template.Template, len(names))
	for _, n := range names {
		base := path.Base(n)
		if base == "layout.html" {
			continue
		}
		t, err := template.New("layout.html").ParseFS(templateFiles, "templates/layout.html", n)
		if err != nil {
			return nil, fmt.Errorf("web: template %s: %w", base, err)
		}
		pages[base[:len(base)-len(".html")]] = t
	}
	return pages, nil
}
