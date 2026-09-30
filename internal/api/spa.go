package api

import (
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"io/fs"
	"net/http"
	"path"
	"strings"
)

const noncePlaceholder = "__CSP_NONCE__"

const spaCSPTemplate = "default-src 'none'; script-src 'self'; style-src 'self' 'nonce-%NONCE%'; img-src 'self' data:; font-src 'self'; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'"

const notBuiltPage = `<!doctype html><html lang="en"><head><meta charset="utf-8"><title>Alice</title></head>
<body><h1>The Alice web interface is not built.</h1><p>Developers: run <code>make web</code> and rebuild the binary.</p></body></html>`

func (s *server) spa() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			w.Header().Set("Allow", "GET, HEAD")
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		name := strings.TrimPrefix(path.Clean("/"+r.URL.Path), "/")
		if name != "" && name != "index.html" && fs.ValidPath(name) {
			if st, err := fs.Stat(s.deps.UI, name); err == nil && !st.IsDir() {
				if strings.HasPrefix(name, "assets/") {
					w.Header().Set("Cache-Control", "public, max-age=31536000, immutable")
				} else {
					w.Header().Set("Cache-Control", "no-cache")
				}
				http.ServeFileFS(w, r, s.deps.UI, name) //nolint:gosec // G703: fs.FS rooted at the UI, name cleaned and validated with fs.ValidPath
				return
			}
			if isAssetPath(name) {
				http.NotFound(w, r)
				return
			}
		}
		s.serveIndex(w)
	})
}

// rootFiles are files a browser or crawler requests by convention. When they
// are missing the answer is 404, not the SPA.
var rootFiles = map[string]bool{
	"favicon.ico":          true,
	"favicon.svg":          true,
	"robots.txt":           true,
	"manifest.webmanifest": true,
}

// isAssetPath reports whether a missing file must be a 404. Everything else is
// a client-side route (even with a dot in it, such as /users/a.b) and gets index.html.
func isAssetPath(name string) bool {
	return strings.HasPrefix(name, "assets/") || rootFiles[name]
}

func (s *server) serveIndex(w http.ResponseWriter) {
	index, err := fs.ReadFile(s.deps.UI, "index.html")
	if errors.Is(err, fs.ErrNotExist) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Header().Set("Cache-Control", "no-store")
		w.WriteHeader(http.StatusServiceUnavailable)
		_, _ = w.Write([]byte(notBuiltPage))
		return
	}
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	nonce := newNonce()
	w.Header().Set("Content-Security-Policy", strings.Replace(spaCSPTemplate, "%NONCE%", nonce, 1))
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	_, _ = w.Write(bytes.ReplaceAll(index, []byte(noncePlaceholder), []byte(nonce)))
}

func newNonce() string {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		panic("crypto/rand failed: " + err.Error())
	}
	return base64.StdEncoding.EncodeToString(b)
}
