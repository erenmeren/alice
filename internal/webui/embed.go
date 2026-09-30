// Package webui embeds the built web UI. Build it with `make web`; without a
// build the server shows a "not built" page instead of failing.
package webui

import (
	"embed"
	"io/fs"
)

//go:embed all:dist
var dist embed.FS

// UI returns the built SPA rooted at its index.html.
func UI() fs.FS {
	sub, err := fs.Sub(dist, "dist/app")
	if err != nil {
		panic(err) // only possible if the embed pattern is wrong
	}
	return sub
}
