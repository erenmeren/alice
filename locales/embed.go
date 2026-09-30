// Package locales embeds the translation catalogs shared by the backend and the web UI.
package locales

import "embed"

// FS contains manifest.json and common/<code>.json.
//
//go:embed manifest.json common/*.json
var FS embed.FS
