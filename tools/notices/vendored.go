package main

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
)

// vendoredAsset is one entry of web/src/design/THIRD_PARTY.json: files copied into the web UI that are not npm packages
// (the Geist fonts and the Lucide icon subset of the Clarity design). Paths are relative to the repository root.
type vendoredAsset struct {
	Name        string   `json:"name"`
	Source      string   `json:"source"`
	License     string   `json:"license"`
	Files       []string `json:"files"`
	LicenseFile string   `json:"licenseFile"`
	text        string
}

// vendoredAssets reads the manifest and every license text; a missing license, name or listed file is an error, so a
// release never ships an asset without its notice.
func vendoredAssets(manifest, root string) ([]vendoredAsset, error) {
	raw, err := os.ReadFile(manifest) //nolint:gosec // G304: the manifest path is the operator's flag
	if err != nil {
		return nil, fmt.Errorf("vendored assets: %w", err)
	}
	var out []vendoredAsset
	if err := json.Unmarshal(raw, &out); err != nil {
		return nil, fmt.Errorf("vendored assets: %s: %w", manifest, err)
	}
	for i := range out {
		a := &out[i]
		if a.Name == "" || a.License == "" || a.LicenseFile == "" {
			return nil, fmt.Errorf("vendored asset %q: name, license and licenseFile are required", a.Name)
		}
		for _, f := range a.Files {
			if _, err := os.Stat(filepath.Join(root, filepath.FromSlash(f))); err != nil {
				return nil, fmt.Errorf("vendored asset %s: %s: %w", a.Name, f, err)
			}
		}
		text, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(a.LicenseFile))) //nolint:gosec // G304: a path from the repository's manifest
		if err != nil || strings.TrimSpace(string(text)) == "" {
			return nil, fmt.Errorf("vendored asset %s: license file %s is missing or empty", a.Name, a.LicenseFile)
		}
		a.text = string(text)
	}
	return out, nil
}

// renderVendored writes the "Web UI (vendored assets)" section; nothing when there are no assets. The license text is
// fenced like the other sections' texts (writeTexts): line endings normalised, a fence longer than any backtick run.
func renderVendored(w io.Writer, assets []vendoredAsset) error {
	if len(assets) == 0 {
		return nil
	}
	var b strings.Builder
	b.WriteString("## Web UI (vendored assets)\n\n")
	for _, a := range assets {
		fmt.Fprintf(&b, "### %s (%s)\n\n", a.Name, a.License)
		if a.Source != "" {
			fmt.Fprintf(&b, "Source: %s\n\n", a.Source)
		}
		b.WriteString("Files:\n\n")
		for _, f := range a.Files {
			fmt.Fprintf(&b, "- `%s`\n", f)
		}
		text := strings.TrimRight(strings.ReplaceAll(a.text, "\r\n", "\n"), "\n")
		fc := fence(text)
		fmt.Fprintf(&b, "\n%stext\n%s\n%s\n\n", fc, text, fc)
	}
	_, err := io.WriteString(w, b.String())
	return err
}
