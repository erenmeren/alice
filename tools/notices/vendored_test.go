package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func writeVendored(t *testing.T, licenseText string, withFile bool) (root, manifest string) {
	t.Helper()
	root = t.TempDir()
	require.NoError(t, os.MkdirAll(filepath.Join(root, "web/src/design/fonts"), 0o755))
	if licenseText != "" {
		require.NoError(t, os.WriteFile(filepath.Join(root, "web/src/design/fonts/OFL.txt"), []byte(licenseText), 0o644))
	}
	if withFile {
		require.NoError(t, os.WriteFile(filepath.Join(root, "web/src/design/fonts/geist.woff"), []byte("wOFF"), 0o644))
	}
	manifest = filepath.Join(root, "web/src/design/THIRD_PARTY.json")
	require.NoError(t, os.WriteFile(manifest, []byte(`[{"name":"Geist","source":"https://github.com/vercel/geist-font","license":"OFL-1.1",
"files":["web/src/design/fonts/geist.woff"],"licenseFile":"web/src/design/fonts/OFL.txt"}]`), 0o644))
	return root, manifest
}

func TestVendoredAssetsSection(t *testing.T) {
	root, manifest := writeVendored(t, "SIL OPEN FONT LICENSE Version 1.1\n", true)
	assets, err := vendoredAssets(manifest, root)
	require.NoError(t, err)
	var b strings.Builder
	require.NoError(t, renderVendored(&b, assets))
	out := b.String()
	require.Contains(t, out, "## Web UI (vendored assets)")
	require.Contains(t, out, "### Geist (OFL-1.1)")
	require.Contains(t, out, "Source: https://github.com/vercel/geist-font")
	require.Contains(t, out, "web/src/design/fonts/geist.woff")
	require.Contains(t, out, "SIL OPEN FONT LICENSE Version 1.1")
}

func TestVendoredAssetWithoutLicenseFails(t *testing.T) {
	root, manifest := writeVendored(t, "", true)
	_, err := vendoredAssets(manifest, root)
	require.ErrorContains(t, err, "vendored asset Geist")
}

func TestVendoredAssetWithMissingFileFails(t *testing.T) {
	root, manifest := writeVendored(t, "license", false)
	_, err := vendoredAssets(manifest, root)
	require.ErrorContains(t, err, "geist.woff")
}

func TestVendoredManifestErrors(t *testing.T) {
	dir := t.TempDir()
	_, err := vendoredAssets(filepath.Join(dir, "missing.json"), dir)
	require.ErrorContains(t, err, "vendored assets")

	bad := filepath.Join(dir, "bad.json")
	write(t, bad, `{`)
	_, err = vendoredAssets(bad, dir)
	require.ErrorContains(t, err, "bad.json")

	noLicense := filepath.Join(dir, "nolicense.json")
	write(t, noLicense, `[{"name":"Lucide","licenseFile":"LICENSE"}]`)
	_, err = vendoredAssets(noLicense, dir)
	require.ErrorContains(t, err, "vendored asset Lucide: name, license and licenseFile are required")

	unnamed := filepath.Join(dir, "unnamed.json")
	write(t, unnamed, `[{"license":"ISC","licenseFile":"LICENSE"}]`)
	_, err = vendoredAssets(unnamed, dir)
	require.ErrorContains(t, err, "vendored asset (unnamed): name, license and licenseFile are required")

	noFiles := filepath.Join(dir, "nofiles.json")
	write(t, noFiles, `[{"name":"Lucide","license":"ISC","files":[],"licenseFile":"LICENSE"}]`)
	_, err = vendoredAssets(noFiles, dir)
	require.ErrorContains(t, err, "vendored asset Lucide: files must list at least one file")

	require.NoError(t, os.Mkdir(filepath.Join(dir, "icons"), 0o755))
	isDir := filepath.Join(dir, "isdir.json")
	write(t, isDir, `[{"name":"Lucide","license":"ISC","files":["icons"],"licenseFile":"LICENSE"}]`)
	_, err = vendoredAssets(isDir, dir)
	require.ErrorContains(t, err, "vendored asset Lucide: icons is a directory, not a file")

	write(t, filepath.Join(dir, "icons.ts"), "export {}")
	blank := filepath.Join(dir, "blank.json")
	write(t, blank, `[{"name":"Lucide","license":"ISC","files":["icons.ts"],"licenseFile":"BLANK"}]`)
	write(t, filepath.Join(dir, "BLANK"), " \n\t\n")
	_, err = vendoredAssets(blank, dir)
	require.ErrorContains(t, err, "license file BLANK is missing or empty")
}

func TestRenderVendoredEdgeCases(t *testing.T) {
	var b bytes.Buffer
	require.NoError(t, renderVendored(&b, nil))
	assert.Empty(t, b.String(), "no manifest, no section")

	// No source line without a source; a license text with backticks gets a longer fence; CRLF is normalised.
	require.NoError(t, renderVendored(&b, []vendoredAsset{{Name: "Icons", License: "ISC", Files: []string{"a.js"},
		text: "line one\r\n```quoted```\r\n"}}))
	out := b.String()
	assert.NotContains(t, out, "Source:")
	assert.Contains(t, out, "- `a.js`\n")
	assert.Contains(t, out, "````text\nline one\n```quoted```\n````\n")
}

// The repository's own manifest: every listed file exists and every license text is present, so a path typo in
// web/src/design/THIRD_PARTY.json fails here and not at release time.
func TestRepositoryVendoredManifest(t *testing.T) {
	root := filepath.Join("..", "..")
	assets, err := vendoredAssets(filepath.Join(root, "web/src/design/THIRD_PARTY.json"), root)
	require.NoError(t, err)
	require.Len(t, assets, 2)
	for _, a := range assets {
		require.NotEmpty(t, a.Files, a.Name)
		for _, f := range a.Files {
			st, err := os.Stat(filepath.Join(root, filepath.FromSlash(f)))
			require.NoError(t, err, f)
			require.False(t, st.IsDir(), f)
		}
		require.NotEmpty(t, strings.TrimSpace(a.text), a.Name)
	}
	var b strings.Builder
	require.NoError(t, renderVendored(&b, assets))
	out := b.String()
	assert.Contains(t, out, "### Geist and Geist Mono (OFL-1.1)")
	assert.Contains(t, out, "SIL OPEN FONT LICENSE")
	// Lucide is ISC; its Feather-derived icons are MIT, and the vendored LUCIDE-LICENSE carries both texts.
	assert.Contains(t, out, "### Lucide icons (subset) (ISC AND MIT)")
	assert.Contains(t, out, "ISC License")
	assert.Contains(t, out, "The MIT License")
}
