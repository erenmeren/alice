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

func write(t *testing.T, path, content string) {
	t.Helper()
	require.NoError(t, os.MkdirAll(filepath.Dir(path), 0o755))
	require.NoError(t, os.WriteFile(path, []byte(content), 0o644))
}

// goVersionM is what "go version -m bin/alice" prints: one dep line per linked module, a
// replacement on the following => line.
const goVersionM = "bin/alice: go1.27.2\n" +
	"\tpath\talice/cmd/alice\n" +
	"\tmod\talice\t(devel)\t\n" +
	"\tdep\tgithub.com/Azure/azure-sdk-for-go/sdk/azcore\tv1.23.2\th1:abc=\n" +
	"\tdep\tgolang.org/x/crypto\tv0.43.0\th1:def=\n" +
	"\tdep\texample.com/old\tv1.0.0\n" +
	"\t=>\texample.com/new\tv1.1.0\th1:ghi=\n" +
	"\tbuild\t-trimpath=true\n"

const helperVersionM = "bin/alice-helper-linux-amd64: go1.27.2\n" +
	"\tpath\talice/cmd/alice-helper\n" +
	"\tdep\tgolang.org/x/crypto\tv0.43.0\th1:def=\n"

func modCache(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	// Upper-case letters are escaped in module cache paths ("!azure").
	write(t, filepath.Join(dir, "github.com/!azure/azure-sdk-for-go/sdk/azcore@v1.23.2/LICENSE.txt"), "MIT License (azcore)\n")
	write(t, filepath.Join(dir, "golang.org/x/crypto@v0.43.0/LICENSE"), "BSD 3-Clause (x/crypto)\n")
	write(t, filepath.Join(dir, "golang.org/x/crypto@v0.43.0/PATENTS"), "Additional IP Rights Grant\n")
	write(t, filepath.Join(dir, "example.com/new@v1.1.0/COPYING"), "Apache 2.0 (new) ``` fenced\n")
	return dir
}

func TestNoticesCoverEveryLinkedModule(t *testing.T) {
	mods := parseBuildInfo(goVersionM)
	assert.Equal(t, []module{
		{Path: "github.com/Azure/azure-sdk-for-go/sdk/azcore", Version: "v1.23.2"},
		{Path: "golang.org/x/crypto", Version: "v0.43.0"},
		{Path: "example.com/new", Version: "v1.1.0"},
	}, mods)
	assert.Equal(t, "go1.27.2", goVersionOf(goVersionM))

	cache := modCache(t)
	goroot := t.TempDir()
	write(t, filepath.Join(goroot, "LICENSE"), "Go license\n")
	var out bytes.Buffer
	err := render(&out, input{
		GoVersion: "go1.27.2", GoRoot: goroot, ModCache: cache,
		Modules: mergeModules(parseBuildInfo(goVersionM), parseBuildInfo(helperVersionM)),
	})
	require.NoError(t, err)
	doc := out.String()
	for _, want := range []string{
		"### Go standard library go1.27.2", "Go license",
		"### github.com/Azure/azure-sdk-for-go/sdk/azcore v1.23.2", "MIT License (azcore)",
		"### golang.org/x/crypto v0.43.0", "BSD 3-Clause (x/crypto)", "Additional IP Rights Grant",
		"### example.com/new v1.1.0", "Apache 2.0 (new) ``` fenced",
	} {
		assert.Contains(t, doc, want)
	}
	assert.Equal(t, 1, strings.Count(doc, "### golang.org/x/crypto"), "a module linked into both binaries is listed once")
	assert.NotContains(t, doc, "example.com/old", "the replacement is what is linked")
	assert.Contains(t, doc, "````text\nApache 2.0 (new) ``` fenced\n````", "a fence longer than any run of backticks in the text")

	// A module without a license file fails the tool.
	require.NoError(t, os.Remove(filepath.Join(cache, "example.com/new@v1.1.0/COPYING")))
	err = render(&bytes.Buffer{}, input{GoVersion: "go1.27.2", GoRoot: goroot, ModCache: cache, Modules: parseBuildInfo(goVersionM)})
	require.ErrorContains(t, err, "example.com/new v1.1.0")
	// A module missing from the cache fails too.
	err = render(&bytes.Buffer{}, input{GoVersion: "go1.27.2", GoRoot: goroot, ModCache: t.TempDir(), Modules: parseBuildInfo(helperVersionM)})
	require.ErrorContains(t, err, "golang.org/x/crypto")
}

func TestNoticesCoverBundledNpmPackages(t *testing.T) {
	nm := t.TempDir()
	lock := filepath.Join(t.TempDir(), "package-lock.json")
	write(t, lock, `{
  "lockfileVersion": 3,
  "packages": {
    "": {"name": "alice-web", "dependencies": {"react": "18.3.1"}},
    "node_modules/react": {"version": "18.3.1", "license": "MIT"},
    "node_modules/@mantine/core": {"version": "8.3.18", "license": "MIT"},
    "node_modules/@mantine/core/node_modules/clsx": {"version": "2.1.1", "license": "MIT"},
    "node_modules/no-license-file": {"version": "1.0.0", "license": "MIT", "author": "Jane Doe"},
    "node_modules/vitest": {"version": "3.0.0", "license": "MIT", "dev": true},
    "node_modules/fsevents": {"version": "2.3.3", "license": "MIT", "optional": true}
  }
}`)
	write(t, filepath.Join(nm, "react/LICENSE"), "MIT (react)\n")
	write(t, filepath.Join(nm, "@mantine/core/LICENSE.md"), "MIT (mantine)\n")
	write(t, filepath.Join(nm, "@mantine/core/node_modules/clsx/license"), "MIT (clsx)\n")
	write(t, filepath.Join(nm, "no-license-file/package.json"), `{"name": "no-license-file"}`)
	write(t, filepath.Join(nm, "vitest/LICENSE"), "dev tool\n")

	pkgs, err := npmPackages(lock)
	require.NoError(t, err)
	var names []string
	for _, p := range pkgs {
		names = append(names, p.Name+" "+p.Version)
	}
	assert.Equal(t, []string{"@mantine/core 8.3.18", "clsx 2.1.1", "fsevents 2.3.3", "no-license-file 1.0.0", "react 18.3.1"}, names,
		"every package without dev: true, sorted by path")

	cache := modCache(t)
	goroot := t.TempDir()
	write(t, filepath.Join(goroot, "LICENSE"), "Go license\n")
	var out bytes.Buffer
	require.NoError(t, render(&out, input{GoVersion: "go1.27.2", GoRoot: goroot, ModCache: cache, NodeModules: nm, Npm: pkgs}))
	doc := out.String()
	for _, want := range []string{
		"### react 18.3.1", "MIT (react)", "### @mantine/core 8.3.18", "MIT (mantine)", "### clsx 2.1.1", "MIT (clsx)",
		"### no-license-file 1.0.0", "License: MIT (as declared in its package.json; the package ships no license file). Author: Jane Doe",
	} {
		assert.Contains(t, doc, want)
	}
	assert.NotContains(t, doc, "vitest")
	assert.NotContains(t, doc, "fsevents", "an optional package that is not installed is not bundled")

	// A package that should be installed but is not: run make web-install first.
	require.NoError(t, os.RemoveAll(filepath.Join(nm, "react")))
	err = render(&bytes.Buffer{}, input{GoVersion: "go1.27.2", GoRoot: goroot, ModCache: cache, NodeModules: nm, Npm: pkgs})
	require.ErrorContains(t, err, "react")
}

func TestCommandLine(t *testing.T) {
	var out bytes.Buffer
	assert.Equal(t, 2, run([]string{"-bogus"}, &out))
	assert.Equal(t, 2, run(nil, &out))

	// The test binary itself is a Go binary with build information and modules in the real cache.
	self, err := os.Executable()
	require.NoError(t, err)
	lock := filepath.Join(t.TempDir(), "package-lock.json")
	write(t, lock, `{"lockfileVersion": 3, "packages": {"": {}}}`)
	dest := filepath.Join(t.TempDir(), "THIRD_PARTY_NOTICES.md")
	out.Reset()
	require.Equal(t, 0, run([]string{"-binaries", self, "-lockfile", lock, "-node-modules", t.TempDir(), "-out", dest}, &out), out.String())
	raw, err := os.ReadFile(dest)
	require.NoError(t, err)
	assert.Contains(t, string(raw), "### github.com/stretchr/testify ")
	assert.Contains(t, string(raw), "### Go standard library go")
	out.Reset()
	assert.Equal(t, 1, run([]string{"-binaries", filepath.Join(t.TempDir(), "missing"), "-lockfile", lock, "-node-modules", t.TempDir(), "-out", dest + "2"}, &out))
}

func TestNpmPackageWithoutAnyLicenseFails(t *testing.T) {
	nm := t.TempDir()
	write(t, filepath.Join(nm, "mystery/package.json"), `{}`)
	goroot := t.TempDir()
	write(t, filepath.Join(goroot, "LICENSE"), "Go license\n")
	err := render(&bytes.Buffer{}, input{GoVersion: "go1.27.2", GoRoot: goroot, NodeModules: nm,
		Npm: []npmPackage{{Key: "node_modules/mystery", Name: "mystery", Version: "1.0.0"}}})
	require.ErrorContains(t, err, "neither a license file nor a declared license")
	err = render(&bytes.Buffer{}, input{GoVersion: "go1.27.2", GoRoot: t.TempDir()})
	require.ErrorContains(t, err, "Go standard library")
	assert.Equal(t, "MIT", jsonText([]byte(`{"type": "MIT"}`)))
	assert.Equal(t, "Jane", jsonText([]byte(`{"name": "Jane"}`)))
	assert.Empty(t, jsonText([]byte(`[1]`)))
	assert.Empty(t, goVersionOf(""))
}
