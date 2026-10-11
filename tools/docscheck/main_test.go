package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func put(t *testing.T, root, rel, content string) {
	t.Helper()
	p := filepath.Join(root, filepath.FromSlash(rel))
	require.NoError(t, os.MkdirAll(filepath.Dir(p), 0o750))
	require.NoError(t, os.WriteFile(p, []byte(content), 0o600))
}

// repo builds the files docscheck reads for what the guides may name.
func repo(t *testing.T) string {
	root := t.TempDir()
	put(t, root, "deploy/release/install.sh", "usage() {\n  cat <<'USAGE'\nUsage: sudo ./install.sh [--dir DIR] [--non-interactive --fingerprint HEX]\n  --restore-mode  prepare\nUSAGE\n}\n")
	put(t, root, "deploy/release/alice-update.sh", "usage() {\n  cat <<'USAGE'\nUsage: ./alice-update.sh PKG [--passphrase-file FILE] [--non-interactive]\nUSAGE\n}\n")
	put(t, root, "deploy/release/alicectl", "usage() {\n  cat <<'USAGE'\nUsage: sudo ./alicectl <command>\n\n  backup [--out FILE]   write a backup\n  restore FILE [--db-only]\n  audit verify\n  help  show\nUSAGE\n}\n")
	put(t, root, "cmd/alice/main.go", "package main\n\nconst usage = `Usage: alice <command>\n\nCommands:\n  serve    Start\n  admin unlock <username>   unlock\n  audit verify   check\n`\n")
	put(t, root, "Makefile", "A_IMAGE ?= x\n.PHONY: up lint\nup: ## start\n\techo up\nlint test: ## lint\n\techo lint\n")
	put(t, root, "tools/docscheck/required.txt", "")
	return root
}

func messages(t *testing.T, root string) string {
	t.Helper()
	return strings.Join(Check(root), "\n")
}

func TestCommandsInGuidesExist(t *testing.T) {
	root := repo(t)
	put(t, root, "docs/ok.md", "# Guide\n\n```sh\n$ sudo ./install.sh --dir /opt/alice --non-interactive --fingerprint abc\nsudo ./alicectl backup --out f   # a comment\ncd /opt/alice && sudo ./alice-update.sh alice.tar.gz --passphrase-file p\nmake lint && make test\nmake up IMAGE_TAG=x\ndocker compose exec alice alice admin unlock ada\nalice audit verify\ndocker compose logs alice\nexport PATH=a alice serve\n```\n\nRun `alicectl restore f --db-only`, then `make up`. Make sure it works; make a copy.\nPlain text may say alicectl frobnicate or make nothing, and `alice` alone is a name.\n")
	assert.Empty(t, messages(t, root))

	put(t, root, "docs/bad.md", "```sh\nsudo ./alicectl frobnicate\nsudo ./alicectl backup --nope\nsudo ./install.sh --nope-either\n./alice-update.sh p --force\nmake nowhere\nalice keys rotate\ndocker compose exec alice alice destroy\n/usr/local/bin/alice reset\n```\n\nInline `make elsewhere` and `alicectl vanish` and `alice gone`.\n")
	got := messages(t, root)
	for _, want := range []string{
		"docs/bad.md:2: alicectl frobnicate",
		"docs/bad.md:3: alicectl --nope",
		"docs/bad.md:4: install.sh --nope-either",
		"docs/bad.md:5: alice-update.sh --force",
		"docs/bad.md:6: make nowhere",
		"docs/bad.md:7: alice keys",
		"docs/bad.md:8: alice destroy",
		"docs/bad.md:9: alice reset",
		"docs/bad.md:12: make elsewhere",
		"docs/bad.md:12: alicectl vanish",
		"docs/bad.md:12: alice gone",
	} {
		assert.Contains(t, got, want)
	}
	assert.Equal(t, 11, len(Check(root)), got)
}

func TestScopeOfTheGuides(t *testing.T) {
	root := repo(t)
	bad := "```sh\nmake nowhere\n```\n"
	put(t, root, "docs/superpowers/plans/p.md", bad)
	put(t, root, "docs/security/reviews/r.md", bad)
	put(t, root, "docs/dev/d.md", "```sh\nmake up\n```\n")
	put(t, root, "CHANGELOG.md", "# Changelog\n\n## Unreleased — Phase 8\n\nRun `make up`.\n\n## Unreleased — Phase 7\n\nOld text with `make gone`.\n")
	assert.Empty(t, messages(t, root), "plans and reviews are not guides; the changelog counts from its Phase 8 entry")

	put(t, root, "SECURITY-REPORT.md", bad)
	assert.Contains(t, messages(t, root), "SECURITY-REPORT.md:2: make nowhere")
	put(t, root, "CHANGELOG.md", "# Changelog\n\n## Unreleased — Phase 8\n\nRun `make gone`.\n")
	assert.Contains(t, messages(t, root), "CHANGELOG.md:5: make gone")

	_, err := loadKnown(t.TempDir())
	assert.Error(t, err)
}

func TestRelativeLinksResolve(t *testing.T) {
	root := repo(t)
	put(t, root, "docs/a.md", "# A\n\n## Second part\n\n```\n## not a heading\n```\n\n[ok](b.md) [ok2](b.md#target-heading) [self](#second-part) [dir](../tools) [web](https://example.com/x.md) [mail](mailto:a@b.c) [root](/Makefile)\n`[code](nowhere.md)`\n")
	put(t, root, "docs/b.md", "# B\n\n## Target heading\n\n### `Code` and [link](b.md)\n\n## Twice\n\n## Twice\n")
	assert.Empty(t, messages(t, root))

	put(t, root, "docs/c.md", "[a](missing.md) [b](b.md#nope) [c](#nowhere) [d](../../outside.md) [e](b.md#twice-1) [f](b.md#code-and-link)\n[g](b.md#not-a-heading)\n")
	got := Check(root)
	require.Len(t, got, 5, strings.Join(got, "\n"))
	joined := strings.Join(got, "\n")
	assert.Contains(t, joined, `docs/c.md:2: link "b.md#not-a-heading"`)
	assert.Contains(t, joined, `docs/c.md:1: link "missing.md": docs/missing.md does not exist`)
	assert.Contains(t, joined, `no heading #nope in docs/b.md`)
	assert.Contains(t, joined, `no heading #nowhere in docs/c.md`)
	assert.Contains(t, joined, `link "../../outside.md" leaves the repository`)
}

func TestRequiredTextIsPresent(t *testing.T) {
	root := repo(t)
	put(t, root, "docs/g.md", "# G\n\nCheck the outer signature\nfirst, then the fingerprint.\n")
	put(t, root, "tools/docscheck/required.txt", "# a comment\n\ndocs/g.md\tCheck the outer signature first\ndocs/g.md\tthen the fingerprint.\n")
	assert.Empty(t, messages(t, root), "a sentence survives re-wrapping")

	put(t, root, "tools/docscheck/required.txt", "docs/g.md\tthis sentence was dropped\ndocs/gone.md\tx\nnot a pair\ndocs/g.md\t\n")
	got := Check(root)
	require.Len(t, got, 4, strings.Join(got, "\n"))
	joined := strings.Join(got, "\n")
	assert.Contains(t, joined, `required.txt:1: docs/g.md no longer contains "this sentence was dropped"`)
	assert.Contains(t, joined, "required.txt:2: docs/gone.md does not exist")
	assert.Contains(t, joined, `required.txt:3: not "<file><TAB><required text>"`)

	require.NoError(t, os.Remove(filepath.Join(root, "tools/docscheck/required.txt")))
	assert.Contains(t, messages(t, root), "required.txt")
}

func TestTheRepositoryGuidesPass(t *testing.T) {
	assert.Empty(t, Check("../.."))
}
