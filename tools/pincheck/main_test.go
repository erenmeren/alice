package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const (
	sha   = "3d3c42e5aac5ba805825da76410c181273ba90b1"
	dg    = "sha256:ebfe2f90462722a7a4de65e91990e97fe0d401c70e0e762c5b53302f905ec1c1"
	pgRef = "postgres:16-alpine@sha256:721873c34ceb9f8d8fc265984940dc982404c105f19ad51be9fdc5970a6080ea"
)

func TestRepositoryIsPinned(t *testing.T) {
	assert.Empty(t, check("../.."))
}

func write(t *testing.T, root, rel, content string) {
	t.Helper()
	p := filepath.Join(root, filepath.FromSlash(rel))
	require.NoError(t, os.MkdirAll(filepath.Dir(p), 0o750))
	require.NoError(t, os.WriteFile(p, []byte(content), 0o600))
}

// messages runs check on a tree of one file and returns its problems.
func messages(t *testing.T, rel, content string) []string {
	t.Helper()
	root := t.TempDir()
	write(t, root, rel, content)
	return check(root)
}

func TestCheckFindsUnpinnedReferences(t *testing.T) {
	root := t.TempDir()
	write(t, root, ".github/workflows/ci.yml", "jobs:\n  a:\n    steps:\n"+
		"      - uses: actions/checkout@"+sha+" # v7.0.1\n"+
		"      - uses: actions/setup-go@v7\n")
	write(t, root, "deploy/Dockerfile", "FROM golang:1.27@"+dg+" AS build\nFROM alpine:3.20\n")
	write(t, root, "deploy/docker-compose.yml", "services:\n  db:\n    image: "+pgRef+"\n  cache:\n    image: redis:7\n")
	write(t, root, "Makefile", "GITLEAKS_IMAGE ?= g:1@"+dg+"\nTRIVY_IMAGE ?= t:1@"+dg+"\n"+
		"ok:\n\tdocker run --rm $(TRIVY_IMAGE) fs .\nbad:\n\tdocker run --rm busybox:1 true\n")
	write(t, root, "internal/x/x.go", "package x\nvar a = postgres.Run(ctx, \""+pgRef+"\")\nvar b = postgres.Run(ctx, \"postgres:16-alpine\")\n")
	got := check(root)
	require.Len(t, got, 5, strings.Join(got, "\n"))
	joined := strings.Join(got, "\n")
	for _, want := range []string{"setup-go@v7", "alpine:3.20", "redis:7", "busybox:1", "postgres:16-alpine is not pinned"} {
		assert.Contains(t, joined, want)
	}
}

func TestWorkflowForms(t *testing.T) {
	const w = ".github/workflows/w.yml"
	assert.Empty(t, messages(t, w, "steps:\n  - uses: ./local-action\n  - uses: ../up\n  - uses: \"actions/checkout@"+sha+"\" # v7\n  - uses: o/r/sub/dir@"+sha+" # v1.2\n  - uses: docker://alpine@"+dg+"\n"))
	assert.Empty(t, messages(t, w, "steps:\n  - uses: &anchor actions/checkout@"+sha+" # v7.0.1\n  - uses: *anchor\n  - name: x # uses: nothing@v1\n"))
	assert.Len(t, messages(t, w, "steps:\n  - uses: actions/checkout@"+sha+"\n"), 1, "SHA without a version comment")
	assert.Len(t, messages(t, w, "steps:\n  - uses: actions/checkout@"+sha+" # latest\n"), 1, "comment is not a version")
	assert.Len(t, messages(t, w, "steps:\n  - uses: actions/checkout@main\n"), 1, "branch")
	assert.Len(t, messages(t, w, "steps:\n  - uses: actions/checkout@"+sha[:39]+" # v7\n"), 1, "short SHA")
	assert.Len(t, messages(t, w, "steps:\n  - uses: actions/checkout@"+"3D3C42E5AAC5BA805825DA76410C181273BA90B1"+" # v7\n"), 1, "upper-case SHA")
	assert.Len(t, messages(t, w, "steps:\n  - uses: docker://alpine:3.20\n"), 1, "docker:// by tag")
	assert.Len(t, messages(t, w, "steps:\n  - uses: o/r/.github/workflows/x.yml@v1\n"), 1, "reusable workflow by tag")
	assert.Empty(t, messages(t, ".github/actions/x/action.yml", "runs:\n  steps:\n    - uses: actions/checkout@"+sha+" # v7\n"))
	assert.Len(t, messages(t, ".github/actions/x/action.yml", "runs:\n  steps:\n    - uses: actions/checkout@v7\n"), 1, "composite action")
}

func TestDockerfileForms(t *testing.T) {
	const f = "Dockerfile"
	img := "golang:1.27@" + dg
	assert.Empty(t, messages(t, f, "# syntax=docker/dockerfile:1@"+dg+"\nFROM "+img+" AS Build\nFROM --platform=linux/amd64 "+img+"\nCOPY --from=build /a /b\nFROM scratch\nFROM build AS again\nCOPY --from=0 /a /b\nCOPY --from=again /a /b\nRUN --mount=type=bind,from=build,target=/x true\n"))
	assert.Len(t, messages(t, f, "# syntax=docker/dockerfile:1\nFROM "+img+"\n"), 1, "syntax frontend by tag")
	assert.Len(t, messages(t, f, "FROM alpine:3.20 AS base\n"), 1, "tag only")
	assert.Len(t, messages(t, f, "FROM alpine AS base\n"), 1, "no tag")
	assert.Len(t, messages(t, f, "from alpine:3.20 as base\n"), 1, "lower case")
	assert.Len(t, messages(t, f, "FROM --platform=$BUILDPLATFORM alpine:3.20\n"), 1, "flag then tag")
	assert.Len(t, messages(t, f, "FROM \\\n  alpine:3.20\n"), 1, "continued line")
	assert.Empty(t, messages(t, f, "FROM \\\n  "+img+"\n"))
	assert.Len(t, messages(t, f, "COPY --from=nginx:1 /a /b\nFROM "+img+"\n"), 1, "COPY --from an image by tag")
	assert.Empty(t, messages(t, f, "FROM "+img+"\nCOPY --from=nginx:1@"+dg+" /a /b\n"))
	assert.Len(t, messages(t, f, "FROM "+img+"\nCOPY --from=nginx:1 /a /b\n"), 1, "COPY --from an image by tag after a stage")
	// build arguments
	assert.Empty(t, messages(t, f, "ARG BASE="+img+"\nFROM ${BASE}\n"))
	assert.Empty(t, messages(t, f, "ARG BASE="+img+"\nFROM $BASE AS x\n"))
	assert.Len(t, messages(t, f, "ARG BASE=alpine:3.20\nFROM ${BASE}\n"), 1, "default is a tag")
	assert.Len(t, messages(t, f, "ARG BASE\nFROM ${BASE}\n"), 1, "no default")
	assert.Len(t, messages(t, f, "FROM ${BASE}\n"), 1, "undeclared")
	assert.Empty(t, messages(t, f, "FROM ${BASE:-"+img+"}\n"), "inline default")
	// file names
	assert.Len(t, messages(t, "sub/ubuntu22.Dockerfile", "FROM ubuntu:22.04\n"), 1)
	assert.Len(t, messages(t, "sub/Dockerfile.dev", "FROM ubuntu:22.04\n"), 1)
	assert.Empty(t, messages(t, "sub/notes.txt", "FROM ubuntu:22.04\n"))
}

func TestComposeForms(t *testing.T) {
	const f = "deploy/docker-compose.e2e.yml"
	assert.Empty(t, messages(t, f, "services:\n  a:\n    image: alice:e2e\n    build: { context: . }\n  b:\n    image: x\n    build:\n      context: .\n  c:\n    ports: []\n"))
	assert.Len(t, messages(t, f, "services:\n  a:\n    image: redis:7\n"), 1)
	assert.Empty(t, messages(t, f, "services:\n  a:\n    image: &img redis:7@"+dg+"\n  b:\n    image: *img\n"))
	assert.Len(t, messages(t, f, "x-base: &base\n  image: redis:7\nservices:\n  a:\n    <<: *base\n  b:\n    <<: *base\n"), 2, "merged anchors count per service")
	assert.Len(t, messages(t, "compose.yaml", "services:\n  a:\n    image: ${IMG:-redis:7}\n"), 1, "variable default is not a digest")
	assert.Empty(t, messages(t, "other.yml", "services:\n  a:\n    image: redis:7\n"), "not a compose file name")
}

func TestMakefileAndShellRun(t *testing.T) {
	vars := "GITLEAKS_IMAGE ?= g:1@" + dg + "\nTRIVY_IMAGE ?= t:1@" + dg + "\n"
	assert.Empty(t, messages(t, "Makefile", vars+"a:\n\tdocker run --rm \\\n\t  -v x:/y \\\n\t  $(GITLEAKS_IMAGE) git\n\tdocker run alice:$(IMAGE_TAG)\n\t@docker run --rm x@"+dg+" y\n\t# docker run bad:1\n"))
	assert.Len(t, messages(t, "Makefile", vars+"a:\n\tdocker run --rm \\\n\t  -v x:/y \\\n\t  ghcr.io/gitleaks/gitleaks:v8 git\n"), 1, "multi-line run by tag")
	assert.Len(t, messages(t, "Makefile", vars+"a:\n\tdocker run --rm $(OTHER_IMAGE) x\n"), 1, "unknown variable")
	assert.Len(t, messages(t, "Makefile", "GITLEAKS_IMAGE ?= g:1\nTRIVY_IMAGE ?= t:1@"+dg+"\n"), 1, "variable by tag")
	assert.Len(t, messages(t, "Makefile", "TRIVY_IMAGE ?= t:1@"+dg+"\n"), 1, "variable missing")
	assert.Empty(t, messages(t, "deploy/dev/s.sh", "docker run --rm --entrypoint /bin/sh \"$(docker inspect -f '{{.Config.Image}}' \"$t\")\" -c true\n"))
	assert.Len(t, messages(t, "deploy/dev/s.sh", "docker run --rm alpine:3 true\n"), 1)
}

func TestGoImages(t *testing.T) {
	root := t.TempDir()
	write(t, root, "deploy/docker-compose.yml", "services:\n  postgres:\n    image: "+pgRef+"\n")
	write(t, root, "a_test.go", "package a\nvar r = testcontainers.ContainerRequest{Image: \"nginx:1\"}\nvar q = testcontainers.ContainerRequest{Image: \"nginx:1@"+dg+"\"}\n")
	write(t, root, "b_test.go", "package a\nvar c, _ = postgres.Run(ctx, \"postgres:16-alpine@"+dg+"\")\n")
	write(t, root, "c_test.go", "package a\nvar c, _ = postgres.Run(ctx,\n\t\""+pgRef+"\")\nvar d, _ = postgres.Run(ctx, \""+pgRef+"\", opts)\n")
	got := check(root)
	require.Len(t, got, 2, strings.Join(got, "\n"))
	assert.Contains(t, got[0], "a_test.go:2")
	assert.Contains(t, got[1], "differs from deploy/docker-compose.yml")
}

func TestSkippedDirectories(t *testing.T) {
	root := t.TempDir()
	write(t, root, "node_modules/x/Dockerfile", "FROM alpine:3\n")
	write(t, root, ".claude/worktrees/w/Dockerfile", "FROM alpine:3\n")
	write(t, root, ".git/Dockerfile", "FROM alpine:3\n")
	assert.Empty(t, check(root))
}
