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
	assert.Len(t, messages(t, "other.yml", "services:\n  a:\n    image: redis:7\n"), 1, "a Compose file by content, whatever its name")
	assert.Empty(t, messages(t, "other.yml", "services:\n  a:\n    ports: []\n"), "services without image: or build: are not a Compose file")
}

// M-1: the production compose names its two images by variable; the release scripts load them from
// the signed package and compare the image IDs with RELEASE before any start (R43 row 22). Only that
// file, only those two exact variables.
func TestProductionComposeImageVariables(t *testing.T) {
	const prod = "deploy/release/docker-compose.yml"
	assert.Empty(t, messages(t, prod, "services:\n  a:\n    image: ${ALICE_IMAGE}\n  b:\n    image: ${POSTGRES_IMAGE}\n  c:\n    image: \"${ALICE_IMAGE}\"\n"))
	for _, img := range []string{"${ALICE_IMAGE:-alice:1.0.0}", "${OTHER_IMAGE}", "redis:7", "$ALICE_IMAGE", "${ALICE_IMAGE}-x", "${POSTGRES_IMAGE}:16", "alice:1.0.0"} {
		assert.Len(t, messages(t, prod, "services:\n  a:\n    image: "+img+"\n"), 1, img)
	}
	for _, other := range []string{"deploy/docker-compose.yml", "deploy/release/compose.yml", "release/docker-compose.yml", "deploy/release/x/docker-compose.yml"} {
		assert.Len(t, messages(t, other, "services:\n  a:\n    image: ${ALICE_IMAGE}\n"), 1, other)
	}
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

// Review fold-in (1): a run split as "docker \" + "run" is still a docker run, and a digest that
// appears only in a trailing comment pins nothing.
func TestDockerRunSplitAndComments(t *testing.T) {
	vars := "GITLEAKS_IMAGE ?= g:1@" + dg + "\nTRIVY_IMAGE ?= t:1@" + dg + "\n"
	assert.Len(t, messages(t, "Makefile", vars+"a:\n\tdocker \\\n\t  run --rm alpine:3 true\n"), 1, "docker \\ + run")
	assert.Len(t, messages(t, "Makefile", vars+"a:\n\tdocker\trun   --rm alpine:3 true\n"), 1, "tabs and repeated blanks")
	assert.Len(t, messages(t, "Makefile", vars+"a:\n\tdocker run --rm alpine:3 true # alpine@"+dg+"\n"), 1, "digest only in a comment")
	assert.Len(t, messages(t, "Makefile", vars+"a:\n\tdocker run --rm \\\n\t  alpine:3 \\\n\t  true # @"+dg+"\n"), 1, "digest only in a comment of a continued line")
	assert.Len(t, messages(t, "deploy/dev/s.sh", "docker container run --rm alpine:3 true\n"), 1, "docker container run")
	assert.Len(t, messages(t, "deploy/dev/s.sh", "id=$(docker create alpine:3)\n"), 1, "docker create pulls too")
	assert.Empty(t, messages(t, "deploy/dev/s.sh", "id=$(docker create alice:ci)\necho 'x#y' && docker run --rm \"alpine@"+dg+"\" true # done\n"))
	assert.Empty(t, messages(t, "deploy/dev/s.sh", "docker run --rm alpine@"+dg+" sh -c 'echo # not a comment'\n"))
}

// Review fold-in (2): only the image operand counts, so an alice: volume, a digest in an option
// value or alice: in the command do not pin an unpinned image.
func TestDockerRunImageOperand(t *testing.T) {
	vars := "GITLEAKS_IMAGE ?= g:1@" + dg + "\nTRIVY_IMAGE ?= t:1@" + dg + "\n"
	for name, line := range map[string]string{
		"alice: volume":         "docker run -v alice:/x alpine:3 true",
		"alice: in a label":     "docker run --label=src=alice:ci alpine:3 true",
		"digest in a value":     "docker run -e PIN=x@" + dg + " alpine:3 true",
		"alice: in the command": "docker run --rm alpine:3 inspect alice:ci",
		"variable in a value":   "docker run --name $(TRIVY_IMAGE) alpine:3",
		"bare alice:":           "docker run --rm alice: true",
		"no image at all":       "docker run --rm",
	} {
		assert.Len(t, messages(t, "Makefile", vars+"a:\n\t"+line+"\n"), 1, name)
	}
	for name, line := range map[string]string{
		"options with values":  "docker run --rm -it --network none -v \"$(CURDIR):/repo\" --user \"$$(id -u):$$(id -g)\" -w /src $(TRIVY_IMAGE) fs .",
		"option=value":         "docker run --rm --network=none --entrypoint=/x alice:$(IMAGE_TAG) version",
		"quoted pinned image":  "docker run --rm \"x@" + dg + "\" y",
		"inside a subshell":    "v=$$(docker run --rm --network none alice:$(IMAGE_TAG) version); echo \"$$v\"",
		"two runs in one line": "docker run --rm $(GITLEAKS_IMAGE) a; docker run --rm alice:ci b",
	} {
		assert.Empty(t, messages(t, "Makefile", vars+"a:\n\t"+line+"\n"), name)
	}
	assert.Len(t, messages(t, "Makefile", vars+"a:\n\tdocker run --rm $(GITLEAKS_IMAGE) a; docker run --rm alpine:3 b\n"), 1, "the second of two runs")
	// The running-container form is accepted only as the operand, not anywhere on the line.
	assert.Len(t, messages(t, "deploy/dev/s.sh", "docker run --rm -l \"$(docker inspect -f '{{.Config.Image}}' x)\" alpine:3 true\n"), 1)
}

// Review fold-in (3): workflows also pull through container:, services and run: scripts.
func TestWorkflowContainersServicesAndRunSteps(t *testing.T) {
	const w = ".github/workflows/w.yml"
	pinned := "postgres:16@" + dg
	assert.Empty(t, messages(t, w, "jobs:\n  a:\n    container: "+pinned+"\n    services:\n      db:\n        image: "+pinned+"\n      c: "+pinned+"\n    steps:\n      - run: docker run --rm alice:ci version\n      - run: |\n          make lint\n          docker run --rm x@"+dg+" y\n"))
	got := messages(t, w, "jobs:\n  a:\n    container: node:24\n    steps:\n      - run: make ci\n")
	require.Len(t, got, 1)
	assert.Contains(t, got[0], "w.yml:3: job a container image node:24")
	assert.Len(t, messages(t, w, "jobs:\n  a:\n    container:\n      image: node:24\n      options: --user 1001\n"), 1, "container mapping")
	assert.Len(t, messages(t, w, "jobs:\n  a:\n    services:\n      db:\n        image: postgres:16\n"), 1, "service by tag")
	assert.Len(t, messages(t, w, "jobs:\n  a:\n    services:\n      db:\n        image: ${{ matrix.img }}\n"), 1, "service by expression")
	got = messages(t, w, "jobs:\n  a:\n    steps:\n      - run: |\n          make lint\n          docker \\\n            run --rm alpine:3 true\n")
	require.Len(t, got, 1, "docker run in a run: block")
	assert.Contains(t, got[0], "w.yml:6:")
	assert.Len(t, messages(t, w, "jobs:\n  a:\n    steps:\n      - run: skopeo inspect docker://alpine:3\n"), 1, "docker:// in a run: step")
	assert.Len(t, messages(t, w, "x: &s\n  run: docker run alpine:3\njobs:\n  a:\n    steps:\n      - *s\n"), 1, "a step that is an alias")
	assert.Len(t, messages(t, ".github/actions/x/action.yml", "runs:\n  using: composite\n  steps:\n    - run: docker run alpine:3\n      shell: bash\n"), 1, "composite action run:")
}

// Trivial gaps closed with the fold-ins: Containerfile names, Compose files with other names,
// and Go literals on the line after Image: or postgres.Run(ctx,.
func TestOtherNamesAndMultiLineGo(t *testing.T) {
	assert.Len(t, messages(t, "Containerfile", "FROM alpine:3\n"), 1)
	assert.Len(t, messages(t, "x/app.Containerfile", "FROM alpine:3\n"), 1)
	assert.Len(t, messages(t, "deploy/stack.yml", "services:\n  a:\n    image: redis:7\n"), 1, "a Compose file by content")
	assert.Empty(t, messages(t, "deploy/other.yml", "services: [a, b]\nimage: redis:7\n"), "not a Compose file")
	got := messages(t, "a_test.go", "package a\nvar r = testcontainers.ContainerRequest{\n\tImage:\n\t\t\"nginx:1\",\n}\n")
	require.Len(t, got, 1)
	assert.Contains(t, got[0], "a_test.go:4:")
	assert.Len(t, messages(t, "b_test.go", "package a\nvar c, _ = postgres.Run(ctx,\n\t\"postgres:16-alpine\")\n"), 1)
}

// Task 17 fold-in: docker pull pulls an image as surely as docker run, Dockerfile names are matched
// in any letter case, and docker compose run names a service (its image: is checked in the Compose
// file), not an image.
func TestDockerPullAndDockerfileCase(t *testing.T) {
	vars := "GITLEAKS_IMAGE ?= g:1@" + dg + "\nTRIVY_IMAGE ?= t:1@" + dg + "\n"
	for name, line := range map[string]string{
		"pull by tag":              "docker pull alpine:3",
		"image pull by tag":        "docker image pull alpine:3",
		"pull with a flag":         "docker pull --platform linux/arm64 alpine:3",
		"pull -q":                  "docker pull -q alpine:3",
		"pull, digest in comment":  "docker pull alpine:3 # alpine@" + dg,
		"pull continued":           "docker \\\n\t  pull alpine:3",
		"pull without an operand":  "docker pull",
		"pull after another stmnt": "docker run --rm alice:ci version && docker pull alpine:3",
	} {
		assert.Len(t, messages(t, "Makefile", vars+"a:\n\t"+line+"\n"), 1, name)
	}
	for name, line := range map[string]string{
		"pull by digest":        "docker pull alpine@" + dg,
		"pull a pinned var":     "docker pull --quiet $(TRIVY_IMAGE)",
		"pull --platform=x":     "docker pull --platform=linux/amd64 x@" + dg,
		"compose run a service": "docker compose -p alice-e2e run --rm alice version",
	} {
		assert.Empty(t, messages(t, "Makefile", vars+"a:\n\t"+line+"\n"), name)
	}
	assert.Len(t, messages(t, "deploy/dev/s.sh", "docker pull nginx:1\n"), 1, "shell script")
	assert.Len(t, messages(t, ".github/workflows/w.yml", "jobs:\n  a:\n    steps:\n      - run: docker pull nginx:1\n"), 1, "workflow run: step")

	for _, name := range []string{"dockerfile", "DOCKERFILE", "dockerfile.dev", "app.dockerfile", "x/app.DockerFile", "containerfile", "app.containerfile"} {
		assert.Len(t, messages(t, name, "FROM alpine:3\n"), 1, name)
	}
	for _, name := range []string{"dockerfiles.txt", "mydockerfile", "Dockerfile_notes", ".dockerfile"} {
		assert.Empty(t, messages(t, name, "FROM alpine:3\n"), name)
	}
}

func TestEveryImageVariableOfTheMakefileIsPinned(t *testing.T) {
	vars := "GITLEAKS_IMAGE ?= g:1@" + dg + "\nTRIVY_IMAGE ?= t:1@" + dg + "\n"
	assert.Empty(t, messages(t, "Makefile", vars+"SHELLCHECK_IMAGE ?= s:v0.11.0@"+dg+"\nc:\n\tdocker run --rm -v x:/s:ro $(SHELLCHECK_IMAGE) -x a.sh\n"))

	byTag := messages(t, "Makefile", vars+"SHELLCHECK_IMAGE ?= s:v0.11.0\n")
	require.Len(t, byTag, 1, "a variable by tag only")
	assert.Contains(t, byTag[0], "SHELLCHECK_IMAGE")

	noTag := messages(t, "Makefile", vars+"OTHER_IMAGE := o@"+dg+"\n")
	require.Len(t, noTag, 1, "a digest without a tag")
	assert.Contains(t, noTag[0], "OTHER_IMAGE")

	undefined := messages(t, "Makefile", vars+"c:\n\tdocker run --rm $(MISSING_IMAGE) x\n")
	require.NotEmpty(t, undefined, "a reference to a variable that is not defined")
	assert.Contains(t, strings.Join(undefined, "\n"), "MISSING_IMAGE")
}

func TestTestImageDockerfilesMustPinFromAndCopyFrom(t *testing.T) {
	assert.Empty(t, messages(t, "test/images/x/Dockerfile", "FROM alpine:3.20@"+dg+"\nCOPY --from=busybox:1@"+dg+" /bin/busybox /b\n"))
	assert.Len(t, messages(t, "test/images/x/Dockerfile", "FROM alpine:3.20\n"), 1)
	assert.Len(t, messages(t, "test/images/x/e2e.Dockerfile", "FROM alpine:3.20@"+dg+"\nCOPY --from=busybox:1 /bin/busybox /b\n"), 1)
}

// M-21: an image operand "$<NAME>_IMAGE" in a shell script passes when the same script gives the
// variable a digest-pinned default (the Makefile exports the same pinned value); $(<NAME>_IMAGE) is
// a pinned Makefile variable only in the Makefile (in a shell script it is a command substitution).
func TestShellImageVariables(t *testing.T) {
	const s = "deploy/dev/zap-stack.sh"
	pinned := "zaproxy/zap-stable:2.16.1@" + dg
	for name, script := range map[string]string{
		"default form":       "ZAP_IMAGE=\"${ZAP_IMAGE:-" + pinned + "}\"\ndocker run --rm \"$ZAP_IMAGE\" zap.sh\n",
		"braced operand":     "ZAP_IMAGE=\"${ZAP_IMAGE:-" + pinned + "}\"\ndocker run --rm -v x:/y \"${ZAP_IMAGE}\" zap.sh\n",
		"plain literal":      "readonly ZAP_IMAGE=" + pinned + "\ndocker pull $ZAP_IMAGE\n",
		"colon-equals":       ": \"${ZAP_IMAGE:=" + pinned + "}\"\ndocker run --rm \"$ZAP_IMAGE\"\n",
		"exported, quoted":   "export ZAP_IMAGE='" + pinned + "'\ndocker create \"$ZAP_IMAGE\"\n",
		"two pinned assigns": "ZAP_IMAGE=" + pinned + "\nZAP_IMAGE=\"${ZAP_IMAGE:-" + pinned + "}\"\ndocker run \"$ZAP_IMAGE\"\n",
	} {
		assert.Empty(t, messages(t, s, script), name)
	}
	for name, script := range map[string]string{
		"never assigned":         "docker run --rm \"$ZAP_IMAGE\" zap.sh\n",
		"assigned by tag":        "ZAP_IMAGE=zaproxy/zap-stable:2.16.1\ndocker run --rm \"$ZAP_IMAGE\"\n",
		"default by tag":         "ZAP_IMAGE=\"${ZAP_IMAGE:-zaproxy/zap-stable:2.16.1}\"\ndocker run --rm \"$ZAP_IMAGE\"\n",
		"digest without tag":     "ZAP_IMAGE=zaproxy/zap-stable@" + dg + "\ndocker run --rm \"$ZAP_IMAGE\"\n",
		"one unpinned assign":    "ZAP_IMAGE=" + pinned + "\nZAP_IMAGE=other:1\ndocker run \"$ZAP_IMAGE\"\n",
		"default of another var": "ZAP_IMAGE=\"${OTHER:-" + pinned + "}\"\ndocker run \"$ZAP_IMAGE\"\n",
		"command substitution":   "docker run --rm $(TRIVY_IMAGE) fs .\n",
		"other variable":         "ZAP_IMAGE=" + pinned + "\ndocker run \"$OTHER_IMAGE\"\n",
	} {
		assert.Len(t, messages(t, s, script), 1, name)
	}
	// The Makefile rule: a pinned := variable is a valid docker pull / run operand.
	vars := "GITLEAKS_IMAGE ?= g:1@" + dg + "\nTRIVY_IMAGE ?= t:1@" + dg + "\n"
	assert.Empty(t, messages(t, "Makefile", vars+"POSTGRES_RELEASE_IMAGE := "+pgRef+"\nr:\n\tdocker image inspect $(POSTGRES_RELEASE_IMAGE) >/dev/null 2>&1 || docker pull "+pgRef+"\n\tdocker run --rm $(POSTGRES_RELEASE_IMAGE) true\n"))
	assert.Len(t, messages(t, "Makefile", vars+"r:\n\tdocker run --rm \"$$ZAP_IMAGE\" true\n"), 1, "a shell variable in a recipe has no pinned default")
}
