#!/usr/bin/env bash
# actionlint's shellcheck (make actionlint): the pinned image reads the run: script from standard
# input, so the workflows' scripts meet the same shellcheck as every script of the repository.
# The Makefile passes its SHELLCHECK_IMAGE; the default is the same pin (tools/pincheck, M-21).
set -euo pipefail
SHELLCHECK_IMAGE=${SHELLCHECK_IMAGE:-koalaman/shellcheck:v0.11.0@sha256:bb596a0d169b85ddd81d8b6d3a2ff6d5baf5fca10b97f575ebc647c3dff62b3d}
exec docker run --rm -i "$SHELLCHECK_IMAGE" "$@"
