# syntax=docker/dockerfile:1@sha256:4edf897a3ffa55b89f906fc8cc78afdb3f1834cc9c7083565e611a8a7d5fe99e

FROM node:24-alpine@sha256:ebfe2f90462722a7a4de65e91990e97fe0d401c70e0e762c5b53302f905ec1c1 AS web
WORKDIR /src
COPY locales/ locales/
COPY web/package.json web/package-lock.json web/
RUN cd web && npm ci
COPY web/ web/
RUN mkdir -p internal/webui/dist && cd web && npm run build

FROM golang:1.27.1-alpine@sha256:8a5910f31396cd4d89662f56c68b3ae31d374308270a1c3bd96672ee5ed43414 AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
COPY --from=web /src/internal/webui/dist/app internal/webui/dist/app
ARG VERSION=dev
ARG COMMIT=unknown
ARG BUILD_TIME=unknown
# GO_TAGS is empty for release images; deploy/docker-compose.e2e.yml sets "e2e testlicense".
ARG GO_TAGS=""
# alice-helper is built exactly as "make helper" builds it (reproducible), only for its checksums:
# the setup script checks the helper an administrator copies onto a server against them (R37
# item 2). The helper itself is not part of the image (Phase 8 ships it in the release bundle).
RUN for arch in amd64 arm64; do \
      CGO_ENABLED=0 GOOS=linux GOARCH=$arch GOAMD64=v1 GOARM64=v8.0 go build -trimpath -buildvcs=false -ldflags "-s -w" \
        -o /out/helper/alice-helper-linux-$arch ./cmd/alice-helper || exit 1; \
    done \
 && cd /out/helper && sha256sum alice-helper-linux-amd64 alice-helper-linux-arm64 > alice-helper.sha256
# No image is built without both checksums, each 64 lower-case hex digits as the Makefile's build
# target checks: the setup script would otherwise refuse to exist (R37 item 2).
RUN sum() { awk -v f="alice-helper-linux-$1" '$2 == f { print $1 }' /out/helper/alice-helper.sha256; } \
 && a=$(sum amd64) && b=$(sum arm64) \
 && for s in "$a" "$b"; do echo "$s" | grep -Eqx '[0-9a-f]{64}' || { echo "missing alice-helper checksums" >&2; exit 1; }; done \
 && CGO_ENABLED=0 go build -trimpath -tags "${GO_TAGS}" \
    -ldflags "-s -w -X alice/internal/version.Version=${VERSION} -X alice/internal/version.Commit=${COMMIT} -X alice/internal/version.BuildTime=${BUILD_TIME} -X alice/internal/providers/linuxssh.helperSHA256LinuxAMD64=$a -X alice/internal/providers/linuxssh.helperSHA256LinuxARM64=$b" \
    -o /out/alice ./cmd/alice \
 && mkdir -p /out/keys /out/opt-alice/state && chmod 0700 /out/keys /out/opt-alice/state

FROM gcr.io/distroless/static-debian12:latest@sha256:d75cdd72874d4790092fcb1b058493ecf6bb5bf2b2b897045b00ff01d91843f2
COPY --from=build /out/alice /usr/local/bin/alice
COPY --from=build --chown=10001:10001 /out/keys /opt/alice/keys
# The state directory is copied as a subdirectory so it keeps mode 0700 (COPY creates its
# destination directory 0755, and nothing at runtime tightens the state directory).
COPY --from=build --chown=10001:10001 /out/opt-alice/ /opt/alice/
USER 10001:10001
EXPOSE 8443
# Exec form: distroless has no shell.
HEALTHCHECK --interval=10s --timeout=5s --start-period=20s --retries=6 \
    CMD ["/usr/local/bin/alice", "healthcheck"]
ENTRYPOINT ["/usr/local/bin/alice"]
CMD ["serve"]
