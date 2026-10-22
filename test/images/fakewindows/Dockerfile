# syntax=docker/dockerfile:1@sha256:4edf897a3ffa55b89f906fc8cc78afdb3f1834cc9c7083565e611a8a7d5fe99e
# Test-only emulated Windows server for the Windows journey (compose service fakewindows of
# deploy/docker-compose.e2e.yml, network "backend"; R60). Never part of a release and never pushed. It holds no key
# material: its SSH host key, its test CA and every certificate are generated when the container starts
# (cmd/alice-fakewindows serve), so no image layer has any. Both base images are the ones deploy/Dockerfile already
# pins. The packages copied below are exactly what go list -deps ./cmd/alice-fakewindows names in this module.

FROM golang:1.27.3-alpine@sha256:f2c872bcee949b7be9c490efd02b48a8a2fbf947cdf533f1c58525ec9d8170fd AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY cmd/alice-fakewindows/ cmd/alice-fakewindows/
COPY internal/providers/windows/wintest/ internal/providers/windows/wintest/
COPY internal/providers/windows/winhelper/ internal/providers/windows/winhelper/
COPY internal/providers/windows/winproto/ internal/providers/windows/winproto/
COPY internal/providers/linuxssh/linuxsshtest/ internal/providers/linuxssh/linuxsshtest/
COPY internal/providers/linuxssh/helperproto/ internal/providers/linuxssh/helperproto/
COPY internal/providers/linuxssh/sshdconf/ internal/providers/linuxssh/sshdconf/
COPY internal/providers/apacheconf/ internal/providers/apacheconf/
COPY internal/providers/haproxyconf/ internal/providers/haproxyconf/
COPY internal/providers/nginx/nginxconf/ internal/providers/nginx/nginxconf/
COPY internal/testutil/pki/ internal/testutil/pki/
COPY internal/platform/clock/ internal/platform/clock/
RUN CGO_ENABLED=0 go build -trimpath -buildvcs=false -ldflags "-s -w" -o /out/alice-fakewindows ./cmd/alice-fakewindows

FROM gcr.io/distroless/static-debian12:latest@sha256:d75cdd72874d4790092fcb1b058493ecf6bb5bf2b2b897045b00ff01d91843f2
COPY --from=build /out/alice-fakewindows /alice-fakewindows
USER 65532:65532
# Exec form: distroless has no shell. The compose service gives serve its flags.
ENTRYPOINT ["/alice-fakewindows"]
CMD ["serve"]
