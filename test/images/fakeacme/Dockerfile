# syntax=docker/dockerfile:1@sha256:4edf897a3ffa55b89f906fc8cc78afdb3f1834cc9c7083565e611a8a7d5fe99e
# Test-only fake of an ACME certificate authority (RFC 8555, with ARI and a DNS hook) for the ACME journeys
# (compose service fakeacme of deploy/docker-compose.e2e.yml). Never part of a release and never pushed. It
# holds no key material: the TLS CA and certificate, the issuing CAs, the external account binding key and
# the DNS hook secret are generated when the container starts (cmd/alice-fakeacme serve), so no image layer
# has any. Both base images are the ones deploy/Dockerfile already pins.

FROM golang:1.27.2-alpine@sha256:f92b6ef800e499660581efdabdf25d9d817a9d124eaf900924f0504e7e27e12d AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY cmd/alice-fakeacme/ cmd/alice-fakeacme/
COPY internal/platform/clock/ internal/platform/clock/
COPY internal/testutil/fakeacme/ internal/testutil/fakeacme/
RUN CGO_ENABLED=0 go build -trimpath -buildvcs=false -ldflags "-s -w" -o /out/alice-fakeacme ./cmd/alice-fakeacme \
 && mkdir -p /out/ca

FROM gcr.io/distroless/static-debian12:latest@sha256:d75cdd72874d4790092fcb1b058493ecf6bb5bf2b2b897045b00ff01d91843f2
COPY --from=build /out/alice-fakeacme /alice-fakeacme
# The directory the TLS CA is written to, owned by the non-root user: Docker copies a mount point's
# content and owner into a new named volume, so the fakeacme-ca volume is writable for it and,
# being world-readable, can be mounted read-only into alice. (compose names the path.)
COPY --from=build --chown=65532:65532 /out/ca /run/alice-e2e-acme
USER 65532:65532
# Exec form: distroless has no shell. The compose service gives serve its flags.
ENTRYPOINT ["/alice-fakeacme"]
CMD ["serve"]
