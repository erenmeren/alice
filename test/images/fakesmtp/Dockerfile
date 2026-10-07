# syntax=docker/dockerfile:1@sha256:4edf897a3ffa55b89f906fc8cc78afdb3f1834cc9c7083565e611a8a7d5fe99e
# Test-only fake SMTP server for the Phase 7 journeys (compose service fakesmtp of deploy/docker-compose.e2e.yml).
# Never part of a release and never pushed. It holds no key material: its certificate and its SMTP password are
# generated when the container starts (cmd/alice-fakesmtp serve). Both base images are the ones deploy/Dockerfile pins.

FROM golang:1.27.1-alpine@sha256:8a5910f31396cd4d89662f56c68b3ae31d374308270a1c3bd96672ee5ed43414 AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY cmd/alice-fakesmtp/ cmd/alice-fakesmtp/
COPY internal/platform/ internal/platform/
COPY internal/testutil/ internal/testutil/
RUN CGO_ENABLED=0 go build -trimpath -buildvcs=false -ldflags "-s -w" -o /out/alice-fakesmtp ./cmd/alice-fakesmtp

FROM gcr.io/distroless/static-debian12:latest@sha256:d75cdd72874d4790092fcb1b058493ecf6bb5bf2b2b897045b00ff01d91843f2
COPY --from=build /out/alice-fakesmtp /alice-fakesmtp
USER 65532:65532
# Exec form: distroless has no shell. The compose service gives serve its flags.
ENTRYPOINT ["/alice-fakesmtp"]
CMD ["serve"]
