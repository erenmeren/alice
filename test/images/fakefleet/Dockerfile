# syntax=docker/dockerfile:1@sha256:4edf897a3ffa55b89f906fc8cc78afdb3f1834cc9c7083565e611a8a7d5fe99e
# Test-only fleet of hostile and ordinary TLS servers for the network discovery journeys (compose service
# fakefleet of deploy/docker-compose.e2e.yml, network "fleet"). Never part of a release and never pushed. It
# holds no key material: its CA and every certificate are generated when the container starts
# (cmd/alice-fakefleet serve), so no image layer has any. Both base images are the ones deploy/Dockerfile
# already pins.

FROM golang:1.27.3-alpine@sha256:f2c872bcee949b7be9c490efd02b48a8a2fbf947cdf533f1c58525ec9d8170fd AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY cmd/alice-fakefleet/ cmd/alice-fakefleet/
COPY internal/testutil/fakefleet/ internal/testutil/fakefleet/
COPY internal/testutil/pki/ internal/testutil/pki/
COPY internal/platform/clock/ internal/platform/clock/
RUN CGO_ENABLED=0 go build -trimpath -buildvcs=false -ldflags "-s -w" -o /out/alice-fakefleet ./cmd/alice-fakefleet

FROM gcr.io/distroless/static-debian12:latest@sha256:d75cdd72874d4790092fcb1b058493ecf6bb5bf2b2b897045b00ff01d91843f2
COPY --from=build /out/alice-fakefleet /alice-fakefleet
USER 65532:65532
# Exec form: distroless has no shell. The compose service gives serve its flags.
ENTRYPOINT ["/alice-fakefleet"]
CMD ["serve"]
