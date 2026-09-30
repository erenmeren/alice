# syntax=docker/dockerfile:1

FROM node:24-alpine AS web
WORKDIR /src
COPY locales/ locales/
COPY web/package.json web/package-lock.json web/
RUN cd web && npm ci
COPY web/ web/
RUN mkdir -p internal/webui/dist && cd web && npm run build

FROM golang:1.27.1-alpine AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
COPY --from=web /src/internal/webui/dist/app internal/webui/dist/app
ARG VERSION=dev
ARG COMMIT=unknown
ARG BUILD_TIME=unknown
RUN CGO_ENABLED=0 go build -trimpath \
    -ldflags "-s -w -X alice/internal/version.Version=${VERSION} -X alice/internal/version.Commit=${COMMIT} -X alice/internal/version.BuildTime=${BUILD_TIME}" \
    -o /out/alice ./cmd/alice \
 && mkdir -p /out/keys && chmod 0700 /out/keys

FROM gcr.io/distroless/static-debian12
COPY --from=build /out/alice /usr/local/bin/alice
COPY --from=build --chown=10001:10001 /out/keys /opt/alice/keys
USER 10001:10001
EXPOSE 8443
# Exec form: distroless has no shell.
HEALTHCHECK --interval=10s --timeout=5s --start-period=20s --retries=6 \
    CMD ["/usr/local/bin/alice", "healthcheck"]
ENTRYPOINT ["/usr/local/bin/alice"]
CMD ["serve"]
