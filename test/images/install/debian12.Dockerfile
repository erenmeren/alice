# Test-only host for the release harness (test/release, make test-release): Debian 12 with the tools
# install.sh, alice-update.sh and alicectl need, and the Docker CLI with the compose plugin from the
# pinned docker CLI image. The harness runs it with --network none and the host's Docker socket
# mounted, so the scripts drive the host engine exactly as on a server, without network access.
# Never part of a release and never pushed. Build (needs the package mirrors):
#   docker build --network host -t alice-test/install-debian12:phase8 -f test/images/install/debian12.Dockerfile test/images/install
FROM debian:12@sha256:f37a335e82bca302e955fa39f9dfe28f1be618f016f8a2b56318e5a5111afc26
RUN apt-get update \
 && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends openssl iproute2 procps tar gzip coreutils findutils util-linux grep sed \
 && rm -rf /var/lib/apt/lists/*
COPY --from=docker:29.9.0-cli@sha256:1a4c7cb63513f349bdad01fcc6e0f3f2f67d37b9da86f14dc0d4a0942eecda00 /usr/local/bin/docker /usr/local/bin/docker
COPY --from=docker:29.9.0-cli@sha256:1a4c7cb63513f349bdad01fcc6e0f3f2f67d37b9da86f14dc0d4a0942eecda00 /usr/local/libexec/docker/cli-plugins/docker-compose /usr/local/libexec/docker/cli-plugins/docker-compose
