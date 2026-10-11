# Test-only host for the release harness (test/release, make test-release): Rocky Linux 9 with the tools
# install.sh, alice-update.sh and alicectl need, and the Docker CLI with the compose plugin from the
# pinned docker CLI image. The harness runs it with --network none and the host's Docker socket
# mounted, so the scripts drive the host engine exactly as on a server, without network access.
# Never part of a release and never pushed. Build (needs the package mirrors):
#   docker build --network host -t alice-test/install-rocky9:phase8 -f test/images/install/rocky9.Dockerfile test/images/install
FROM rockylinux/rockylinux:9@sha256:8101994123cf3d0a8fee517bee7f39e555c7d92bd2d9eb3303cc988a0eeed00f
# coreutils replaces the image's coreutils-single (--allowerasing).
RUN dnf install -y --allowerasing --setopt=install_weak_deps=False openssl iproute procps-ng tar gzip coreutils findutils util-linux grep sed \
 && dnf clean all
COPY --from=docker:29.9.0-cli@sha256:1a4c7cb63513f349bdad01fcc6e0f3f2f67d37b9da86f14dc0d4a0942eecda00 /usr/local/bin/docker /usr/local/bin/docker
COPY --from=docker:29.9.0-cli@sha256:1a4c7cb63513f349bdad01fcc6e0f3f2f67d37b9da86f14dc0d4a0942eecda00 /usr/local/libexec/docker/cli-plugins/docker-compose /usr/local/libexec/docker/cli-plugins/docker-compose
