# syntax=docker/dockerfile:1
# Test-only SSH target for the Playwright suite (deploy/docker-compose.e2e.yml). Never part of a
# release. Keys are generated at build time and their private halves deleted at once, so nothing
# secret is committed (gitleaks) and every build has fresh fixture keys.

FROM golang:1.27.1-alpine AS helper
WORKDIR /src
COPY go.mod go.sum ./
COPY cmd/alice-helper/ cmd/alice-helper/
COPY internal/providers/linuxssh/helperproto/ internal/providers/linuxssh/helperproto/
COPY internal/providers/linuxssh/sshdconf/ internal/providers/linuxssh/sshdconf/
COPY internal/providers/nginx/nginxconf/ internal/providers/nginx/nginxconf/
# Built exactly as "make helper" and deploy/Dockerfile build it, so its checksum is the one the
# e2e Alice image embeds and the setup script accepts it (R37 item 2).
RUN CGO_ENABLED=0 GOOS=linux GOAMD64=v1 GOARM64=v8.0 go build -trimpath -buildvcs=false -ldflags "-s -w" -o /out/alice-helper ./cmd/alice-helper

FROM ubuntu:22.04
RUN apt-get update \
 && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends openssh-server sudo procps \
 && rm -rf /var/lib/apt/lists/* \
 && mkdir -p /run/sshd /opt/alice-bundle \
 && ssh-keygen -A \
 && sed -i 's/^session\s\+required\s\+pam_loginuid.so/session optional pam_loginuid.so/' /etc/pam.d/sshd
RUN set -eu; \
    useradd --uid 1001 --create-home --shell /bin/bash deploy; \
    install -d -m 0700 -o deploy -g deploy /home/deploy/.ssh; \
    install -d -m 0700 /root/.ssh; \
    tmp="$(mktemp -d)"; \
    ssh-keygen -q -t ed25519 -N '' -C deploy@laptop -f "$tmp/k1"; \
    ssh-keygen -q -t rsa -b 3072 -N '' -C ci@build -f "$tmp/k2"; \
    ssh-keygen -q -t ed25519 -N '' -C root@bastion -f "$tmp/k3"; \
    cat "$tmp/k1.pub" "$tmp/k2.pub" > /home/deploy/.ssh/authorized_keys; \
    printf 'from="10.0.0.0/8" %s\n' "$(cat "$tmp/k3.pub")" > /root/.ssh/authorized_keys; \
    chown deploy:deploy /home/deploy/.ssh/authorized_keys; \
    chmod 0600 /home/deploy/.ssh/authorized_keys /root/.ssh/authorized_keys; \
    rm -rf "$tmp"
COPY --from=helper /out/alice-helper /opt/alice-bundle/alice-helper
COPY test/images/e2e-target/alice-e2e-prepare test/images/e2e-target/alice-e2e-rotate-hostkey /usr/local/sbin/
RUN chmod 0755 /opt/alice-bundle/alice-helper /usr/local/sbin/alice-e2e-prepare /usr/local/sbin/alice-e2e-rotate-hostkey
CMD ["/usr/sbin/sshd", "-D", "-e"]
