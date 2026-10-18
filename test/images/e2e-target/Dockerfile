# syntax=docker/dockerfile:1@sha256:4edf897a3ffa55b89f906fc8cc78afdb3f1834cc9c7083565e611a8a7d5fe99e
# Test-only SSH target for the Playwright suite (deploy/docker-compose.e2e.yml). Never part of a
# release and never pushed. SSH fixture keys are generated at build time and their private halves
# deleted at once, so nothing secret is committed (gitleaks) and every build has fresh fixture keys.
# From Phase 4 it also runs the distribution's Nginx with two TLS websites (nginx-www.conf); their
# test CA and certificates are created when the container starts (alice-e2e-start), so no private
# key is in any image layer. The container has no systemd: /usr/bin/systemctl is a test shim and
# /usr/sbin/nginx a pass-through wrapper with fault injection for "nginx -t" (see both files).
# From Phase B it also has the distribution's Apache (mod_ssl on, the default site off) with two TLS
# websites on port 8443 (apache-sites.conf), configured and never started: Alice only discovers
# Apache servers, and Nginx owns ports 80 and 443. Their certificates are issued at container start too.
# From Phase C it also has the distribution's HAProxy with two TLS sections on ports 9443 and 9444
# (haproxy.cfg, haproxy.crtlist), configured and never started ("haproxy -c" only checks the
# configuration): Alice only discovers HAProxy servers. Their certificates are issued at container start.
# The deploy account has no password but is not locked ("*", not useradd's "!"), so the Phase 6
# journey's key login (a key Alice generated and deployed there) works with or without PAM.

FROM golang:1.27.2-alpine@sha256:f92b6ef800e499660581efdabdf25d9d817a9d124eaf900924f0504e7e27e12d AS helper
WORKDIR /src
COPY go.mod go.sum ./
COPY cmd/alice-helper/ cmd/alice-helper/
COPY internal/providers/linuxssh/helperproto/ internal/providers/linuxssh/helperproto/
COPY internal/providers/linuxssh/sshdconf/ internal/providers/linuxssh/sshdconf/
COPY internal/providers/nginx/nginxconf/ internal/providers/nginx/nginxconf/
COPY internal/providers/apacheconf/ internal/providers/apacheconf/
COPY internal/providers/haproxyconf/ internal/providers/haproxyconf/
# Built exactly as "make helper" and deploy/Dockerfile build it, so its checksum is the one the
# e2e Alice image embeds and the setup script accepts it (R37 item 2).
RUN CGO_ENABLED=0 GOOS=linux GOAMD64=v1 GOARM64=v8.0 go build -trimpath -buildvcs=false -ldflags "-s -w" -o /out/alice-helper ./cmd/alice-helper

FROM ubuntu:22.04@sha256:5ec03bb3441e8b0bf3b4f9cd4629a1ae763010dc3035bb8da3ae6cf026486401
RUN apt-get update \
 && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends openssh-server sudo procps nginx apache2 haproxy openssl \
 && rm -rf /var/lib/apt/lists/* \
 && mkdir -p /run/sshd /opt/alice-bundle \
 && ssh-keygen -A \
 && sed -i 's/^session\s\+required\s\+pam_loginuid.so/session optional pam_loginuid.so/' /etc/pam.d/sshd
RUN set -eu; \
    useradd --uid 1001 --create-home --shell /bin/bash deploy; \
    usermod -p '*' deploy; \
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
# Nginx as on a real Ubuntu server, with the test websites only. The distribution's binary moves
# aside (dpkg-divert, so the process is still named nginx) behind the test wrapper.
RUN set -eu; \
    rm -f /etc/nginx/sites-enabled/default; \
    install -d -m 0755 /usr/lib/alice-e2e /etc/alice-e2e; \
    dpkg-divert --quiet --local --rename --divert /usr/lib/alice-e2e/nginx --add /usr/sbin/nginx; \
    echo ok > /etc/alice-e2e/reload-mode; \
    echo ok > /etc/alice-e2e/test-mode; \
    install -d -m 0755 -o root -g root /var/www/alice-acme /var/www/alice-acme/.well-known /var/www/alice-acme/.well-known/acme-challenge; \
    [ ! -e /usr/bin/systemctl ]
# Apache as on a real Ubuntu server, with the test websites only. It is never started.
RUN set -eu; \
    a2enmod -q ssl; \
    a2dissite -q 000-default
COPY test/images/e2e-target/nginx-www.conf /etc/nginx/conf.d/www.conf
COPY test/images/e2e-target/apache-sites.conf /etc/apache2/sites-enabled/alice-e2e.conf
# HAProxy as on a real Ubuntu server, with the test sections only. It is never started.
COPY test/images/e2e-target/haproxy.cfg /etc/haproxy/haproxy.cfg
COPY test/images/e2e-target/haproxy.crtlist /etc/haproxy/alice-e2e.crtlist
COPY test/images/e2e-target/nginx-wrapper /usr/sbin/nginx
COPY test/images/e2e-target/systemctl /usr/bin/systemctl
COPY --from=helper /out/alice-helper /opt/alice-bundle/alice-helper
COPY test/images/e2e-target/alice-e2e-prepare test/images/e2e-target/alice-e2e-rotate-hostkey \
     test/images/e2e-target/alice-e2e-start test/images/e2e-target/alice-e2e-pki \
     test/images/e2e-target/alice-e2e-newcert test/images/e2e-target/alice-e2e-served \
     test/images/e2e-target/alice-e2e-reload-mode test/images/e2e-target/alice-e2e-test-mode \
     test/images/e2e-target/alice-e2e-nginx-reset test/images/e2e-target/alice-e2e-restore-hostkey \
     test/images/e2e-target/alice-e2e-config-mode /usr/local/sbin/
RUN chmod 0644 /etc/nginx/conf.d/www.conf /etc/apache2/sites-enabled/alice-e2e.conf /etc/haproxy/haproxy.cfg /etc/haproxy/alice-e2e.crtlist \
 && chmod 0755 /usr/sbin/nginx /usr/bin/systemctl /opt/alice-bundle/alice-helper /usr/local/sbin/alice-e2e-*
CMD ["/usr/local/sbin/alice-e2e-start"]
