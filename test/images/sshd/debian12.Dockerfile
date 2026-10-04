# Real OpenSSH and Nginx target (spec §22.3) for internal/providers/linuxssh/containers_integration_test.go
# (TestRealOpenSSH) and internal/providers/nginx/containers_integration_test.go (TestRealNginx).
# Build context: test/images. alice-helper and the setup script are installed by the tests, not by
# the image. Nginx is the distribution's package with its default configuration, untouched and not
# started (TestRealNginx starts it); libnginx-mod-stream and libnginx-mod-mail add the stream and mail
# modules (Ubuntu's nginx brings them, Debian's does not). ssl-cert brings Debian's ssl-cert group
# and /etc/ssl/private; its snakeoil pair is deleted in the same layer, so no private key is in any
# image layer. The container has no systemd: /usr/bin/systemctl and /usr/sbin/nginx are the e2e
# target's test shims (test/images/e2e-target; the distribution's binary moves to
# /usr/lib/alice-e2e/nginx).
FROM debian:12@sha256:f37a335e82bca302e955fa39f9dfe28f1be618f016f8a2b56318e5a5111afc26
RUN apt-get update \
 && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends openssh-server sudo procps nginx libnginx-mod-stream libnginx-mod-mail openssl ssl-cert \
 && rm -rf /var/lib/apt/lists/* \
 && rm -f /etc/ssl/private/ssl-cert-snakeoil.key /etc/ssl/certs/ssl-cert-snakeoil.pem \
 && mkdir -p /run/sshd \
 && ssh-keygen -A \
 && sed -i 's/^session\s\+required\s\+pam_loginuid.so/session optional pam_loginuid.so/' /etc/pam.d/sshd
COPY sshd/fixtures.sh /usr/local/sbin/alice-fixtures.sh
RUN sh /usr/local/sbin/alice-fixtures.sh
RUN set -eu; \
    install -d -m 0755 /usr/lib/alice-e2e /etc/alice-e2e; \
    dpkg-divert --quiet --local --rename --divert /usr/lib/alice-e2e/nginx --add /usr/sbin/nginx; \
    echo ok > /etc/alice-e2e/reload-mode; \
    echo ok > /etc/alice-e2e/test-mode; \
    [ ! -e /usr/bin/systemctl ]
COPY e2e-target/nginx-wrapper /usr/sbin/nginx
COPY e2e-target/systemctl /usr/bin/systemctl
RUN chmod 0755 /usr/sbin/nginx /usr/bin/systemctl
EXPOSE 22
CMD ["/usr/sbin/sshd", "-D", "-e"]
