# Real OpenSSH and Nginx target (spec §22.3) for internal/providers/linuxssh/containers_integration_test.go
# (TestRealOpenSSH) and internal/providers/nginx/containers_integration_test.go (TestRealNginx).
# Build context: test/images. alice-helper and the setup script are installed by the tests, not by
# the image. Nginx is the distribution's package with its default configuration, untouched and not
# started (TestRealNginx starts it); nginx-mod-stream and nginx-mod-mail add the stream and mail
# modules. The container runs no systemd: /usr/bin/systemctl and /usr/sbin/nginx are the e2e
# target's test shims (test/images/e2e-target; the distribution's binaries move to
# /usr/lib/alice-e2e/). The nginx package pulls in the systemd package here, so its systemctl is
# moved aside, not missing.
FROM rockylinux/rockylinux:9
RUN dnf install -y openssh-server sudo shadow-utils procps-ng util-linux nginx nginx-mod-stream nginx-mod-mail openssl \
 && dnf clean all \
 && mkdir -p /run/sshd \
 && ssh-keygen -A \
 && sed -i 's/^session\s\+required\s\+pam_loginuid.so/session optional pam_loginuid.so/' /etc/pam.d/sshd
COPY sshd/fixtures.sh /usr/local/sbin/alice-fixtures.sh
RUN sh /usr/local/sbin/alice-fixtures.sh
RUN set -eu; \
    install -d -m 0755 /usr/lib/alice-e2e /etc/alice-e2e; \
    mv /usr/sbin/nginx /usr/lib/alice-e2e/nginx; \
    mv /usr/bin/systemctl /usr/lib/alice-e2e/systemctl; \
    echo ok > /etc/alice-e2e/reload-mode; \
    echo ok > /etc/alice-e2e/test-mode; \
    [ ! -e /usr/bin/systemctl ]
COPY e2e-target/nginx-wrapper /usr/sbin/nginx
COPY e2e-target/systemctl /usr/bin/systemctl
RUN chmod 0755 /usr/sbin/nginx /usr/bin/systemctl
EXPOSE 22
CMD ["/usr/sbin/sshd", "-D", "-e"]
