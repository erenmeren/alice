# Real OpenSSH, Nginx, Apache and HAProxy target (spec §22.3) for internal/providers/linuxssh/containers_integration_test.go
# (TestRealOpenSSH), internal/providers/nginx/containers_integration_test.go (TestRealNginx),
# internal/providers/apache/containers_integration_test.go (TestRealApache) and
# internal/providers/haproxy/containers_integration_test.go (TestRealHAProxy).
# Build context: test/images. alice-helper and the setup script are installed by the tests, not by
# the image. Nginx is the distribution's package with its default configuration, untouched and not
# started (TestRealNginx starts it); nginx-mod-stream and nginx-mod-mail add the stream and mail
# modules. The container runs no systemd: /usr/bin/systemctl and /usr/sbin/nginx are the e2e
# target's test shims (test/images/e2e-target; the distribution's binaries move to
# /usr/lib/alice-e2e/). The nginx package pulls in the systemd package here, so its systemctl is
# moved aside, not missing.
# httpd and mod_ssl are the distribution's Apache httpd with its default configuration: installed,
# never started (discovery only reads its configuration; Nginx owns ports 80 and 443). ssl.conf's
# localhost pair (which the service's first start would generate) is written by the test, never in
# a layer.
# haproxy is the distribution's package with its default configuration: installed, never started
# (discovery only; Nginx owns 80 and 443); the test writes its fixture configuration on ports
# 9443-9445 (TestRealHAProxy, internal/providers/haproxy/containers_integration_test.go).
FROM rockylinux/rockylinux:10@sha256:827d37bc128288ccf160ee318bb3cb92d591164cb217e92f8bc61e3982ae1834
RUN dnf install -y openssh-server sudo shadow-utils procps-ng util-linux nginx nginx-mod-stream nginx-mod-mail httpd mod_ssl haproxy openssl \
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
