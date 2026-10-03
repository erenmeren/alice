# Real OpenSSH target for internal/providers/linuxssh/containers_integration_test.go (spec §22.3).
# alice-helper and the setup script are installed by the test, not by the image.
FROM rockylinux/rockylinux:9
RUN dnf install -y openssh-server sudo shadow-utils procps-ng util-linux \
 && dnf clean all \
 && mkdir -p /run/sshd \
 && ssh-keygen -A \
 && sed -i 's/^session\s\+required\s\+pam_loginuid.so/session optional pam_loginuid.so/' /etc/pam.d/sshd
COPY fixtures.sh /usr/local/sbin/alice-fixtures.sh
RUN sh /usr/local/sbin/alice-fixtures.sh
EXPOSE 22
CMD ["/usr/sbin/sshd", "-D", "-e"]
