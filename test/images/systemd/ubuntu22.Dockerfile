# Real-systemd Nginx target (spec §22.3, R38 item 16) for internal/providers/nginx/systemd_test.go
# (TestRealSystemdNginx; make test-systemd): Ubuntu 22.04 with systemd as PID 1, the distribution's
# OpenSSH, sudo and Nginx, each started by its own unit. Unlike test/images/sshd there are no test
# shims: "systemctl reload nginx" is systemd's and "nginx -t" is the distribution's binary.
# alice-helper and the setup script are installed by the test, not by the image; Nginx's default
# site has no TLS until the test gives it a test-generated pair (no private key in any layer: the
# ssl-cert snakeoil pair is not installed). Build context: test/images; built with --network host.
# Runs only privileged with the host's cgroups (the test's flags); never shipped.
FROM ubuntu:22.04@sha256:5ec03bb3441e8b0bf3b4f9cd4629a1ae763010dc3035bb8da3ae6cf026486401
ENV container=docker
RUN apt-get update \
 && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
      systemd systemd-sysv dbus openssh-server sudo nginx openssl ca-certificates procps \
 && rm -rf /var/lib/apt/lists/* \
 && rm -f /etc/ssl/private/ssl-cert-snakeoil.key /etc/ssl/certs/ssl-cert-snakeoil.pem \
 && sed -i 's/^session\s\+required\s\+pam_loginuid.so/session optional pam_loginuid.so/' /etc/pam.d/sshd \
 && rm -f /etc/ssh/ssh_host_*_key /etc/ssh/ssh_host_*_key.pub \
 && systemctl mask getty@.service console-getty.service systemd-logind.service \
      systemd-udevd.service systemd-udev-trigger.service systemd-timesyncd.service \
      systemd-resolved.service apt-daily.timer apt-daily-upgrade.timer motd-news.timer e2scrub_reap.service \
 && systemctl enable ssh.service nginx.service
# Host keys are made at the first boot of each container, never in a layer shared by every container.
RUN printf '[Unit]\nDescription=SSH host keys\nBefore=ssh.service\nConditionPathExists=!/etc/ssh/ssh_host_ed25519_key\n[Service]\nType=oneshot\nExecStart=/usr/bin/ssh-keygen -A\n[Install]\nWantedBy=multi-user.target\n' \
      > /etc/systemd/system/alice-ssh-hostkeys.service \
 && systemctl enable alice-ssh-hostkeys.service
EXPOSE 22 443
STOPSIGNAL SIGRTMIN+3
CMD ["/sbin/init"]
