# syntax=docker/dockerfile:1@sha256:4edf897a3ffa55b89f906fc8cc78afdb3f1834cc9c7083565e611a8a7d5fe99e
# Test-only fake directory for the directory sign-in journey (compose service fakeldap of deploy/docker-compose.e2e.yml,
# web/e2e/ldap.spec.ts). Never part of a release and never pushed. It is the OpenLDAP image the integration tests use
# (internal/testutil/fakeldap), pinned by the same tag and index digest, with the same tree and throw-away passwords
# (bootstrap.ldif). It holds no key material: the CA and the server certificate for ldap.alice-e2e.test are generated
# when the container starts (alice-fakeldap-start), in a tmpfs. The image's own start-up tooling (/container/tool/run,
# which needs root) is not used: slapd runs directly as the image's openldap user (911) from a static slapd.conf.
FROM osixia/openldap:1.5.0@sha256:18742e9c449c9c1afe129d3f2f3ee15fb34cc43e5f940a20f3399728f41d7c28
COPY test/images/openldap/slapd.conf test/images/openldap/bootstrap.ldif /etc/alice-fakeldap/
COPY test/images/openldap/alice-fakeldap-start test/images/openldap/alice-fakeldap-ctl /usr/local/bin/
# The scripts keep their mode from the repository (0755; COPY --chmod needs BuildKit, which is not always there).
USER 911:911
EXPOSE 636
ENTRYPOINT ["/usr/local/bin/alice-fakeldap-start"]
