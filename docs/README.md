# Alice Documentation

Alice is a self-hosted manager for TLS certificates, Azure Key Vault certificates and SSH keys. These guides come
with every release package (`docs/`) and are written in English.

## Which document do I need?

| I am … | and I want to … | Read |
|---|---|---|
| IT administrator, infrastructure team | prepare a server and install Alice | [install-guide.md](install-guide.md) |
| Administrator doing the first setup | go through the setup wizard | [first-run.md](first-run.md) |
| Administrator | manage people, roles, single sign-on, directory sign-in (LDAP, Active Directory), settings, backups in the web interface, the HTTPS certificate, audit forwarding | [admin-guide.md](admin-guide.md) |
| Administrator | allow Alice to scan networks for certificates, and read what it found | [admin-guide.md](admin-guide.md#network-discovery), [operator-guide.md](operator-guide.md#network-discovery) |
| Operator or administrator | work with servers, certificates, deployments, Key Vaults and SSH key rotation | [operator-guide.md](operator-guide.md), [admin-guide.md](admin-guide.md) |
| System operator, on-call staff | run the server: `alicectl`, logs, health, disk, monitoring, moving to a new server | [operator-guide.md](operator-guide.md) |
| Operator, IT manager, auditor asking for continuity evidence | understand backups, copy them off the server, restore, run a recovery drill | [backup-restore.md](backup-restore.md) |
| Operator | update Alice to a new release, or understand a rollback | [upgrade.md](upgrade.md) |
| Linux or Nginx administrator | prepare a server so that Alice can manage it | [nginx-host-preparation.md](nginx-host-preparation.md) |
| Apache administrator | prepare an Apache server so that Alice can read its certificates (discovery only) | [apache-host-preparation.md](apache-host-preparation.md) |
| Azure administrator | give Alice access to a Key Vault | [azure-setup.md](azure-setup.md) |
| Customer administrator, purchasing | activate or renew the license, understand the evaluation and lock mode | [licensing.md](licensing.md) |
| Anyone who sees an error or a code `ALC-…` | find the cause and the fix | [troubleshooting.md](troubleshooting.md) |
| Security team, auditor, procurement review | review the architecture, encryption, risks and controls | [security-overview.md](security-overview.md), [authz-matrix.md](authz-matrix.md) |
| Integrator, automation engineer | use the API with tokens | [api.md](api.md) |

## Common tasks

| Task | Where |
|---|---|
| Check the release package before installing | [install-guide.md, section 3](install-guide.md#3-check-the-package-before-you-extract-it) |
| Lost the one-time setup code | [first-run.md](first-run.md#before-you-begin) |
| Make a backup now | [admin-guide.md](admin-guide.md#backups), or `alicectl backup` ([operator-guide.md](operator-guide.md#alicectl-reference)) |
| Restore after a mistake, or move to new hardware | [backup-restore.md](backup-restore.md#restore-on-the-same-server), [backup-restore.md](backup-restore.md#restore-on-a-new-server) |
| Replace the HTTPS certificate | [admin-guide.md](admin-guide.md#https-certificate) |
| Let Active Directory users sign in (single sign-on) | [admin-guide.md](admin-guide.md#active-directory) |
| Let LDAP or Active Directory users sign in with their directory password | [admin-guide.md](admin-guide.md#ldap-and-active-directory) |
| A directory sign-in is refused | [troubleshooting.md](troubleshooting.md#directory-sign-in-ldap-and-active-directory) |
| Forward the audit log to a SIEM | [admin-guide.md](admin-guide.md#audit-forwarding) |
| Collect information for support | [troubleshooting.md](troubleshooting.md#how-to-create-a-support-bundle) |
| An update failed | [troubleshooting.md](troubleshooting.md#update-rolled-back) |
| Which role may do what | [authz-matrix.md](authz-matrix.md) |

The release notes are in `CHANGELOG.md` of the release package. The release's security report, with the scan
results and residual risks, is `SECURITY-REPORT.md` there.
