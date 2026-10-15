# LDAP and Active Directory sign-in: design

Status: draft for review. Date: 2026-10-15. Replaces the decision "LDAP deferred to v2" in `alice-v1/00-decisions.md` for sign-in only.

## 1. Purpose and agreed understanding

Large customers run Active Directory (AD). Some of them have no OpenID Connect (OIDC) identity provider in front of it (no Entra ID, no AD FS, no Keycloak). Alice can sign people in through OIDC today (`docs/admin-guide.md`, "Single sign-on"); it cannot talk to a directory directly.

What the owner asked for, in order:

1. A guide for the existing OIDC route with AD. **Done** (commit `5c2272e`: "Active Directory" section in `docs/admin-guide.md`, troubleshooting rows, checked against a real Keycloak with LDAP federation).
2. Direct sign-in against a directory over LDAP. **This document.**

Decisions made with the owner:

| Decision | Choice |
|---|---|
| Directories | Generic LDAP. AD is supported through settings (attribute names, filters), not through AD-only code paths. |
| Existing users | Local accounts, user creation on **People & access** and the break-glass administrator stay exactly as they are. Nothing is removed. |
| Directory users | Created automatically at their first sign-in (like SSO users). Nobody has to create them by hand. |
| Password check | A read-only service account searches for the user's DN; Alice then binds as that DN with the typed password. |
| MFA | Settable per directory, **on by default**. When on, Alice asks for its own TOTP after the directory password. |
| Groups | Group search with a configurable filter. AD gets a ready-made template that also returns nested groups. Generic LDAP: nested groups off. |
| User names | Identity is a stable unique attribute of the directory entry; the sign-in name is a configured attribute; non-ASCII letters are transliterated by an explicit table. |

Findings from the guide work that shape this design: Alice's user-name rule drops every character except `a-z 0-9 . _ - @` (so `çiğdem` became `idem`); Keycloak puts only direct group memberships in a token; an AD FS without `auth_time` can never pass "Confirm it's you".

## 2. Scope

In scope: sign-in with a directory password over `ldaps://`; group to role mapping; first-sign-in provisioning; Alice-side TOTP; administrator settings with connection and sign-in tests; audit; documents; tests.

Out of scope: Kerberos/SPNEGO (passwordless Windows sign-in), SAML, importing users in bulk, `ldap://` with STARTTLS, writing to the directory (Alice never changes a password or an entry), password change for directory users.

New dependency: `github.com/go-ldap/ldap/v3` (MIT, pure Go; the product builds with `CGO_ENABLED=0`).

## 3. Structure and data model

New package `internal/auth/ldap` next to `internal/auth/oidc`:

- `directory.go`: connections. `ldaps://` only (no plain `ldap://`, no STARTTLS), server certificate and host name verified against the system roots plus an optional PEM authority, dial and operation timeouts, response size limit, referrals not followed, address list tried in order.
- `search.go`: user lookup and group search. Filter values are escaped (RFC 4515), DNs are escaped (RFC 4514). A user lookup must return exactly one entry.
- `service.go`: the sign-in flow (section 4).

Tables (new migration):

- `ldap_directories` (at most 3): name; list of `ldaps://` addresses; user base DN; user filter (with `{login}`); sign-in name attribute; **unique id attribute** (AD `objectGUID`, OpenLDAP `entryUUID`; settable); display-name and e-mail attributes; service account DN; group base DN; group filter (default `(member={dn})`; AD template `(member:1.2.840.113556.1.4.1941:={dn})`); authority (PEM, optional); `mfa_required` (default true); `allow_sign_in` (default false).
- The service account password is a secret in `setting_secrets`, encrypted with the master key like the OIDC client secret; it is never returned by any API.
- `ldap_group_mappings`: directory, group (DN or name as the filter returns it), Alice role. The setting "SSO users may be Admin" applies to directory users in the same way (off by default).
- `users.auth_source` gains the value `ldap`; a directory user is matched by `(ldap_directory_id, ldap_unique_id)` only, never by name or e-mail, and is never joined to a local account.

Untouched: local accounts, the setup wizard administrator, OIDC, user creation by hand.

## 4. Sign-in flow

The sign-in page keeps the password form and gains **Sign in to**: *Local* (default) and each enabled directory. A local `admin` and a directory `admin` can therefore never be confused.

For a directory sign-in:

1. **Limits first**: per-address and per-(directory, login name) rate limits apply before any traffic to the directory. This also protects directory accounts from being locked through Alice; Alice's limit is below the usual AD lockout threshold.
2. An **empty password is refused** without contacting the directory (an LDAP bind with an empty password usually succeeds anonymously).
3. Bind with the service account and search the user: exactly one match, otherwise refused.
4. Bind as the found DN with the typed password. The password is never stored or logged and is cleared from memory afterwards.
5. Read the unique id, display name and e-mail; read the groups with the group search.
6. Groups to role: the highest mapped role wins. **No mapped group: refused**; nobody gets a role by default.
7. Create or update the user in one transaction (name by the transliteration table, `-2`, `-3` on a clash).
8. **MFA** when `mfa_required` is on: the existing TOTP enrolment and verification flow runs (recovery codes included). When off, the session opens at once. Session lifetimes are the SSO ones (30 minutes idle, 12 hours in all).
9. Groups are read again at every sign-in. "Confirm it's you" for a directory user asks for the directory password again and repeats the bind.

Errors: the person sees one generic message for an unknown user and a wrong password (no user enumeration; comparable timing). The audit entry carries the reason: `bad_credentials`, `no_access`, `directory_unreachable`, `ambiguous_user`, `user_disabled`, `provider_disabled`, `login_invalid`, `mfa_failed`.

A user disabled in the directory fails the bind (AD) and is refused at the next sign-in. An open session lasts as for SSO (30 minutes idle, 12 hours in all); **Disable** on People & access stops it at once.

## 5. Administrator interface and audit

**Settings, Directories**: add and edit a directory (an empty password field keeps the stored password; changing an address list or the service account needs the password again); group mappings; **Allow sign-in**.

- **Test connection**: service account bind and one search; no sign-in is opened.
- **Test sign-in**: user name and password (not stored) show the groups found and the role that would be given.

**People & access**: directory users carry the badge **Directory** and the directory's name; no **Set a new password** (the directory owns it); **Reset two-factor sign-in** exists (the TOTP is Alice's); the role comes from the groups and a change by hand is refused (as for SSO). A directory that people have signed in through cannot be deleted; switch it off.

Audit: directory added, changed, deleted; mapping added, removed; connection test and sign-in test run; `auth.ldap.denied` with the reason; user created; role updated. The service account password and any user password appear in no record.

## 6. Security notes

- The directory password passes through Alice (unlike OIDC): this is the cost of the feature. It is handled in one function, never logged, cleared after use; TLS to the directory is mandatory and verified.
- Compromise of the Alice database gives the service account password only if the master key is also lost (it is encrypted); the account is read-only by requirement, documented.
- A directory administrator can change group membership and thus roles; this is inherent and documented (as for OIDC).
- Directory availability: when the directory is down, directory users cannot sign in; the local break-glass administrator still can.
- LDAP injection: escaping of every inserted value, tests with hostile names; user filter templates may contain only `{login}`; group filters only `{dn}` and `{login}`.
- Account lockout in the directory by guessing through Alice is limited by the rate limits in section 4 step 1.

## 7. Testing

- Unit and fuzz: filter and DN escaping with injection strings; empty password; zero and several matches; TLS (wrong authority, wrong host name, `ldap://` refused); timeouts; response size limit; referrals not followed; transliteration table and name clashes.
- Integration with a real OpenLDAP (testcontainers; with the memberOf overlay and AD-style attribute names): sign-in, role mapping, nested groups through the AD template where OpenLDAP supports it (state what could not be verified), MFA on and off, rate limiting, a user removed from every mapped group, a disabled user, session lifetimes, audit content, no password in any output.
- Not tested: a real AD or Samba AD (marked "not run by the author" in the documents).
- Security review, documents: "LDAP and Active Directory" in the administrator guide, troubleshooting rows, the security overview, the threat notes of section 6.

## 8. Delivery

Five tasks, each with tests: (1) schema, settings, secrets; (2) the `ldap` package; (3) sign-in service, provisioning, MFA link; (4) API and interface; (5) tests, documents, security review.

## 9. Open items

| ID | Item |
|---|---|
| L1 | The exact AD template and attribute names are Alice's defaults from the documentation of AD and of OpenLDAP; they are not run against a real AD. A customer test (or a Samba AD test) is wanted before claiming support. |
| L2 | Whether "Confirm it's you" should accept the directory password alone (when MFA is off) or always require a fresh bind plus TOTP when MFA is on; the plan follows section 4 step 9. |
| L3 | Rate limit numbers (per address, per directory and login name) to be fixed in the plan from the existing sign-in limits. |
