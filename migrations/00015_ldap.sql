-- +goose Up
-- LDAP and Active Directory sign-in: the directories an Administrator configures, their group-to-role mappings and the
-- users a directory sign-in creates. Spec: docs/superpowers/specs/2026-10-15-ldap-directory-signin-design.md; plan:
-- docs/superpowers/plans/2026-10-15-ldap-directory-signin.md (Task 1, rulings 3, 9, 11). Same conventions as 00011:
-- closed lists for values Alice owns, format checks for names, no clock defaults. At most 3 directories is the
-- service's rule (a count inside a lock), not a CHECK.

-- ldap_addresses_ok: a one-dimensional list of 1 to 3 addresses, each ldaps://host[:port] (no plain ldap://, no
-- STARTTLS, no path, query, fragment or user part, no space or control character), at most 255 characters each.
-- Whether the host is allowed to be dialled is the service's check (netaddr), at sign-in time.
-- +goose StatementBegin
CREATE FUNCTION ldap_addresses_ok(a text[]) RETURNS boolean LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
SET search_path = pg_catalog, pg_temp AS $$
    SELECT coalesce(array_ndims(a) = 1, false) AND cardinality(a) BETWEEN 1 AND 3
       AND coalesce(bool_and(x IS NOT NULL AND char_length(x) <= 255 AND x ~ '^ldaps://[^/[:space:][:cntrl:]?#@]+$'), false)
    FROM unnest(a) AS u(x)
$$;
-- +goose StatementEnd

-- Directories (spec "Data"; ruling 11). The service account password lives in setting_secrets under
-- ldap.directory.<id>.bind_password, never here. Attribute names are LDAP attribute descriptors (a name or an OID, no
-- options); the display-name, e-mail and group-name attributes may be empty (no display name or e-mail from the
-- directory; the group's DN is its value). The user filter holds {login} exactly once and no other placeholder; the
-- group filter holds {dn} or {login} (at least one, so a group search never returns every group for every user) and
-- nothing else. The service escapes every value it puts in.
CREATE TABLE ldap_directories (
    id                     uuid PRIMARY KEY,
    name                   text NOT NULL CHECK (char_length(name) BETWEEN 1 AND 60),
    addresses              text[] NOT NULL CHECK (ldap_addresses_ok(addresses)),
    user_base_dn           text NOT NULL CHECK (char_length(user_base_dn) BETWEEN 1 AND 1024 AND user_base_dn !~ '[[:cntrl:]]'),
    user_filter            text NOT NULL CHECK (char_length(user_filter) <= 1024 AND user_filter ~ '^\(.*\)$'
                                                AND user_filter !~ '[[:cntrl:]]'
                                                AND user_filter LIKE '%{login}%' AND user_filter NOT LIKE '%{login}%{login}%'
                                                AND replace(user_filter, '{login}', '') !~ '[{}]'),
    login_attribute        text NOT NULL CHECK (login_attribute ~ '^([A-Za-z][A-Za-z0-9-]{0,99}|[0-9]{1,10}(\.[0-9]{1,10}){1,30})$'),
    unique_id_attribute    text NOT NULL CHECK (unique_id_attribute ~ '^([A-Za-z][A-Za-z0-9-]{0,99}|[0-9]{1,10}(\.[0-9]{1,10}){1,30})$'),
    display_name_attribute text NOT NULL CHECK (display_name_attribute ~ '^([A-Za-z][A-Za-z0-9-]{0,99}|[0-9]{1,10}(\.[0-9]{1,10}){1,30})?$'),
    email_attribute        text NOT NULL CHECK (email_attribute ~ '^([A-Za-z][A-Za-z0-9-]{0,99}|[0-9]{1,10}(\.[0-9]{1,10}){1,30})?$'),
    bind_dn                text NOT NULL CHECK (char_length(bind_dn) BETWEEN 1 AND 1024 AND bind_dn !~ '[[:cntrl:]]'),
    group_base_dn          text NOT NULL CHECK (char_length(group_base_dn) BETWEEN 1 AND 1024 AND group_base_dn !~ '[[:cntrl:]]'),
    group_filter           text NOT NULL CHECK (char_length(group_filter) <= 1024 AND group_filter ~ '^\(.*\)$'
                                                AND group_filter !~ '[[:cntrl:]]' AND group_filter ~ '\{(dn|login)\}'
                                                AND replace(replace(group_filter, '{dn}', ''), '{login}', '') !~ '[{}]'),
    group_name_attribute   text NOT NULL CHECK (group_name_attribute ~ '^([A-Za-z][A-Za-z0-9-]{0,99}|[0-9]{1,10}(\.[0-9]{1,10}){1,30})?$'),
    ca_pem                 text NOT NULL DEFAULT '' CHECK (char_length(ca_pem) <= 65536),
    mfa_required           boolean NOT NULL DEFAULT true,
    enabled                boolean NOT NULL DEFAULT false,
    version                integer NOT NULL DEFAULT 1 CHECK (version >= 1),
    created_by             uuid REFERENCES users (id),
    created_at             timestamptz NOT NULL,
    updated_at             timestamptz NOT NULL
);
CREATE UNIQUE INDEX ldap_directories_name ON ldap_directories (lower(name));

-- Group-to-role mappings (ruling 8): the group exactly as the group search returns it (its DN or the configured name
-- attribute; case-sensitive), a non-empty value, no "all users" mapping.
CREATE TABLE ldap_group_mappings (
    id           uuid PRIMARY KEY,
    directory_id uuid NOT NULL REFERENCES ldap_directories (id) ON DELETE CASCADE,
    group_value  text NOT NULL CHECK (char_length(group_value) BETWEEN 1 AND 256
                                      AND group_value = btrim(group_value)
                                      AND group_value !~ '[[:cntrl:]]'),
    role         text NOT NULL CHECK (role IN ('admin', 'operator', 'auditor')),
    created_by   uuid REFERENCES users (id),
    created_at   timestamptz NOT NULL,
    UNIQUE (directory_id, group_value)
);

-- Directory users (rulings 3 and 9): matched by (ldap_directory_id, ldap_unique_id) only; the unique id is the
-- lower-case hex of the unique id attribute's bytes. No password, never the break-glass account, role always from the
-- mapping. A local or SSO user has neither column; a directory with users cannot be deleted (no cascade).
ALTER TABLE users DROP CONSTRAINT users_auth_source_check;
ALTER TABLE users ADD CONSTRAINT users_auth_source_check CHECK (auth_source IN ('local', 'oidc', 'ldap'));
ALTER TABLE users DROP CONSTRAINT users_role_source_check;
ALTER TABLE users ADD CONSTRAINT users_role_source_check CHECK (role_source IN ('manual', 'oidc_mapping', 'ldap_mapping'));
ALTER TABLE users ADD COLUMN ldap_directory_id uuid REFERENCES ldap_directories (id);
ALTER TABLE users ADD COLUMN ldap_unique_id text CHECK (char_length(ldap_unique_id) BETWEEN 2 AND 254
                                                        AND char_length(ldap_unique_id) % 2 = 0
                                                        AND ldap_unique_id ~ '^[0-9a-f]+$');
ALTER TABLE users ADD CONSTRAINT users_ldap_identity CHECK (
    (auth_source = 'ldap') = (ldap_directory_id IS NOT NULL)
    AND (auth_source = 'ldap') = (ldap_unique_id IS NOT NULL));
ALTER TABLE users ADD CONSTRAINT users_ldap_not_local CHECK (auth_source <> 'ldap'
    OR (password_hash IS NULL AND NOT is_break_glass AND role_source = 'ldap_mapping'));
CREATE UNIQUE INDEX users_ldap_identity_unique ON users (ldap_directory_id, ldap_unique_id) WHERE ldap_directory_id IS NOT NULL;

-- The service account password of each directory is a settings secret (AAD setting_secrets/<key>/ciphertext). The
-- list of keys stays closed.
ALTER TABLE setting_secrets DROP CONSTRAINT setting_secrets_key_check;
ALTER TABLE setting_secrets ADD CONSTRAINT setting_secrets_key_check CHECK (key ~ '^(notify\.smtp\.password|backup\.sender|sso\.provider\.[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\.client_secret|ldap\.directory\.[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\.bind_password)$');

GRANT SELECT, INSERT, UPDATE, DELETE ON ldap_directories, ldap_group_mappings TO alice_app;

-- +goose Down
-- Correct only on a database without directory data. The Down refuses, with a clear message and SQLSTATE Z1021, when a
-- directory, a directory user or a directory bind password exists; nothing is changed then.
-- +goose StatementBegin
DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM ldap_directories) OR EXISTS (SELECT 1 FROM users WHERE auth_source = 'ldap')
            OR EXISTS (SELECT 1 FROM setting_secrets WHERE key LIKE 'ldap.directory.%') THEN
        RAISE EXCEPTION 'cannot migrate down: directory data exists (LDAP directories, directory users or directory bind passwords); remove it first or restore a backup taken before 00015' USING ERRCODE = 'Z1021';
    END IF;
END $$;
-- +goose StatementEnd
ALTER TABLE setting_secrets DROP CONSTRAINT setting_secrets_key_check;
ALTER TABLE setting_secrets ADD CONSTRAINT setting_secrets_key_check CHECK (key ~ '^(notify\.smtp\.password|backup\.sender|sso\.provider\.[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\.client_secret)$');
DROP INDEX users_ldap_identity_unique;
ALTER TABLE users DROP CONSTRAINT users_ldap_not_local;
ALTER TABLE users DROP CONSTRAINT users_ldap_identity;
ALTER TABLE users DROP COLUMN ldap_unique_id;
ALTER TABLE users DROP COLUMN ldap_directory_id;
ALTER TABLE users DROP CONSTRAINT users_role_source_check;
ALTER TABLE users ADD CONSTRAINT users_role_source_check CHECK (role_source IN ('manual', 'oidc_mapping'));
ALTER TABLE users DROP CONSTRAINT users_auth_source_check;
ALTER TABLE users ADD CONSTRAINT users_auth_source_check CHECK (auth_source IN ('local', 'oidc'));
DROP TABLE ldap_group_mappings;
DROP TABLE ldap_directories;
DROP FUNCTION ldap_addresses_ok(text[]);
