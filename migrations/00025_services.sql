-- +goose Up
-- Scoped access and service ownership (R49, docs/superpowers/specs/2026-10-21-scoped-rbac-and-service-ownership-design.md
-- §4). This migration creates the whole schema of the design, so the later phases need none: Phase 1 uses services,
-- environments, policies (version 1 only), trusts and the service columns; role bindings, directory groups, owners,
-- automation accounts and token limits stay empty and unused until their phase.
--
-- Every existing resource moves to the protected Default service and every user keeps its global role: nothing changes
-- until an Administrator creates a second service (and, from Phase 2, a binding). The owning-service columns take the
-- Default service as their default (default_service_id()): the application names the service of every row it creates,
-- the default only keeps rows written by other means (tests, a restore of an older dump) in Default, as the backfill
-- does. Adding the columns with that default fills them without an UPDATE, so no history trigger (a finished incident,
-- a revoked certificate) fires.

-- An Administrator-managed label of services. Seeded: production, staging, test, development; the UI shows a seeded
-- key's name in the reader's language until an Administrator renames it.
CREATE TABLE environments (
    id         uuid PRIMARY KEY,
    key        text NOT NULL UNIQUE CHECK (key ~ '^[a-z][a-z0-9-]{0,31}$'),
    name       text NOT NULL CHECK (char_length(name) BETWEEN 1 AND 60 AND name = btrim(name) AND name !~ '[[:cntrl:]]'),
    sort       smallint NOT NULL DEFAULT 0,
    version    integer NOT NULL DEFAULT 1 CHECK (version >= 1),
    created_at timestamptz NOT NULL,
    updated_at timestamptz NOT NULL
);
INSERT INTO environments (id, key, name, sort, created_at, updated_at) VALUES
    (gen_random_uuid(), 'production', 'Production', 10, now(), now()),
    (gen_random_uuid(), 'staging', 'Staging', 20, now(), now()),
    (gen_random_uuid(), 'test', 'Test', 30, now(), now()),
    (gen_random_uuid(), 'development', 'Development', 40, now(), now());

-- A named group of resources with an optional environment, an owner team and a policy. Exactly one service is the
-- Default service; it cannot be deleted (the application refuses, ALC-SVC-0004).
CREATE TABLE services (
    id             uuid PRIMARY KEY,
    name           citext NOT NULL CHECK (char_length(name::text) BETWEEN 1 AND 100 AND name::text = btrim(name::text)
                                          AND name::text !~ '[[:cntrl:]]'),
    description    text NOT NULL DEFAULT '' CHECK (char_length(description) <= 500),
    environment_id uuid REFERENCES environments (id),
    is_default     boolean NOT NULL DEFAULT false,
    policy_version integer NOT NULL DEFAULT 1 CHECK (policy_version >= 1),
    version        integer NOT NULL DEFAULT 1 CHECK (version >= 1),
    created_by     uuid REFERENCES users (id),
    created_at     timestamptz NOT NULL,
    updated_at     timestamptz NOT NULL
);
CREATE UNIQUE INDEX services_name ON services (name);
CREATE UNIQUE INDEX services_one_default ON services (is_default) WHERE is_default;
CREATE INDEX services_environment ON services (environment_id);

-- Append-only policy history (design §7.3). Version 1 of every service is the empty policy {"schema":1}.
CREATE TABLE service_policies (
    service_id uuid NOT NULL REFERENCES services (id) ON DELETE CASCADE,
    version    integer NOT NULL CHECK (version >= 1),
    body       jsonb NOT NULL CHECK (jsonb_typeof(body) = 'object' AND octet_length(body::text) <= 65536),
    created_by uuid REFERENCES users (id),
    created_at timestamptz NOT NULL,
    PRIMARY KEY (service_id, version)
);

INSERT INTO services (id, name, is_default, created_at, updated_at) VALUES (gen_random_uuid(), 'Default', true, now(), now());
INSERT INTO service_policies (service_id, version, body, created_at) SELECT id, 1, '{"schema":1}', now() FROM services;

-- The Default service: the owning service of every row written without one.
-- +goose StatementBegin
CREATE FUNCTION default_service_id() RETURNS uuid LANGUAGE sql STABLE
SET search_path = pg_catalog, pg_temp AS $$
    SELECT id FROM public.services WHERE is_default
$$;
-- +goose StatementEnd

-- A directory group Alice refers to (bindings, owner teams). value is exactly what the group claim (OIDC) or the group
-- search (LDAP) returns, with the rules of oidc_group_mappings / ldap_group_mappings (case-sensitive for LDAP).
CREATE TABLE directory_groups (
    id                uuid PRIMARY KEY,
    source            text NOT NULL CHECK (source IN ('oidc', 'ldap')),
    oidc_provider_id  uuid REFERENCES oidc_providers (id) ON DELETE CASCADE,
    ldap_directory_id uuid REFERENCES ldap_directories (id) ON DELETE CASCADE,
    value             text NOT NULL CHECK (char_length(value) BETWEEN 1 AND 1024 AND value = btrim(value) AND value !~ '[[:cntrl:]]'),
    label             text NOT NULL DEFAULT '' CHECK (char_length(label) <= 100),
    created_by        uuid REFERENCES users (id),
    created_at        timestamptz NOT NULL,
    CHECK ((source = 'oidc') = (oidc_provider_id IS NOT NULL) AND (source = 'ldap') = (ldap_directory_id IS NOT NULL)),
    UNIQUE NULLS NOT DISTINCT (source, oidc_provider_id, ldap_directory_id, value)
);

-- The groups a directory or SSO user had at the last sign-in or step-up (rewritten there in the same transaction as
-- the role; at most 1000 per user). The provider or directory is the user's own.
CREATE TABLE user_directory_groups (
    user_id uuid NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    value   text NOT NULL CHECK (char_length(value) BETWEEN 1 AND 1024),
    seen_at timestamptz NOT NULL,
    PRIMARY KEY (user_id, value)
);

-- A role held on one service or on every service of an environment, by a person, an automation account or a directory
-- group. Global roles stay users.role (and the group mappings), as before.
CREATE TABLE role_bindings (
    id                 uuid PRIMARY KEY,
    user_id            uuid REFERENCES users (id) ON DELETE CASCADE,
    directory_group_id uuid REFERENCES directory_groups (id) ON DELETE CASCADE,
    role               text NOT NULL CHECK (role IN ('admin', 'operator', 'auditor')),
    service_id         uuid REFERENCES services (id) ON DELETE CASCADE,
    environment_id     uuid REFERENCES environments (id) ON DELETE RESTRICT,
    created_by         uuid REFERENCES users (id),
    created_at         timestamptz NOT NULL,
    CHECK (num_nonnulls(user_id, directory_group_id) = 1),
    CHECK (num_nonnulls(service_id, environment_id) = 1),
    UNIQUE NULLS NOT DISTINCT (user_id, directory_group_id, role, service_id, environment_id)
);
CREATE INDEX role_bindings_user ON role_bindings (user_id) WHERE user_id IS NOT NULL;
CREATE INDEX role_bindings_group ON role_bindings (directory_group_id) WHERE directory_group_id IS NOT NULL;

-- target_service accepts certificates and SSH keys owned by source_service (design §5.6): checked by every deployment
-- that places a key of one service on a server or into a Key Vault of another.
CREATE TABLE service_trusts (
    id                uuid PRIMARY KEY,
    source_service_id uuid NOT NULL REFERENCES services (id) ON DELETE CASCADE,
    target_service_id uuid NOT NULL REFERENCES services (id) ON DELETE CASCADE,
    created_by        uuid REFERENCES users (id),
    created_at        timestamptz NOT NULL,
    CHECK (source_service_id <> target_service_id),
    UNIQUE (source_service_id, target_service_id)
);
CREATE INDEX service_trusts_target ON service_trusts (target_service_id);

CREATE TABLE service_owners (
    id                 uuid PRIMARY KEY,
    service_id         uuid NOT NULL REFERENCES services (id) ON DELETE CASCADE,
    user_id            uuid REFERENCES users (id) ON DELETE CASCADE,
    directory_group_id uuid REFERENCES directory_groups (id) ON DELETE CASCADE,
    created_by         uuid REFERENCES users (id),
    created_at         timestamptz NOT NULL,
    CHECK (num_nonnulls(user_id, directory_group_id) = 1),
    UNIQUE NULLS NOT DISTINCT (service_id, user_id, directory_group_id)
);

-- The owning service of every resource that has one (design §4.2, §4.5); derived resources (locations, deployments,
-- bindings, Key Vault objects, orders, scans, ...) take their parent's.
ALTER TABLE targets ADD COLUMN service_id uuid NOT NULL DEFAULT default_service_id() REFERENCES services (id);
ALTER TABLE certificates ADD COLUMN service_id uuid NOT NULL DEFAULT default_service_id() REFERENCES services (id);
ALTER TABLE csr_requests ADD COLUMN service_id uuid NOT NULL DEFAULT default_service_id() REFERENCES services (id);
ALTER TABLE ssh_keys ADD COLUMN service_id uuid NOT NULL DEFAULT default_service_id() REFERENCES services (id);
ALTER TABLE acme_certificates ADD COLUMN service_id uuid NOT NULL DEFAULT default_service_id() REFERENCES services (id);
ALTER TABLE discovery_scopes ADD COLUMN service_id uuid NOT NULL DEFAULT default_service_id() REFERENCES services (id);
CREATE INDEX targets_service ON targets (service_id);
CREATE INDEX certificates_service ON certificates (service_id);
CREATE INDEX certificates_service_expiry ON certificates (service_id, not_after, id);
CREATE INDEX csr_requests_service ON csr_requests (service_id);
CREATE INDEX ssh_keys_service ON ssh_keys (service_id);
CREATE INDEX acme_certificates_service ON acme_certificates (service_id);
CREATE INDEX discovery_scopes_service ON discovery_scopes (service_id);
-- Moving a resource to another service (POST /services/{id}/actions/assign) is the one change of the column.
GRANT UPDATE (service_id) ON targets, certificates, csr_requests, ssh_keys, acme_certificates, discovery_scopes TO alice_app;

-- A job's service is set when it is queued (the target's, the ACME certificate's, the key's, the scope's); NULL for
-- platform work (backup, license, audit, ...). An alert row records the service of its object when it was written.
-- Both are history of a service, not its content: deleting an (empty) service leaves them without one.
ALTER TABLE jobs ADD COLUMN service_id uuid REFERENCES services (id) ON DELETE SET NULL;
UPDATE jobs SET service_id = default_service_id() WHERE target_id IS NOT NULL;
CREATE INDEX jobs_service ON jobs (service_id);
ALTER TABLE alerts ADD COLUMN service_id uuid REFERENCES services (id) ON DELETE SET NULL DEFAULT default_service_id();
ALTER TABLE alerts ALTER COLUMN service_id DROP DEFAULT;
CREATE INDEX alerts_service ON alerts (service_id);

-- Every service that held an affected location when the incident started (a finished incident is history: the column is
-- filled by its default, the Default service, without an UPDATE); then the empty list for new rows, which the
-- application fills.
ALTER TABLE certificate_incidents ADD COLUMN service_ids uuid[] NOT NULL DEFAULT ARRAY[default_service_id()];
ALTER TABLE certificate_incidents ALTER COLUMN service_ids SET DEFAULT '{}';
-- The services a person with rights on all of them approved when a rotation policy was switched on or run.
ALTER TABLE rotation_policies ADD COLUMN approved_service_ids uuid[] NOT NULL DEFAULT '{}';
UPDATE rotation_policies SET approved_service_ids = ARRAY[default_service_id()] WHERE enabled;
GRANT UPDATE (approved_service_ids) ON rotation_policies TO alice_app;
-- NULL: the owner's whole reach; otherwise a narrowing to these services.
ALTER TABLE api_tokens ADD COLUMN service_ids uuid[] CHECK (cardinality(service_ids) BETWEEN 1 AND 50);

-- A Key Vault binding's website whose server's service does not accept the vault's keys (no trust, design §5.6): the
-- automatic deployment planner marks it service.untrusted (its notice goes out when the mark is set) and clears it when
-- a trust allows it again or the website leaves the binding. An ACME binding has its own mark (acme_bindings).
ALTER TABLE certificate_locations ADD COLUMN binding_attention_code text NOT NULL DEFAULT ''
    CHECK (binding_attention_code ~ '^[A-Za-z0-9._-]{0,100}$');
ALTER TABLE certificate_locations ADD COLUMN binding_attention_at timestamptz;
ALTER TABLE certificate_locations ADD CONSTRAINT certificate_locations_binding_attention
    CHECK ((binding_attention_at IS NULL) = (binding_attention_code = ''));
GRANT UPDATE (binding_attention_code, binding_attention_at) ON certificate_locations TO alice_app;

-- People without a global role (scoped bindings only) and automation accounts: a non-person that never signs in and only
-- holds API tokens; never the break-glass account, never a global Administrator. (The design's "break-glass account is
-- always a global Administrator" CHECK is not added: today another Administrator may demote it, and Phase 1 changes
-- nobody's rights.)
ALTER TABLE users ALTER COLUMN role DROP NOT NULL;
ALTER TABLE users ADD COLUMN description text NOT NULL DEFAULT '' CHECK (char_length(description) <= 500);
ALTER TABLE users DROP CONSTRAINT users_auth_source_check;
ALTER TABLE users ADD CONSTRAINT users_auth_source_check CHECK (auth_source IN ('local', 'oidc', 'ldap', 'automation'));
ALTER TABLE users ADD CONSTRAINT users_automation_not_person CHECK (auth_source <> 'automation'
    OR (password_hash IS NULL AND NOT is_break_glass AND role_source = 'manual' AND (role IS NULL OR role IN ('operator', 'auditor'))));

GRANT SELECT, INSERT, UPDATE, DELETE ON environments, services, directory_groups, user_directory_groups, role_bindings,
    service_trusts, service_owners TO alice_app;
GRANT SELECT, INSERT ON service_policies TO alice_app;

-- +goose Down
-- A Down never silently widens access: it refuses (SQLSTATE Z1025) while a second service, a role binding, an
-- automation account or a user without a global role exists; nothing is changed then. Without them every resource is
-- in the Default service and every user has its global role, which is the schema below.
-- +goose StatementBegin
DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM services WHERE NOT is_default) OR EXISTS (SELECT 1 FROM role_bindings)
            OR EXISTS (SELECT 1 FROM users WHERE auth_source = 'automation' OR role IS NULL) THEN
        RAISE EXCEPTION 'cannot migrate down: scoped access exists (a second service, a role binding, an automation account or a user without a global role); remove it first or restore a backup taken before 00025' USING ERRCODE = 'Z1025';
    END IF;
END $$;
-- +goose StatementEnd
REVOKE SELECT, INSERT ON service_policies FROM alice_app;
REVOKE SELECT, INSERT, UPDATE, DELETE ON environments, services, directory_groups, user_directory_groups, role_bindings,
    service_trusts, service_owners FROM alice_app;
ALTER TABLE users DROP CONSTRAINT users_automation_not_person;
ALTER TABLE users DROP CONSTRAINT users_auth_source_check;
ALTER TABLE users ADD CONSTRAINT users_auth_source_check CHECK (auth_source IN ('local', 'oidc', 'ldap'));
ALTER TABLE users DROP COLUMN description;
ALTER TABLE users ALTER COLUMN role SET NOT NULL;
REVOKE UPDATE (binding_attention_code, binding_attention_at) ON certificate_locations FROM alice_app;
ALTER TABLE certificate_locations DROP CONSTRAINT certificate_locations_binding_attention;
ALTER TABLE certificate_locations DROP COLUMN binding_attention_at;
ALTER TABLE certificate_locations DROP COLUMN binding_attention_code;
ALTER TABLE api_tokens DROP COLUMN service_ids;
REVOKE UPDATE (approved_service_ids) ON rotation_policies FROM alice_app;
ALTER TABLE rotation_policies DROP COLUMN approved_service_ids;
ALTER TABLE certificate_incidents DROP COLUMN service_ids;
ALTER TABLE alerts DROP COLUMN service_id;
ALTER TABLE jobs DROP COLUMN service_id;
REVOKE UPDATE (service_id) ON targets, certificates, csr_requests, ssh_keys, acme_certificates, discovery_scopes FROM alice_app;
ALTER TABLE discovery_scopes DROP COLUMN service_id;
ALTER TABLE acme_certificates DROP COLUMN service_id;
ALTER TABLE ssh_keys DROP COLUMN service_id;
ALTER TABLE csr_requests DROP COLUMN service_id;
ALTER TABLE certificates DROP COLUMN service_id;
ALTER TABLE targets DROP COLUMN service_id;
DROP TABLE service_owners;
DROP TABLE service_trusts;
DROP TABLE role_bindings;
DROP TABLE user_directory_groups;
DROP TABLE directory_groups;
DROP FUNCTION default_service_id();
DROP TABLE service_policies;
DROP TABLE services;
DROP TABLE environments;
