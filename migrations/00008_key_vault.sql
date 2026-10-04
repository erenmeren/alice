-- +goose Up
-- Phase 5: Azure Key Vault targets and their sign-in credentials, the vault inventory, bindings of
-- vault certificates to Nginx websites, Key Vault deployments and imports (spec §7.2-§7.4, §11; R40).
-- Same conventions as 00006: closed lists for values Alice owns, format checks for names Azure
-- owns, no clock defaults. Nothing here can hold a client secret, a private key, a token, a PFX or a
-- vault secret's value: credentials stay in the Phase 3 envelope and the vault inventory is metadata.
-- Key Vault object names are case-insensitive in Azure (and ASCII-only here), so their uniqueness
-- is on lower(name COLLATE "C"), an ASCII fold that does not follow the database's locale (a Turkish
-- collation folds I to a dotless i). An upsert names the conflict target exactly as
-- (target_id, lower(name COLLATE "C")); for imports with WHERE state IN ('queued', 'running', 'uncertain').

-- A vault's credential belongs to its vault (R37 item 11, R40 row 9): target_id is set in the
-- transaction that inserts the vault, so the foreign key is checked at commit. Credentials stay
-- append-only: a replacement is a new row that targets.credential_id moves to.
ALTER TABLE credentials DROP CONSTRAINT credentials_purpose_check;
ALTER TABLE credentials ADD CONSTRAINT credentials_purpose_check CHECK (purpose IN ('platform_ssh', 'azure_vault'));
ALTER TABLE credentials ADD COLUMN target_id uuid REFERENCES targets (id) DEFERRABLE INITIALLY DEFERRED;
ALTER TABLE credentials ADD CONSTRAINT credentials_target_purpose CHECK ((purpose = 'azure_vault') = (target_id IS NOT NULL));
ALTER TABLE credentials ADD CONSTRAINT credentials_kind_purpose CHECK (
    (purpose = 'platform_ssh' AND kind = 'ssh_private_key')
    OR (purpose = 'azure_vault' AND kind IN ('azure_sp_secret', 'azure_sp_cert', 'azure_managed_identity')));
CREATE INDEX credentials_target ON credentials (target_id) WHERE target_id IS NOT NULL;

-- Vault targets: status degraded (R40 row 12), a poll interval of 5 minutes to 24 hours (row 13),
-- the failure count that delays the next poll, and the vault address (row 5; host and port keep the
-- Phase 3 endpoint index: one live target per vault).
ALTER TABLE targets DROP CONSTRAINT targets_status_check;
ALTER TABLE targets ADD CONSTRAINT targets_status_check CHECK (status IN ('pending_host_key', 'checking', 'ok', 'unreachable',
    'host_key_changed', 'auth_failed', 'disabled', 'degraded'));
ALTER TABLE targets DROP CONSTRAINT targets_discovery_interval_seconds_check;
ALTER TABLE targets ADD CONSTRAINT targets_discovery_interval_seconds_check CHECK (CASE WHEN type = 'azure_key_vault'
    THEN discovery_interval_seconds BETWEEN 300 AND 86400 ELSE discovery_interval_seconds BETWEEN 3600 AND 2592000 END);
ALTER TABLE targets ADD COLUMN poll_failures integer NOT NULL DEFAULT 0 CHECK (poll_failures BETWEEN 0 AND 1000000);
ALTER TABLE targets ADD CONSTRAINT targets_vault_config CHECK (type <> 'azure_key_vault' OR coalesce(
    jsonb_typeof(config->'host') = 'string'
    AND config->>'host' ~ '^[a-z](-?[a-z0-9])+\.vault\.azure\.net$'
    AND char_length(config->>'host') BETWEEN 19 AND 40
    AND config->'port' = '443'::jsonb
    AND config->>'vault_url' = 'https://' || (config->>'host'), false));

-- A target's credential is the credential of that target (R37 item 11, R40 row 9). Whoever writes the
-- row, a vault names a credential of its own (purpose azure_vault, target_id = the vault) and every
-- other target a platform key (SQLSTATE Z1006). The application role may set credential_id only on a
-- vault (a replacement is a new credential row that the vault moves to): any statement that sets it
-- on another kind of target is refused (Z1005), whatever the value; the owner role is not narrowed.
-- It runs as the invoking role (alice_app can read credentials), so every name is schema-qualified
-- and the search path is pinned with pg_temp last. Z1001-Z1004 are 00006's.
-- +goose StatementBegin
CREATE FUNCTION targets_check_credential() RETURNS trigger LANGUAGE plpgsql
SET search_path = pg_catalog, pg_temp AS $$
BEGIN
    IF TG_OP = 'UPDATE' AND current_user = 'alice_app' AND NEW.type <> 'azure_key_vault' THEN
        RAISE EXCEPTION 'the application cannot change the credential of a server' USING ERRCODE = 'Z1005';
    END IF;
    IF TG_OP = 'UPDATE' AND NEW.credential_id IS NOT DISTINCT FROM OLD.credential_id AND NEW.type IS NOT DISTINCT FROM OLD.type THEN
        RETURN NEW;
    END IF;
    IF NEW.type = 'azure_key_vault' THEN
        IF NOT EXISTS (SELECT 1 FROM public.credentials c WHERE c.id = NEW.credential_id AND c.purpose = 'azure_vault' AND c.target_id = NEW.id) THEN
            RAISE EXCEPTION 'the credential does not belong to the vault' USING ERRCODE = 'Z1006';
        END IF;
    ELSIF NOT EXISTS (SELECT 1 FROM public.credentials c WHERE c.id = NEW.credential_id AND c.purpose = 'platform_ssh') THEN
        RAISE EXCEPTION 'a server uses the platform key' USING ERRCODE = 'Z1006';
    END IF;
    RETURN NEW;
END $$;
-- +goose StatementEnd
CREATE TRIGGER targets_credential_check BEFORE INSERT OR UPDATE OF credential_id, type ON targets
    FOR EACH ROW EXECUTE FUNCTION targets_check_credential();

-- One row per certificate name of a vault (spec §11.1; R40 row 14). current_version, current_thumbprint
-- and kv_updated_at change together, when Alice read the latest version's details (R40 row 17);
-- enabled, not_before and expires follow every listing.
CREATE TABLE kv_certificates (
    id                  uuid PRIMARY KEY,
    target_id           uuid NOT NULL REFERENCES targets (id),
    name                text NOT NULL CHECK (name ~ '^[0-9A-Za-z-]{1,127}$'),
    current_version     text NOT NULL DEFAULT '' CHECK (current_version ~ '^([0-9a-f]{32})?$'),
    current_thumbprint  text NOT NULL DEFAULT '' CHECK (current_thumbprint ~ '^([0-9a-f]{40})?$'),
    kv_updated_at       timestamptz,                  -- attributes.updated of the version whose details Alice read
    listed_thumbprint   text NOT NULL CHECK (listed_thumbprint ~ '^[0-9a-f]{40}$'), -- the last listing's x5t
    listed_updated_at   timestamptz,                  -- the last listing's attributes.updated
    enabled             boolean NOT NULL,
    not_before          timestamptz,
    expires             timestamptz,
    kv_created_at       timestamptz,
    exportable          boolean,                      -- NULL until the policy was read
    key_type            text NOT NULL DEFAULT '' CHECK (key_type IN ('', 'rsa', 'ecdsa', 'other')),
    key_size            integer NOT NULL DEFAULT 0 CHECK (key_size BETWEEN 0 AND 16384),
    content_type        text NOT NULL DEFAULT '' CHECK (content_type IN ('', 'pkcs12', 'pem', 'other')),
    issuer_name         text NOT NULL DEFAULT '' CHECK (char_length(issuer_name) <= 127),
    auto_renew          boolean NOT NULL DEFAULT false,
    details_pending     boolean NOT NULL DEFAULT false, -- the listing changed and the details wait for the next poll
    first_seen_at       timestamptz NOT NULL,
    last_seen_at        timestamptz NOT NULL,
    missing_since       timestamptz,
    removed_notified_at timestamptz,
    CONSTRAINT kv_certificates_id_target UNIQUE (id, target_id) -- the target of a binding's certificate (bindings_vault)
);
CREATE UNIQUE INDEX kv_certificates_name ON kv_certificates (target_id, lower(name COLLATE "C"));

-- One row per version Alice listed (spec certificate_versions). certificate_id is the leaf's row once
-- Alice read the version's details (only versions Alice saw as current have one; R40 row 17).
CREATE TABLE kv_certificate_versions (
    id                uuid PRIMARY KEY,
    kv_certificate_id uuid NOT NULL REFERENCES kv_certificates (id),
    version           text NOT NULL CHECK (version ~ '^[0-9a-f]{32}$'),
    thumbprint        text NOT NULL CHECK (thumbprint ~ '^[0-9a-f]{40}$'),
    certificate_id    uuid REFERENCES certificates (id),
    enabled           boolean NOT NULL,
    not_before        timestamptz,
    expires           timestamptz,
    kv_created_at     timestamptz,
    exportable        boolean,
    key_type          text NOT NULL DEFAULT '' CHECK (key_type IN ('', 'rsa', 'ecdsa', 'other')),
    content_type      text NOT NULL DEFAULT '' CHECK (content_type IN ('', 'pkcs12', 'pem', 'other')),
    detected_at       timestamptz NOT NULL,
    -- Never deployed by itself, only by an Administrator (R40 row 21; rulings S7, S8): the license gate was
    -- not open when it was first seen ('license'), or auto-deploy found its chain incomplete ('incomplete_chain').
    held              boolean NOT NULL DEFAULT false,
    held_reason       text NOT NULL DEFAULT '' CHECK (held_reason IN ('', 'license', 'incomplete_chain')),
    notified_at       timestamptz,                    -- its new-version email went out
    skipped_notified_at timestamptz,                  -- its skipped-version email went out (a separate mark: D25)
    UNIQUE (kv_certificate_id, version),
    CHECK (held = (held_reason <> ''))
);
CREATE INDEX kv_certificate_versions_certificate ON kv_certificate_versions (certificate_id) WHERE certificate_id IS NOT NULL;
CREATE INDEX kv_certificate_versions_thumbprint ON kv_certificate_versions (thumbprint);

-- Key and secret metadata (spec §11.1); never key material, never secret values.
CREATE TABLE kv_keys (
    id                 uuid PRIMARY KEY,
    target_id          uuid NOT NULL REFERENCES targets (id),
    name               text NOT NULL CHECK (name ~ '^[0-9A-Za-z-]{1,127}$'),
    version            text NOT NULL DEFAULT '' CHECK (version ~ '^([0-9a-f]{32})?$'),
    key_type           text NOT NULL DEFAULT '' CHECK (key_type IN ('', 'rsa', 'ec', 'oct', 'other')),
    hsm                boolean NOT NULL DEFAULT false,
    key_size           integer NOT NULL DEFAULT 0 CHECK (key_size BETWEEN 0 AND 16384),
    curve              text NOT NULL DEFAULT '' CHECK (curve IN ('', 'P-256', 'P-256K', 'P-384', 'P-521', 'other')),
    details_updated_at timestamptz,   -- attributes.updated when the details were read
    details_problem    text NOT NULL DEFAULT '' CHECK (details_problem IN ('', 'forbidden', 'failed')),
    enabled            boolean NOT NULL,
    managed            boolean NOT NULL DEFAULT false,
    not_before         timestamptz,
    expires            timestamptz,
    kv_created_at      timestamptz,
    kv_updated_at      timestamptz,
    first_seen_at      timestamptz NOT NULL,
    last_seen_at       timestamptz NOT NULL,
    missing_since      timestamptz
);
CREATE UNIQUE INDEX kv_keys_name ON kv_keys (target_id, lower(name COLLATE "C"));
CREATE TABLE kv_secrets (
    id            uuid PRIMARY KEY,
    target_id     uuid NOT NULL REFERENCES targets (id),
    name          text NOT NULL CHECK (name ~ '^[0-9A-Za-z-]{1,127}$'),
    content_type  text NOT NULL DEFAULT '' CHECK (char_length(content_type) <= 255),
    enabled       boolean NOT NULL,
    managed       boolean NOT NULL DEFAULT false,
    not_before    timestamptz,
    expires       timestamptz,
    kv_created_at timestamptz,
    kv_updated_at timestamptz,
    first_seen_at timestamptz NOT NULL,
    last_seen_at  timestamptz NOT NULL,
    missing_since timestamptz
);
CREATE UNIQUE INDEX kv_secrets_name ON kv_secrets (target_id, lower(name COLLATE "C"));
CREATE INDEX kv_certificates_expires ON kv_certificates (expires) WHERE missing_since IS NULL;
CREATE INDEX kv_keys_expires ON kv_keys (expires) WHERE missing_since IS NULL;

-- A binding connects one vault certificate to Nginx locations (spec §11.7; R40 rows 22-24).
CREATE TABLE bindings (
    id                uuid PRIMARY KEY,
    kv_certificate_id uuid NOT NULL REFERENCES kv_certificates (id),
    kv_target_id      uuid NOT NULL REFERENCES targets (id),
    -- kv_target_id is the vault of the certificate, not any target: a vault cannot be deleted under a live binding
    CONSTRAINT bindings_vault FOREIGN KEY (kv_certificate_id, kv_target_id) REFERENCES kv_certificates (id, target_id),
    auto_deploy       boolean NOT NULL DEFAULT false,
    auto_since        timestamptz,           -- when automatic deployment was last turned on
    stopped_version   text NOT NULL DEFAULT '' CHECK (stopped_version ~ '^([0-9a-f]{32})?$'), -- the wave of this version stopped (R40 row 20)
    created_by        uuid REFERENCES users (id),
    created_at        timestamptz NOT NULL,
    deleted_at        timestamptz,
    version           integer NOT NULL DEFAULT 1 CHECK (version >= 1),
    CHECK (auto_deploy = (auto_since IS NOT NULL))
);
CREATE UNIQUE INDEX bindings_one_live ON bindings (kv_certificate_id) WHERE deleted_at IS NULL;
CREATE INDEX bindings_auto ON bindings (id) WHERE deleted_at IS NULL AND auto_deploy;

ALTER TABLE certificate_locations ADD COLUMN binding_id uuid REFERENCES bindings (id);
CREATE INDEX certificate_locations_binding ON certificate_locations (binding_id) WHERE binding_id IS NOT NULL;

-- A Key Vault deployment names its binding and the vault version it deploys (R38 item 7's
-- "binding_id arrives in Phase 5"; R40 row 18). Both are written by the INSERT only.
ALTER TABLE deployments ADD COLUMN binding_id uuid REFERENCES bindings (id);
ALTER TABLE deployments ADD COLUMN kv_version_id uuid REFERENCES kv_certificate_versions (id);
ALTER TABLE deployments ADD CONSTRAINT deployments_kv_source CHECK ((binding_id IS NULL) = (kv_version_id IS NULL));
CREATE INDEX deployments_kv_version ON deployments (kv_version_id, location_id, created_at DESC) WHERE kv_version_id IS NOT NULL;
CREATE INDEX deployments_binding ON deployments (binding_id, created_at DESC) WHERE binding_id IS NOT NULL;

-- Imports of a certificate held in Alice into a vault (spec §11.8; R40 row 25).
CREATE TABLE kv_imports (
    id             uuid PRIMARY KEY,
    certificate_id uuid NOT NULL REFERENCES certificates (id),
    target_id      uuid NOT NULL REFERENCES targets (id),
    name           text NOT NULL CHECK (name ~ '^[0-9A-Za-z-]{1,127}$'),
    new_version    boolean NOT NULL,     -- the name existed: the person confirmed a new version
    state          text NOT NULL CHECK (state IN ('queued', 'running', 'succeeded', 'failed', 'uncertain')),
    thumbprint     text NOT NULL CHECK (thumbprint ~ '^[0-9a-f]{40}$'), -- SHA-1 of the imported leaf: how a poll recognises it
    version        text NOT NULL DEFAULT '' CHECK (version ~ '^([0-9a-f]{32})?$'),
    error_code     text NOT NULL DEFAULT '' CHECK (error_code ~ '^[A-Za-z0-9._-]{0,100}$'),
    error_params   jsonb NOT NULL DEFAULT '{}' CHECK (jsonb_typeof(error_params) = 'object' AND octet_length(error_params::text) <= 4096),
    job_id         uuid REFERENCES jobs (id) ON DELETE SET NULL,
    requested_by   uuid REFERENCES users (id),
    created_at     timestamptz NOT NULL,
    sent_at        timestamptz,
    finished_at    timestamptz,
    CHECK ((state IN ('succeeded', 'failed')) = (finished_at IS NOT NULL)),
    CHECK (state <> 'succeeded' OR version <> ''),
    -- created_at is the request's time and sent_at the moment before the send: an uncertain import is
    -- settled only by a vault version created after the request (ruling S14). Whatever reached or may
    -- have reached the vault was sent; nothing queued was.
    CHECK (state <> 'queued' OR sent_at IS NULL),
    CHECK (state NOT IN ('running', 'uncertain', 'succeeded') OR sent_at IS NOT NULL)
);
-- One active import per vault and name; names compare case-insensitively like the vault's.
CREATE UNIQUE INDEX kv_imports_one_active ON kv_imports (target_id, lower(name COLLATE "C")) WHERE state IN ('queued', 'running', 'uncertain');
CREATE INDEX kv_imports_job ON kv_imports (job_id) WHERE job_id IS NOT NULL; -- the foreign key of a pruned job

-- An import is history and is never sent twice. A finished import (succeeded or failed) changes only in
-- job_id going to NULL (the foreign key's ON DELETE SET NULL when maintenance.cleanup prunes the job, run
-- as the table owner, passes through here); sent_at, once set, never changes; state never returns to
-- queued; an uncertain import is settled (succeeded or failed) or stays uncertain, it is never run again.
-- SQLSTATE Z1007. Same shape as deployments_protect_done: the invoking role, a pinned search path.
-- +goose StatementBegin
CREATE FUNCTION kv_imports_protect_history() RETURNS trigger LANGUAGE plpgsql
SET search_path = pg_catalog, pg_temp AS $$
BEGIN
    IF OLD.finished_at IS NOT NULL THEN
        IF NEW.job_id IS NOT NULL AND NEW.job_id IS DISTINCT FROM OLD.job_id THEN
            RAISE EXCEPTION 'a finished import gains no job' USING ERRCODE = 'Z1007';
        END IF;
        IF to_jsonb(NEW) - 'job_id' IS DISTINCT FROM to_jsonb(OLD) - 'job_id' THEN
            RAISE EXCEPTION 'a finished import is history' USING ERRCODE = 'Z1007';
        END IF;
        RETURN NEW;
    END IF;
    IF OLD.sent_at IS NOT NULL AND NEW.sent_at IS DISTINCT FROM OLD.sent_at THEN
        RAISE EXCEPTION 'the send time of an import never changes' USING ERRCODE = 'Z1007';
    END IF;
    IF NEW.state = 'queued' AND OLD.state <> 'queued' THEN
        RAISE EXCEPTION 'an import that left the queue is never queued again' USING ERRCODE = 'Z1007';
    END IF;
    IF OLD.state = 'uncertain' AND NEW.state NOT IN ('uncertain', 'succeeded', 'failed') THEN
        RAISE EXCEPTION 'an uncertain import is settled, never sent again' USING ERRCODE = 'Z1007';
    END IF;
    RETURN NEW;
END $$;
-- +goose StatementEnd
CREATE TRIGGER kv_imports_history_frozen BEFORE UPDATE ON kv_imports
    FOR EACH ROW EXECUTE FUNCTION kv_imports_protect_history();
CREATE INDEX kv_imports_certificate ON kv_imports (certificate_id, created_at DESC);

-- History is never deleted; vault inventory rows are marked missing, bindings soft-deleted.
GRANT SELECT, INSERT ON kv_certificates, kv_certificate_versions, kv_keys, kv_secrets, bindings, kv_imports TO alice_app;
GRANT UPDATE (credential_id, poll_failures) ON targets TO alice_app;
GRANT UPDATE (current_version, current_thumbprint, kv_updated_at, listed_thumbprint, listed_updated_at, enabled, not_before,
    expires, kv_created_at, exportable, key_type, key_size, content_type, issuer_name, auto_renew, details_pending, last_seen_at,
    missing_since, removed_notified_at) ON kv_certificates TO alice_app;
GRANT UPDATE (certificate_id, enabled, not_before, expires, exportable, key_type, content_type, held, held_reason, notified_at,
    skipped_notified_at) ON kv_certificate_versions TO alice_app;
GRANT UPDATE (version, key_type, hsm, key_size, curve, details_updated_at, details_problem, enabled, managed, not_before, expires,
    kv_created_at, kv_updated_at, last_seen_at, missing_since) ON kv_keys TO alice_app;
GRANT UPDATE (content_type, enabled, managed, not_before, expires, kv_created_at, kv_updated_at, last_seen_at, missing_since)
    ON kv_secrets TO alice_app;
GRANT UPDATE (auto_deploy, auto_since, stopped_version, deleted_at, version) ON bindings TO alice_app;
GRANT UPDATE (binding_id) ON certificate_locations TO alice_app;
GRANT UPDATE (state, version, error_code, error_params, job_id, sent_at, finished_at) ON kv_imports TO alice_app;

-- +goose Down
-- Correct only on a database without Key Vault data (as 00006's). The Down refuses, with a clear message and
-- SQLSTATE Z1008, when a vault target (soft-deleted ones too: targets are never deleted) or a vault
-- credential exists, or when a server has the status degraded (the restored check would refuse it); nothing
-- is changed then (goose runs the Down in one transaction).
-- +goose StatementBegin
DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM credentials WHERE purpose = 'azure_vault') OR EXISTS (SELECT 1 FROM targets WHERE type = 'azure_key_vault') THEN
        RAISE EXCEPTION 'cannot migrate down: Key Vault data exists (vault targets or their credentials); remove it first or restore a backup taken before 00008' USING ERRCODE = 'Z1008';
    END IF;
    IF EXISTS (SELECT 1 FROM targets WHERE status = 'degraded') THEN
        RAISE EXCEPTION 'cannot migrate down: a target has the status degraded, which 00007 and earlier do not know; give it another status first' USING ERRCODE = 'Z1008';
    END IF;
END $$;
-- +goose StatementEnd
DROP TRIGGER kv_imports_history_frozen ON kv_imports;
DROP FUNCTION kv_imports_protect_history();
DROP TRIGGER targets_credential_check ON targets;
DROP FUNCTION targets_check_credential();
REVOKE UPDATE (binding_id) ON certificate_locations FROM alice_app;
REVOKE UPDATE (credential_id, poll_failures) ON targets FROM alice_app;
DROP TABLE kv_imports;
ALTER TABLE deployments DROP CONSTRAINT deployments_kv_source;
ALTER TABLE deployments DROP COLUMN kv_version_id;
ALTER TABLE deployments DROP COLUMN binding_id;
ALTER TABLE certificate_locations DROP COLUMN binding_id;
DROP TABLE bindings;
DROP TABLE kv_secrets;
DROP TABLE kv_keys;
DROP TABLE kv_certificate_versions;
DROP TABLE kv_certificates;
ALTER TABLE targets DROP CONSTRAINT targets_vault_config;
ALTER TABLE targets DROP COLUMN poll_failures;
ALTER TABLE targets DROP CONSTRAINT targets_discovery_interval_seconds_check;
ALTER TABLE targets ADD CONSTRAINT targets_discovery_interval_seconds_check CHECK (discovery_interval_seconds BETWEEN 3600 AND 2592000);
ALTER TABLE targets DROP CONSTRAINT targets_status_check;
ALTER TABLE targets ADD CONSTRAINT targets_status_check CHECK (status IN ('pending_host_key', 'checking', 'ok', 'unreachable',
    'host_key_changed', 'auth_failed', 'disabled'));
DROP INDEX credentials_target;
ALTER TABLE credentials DROP CONSTRAINT credentials_kind_purpose;
ALTER TABLE credentials DROP CONSTRAINT credentials_target_purpose;
ALTER TABLE credentials DROP COLUMN target_id;
ALTER TABLE credentials DROP CONSTRAINT credentials_purpose_check;
ALTER TABLE credentials ADD CONSTRAINT credentials_purpose_check CHECK (purpose IN ('platform_ssh'));
