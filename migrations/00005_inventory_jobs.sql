-- +goose Up
-- Phase 3: providers, targets, SSH key inventory and the durable job queue (spec §7.2–§7.4, §8; R37).

CREATE TABLE credentials (
    id          uuid PRIMARY KEY,
    purpose     text NOT NULL CHECK (purpose IN ('platform_ssh')),
    kind        text NOT NULL CHECK (kind IN ('ssh_private_key', 'ssh_password_unused', 'azure_sp_secret', 'azure_sp_cert', 'azure_managed_identity')),
    public_info jsonb NOT NULL DEFAULT '{}',
    ciphertext  bytea NOT NULL,
    nonce       bytea NOT NULL CHECK (octet_length(nonce) = 12),
    wrapped_dek bytea NOT NULL,
    key_version integer NOT NULL CHECK (key_version >= 1),
    created_at  timestamptz NOT NULL,
    rotated_at  timestamptz
);
CREATE UNIQUE INDEX credentials_one_platform_key ON credentials (purpose) WHERE purpose = 'platform_ssh';

CREATE TABLE targets (
    id                         uuid PRIMARY KEY,
    name                       citext NOT NULL CHECK (char_length(name::text) BETWEEN 1 AND 100),
    type                       text NOT NULL CHECK (type IN ('nginx', 'linux', 'azure_key_vault')),
    config                     jsonb NOT NULL,
    credential_id              uuid NOT NULL REFERENCES credentials (id),
    status                     text NOT NULL CHECK (status IN ('pending_host_key', 'checking', 'ok', 'unreachable', 'host_key_changed', 'auth_failed', 'disabled')),
    last_error_code            text NOT NULL DEFAULT '',
    last_success_at            timestamptz,
    last_discovery_at          timestamptz,
    discovery_interval_seconds integer NOT NULL DEFAULT 86400 CHECK (discovery_interval_seconds BETWEEN 3600 AND 2592000),
    keys_managed_elsewhere     boolean NOT NULL DEFAULT false,
    facts                      jsonb NOT NULL DEFAULT '{}',
    capabilities               text[] NOT NULL DEFAULT '{}',
    counts_toward_license      boolean NOT NULL DEFAULT true,
    version                    integer NOT NULL DEFAULT 1 CHECK (version >= 1),
    created_by                 uuid REFERENCES users (id),
    created_at                 timestamptz NOT NULL,
    updated_at                 timestamptz NOT NULL,
    deleted_at                 timestamptz,
    CHECK (type = 'azure_key_vault' OR (config ? 'host' AND config ? 'port'))
);
CREATE UNIQUE INDEX targets_name_live ON targets (name) WHERE deleted_at IS NULL;
CREATE UNIQUE INDEX targets_endpoint_live ON targets (type, lower(config->>'host'), ((config->>'port')::int)) WHERE deleted_at IS NULL;
CREATE INDEX targets_live_created ON targets (created_at, id) WHERE deleted_at IS NULL;

CREATE TABLE host_keys (
    id                 uuid PRIMARY KEY,
    target_id          uuid NOT NULL REFERENCES targets (id),
    key_type           text NOT NULL,
    public_key         bytea NOT NULL,
    fingerprint_sha256 text NOT NULL,
    status             text NOT NULL CHECK (status IN ('observed', 'pinned', 'superseded', 'rejected')),
    observed_at        timestamptz NOT NULL,
    confirmed_by       uuid REFERENCES users (id),
    confirmed_at       timestamptz,
    superseded_at      timestamptz,
    UNIQUE (target_id, fingerprint_sha256)
);
CREATE UNIQUE INDEX host_keys_one_pinned ON host_keys (target_id) WHERE status = 'pinned';

CREATE TABLE ssh_keys (
    id                 uuid PRIMARY KEY,
    fingerprint_sha256 text NOT NULL UNIQUE,
    key_type           text NOT NULL,
    bits               integer NOT NULL DEFAULT 0,
    public_key         text NOT NULL,
    managed            boolean NOT NULL DEFAULT false,
    is_platform_key    boolean NOT NULL DEFAULT false,
    weak               boolean NOT NULL DEFAULT false,
    label              text NOT NULL DEFAULT '',
    first_seen_at      timestamptz NOT NULL,
    created_at         timestamptz NOT NULL,
    retired_at         timestamptz
);

CREATE TABLE ssh_key_locations (
    id                      uuid PRIMARY KEY,
    ssh_key_id              uuid NOT NULL REFERENCES ssh_keys (id),
    target_id               uuid NOT NULL REFERENCES targets (id),
    os_user                 text NOT NULL,
    file_path               text NOT NULL,
    line_no                 integer NOT NULL CHECK (line_no >= 1),
    options                 text NOT NULL DEFAULT '',
    comment                 text NOT NULL DEFAULT '',
    flags                   text[] NOT NULL DEFAULT '{}',
    first_seen_at           timestamptz NOT NULL,
    last_seen_at            timestamptz NOT NULL,
    missing_since           timestamptz,
    removed_by_alice_at     timestamptz,
    is_alice_connection_key boolean NOT NULL DEFAULT false,
    UNIQUE (ssh_key_id, target_id, os_user, file_path)
);
CREATE INDEX ssh_key_locations_target ON ssh_key_locations (target_id);

-- The platform's own key can never be marked removed or deleted (spec §7.3, SEC-081). The
-- service layer and the provider refuse first; this trigger holds even if both had a bug.
-- A location is Alice's own when its flag is set or when its key's fingerprint is the one in the
-- platform_ssh credential, so clearing the flag or repointing the row does not unprotect it.
-- It runs as the invoking role (alice_app can read credentials and ssh_keys).
-- Replacing the platform key is an owner procedure that disables this trigger (R37 #11).
-- +goose StatementBegin
CREATE FUNCTION ssh_key_locations_protect_alice_key() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE
    platform_fp text;
    is_own boolean;
BEGIN
    SELECT public_info->>'fingerprint' INTO platform_fp FROM credentials WHERE purpose = 'platform_ssh';
    IF TG_OP = 'DELETE' THEN
        SELECT OLD.is_alice_connection_key OR EXISTS (
            SELECT 1 FROM ssh_keys WHERE id = OLD.ssh_key_id AND fingerprint_sha256 = platform_fp) INTO is_own;
        IF is_own THEN
            RAISE EXCEPTION 'the location of Alice''s own connection key cannot be deleted' USING ERRCODE = 'P0001';
        END IF;
        RETURN OLD;
    END IF;
    IF OLD.is_alice_connection_key AND (NOT NEW.is_alice_connection_key
            OR NEW.ssh_key_id <> OLD.ssh_key_id OR NEW.target_id <> OLD.target_id
            OR NEW.os_user <> OLD.os_user OR NEW.file_path <> OLD.file_path) THEN
        RAISE EXCEPTION 'the identity of Alice''s own connection key location cannot change' USING ERRCODE = 'P0001';
    END IF;
    IF NEW.removed_by_alice_at IS NOT NULL THEN
        SELECT OLD.is_alice_connection_key OR NEW.is_alice_connection_key OR EXISTS (
            SELECT 1 FROM ssh_keys WHERE id IN (OLD.ssh_key_id, NEW.ssh_key_id) AND fingerprint_sha256 = platform_fp) INTO is_own;
        IF is_own THEN
            RAISE EXCEPTION 'Alice''s own connection key cannot be removed' USING ERRCODE = 'P0001';
        END IF;
    END IF;
    RETURN NEW;
END $$;
-- +goose StatementEnd
CREATE TRIGGER ssh_key_locations_protect BEFORE UPDATE OR DELETE ON ssh_key_locations
    FOR EACH ROW EXECUTE FUNCTION ssh_key_locations_protect_alice_key();

CREATE TABLE jobs (
    id              uuid PRIMARY KEY,
    type            text NOT NULL,
    class           text NOT NULL CHECK (class IN ('always', 'read_only', 'change')),
    kind            text NOT NULL CHECK (kind IN ('scheduled', 'user', 'system')),
    payload         jsonb NOT NULL DEFAULT '{}',
    payload_mac     bytea NOT NULL CHECK (octet_length(payload_mac) = 32),
    target_id       uuid REFERENCES targets (id),
    dedupe_key      text,
    status          text NOT NULL CHECK (status IN ('queued', 'running', 'succeeded', 'failed', 'cancelled', 'dead', 'blocked_license')),
    priority        smallint NOT NULL DEFAULT 5 CHECK (priority BETWEEN 1 AND 9),
    run_at          timestamptz NOT NULL,
    attempts        integer NOT NULL DEFAULT 0 CHECK (attempts >= 0),
    max_attempts    integer NOT NULL CHECK (max_attempts >= 1),
    locked_by       text,
    locked_until    timestamptz,
    heartbeat_at    timestamptz,
    last_error_code text NOT NULL DEFAULT '',
    result          jsonb NOT NULL DEFAULT '{}',
    created_by      uuid REFERENCES users (id),
    created_by_role text NOT NULL DEFAULT '',
    confirmed_by    uuid REFERENCES users (id),
    confirmed_at    timestamptz,
    created_at      timestamptz NOT NULL,
    started_at      timestamptz,
    finished_at     timestamptz
);
CREATE INDEX jobs_due ON jobs (priority, run_at) WHERE status = 'queued';
CREATE INDEX jobs_running_lease ON jobs (locked_until) WHERE status = 'running';
CREATE INDEX jobs_target ON jobs (target_id, created_at DESC);
CREATE INDEX jobs_finished ON jobs (finished_at) WHERE finished_at IS NOT NULL;
CREATE UNIQUE INDEX jobs_dedupe_live ON jobs (dedupe_key) WHERE status IN ('queued', 'running', 'blocked_license');

CREATE TABLE job_attempts (
    id          uuid PRIMARY KEY,
    job_id      uuid NOT NULL REFERENCES jobs (id) ON DELETE CASCADE,
    attempt     integer NOT NULL,
    worker_id   text NOT NULL,
    started_at  timestamptz NOT NULL,
    finished_at timestamptz,
    error_code  text NOT NULL DEFAULT '',
    UNIQUE (job_id, attempt)
);

CREATE TABLE target_locks (
    target_id    uuid PRIMARY KEY REFERENCES targets (id),
    job_id       uuid NOT NULL REFERENCES jobs (id) ON DELETE CASCADE,
    operation    text NOT NULL,
    locked_by    text NOT NULL,
    heartbeat_at timestamptz NOT NULL,
    lease_until  timestamptz NOT NULL
);
CREATE INDEX target_locks_job ON target_locks (job_id);

-- Credentials are append-only for the application; inventory rows are never deleted (soft delete
-- and missing_since keep the history); jobs, attempts and target locks are working tables.
GRANT SELECT, INSERT ON credentials TO alice_app;
GRANT SELECT, INSERT ON targets, host_keys, ssh_keys, ssh_key_locations TO alice_app;
GRANT UPDATE (name, discovery_interval_seconds, version, updated_at, deleted_at, status, last_error_code, facts,
    last_success_at, last_discovery_at, keys_managed_elsewhere) ON targets TO alice_app;
GRANT UPDATE (status, observed_at, confirmed_by, confirmed_at, superseded_at) ON host_keys TO alice_app;
GRANT UPDATE (is_platform_key, weak) ON ssh_keys TO alice_app;
GRANT UPDATE (line_no, options, comment, flags, last_seen_at, missing_since, removed_by_alice_at, is_alice_connection_key)
    ON ssh_key_locations TO alice_app;
GRANT SELECT, INSERT, UPDATE, DELETE ON jobs, job_attempts, target_locks TO alice_app;

-- +goose Down
DROP TABLE target_locks;
DROP TABLE job_attempts;
DROP TABLE jobs;
DROP TRIGGER ssh_key_locations_protect ON ssh_key_locations;
DROP FUNCTION ssh_key_locations_protect_alice_key();
DROP TABLE ssh_key_locations;
DROP TABLE ssh_keys;
DROP TABLE host_keys;
DROP TABLE targets;
DROP TABLE credentials;
