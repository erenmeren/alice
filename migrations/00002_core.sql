-- +goose Up
-- +goose StatementBegin
DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'alice_app') THEN
        CREATE ROLE alice_app NOLOGIN;
    END IF;
END
$$;
-- +goose StatementEnd

CREATE TABLE users (
    id                  uuid PRIMARY KEY,
    username            citext NOT NULL UNIQUE,
    email               citext NOT NULL DEFAULT '',
    display_name        text NOT NULL,
    auth_source         text NOT NULL DEFAULT 'local' CHECK (auth_source IN ('local', 'oidc')),
    password_hash       text,
    role                text NOT NULL CHECK (role IN ('admin', 'operator', 'auditor')),
    role_source         text NOT NULL DEFAULT 'manual' CHECK (role_source IN ('manual', 'oidc_mapping')),
    locale              text NOT NULL DEFAULT 'en',
    timezone            text,
    is_break_glass      boolean NOT NULL DEFAULT false,
    disabled_at         timestamptz,
    failed_logins       integer NOT NULL DEFAULT 0,
    locked_until        timestamptz,
    password_changed_at timestamptz,
    last_login_at       timestamptz,
    created_at          timestamptz NOT NULL,
    updated_at          timestamptz NOT NULL,
    CONSTRAINT users_local_has_password CHECK (auth_source <> 'local' OR password_hash IS NOT NULL)
);

CREATE TABLE user_mfa (
    user_id          uuid PRIMARY KEY REFERENCES users (id) ON DELETE CASCADE,
    totp_secret_ct   bytea NOT NULL,
    totp_nonce       bytea NOT NULL,
    totp_wrapped_dek bytea NOT NULL,
    totp_key_version integer NOT NULL,
    enrolled_at      timestamptz,
    last_used_step   bigint NOT NULL DEFAULT 0,
    created_at       timestamptz NOT NULL
);

CREATE TABLE recovery_codes (
    id         uuid PRIMARY KEY,
    user_id    uuid NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    code_hash  text NOT NULL,
    used_at    timestamptz,
    created_at timestamptz NOT NULL
);
CREATE INDEX recovery_codes_unused ON recovery_codes (user_id) WHERE used_at IS NULL;

CREATE TABLE sessions (
    id_hash         bytea PRIMARY KEY,
    user_id         uuid NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    kind            text NOT NULL CHECK (kind IN ('pending', 'full')),
    created_at      timestamptz NOT NULL,
    last_seen_at    timestamptz NOT NULL,
    expires_at      timestamptz NOT NULL,
    idle_expires_at timestamptz NOT NULL,
    ip              inet,
    user_agent      text NOT NULL DEFAULT '',
    mfa_verified_at timestamptz,
    stepup_until    timestamptz,
    revoked_at      timestamptz
);
CREATE INDEX sessions_user ON sessions (user_id);
CREATE INDEX sessions_expires ON sessions (expires_at);

CREATE TABLE api_tokens (
    id           uuid PRIMARY KEY,
    user_id      uuid NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    name         text NOT NULL,
    token_hash   bytea NOT NULL UNIQUE,
    token_prefix text NOT NULL,
    scopes       text[] NOT NULL,
    expires_at   timestamptz NOT NULL,
    last_used_at timestamptz,
    revoked_at   timestamptz,
    created_at   timestamptz NOT NULL
);
CREATE INDEX api_tokens_user ON api_tokens (user_id);

CREATE TABLE setup_sessions (
    id_hash               bytea PRIMARY KEY,
    created_at            timestamptz NOT NULL,
    idle_expires_at       timestamptz NOT NULL,
    pending_username      citext,
    pending_display_name  text,
    pending_email         citext,
    pending_password_hash text,
    totp_secret_ct        bytea,
    totp_nonce            bytea,
    totp_wrapped_dek      bytea,
    totp_key_version      integer
);

CREATE TABLE master_key_versions (
    version    integer PRIMARY KEY,
    key_check  bytea NOT NULL,
    created_at timestamptz NOT NULL,
    retired_at timestamptz
);

CREATE TABLE audit_log (
    seq         bigint PRIMARY KEY CHECK (seq > 0),
    at          timestamptz NOT NULL,
    actor_type  text NOT NULL CHECK (actor_type IN ('user', 'api_token', 'system', 'oidc')),
    actor_id    uuid,
    actor_name  text NOT NULL,
    ip          inet,
    action      text NOT NULL,
    object_type text NOT NULL DEFAULT '',
    object_id   text NOT NULL DEFAULT '',
    result      text NOT NULL CHECK (result IN ('success', 'failure', 'denied')),
    details     jsonb NOT NULL DEFAULT '{}',
    request_id  text NOT NULL DEFAULT '',
    prev_hash   bytea NOT NULL,
    hash        bytea NOT NULL
);
CREATE INDEX audit_log_action ON audit_log (action);

-- +goose StatementBegin
CREATE FUNCTION audit_log_immutable() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    RAISE EXCEPTION 'audit_log is append-only';
END
$$;
-- +goose StatementEnd

CREATE TRIGGER audit_log_no_update_delete BEFORE UPDATE OR DELETE ON audit_log
    FOR EACH ROW EXECUTE FUNCTION audit_log_immutable();
CREATE TRIGGER audit_log_no_truncate BEFORE TRUNCATE ON audit_log
    FOR EACH STATEMENT EXECUTE FUNCTION audit_log_immutable();

GRANT USAGE ON SCHEMA public TO alice_app;
GRANT SELECT ON goose_db_version TO alice_app;
GRANT SELECT, INSERT, UPDATE, DELETE ON settings, users, user_mfa, recovery_codes, sessions, api_tokens, setup_sessions TO alice_app;
GRANT SELECT, INSERT ON master_key_versions, audit_log TO alice_app;

-- +goose Down
DROP TABLE audit_log;
DROP FUNCTION audit_log_immutable();
DROP TABLE master_key_versions;
DROP TABLE setup_sessions;
DROP TABLE api_tokens;
DROP TABLE sessions;
DROP TABLE recovery_codes;
DROP TABLE user_mfa;
DROP TABLE users;
