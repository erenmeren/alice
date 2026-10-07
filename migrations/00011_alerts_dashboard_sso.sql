-- +goose Up
-- Phase 7: alerts, dashboard, saved views and OpenID Connect single sign-on (spec §7.1, §7.4, §7.6, §15.3,
-- §26.9; R42). Same conventions as 00006-00010: closed lists for values Alice owns, format checks for names,
-- no clock defaults.

-- The ledger of sent expiry notices (R42 rows 2-5). One row per kind, object, expiry instant and threshold
-- (0 = expired): the transaction that inserts the row is the only one that queues its email, so a notice is
-- queued once even when two scans run at once. Append-only for the application.
CREATE TABLE alerts (
    id             uuid PRIMARY KEY,
    kind           text NOT NULL CHECK (kind IN ('certificate_expiry', 'kv_certificate_expiry', 'kv_key_expiry',
                                                  'kv_credential_expiry')),
    object_id      uuid NOT NULL,
    subject        text NOT NULL CHECK (char_length(subject) BETWEEN 1 AND 300),
    expires_at     timestamptz NOT NULL,
    threshold_days integer NOT NULL CHECK (threshold_days BETWEEN 0 AND 365),
    license_locked boolean NOT NULL,
    emailed        boolean NOT NULL,
    created_at     timestamptz NOT NULL,
    UNIQUE (kind, object_id, expires_at, threshold_days)
);
CREATE INDEX alerts_created ON alerts (created_at DESC, id DESC);

-- Envelope secrets of settings (§7.6; R42 rows 9 and 19): the SMTP password and the client secret of each
-- identity provider. AAD setting_secrets/<key>/ciphertext. Nothing else may be stored here.
CREATE TABLE setting_secrets (
    key         text PRIMARY KEY CHECK (key ~ '^(notify\.smtp\.password|sso\.provider\.[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\.client_secret)$'),
    ciphertext  bytea NOT NULL,
    nonce       bytea NOT NULL CHECK (octet_length(nonce) = 12),
    wrapped_dek bytea NOT NULL,
    key_version integer NOT NULL CHECK (key_version >= 1),
    updated_at  timestamptz NOT NULL
);

-- Personal saved views (R42 row 15): private to their user, two pages, names unique per user and page.
CREATE TABLE saved_views (
    id         uuid PRIMARY KEY,
    user_id    uuid NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    page       text NOT NULL CHECK (page IN ('certificates', 'ssh_keys')),
    name       text NOT NULL CHECK (char_length(name) BETWEEN 1 AND 60),
    query      jsonb NOT NULL CHECK (jsonb_typeof(query) = 'object'),
    created_at timestamptz NOT NULL
);
CREATE UNIQUE INDEX saved_views_name ON saved_views (user_id, page, lower(name));

-- Identity providers (§7.1; R42 row 19). The endpoints are read by discovery at configuration time and on
-- Refresh (SEC-013), never from a request; the client secret lives in setting_secrets.
CREATE TABLE oidc_providers (
    id                     uuid PRIMARY KEY,
    name                   text NOT NULL CHECK (char_length(name) BETWEEN 1 AND 60),
    issuer_url             text NOT NULL CHECK (char_length(issuer_url) <= 500
                                               AND issuer_url ~ '^https://[^[:space:]/?#@]+(/[^[:space:]?#]*)?$'),
    client_id              text NOT NULL CHECK (char_length(client_id) BETWEEN 1 AND 255 AND client_id !~ '[[:cntrl:][:space:]]'),
    scopes                 text[] NOT NULL CHECK (cardinality(scopes) BETWEEN 1 AND 10 AND 'openid' = ANY (scopes)),
    groups_claim           text NOT NULL CHECK (groups_claim ~ '^[A-Za-z0-9_.:/-]{1,100}$'),
    ca_pem                 text NOT NULL DEFAULT '' CHECK (char_length(ca_pem) <= 65536),
    authorization_endpoint text NOT NULL CHECK (char_length(authorization_endpoint) <= 500 AND authorization_endpoint ~ '^https://'),
    token_endpoint         text NOT NULL CHECK (char_length(token_endpoint) <= 500 AND token_endpoint ~ '^https://'),
    jwks_uri               text NOT NULL CHECK (char_length(jwks_uri) <= 500 AND jwks_uri ~ '^https://'),
    enabled                boolean NOT NULL,
    version                integer NOT NULL DEFAULT 1 CHECK (version >= 1),
    created_by             uuid REFERENCES users (id),
    created_at             timestamptz NOT NULL,
    updated_at             timestamptz NOT NULL
);
CREATE UNIQUE INDEX oidc_providers_name ON oidc_providers (lower(name));
CREATE UNIQUE INDEX oidc_providers_client ON oidc_providers (issuer_url, client_id);

-- Group-to-role mappings (SEC-014; R42 row 24): a non-empty group value, no "all users" mapping.
CREATE TABLE oidc_group_mappings (
    id                uuid PRIMARY KEY,
    provider_id       uuid NOT NULL REFERENCES oidc_providers (id) ON DELETE CASCADE,
    group_claim_value text NOT NULL CHECK (char_length(group_claim_value) BETWEEN 1 AND 256
                                           AND group_claim_value = btrim(group_claim_value)
                                           AND group_claim_value !~ '[[:cntrl:]]'),
    role              text NOT NULL CHECK (role IN ('admin', 'operator', 'auditor')),
    created_by        uuid REFERENCES users (id),
    created_at        timestamptz NOT NULL,
    UNIQUE (provider_id, group_claim_value)
);

-- SSO users (§7.1, SEC-015; R42 rows 21-23): matched by (oidc_provider_id, oidc_subject) only (S-8; the issuer stays stored for display); no password, never the
-- break-glass account, role always from the mapping. A local user has none of the three columns.
ALTER TABLE users ADD COLUMN oidc_provider_id uuid REFERENCES oidc_providers (id);
ALTER TABLE users ADD COLUMN oidc_issuer text CHECK (char_length(oidc_issuer) <= 500);
ALTER TABLE users ADD COLUMN oidc_subject text CHECK (char_length(oidc_subject) BETWEEN 1 AND 255);
ALTER TABLE users ADD CONSTRAINT users_oidc_identity CHECK (
    (auth_source = 'oidc') = (oidc_provider_id IS NOT NULL)
    AND (auth_source = 'oidc') = (oidc_issuer IS NOT NULL)
    AND (auth_source = 'oidc') = (oidc_subject IS NOT NULL));
ALTER TABLE users ADD CONSTRAINT users_oidc_not_local CHECK (auth_source <> 'oidc'
    OR (password_hash IS NULL AND NOT is_break_glass AND role_source = 'oidc_mapping'));
CREATE UNIQUE INDEX users_oidc_identity_unique ON users (oidc_provider_id, oidc_subject) WHERE oidc_provider_id IS NOT NULL;

-- One sign-in in flight (SEC-011): single use (deleted when used), at most 10 minutes, bound to the hash of the
-- browser's binding cookie; a step-up names the session and user it belongs to.
CREATE TABLE oidc_login_states (
    state_hash    bytea PRIMARY KEY CHECK (octet_length(state_hash) = 32),
    provider_id   uuid NOT NULL REFERENCES oidc_providers (id) ON DELETE CASCADE,
    binding_hash  bytea NOT NULL CHECK (octet_length(binding_hash) = 32),
    nonce         text NOT NULL CHECK (nonce ~ '^[A-Za-z0-9_-]{43}$'),
    code_verifier text NOT NULL CHECK (code_verifier ~ '^[A-Za-z0-9_-]{43,128}$'),
    purpose       text NOT NULL CHECK (purpose IN ('login', 'stepup')),
    session_hash  bytea CHECK (octet_length(session_hash) = 32),
    user_id       uuid REFERENCES users (id) ON DELETE CASCADE,
    next_path     text NOT NULL CHECK (char_length(next_path) BETWEEN 1 AND 2048 AND next_path ~ '^/'),
    created_at    timestamptz NOT NULL,
    expires_at    timestamptz NOT NULL,
    CHECK ((purpose = 'stepup') = (session_hash IS NOT NULL AND user_id IS NOT NULL)),
    CHECK (expires_at > created_at AND expires_at <= created_at + interval '10 minutes')
);
CREATE INDEX oidc_login_states_expires ON oidc_login_states (expires_at);

GRANT SELECT, INSERT ON alerts TO alice_app;
GRANT SELECT, INSERT, UPDATE, DELETE ON setting_secrets, saved_views, oidc_providers, oidc_group_mappings TO alice_app;
GRANT SELECT, INSERT, DELETE ON oidc_login_states TO alice_app;

-- +goose Down
-- Correct only on a database without Phase 7 data, as 00010's. The Down refuses, with a clear message and
-- SQLSTATE Z1015, when a sent notice, a settings secret, a saved view, an identity provider or an SSO user exists;
-- nothing is changed then. Mail and alert settings in the settings table are left as they are.
-- +goose StatementBegin
DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM alerts) OR EXISTS (SELECT 1 FROM setting_secrets) OR EXISTS (SELECT 1 FROM saved_views)
            OR EXISTS (SELECT 1 FROM oidc_providers) OR EXISTS (SELECT 1 FROM users WHERE auth_source = 'oidc') THEN
        RAISE EXCEPTION 'cannot migrate down: Phase 7 data exists (sent notices, settings secrets, saved views, identity providers or SSO users); remove it first or restore a backup taken before 00011' USING ERRCODE = 'Z1015';
    END IF;
END $$;
-- +goose StatementEnd
DROP INDEX users_oidc_identity_unique;
ALTER TABLE users DROP CONSTRAINT users_oidc_not_local;
ALTER TABLE users DROP CONSTRAINT users_oidc_identity;
ALTER TABLE users DROP COLUMN oidc_subject;
ALTER TABLE users DROP COLUMN oidc_issuer;
ALTER TABLE users DROP COLUMN oidc_provider_id;
DROP TABLE oidc_login_states;
DROP TABLE oidc_group_mappings;
DROP TABLE oidc_providers;
DROP TABLE saved_views;
DROP TABLE setting_secrets;
DROP TABLE alerts;
