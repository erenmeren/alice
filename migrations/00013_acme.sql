-- +goose Up
-- ACME certificate issuance and renewal: certificate authorities (providers), their accounts, DNS-01 hooks, the certificates
-- Alice orders, every order, and the locations an issued certificate is deployed to. Plan: docs/superpowers/plans/2026-10-13-acme-issuance.md.
--
-- Secrets (the account key, the EAB HMAC key, a hook's bearer or HMAC secret, the key of an order in flight) are sealed
-- with the master key exactly as credentials are: ciphertext, nonce, wrapped DEK and key version, AAD
-- <table>/<row id>/<column prefix>. No plaintext column exists. No column default is a clock: the application passes the
-- time it decided on. Finished orders are history (SQLSTATE Z1017).

-- A certificate authority: an ACME directory, optionally with a CA bundle of its own (public certificates) and an
-- external account binding. The preset only pre-fills the form. allowed_suffixes is the name allow-list of the provider
-- (domain suffixes such as .corp.example.com; an empty list refuses every name, A9). Soft-deleted, never removed.
CREATE TABLE acme_providers (
    id                   uuid PRIMARY KEY,
    name                 citext NOT NULL CHECK (char_length(name::text) BETWEEN 1 AND 100),
    directory_url        text NOT NULL CHECK (directory_url ~ '^https://[^/@[:space:]]+(/|$)' AND char_length(directory_url) <= 2048),
    ca_bundle_pem        text NOT NULL DEFAULT '' CHECK (char_length(ca_bundle_pem) <= 262144),
    preset               text NOT NULL DEFAULT 'custom' CHECK (preset IN ('letsencrypt', 'letsencrypt_staging', 'zerossl', 'custom')),
    eab_kid              text NOT NULL DEFAULT '' CHECK (char_length(eab_kid) <= 255),
    eab_hmac_ct          bytea CHECK (octet_length(eab_hmac_ct) BETWEEN 1 AND 4096),
    eab_hmac_nonce       bytea CHECK (octet_length(eab_hmac_nonce) = 12),
    eab_hmac_wrapped_dek bytea CHECK (octet_length(eab_hmac_wrapped_dek) BETWEEN 1 AND 1024),
    eab_hmac_key_version integer CHECK (eab_hmac_key_version >= 1),
    allowed_suffixes     text[] NOT NULL DEFAULT '{}' CHECK (cardinality(allowed_suffixes) <= 100),
    created_by           uuid REFERENCES users (id),
    created_at           timestamptz NOT NULL,
    updated_at           timestamptz NOT NULL,
    deleted_at           timestamptz,
    -- an EAB key id and its sealed HMAC key come together or not at all
    CHECK ((eab_kid <> '') = (eab_hmac_ct IS NOT NULL)),
    CHECK ((eab_hmac_ct IS NULL) = (eab_hmac_nonce IS NULL) AND (eab_hmac_ct IS NULL) = (eab_hmac_wrapped_dek IS NULL)
           AND (eab_hmac_ct IS NULL) = (eab_hmac_key_version IS NULL))
);
CREATE UNIQUE INDEX acme_providers_name ON acme_providers (name) WHERE deleted_at IS NULL;

-- The account at a provider. One active account per provider; a key rollover (RFC 8555 7.3.5) first commits the new key as a
-- 'pending_rollover' row, then asks the CA, then flips active/retired in one transaction (A6). The sealed key is never
-- updated (AAD acme_accounts/<id>/key): a rollover is a new row. pending_since is the database time a pending key was
-- inserted: a recovery leaves a pending key alone while the CA call that may switch to it can still be in flight.
CREATE TABLE acme_accounts (
    id              uuid PRIMARY KEY,
    provider_id     uuid NOT NULL REFERENCES acme_providers (id),
    contact_email   text NOT NULL DEFAULT '' CHECK (char_length(contact_email) <= 254),
    account_url     text NOT NULL DEFAULT '' CHECK (char_length(account_url) <= 2048),
    tos_url         text NOT NULL DEFAULT '' CHECK (char_length(tos_url) <= 2048),
    tos_accepted_by uuid REFERENCES users (id),
    tos_accepted_at timestamptz,
    key_ct          bytea NOT NULL CHECK (octet_length(key_ct) BETWEEN 1 AND 4096),
    key_nonce       bytea NOT NULL CHECK (octet_length(key_nonce) = 12),
    key_wrapped_dek bytea NOT NULL CHECK (octet_length(key_wrapped_dek) BETWEEN 1 AND 1024),
    key_version     integer NOT NULL CHECK (key_version >= 1),
    state           text NOT NULL CHECK (state IN ('active', 'pending_rollover', 'retired', 'deactivated')),
    pending_since   timestamptz,
    created_by      uuid REFERENCES users (id),
    created_at      timestamptz NOT NULL,
    updated_at      timestamptz NOT NULL,
    CHECK (state <> 'pending_rollover' OR pending_since IS NOT NULL)
);
CREATE UNIQUE INDEX acme_accounts_one_active ON acme_accounts (provider_id) WHERE state = 'active';
CREATE UNIQUE INDEX acme_accounts_one_pending ON acme_accounts (provider_id) WHERE state = 'pending_rollover';
CREATE INDEX acme_accounts_provider ON acme_accounts (provider_id, created_at DESC, id DESC);

-- A rollover the CA did not take discards its pending key: the pending_rollover row is deleted. Every other account row
-- is history and is never deleted. SQLSTATE Z1018.
-- +goose StatementBegin
CREATE FUNCTION acme_accounts_protect_delete() RETURNS trigger LANGUAGE plpgsql
SET search_path = pg_catalog, pg_temp AS $$
BEGIN
    IF OLD.state <> 'pending_rollover' THEN
        RAISE EXCEPTION 'only a pending ACME account key can be deleted' USING ERRCODE = 'Z1018';
    END IF;
    RETURN OLD;
END $$;
-- +goose StatementEnd
CREATE TRIGGER acme_accounts_delete_pending_only BEFORE DELETE ON acme_accounts
    FOR EACH ROW EXECUTE FUNCTION acme_accounts_protect_delete();

-- The account states move one way: active -> retired | deactivated (a rollover, a directory change, a deactivation) and
-- pending_rollover -> active (a settled rollover). A pending key is only ever INSERTED as pending (so no row can be made
-- deletable by an UPDATE), and retired and deactivated are final. SQLSTATE Z1019.
-- +goose StatementBegin
CREATE FUNCTION acme_accounts_protect_state() RETURNS trigger LANGUAGE plpgsql
SET search_path = pg_catalog, pg_temp AS $$
BEGIN
    IF NEW.state IS DISTINCT FROM OLD.state
       AND NOT ((OLD.state = 'active' AND NEW.state IN ('retired', 'deactivated'))
                OR (OLD.state = 'pending_rollover' AND NEW.state = 'active')) THEN
        RAISE EXCEPTION 'this ACME account state change is not allowed' USING ERRCODE = 'Z1019';
    END IF;
    RETURN NEW;
END $$;
-- +goose StatementEnd
CREATE TRIGGER acme_accounts_state_forward_only BEFORE UPDATE ON acme_accounts
    FOR EACH ROW EXECUTE FUNCTION acme_accounts_protect_state();

-- A DNS-01 hook: an HTTPS endpoint Alice calls to publish and remove a challenge record. The secret (sent both as the bearer
-- token and as the HMAC key of X-Alice-Signature; the endpoint checks either) is sealed (AAD acme_hooks/<id>/secret). allowed_suffixes as the provider's (A9).
-- propagation_wait_seconds (0 = no wait) and poll_timeout_seconds bound the hook solver's waits (dns01 limits 120 s and
-- 100 s); together they stay within the ACME client's 120 s call budget the challenge is published under.
CREATE TABLE acme_hooks (
    id                 uuid PRIMARY KEY,
    name               citext NOT NULL CHECK (char_length(name::text) BETWEEN 1 AND 100),
    url                text NOT NULL CHECK (url ~ '^https://[^/@[:space:]]+(/|$)' AND char_length(url) <= 2048),
    ca_bundle_pem      text NOT NULL DEFAULT '' CHECK (char_length(ca_bundle_pem) <= 262144),
    secret_ct          bytea NOT NULL CHECK (octet_length(secret_ct) BETWEEN 1 AND 4096),
    secret_nonce       bytea NOT NULL CHECK (octet_length(secret_nonce) = 12),
    secret_wrapped_dek bytea NOT NULL CHECK (octet_length(secret_wrapped_dek) BETWEEN 1 AND 1024),
    secret_key_version integer NOT NULL CHECK (secret_key_version >= 1),
    allowed_suffixes   text[] NOT NULL DEFAULT '{}' CHECK (cardinality(allowed_suffixes) <= 100),
    propagation_wait_seconds integer NOT NULL DEFAULT 5 CHECK (propagation_wait_seconds BETWEEN 0 AND 120),
    poll_timeout_seconds     integer NOT NULL DEFAULT 60 CHECK (poll_timeout_seconds BETWEEN 1 AND 100),
    created_by         uuid REFERENCES users (id),
    created_at         timestamptz NOT NULL,
    updated_at         timestamptz NOT NULL,
    deleted_at         timestamptz,
    CHECK (propagation_wait_seconds + poll_timeout_seconds <= 120)
);
CREATE UNIQUE INDEX acme_hooks_name ON acme_hooks (name) WHERE deleted_at IS NULL;

-- The ordered identity: names, key policy, proof method and renewal window. current_certificate_id is the leaf of the
-- last successful order (a normal certificates row with source 'acme'). Soft-deleted, never removed (orders refer to it).
-- A DNS-01 certificate publishes through its hook; an HTTP-01 certificate through the managed Nginx server its names
-- point at (http_target_id: that server's helper writes the token file), and only an HTTP-01 one has such a server.
CREATE TABLE acme_certificates (
    id                     uuid PRIMARY KEY,
    provider_id            uuid NOT NULL REFERENCES acme_providers (id),
    account_id             uuid NOT NULL REFERENCES acme_accounts (id),
    names                  text[] NOT NULL CHECK (cardinality(names) BETWEEN 1 AND 100),
    key_type               text NOT NULL CHECK (key_type IN ('ecdsa_p256', 'ecdsa_p384', 'rsa_2048', 'rsa_3072', 'rsa_4096')),
    challenge              text NOT NULL CHECK (challenge IN ('dns01', 'http01')),
    hook_id                uuid REFERENCES acme_hooks (id),
    http_target_id         uuid REFERENCES targets (id),
    renew_before_days      integer NOT NULL DEFAULT 30 CHECK (renew_before_days BETWEEN 1 AND 60),
    auto_renew             boolean NOT NULL DEFAULT true,
    auto_deploy            boolean NOT NULL DEFAULT false,
    state                  text NOT NULL DEFAULT 'pending' CHECK (state IN ('pending', 'issuing', 'active', 'failing', 'stopped')),
    current_certificate_id uuid REFERENCES certificates (id),
    failures               integer NOT NULL DEFAULT 0 CHECK (failures >= 0),
    next_attempt_at        timestamptz,
    last_attempt_at        timestamptz,
    last_error_code        text NOT NULL DEFAULT '' CHECK (last_error_code ~ '^[A-Za-z0-9._-]{0,100}$'),
    created_by             uuid REFERENCES users (id),
    created_at             timestamptz NOT NULL,
    updated_at             timestamptz NOT NULL,
    deleted_at             timestamptz,
    CHECK (challenge <> 'dns01' OR hook_id IS NOT NULL),
    CHECK ((challenge = 'http01') = (http_target_id IS NOT NULL))
);
CREATE INDEX acme_certificates_provider ON acme_certificates (provider_id);
CREATE INDEX acme_certificates_account ON acme_certificates (account_id);
CREATE INDEX acme_certificates_hook ON acme_certificates (hook_id) WHERE hook_id IS NOT NULL;
CREATE INDEX acme_certificates_http_target ON acme_certificates (http_target_id) WHERE http_target_id IS NOT NULL;
CREATE INDEX acme_certificates_current ON acme_certificates (current_certificate_id) WHERE current_certificate_id IS NOT NULL;
CREATE INDEX acme_certificates_due ON acme_certificates (next_attempt_at, id) WHERE auto_renew AND deleted_at IS NULL;

-- One order (an issue or a test run) of an ACME certificate. Append-only once finished. While it runs it holds, in
-- deletable columns, the sealed private key of the certificate being ordered (pending_key_*, AAD
-- acme_orders/<id>/pending_key; A8: moved to managed_private_keys with the certificates row in one transaction on success,
-- deleted on failure) and the challenge records it presented (presented, A12: DNS records and token files the cleanup job removes;
-- cleanup_at and cleanup_error_code are the last cleanup attempt and its failure, '' when it removed everything).
CREATE TABLE acme_orders (
    id                      uuid PRIMARY KEY,
    acme_certificate_id     uuid NOT NULL REFERENCES acme_certificates (id),
    kind                    text NOT NULL CHECK (kind IN ('issue', 'test')),
    state                   text NOT NULL DEFAULT 'running' CHECK (state IN ('running', 'succeeded', 'failed')),
    started_at              timestamptz NOT NULL,
    finished_at             timestamptz,
    error_code              text NOT NULL DEFAULT '' CHECK (error_code ~ '^[A-Za-z0-9._-]{0,100}$'),
    order_url               text NOT NULL DEFAULT '' CHECK (char_length(order_url) <= 2048),
    certificate_id          uuid REFERENCES certificates (id),
    requested_by            uuid REFERENCES users (id),
    pending_key_ct          bytea CHECK (octet_length(pending_key_ct) BETWEEN 1 AND 300000),
    pending_key_nonce       bytea CHECK (octet_length(pending_key_nonce) = 12),
    pending_key_wrapped_dek bytea CHECK (octet_length(pending_key_wrapped_dek) BETWEEN 1 AND 1024),
    pending_key_version     integer CHECK (pending_key_version >= 1),
    presented               jsonb NOT NULL DEFAULT '[]' CHECK (jsonb_typeof(presented) = 'array' AND octet_length(presented::text) <= 65536),
    cleanup_at              timestamptz,
    cleanup_error_code      text NOT NULL DEFAULT '' CHECK (cleanup_error_code ~ '^[A-Za-z0-9._-]{0,100}$'),
    CHECK ((state = 'running') = (finished_at IS NULL)),
    CHECK ((pending_key_ct IS NULL) = (pending_key_nonce IS NULL) AND (pending_key_ct IS NULL) = (pending_key_wrapped_dek IS NULL)
           AND (pending_key_ct IS NULL) = (pending_key_version IS NULL))
);
-- At most one order in flight per ACME certificate: a second acme.issue finds the first.
CREATE UNIQUE INDEX acme_orders_one_running ON acme_orders (acme_certificate_id) WHERE state = 'running';
CREATE INDEX acme_orders_certificate ON acme_orders (acme_certificate_id, started_at DESC, id DESC);
CREATE INDEX acme_orders_issued ON acme_orders (certificate_id) WHERE certificate_id IS NOT NULL;
CREATE INDEX acme_orders_presented ON acme_orders (finished_at) WHERE presented <> '[]'::jsonb; -- the cleanup sweep

-- A finished order is history: nothing changes except the pending key going to NULL (all four columns together by the CHECK),
-- the presented list shrinking as the cleanup job removes the records (every element left is an element it had, whole;
-- never a new or a changed one), and the cleanup job's last
-- attempt (cleanup_at, cleanup_error_code). SQLSTATE Z1017.
-- +goose StatementBegin
CREATE FUNCTION acme_orders_protect_done() RETURNS trigger LANGUAGE plpgsql
SET search_path = pg_catalog, pg_temp AS $$
BEGIN
    IF OLD.state <> 'running' THEN
        IF (to_jsonb(NEW) - 'pending_key_ct' - 'pending_key_nonce' - 'pending_key_wrapped_dek' - 'pending_key_version' - 'presented'
                - 'cleanup_at' - 'cleanup_error_code')
                IS DISTINCT FROM (to_jsonb(OLD) - 'pending_key_ct' - 'pending_key_nonce' - 'pending_key_wrapped_dek' - 'pending_key_version' - 'presented'
                - 'cleanup_at' - 'cleanup_error_code')
           OR (NEW.pending_key_ct IS NOT NULL AND NEW.pending_key_ct IS DISTINCT FROM OLD.pending_key_ct)
           OR EXISTS (SELECT 1 FROM jsonb_array_elements(NEW.presented) AS n(e)
                      WHERE NOT EXISTS (SELECT 1 FROM jsonb_array_elements(OLD.presented) AS o(e) WHERE o.e = n.e)) THEN
            RAISE EXCEPTION 'a finished ACME order cannot be changed' USING ERRCODE = 'Z1017';
        END IF;
    END IF;
    RETURN NEW;
END $$;
-- +goose StatementEnd
CREATE TRIGGER acme_orders_done_frozen BEFORE UPDATE ON acme_orders
    FOR EACH ROW EXECUTE FUNCTION acme_orders_protect_done();

-- The locations an ACME certificate is deployed to; auto_deploy per location. A binding is removed with DELETE.
CREATE TABLE acme_bindings (
    acme_certificate_id uuid NOT NULL REFERENCES acme_certificates (id),
    location_id         uuid NOT NULL REFERENCES certificate_locations (id),
    auto_deploy         boolean NOT NULL DEFAULT false,
    created_by          uuid REFERENCES users (id),
    created_at          timestamptz NOT NULL,
    PRIMARY KEY (acme_certificate_id, location_id)
);
CREATE INDEX acme_bindings_location ON acme_bindings (location_id);

-- Certificates and deployments gain the ACME values. certificates_check_key (Z1001, Z1002, Z1004) already applies to an
-- INSERT with source 'acme' and refuses any later change of the source.
ALTER TABLE certificates DROP CONSTRAINT certificates_source_check;
ALTER TABLE certificates ADD CONSTRAINT certificates_source_check CHECK (source IN ('discovered', 'uploaded', 'csr', 'azure_kv', 'acme'));
ALTER TABLE deployments DROP CONSTRAINT deployments_trigger_check;
ALTER TABLE deployments ADD CONSTRAINT deployments_trigger_check CHECK (trigger IN ('manual', 'kv_renewal', 'retry', 'acme_renewal'));

-- Grants (pattern 00006): providers, hooks and certificates are soft-deleted and never removed; an account row is removed
-- only while it is a pending rollover key the CA did not take (Z1018), its state only moves forward (Z1019), and its sealed
-- key and pending_since never change (a rollover is a new row); orders are history (no DELETE; the freeze trigger above);
-- a binding is added and removed.
GRANT SELECT, INSERT ON acme_providers, acme_accounts, acme_hooks, acme_certificates, acme_orders TO alice_app;
GRANT SELECT, INSERT, DELETE ON acme_bindings TO alice_app;
GRANT DELETE ON acme_accounts TO alice_app; -- pending_rollover rows only (the trigger above, Z1018)
GRANT UPDATE (name, directory_url, ca_bundle_pem, preset, eab_kid, eab_hmac_ct, eab_hmac_nonce, eab_hmac_wrapped_dek, eab_hmac_key_version,
    allowed_suffixes, updated_at, deleted_at) ON acme_providers TO alice_app;
GRANT UPDATE (contact_email, account_url, tos_url, tos_accepted_by, tos_accepted_at, state, updated_at) ON acme_accounts TO alice_app;
GRANT UPDATE (name, url, ca_bundle_pem, secret_ct, secret_nonce, secret_wrapped_dek, secret_key_version, allowed_suffixes,
    propagation_wait_seconds, poll_timeout_seconds, updated_at, deleted_at) ON acme_hooks TO alice_app;
GRANT UPDATE (provider_id, account_id, names, key_type, challenge, hook_id, http_target_id, renew_before_days, auto_renew, auto_deploy, state, current_certificate_id,
    failures, next_attempt_at, last_attempt_at, last_error_code, updated_at, deleted_at) ON acme_certificates TO alice_app;
GRANT UPDATE (state, finished_at, error_code, order_url, certificate_id, pending_key_ct, pending_key_nonce, pending_key_wrapped_dek,
    pending_key_version, presented, cleanup_at, cleanup_error_code) ON acme_orders TO alice_app;
GRANT UPDATE (auto_deploy) ON acme_bindings TO alice_app;

-- +goose Down
-- Re-map what the CHECKs of 00006 would refuse before they are restored (A4): an ACME certificate keeps its sealed key and
-- becomes an uploaded one, an ACME renewal deployment becomes a retry. The two history triggers are switched off for these
-- updates only (the Down runs as the table owner, in one transaction). The ACME tables and their data are dropped.
ALTER TABLE certificates DISABLE TRIGGER certificates_key_check;
UPDATE certificates SET source = 'uploaded' WHERE source = 'acme';
ALTER TABLE certificates ENABLE TRIGGER certificates_key_check;
ALTER TABLE deployments DISABLE TRIGGER deployments_done_frozen;
UPDATE deployments SET trigger = 'retry' WHERE trigger = 'acme_renewal';
ALTER TABLE deployments ENABLE TRIGGER deployments_done_frozen;
ALTER TABLE certificates DROP CONSTRAINT certificates_source_check;
ALTER TABLE certificates ADD CONSTRAINT certificates_source_check CHECK (source IN ('discovered', 'uploaded', 'csr', 'azure_kv'));
ALTER TABLE deployments DROP CONSTRAINT deployments_trigger_check;
ALTER TABLE deployments ADD CONSTRAINT deployments_trigger_check CHECK (trigger IN ('manual', 'kv_renewal', 'retry'));
DROP TABLE acme_bindings;
DROP TRIGGER acme_orders_done_frozen ON acme_orders;
DROP FUNCTION acme_orders_protect_done();
DROP TABLE acme_orders;
DROP TABLE acme_certificates;
DROP TABLE acme_hooks;
DROP TABLE acme_accounts;
DROP FUNCTION acme_accounts_protect_delete();
DROP FUNCTION acme_accounts_protect_state();
DROP TABLE acme_providers;
