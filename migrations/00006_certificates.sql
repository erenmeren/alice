-- +goose Up
-- Phase 4: certificates, Nginx certificate locations, private keys held by Alice, signing requests,
-- deployments and their steps (spec §7.2–§7.4, §12; R38).
--
-- Enumerations: values the application owns (owner, algorithm, source, trigger, state, status,
-- result, phase, verified, step status) are closed lists; vocabularies a newer helper may extend
-- (unsupported reasons, file problems, warning codes, step names, error classes) are format checks
-- (lower-case snake identifiers of bounded length), so an unknown value from a newer helper is
-- stored instead of failing the INSERT. jsonb columns are objects or arrays of bounded size.
-- No column default is a clock: the application passes the time it decided on.

-- Private keys uploaded into Alice or generated for a signing request (spec §7.2). Envelope
-- columns as credentials (AAD managed_private_keys/<id>/ciphertext); there is no plaintext column,
-- and the application can neither update nor delete a row.
CREATE TABLE managed_private_keys (
    id                uuid PRIMARY KEY,
    owner_type        text NOT NULL CHECK (owner_type IN ('certificate', 'csr')),
    algorithm         text NOT NULL CHECK (algorithm IN ('rsa', 'ecdsa')),
    -- RSA from 2048 bits (any size above: uploads have no upper bound), ECDSA P-256 or P-384
    bits              integer NOT NULL,
    public_key_sha256 text NOT NULL CHECK (public_key_sha256 ~ '^[0-9a-f]{64}$'), -- not unique: a renewal may reuse a key
    ciphertext        bytea NOT NULL CHECK (octet_length(ciphertext) BETWEEN 1 AND 300000),
    nonce             bytea NOT NULL CHECK (octet_length(nonce) = 12),
    wrapped_dek       bytea NOT NULL CHECK (octet_length(wrapped_dek) BETWEEN 1 AND 1024),
    key_version       integer NOT NULL CHECK (key_version >= 1),
    created_by        uuid REFERENCES users (id),
    created_at        timestamptz NOT NULL,
    CHECK ((algorithm = 'rsa' AND bits >= 2048) OR (algorithm = 'ecdsa' AND bits IN (256, 384)))
);

CREATE INDEX managed_private_keys_public_key ON managed_private_keys (public_key_sha256);

CREATE TABLE certificates (
    id                 uuid PRIMARY KEY,
    fingerprint_sha256 text NOT NULL UNIQUE CHECK (fingerprint_sha256 ~ '^[0-9a-f]{64}$'), -- SHA-256 of the leaf DER
    subject_cn         text NOT NULL DEFAULT '',
    subject            text NOT NULL DEFAULT '',
    issuer             text NOT NULL DEFAULT '',
    serial             text NOT NULL DEFAULT '',
    sans               text[] NOT NULL DEFAULT '{}',
    not_before         timestamptz NOT NULL,
    not_after          timestamptz NOT NULL,
    key_algorithm      text NOT NULL CHECK (key_algorithm IN ('rsa', 'ecdsa', 'ed25519', 'other')),
    key_bits           integer NOT NULL DEFAULT 0 CHECK (key_bits >= 0),
    public_key_sha256  text NOT NULL CHECK (public_key_sha256 ~ '^[0-9a-f]{64}$'),
    -- leaf first, then the chain; public. Updatable (a better chain), and nothing here ties its first
    -- block to fingerprint_sha256: the provider refuses a deployment whose leaf differs.
    pem_chain          text NOT NULL CHECK (char_length(pem_chain) <= 1048576),
    chain_complete     boolean NOT NULL DEFAULT false,
    self_signed        boolean NOT NULL DEFAULT false,
    source             text NOT NULL CHECK (source IN ('discovered', 'uploaded', 'csr', 'azure_kv')),
    label              text NOT NULL DEFAULT '' CHECK (char_length(label) <= 100),
    private_key_id     uuid UNIQUE REFERENCES managed_private_keys (id),
    first_seen_at      timestamptz NOT NULL,
    last_seen_at       timestamptz NOT NULL,
    created_by         uuid REFERENCES users (id),
    created_at         timestamptz NOT NULL
);
CREATE INDEX certificates_not_after ON certificates (not_after, id);
CREATE INDEX certificates_sans ON certificates USING gin (sans);
CREATE INDEX certificates_public_key ON certificates (public_key_sha256);

-- A certificate's private key is the key of that certificate, whoever writes the row, and a key
-- once attached is never replaced or detached (uploading the key of a discovered certificate is the
-- only update of private_key_id: NULL to a key whose public key hash equals the certificate's).
-- SQLSTATEs: Z1001 the key does not belong to the certificate, Z1002 a key is already attached
-- (class Z1, Alice's own: the SQL standard reserves classes beginning 0-4 and A-H, implementation-
-- defined classes begin 5-9 or I-Z; Z1003 is the frozen deployment below, also raised for a new step of
-- a finished deployment).
-- It runs as the invoking role (alice_app can read managed_private_keys), so every name is
-- schema-qualified and the search path is pinned with pg_temp last.
-- +goose StatementBegin
CREATE FUNCTION certificates_check_key() RETURNS trigger LANGUAGE plpgsql
SET search_path = pg_catalog, pg_temp AS $$
BEGIN
    IF TG_OP = 'UPDATE' AND OLD.private_key_id IS NOT NULL AND NEW.private_key_id IS DISTINCT FROM OLD.private_key_id THEN
        RAISE EXCEPTION 'the private key of a certificate cannot be replaced or detached' USING ERRCODE = 'Z1002';
    END IF;
    IF NEW.private_key_id IS NOT NULL AND (TG_OP = 'INSERT' OR NEW.private_key_id IS DISTINCT FROM OLD.private_key_id) THEN
        IF NOT EXISTS (SELECT 1 FROM public.managed_private_keys k
                       WHERE k.id = NEW.private_key_id AND k.public_key_sha256 = NEW.public_key_sha256) THEN
            RAISE EXCEPTION 'the private key does not belong to the certificate' USING ERRCODE = 'Z1001';
        END IF;
    END IF;
    RETURN NEW;
END $$;
-- +goose StatementEnd
CREATE TRIGGER certificates_key_check BEFORE INSERT OR UPDATE OF private_key_id, public_key_sha256 ON certificates
    FOR EACH ROW EXECUTE FUNCTION certificates_check_key();

CREATE TABLE csr_requests (
    id             uuid PRIMARY KEY,
    private_key_id uuid NOT NULL UNIQUE REFERENCES managed_private_keys (id),
    -- the X.509 bound of a common name (ub-common-name); the application refuses longer names
    common_name    text NOT NULL CHECK (char_length(common_name) BETWEEN 1 AND 64),
    sans           text[] NOT NULL DEFAULT '{}' CHECK (cardinality(sans) <= 100),
    csr_pem        text NOT NULL CHECK (char_length(csr_pem) <= 65536),
    status         text NOT NULL CHECK (status IN ('pending', 'completed', 'cancelled')),
    certificate_id uuid REFERENCES certificates (id),
    created_by     uuid REFERENCES users (id),
    created_at     timestamptz NOT NULL,
    finished_at    timestamptz,
    CHECK ((status = 'completed') = (certificate_id IS NOT NULL)),
    CHECK ((status <> 'pending') = (finished_at IS NOT NULL))
);

-- One row per certificate file an Nginx target uses (spec §7.3, §12.4 step 6: a file shared by
-- several server blocks is one location; its server blocks are in servers). A path the helper
-- refused is stored as the provider shows it, strconv.QuoteToASCII of its first 4096 bytes: at most
-- 4*4096+2 = 16386 characters (an invalid byte becomes \xNN), so cert_path and key_path allow 16400.
-- Such a location is unsupported and its path is never sent back; deployments.cert_path and
-- key_path are the strict ones. Uniqueness and lookups use the hash of the path (below): a btree
-- entry on the raw text fails for incompressible values of 2.7 KB and more.
CREATE TABLE certificate_locations (
    id                   uuid PRIMARY KEY,
    target_id            uuid NOT NULL REFERENCES targets (id),
    kind                 text NOT NULL CHECK (kind IN ('nginx_file')),
    cert_path            text NOT NULL CHECK (char_length(cert_path) BETWEEN 1 AND 16400),
    key_path             text NOT NULL DEFAULT '' CHECK (char_length(key_path) <= 16400),
    resolved_cert_path   text NOT NULL DEFAULT '' CHECK (char_length(resolved_cert_path) <= 4096), -- the file a symlink leads to
    certificate_id       uuid REFERENCES certificates (id),       -- NULL: no readable certificate in the file
    key_type             text NOT NULL DEFAULT '' CHECK (key_type IN ('', 'rsa', 'ecdsa')),
    servers              jsonb NOT NULL DEFAULT '[]' CHECK (jsonb_typeof(servers) = 'array' AND octet_length(servers::text) <= 33554432), -- providers.CertServer list; 32 MiB: the helper's whole answer is capped at 16 MiB
    supported            boolean NOT NULL,
    unsupported_reason   text NOT NULL DEFAULT '' CHECK (unsupported_reason ~ '^([a-z][a-z_]{0,39})?$'),
    problem              text NOT NULL DEFAULT '' CHECK (problem ~ '^([a-z][a-z_]{0,39})?$'),
    key_problem          text NOT NULL DEFAULT '' CHECK (key_problem ~ '^([a-z][a-z_]{0,39})?$'),
    inherited            boolean NOT NULL DEFAULT false,
    custom_location      boolean NOT NULL DEFAULT false,
    symlinked            boolean NOT NULL DEFAULT false,
    cert_file_sha256     text NOT NULL DEFAULT '' CHECK (cert_file_sha256 ~ '^([0-9a-f]{64})?$'), -- the helper's hash of the file's bytes: the deploy compare-and-swap value, not a certificate fingerprint
    key_exists           boolean NOT NULL DEFAULT false,
    key_mode             text NOT NULL DEFAULT '' CHECK (key_mode ~ '^(0?[0-7]{3,4})?$'),
    key_owner            text NOT NULL DEFAULT '' CHECK (char_length(key_owner) <= 64),
    key_group            text NOT NULL DEFAULT '' CHECK (char_length(key_group) <= 64),
    warnings             text[] NOT NULL DEFAULT '{}' CHECK (cardinality(warnings) <= 32 AND array_position(warnings, NULL) IS NULL
                             AND array_to_string(warnings, ',') ~ '^([a-z][a-z_]{0,39}(,[a-z][a-z_]{0,39})*)?$'
                             AND cardinality(string_to_array(array_to_string(warnings, ','), ',')) = cardinality(warnings)),
    deployed_fingerprint text NOT NULL DEFAULT '' CHECK (deployed_fingerprint ~ '^([0-9a-f]{64})?$'), -- the leaf Alice last deployed here
    changed_outside_at   timestamptz,
    verify_port          integer CHECK (verify_port BETWEEN 1 AND 65535),
    verify_sni           text CHECK (verify_sni ~ '^[a-z0-9._-]{1,253}$'),
    skip_verify          boolean NOT NULL DEFAULT false,
    first_seen_at        timestamptz NOT NULL,
    last_seen_at         timestamptz NOT NULL,
    missing_since        timestamptz,
    version              integer NOT NULL DEFAULT 1 CHECK (version >= 1),
    CHECK (NOT supported OR unsupported_reason = '')
);
-- One location per target, kind and certificate path, by the SHA-256 of the path's UTF-8 bytes
-- (convert_to is only STABLE, so the immutable wrapper below is what an index may call; the
-- database encoding is fixed, so the conversion is deterministic). The conflict target and every
-- lookup by path write the same expression:
--   ON CONFLICT (target_id, kind, certificate_location_path_hash(cert_path))
--   WHERE target_id = $1 AND kind = $2 AND certificate_location_path_hash(cert_path) = certificate_location_path_hash($3)
--         AND cert_path = $3
-- +goose StatementBegin
CREATE FUNCTION certificate_location_path_hash(p text) RETURNS bytea LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
SET search_path = pg_catalog, pg_temp
RETURN sha256(convert_to(p, 'UTF8'));
-- +goose StatementEnd
CREATE UNIQUE INDEX certificate_locations_path ON certificate_locations (target_id, kind, certificate_location_path_hash(cert_path));
CREATE INDEX certificate_locations_certificate ON certificate_locations (certificate_id);

-- One deployment of one certificate to one location (spec §7.4). Its id is also the helper's
-- operation id (backups in /var/lib/alice-helper/backups/<id>); operation_id records the id
-- actually sent, before the first send.
CREATE TABLE deployments (
    id                   uuid PRIMARY KEY,
    certificate_id       uuid NOT NULL REFERENCES certificates (id),
    location_id          uuid NOT NULL REFERENCES certificate_locations (id),
    target_id            uuid NOT NULL REFERENCES targets (id),
    job_id               uuid REFERENCES jobs (id) ON DELETE SET NULL,
    trigger              text NOT NULL CHECK (trigger IN ('manual', 'kv_renewal', 'retry')),
    requested_by         uuid REFERENCES users (id),
    state                text NOT NULL CHECK (state IN ('queued', 'precheck', 'deploying', 'recovering', 'done')),
    status               text NOT NULL CHECK (status IN ('pending', 'running', 'succeeded', 'unchanged', 'failed',
                                                         'rolled_back', 'rollback_failed', 'needs_attention')),
    -- providers.DeployResult as last known; 'uncertain' while the outcome is being recovered
    result               text NOT NULL DEFAULT '' CHECK (result IN ('', 'committed', 'unchanged', 'no_change', 'rolled_back',
                                                                   'rollback_failed', 'uncertain')),
    -- the helper journal phase (providers.Phase*) of the last answer, '' when none
    phase                text NOT NULL DEFAULT '' CHECK (phase IN ('', 'none', 'prepared', 'writing', 'committed', 'unchanged',
                                                                   'restoring', 'restored', 'restore_failed')),
    operation_id         uuid UNIQUE,
    new_fingerprint      text NOT NULL CHECK (new_fingerprint ~ '^[0-9a-f]{64}$'),
    new_chain_length     integer NOT NULL DEFAULT 0 CHECK (new_chain_length >= 0), -- 0: not recorded yet; the engine records it before the first send
    previous_fingerprint text NOT NULL DEFAULT '' CHECK (previous_fingerprint ~ '^([0-9a-f]{64})?$'),
    previous_chain_length integer NOT NULL DEFAULT 0 CHECK (previous_chain_length >= 0), -- 0: not compared
    expect_cert_sha256   text NOT NULL DEFAULT '' CHECK (expect_cert_sha256 ~ '^([0-9a-f]{64})?$'), -- the file hash the deployment expects to replace; recorded before the first send
    cert_path            text NOT NULL CHECK (cert_path ~ '^/[A-Za-z0-9._/@:+-]+$' AND char_length(cert_path) <= 4096),
    key_path             text NOT NULL CHECK (key_path ~ '^/[A-Za-z0-9._/@:+-]+$' AND char_length(key_path) <= 4096),
    confirm_incomplete_chain boolean NOT NULL DEFAULT false,
    rollback_info        jsonb CHECK (jsonb_typeof(rollback_info) = 'object' AND octet_length(rollback_info::text) <= 4096), -- providers.BackupRef, written before the first change
    verified             text NOT NULL DEFAULT '' CHECK (verified IN ('', 'remote', 'local', 'skipped')),
    error_code           text NOT NULL DEFAULT '' CHECK (error_code ~ '^[A-Za-z0-9._-]{0,100}$'),
    error_params         jsonb NOT NULL DEFAULT '{}' CHECK (jsonb_typeof(error_params) = 'object' AND octet_length(error_params::text) <= 4096),
    failed_step          text NOT NULL DEFAULT '' CHECK (failed_step ~ '^([a-z][a-z_]{0,39})?$'),
    cause_step           text NOT NULL DEFAULT '' CHECK (cause_step ~ '^([a-z][a-z_]{0,39})?$'),
    helper_error         text NOT NULL DEFAULT '' CHECK (helper_error ~ '^([a-z][a-z_]{0,39})?$'), -- the helper's error class (a ConfigErr* value, file_changed) or ''
    -- the verification failure that preceded an uncertain outcome (its reason and the port probed)
    verify_failed_reason text NOT NULL DEFAULT '' CHECK (verify_failed_reason ~ '^[A-Za-z0-9._-]{0,100}$'),
    verify_failed_port   integer CHECK (verify_failed_port BETWEEN 1 AND 65535),
    recover_after        timestamptz,
    recovery_attempts    integer NOT NULL DEFAULT 0 CHECK (recovery_attempts >= 0),
    created_at           timestamptz NOT NULL,
    started_at           timestamptz,
    finished_at          timestamptz,
    CHECK ((state = 'done') = (finished_at IS NOT NULL)),
    CHECK ((state = 'done') = (status NOT IN ('pending', 'running', 'needs_attention')))
);
CREATE UNIQUE INDEX deployments_one_active ON deployments (location_id) WHERE state <> 'done';
CREATE INDEX deployments_target ON deployments (target_id, created_at DESC, id DESC);
CREATE INDEX deployments_location ON deployments (location_id, created_at DESC, id DESC);
CREATE INDEX deployments_job ON deployments (job_id) WHERE job_id IS NOT NULL; -- the foreign key of a pruned job
CREATE INDEX deployments_certificate ON deployments (certificate_id, created_at DESC, id DESC);
CREATE INDEX deployments_created ON deployments (created_at DESC, id DESC);
CREATE INDEX deployments_unfinished ON deployments (recover_after) WHERE state IN ('deploying', 'recovering');

-- A finished deployment is history: nothing changes except job_id going to NULL (the foreign key's
-- ON DELETE SET NULL when maintenance.cleanup prunes the job; it runs as the table owner and passes
-- through this trigger). Everything the engine sends or learns (expect_cert_sha256, chain lengths,
-- operation_id, previous_fingerprint, result, error fields) is written before or with the update
-- that makes the row done. SQLSTATE Z1003.
-- +goose StatementBegin
CREATE FUNCTION deployments_protect_done() RETURNS trigger LANGUAGE plpgsql
SET search_path = pg_catalog, pg_temp AS $$
BEGIN
    IF OLD.state = 'done' AND ((to_jsonb(NEW) - 'job_id') IS DISTINCT FROM (to_jsonb(OLD) - 'job_id')
            OR (NEW.job_id IS NOT NULL AND NEW.job_id IS DISTINCT FROM OLD.job_id)) THEN
        RAISE EXCEPTION 'a finished deployment cannot be changed' USING ERRCODE = 'Z1003';
    END IF;
    RETURN NEW;
END $$;
-- +goose StatementEnd
CREATE TRIGGER deployments_done_frozen BEFORE UPDATE ON deployments
    FOR EACH ROW EXECUTE FUNCTION deployments_protect_done();

-- Append-only step events (R38 item 7): one row per started/ok/failed/skipped.
CREATE TABLE deployment_steps (
    id            uuid PRIMARY KEY,
    deployment_id uuid NOT NULL REFERENCES deployments (id) ON DELETE CASCADE,
    n             integer NOT NULL CHECK (n >= 1),
    name          text NOT NULL CHECK (name ~ '^[a-z][a-z_]{0,39}$'),
    status        text NOT NULL CHECK (status IN ('started', 'ok', 'failed', 'skipped')),
    at            timestamptz NOT NULL,
    params        jsonb NOT NULL DEFAULT '{}' CHECK (jsonb_typeof(params) = 'object' AND octet_length(params::text) <= 4096),
    UNIQUE (deployment_id, n)
);

-- A finished deployment gets no new step either (its history is final; SQLSTATE Z1003, as an update
-- of it). The parent row is read FOR SHARE: an insert that races the update finishing the
-- deployment waits for it and then sees it done. It runs as the invoking role (alice_app may lock
-- deployments rows: it has column UPDATE grants), so names are schema-qualified and the search path
-- pinned, as certificates_check_key.
-- +goose StatementBegin
CREATE FUNCTION deployment_steps_check_open() RETURNS trigger LANGUAGE plpgsql
SET search_path = pg_catalog, pg_temp AS $$
BEGIN
    IF EXISTS (SELECT 1 FROM public.deployments d WHERE d.id = NEW.deployment_id AND d.state = 'done' FOR SHARE OF d) THEN
        RAISE EXCEPTION 'a finished deployment cannot get new steps' USING ERRCODE = 'Z1003';
    END IF;
    RETURN NEW;
END $$;
-- +goose StatementEnd
CREATE TRIGGER deployment_steps_open BEFORE INSERT ON deployment_steps
    FOR EACH ROW EXECUTE FUNCTION deployment_steps_check_open();

-- Keys and steps are append-only for the application; certificates, locations, signing requests
-- and deployments are never deleted (history) and are updated only in the columns listed.
GRANT SELECT, INSERT ON managed_private_keys, certificates, csr_requests, certificate_locations, deployments,
    deployment_steps TO alice_app;
GRANT UPDATE (label, private_key_id, last_seen_at, pem_chain, chain_complete) ON certificates TO alice_app;
GRANT UPDATE (status, certificate_id, finished_at) ON csr_requests TO alice_app;
GRANT UPDATE (key_path, resolved_cert_path, certificate_id, key_type, servers, supported, unsupported_reason, problem,
    key_problem, inherited, custom_location, symlinked, cert_file_sha256, key_exists, key_mode, key_owner, key_group,
    warnings, deployed_fingerprint, changed_outside_at, verify_port, verify_sni, skip_verify, last_seen_at,
    missing_since, version)
    ON certificate_locations TO alice_app;
GRANT UPDATE (job_id, state, status, result, phase, operation_id, new_chain_length, expect_cert_sha256,
    previous_fingerprint, previous_chain_length, rollback_info, verified, error_code, error_params, failed_step, cause_step, helper_error, verify_failed_reason,
    verify_failed_port, recover_after, recovery_attempts, started_at, finished_at) ON deployments TO alice_app;

-- +goose Down
DROP TABLE deployment_steps;
DROP FUNCTION deployment_steps_check_open();
DROP TABLE deployments;
DROP FUNCTION deployments_protect_done();
DROP TABLE certificate_locations;
DROP TABLE csr_requests;
DROP TRIGGER certificates_key_check ON certificates;
DROP FUNCTION certificates_check_key();
DROP TABLE certificates;
DROP TABLE managed_private_keys;
DROP FUNCTION certificate_location_path_hash(text);
