-- +goose Up
-- Network certificate discovery: the scan scopes an Administrator defines, the scans of a scope, the certificates the
-- scanned endpoints presented and the endpoints themselves. Plan: docs/superpowers/plans/2026-10-13-network-discovery.md
-- (Tables, amendments A3-A5).
--
-- Only public certificates are stored; nothing here is a secret. Discovered certificates are not the managed inventory
-- (certificates): they never count toward the license and never enter the managed alerts or exports. No column default
-- is a clock: the application passes the time it decided on.

-- discovery_name_ok: a host or SNI name as the scope validator stores it (A3): lower-case LDH labels (IDNA A-labels) of
-- 1 to 63 characters that neither start nor end with a hyphen, joined by single dots, at most 253 characters in all; no
-- space, no CR/LF, no trailing dot. Whether a name looks like an IP literal is the validator's check.
-- +goose StatementBegin
CREATE FUNCTION discovery_name_ok(n text) RETURNS boolean LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
SET search_path = pg_catalog, pg_temp AS $$
    SELECT char_length(n) <= 253 AND n ~ '^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)*$'
$$;
-- +goose StatementEnd

-- discovery_names_ok: every element of a name list is a name (no NULL element).
-- +goose StatementBegin
CREATE FUNCTION discovery_names_ok(ns text[]) RETURNS boolean LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
SET search_path = pg_catalog, pg_temp AS $$
    SELECT coalesce(bool_and(n IS NOT NULL AND public.discovery_name_ok(n)), true) FROM unnest(ns) AS u(n)
$$;
-- +goose StatementEnd

-- discovery_fingerprints_ok: every element is a SHA-256 fingerprint in the form of certificates.fingerprint_sha256.
-- +goose StatementBegin
CREATE FUNCTION discovery_fingerprints_ok(fps text[]) RETURNS boolean LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
SET search_path = pg_catalog, pg_temp AS $$
    SELECT coalesce(bool_and(f IS NOT NULL AND f ~ '^[0-9a-f]{64}$'), true) FROM unnest(fps) AS u(f)
$$;
-- +goose StatementEnd

-- discovery_strings_ok: a JSON array of at most max strings of at most 255 characters each (scope entries and
-- exclusions, the global exclusions and allowed scan networks). The validator decides what the strings mean.
-- +goose StatementBegin
CREATE FUNCTION discovery_strings_ok(v jsonb, max integer) RETURNS boolean LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
SET search_path = pg_catalog, pg_temp AS $$
    SELECT jsonb_typeof(v) = 'array' AND jsonb_array_length(v) <= max
       AND NOT EXISTS (SELECT 1 FROM jsonb_array_elements(v) AS e(x) WHERE jsonb_typeof(x) <> 'string' OR char_length(x #>> '{}') NOT BETWEEN 1 AND 255)
$$;
-- +goose StatementEnd

-- A scan scope (design decision 1): up to 256 entries (CIDR ranges, single addresses, host names), up to 16 ports,
-- up to 256 SNI names, the scope's own exclusions, the rate and concurrency of its scans, an optional schedule (every
-- N hours, optionally inside a daily window in a time zone) and whether its findings raise expiry alerts. Soft-deleted,
-- never removed (its scans refer to it); a live name is unique case-insensitively. version is the If-Match version.
-- last_scheduled_at is when the schedule last queued a scan of it.
CREATE TABLE discovery_scopes (
    id                uuid PRIMARY KEY,
    name              citext NOT NULL CHECK (char_length(name::text) BETWEEN 1 AND 100),
    entries           jsonb NOT NULL CHECK (discovery_strings_ok(entries, 256) AND jsonb_array_length(entries) >= 1),
    ports             integer[] NOT NULL CHECK (cardinality(ports) BETWEEN 1 AND 16 AND array_ndims(ports) = 1
                          AND array_position(ports, NULL) IS NULL AND 1 <= ALL (ports) AND 65535 >= ALL (ports)),
    sni_names         text[] NOT NULL DEFAULT '{}' CHECK (cardinality(sni_names) <= 256 AND discovery_names_ok(sni_names)),
    exclusions        jsonb NOT NULL DEFAULT '[]' CHECK (discovery_strings_ok(exclusions, 256)),
    enabled           boolean NOT NULL DEFAULT true,
    schedule_hours    integer CHECK (schedule_hours BETWEEN 1 AND 168),
    window_start      time,
    window_end        time,
    window_tz         text NOT NULL DEFAULT 'UTC' CHECK (window_tz ~ '^[A-Za-z0-9_+/-]{1,64}$'),
    alert_on_expiry   boolean NOT NULL DEFAULT false,
    rate_per_sec      integer NOT NULL DEFAULT 20 CHECK (rate_per_sec BETWEEN 1 AND 100),
    concurrency       integer NOT NULL DEFAULT 32 CHECK (concurrency BETWEEN 1 AND 64),
    last_scheduled_at timestamptz,
    version           integer NOT NULL DEFAULT 1 CHECK (version >= 1),
    created_by        uuid REFERENCES users (id),
    created_at        timestamptz NOT NULL,
    updated_at        timestamptz NOT NULL,
    deleted_at        timestamptz,
    -- a window has both ends, is not empty, and only narrows a schedule
    CHECK ((window_start IS NULL) = (window_end IS NULL)),
    CHECK (window_start IS NULL OR (schedule_hours IS NOT NULL AND window_start <> window_end))
);
CREATE UNIQUE INDEX discovery_scopes_name ON discovery_scopes (name) WHERE deleted_at IS NULL;

-- One scan of a scope (A5): queued, then running, then done, cancelled (a person, or the license lock), timed_out (the
-- 60-minute cap; partial results kept) or failed (error_code: the reason, for example discovery.scan_interrupted).
-- Only cancelled, timed_out and failed scans carry an error_code. cancel_requested is the flag the workers poll. The counts are of endpoints (address x port x SNI; at most 20,000 per
-- scan); certificates_new counts new fingerprints and cert_churn those beyond the per-scan and per-day caps that were
-- only counted (A4). One scan per scope is queued or running at a time. A finished scan is history (Z1020); only the
-- last 30 per scope are kept, so finished scans are deleted.
CREATE TABLE discovery_scans (
    id                 uuid PRIMARY KEY,
    scope_id           uuid NOT NULL REFERENCES discovery_scopes (id),
    trigger            text NOT NULL CHECK (trigger IN ('manual', 'schedule')),
    state              text NOT NULL DEFAULT 'queued' CHECK (state IN ('queued', 'running', 'done', 'cancelled', 'timed_out', 'failed')),
    cancel_requested   boolean NOT NULL DEFAULT false,
    endpoints_total    integer NOT NULL DEFAULT 0 CHECK (endpoints_total BETWEEN 0 AND 20000),
    endpoints_answered integer NOT NULL DEFAULT 0 CHECK (endpoints_answered >= 0),
    endpoints_failed   integer NOT NULL DEFAULT 0 CHECK (endpoints_failed >= 0),
    endpoints_excluded integer NOT NULL DEFAULT 0 CHECK (endpoints_excluded >= 0),
    certificates_new   integer NOT NULL DEFAULT 0 CHECK (certificates_new >= 0),
    cert_churn         integer NOT NULL DEFAULT 0 CHECK (cert_churn >= 0),
    requested_by       uuid REFERENCES users (id),
    queued_at          timestamptz NOT NULL,
    started_at         timestamptz,
    finished_at        timestamptz,
    error_code         text NOT NULL DEFAULT '' CHECK (error_code ~ '^[A-Za-z0-9._-]{0,100}$'),
    CHECK (endpoints_answered + endpoints_failed + endpoints_excluded <= endpoints_total),
    CHECK (state <> 'queued' OR started_at IS NULL),
    CHECK (state <> 'running' OR started_at IS NOT NULL),
    CHECK ((state IN ('queued', 'running')) = (finished_at IS NULL)),
    CHECK (finished_at IS NULL OR started_at IS NULL OR finished_at >= started_at),
    CHECK (state <> 'failed' OR error_code <> ''),
    CHECK (state NOT IN ('queued', 'running', 'done') OR error_code = ''),
    CHECK (trigger = 'manual' OR requested_by IS NULL)
);
CREATE UNIQUE INDEX discovery_scans_one_active ON discovery_scans (scope_id) WHERE state IN ('queued', 'running');
CREATE INDEX discovery_scans_scope ON discovery_scans (scope_id, queued_at DESC, id DESC);
CREATE INDEX discovery_scans_list ON discovery_scans (queued_at DESC, id DESC);

-- A finished scan is history: nothing of it changes. A scan in flight is never deleted (pruning removes old finished
-- scans only). SQLSTATE Z1020.
-- +goose StatementBegin
CREATE FUNCTION discovery_scans_protect_done() RETURNS trigger LANGUAGE plpgsql
SET search_path = pg_catalog, pg_temp AS $$
BEGIN
    IF TG_OP = 'DELETE' THEN
        IF OLD.state IN ('queued', 'running') THEN
            RAISE EXCEPTION 'a discovery scan in flight cannot be deleted' USING ERRCODE = 'Z1020';
        END IF;
        RETURN OLD;
    END IF;
    IF OLD.state NOT IN ('queued', 'running') AND to_jsonb(NEW) IS DISTINCT FROM to_jsonb(OLD) THEN
        RAISE EXCEPTION 'a finished discovery scan cannot be changed' USING ERRCODE = 'Z1020';
    END IF;
    RETURN NEW;
END $$;
-- +goose StatementEnd
CREATE TRIGGER discovery_scans_done_frozen BEFORE UPDATE OR DELETE ON discovery_scans
    FOR EACH ROW EXECUTE FUNCTION discovery_scans_protect_done();

-- A certificate an endpoint presented, once per SHA-256 fingerprint of its DER (the definition of
-- certificates.fingerprint_sha256, so "unmanaged" is a join on it). is_leaf: it was presented as a leaf at least once;
-- intermediates are stored once, by fingerprint, with is_leaf false (A4). pem is the one certificate (at most 16 KiB of
-- DER). A certificate no endpoint refers to and not seen for 7 days is deleted (A4: the orphan purge reads last_seen).
CREATE TABLE discovery_certificates (
    fingerprint_sha256 text PRIMARY KEY CHECK (fingerprint_sha256 ~ '^[0-9a-f]{64}$'),
    is_leaf            boolean NOT NULL,
    subject_cn         text NOT NULL DEFAULT '' CHECK (char_length(subject_cn) <= 1024),
    sans               text[] NOT NULL DEFAULT '{}' CHECK (cardinality(sans) <= 1000 AND array_position(sans, NULL) IS NULL
                           AND octet_length(array_to_string(sans, ',')) <= 65536),
    issuer_cn          text NOT NULL DEFAULT '' CHECK (char_length(issuer_cn) <= 1024),
    not_before         timestamptz NOT NULL,
    not_after          timestamptz NOT NULL,
    key_algorithm      text NOT NULL CHECK (key_algorithm IN ('rsa', 'ecdsa', 'ed25519', 'other')),
    self_signed        boolean NOT NULL DEFAULT false,
    -- 16 KiB of DER is 21,848 base64 characters, 342 line breaks and the two armour lines
    pem                text NOT NULL CHECK (char_length(pem) <= 22300 AND pem LIKE '-----BEGIN CERTIFICATE-----%'),
    first_seen         timestamptz NOT NULL,
    last_seen          timestamptz NOT NULL,
    CHECK (not_after >= not_before),
    CHECK (last_seen >= first_seen)
);
CREATE INDEX discovery_certificates_expiry ON discovery_certificates (not_after, fingerprint_sha256) WHERE is_leaf;
CREATE INDEX discovery_certificates_last_seen ON discovery_certificates (last_seen);

-- An endpoint of a scope: an address, a port and the SNI name sent ('' = none). host is the scope's host name the
-- address was resolved from ('' for an address entry; A3). The leaf it presents (fingerprint_sha256) and the rest of
-- the chain in the order presented (chain_fingerprints, at most 9; chain_sha256 is the digest of the whole presented
-- chain) are stored certificates. previous_fingerprints is the ring of the last 5 leaves it presented before (rotations).
-- state: present (answered TLS with a certificate), unreachable (last_error_code says why), no_tls, malformed (a
-- certificate Go cannot parse), excluded (the policy refused to dial it: never dialed), gone (left the scope or missed
-- 3 scans; gone_since is when, retention deletes it). last_error_code is a closed set: a Go error string is never stored.
-- missed_scans counts attempted scans without an answer. last_seen is when it last presented a certificate.
CREATE TABLE discovery_endpoints (
    id                    uuid PRIMARY KEY,
    scope_id              uuid NOT NULL REFERENCES discovery_scopes (id),
    address               inet NOT NULL CHECK (masklen(address) = CASE family(address) WHEN 4 THEN 32 ELSE 128 END),
    port                  integer NOT NULL CHECK (port BETWEEN 1 AND 65535),
    sni                   text NOT NULL DEFAULT '' CHECK (sni = '' OR discovery_name_ok(sni)),
    host                  text NOT NULL DEFAULT '' CHECK (host = '' OR discovery_name_ok(host)),
    fingerprint_sha256    text REFERENCES discovery_certificates (fingerprint_sha256),
    chain_fingerprints    text[] NOT NULL DEFAULT '{}' CHECK (cardinality(chain_fingerprints) <= 9 AND discovery_fingerprints_ok(chain_fingerprints)),
    chain_sha256          text NOT NULL DEFAULT '' CHECK (chain_sha256 = '' OR chain_sha256 ~ '^[0-9a-f]{64}$'),
    tls_version           text NOT NULL DEFAULT '' CHECK (tls_version IN ('', 'TLS 1.0', 'TLS 1.1', 'TLS 1.2', 'TLS 1.3')),
    cipher                text NOT NULL DEFAULT '' CHECK (cipher ~ '^[A-Za-z0-9_]{0,64}$'),
    state                 text NOT NULL CHECK (state IN ('present', 'unreachable', 'gone', 'no_tls', 'excluded', 'malformed')),
    last_error_code       text NOT NULL DEFAULT '' CHECK (last_error_code IN ('', 'refused', 'timeout', 'no_tls', 'reset', 'chain_too_large',
                              'policy', 'malformed')),
    missed_scans          integer NOT NULL DEFAULT 0 CHECK (missed_scans >= 0),
    previous_fingerprints text[] NOT NULL DEFAULT '{}' CHECK (cardinality(previous_fingerprints) <= 5 AND discovery_fingerprints_ok(previous_fingerprints)),
    first_seen            timestamptz NOT NULL,
    last_seen             timestamptz,
    last_scanned_at       timestamptz NOT NULL,
    last_scan_id          uuid REFERENCES discovery_scans (id) ON DELETE SET NULL,
    gone_since            timestamptz,
    CHECK (state <> 'present' OR (fingerprint_sha256 IS NOT NULL AND last_error_code = '')),
    CHECK (state <> 'excluded' OR last_error_code = 'policy'),
    CHECK (state <> 'malformed' OR last_error_code = 'malformed'),
    CHECK (state <> 'no_tls' OR last_error_code = 'no_tls'),
    CHECK (state <> 'unreachable' OR last_error_code IN ('refused', 'timeout', 'reset', 'chain_too_large')),
    CHECK ((state = 'gone') = (gone_since IS NOT NULL))
);
CREATE UNIQUE INDEX discovery_endpoints_key ON discovery_endpoints (scope_id, address, port, sni);
CREATE INDEX discovery_endpoints_list ON discovery_endpoints (address, port, sni, id);
CREATE INDEX discovery_endpoints_fingerprint ON discovery_endpoints (fingerprint_sha256) WHERE fingerprint_sha256 IS NOT NULL;
CREATE INDEX discovery_endpoints_chain ON discovery_endpoints USING gin (chain_fingerprints);
CREATE INDEX discovery_endpoints_gone ON discovery_endpoints (gone_since) WHERE state = 'gone';
CREATE INDEX discovery_endpoints_last_scan ON discovery_endpoints (last_scan_id) WHERE last_scan_id IS NOT NULL;

-- The discovery settings (A2, design decision 3). An absent row is the default: no global exclusions, 90 days of
-- retention, and no allowed scan network (nothing may be scanned). A stored row has this shape.
-- CASE keeps the order of evaluation: no other key's value is ever cast.
ALTER TABLE settings ADD CONSTRAINT settings_discovery_retention_days CHECK (CASE
    WHEN key <> 'discovery.retention_days' THEN true
    WHEN jsonb_typeof(value) <> 'number' OR value::text !~ '^[0-9]{1,4}$' THEN false
    ELSE value::text::integer BETWEEN 7 AND 730 END);
ALTER TABLE settings ADD CONSTRAINT settings_discovery_exclusions CHECK (CASE
    WHEN key <> 'discovery.exclusions' THEN true ELSE discovery_strings_ok(value, 256) END);
ALTER TABLE settings ADD CONSTRAINT settings_discovery_allowed_networks CHECK (CASE
    WHEN key <> 'discovery.allowed_networks' THEN true ELSE discovery_strings_ok(value, 256) END);

-- Grants (pattern 00013): a scope is soft-deleted and never removed, and its identity (id, creator, creation time) is
-- fixed; a scan's scope, trigger, requester and queue time are fixed and a finished scan is frozen (Z1020); a
-- certificate's body and parsed fields never change (its fingerprint is their hash), only when it was last seen and
-- whether it was seen as a leaf; an endpoint's key (scope, address, port, SNI), host and first sighting are fixed.
-- Scans, certificates and endpoints are deleted by pruning and retention.
GRANT SELECT, INSERT ON discovery_scopes TO alice_app;
GRANT SELECT, INSERT, DELETE ON discovery_scans, discovery_certificates, discovery_endpoints TO alice_app;
GRANT UPDATE (name, entries, ports, sni_names, exclusions, enabled, schedule_hours, window_start, window_end, window_tz, alert_on_expiry,
    rate_per_sec, concurrency, last_scheduled_at, version, updated_at, deleted_at) ON discovery_scopes TO alice_app;
GRANT UPDATE (state, cancel_requested, endpoints_total, endpoints_answered, endpoints_failed, endpoints_excluded, certificates_new, cert_churn,
    started_at, finished_at, error_code) ON discovery_scans TO alice_app;
GRANT UPDATE (last_seen, is_leaf) ON discovery_certificates TO alice_app;
GRANT UPDATE (fingerprint_sha256, chain_fingerprints, chain_sha256, tls_version, cipher, state, last_error_code, missed_scans,
    previous_fingerprints, last_seen, last_scanned_at, last_scan_id, gone_since) ON discovery_endpoints TO alice_app;

-- +goose Down
-- The discovery data is dropped, and so are the discovery settings it was governed by: an Up after the Down then never
-- meets a value its CHECKs refuse.
DELETE FROM settings WHERE key IN ('discovery.exclusions', 'discovery.retention_days', 'discovery.allowed_networks');
ALTER TABLE settings DROP CONSTRAINT settings_discovery_allowed_networks;
ALTER TABLE settings DROP CONSTRAINT settings_discovery_exclusions;
ALTER TABLE settings DROP CONSTRAINT settings_discovery_retention_days;
DROP TABLE discovery_endpoints;
DROP TABLE discovery_certificates;
DROP TRIGGER discovery_scans_done_frozen ON discovery_scans;
DROP FUNCTION discovery_scans_protect_done();
DROP TABLE discovery_scans;
DROP TABLE discovery_scopes;
DROP FUNCTION discovery_strings_ok(jsonb, integer);
DROP FUNCTION discovery_fingerprints_ok(text[]);
DROP FUNCTION discovery_names_ok(text[]);
DROP FUNCTION discovery_name_ok(text);
