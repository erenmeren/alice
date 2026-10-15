-- +goose Up

-- Group roles. Individual logins are created by the operator as members of one of them.
-- +goose StatementBegin
DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'vendor_sales') THEN
        CREATE ROLE vendor_sales NOLOGIN;
    END IF;
    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'vendor_signer') THEN
        CREATE ROLE vendor_signer NOLOGIN IN ROLE vendor_sales;
    END IF;
    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'vendor_owner') THEN
        CREATE ROLE vendor_owner NOLOGIN IN ROLE vendor_signer;
    END IF;
END
$$;
-- +goose StatementEnd

CREATE TABLE customers (
    id         bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    name       text NOT NULL CHECK (length(name) BETWEEN 1 AND 200 AND name = btrim(name)),
    contact    text NOT NULL DEFAULT '' CHECK (length(contact) <= 500),
    notes      text NOT NULL DEFAULT '' CHECK (length(notes) <= 4000),
    created_by text NOT NULL DEFAULT current_user,
    created_at timestamptz NOT NULL DEFAULT now()
);
CREATE UNIQUE INDEX customers_name_key ON customers (lower(name));

CREATE TABLE license_requests (
    id           bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    customer_id  bigint NOT NULL REFERENCES customers (id),
    installation text NOT NULL CHECK (length(installation) BETWEEN 5 AND 64),
    targets      integer NOT NULL CHECK (targets BETWEEN 1 AND 100000),
    valid_from   text NOT NULL DEFAULT '' CHECK (length(valid_from) <= 40),
    months       integer NOT NULL DEFAULT 12 CHECK (months BETWEEN 1 AND 60),
    features     text[] NOT NULL DEFAULT '{}',
    replaces     text NOT NULL DEFAULT '' CHECK (length(replaces) <= 64),
    status       text NOT NULL DEFAULT 'open' CHECK (status IN ('open', 'signed', 'rejected', 'cancelled')),
    requested_by text NOT NULL DEFAULT current_user,
    requested_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX license_requests_status_idx ON license_requests (status, requested_at);

CREATE TABLE licenses (
    license_id   text PRIMARY KEY,
    request_id   bigint NOT NULL UNIQUE REFERENCES license_requests (id),
    customer_id  bigint NOT NULL REFERENCES customers (id),
    installation text NOT NULL,
    key_id       text NOT NULL,
    issued_at    timestamptz NOT NULL,
    valid_from   timestamptz NOT NULL,
    valid_until  timestamptz NOT NULL,
    targets      integer NOT NULL,
    replaces     text NOT NULL DEFAULT '',
    file         bytea NOT NULL,
    file_sha256  text NOT NULL,
    signed_by    text NOT NULL DEFAULT current_user,
    revoked_at   timestamptz
);
CREATE INDEX licenses_valid_until_idx ON licenses (valid_until);
CREATE INDEX licenses_customer_idx ON licenses (customer_id);

CREATE TABLE audit (
    seq       bigint PRIMARY KEY,
    at        timestamptz NOT NULL,
    actor     text NOT NULL,
    action    text NOT NULL,
    subject   text NOT NULL,
    details   jsonb NOT NULL,
    prev_hash text NOT NULL,
    hash      text NOT NULL UNIQUE
);

-- Append-only rules, for every role including the table owner.
-- +goose StatementBegin
CREATE FUNCTION vendor_forbid_change() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    RAISE EXCEPTION 'vendor: % is append-only', TG_TABLE_NAME USING ERRCODE = 'integrity_constraint_violation';
END
$$;
-- +goose StatementEnd
CREATE TRIGGER audit_append_only BEFORE UPDATE OR DELETE ON audit
    FOR EACH ROW EXECUTE FUNCTION vendor_forbid_change();
CREATE TRIGGER audit_no_truncate BEFORE TRUNCATE ON audit
    FOR EACH STATEMENT EXECUTE FUNCTION vendor_forbid_change();
CREATE TRIGGER licenses_no_delete BEFORE DELETE ON licenses
    FOR EACH ROW EXECUTE FUNCTION vendor_forbid_change();
-- +goose StatementBegin
CREATE FUNCTION vendor_license_update_guard() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    IF (to_jsonb(OLD) - 'revoked_at') IS DISTINCT FROM (to_jsonb(NEW) - 'revoked_at') THEN
        RAISE EXCEPTION 'vendor: only revoked_at of a license may change' USING ERRCODE = 'integrity_constraint_violation';
    END IF;
    RETURN NEW;
END
$$;
-- +goose StatementEnd
CREATE TRIGGER licenses_update_guard BEFORE UPDATE ON licenses
    FOR EACH ROW EXECUTE FUNCTION vendor_license_update_guard();

-- The audit chain. The hash covers the previous hash, so changing or removing a row in the middle
-- breaks every later row. Only these functions write audit rows.
-- +goose StatementBegin
CREATE FUNCTION audit_hash(prev text, s bigint, t timestamptz, a text, ac text, sub text, d jsonb)
RETURNS text LANGUAGE sql STABLE AS $$
    SELECT encode(sha256(convert_to(concat_ws('|', prev, s::text,
        to_char(t AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.US'), a, ac, sub, d::text), 'UTF8')), 'hex')
$$;
-- +goose StatementEnd

-- The actor is the role the caller acts as (SET ROLE), or the login when there is none.
-- +goose StatementBegin
CREATE FUNCTION audit_actor() RETURNS text LANGUAGE sql STABLE AS $$
    SELECT CASE WHEN current_setting('role') = 'none' THEN session_user::text ELSE current_setting('role') END
$$;
-- +goose StatementEnd

-- +goose StatementBegin
CREATE FUNCTION audit_append(p_action text, p_subject text, p_details jsonb DEFAULT '{}'::jsonb)
RETURNS bigint LANGUAGE plpgsql SECURITY DEFINER SET search_path = public, pg_temp AS $$
DECLARE
    prev text;
    s    bigint;
    t    timestamptz;
    a    text;
BEGIN
    PERFORM pg_advisory_xact_lock(727001);
    SELECT seq, hash INTO s, prev FROM audit ORDER BY seq DESC LIMIT 1;
    s := COALESCE(s, 0) + 1;
    prev := COALESCE(prev, repeat('0', 64));
    t := date_trunc('microseconds', clock_timestamp());
    a := audit_actor();
    INSERT INTO audit (seq, at, actor, action, subject, details, prev_hash, hash)
    VALUES (s, t, a, p_action, p_subject, p_details, prev,
            audit_hash(prev, s, t, a, p_action, p_subject, p_details));
    RETURN s;
END
$$;
-- +goose StatementEnd

-- Returns 0 when the chain is intact, otherwise the first sequence number that does not fit.
-- +goose StatementBegin
CREATE FUNCTION audit_verify() RETURNS bigint
LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path = public, pg_temp AS $$
DECLARE
    r      audit%ROWTYPE;
    prev   text := repeat('0', 64);
    expect bigint := 1;
BEGIN
    FOR r IN SELECT * FROM audit ORDER BY seq LOOP
        IF r.seq <> expect OR r.prev_hash <> prev
           OR r.hash <> audit_hash(prev, r.seq, r.at, r.actor, r.action, r.subject, r.details) THEN
            RETURN r.seq;
        END IF;
        prev := r.hash;
        expect := expect + 1;
    END LOOP;
    RETURN 0;
END
$$;
-- +goose StatementEnd

-- Privileges. Nothing is granted to PUBLIC.
REVOKE ALL ON customers, license_requests, licenses, audit FROM PUBLIC;
REVOKE ALL ON FUNCTION audit_append(text, text, jsonb), audit_verify(), audit_hash(text, bigint, timestamptz, text, text, text, jsonb),
    audit_actor() FROM PUBLIC;
GRANT USAGE ON SCHEMA public TO vendor_sales;

GRANT SELECT, INSERT ON customers TO vendor_sales;
GRANT UPDATE ON customers TO vendor_signer;
GRANT SELECT, INSERT, UPDATE ON license_requests TO vendor_sales;
GRANT SELECT ON licenses TO vendor_sales;
GRANT INSERT ON licenses TO vendor_signer;
GRANT UPDATE (revoked_at) ON licenses TO vendor_owner;
GRANT SELECT ON audit TO vendor_owner;
GRANT EXECUTE ON FUNCTION audit_append(text, text, jsonb), audit_actor() TO vendor_sales;
GRANT EXECUTE ON FUNCTION audit_verify() TO vendor_owner;

-- Row-level security on requests: everybody who may read can read all; a sales login changes only
-- its own open requests (and may only cancel them); signers change any.
ALTER TABLE license_requests ENABLE ROW LEVEL SECURITY;
CREATE POLICY requests_read ON license_requests FOR SELECT TO vendor_sales USING (true);
CREATE POLICY requests_insert ON license_requests FOR INSERT TO vendor_sales
    WITH CHECK (requested_by = current_user AND status = 'open');
CREATE POLICY requests_update_own ON license_requests FOR UPDATE TO vendor_sales
    USING (requested_by = current_user AND status = 'open')
    WITH CHECK (requested_by = current_user AND status IN ('open', 'cancelled'));
CREATE POLICY requests_update_signer ON license_requests FOR UPDATE TO vendor_signer
    USING (true) WITH CHECK (true);

-- +goose Down
DROP FUNCTION audit_verify();
DROP FUNCTION audit_append(text, text, jsonb);
DROP FUNCTION audit_actor();
DROP FUNCTION audit_hash(text, bigint, timestamptz, text, text, text, jsonb);
DROP TABLE audit;
DROP TABLE licenses;
DROP TABLE license_requests;
DROP TABLE customers;
DROP FUNCTION vendor_license_update_guard();
DROP FUNCTION vendor_forbid_change();
