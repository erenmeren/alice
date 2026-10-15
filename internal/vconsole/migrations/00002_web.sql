-- +goose Up
-- +goose StatementBegin
DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'vendor_web') THEN
        CREATE ROLE vendor_web NOLOGIN IN ROLE vendor_sales;
    END IF;
END
$$;
-- +goose StatementEnd

-- Who is acting. The web service is one login that acts for a signed-in person by setting
-- vendor.actor for the transaction. The setting counts only for members that inherit vendor_web;
-- not superusers or admin-only grantors (on PostgreSQL 16 the CREATEROLE login that runs this
-- migration holds vendor_web with ADMIN but without INHERIT). Any other login that sets it still
-- appears under its own name.
-- +goose StatementBegin
CREATE FUNCTION vendor_actor() RETURNS text LANGUAGE sql STABLE AS $$
    SELECT CASE
        WHEN pg_has_role(session_user, 'vendor_web', 'USAGE')
             AND NOT (SELECT rolsuper FROM pg_roles WHERE rolname = session_user)
             AND coalesce(current_setting('vendor.actor', true), '') ~ '^[A-Za-z0-9._-]{1,64}$'
        THEN 'web:' || current_setting('vendor.actor', true)
        ELSE session_user::text
    END
$$;
-- +goose StatementEnd
REVOKE ALL ON FUNCTION vendor_actor() FROM PUBLIC;
GRANT EXECUTE ON FUNCTION vendor_actor() TO vendor_sales;

CREATE OR REPLACE FUNCTION audit_actor() RETURNS text LANGUAGE sql STABLE AS $$ SELECT vendor_actor() $$;

ALTER TABLE customers        ALTER COLUMN created_by   SET DEFAULT vendor_actor();
ALTER TABLE license_requests ALTER COLUMN requested_by SET DEFAULT vendor_actor();
ALTER TABLE licenses         ALTER COLUMN signed_by    SET DEFAULT vendor_actor();

DROP POLICY requests_insert ON license_requests;
DROP POLICY requests_update_own ON license_requests;
CREATE POLICY requests_insert ON license_requests FOR INSERT TO vendor_sales
    WITH CHECK (requested_by = vendor_actor() AND status = 'open');
CREATE POLICY requests_update_own ON license_requests FOR UPDATE TO vendor_sales
    USING (requested_by = vendor_actor() AND status = 'open')
    WITH CHECK (requested_by = vendor_actor() AND status IN ('open', 'cancelled'));

CREATE TABLE web_users (
    id          bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    name        text NOT NULL CHECK (name ~ '^[A-Za-z0-9._-]{1,64}$'),
    created_by  text NOT NULL DEFAULT session_user,
    created_at  timestamptz NOT NULL DEFAULT now(),
    disabled_at timestamptz
);
CREATE UNIQUE INDEX web_users_name_key ON web_users (lower(name));

CREATE TABLE web_credentials (
    credential_id bytea PRIMARY KEY,
    user_id       bigint NOT NULL REFERENCES web_users (id),
    credential    jsonb NOT NULL,
    created_at    timestamptz NOT NULL DEFAULT now(),
    last_used_at  timestamptz
);
CREATE INDEX web_credentials_user_idx ON web_credentials (user_id);

CREATE TABLE web_enrollments (
    token_hash text PRIMARY KEY,
    user_id    bigint NOT NULL REFERENCES web_users (id),
    expires_at timestamptz NOT NULL,
    used_at    timestamptz
);

CREATE TABLE web_sessions (
    token_hash text PRIMARY KEY,
    user_id    bigint NOT NULL REFERENCES web_users (id),
    created_at timestamptz NOT NULL,
    expires_at timestamptz NOT NULL,
    last_seen  timestamptz NOT NULL
);

REVOKE ALL ON web_users, web_credentials, web_enrollments, web_sessions FROM PUBLIC;
GRANT SELECT ON web_users TO vendor_web;
GRANT SELECT, INSERT ON web_credentials TO vendor_web;
GRANT UPDATE (credential, last_used_at) ON web_credentials TO vendor_web;
GRANT SELECT ON web_enrollments TO vendor_web;
GRANT UPDATE (used_at) ON web_enrollments TO vendor_web;
GRANT SELECT, INSERT, DELETE ON web_sessions TO vendor_web;
GRANT UPDATE (last_seen) ON web_sessions TO vendor_web;
-- The owner creates and disables web users and issues enrollment codes.
GRANT SELECT, INSERT ON web_users TO vendor_owner;
GRANT UPDATE (disabled_at) ON web_users TO vendor_owner;
GRANT SELECT, INSERT ON web_enrollments TO vendor_owner;
GRANT SELECT ON web_credentials TO vendor_owner;
GRANT DELETE ON web_sessions TO vendor_owner;
GRANT SELECT ON web_sessions TO vendor_owner;

-- +goose StatementBegin
CREATE FUNCTION vendor_audit_web() RETURNS trigger LANGUAGE plpgsql SECURITY DEFINER SET search_path = public, pg_temp AS $$
BEGIN
    IF TG_TABLE_NAME = 'web_users' THEN
        IF TG_OP = 'INSERT' THEN
            PERFORM audit_append('webuser.add', NEW.name, '{}'::jsonb);
        ELSIF NEW.disabled_at IS DISTINCT FROM OLD.disabled_at THEN
            PERFORM audit_append(CASE WHEN NEW.disabled_at IS NULL THEN 'webuser.enable' ELSE 'webuser.disable' END, NEW.name, '{}'::jsonb);
        END IF;
    ELSIF TG_TABLE_NAME = 'web_credentials' AND TG_OP = 'INSERT' THEN
        PERFORM audit_append('webuser.passkey_add', (SELECT name FROM web_users WHERE id = NEW.user_id),
                            jsonb_build_object('user_id', NEW.user_id));
    ELSIF TG_TABLE_NAME = 'web_enrollments' AND TG_OP = 'INSERT' THEN
        PERFORM audit_append('webuser.invite', (SELECT name FROM web_users WHERE id = NEW.user_id),
                            jsonb_build_object('user_id', NEW.user_id, 'expires_at', NEW.expires_at));
    END IF;
    RETURN NULL;
END
$$;
-- +goose StatementEnd
CREATE TRIGGER web_users_audit AFTER INSERT OR UPDATE ON web_users FOR EACH ROW EXECUTE FUNCTION vendor_audit_web();
CREATE TRIGGER web_credentials_audit AFTER INSERT ON web_credentials FOR EACH ROW EXECUTE FUNCTION vendor_audit_web();
CREATE TRIGGER web_enrollments_audit AFTER INSERT ON web_enrollments FOR EACH ROW EXECUTE FUNCTION vendor_audit_web();

-- The web service may record one kind of audit row: a successful sign-in.
-- +goose StatementBegin
CREATE FUNCTION web_audit_login(p_user text) RETURNS void LANGUAGE sql SECURITY DEFINER SET search_path = public, pg_temp AS $$
    SELECT audit_append('web.login', p_user, '{}'::jsonb) WHERE EXISTS (SELECT 1 FROM web_users WHERE name = p_user AND disabled_at IS NULL)
$$;
-- +goose StatementEnd
REVOKE ALL ON FUNCTION web_audit_login(text), vendor_audit_web() FROM PUBLIC;
GRANT EXECUTE ON FUNCTION web_audit_login(text) TO vendor_web;

-- +goose Down
DROP FUNCTION web_audit_login(text);
DROP TABLE web_sessions, web_enrollments, web_credentials, web_users;
DROP FUNCTION vendor_audit_web();
