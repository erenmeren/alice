-- +goose Up
-- +goose StatementBegin
DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'vendor_notifier') THEN
        CREATE ROLE vendor_notifier NOLOGIN;
    END IF;
END
$$;
-- +goose StatementEnd

-- Settings. Only keys the code knows; a bad owner address would make the issuance trigger fail and
-- block issuing, so it is validated here.
CREATE TABLE vendor_settings (
    key        text PRIMARY KEY CHECK (key IN ('owner_email', 'timezone', 'last_summary_at')),
    value      text NOT NULL CHECK (length(value) <= 254),
    updated_by text,
    updated_at timestamptz,
    CHECK (key <> 'owner_email' OR value = '' OR (value ~ '^[^@\s]+@[^@\s]+\.[^@\s]+$'))
);

-- +goose StatementBegin
CREATE FUNCTION vendor_settings_stamp() RETURNS trigger LANGUAGE plpgsql SECURITY DEFINER SET search_path = public, pg_temp AS $$
BEGIN
    NEW.updated_by := vendor_actor();
    NEW.updated_at := now();
    RETURN NEW;
END
$$;
-- +goose StatementEnd
CREATE TRIGGER vendor_settings_stamp BEFORE INSERT OR UPDATE ON vendor_settings
    FOR EACH ROW EXECUTE FUNCTION vendor_settings_stamp();

ALTER TABLE web_users ADD COLUMN email text NOT NULL DEFAULT ''
    CONSTRAINT web_users_email_check CHECK (email = '' OR (email ~ '^[^@\s]+@[^@\s]+\.[^@\s]+$' AND length(email) <= 254));

CREATE TABLE mail_outbox (
    id              bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    kind            text NOT NULL DEFAULT '' CHECK (length(kind) <= 40),
    to_addrs        text[] NOT NULL CHECK (cardinality(to_addrs) <= 20
                        AND length(array_to_string(to_addrs, ',')) <= 2000
                        AND array_to_string(to_addrs, ',') !~ '[\r\n]'),
    subject         text NOT NULL CHECK (length(subject) BETWEEN 1 AND 200 AND subject !~ '[\r\n]'),
    body            text NOT NULL CHECK (length(body) <= 200000),
    created_at      timestamptz NOT NULL DEFAULT now(),
    sent_at         timestamptz,
    attempts        integer NOT NULL DEFAULT 0,
    last_error      text NOT NULL DEFAULT '' CHECK (length(last_error) <= 2000),
    failed_at       timestamptz,
    next_attempt_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX mail_outbox_pending_idx ON mail_outbox (next_attempt_at) WHERE sent_at IS NULL AND failed_at IS NULL;

CREATE TABLE reminders (
    license_id  text NOT NULL REFERENCES licenses (license_id),
    days_before integer NOT NULL CHECK (days_before IN (90, 60, 30)),
    created_at  timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (license_id, days_before)
);

-- Settings and web-user address changes are audited, with the new value (never a secret).
-- +goose StatementBegin
CREATE FUNCTION vendor_audit_settings() RETURNS trigger LANGUAGE plpgsql SECURITY DEFINER SET search_path = public, pg_temp AS $$
BEGIN
    IF TG_OP = 'INSERT' OR NEW.value IS DISTINCT FROM OLD.value THEN
        PERFORM audit_append('settings.set', NEW.key, jsonb_build_object('value', NEW.value));
    END IF;
    RETURN NULL;
END
$$;
-- +goose StatementEnd
CREATE TRIGGER vendor_settings_audit AFTER INSERT OR UPDATE ON vendor_settings
    FOR EACH ROW EXECUTE FUNCTION vendor_audit_settings();

-- +goose StatementBegin
CREATE OR REPLACE FUNCTION vendor_audit_web() RETURNS trigger LANGUAGE plpgsql SECURITY DEFINER SET search_path = public, pg_temp AS $$
BEGIN
    IF TG_TABLE_NAME = 'web_users' THEN
        IF TG_OP = 'INSERT' THEN
            PERFORM audit_append('webuser.add', NEW.name, '{}'::jsonb);
        ELSE
            IF NEW.disabled_at IS DISTINCT FROM OLD.disabled_at THEN
                PERFORM audit_append(CASE WHEN NEW.disabled_at IS NULL THEN 'webuser.enable' ELSE 'webuser.disable' END, NEW.name, '{}'::jsonb);
            END IF;
            IF NEW.email IS DISTINCT FROM OLD.email THEN
                PERFORM audit_append('webuser.email', NEW.name, jsonb_build_object('email', NEW.email));
            END IF;
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

-- The owner mail is written by the same statement that inserts the license, whatever client does it.
-- With no owner address the row is kept with an empty recipient list; the sender waits for one.
-- +goose StatementBegin
CREATE FUNCTION vendor_notify_license() RETURNS trigger LANGUAGE plpgsql SECURITY DEFINER SET search_path = public, pg_temp AS $$
DECLARE
    cust  text;
    owner text;
BEGIN
    SELECT name INTO cust FROM customers WHERE id = NEW.customer_id;
    SELECT value INTO owner FROM vendor_settings WHERE key = 'owner_email';
    INSERT INTO mail_outbox (kind, to_addrs, subject, body)
    VALUES ('issued',
            CASE WHEN coalesce(owner, '') = '' THEN '{}'::text[] ELSE ARRAY[owner] END,
            left(regexp_replace(format('License issued: %s (%s)', cust, NEW.license_id), '[\r\n]+', ' ', 'g'), 200),
            format(E'A license was issued.\n\nCustomer: %s\nLicense: %s\nTargets: %s\nValid from: %s\nValid until: %s\nSigned by: %s\nKey id: %s\nRequest: %s\n',
                   cust, NEW.license_id, NEW.targets,
                   to_char(NEW.valid_from AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS"Z"'),
                   to_char(NEW.valid_until AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS"Z"'),
                   NEW.signed_by, NEW.key_id, NEW.request_id));
    RETURN NULL;
END
$$;
-- +goose StatementEnd
CREATE TRIGGER licenses_notify AFTER INSERT ON licenses
    FOR EACH ROW EXECUTE FUNCTION vendor_notify_license();

-- The notifier's one write to settings: remember when the last summary went out.
-- +goose StatementBegin
CREATE FUNCTION notify_mark_summary(ts timestamptz) RETURNS void LANGUAGE sql SECURITY DEFINER SET search_path = public, pg_temp AS $$
    INSERT INTO vendor_settings (key, value) VALUES ('last_summary_at', to_char(ts AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS"Z"'))
    ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value
$$;
-- +goose StatementEnd

-- Privileges. Nothing is granted to PUBLIC.
REVOKE ALL ON vendor_settings, mail_outbox, reminders FROM PUBLIC;
REVOKE ALL ON FUNCTION vendor_settings_stamp(), vendor_audit_settings(), vendor_notify_license(), notify_mark_summary(timestamptz) FROM PUBLIC;

GRANT SELECT, INSERT ON vendor_settings TO vendor_owner;
GRANT UPDATE (value) ON vendor_settings TO vendor_owner;
GRANT UPDATE (email) ON web_users TO vendor_owner;

GRANT USAGE ON SCHEMA public TO vendor_notifier;
GRANT SELECT (license_id, request_id, customer_id, installation, key_id, issued_at, valid_from, valid_until,
              targets, replaces, file_sha256, signed_by, revoked_at) ON licenses TO vendor_notifier;
GRANT SELECT ON customers, license_requests, web_users, vendor_settings, audit TO vendor_notifier;
GRANT SELECT, INSERT ON reminders TO vendor_notifier;
GRANT SELECT, INSERT, UPDATE ON mail_outbox TO vendor_notifier;
GRANT EXECUTE ON FUNCTION notify_mark_summary(timestamptz) TO vendor_notifier;

-- +goose Down
DROP FUNCTION notify_mark_summary(timestamptz);
DROP TRIGGER licenses_notify ON licenses;
DROP FUNCTION vendor_notify_license();
DROP TABLE reminders, mail_outbox;
DROP TABLE vendor_settings;
DROP FUNCTION vendor_audit_settings();
DROP FUNCTION vendor_settings_stamp();
-- +goose StatementBegin
CREATE OR REPLACE FUNCTION vendor_audit_web() RETURNS trigger LANGUAGE plpgsql SECURITY DEFINER SET search_path = public, pg_temp AS $$
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
ALTER TABLE web_users DROP COLUMN email;
REVOKE USAGE ON SCHEMA public FROM vendor_notifier;
