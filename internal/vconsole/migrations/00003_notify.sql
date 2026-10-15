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

-- Settings. Only keys the code knows.
CREATE TABLE vendor_settings (
    key        text PRIMARY KEY CHECK (key IN ('timezone', 'last_summary_at')),
    value      text NOT NULL CHECK (length(value) <= 254),
    updated_by text,
    updated_at timestamptz
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

-- What a web user may see. The role is set when the user is created (vendor_owner may INSERT it)
-- and nobody but the migration login can change it afterwards: there is no UPDATE grant on it.
ALTER TABLE web_users ADD COLUMN role text NOT NULL DEFAULT 'sales'
    CONSTRAINT web_users_role_check CHECK (role IN ('sales', 'owner'));

CREATE TABLE reminders (
    license_id  text NOT NULL REFERENCES licenses (license_id),
    days_before integer NOT NULL CHECK (days_before IN (90, 60, 30)),
    created_at  timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (license_id, days_before)
);

-- In-app notifications, shown by the web service. audience 'owner' is for web users with the role
-- owner, 'sales' for every web user, 'user' for the one web user named in target_user. The title is
-- one line (no control or line-separator characters). dedupe_key makes every notification unique,
-- so writers use INSERT ... ON CONFLICT (dedupe_key) DO NOTHING and concurrent runs write it once.
CREATE TABLE notifications (
    id          bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    kind        text NOT NULL CHECK (length(kind) BETWEEN 1 AND 40),
    severity    text NOT NULL DEFAULT 'info' CHECK (severity IN ('info', 'warning', 'alert')),
    title       text NOT NULL CHECK (length(title) BETWEEN 1 AND 200 AND title !~ '[\u0001-\u001f\u007f-\u009f  ]'),
    body        text NOT NULL DEFAULT '' CHECK (length(body) <= 4000),
    audience    text NOT NULL CHECK (audience IN ('owner', 'sales', 'user')),
    target_user text CHECK (target_user ~ '^[A-Za-z0-9._-]{1,64}$'),
    subject     text NOT NULL DEFAULT '' CHECK (length(subject) <= 64),
    created_at  timestamptz NOT NULL DEFAULT now(),
    dedupe_key  text NOT NULL UNIQUE CHECK (length(dedupe_key) BETWEEN 1 AND 200),
    CONSTRAINT notifications_target_check CHECK ((audience = 'user') = (target_user IS NOT NULL))
);
CREATE INDEX notifications_created_idx ON notifications (created_at);

-- Per-user read state. Rows are written only by web_mark_read and web_mark_all_read.
CREATE TABLE notification_reads (
    notification_id bigint NOT NULL REFERENCES notifications (id) ON DELETE CASCADE,
    user_id         bigint NOT NULL REFERENCES web_users (id),
    read_at         timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (notification_id, user_id)
);
CREATE INDEX notification_reads_user_idx ON notification_reads (user_id);

-- Settings changes are audited, with the new value (never a secret).
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

-- The web user audit now records the role at creation and any later role change (only the
-- migration login can make one, but it must not go unrecorded).
-- +goose StatementBegin
CREATE OR REPLACE FUNCTION vendor_audit_web() RETURNS trigger LANGUAGE plpgsql SECURITY DEFINER SET search_path = public, pg_temp AS $$
BEGIN
    IF TG_TABLE_NAME = 'web_users' THEN
        IF TG_OP = 'INSERT' THEN
            PERFORM audit_append('webuser.add', NEW.name, jsonb_build_object('role', NEW.role));
        ELSE
            IF NEW.disabled_at IS DISTINCT FROM OLD.disabled_at THEN
                PERFORM audit_append(CASE WHEN NEW.disabled_at IS NULL THEN 'webuser.enable' ELSE 'webuser.disable' END, NEW.name, '{}'::jsonb);
            END IF;
            IF NEW.role IS DISTINCT FROM OLD.role THEN
                PERFORM audit_append('webuser.role', NEW.name, jsonb_build_object('from', OLD.role, 'to', NEW.role));
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

-- One line of display text from a free-text value: every run of control characters (line breaks,
-- escape sequences, C1 controls), line and paragraph separators and bidi or zero-width format
-- characters becomes one space, then the first 200 characters are kept. The \u escapes are read by
-- the regex engine (standard_conforming_strings). The set covers everything the notifications title
-- check refuses, so a cleaned value can never make an insert fail.
-- +goose StatementBegin
CREATE FUNCTION vendor_clean_line(s text) RETURNS text LANGUAGE sql IMMUTABLE AS $$
    SELECT left(regexp_replace(s,
        '[[:cntrl:]\u0001-\u001f\u007f-\u009f­؜᠎​-‏ -‮⁠-⁯﻿￹-￻]+', ' ', 'g'), 200)
$$;
-- +goose StatementEnd

-- The owner notification is written by the same statement that inserts the license, whatever
-- client does it (a signer or owner login with raw SQL included): the function runs as its owner.
-- It must never make the license insert fail, so every interpolated value is cleaned and bounded
-- and the result fits every check of notifications. "Signed by" is the acting login
-- (vendor_actor(), as in the audit row): signed_by is only a column default the inserting client
-- can override, so a different value is shown as "Recorded signer". No installation ID, no file.
-- A license id too long for the dedupe key (real ones are short) is keyed by its hash instead.
-- +goose StatementBegin
CREATE FUNCTION vendor_notify_license() RETURNS trigger LANGUAGE plpgsql SECURITY DEFINER SET search_path = public, pg_temp AS $$
DECLARE
    cust  text;
    actor text := vendor_actor();
BEGIN
    SELECT name INTO cust FROM customers WHERE id = NEW.customer_id;
    INSERT INTO notifications (kind, severity, title, body, audience, subject, dedupe_key)
    VALUES ('license.issued', 'info',
            left(vendor_clean_line(format('License issued: %s (%s)', vendor_clean_line(cust), vendor_clean_line(NEW.license_id))), 200),
            left(format(E'A license was issued.\n\nCustomer: %s\nLicense: %s\nTargets: %s\nValid from: %s\nValid until: %s\nSigned by: %s\n%sKey ID: %s\nRequest: %s\n',
                   vendor_clean_line(cust), vendor_clean_line(NEW.license_id), NEW.targets,
                   to_char(NEW.valid_from AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS"Z"'),
                   to_char(NEW.valid_until AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS"Z"'),
                   vendor_clean_line(actor),
                   CASE WHEN NEW.signed_by IS DISTINCT FROM actor
                        THEN format(E'Recorded signer: %s (differs from the login)\n', vendor_clean_line(NEW.signed_by))
                        ELSE '' END,
                   vendor_clean_line(NEW.key_id), NEW.request_id), 4000),
            'owner',
            left(vendor_clean_line(NEW.license_id), 64),
            CASE WHEN length(NEW.license_id) <= 180 THEN 'issued:' || NEW.license_id
                 ELSE 'issued:sha256:' || encode(sha256(convert_to(NEW.license_id, 'UTF8')), 'hex') END)
    ON CONFLICT (dedupe_key) DO NOTHING;
    RETURN NULL;
END
$$;
-- +goose StatementEnd
CREATE TRIGGER licenses_notify AFTER INSERT ON licenses
    FOR EACH ROW EXECUTE FUNCTION vendor_notify_license();

-- The notifier's one write to settings: remember when the last summary was made.
-- +goose StatementBegin
CREATE FUNCTION notify_mark_summary(ts timestamptz) RETURNS void LANGUAGE sql SECURITY DEFINER SET search_path = public, pg_temp AS $$
    INSERT INTO vendor_settings (key, value) VALUES ('last_summary_at', to_char(ts AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS"Z"'))
    ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value
$$;
-- +goose StatementEnd

-- Pruning: a notification older than the cutoff that at least one web user has read is removed
-- (its read rows go with it). Unread ones stay whatever their age, so nothing disappears unseen.
-- The rule is deliberately simple: with several owners, one owner's read is enough.
-- +goose StatementBegin
CREATE FUNCTION notify_prune(p_before timestamptz) RETURNS bigint LANGUAGE plpgsql SECURITY DEFINER SET search_path = public, pg_temp AS $$
DECLARE
    removed bigint;
BEGIN
    DELETE FROM notifications n
     WHERE n.created_at < p_before
       AND EXISTS (SELECT 1 FROM notification_reads r WHERE r.notification_id = n.id);
    GET DIAGNOSTICS removed = ROW_COUNT;
    RETURN removed;
END
$$;
-- +goose StatementEnd

-- The visibility rule, in one place. The user's role and name are read from web_users by id; a
-- disabled or unknown user sees nothing. The owner sees owner and sales notifications and their own
-- user ones, a sales user sees sales notifications and their own. Names compare case-insensitively,
-- as web_users.name is unique case-insensitively. Nobody gets EXECUTE on this helper: only the
-- web_* functions below (running as their owner) call it.
-- +goose StatementBegin
CREATE FUNCTION vendor_notifications_for(p_user_id bigint) RETURNS SETOF notifications
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = public, pg_temp AS $$
    SELECT n.*
      FROM notifications n
      JOIN web_users u ON u.id = p_user_id AND u.disabled_at IS NULL
     WHERE n.audience = 'sales'
        OR (n.audience = 'owner' AND u.role = 'owner')
        OR (n.audience = 'user' AND lower(n.target_user) = lower(u.name))
$$;
-- +goose StatementEnd

-- The web service reads and marks notifications only through these four functions; it has no
-- direct access to notifications or notification_reads, so a bug in the Go code cannot widen what
-- a person sees. The service passes the signed-in user's id, and is trusted to pass the right one
-- exactly as it is trusted to set vendor.actor.
-- +goose StatementBegin
CREATE FUNCTION web_notifications(p_user_id bigint, p_limit integer, p_unread_only boolean)
RETURNS TABLE (id bigint, kind text, severity text, title text, body text, audience text, subject text,
               created_at timestamptz, read_at timestamptz)
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = public, pg_temp AS $$
    SELECT v.id, v.kind, v.severity, v.title, v.body, v.audience, v.subject, v.created_at, r.read_at
      FROM vendor_notifications_for(p_user_id) v
      LEFT JOIN notification_reads r ON r.notification_id = v.id AND r.user_id = p_user_id
     WHERE NOT coalesce(p_unread_only, false) OR r.read_at IS NULL
     ORDER BY v.created_at DESC, v.id DESC
     LIMIT least(greatest(coalesce(p_limit, 100), 0), 500)
$$;
-- +goose StatementEnd

-- +goose StatementBegin
CREATE FUNCTION web_unread_count(p_user_id bigint) RETURNS bigint
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = public, pg_temp AS $$
    SELECT count(*)
      FROM vendor_notifications_for(p_user_id) v
     WHERE NOT EXISTS (SELECT 1 FROM notification_reads r WHERE r.notification_id = v.id AND r.user_id = p_user_id)
$$;
-- +goose StatementEnd

-- Marks one notification read for the user. Returns whether the user can see it; an invisible
-- notification answers exactly like one that does not exist and records nothing. Idempotent.
-- +goose StatementBegin
CREATE FUNCTION web_mark_read(p_user_id bigint, p_notification_id bigint) RETURNS boolean
LANGUAGE plpgsql SECURITY DEFINER SET search_path = public, pg_temp AS $$
BEGIN
    INSERT INTO notification_reads (notification_id, user_id)
    SELECT v.id, p_user_id FROM vendor_notifications_for(p_user_id) v WHERE v.id = p_notification_id
    ON CONFLICT DO NOTHING;
    RETURN EXISTS (SELECT 1 FROM vendor_notifications_for(p_user_id) v WHERE v.id = p_notification_id);
END
$$;
-- +goose StatementEnd

-- Marks every notification the user can see as read; returns how many were newly marked.
-- +goose StatementBegin
CREATE FUNCTION web_mark_all_read(p_user_id bigint) RETURNS bigint
LANGUAGE plpgsql SECURITY DEFINER SET search_path = public, pg_temp AS $$
DECLARE
    marked bigint;
BEGIN
    INSERT INTO notification_reads (notification_id, user_id)
    SELECT v.id, p_user_id FROM vendor_notifications_for(p_user_id) v
    ON CONFLICT DO NOTHING;
    GET DIAGNOSTICS marked = ROW_COUNT;
    RETURN marked;
END
$$;
-- +goose StatementEnd

-- Privileges. Nothing is granted to PUBLIC.
REVOKE ALL ON vendor_settings, reminders, notifications, notification_reads FROM PUBLIC;
REVOKE ALL ON FUNCTION vendor_settings_stamp(), vendor_audit_settings(), vendor_clean_line(text), vendor_notify_license(),
    notify_mark_summary(timestamptz), notify_prune(timestamptz), vendor_notifications_for(bigint),
    web_notifications(bigint, integer, boolean), web_unread_count(bigint), web_mark_read(bigint, bigint),
    web_mark_all_read(bigint) FROM PUBLIC;

GRANT SELECT, INSERT ON vendor_settings TO vendor_owner;
GRANT UPDATE (value) ON vendor_settings TO vendor_owner;
-- The owner reads the reminder record and the notifications (CLI work); only the notifier and the
-- issuance trigger write them.
GRANT SELECT ON reminders, notifications, notification_reads TO vendor_owner;

-- The web service: the four functions only.
GRANT EXECUTE ON FUNCTION web_notifications(bigint, integer, boolean), web_unread_count(bigint),
    web_mark_read(bigint, bigint), web_mark_all_read(bigint) TO vendor_web;

-- The notifier reads only the columns the notify code uses: no customer contacts or notes, no
-- audit details, no license files, no request contents.
GRANT USAGE ON SCHEMA public TO vendor_notifier;
GRANT SELECT (license_id, request_id, customer_id, installation, key_id, issued_at, valid_from, valid_until,
              targets, replaces, file_sha256, signed_by, revoked_at) ON licenses TO vendor_notifier;
GRANT SELECT (id, name) ON customers TO vendor_notifier;
GRANT SELECT (id, customer_id, status, requested_by, requested_at) ON license_requests TO vendor_notifier;
GRANT SELECT (name, disabled_at, role) ON web_users TO vendor_notifier;
GRANT SELECT (at, actor, action, subject) ON audit TO vendor_notifier;
GRANT SELECT ON vendor_settings TO vendor_notifier;
GRANT SELECT, INSERT ON reminders TO vendor_notifier;
-- It creates notifications (created_at is always the database's now()) and never changes them;
-- pruning goes through notify_prune.
GRANT SELECT ON notifications TO vendor_notifier;
GRANT INSERT (kind, severity, title, body, audience, target_user, subject, dedupe_key) ON notifications TO vendor_notifier;
GRANT EXECUTE ON FUNCTION notify_mark_summary(timestamptz), notify_prune(timestamptz) TO vendor_notifier;
-- license_requests has row-level security; the notifier is not a sales member, so it needs its own read policy.
CREATE POLICY requests_read_notifier ON license_requests FOR SELECT TO vendor_notifier USING (true);

-- +goose Down
DROP POLICY requests_read_notifier ON license_requests;
REVOKE SELECT (id, name) ON customers FROM vendor_notifier;
REVOKE SELECT (id, customer_id, status, requested_by, requested_at) ON license_requests FROM vendor_notifier;
REVOKE SELECT (name, disabled_at, role) ON web_users FROM vendor_notifier;
REVOKE SELECT (at, actor, action, subject) ON audit FROM vendor_notifier;
REVOKE ALL ON customers, license_requests, web_users, audit FROM vendor_notifier;
REVOKE ALL ON licenses FROM vendor_notifier;
REVOKE SELECT (license_id, request_id, customer_id, installation, key_id, issued_at, valid_from, valid_until,
               targets, replaces, file_sha256, signed_by, revoked_at) ON licenses FROM vendor_notifier;
DROP FUNCTION web_mark_all_read(bigint);
DROP FUNCTION web_mark_read(bigint, bigint);
DROP FUNCTION web_unread_count(bigint);
DROP FUNCTION web_notifications(bigint, integer, boolean);
DROP FUNCTION vendor_notifications_for(bigint);
DROP FUNCTION notify_prune(timestamptz);
DROP FUNCTION notify_mark_summary(timestamptz);
DROP TRIGGER licenses_notify ON licenses;
DROP FUNCTION vendor_notify_license();
DROP FUNCTION vendor_clean_line(text);
DROP TABLE notification_reads, notifications, reminders;
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
ALTER TABLE web_users DROP COLUMN role;
REVOKE USAGE ON SCHEMA public FROM vendor_notifier;
