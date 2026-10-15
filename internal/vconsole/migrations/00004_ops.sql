-- +goose Up
-- The newest audit row and its hash: the checkpoint the weekly summary notification shows the owner
-- (who copies it into the paper log). The notifier has no column grant on audit, so it reads the
-- head only through this function.
-- +goose StatementBegin
CREATE FUNCTION audit_head() RETURNS TABLE (seq bigint, hash text)
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = public, pg_temp AS $$
    SELECT a.seq, a.hash FROM audit a ORDER BY a.seq DESC LIMIT 1
$$;
-- +goose StatementEnd

REVOKE ALL ON FUNCTION audit_head() FROM PUBLIC;
GRANT EXECUTE ON FUNCTION audit_head() TO vendor_owner, vendor_notifier;

-- A revoke records why. The store sets the transaction-local setting vendor.reason in the same
-- transaction as the UPDATE; the trigger copies it into the license.revoke details. Control and
-- format characters (line breaks, bidi marks) become spaces and the text is cut to 200 characters,
-- so a caller that skips the Go checks still cannot put a multi-line or spoofed text in the audit.
-- An empty or missing setting keeps the old details.
-- +goose StatementBegin
CREATE OR REPLACE FUNCTION vendor_audit_licenses() RETURNS trigger LANGUAGE plpgsql SECURITY DEFINER SET search_path = public, pg_temp AS $$
DECLARE
    reason text := left(btrim(regexp_replace(coalesce(current_setting('vendor.reason', true), ''),
        '[\u0001-\u001f\u007f-\u009f\u00ad\u200b-\u200f\u2028-\u202e\u2060-\u2069\u061c\u180e\u206a-\u206f\ufeff\ufff9-\ufffb]', ' ', 'g')), 200);
BEGIN
    IF TG_OP = 'INSERT' THEN
        PERFORM audit_append('license.issue', NEW.license_id, jsonb_build_object('request', NEW.request_id,
            'customer_id', NEW.customer_id, 'installation', NEW.installation, 'targets', NEW.targets,
            'valid_until', NEW.valid_until, 'key_id', NEW.key_id, 'file_sha256', NEW.file_sha256,
            'replaces', NEW.replaces));
    ELSIF NEW.revoked_at IS DISTINCT FROM OLD.revoked_at THEN
        IF reason = '' THEN
            PERFORM audit_append('license.revoke', NEW.license_id, jsonb_build_object('revoked_at', NEW.revoked_at));
        ELSE
            PERFORM audit_append('license.revoke', NEW.license_id, jsonb_build_object('revoked_at', NEW.revoked_at,
                'reason', reason));
        END IF;
    END IF;
    RETURN NULL;
END
$$;
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
CREATE OR REPLACE FUNCTION vendor_audit_licenses() RETURNS trigger LANGUAGE plpgsql SECURITY DEFINER SET search_path = public, pg_temp AS $$
BEGIN
    IF TG_OP = 'INSERT' THEN
        PERFORM audit_append('license.issue', NEW.license_id, jsonb_build_object('request', NEW.request_id,
            'customer_id', NEW.customer_id, 'installation', NEW.installation, 'targets', NEW.targets,
            'valid_until', NEW.valid_until, 'key_id', NEW.key_id, 'file_sha256', NEW.file_sha256,
            'replaces', NEW.replaces));
    ELSIF NEW.revoked_at IS DISTINCT FROM OLD.revoked_at THEN
        PERFORM audit_append('license.revoke', NEW.license_id, jsonb_build_object('revoked_at', NEW.revoked_at));
    END IF;
    RETURN NULL;
END
$$;
-- +goose StatementEnd
DROP FUNCTION audit_head();
