-- +goose Up
-- Emergency extensions (docs/superpowers/rulings/vendor-emergency-extension.md): a request of kind
-- 'emergency' asks for a short license (1 to 30 days, from the signing day) for an installation
-- whose license lapsed, carrying over the customer, installation, targets and features of the
-- installation's latest license (extends). It needs a reason. It is signed like any request; the
-- signed license is an ordinary license, so the label lives only here, in the audit log and in
-- the owner's notification. A normal request keeps every column as before.
ALTER TABLE license_requests
    ADD COLUMN kind    text NOT NULL DEFAULT 'license' CHECK (kind IN ('license', 'emergency')),
    ADD COLUMN days    integer CHECK (days BETWEEN 1 AND 30),
    ADD COLUMN reason  text NOT NULL DEFAULT '' CHECK (length(reason) <= 200),
    ADD COLUMN extends text NOT NULL DEFAULT '' CHECK (length(extends) <= 64);
-- An extension has a term in days and no months, start date or replaced license.
ALTER TABLE license_requests ALTER COLUMN months DROP NOT NULL;
ALTER TABLE license_requests ADD CONSTRAINT license_requests_kind_shape CHECK (
    (kind = 'license' AND months IS NOT NULL AND days IS NULL AND reason = '' AND extends = '')
    OR (kind = 'emergency' AND months IS NULL AND days IS NOT NULL AND valid_from = '' AND replaces = ''
        AND extends <> '' AND btrim(reason) <> ''));

-- request.add of an extension says so, with its term, reason and the license it carries over.
-- +goose StatementBegin
CREATE OR REPLACE FUNCTION vendor_audit_requests() RETURNS trigger LANGUAGE plpgsql SECURITY DEFINER SET search_path = public, pg_temp AS $$
BEGIN
    IF TG_OP = 'INSERT' THEN
        IF NEW.kind = 'emergency' THEN
            PERFORM audit_append('request.add', NEW.id::text, jsonb_build_object('customer_id', NEW.customer_id,
                'installation', NEW.installation, 'targets', NEW.targets, 'kind', 'emergency', 'days', NEW.days,
                'reason', vendor_clean_line(NEW.reason), 'extends', NEW.extends));
        ELSE
            PERFORM audit_append('request.add', NEW.id::text, jsonb_build_object('customer_id', NEW.customer_id,
                'installation', NEW.installation, 'targets', NEW.targets));
        END IF;
    ELSIF NEW.status IS DISTINCT FROM OLD.status THEN
        PERFORM audit_append('request.' || NEW.status, NEW.id::text, jsonb_build_object('from', OLD.status));
    ELSE
        PERFORM audit_append('request.edit', NEW.id::text, jsonb_build_object('old', to_jsonb(OLD), 'new', to_jsonb(NEW)));
    END IF;
    RETURN NULL;
END
$$;
-- +goose StatementEnd

-- license.issue of an extension says so (the request row is the record of what it is).
-- +goose StatementBegin
CREATE OR REPLACE FUNCTION vendor_audit_licenses() RETURNS trigger LANGUAGE plpgsql SECURITY DEFINER SET search_path = public, pg_temp AS $$
DECLARE
    reason text := left(btrim(regexp_replace(coalesce(current_setting('vendor.reason', true), ''),
        '[\u0001-\u001f\u007f-\u009f\u00ad\u200b-\u200f\u2028-\u202e\u2060-\u2069\u061c\u180e\u206a-\u206f\ufeff\ufff9-\ufffb]', ' ', 'g')), 200);
    details jsonb;
    rk text;
    rd integer;
BEGIN
    IF TG_OP = 'INSERT' THEN
        details := jsonb_build_object('request', NEW.request_id,
            'customer_id', NEW.customer_id, 'installation', NEW.installation, 'targets', NEW.targets,
            'valid_until', NEW.valid_until, 'key_id', NEW.key_id, 'file_sha256', NEW.file_sha256,
            'replaces', NEW.replaces);
        SELECT kind, days INTO rk, rd FROM license_requests WHERE id = NEW.request_id;
        IF rk = 'emergency' THEN
            details := details || jsonb_build_object('kind', 'emergency', 'days', rd);
        END IF;
        PERFORM audit_append('license.issue', NEW.license_id, details);
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

-- The owner's notification names an extension as one, with its term and reason.
-- +goose StatementBegin
CREATE OR REPLACE FUNCTION vendor_notify_license() RETURNS trigger LANGUAGE plpgsql SECURITY DEFINER SET search_path = public, pg_temp AS $$
DECLARE
    cust  text;
    actor text := vendor_actor();
    rk    text;
    rd    integer;
    rr    text;
BEGIN
    SELECT name INTO cust FROM customers WHERE id = NEW.customer_id;
    SELECT kind, days, reason INTO rk, rd, rr FROM license_requests WHERE id = NEW.request_id;
    INSERT INTO notifications (kind, severity, title, body, audience, subject, dedupe_key)
    VALUES ('license.issued', 'info',
            left(vendor_clean_line(format('%s: %s (%s)',
                CASE WHEN rk = 'emergency' THEN 'Emergency extension issued' ELSE 'License issued' END,
                vendor_clean_line(cust), vendor_clean_line(NEW.license_id))), 200),
            left(format(E'%s\n\nCustomer: %s\nLicense: %s\nTargets: %s\nValid from: %s\nValid until: %s\n%sSigned by: %s\n%sKey ID: %s\nRequest: %s\n',
                   CASE WHEN rk = 'emergency' THEN 'An emergency extension was issued.' ELSE 'A license was issued.' END,
                   vendor_clean_line(cust), vendor_clean_line(NEW.license_id), NEW.targets,
                   to_char(NEW.valid_from AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS"Z"'),
                   to_char(NEW.valid_until AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS"Z"'),
                   CASE WHEN rk = 'emergency'
                        THEN format(E'Emergency extension: %s days\nReason: %s\n', rd, vendor_clean_line(coalesce(rr, '')))
                        ELSE '' END,
                   vendor_clean_line(actor),
                   CASE WHEN NEW.signed_by IS DISTINCT FROM actor
                        THEN format(E'Recorded signer: %s (differs from the login)\n', vendor_clean_line(NEW.signed_by))
                        ELSE '' END,
                   vendor_clean_line(NEW.key_id), NEW.request_id), 4000),
            'owner',
            left(vendor_clean_line(NEW.license_id), 64),
            CASE WHEN length(NEW.license_id) <= 180 THEN 'issued:' || NEW.license_id
                 ELSE 'issued-sha256:' || encode(sha256(convert_to(NEW.license_id, 'UTF8')), 'hex') END)
    ON CONFLICT (dedupe_key) DO NOTHING;
    RETURN NULL;
END
$$;
-- +goose StatementEnd

-- +goose Down
-- Refuses (NOT NULL) while an extension request exists: its row cannot be expressed without them.
-- +goose StatementBegin
CREATE OR REPLACE FUNCTION vendor_notify_license() RETURNS trigger LANGUAGE plpgsql SECURITY DEFINER SET search_path = public, pg_temp AS $$
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
                 ELSE 'issued-sha256:' || encode(sha256(convert_to(NEW.license_id, 'UTF8')), 'hex') END)
    ON CONFLICT (dedupe_key) DO NOTHING;
    RETURN NULL;
END
$$;
-- +goose StatementEnd
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
-- +goose StatementBegin
CREATE OR REPLACE FUNCTION vendor_audit_requests() RETURNS trigger LANGUAGE plpgsql SECURITY DEFINER SET search_path = public, pg_temp AS $$
BEGIN
    IF TG_OP = 'INSERT' THEN
        PERFORM audit_append('request.add', NEW.id::text, jsonb_build_object('customer_id', NEW.customer_id,
            'installation', NEW.installation, 'targets', NEW.targets));
    ELSIF NEW.status IS DISTINCT FROM OLD.status THEN
        PERFORM audit_append('request.' || NEW.status, NEW.id::text, jsonb_build_object('from', OLD.status));
    ELSE
        PERFORM audit_append('request.edit', NEW.id::text, jsonb_build_object('old', to_jsonb(OLD), 'new', to_jsonb(NEW)));
    END IF;
    RETURN NULL;
END
$$;
-- +goose StatementEnd
ALTER TABLE license_requests DROP CONSTRAINT license_requests_kind_shape;
ALTER TABLE license_requests ALTER COLUMN months SET NOT NULL;
ALTER TABLE license_requests DROP COLUMN extends, DROP COLUMN reason, DROP COLUMN days, DROP COLUMN kind;
