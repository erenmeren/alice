-- +goose Up
-- Hardening batch 1, D5 (R64 Rulings 14 to 20): Alice asks the authority that issued each certificate whether it was
-- revoked (OCSP, then CRL). revocation_checks holds the last result per certificate (by fingerprint: an inventory
-- certificate or a leaf network discovery found) and when to check it again. A revocation the authority signed marks
-- an inventory certificate revoked for good (revoked_at, final since 00021, Z1022), with revocation_seen naming how
-- Alice learned it; certificateHold is recorded here only (the authority can lift it).
CREATE TABLE revocation_checks (
    fingerprint_sha256 text PRIMARY KEY CHECK (fingerprint_sha256 ~ '^[0-9a-f]{64}$'),
    status        text NOT NULL CHECK (status IN ('good', 'revoked', 'on_hold', 'unknown', 'unavailable', 'not_checkable')),
    method        text NOT NULL DEFAULT '' CHECK (method IN ('', 'ocsp', 'crl')),
    revoked_at    timestamptz,
    reason        text NOT NULL DEFAULT '' CHECK (reason IN ('', 'unspecified', 'keyCompromise', 'cACompromise', 'affiliationChanged',
                      'superseded', 'cessationOfOperation', 'certificateHold', 'privilegeWithdrawn', 'aACompromise')),
    error_code    text NOT NULL DEFAULT '' CHECK (error_code ~ '^[a-z0-9._]{0,100}$'),
    failures      integer NOT NULL DEFAULT 0 CHECK (failures >= 0),
    checked_at    timestamptz NOT NULL,
    next_check_at timestamptz NOT NULL,
    notified_at   timestamptz,
    CHECK ((status IN ('revoked', 'on_hold')) = (revoked_at IS NOT NULL)),
    CHECK ((status IN ('unavailable', 'not_checkable')) = (error_code <> ''))
);
CREATE INDEX revocation_checks_due ON revocation_checks (next_check_at);
GRANT SELECT, INSERT, UPDATE, DELETE ON revocation_checks TO alice_app;

-- The reasons an authority can give are the RFC 5280 final ones: cACompromise, privilegeWithdrawn and aACompromise join
-- the four Alice could ask for (certificateHold is not final and removeFromCRL is no revocation).
ALTER TABLE certificates DROP CONSTRAINT certificates_revocation_reason_check;
ALTER TABLE certificates ADD CONSTRAINT certificates_revocation_reason_check CHECK (revocation_reason IN ('', 'unspecified', 'keyCompromise',
    'cACompromise', 'affiliationChanged', 'superseded', 'cessationOfOperation', 'privilegeWithdrawn', 'aACompromise'));

-- How Alice learned of a revocation she did not ask for ('' for her own): frozen with the revocation.
ALTER TABLE certificates ADD COLUMN revocation_seen text NOT NULL DEFAULT '' CHECK (revocation_seen IN ('', 'ocsp', 'crl'));
ALTER TABLE certificates ADD CONSTRAINT certificates_revocation_seen CHECK (revocation_seen = '' OR revoked_at IS NOT NULL);
GRANT UPDATE (revocation_seen) ON certificates TO alice_app;

-- +goose StatementBegin
CREATE OR REPLACE FUNCTION certificates_protect_revocation() RETURNS trigger LANGUAGE plpgsql
SET search_path = pg_catalog, pg_temp AS $$
BEGIN
    IF (OLD.revoked_at IS NOT NULL AND (NEW.revoked_at, NEW.revocation_reason, NEW.revoked_by, NEW.revocation_seen)
            IS DISTINCT FROM (OLD.revoked_at, OLD.revocation_reason, OLD.revoked_by, OLD.revocation_seen))
       OR (OLD.compromised_at IS NOT NULL AND (NEW.compromised_at, NEW.compromised_by)
            IS DISTINCT FROM (OLD.compromised_at, OLD.compromised_by)) THEN
        RAISE EXCEPTION 'a revoked or compromised certificate stays so' USING ERRCODE = 'Z1022';
    END IF;
    RETURN NEW;
END $$;
-- +goose StatementEnd
DROP TRIGGER certificates_revocation_final ON certificates;
CREATE TRIGGER certificates_revocation_final BEFORE UPDATE OF revoked_at, revocation_reason, revoked_by, revocation_seen, compromised_at, compromised_by
    ON certificates FOR EACH ROW EXECUTE FUNCTION certificates_protect_revocation();

-- An installation that existed before this migration keeps the check off until an administrator switches it on (R64
-- Ruling 19): new outbound traffic after an update can trip a customer's egress rules. A new installation (no user yet)
-- has no row, which reads as on.
INSERT INTO settings (key, value, updated_at) SELECT 'revocation.check', '{"enabled": false, "version": 0}', now()
WHERE EXISTS (SELECT 1 FROM users) ON CONFLICT (key) DO NOTHING;

-- +goose Down
-- +goose StatementBegin
DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM certificates WHERE revocation_seen <> ''
               OR revocation_reason IN ('cACompromise', 'privilegeWithdrawn', 'aACompromise')) THEN
        RAISE EXCEPTION 'a certificate carries a revocation the authority reported; it cannot be represented before 00034';
    END IF;
END $$;
-- +goose StatementEnd
DROP TRIGGER certificates_revocation_final ON certificates;
-- +goose StatementBegin
CREATE OR REPLACE FUNCTION certificates_protect_revocation() RETURNS trigger LANGUAGE plpgsql
SET search_path = pg_catalog, pg_temp AS $$
BEGIN
    IF (OLD.revoked_at IS NOT NULL AND (NEW.revoked_at, NEW.revocation_reason, NEW.revoked_by)
            IS DISTINCT FROM (OLD.revoked_at, OLD.revocation_reason, OLD.revoked_by))
       OR (OLD.compromised_at IS NOT NULL AND (NEW.compromised_at, NEW.compromised_by)
            IS DISTINCT FROM (OLD.compromised_at, OLD.compromised_by)) THEN
        RAISE EXCEPTION 'a revoked or compromised certificate stays so' USING ERRCODE = 'Z1022';
    END IF;
    RETURN NEW;
END $$;
-- +goose StatementEnd
CREATE TRIGGER certificates_revocation_final BEFORE UPDATE OF revoked_at, revocation_reason, revoked_by, compromised_at, compromised_by
    ON certificates FOR EACH ROW EXECUTE FUNCTION certificates_protect_revocation();
ALTER TABLE certificates DROP CONSTRAINT certificates_revocation_seen;
ALTER TABLE certificates DROP COLUMN revocation_seen;
ALTER TABLE certificates DROP CONSTRAINT certificates_revocation_reason_check;
ALTER TABLE certificates ADD CONSTRAINT certificates_revocation_reason_check
    CHECK (revocation_reason IN ('', 'unspecified', 'keyCompromise', 'affiliationChanged', 'superseded', 'cessationOfOperation'));
DROP TABLE revocation_checks;
DELETE FROM settings WHERE key = 'revocation.check';
