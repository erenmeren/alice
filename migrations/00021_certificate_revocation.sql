-- +goose Up
-- Certificate revocation and key-compromise incidents (owner decision 2026-10-20,
-- docs/superpowers/rulings/certificate-revocation.md).
--
-- A certificate version (a certificates row) can be revoked at its CA (RFC 8555 section 7.6; only one Alice ordered over
-- ACME) and marked compromised by Alice (its private key is no longer secret: any source). Both marks are final: once set
-- they never change or clear (SQLSTATE Z1022), and a deployment of a certificate carrying either is refused.
ALTER TABLE certificates ADD COLUMN revoked_at timestamptz;
ALTER TABLE certificates ADD COLUMN revocation_reason text NOT NULL DEFAULT ''
    CHECK (revocation_reason IN ('', 'unspecified', 'keyCompromise', 'affiliationChanged', 'superseded', 'cessationOfOperation'));
ALTER TABLE certificates ADD COLUMN revoked_by uuid REFERENCES users (id);
ALTER TABLE certificates ADD COLUMN compromised_at timestamptz;
ALTER TABLE certificates ADD COLUMN compromised_by uuid REFERENCES users (id);
ALTER TABLE certificates ADD CONSTRAINT certificates_revocation CHECK ((revoked_at IS NULL) = (revocation_reason = '')
    AND (revoked_at IS NOT NULL OR revoked_by IS NULL));
ALTER TABLE certificates ADD CONSTRAINT certificates_compromise CHECK (compromised_at IS NOT NULL OR compromised_by IS NULL);

-- +goose StatementBegin
CREATE FUNCTION certificates_protect_revocation() RETURNS trigger LANGUAGE plpgsql
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
GRANT UPDATE (revoked_at, revocation_reason, revoked_by, compromised_at, compromised_by) ON certificates TO alice_app;

-- The impact of a compromised key reaches certificates found by network discovery too: their public key hash (the
-- SHA-256 of the SubjectPublicKeyInfo, as certificates.public_key_sha256). '' for a row stored before this migration,
-- until a scan sees the certificate again (the ingest fills it then).
ALTER TABLE discovery_certificates ADD COLUMN public_key_sha256 text NOT NULL DEFAULT ''
    CHECK (public_key_sha256 ~ '^([0-9a-f]{64})?$');
CREATE INDEX discovery_certificates_public_key ON discovery_certificates (public_key_sha256) WHERE public_key_sha256 <> '';
GRANT UPDATE (public_key_sha256) ON discovery_certificates TO alice_app;

-- One key-compromise incident: a certificate whose private key is no longer secret, replaced everywhere it is deployed and
-- (for a certificate Alice ordered over ACME) revoked at its CA with reason keyCompromise. state:
--   awaiting_replacement  a certificate from another source waits for a person to choose its replacement
--   ordering              the ACME certificate is being ordered again, with a new key (order_id)
--   deploying             the replacement is being deployed to the affected locations (certificate_incident_locations)
--   revoking              every location is verified: the compromised ACME certificate is being revoked
--   needs_attention       a step failed (attention_code); a person retries, revokes regardless or closes the incident
--   completed / closed    finished by Alice (everything done) or by a person (closed as it stood)
-- revoke_mode: after_verified (revoke once every location is verified) or now (a person chose to revoke regardless).
-- revocation: pending, revoked, failed (the CA refused: attention), not_possible (not an ACME certificate: the issuing CA
-- must revoke it; Alice marked it compromised). revoke_attempts and next_attempt_at pace revocations the CA could not
-- answer. At most one open incident per certificate.
CREATE TABLE certificate_incidents (
    id                         uuid PRIMARY KEY,
    certificate_id             uuid NOT NULL REFERENCES certificates (id),
    public_key_sha256          text NOT NULL CHECK (public_key_sha256 ~ '^[0-9a-f]{64}$'),
    acme_certificate_id        uuid REFERENCES acme_certificates (id),
    state                      text NOT NULL CHECK (state IN ('awaiting_replacement', 'ordering', 'deploying', 'revoking', 'needs_attention',
                                   'completed', 'closed')),
    revoke_mode                text NOT NULL DEFAULT 'after_verified' CHECK (revoke_mode IN ('after_verified', 'now')),
    revocation                 text NOT NULL CHECK (revocation IN ('pending', 'revoked', 'failed', 'not_possible')),
    order_id                   uuid REFERENCES acme_orders (id),
    replacement_certificate_id uuid REFERENCES certificates (id),
    attention_code             text NOT NULL DEFAULT '' CHECK (attention_code ~ '^[A-Za-z0-9._-]{0,100}$'),
    revoke_attempts            integer NOT NULL DEFAULT 0 CHECK (revoke_attempts >= 0),
    next_attempt_at            timestamptz,
    revoked_at                 timestamptz,
    started_by                 uuid REFERENCES users (id),
    closed_by                  uuid REFERENCES users (id),
    created_at                 timestamptz NOT NULL,
    updated_at                 timestamptz NOT NULL,
    finished_at                timestamptz,
    CHECK ((state IN ('completed', 'closed')) = (finished_at IS NOT NULL)),
    CHECK ((state = 'needs_attention') = (attention_code <> '')),
    CHECK ((acme_certificate_id IS NULL) = (revocation = 'not_possible')),
    CHECK ((revocation = 'revoked') = (revoked_at IS NOT NULL)),
    CHECK (replacement_certificate_id IS NULL OR replacement_certificate_id <> certificate_id)
);
CREATE UNIQUE INDEX certificate_incidents_one_open ON certificate_incidents (certificate_id) WHERE finished_at IS NULL;
CREATE INDEX certificate_incidents_open ON certificate_incidents (created_at, id) WHERE finished_at IS NULL;
CREATE INDEX certificate_incidents_created ON certificate_incidents (created_at DESC, id DESC);
CREATE INDEX certificate_incidents_key ON certificate_incidents (public_key_sha256);

-- One affected location of an incident and how its replacement went: pending (not requested yet), deploying
-- (deployment_id runs), verified (deployed and checked on the server), unverified (deployed, the check was skipped),
-- failed (error_code), skipped (error_code says why Alice does not replace it: another certificate with the same key, a
-- place on a server Alice cannot deploy to). Rows of a finished incident are history.
CREATE TABLE certificate_incident_locations (
    incident_id   uuid NOT NULL REFERENCES certificate_incidents (id),
    location_id   uuid NOT NULL REFERENCES certificate_locations (id),
    status        text NOT NULL CHECK (status IN ('pending', 'deploying', 'verified', 'unverified', 'failed', 'skipped')),
    deployment_id uuid REFERENCES deployments (id),
    error_code    text NOT NULL DEFAULT '' CHECK (error_code ~ '^[A-Za-z0-9._-]{0,100}$'),
    attempts      integer NOT NULL DEFAULT 0 CHECK (attempts >= 0),
    updated_at    timestamptz NOT NULL,
    PRIMARY KEY (incident_id, location_id),
    CHECK ((status IN ('failed', 'skipped')) = (error_code <> '')),
    CHECK (status NOT IN ('deploying', 'verified', 'unverified') OR deployment_id IS NOT NULL)
);
CREATE INDEX certificate_incident_locations_deployment ON certificate_incident_locations (deployment_id) WHERE deployment_id IS NOT NULL;

-- A finished incident and its locations are history (SQLSTATE Z1023).
-- +goose StatementBegin
CREATE FUNCTION certificate_incidents_protect_done() RETURNS trigger LANGUAGE plpgsql
SET search_path = pg_catalog, pg_temp AS $$
BEGIN
    IF TG_TABLE_NAME = 'certificate_incidents' THEN
        IF OLD.finished_at IS NOT NULL THEN
            RAISE EXCEPTION 'a finished incident cannot be changed' USING ERRCODE = 'Z1023';
        END IF;
    ELSIF EXISTS (SELECT 1 FROM public.certificate_incidents i WHERE i.id = NEW.incident_id AND i.finished_at IS NOT NULL FOR SHARE OF i) THEN
        RAISE EXCEPTION 'a finished incident cannot be changed' USING ERRCODE = 'Z1023';
    END IF;
    RETURN NEW;
END $$;
-- +goose StatementEnd
CREATE TRIGGER certificate_incidents_done_frozen BEFORE UPDATE ON certificate_incidents
    FOR EACH ROW EXECUTE FUNCTION certificate_incidents_protect_done();
CREATE TRIGGER certificate_incident_locations_done_frozen BEFORE INSERT OR UPDATE ON certificate_incident_locations
    FOR EACH ROW EXECUTE FUNCTION certificate_incidents_protect_done();

GRANT SELECT, INSERT ON certificate_incidents, certificate_incident_locations TO alice_app;
GRANT UPDATE (state, revoke_mode, revocation, order_id, replacement_certificate_id, attention_code, revoke_attempts, next_attempt_at,
    revoked_at, closed_by, updated_at, finished_at) ON certificate_incidents TO alice_app;
GRANT UPDATE (status, deployment_id, error_code, attempts, updated_at) ON certificate_incident_locations TO alice_app;

-- +goose Down
DROP TABLE certificate_incident_locations;
DROP TABLE certificate_incidents;
DROP FUNCTION certificate_incidents_protect_done();
REVOKE UPDATE (public_key_sha256) ON discovery_certificates FROM alice_app;
DROP INDEX discovery_certificates_public_key;
ALTER TABLE discovery_certificates DROP COLUMN public_key_sha256;
REVOKE UPDATE (revoked_at, revocation_reason, revoked_by, compromised_at, compromised_by) ON certificates FROM alice_app;
DROP TRIGGER certificates_revocation_final ON certificates;
DROP FUNCTION certificates_protect_revocation();
ALTER TABLE certificates DROP CONSTRAINT certificates_compromise;
ALTER TABLE certificates DROP CONSTRAINT certificates_revocation;
ALTER TABLE certificates DROP COLUMN compromised_by;
ALTER TABLE certificates DROP COLUMN compromised_at;
ALTER TABLE certificates DROP COLUMN revoked_by;
ALTER TABLE certificates DROP COLUMN revocation_reason;
ALTER TABLE certificates DROP COLUMN revoked_at;
