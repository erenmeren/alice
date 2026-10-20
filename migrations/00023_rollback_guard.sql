-- +goose Up
-- No rollback puts a revoked or compromised certificate or key back on a server (R48, owner decision 2026-10-20,
-- docs/superpowers/rulings/certificate-revocation.md "Rollback guard").
--
-- A deployment records, with its send values, which certificate the file it replaces held (the backup a rollback would
-- put back): its leaf fingerprint and public key hash, '' when Alice did not know the file's certificate. The engine
-- checks them against the revocation and compromise marks of certificates (00021) at the start and again before every
-- rollback, so a compromise marked while the deployment runs still applies; a rollback the guard refuses restores
-- nothing and ends the deployment rollback_failed with deployment.rollback_forbidden, phase restore_forbidden when the
-- helper recorded the refusal itself.
ALTER TABLE deployments ADD COLUMN rollback_leaf_sha256 text NOT NULL DEFAULT '' CHECK (rollback_leaf_sha256 ~ '^([0-9a-f]{64})?$');
ALTER TABLE deployments ADD COLUMN rollback_spki_sha256 text NOT NULL DEFAULT '' CHECK (rollback_spki_sha256 ~ '^([0-9a-f]{64})?$');
ALTER TABLE deployments DROP CONSTRAINT deployments_phase_check;
ALTER TABLE deployments ADD CONSTRAINT deployments_phase_check CHECK (phase IN ('', 'none', 'prepared', 'writing', 'committed', 'unchanged',
    'restoring', 'restored', 'restore_failed', 'restore_forbidden'));
GRANT UPDATE (rollback_leaf_sha256, rollback_spki_sha256) ON deployments TO alice_app;

-- The forbidden lists the engine sends to the helper: the newest compromised keys and revoked certificates first.
CREATE INDEX certificates_compromised ON certificates (compromised_at DESC) WHERE compromised_at IS NOT NULL;
CREATE INDEX certificates_revoked ON certificates (revoked_at DESC) WHERE revoked_at IS NOT NULL;

-- +goose Down
DROP INDEX certificates_revoked;
DROP INDEX certificates_compromised;
REVOKE UPDATE (rollback_leaf_sha256, rollback_spki_sha256) ON deployments FROM alice_app;
-- A done deployment is frozen (deployments_done_frozen): its phase is kept, so the old check comes back NOT VALID.
ALTER TABLE deployments DROP CONSTRAINT deployments_phase_check;
ALTER TABLE deployments ADD CONSTRAINT deployments_phase_check CHECK (phase IN ('', 'none', 'prepared', 'writing', 'committed', 'unchanged',
    'restoring', 'restored', 'restore_failed')) NOT VALID;
ALTER TABLE deployments DROP COLUMN rollback_spki_sha256;
ALTER TABLE deployments DROP COLUMN rollback_leaf_sha256;
