-- +goose Up
-- What should be there, what Alice last deployed and what is observed today (R52, owner decision 2026-10-21,
-- docs/superpowers/rulings/certificate-drift.md). Alice no longer takes a past successful deployment for the truth: a
-- bound location is in sync only while its newest observations agree with the certificate it should have.
--
-- The desired certificate is the binding's (an ACME certificate's current certificate, a Key Vault binding's current
-- version); the last deployment is deployments with certificate_locations.deployed_fingerprint; the file is
-- certificate_locations.certificate_id as the last scan read it. file_observed_at is when a scan last read the file's
-- content (a certificate, or that the file holds none): last_seen_at moves with every scan that names the location,
-- also one that could not read the file, so the two are never the same clock. Existing rows read the file at their
-- last scan when they hold a certificate.
ALTER TABLE certificate_locations ADD COLUMN file_observed_at timestamptz;
UPDATE certificate_locations SET file_observed_at = last_seen_at WHERE certificate_id IS NOT NULL;
GRANT UPDATE (file_observed_at) ON certificate_locations TO alice_app;

-- One row per bound location: the TLS observation (what the websites served at the last probe that completed a
-- handshake, from Alice or from the server itself, with the R51 level and trust), the last probe attempt and its
-- failure, the drift episode (since when the newest observations disagree with the desired certificate, what was seen
-- and by which observation), the repair mode and an automatic repair's back-off. drift_mode NULL is the default: auto
-- when automatic deployment is on for the binding, observe otherwise. next_observe_at spreads the observations.
CREATE TABLE location_observations (
    location_id         uuid PRIMARY KEY REFERENCES certificate_locations (id),
    drift_mode          text CHECK (drift_mode IN ('observe', 'approve', 'auto')),
    next_observe_at     timestamptz,
    tls_attempted_at    timestamptz,
    tls_error           text NOT NULL DEFAULT '' CHECK (tls_error ~ '^([a-z][a-z0-9_.]{0,79})?$'),
    tls_observed_at     timestamptz,
    tls_fingerprint     text NOT NULL DEFAULT '' CHECK (tls_fingerprint ~ '^([0-9a-f]{64})?$'),
    tls_probe           text NOT NULL DEFAULT '' CHECK (tls_probe IN ('', 'alice', 'helper')),
    tls_level           integer NOT NULL DEFAULT 0 CHECK (tls_level BETWEEN 0 AND 4),
    tls_trust           text NOT NULL DEFAULT '' CHECK (tls_trust IN ('', 'trusted', 'untrusted', 'unchecked')),
    tls_trust_error     text NOT NULL DEFAULT '' CHECK (tls_trust_error IN ('', 'unknown_authority', 'wrong_intermediate',
                            'incomplete_chain', 'chain_order', 'name_mismatch', 'expired', 'not_yet_valid', 'invalid_chain')),
    in_sync_fingerprint text NOT NULL DEFAULT '' CHECK (in_sync_fingerprint ~ '^([0-9a-f]{64})?$'),
    in_sync_at          timestamptz,
    drift_since         timestamptz,
    drift_fingerprint   text NOT NULL DEFAULT '' CHECK (drift_fingerprint ~ '^([0-9a-f]{64})?$'),
    drift_source        text NOT NULL DEFAULT '' CHECK (drift_source IN ('', 'file', 'tls')),
    backoff_reason      text NOT NULL DEFAULT '' CHECK (backoff_reason IN ('', 'flapping', 'repair_failing')),
    backed_off_at       timestamptz,
    updated_at          timestamptz NOT NULL,
    CHECK ((drift_since IS NULL) = (drift_source = '')),
    CHECK ((backed_off_at IS NULL) = (backoff_reason = '')),
    CHECK (tls_trust = 'untrusted' OR tls_trust_error = ''),
    CHECK ((in_sync_at IS NULL) = (in_sync_fingerprint = ''))
);
CREATE INDEX location_observations_due ON location_observations (next_observe_at);
CREATE INDEX location_observations_drifted ON location_observations (drift_since) WHERE drift_since IS NOT NULL;
-- Observations are Alice's own state, not history: a row is rewritten by every observation and removed with its binding.
GRANT SELECT, INSERT, UPDATE, DELETE ON location_observations TO alice_app;

-- Existing bindings keep their behaviour: they observe and report, nothing repairs them until a person chooses.
INSERT INTO location_observations (location_id, drift_mode, updated_at)
SELECT location_id, 'observe', now() FROM acme_bindings
UNION
SELECT id, 'observe', now() FROM certificate_locations WHERE binding_id IS NOT NULL
ON CONFLICT (location_id) DO NOTHING;

-- An automatic repair is a deployment of its own trigger (a certificate.deploy_auto job, run by the deployment engine).
ALTER TABLE deployments DROP CONSTRAINT deployments_trigger_check;
ALTER TABLE deployments ADD CONSTRAINT deployments_trigger_check CHECK (trigger IN ('manual', 'kv_renewal', 'retry', 'acme_renewal',
    'drift_repair'));

-- The drift notices in the ledger of the notices (00011): one row per location and drift episode (expires_at = when the
-- drift began) for the drift itself and for its repair, one per back-off (expires_at = when automatic repair backed
-- off), so each is told once.
ALTER TABLE alerts DROP CONSTRAINT alerts_kind_check;
ALTER TABLE alerts ADD CONSTRAINT alerts_kind_check CHECK (kind IN ('certificate_expiry', 'kv_certificate_expiry', 'kv_key_expiry',
    'kv_credential_expiry', 'discovered_certificate_expiry', 'acme_renewal_expiry', 'acme_renewal_ca_wait', 'location_drift',
    'location_drift_repaired', 'location_drift_backoff'));

-- +goose Down
DELETE FROM alerts WHERE kind IN ('location_drift', 'location_drift_repaired', 'location_drift_backoff');
ALTER TABLE alerts DROP CONSTRAINT alerts_kind_check;
ALTER TABLE alerts ADD CONSTRAINT alerts_kind_check CHECK (kind IN ('certificate_expiry', 'kv_certificate_expiry', 'kv_key_expiry',
    'kv_credential_expiry', 'discovered_certificate_expiry', 'acme_renewal_expiry', 'acme_renewal_ca_wait'));
-- A repair deployment becomes a retry (the history trigger is switched off for this update only, as 00013 does).
ALTER TABLE deployments DISABLE TRIGGER deployments_done_frozen;
UPDATE deployments SET trigger = 'retry' WHERE trigger = 'drift_repair';
ALTER TABLE deployments ENABLE TRIGGER deployments_done_frozen;
ALTER TABLE deployments DROP CONSTRAINT deployments_trigger_check;
ALTER TABLE deployments ADD CONSTRAINT deployments_trigger_check CHECK (trigger IN ('manual', 'kv_renewal', 'retry', 'acme_renewal'));
DROP TABLE location_observations;
REVOKE UPDATE (file_observed_at) ON certificate_locations FROM alice_app;
ALTER TABLE certificate_locations DROP COLUMN file_observed_at;
