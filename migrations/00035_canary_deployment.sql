-- +goose Up
-- Canary deployment (R65, design docs/superpowers/specs/2026-10-24-canary-deployment-design.md §16): a multi-website
-- deployment whose source service asks for it goes to wave 1 first, is observed for a hold time, then goes to wave 2.
-- deployment_rollouts holds one such deployment of one certificate (its waves, hold times and a snapshot of the policy);
-- canary_checks the latest observation of one holding wave-1 deployment (one row, rewritten per round). A deployment
-- gains its rollout and wave (written at insert), the file hash a success would record (written when it enters the new
-- state 'holding': sent and verified, not finished), and the reason of a revert (the recovery rolls it back).
CREATE TABLE deployment_rollouts (
    id                  uuid PRIMARY KEY,
    certificate_id      uuid NOT NULL REFERENCES certificates (id),
    service_id          uuid REFERENCES services (id) ON DELETE SET NULL,
    policy_version      integer NOT NULL CHECK (policy_version >= 1),
    settings            jsonb NOT NULL CHECK (jsonb_typeof(settings) = 'object' AND octet_length(settings::text) <= 8192),
    origin              text NOT NULL CHECK (origin IN ('manual', 'acme', 'key_vault')),
    acme_certificate_id uuid REFERENCES acme_certificates (id),
    binding_id          uuid REFERENCES bindings (id) ON DELETE SET NULL,
    kv_version_id       uuid REFERENCES kv_certificate_versions (id),
    requested_by        uuid REFERENCES users (id),
    state               text NOT NULL CHECK (state IN ('wave1', 'hold', 'wave2', 'completed', 'failed', 'aborted', 'stopped', 'preempted')),
    reason              text NOT NULL DEFAULT '' CHECK (reason ~ '^[A-Za-z0-9._-]{0,100}$'),
    reason_params       jsonb NOT NULL DEFAULT '{}' CHECK (jsonb_typeof(reason_params) = 'object' AND octet_length(reason_params::text) <= 4096),
    wave1_location_ids  uuid[] NOT NULL CHECK (cardinality(wave1_location_ids) BETWEEN 1 AND 19),
    wave2_location_ids  uuid[] NOT NULL CHECK (cardinality(wave2_location_ids) >= 1),
    skipped             jsonb NOT NULL DEFAULT '[]' CHECK (jsonb_typeof(skipped) = 'array' AND octet_length(skipped::text) <= 8192),
    hold_started_at     timestamptz,
    hold_until          timestamptz,
    gate_waiting_since  timestamptz,
    created_at          timestamptz NOT NULL,
    finished_at         timestamptz,
    version             integer NOT NULL DEFAULT 1 CHECK (version >= 1),
    CHECK ((state IN ('completed', 'failed', 'aborted', 'stopped', 'preempted')) = (finished_at IS NOT NULL)),
    CHECK (origin <> 'acme' OR acme_certificate_id IS NOT NULL),
    CHECK (origin <> 'key_vault' OR (binding_id IS NOT NULL AND kv_version_id IS NOT NULL)),
    CHECK (acme_certificate_id IS NULL OR kv_version_id IS NULL)
);
CREATE INDEX deployment_rollouts_active ON deployment_rollouts (created_at, id) WHERE finished_at IS NULL;
CREATE INDEX deployment_rollouts_certificate ON deployment_rollouts (certificate_id, created_at DESC);
CREATE UNIQUE INDEX deployment_rollouts_one_acme ON deployment_rollouts (acme_certificate_id, certificate_id)
    WHERE origin = 'acme' AND state NOT IN ('failed', 'aborted');
CREATE UNIQUE INDEX deployment_rollouts_one_kv ON deployment_rollouts (binding_id, kv_version_id)
    WHERE origin = 'key_vault' AND state NOT IN ('failed', 'aborted');
GRANT SELECT, INSERT ON deployment_rollouts TO alice_app;
GRANT UPDATE (state, reason, reason_params, skipped, hold_started_at, hold_until, gate_waiting_since, finished_at, version)
    ON deployment_rollouts TO alice_app;

-- The observation of one holding wave-1 deployment (one row, rewritten per round; it goes with its deployment).
CREATE TABLE canary_checks (
    deployment_id         uuid PRIMARY KEY REFERENCES deployments (id) ON DELETE CASCADE,
    rollout_id            uuid NOT NULL REFERENCES deployment_rollouts (id) ON DELETE CASCADE,
    rounds                integer NOT NULL DEFAULT 0 CHECK (rounds >= 0),
    passes                integer NOT NULL DEFAULT 0 CHECK (passes >= 0),
    consecutive_failures  integer NOT NULL DEFAULT 0 CHECK (consecutive_failures >= 0),
    next_check_at         timestamptz NOT NULL,
    last_at               timestamptz,
    last_result           text NOT NULL DEFAULT '' CHECK (last_result IN ('', 'pass', 'fail', 'unknown')),
    last_reason           text NOT NULL DEFAULT '' CHECK (last_reason ~ '^[A-Za-z0-9._-]{0,100}$'),
    last_tls              text NOT NULL DEFAULT '' CHECK (last_tls IN ('', 'pass', 'fail', 'skipped', 'unknown')),
    last_http_status      integer CHECK (last_http_status BETWEEN 100 AND 599),
    last_latency_ms       integer CHECK (last_latency_ms >= 0),
    last_pass_at          timestamptz,
    first_failure         jsonb CHECK (first_failure IS NULL OR (jsonb_typeof(first_failure) = 'object' AND octet_length(first_failure::text) <= 2048))
);
CREATE INDEX canary_checks_due ON canary_checks (next_check_at);
CREATE INDEX canary_checks_rollout ON canary_checks (rollout_id);
GRANT SELECT, INSERT ON canary_checks TO alice_app;
GRANT UPDATE (rounds, passes, consecutive_failures, next_check_at, last_at, last_result, last_reason, last_tls, last_http_status,
    last_latency_ms, last_pass_at, first_failure) ON canary_checks TO alice_app;

ALTER TABLE deployments
    ADD COLUMN rollout_id uuid REFERENCES deployment_rollouts (id),
    ADD COLUMN wave smallint CHECK (wave IN (1, 2)),
    ADD COLUMN held_cert_file_sha256 text NOT NULL DEFAULT '' CHECK (held_cert_file_sha256 ~ '^([0-9a-f]{64})?$'),
    ADD COLUMN revert_reason text NOT NULL DEFAULT '' CHECK (revert_reason ~ '^[A-Za-z0-9._-]{0,100}$'),
    ADD CONSTRAINT deployments_wave_rollout CHECK ((rollout_id IS NULL) = (wave IS NULL)),
    ADD CONSTRAINT deployments_holding_wave1 CHECK (state <> 'holding' OR (wave IS NOT DISTINCT FROM 1 AND status = 'running'));
ALTER TABLE deployments DROP CONSTRAINT deployments_state_check;
ALTER TABLE deployments ADD CONSTRAINT deployments_state_check CHECK (state IN ('queued', 'precheck', 'deploying', 'holding', 'recovering', 'done'));
CREATE INDEX deployments_rollout ON deployments (rollout_id, wave) WHERE rollout_id IS NOT NULL;
GRANT UPDATE (held_cert_file_sha256, revert_reason) ON deployments TO alice_app;

-- +goose Down
-- Correct only on an installation that never used canary deployment: refuses, with SQLSTATE Z1033, while a rollout
-- exists or a deployment names one (its history would be lost silently).
-- +goose StatementBegin
DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM deployment_rollouts) OR EXISTS (SELECT 1 FROM deployments WHERE rollout_id IS NOT NULL OR state = 'holding') THEN
        RAISE EXCEPTION 'cannot migrate down: canary rollouts exist; restore a backup taken before 00035' USING ERRCODE = 'Z1033';
    END IF;
END $$;
-- +goose StatementEnd
REVOKE UPDATE (held_cert_file_sha256, revert_reason) ON deployments FROM alice_app;
DROP INDEX deployments_rollout;
ALTER TABLE deployments DROP CONSTRAINT deployments_state_check;
ALTER TABLE deployments ADD CONSTRAINT deployments_state_check CHECK (state IN ('queued', 'precheck', 'deploying', 'recovering', 'done'));
ALTER TABLE deployments DROP CONSTRAINT deployments_holding_wave1;
ALTER TABLE deployments DROP CONSTRAINT deployments_wave_rollout;
ALTER TABLE deployments DROP COLUMN revert_reason;
ALTER TABLE deployments DROP COLUMN held_cert_file_sha256;
ALTER TABLE deployments DROP COLUMN wave;
ALTER TABLE deployments DROP COLUMN rollout_id;
DROP TABLE canary_checks;
DROP TABLE deployment_rollouts;
