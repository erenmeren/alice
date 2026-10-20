-- +goose Up
-- The continuity window of a licensed lock (owner decision 2026-10-20, docs/superpowers/rulings/license-lock-continuity.md):
-- jobs of the license class continuity (ACME renewal orders and automatic deployments of certificates already managed,
-- with the Key Vault polls that see renewed versions) run for 45 days after a lock begins. The class is stored on every
-- job row (jobs.class, 00005) and the runner claims by it: a poll queued before the upgrade takes the class kv.poll has
-- now (the payload MAC does not cover the class). Queued deployments and orders keep theirs (change): they were asked for
-- under the old rules.
ALTER TABLE jobs DROP CONSTRAINT jobs_class_check;
ALTER TABLE jobs ADD CONSTRAINT jobs_class_check CHECK (class IN ('always', 'read_only', 'change', 'continuity'));
UPDATE jobs SET class = 'continuity' WHERE type = 'kv.poll' AND status IN ('queued', 'running', 'blocked_license');

-- +goose Down
-- A continuity job becomes what its kind of work was before the window existed: an ACME renewal order (acme.renew) is an
-- acme.issue, an automatic deployment (certificate.deploy_auto) a certificate.deploy, both of class change; a Key Vault
-- poll and the planners go back to read_only. The payload MAC covers the type (jobs.Queue.mac), so a live job whose type
-- changes would be refused as tampered: the Down refuses, with SQLSTATE Z1008, while a live renewal order or automatic
-- deployment exists (finish them, or discard them under Waiting for an administrator, then migrate down); nothing is
-- changed then (goose runs the Down in one transaction). Finished rows keep their type and are only re-classed.
-- +goose StatementBegin
DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM jobs WHERE type IN ('acme.renew', 'certificate.deploy_auto') AND status IN ('queued', 'running', 'blocked_license')) THEN
        RAISE EXCEPTION 'cannot migrate down: renewal orders or automatic deployments of the continuity window are queued, running or held; let them finish or discard them first' USING ERRCODE = 'Z1008';
    END IF;
END $$;
-- +goose StatementEnd
ALTER TABLE jobs DROP CONSTRAINT jobs_class_check;
UPDATE jobs SET class = 'change' WHERE class = 'continuity' AND type IN ('acme.renew', 'certificate.deploy_auto');
UPDATE jobs SET class = 'read_only' WHERE class = 'continuity';
ALTER TABLE jobs ADD CONSTRAINT jobs_class_check CHECK (class IN ('always', 'read_only', 'change'));
