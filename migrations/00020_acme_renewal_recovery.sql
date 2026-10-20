-- +goose Up
-- Recovery of ACME renewals after an outage (owner decision 2026-10-20, docs/superpowers/rulings/acme-renewal-recovery.md).
-- Every failed renewal has a class: transient (an outage that clears by itself) or permanent (it needs a person).
-- last_failure_class is the class of the last failure ('' before the first one, and after a success or a re-arm);
-- permanent_failures counts the permanent failures of the current series (failures counts all of them). Five permanent
-- failures stop automatic renewal; transient ones never do while the certificate is valid, and a certificate stopped
-- with a transient last failure is ordered again by itself, slowly, until it expires.
ALTER TABLE acme_certificates ADD COLUMN last_failure_class text NOT NULL DEFAULT ''
    CHECK (last_failure_class IN ('', 'transient', 'permanent'));
ALTER TABLE acme_certificates ADD COLUMN permanent_failures integer NOT NULL DEFAULT 0 CHECK (permanent_failures >= 0);
-- A series that began before the classes existed: its last code says the class (renew.ClassOfCode), and all of its
-- failures count as that class (the earlier codes are not kept). So a series stopped by five outages is recovered by
-- itself and a series stopped by five refusals stays stopped.
UPDATE acme_certificates SET last_failure_class = CASE WHEN last_error_code IN ('acme.ca_rate_limited', 'acme.provider_unreachable',
        'acme.not_issued_in_time', 'acme.order_abandoned', 'acme.rollover_pending') THEN 'transient' ELSE 'permanent' END
WHERE failures > 0 AND last_error_code <> '';
UPDATE acme_certificates SET permanent_failures = failures WHERE last_failure_class = 'permanent';
GRANT UPDATE (last_failure_class, permanent_failures) ON acme_certificates TO alice_app;

-- The "expires soon while its renewal fails" e-mails share the ledger of the expiry notices (00011): one row per ACME
-- certificate, expiry instant of its current certificate and threshold (14, 7, 3, 1 days), so each is queued once.
ALTER TABLE alerts DROP CONSTRAINT alerts_kind_check;
ALTER TABLE alerts ADD CONSTRAINT alerts_kind_check CHECK (kind IN ('certificate_expiry', 'kv_certificate_expiry', 'kv_key_expiry',
    'kv_credential_expiry', 'discovered_certificate_expiry', 'acme_renewal_expiry'));

-- The renewal e-mails name their ACME certificate (param acme_certificate_id), so its page shows how the last one was
-- delivered (pattern of notifications_outbox_rotation_preview, 00010).
CREATE INDEX notifications_outbox_acme_certificate ON notifications_outbox ((params->>'acme_certificate_id'), created_at DESC)
    WHERE params ? 'acme_certificate_id';

-- +goose Down
DROP INDEX notifications_outbox_acme_certificate;
DELETE FROM alerts WHERE kind = 'acme_renewal_expiry';
ALTER TABLE alerts DROP CONSTRAINT alerts_kind_check;
ALTER TABLE alerts ADD CONSTRAINT alerts_kind_check CHECK (kind IN ('certificate_expiry', 'kv_certificate_expiry', 'kv_key_expiry',
    'kv_credential_expiry', 'discovered_certificate_expiry'));
REVOKE UPDATE (last_failure_class, permanent_failures) ON acme_certificates FROM alice_app;
ALTER TABLE acme_certificates DROP COLUMN permanent_failures;
ALTER TABLE acme_certificates DROP COLUMN last_failure_class;
