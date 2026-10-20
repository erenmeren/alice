-- +goose Up
-- Never retry before the CA said we may (owner decision 2026-10-20, docs/superpowers/rulings/acme-ca-retry-after.md).
-- ca_not_before is the CA's earliest retry time for a new order of the certificate (the Retry-After of a rate limit,
-- bounded at seven days when it is recorded), kept apart from next_attempt_at (Alice's own backoff, capped at 24 hours
-- and repaired after a clock step): the next attempt is the later of the two. Only a successful order clears it; a
-- re-arm keeps it.
ALTER TABLE acme_certificates ADD COLUMN ca_not_before timestamptz;
-- A rate limit recorded before: its next_attempt_at held the CA's wait (capped at 24 hours then).
UPDATE acme_certificates SET ca_not_before = next_attempt_at
WHERE last_error_code = 'acme.ca_rate_limited' AND next_attempt_at IS NOT NULL AND next_attempt_at > now();
GRANT UPDATE (ca_not_before) ON acme_certificates TO alice_app;

-- A CA wait that leaves less than half of the renewal window e-mails the Administrators at once, in the ledger of the
-- expiry notices (00011, 00020): one row per ACME certificate, expiry instant of its current certificate and whole days
-- left at the end of the CA's wait, so each such wait is told once.
ALTER TABLE alerts DROP CONSTRAINT alerts_kind_check;
ALTER TABLE alerts ADD CONSTRAINT alerts_kind_check CHECK (kind IN ('certificate_expiry', 'kv_certificate_expiry', 'kv_key_expiry',
    'kv_credential_expiry', 'discovered_certificate_expiry', 'acme_renewal_expiry', 'acme_renewal_ca_wait'));

-- +goose Down
DELETE FROM alerts WHERE kind = 'acme_renewal_ca_wait';
ALTER TABLE alerts DROP CONSTRAINT alerts_kind_check;
ALTER TABLE alerts ADD CONSTRAINT alerts_kind_check CHECK (kind IN ('certificate_expiry', 'kv_certificate_expiry', 'kv_key_expiry',
    'kv_credential_expiry', 'discovered_certificate_expiry', 'acme_renewal_expiry'));
-- The CA's wait goes back into next_attempt_at, as before (capped at 24 hours, as the earlier code did).
UPDATE acme_certificates SET next_attempt_at = LEAST(GREATEST(COALESCE(next_attempt_at, ca_not_before), ca_not_before), now() + interval '24 hours')
WHERE ca_not_before IS NOT NULL AND ca_not_before > now();
REVOKE UPDATE (ca_not_before) ON acme_certificates FROM alice_app;
ALTER TABLE acme_certificates DROP COLUMN ca_not_before;
