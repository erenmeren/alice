-- +goose Up
-- A deployment's verification proves trust, not only "the same leaf with the same chain length" (R51, owner decision
-- 2026-10-20, docs/superpowers/rulings/deployment-trust-verification.md).
--
-- The engine records what the verification of the new certificate found about the served chains: trust_status
-- (trusted: every chain verified against the trust store for the endpoint's name at the probe time; untrusted: one did
-- not, trust_error says why and trust_port where; unchecked: an older helper answered without the chain; '' not
-- measured: verification skipped, or a deployment from before R51), the store it checked against (system roots, the
-- issuing ACME authority's CA bundle, or the root uploaded with the chain) and whether the anchor was known
-- (trust_enforced: an untrusted chain then failed the deployment, deployment.verify_untrusted, and was rolled back).
-- The level the API shows (installed, served, trusted) is derived from verified and trust_status; a deployment from
-- before R51 reads as served, which is what it proved.
ALTER TABLE deployments ADD COLUMN trust_status text NOT NULL DEFAULT '' CHECK (trust_status IN ('', 'trusted', 'untrusted', 'unchecked'));
ALTER TABLE deployments ADD COLUMN trust_error text NOT NULL DEFAULT '' CHECK (trust_error IN ('', 'unknown_authority', 'wrong_intermediate',
    'incomplete_chain', 'chain_order', 'name_mismatch', 'expired', 'not_yet_valid', 'invalid_chain'));
ALTER TABLE deployments ADD COLUMN trust_port integer CHECK (trust_port BETWEEN 1 AND 65535);
ALTER TABLE deployments ADD COLUMN trust_store text NOT NULL DEFAULT '' CHECK (trust_store IN ('', 'system', 'acme_bundle', 'uploaded_root'));
ALTER TABLE deployments ADD COLUMN trust_enforced boolean NOT NULL DEFAULT false;
ALTER TABLE deployments ADD CONSTRAINT deployments_trust_reason_check CHECK ((trust_status = 'untrusted') = (trust_error <> ''));
GRANT UPDATE (trust_status, trust_error, trust_port, trust_store, trust_enforced) ON deployments TO alice_app;

-- +goose Down
REVOKE UPDATE (trust_status, trust_error, trust_port, trust_store, trust_enforced) ON deployments FROM alice_app;
ALTER TABLE deployments DROP CONSTRAINT deployments_trust_reason_check;
ALTER TABLE deployments DROP COLUMN trust_enforced;
ALTER TABLE deployments DROP COLUMN trust_store;
ALTER TABLE deployments DROP COLUMN trust_port;
ALTER TABLE deployments DROP COLUMN trust_error;
ALTER TABLE deployments DROP COLUMN trust_status;
