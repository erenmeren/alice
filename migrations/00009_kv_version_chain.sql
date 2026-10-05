-- +goose Up
-- Phase 5 (fix round): what the last read of a vault version's secret found about its chain. The poll stores
-- only the leaf, so the chain is known only once a deployment has read the secret; a version whose chain was
-- found incomplete needs an Administrator's confirmation for every manual deployment (Deploy now offers it,
-- the request is refused without it), whether or not the version is held: releasing a hold does not confirm
-- the chain. A later read that finds the chain complete clears it.
ALTER TABLE kv_certificate_versions ADD COLUMN chain_incomplete boolean NOT NULL DEFAULT false;
GRANT UPDATE (chain_incomplete) ON kv_certificate_versions TO alice_app;

-- +goose Down
REVOKE UPDATE (chain_incomplete) ON kv_certificate_versions FROM alice_app;
ALTER TABLE kv_certificate_versions DROP COLUMN chain_incomplete;
