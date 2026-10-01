-- +goose Up
-- Phase 2 final review B1: the installation row is authenticated (spec §16.1(a)). The seal is
-- HMAC-SHA256 under the HKDF sub-key alice/installation/v1 over the installation ID and
-- timestamp; Alice writes it when it creates the installation, or once on the first start
-- after this migration for an installation created before it. A row whose seal does not
-- match is never trusted. The application may no longer change the ID or the timestamp.
ALTER TABLE license ADD COLUMN installation_seal bytea
    CHECK (installation_seal IS NULL OR octet_length(installation_seal) = 32);

REVOKE UPDATE ON license FROM alice_app;
GRANT UPDATE (state, clock_jump, updated_at, installation_seal) ON license TO alice_app;

-- +goose Down
REVOKE UPDATE (state, clock_jump, updated_at, installation_seal) ON license FROM alice_app;
GRANT UPDATE ON license TO alice_app;
ALTER TABLE license DROP COLUMN installation_seal;
