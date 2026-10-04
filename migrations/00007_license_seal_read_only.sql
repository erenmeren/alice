-- +goose Up
-- AUD-18: every installation row is sealed in the transaction that creates it (an INSERT) and
-- nothing writes a seal to an existing row any more (the one-time upgrade seal of 00004 is
-- gone), so the application loses UPDATE on the seal. It keeps UPDATE on the cached state, a
-- held clock jump and updated_at; the installation ID and timestamp stay read-only (00004).
REVOKE UPDATE (installation_seal) ON license FROM alice_app;

-- +goose Down
GRANT UPDATE (installation_seal) ON license TO alice_app;
