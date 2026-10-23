-- +goose Up
-- Windows certificate cleanup, W3 (R62 Ruling 13): the per-server switch "remove certificates Alice imported once nothing uses them". It has a
-- column of its own (not a targets.config key: config holds the connection and the application may not write it). Every existing
-- target keeps the default, on; the application may change only this column.
ALTER TABLE targets ADD COLUMN certificate_cleanup boolean NOT NULL DEFAULT true;
GRANT UPDATE (certificate_cleanup) ON targets TO alice_app;

-- +goose Down
REVOKE UPDATE (certificate_cleanup) ON targets FROM alice_app;
ALTER TABLE targets DROP COLUMN certificate_cleanup;
