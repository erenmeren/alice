-- +goose Up
-- Web server providers, Phase B (spec docs/superpowers/specs/2026-10-17-web-server-providers-design.md §3.2, §8.1): the
-- apache target type, and the column grant the startup capability sync needs (Alice rewrites every live target's stored
-- capability set from its registered provider, so a capability change needs no data migration).
ALTER TABLE targets DROP CONSTRAINT targets_type_check;
ALTER TABLE targets ADD CONSTRAINT targets_type_check CHECK (type IN ('nginx', 'apache', 'linux', 'azure_key_vault'));

GRANT UPDATE (capabilities) ON targets TO alice_app;

-- +goose Down
-- Refuses, with SQLSTATE Z1008, while a target of type apache exists (deleted ones too: targets are never hard-deleted, so
-- the Down cannot remove them without losing history); nothing is changed then (goose runs the Down in one transaction).
-- +goose StatementBegin
DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM targets WHERE type = 'apache') THEN
        RAISE EXCEPTION 'cannot migrate down: Apache servers exist (targets of type apache, deleted ones included); restore a backup taken before 00017' USING ERRCODE = 'Z1008';
    END IF;
END $$;
-- +goose StatementEnd
REVOKE UPDATE (capabilities) ON targets FROM alice_app;
ALTER TABLE targets DROP CONSTRAINT targets_type_check;
ALTER TABLE targets ADD CONSTRAINT targets_type_check CHECK (type IN ('nginx', 'linux', 'azure_key_vault'));
