-- +goose Up
-- Web server providers, Phase C (spec docs/superpowers/specs/2026-10-17-web-server-providers-design.md §3.2): the haproxy
-- target type. The startup capability sync (00017's grant) covers its capability set; no data changes.
ALTER TABLE targets DROP CONSTRAINT targets_type_check;
ALTER TABLE targets ADD CONSTRAINT targets_type_check CHECK (type IN ('nginx', 'apache', 'haproxy', 'linux', 'azure_key_vault'));

-- +goose Down
-- Refuses, with SQLSTATE Z1008, while a target of type haproxy exists (deleted ones too: targets are never hard-deleted, so
-- the Down cannot remove them without losing history); nothing is changed then (goose runs the Down in one transaction).
-- +goose StatementBegin
DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM targets WHERE type = 'haproxy') THEN
        RAISE EXCEPTION 'cannot migrate down: HAProxy servers exist (targets of type haproxy, deleted ones included); restore a backup taken before 00018' USING ERRCODE = 'Z1008';
    END IF;
END $$;
-- +goose StatementEnd
ALTER TABLE targets DROP CONSTRAINT targets_type_check;
ALTER TABLE targets ADD CONSTRAINT targets_type_check CHECK (type IN ('nginx', 'apache', 'linux', 'azure_key_vault'));
