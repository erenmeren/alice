-- +goose Up
-- Windows servers, phase W8: one live Windows server per host (R72 Rulings 4-5; docs/superpowers/rulings/windows-iis.md,
-- "W8 (R72)"). At most one target of type windows with deleted_at IS NULL per lower(config->>'host'), any port, either
-- transport; the host is compared as text, as targets_endpoint_live compares it. The Up refuses, with SQLSTATE Z1037,
-- while two live Windows servers share a host (nothing is changed then: goose runs the Up in one transaction); the
-- operator removes one of each pair in Alice first (docs/upgrade.md names the query).
-- +goose StatementBegin
DO $$
BEGIN
    IF EXISTS (SELECT lower(config->>'host') FROM targets WHERE type = 'windows' AND deleted_at IS NULL GROUP BY 1 HAVING count(*) > 1) THEN
        RAISE EXCEPTION 'cannot migrate up: two Windows servers share a host; remove one of each pair in Alice (Servers page), then upgrade' USING ERRCODE = 'Z1037';
    END IF;
END $$;
-- +goose StatementEnd
CREATE UNIQUE INDEX targets_windows_host_live ON targets (lower(config->>'host')) WHERE type = 'windows' AND deleted_at IS NULL;
-- Removing a CCS or WinRM password ends its live row (R72 Ruling 7): the application may set rotated_at, no other
-- column; rows are still never deleted.
GRANT UPDATE (rotated_at) ON credentials TO alice_app;

-- +goose Down
REVOKE UPDATE (rotated_at) ON credentials FROM alice_app;
DROP INDEX targets_windows_host_live;
