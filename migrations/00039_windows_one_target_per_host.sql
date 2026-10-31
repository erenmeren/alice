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
-- The Down refuses, with SQLSTATE Z1038, while a removed CCS or WinRM password exists (an ended row with no live row of
-- its live target and purpose): code before 00039 reads the newest row whether ended or not and would use it again. A
-- replaced password (a live row after the ended one) does not block it. Nothing is changed then.
-- +goose StatementBegin
DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM credentials c JOIN targets t ON t.id = c.target_id AND t.deleted_at IS NULL
               WHERE c.purpose IN ('win_ccs', 'win_winrm') AND c.rotated_at IS NOT NULL
               AND NOT EXISTS (SELECT 1 FROM credentials n WHERE n.target_id = c.target_id AND n.purpose = c.purpose AND n.rotated_at IS NULL)) THEN
        RAISE EXCEPTION 'cannot migrate down: removed Windows passwords exist; set a new password or remove the server in Alice, or restore a backup taken before 00039' USING ERRCODE = 'Z1038';
    END IF;
END $$;
-- +goose StatementEnd
REVOKE UPDATE (rotated_at) ON credentials FROM alice_app;
DROP INDEX targets_windows_host_live;
