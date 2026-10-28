-- +goose Up
-- Windows servers, phase W6: the Remote Desktop certificate (R69; rulings in docs/superpowers/rulings/windows-iis.md,
-- "W6 (R69)"). The RDP-Tcp listener of a Windows server is a location of its own kind (win_rdp: 00031's locator, details
-- and probe address, no key path). No credential and no column: only the two kind CHECKs below change; every existing
-- row still holds them.
ALTER TABLE certificate_locations DROP CONSTRAINT certificate_locations_kind_check;
ALTER TABLE certificate_locations ADD CONSTRAINT certificate_locations_kind_check CHECK (kind IN ('server_file', 'win_sslbinding',
    'f5_clientssl', 'k8s_tls_secret', 'win_ccs_file', 'win_rdp'));
ALTER TABLE deployments DROP CONSTRAINT deployments_location_kind_check;
ALTER TABLE deployments ADD CONSTRAINT deployments_location_kind_check CHECK (location_kind IN ('server_file', 'win_sslbinding',
    'f5_clientssl', 'k8s_tls_secret', 'win_ccs_file', 'win_rdp'));

-- +goose Down
-- Correct only on a database without RDP data. The Down refuses, with SQLSTATE Z1035, while a win_rdp location or
-- deployment exists (as 00036's Down does); nothing is changed then (goose runs the Down in one transaction). Otherwise
-- it restores the lists of 00036.
-- +goose StatementBegin
DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM certificate_locations WHERE kind = 'win_rdp')
            OR EXISTS (SELECT 1 FROM deployments WHERE location_kind = 'win_rdp') THEN
        RAISE EXCEPTION 'cannot migrate down: RDP data exists (win_rdp locations or deployments); restore a backup taken before 00037' USING ERRCODE = 'Z1035';
    END IF;
END $$;
-- +goose StatementEnd
ALTER TABLE deployments DROP CONSTRAINT deployments_location_kind_check;
ALTER TABLE deployments ADD CONSTRAINT deployments_location_kind_check CHECK (location_kind IN ('server_file', 'win_sslbinding',
    'f5_clientssl', 'k8s_tls_secret', 'win_ccs_file'));
ALTER TABLE certificate_locations DROP CONSTRAINT certificate_locations_kind_check;
ALTER TABLE certificate_locations ADD CONSTRAINT certificate_locations_kind_check CHECK (kind IN ('server_file', 'win_sslbinding',
    'f5_clientssl', 'k8s_tls_secret', 'win_ccs_file'));
