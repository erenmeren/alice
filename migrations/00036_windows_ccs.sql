-- +goose Up
-- Windows servers, phase W5: the Centralized Certificate Store (R68; rulings in docs/superpowers/rulings/windows-iis.md,
-- "W5 (R68)"). A CCS file is a location of its own kind (win_ccs_file: 00031's locator, details and probe address, no key
-- path), and the CCS password of a Windows server is a credential that belongs to the server (purpose win_ccs, kind
-- win_ccs_password, sealed like every credential, AAD credentials/<id>/ciphertext). The rows are append-only: the newest
-- row of a server is its password. A Windows server still signs in with the platform key: targets.credential_id never
-- names this credential, so the target credential trigger is unchanged. Only the six CHECKs below change; every
-- existing row still holds them.
ALTER TABLE certificate_locations DROP CONSTRAINT certificate_locations_kind_check;
ALTER TABLE certificate_locations ADD CONSTRAINT certificate_locations_kind_check CHECK (kind IN ('server_file', 'win_sslbinding',
    'f5_clientssl', 'k8s_tls_secret', 'win_ccs_file'));
ALTER TABLE deployments DROP CONSTRAINT deployments_location_kind_check;
ALTER TABLE deployments ADD CONSTRAINT deployments_location_kind_check CHECK (location_kind IN ('server_file', 'win_sslbinding',
    'f5_clientssl', 'k8s_tls_secret', 'win_ccs_file'));
ALTER TABLE credentials DROP CONSTRAINT credentials_purpose_check;
ALTER TABLE credentials ADD CONSTRAINT credentials_purpose_check CHECK (purpose IN ('platform_ssh', 'azure_vault', 'f5_device',
    'kubernetes_cluster', 'win_ccs'));
ALTER TABLE credentials DROP CONSTRAINT credentials_kind_check;
ALTER TABLE credentials ADD CONSTRAINT credentials_kind_check CHECK (kind IN ('ssh_private_key', 'ssh_password_unused', 'azure_sp_secret',
    'azure_sp_cert', 'azure_managed_identity', 'f5_password', 'k8s_token', 'k8s_client_cert', 'win_ccs_password'));
ALTER TABLE credentials DROP CONSTRAINT credentials_target_purpose;
ALTER TABLE credentials ADD CONSTRAINT credentials_target_purpose CHECK ((purpose IN ('azure_vault', 'f5_device', 'kubernetes_cluster',
    'win_ccs')) = (target_id IS NOT NULL));
ALTER TABLE credentials DROP CONSTRAINT credentials_kind_purpose;
ALTER TABLE credentials ADD CONSTRAINT credentials_kind_purpose CHECK (
    (purpose = 'platform_ssh' AND kind = 'ssh_private_key')
    OR (purpose = 'azure_vault' AND kind IN ('azure_sp_secret', 'azure_sp_cert', 'azure_managed_identity'))
    OR (purpose = 'f5_device' AND kind = 'f5_password')
    OR (purpose = 'kubernetes_cluster' AND kind IN ('k8s_token', 'k8s_client_cert'))
    OR (purpose = 'win_ccs' AND kind = 'win_ccs_password'));

-- +goose Down
-- Correct only on a database without CCS data. The Down refuses, with SQLSTATE Z1034, while a win_ccs_file location or
-- deployment or a win_ccs credential exists (as 00031's Down does); nothing is changed then (goose runs the Down in one
-- transaction). Otherwise it restores the lists of 00031, which 00032-00035 did not change.
-- +goose StatementBegin
DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM certificate_locations WHERE kind = 'win_ccs_file')
            OR EXISTS (SELECT 1 FROM deployments WHERE location_kind = 'win_ccs_file')
            OR EXISTS (SELECT 1 FROM credentials WHERE purpose = 'win_ccs') THEN
        RAISE EXCEPTION 'cannot migrate down: CCS data exists (win_ccs_file locations or deployments, or CCS passwords); restore a backup taken before 00036' USING ERRCODE = 'Z1034';
    END IF;
END $$;
-- +goose StatementEnd
ALTER TABLE credentials DROP CONSTRAINT credentials_kind_purpose;
ALTER TABLE credentials ADD CONSTRAINT credentials_kind_purpose CHECK (
    (purpose = 'platform_ssh' AND kind = 'ssh_private_key')
    OR (purpose = 'azure_vault' AND kind IN ('azure_sp_secret', 'azure_sp_cert', 'azure_managed_identity'))
    OR (purpose = 'f5_device' AND kind = 'f5_password')
    OR (purpose = 'kubernetes_cluster' AND kind IN ('k8s_token', 'k8s_client_cert')));
ALTER TABLE credentials DROP CONSTRAINT credentials_target_purpose;
ALTER TABLE credentials ADD CONSTRAINT credentials_target_purpose CHECK ((purpose IN ('azure_vault', 'f5_device', 'kubernetes_cluster'))
    = (target_id IS NOT NULL));
ALTER TABLE credentials DROP CONSTRAINT credentials_kind_check;
ALTER TABLE credentials ADD CONSTRAINT credentials_kind_check CHECK (kind IN ('ssh_private_key', 'ssh_password_unused', 'azure_sp_secret',
    'azure_sp_cert', 'azure_managed_identity', 'f5_password', 'k8s_token', 'k8s_client_cert'));
ALTER TABLE credentials DROP CONSTRAINT credentials_purpose_check;
ALTER TABLE credentials ADD CONSTRAINT credentials_purpose_check CHECK (purpose IN ('platform_ssh', 'azure_vault', 'f5_device',
    'kubernetes_cluster'));
ALTER TABLE deployments DROP CONSTRAINT deployments_location_kind_check;
ALTER TABLE deployments ADD CONSTRAINT deployments_location_kind_check CHECK (location_kind IN ('server_file', 'win_sslbinding',
    'f5_clientssl', 'k8s_tls_secret'));
ALTER TABLE certificate_locations DROP CONSTRAINT certificate_locations_kind_check;
ALTER TABLE certificate_locations ADD CONSTRAINT certificate_locations_kind_check CHECK (kind IN ('server_file', 'win_sslbinding',
    'f5_clientssl', 'k8s_tls_secret'));
