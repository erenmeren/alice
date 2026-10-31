-- +goose Up
-- Windows servers, phase W7: the WinRM transport (R71; rulings in docs/superpowers/rulings/windows-iis.md, "W7 (R71)").
-- The transport is a key of targets.config (jsonb), so it needs no column. The WinRM password of a Windows server is a
-- credential that belongs to the server (purpose win_winrm, kind winrm_password, sealed like every credential, AAD
-- credentials/<id>/ciphertext; public_info empty). The rows are append-only: the newest row of a server is its
-- password. targets.credential_id still names the platform key, so the target credential trigger is unchanged. Only the
-- four credential CHECKs below change; every existing row still holds them.
ALTER TABLE credentials DROP CONSTRAINT credentials_purpose_check;
ALTER TABLE credentials ADD CONSTRAINT credentials_purpose_check CHECK (purpose IN ('platform_ssh', 'azure_vault', 'f5_device',
    'kubernetes_cluster', 'win_ccs', 'win_winrm'));
ALTER TABLE credentials DROP CONSTRAINT credentials_kind_check;
ALTER TABLE credentials ADD CONSTRAINT credentials_kind_check CHECK (kind IN ('ssh_private_key', 'ssh_password_unused', 'azure_sp_secret',
    'azure_sp_cert', 'azure_managed_identity', 'f5_password', 'k8s_token', 'k8s_client_cert', 'win_ccs_password', 'winrm_password'));
ALTER TABLE credentials DROP CONSTRAINT credentials_target_purpose;
ALTER TABLE credentials ADD CONSTRAINT credentials_target_purpose CHECK ((purpose IN ('azure_vault', 'f5_device', 'kubernetes_cluster',
    'win_ccs', 'win_winrm')) = (target_id IS NOT NULL));
ALTER TABLE credentials DROP CONSTRAINT credentials_kind_purpose;
ALTER TABLE credentials ADD CONSTRAINT credentials_kind_purpose CHECK (
    (purpose = 'platform_ssh' AND kind = 'ssh_private_key')
    OR (purpose = 'azure_vault' AND kind IN ('azure_sp_secret', 'azure_sp_cert', 'azure_managed_identity'))
    OR (purpose = 'f5_device' AND kind = 'f5_password')
    OR (purpose = 'kubernetes_cluster' AND kind IN ('k8s_token', 'k8s_client_cert'))
    OR (purpose = 'win_ccs' AND kind = 'win_ccs_password')
    OR (purpose = 'win_winrm' AND kind = 'winrm_password'));

-- +goose Down
-- Correct only on a database without WinRM passwords. The Down refuses, with SQLSTATE Z1036, while a win_winrm
-- credential exists (as 00036's Down does); nothing is changed then (goose runs the Down in one transaction). Otherwise
-- it restores the lists of 00036, which 00037 did not change. A target whose config names the winrm transport is left as
-- it is: an older Alice reads it as an SSH target and fails its connection test.
-- +goose StatementBegin
DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM credentials WHERE purpose = 'win_winrm') THEN
        RAISE EXCEPTION 'cannot migrate down: WinRM passwords exist; restore a backup taken before 00038' USING ERRCODE = 'Z1036';
    END IF;
END $$;
-- +goose StatementEnd
ALTER TABLE credentials DROP CONSTRAINT credentials_kind_purpose;
ALTER TABLE credentials ADD CONSTRAINT credentials_kind_purpose CHECK (
    (purpose = 'platform_ssh' AND kind = 'ssh_private_key')
    OR (purpose = 'azure_vault' AND kind IN ('azure_sp_secret', 'azure_sp_cert', 'azure_managed_identity'))
    OR (purpose = 'f5_device' AND kind = 'f5_password')
    OR (purpose = 'kubernetes_cluster' AND kind IN ('k8s_token', 'k8s_client_cert'))
    OR (purpose = 'win_ccs' AND kind = 'win_ccs_password'));
ALTER TABLE credentials DROP CONSTRAINT credentials_target_purpose;
ALTER TABLE credentials ADD CONSTRAINT credentials_target_purpose CHECK ((purpose IN ('azure_vault', 'f5_device', 'kubernetes_cluster',
    'win_ccs')) = (target_id IS NOT NULL));
ALTER TABLE credentials DROP CONSTRAINT credentials_kind_check;
ALTER TABLE credentials ADD CONSTRAINT credentials_kind_check CHECK (kind IN ('ssh_private_key', 'ssh_password_unused', 'azure_sp_secret',
    'azure_sp_cert', 'azure_managed_identity', 'f5_password', 'k8s_token', 'k8s_client_cert', 'win_ccs_password'));
ALTER TABLE credentials DROP CONSTRAINT credentials_purpose_check;
ALTER TABLE credentials ADD CONSTRAINT credentials_purpose_check CHECK (purpose IN ('platform_ssh', 'azure_vault', 'f5_device',
    'kubernetes_cluster', 'win_ccs'));
