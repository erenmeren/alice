-- +goose Up
-- Phase 8 (R43 row 41): the installation's backup sender private key is a settings secret (a master-key envelope,
-- AAD setting_secrets/backup.sender/ciphertext), stored by the recovery-passphrase step and read by the backup.
-- The list of keys stays closed.
ALTER TABLE setting_secrets DROP CONSTRAINT setting_secrets_key_check;
ALTER TABLE setting_secrets ADD CONSTRAINT setting_secrets_key_check CHECK (key ~ '^(notify\.smtp\.password|backup\.sender|sso\.provider\.[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\.client_secret)$');

-- +goose Down
-- Correct only on a database without a backup sender key: removing it would make every later backup unreadable
-- with the recovery passphrase. The Down refuses with SQLSTATE Z1016 then; nothing is changed.
-- +goose StatementBegin
DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM setting_secrets WHERE key = 'backup.sender') THEN
        RAISE EXCEPTION 'cannot migrate down: the backup sender key exists; restore a backup taken before 00012 instead' USING ERRCODE = 'Z1016';
    END IF;
END $$;
-- +goose StatementEnd
ALTER TABLE setting_secrets DROP CONSTRAINT setting_secrets_key_check;
ALTER TABLE setting_secrets ADD CONSTRAINT setting_secrets_key_check CHECK (key ~ '^(notify\.smtp\.password|sso\.provider\.[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\.client_secret)$');
