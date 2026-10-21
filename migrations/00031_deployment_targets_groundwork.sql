-- +goose Up
-- Deployment targets groundwork (R59, phase G of docs/superpowers/specs/2026-10-21-deployment-targets-roadmap.md; rulings
-- in docs/superpowers/rulings/deployment-targets-groundwork.md). It prepares the Windows server, F5 BIG-IP and Kubernetes
-- targets and changes nothing for the targets and locations that exist: every new column has a default that existing
-- rows keep, every widened CHECK still holds them, and no provider writes the new values yet. 00030 is another branch's.

-- G6: the three target types. A Windows server signs in with the platform key like a Linux server; a BIG-IP and a
-- Kubernetes cluster sign in with a credential of their own (G3), as a vault does.
ALTER TABLE targets DROP CONSTRAINT targets_type_check;
ALTER TABLE targets ADD CONSTRAINT targets_type_check CHECK (type IN ('nginx', 'apache', 'haproxy', 'linux', 'azure_key_vault',
    'windows', 'f5_bigip', 'kubernetes'));

-- G3: the credentials of API targets. A credential of a BIG-IP (a user name and password) or of a cluster (a
-- ServiceAccount token, or a client certificate and key) belongs to its target, as a vault's does (00008): target_id is
-- set in the transaction that inserts the target, and a replacement is a new row the target moves to.
ALTER TABLE credentials DROP CONSTRAINT credentials_purpose_check;
ALTER TABLE credentials ADD CONSTRAINT credentials_purpose_check CHECK (purpose IN ('platform_ssh', 'azure_vault', 'f5_device',
    'kubernetes_cluster'));
ALTER TABLE credentials DROP CONSTRAINT credentials_kind_check;
ALTER TABLE credentials ADD CONSTRAINT credentials_kind_check CHECK (kind IN ('ssh_private_key', 'ssh_password_unused', 'azure_sp_secret',
    'azure_sp_cert', 'azure_managed_identity', 'f5_password', 'k8s_token', 'k8s_client_cert'));
ALTER TABLE credentials DROP CONSTRAINT credentials_target_purpose;
ALTER TABLE credentials ADD CONSTRAINT credentials_target_purpose CHECK ((purpose IN ('azure_vault', 'f5_device', 'kubernetes_cluster'))
    = (target_id IS NOT NULL));
ALTER TABLE credentials DROP CONSTRAINT credentials_kind_purpose;
ALTER TABLE credentials ADD CONSTRAINT credentials_kind_purpose CHECK (
    (purpose = 'platform_ssh' AND kind = 'ssh_private_key')
    OR (purpose = 'azure_vault' AND kind IN ('azure_sp_secret', 'azure_sp_cert', 'azure_managed_identity'))
    OR (purpose = 'f5_device' AND kind = 'f5_password')
    OR (purpose = 'kubernetes_cluster' AND kind IN ('k8s_token', 'k8s_client_cert')));

-- A target's credential is the credential of that target (00008's rule, widened): a vault, a BIG-IP and a cluster name a
-- credential of their own purpose that belongs to them (Z1006); every other target the platform key. The application
-- may move credential_id only on those three (a replacement; Z1005 otherwise). The body is 00008's with the type lists
-- widened; the Down puts 00008's back.
-- +goose StatementBegin
CREATE OR REPLACE FUNCTION targets_check_credential() RETURNS trigger LANGUAGE plpgsql
SET search_path = pg_catalog, pg_temp AS $$
DECLARE
    own_purpose text := CASE NEW.type WHEN 'azure_key_vault' THEN 'azure_vault' WHEN 'f5_bigip' THEN 'f5_device'
                                      WHEN 'kubernetes' THEN 'kubernetes_cluster' END;
BEGIN
    IF TG_OP = 'UPDATE' AND current_user = 'alice_app' AND own_purpose IS NULL THEN
        RAISE EXCEPTION 'the application cannot change the credential of a server' USING ERRCODE = 'Z1005';
    END IF;
    IF TG_OP = 'UPDATE' AND NEW.credential_id IS NOT DISTINCT FROM OLD.credential_id AND NEW.type IS NOT DISTINCT FROM OLD.type THEN
        RETURN NEW;
    END IF;
    IF own_purpose IS NOT NULL THEN
        IF NOT EXISTS (SELECT 1 FROM public.credentials c WHERE c.id = NEW.credential_id AND c.purpose = own_purpose AND c.target_id = NEW.id) THEN
            RAISE EXCEPTION 'the credential does not belong to the target' USING ERRCODE = 'Z1006';
        END IF;
    ELSIF NOT EXISTS (SELECT 1 FROM public.credentials c WHERE c.id = NEW.credential_id AND c.purpose = 'platform_ssh') THEN
        RAISE EXCEPTION 'a server uses the platform key' USING ERRCODE = 'Z1006';
    END IF;
    RETURN NEW;
END $$;
-- +goose StatementEnd

-- G1: location kinds with a locator. A location of a new kind is identified by its locator (the kind's identity, a flat
-- JSON object the provider validates: an http.sys binding, a client SSL profile entry, a Secret's namespace and name),
-- unique per target and kind; cert_path holds its canonical text (unique too: the 00006 index), key_path and the Unix
-- key columns stay empty, and details holds the kind's bounded facts. A certificate file keeps no locator and no
-- details, so every existing row and every row a web-server scan writes is unchanged.
ALTER TABLE certificate_locations DROP CONSTRAINT certificate_locations_kind_check;
ALTER TABLE certificate_locations ADD CONSTRAINT certificate_locations_kind_check CHECK (kind IN ('server_file', 'win_sslbinding',
    'f5_clientssl', 'k8s_tls_secret'));
ALTER TABLE certificate_locations ADD COLUMN locator jsonb
    CHECK (jsonb_typeof(locator) = 'object' AND octet_length(locator::text) <= 1024);
ALTER TABLE certificate_locations ADD COLUMN details jsonb NOT NULL DEFAULT '{}'
    CHECK (jsonb_typeof(details) = 'object' AND octet_length(details::text) <= 16384);
-- G4: the Administrator's probe address of a location (an address Alice reaches the endpoint at: a load balancer's
-- internal address, an address without a route domain), next to verify_port and verify_sni. A host name or an IP
-- literal; only a location of an API or Windows kind takes one in this phase.
ALTER TABLE certificate_locations ADD COLUMN verify_address text
    CHECK (verify_address ~ '^[A-Za-z0-9][A-Za-z0-9.:-]{0,252}$');
ALTER TABLE certificate_locations ADD CONSTRAINT certificate_locations_kind_shape CHECK (CASE WHEN kind = 'server_file'
    THEN locator IS NULL AND details = '{}'::jsonb AND verify_address IS NULL
    ELSE locator IS NOT NULL AND char_length(cert_path) <= 1024 AND key_path = '' AND resolved_cert_path = '' AND key_mode = ''
         AND key_owner = '' AND key_group = '' AND NOT symlinked END);
CREATE UNIQUE INDEX certificate_locations_locator ON certificate_locations (target_id, kind, locator) WHERE locator IS NOT NULL;
-- The locator is the location's identity and is never rewritten (a binding that changes is another location).
GRANT UPDATE (details, verify_address) ON certificate_locations TO alice_app;

-- A deployment records the kind of its location: a certificate file's paths keep 00006's rule (what the helper
-- accepts); a location of another kind records its canonical text and no key path.
ALTER TABLE deployments ADD COLUMN location_kind text NOT NULL DEFAULT 'server_file'
    CHECK (location_kind IN ('server_file', 'win_sslbinding', 'f5_clientssl', 'k8s_tls_secret'));
ALTER TABLE deployments DROP CONSTRAINT deployments_cert_path_check;
ALTER TABLE deployments DROP CONSTRAINT deployments_key_path_check;
ALTER TABLE deployments ADD CONSTRAINT deployments_location_paths CHECK (CASE WHEN location_kind = 'server_file'
    THEN cert_path ~ '^/[A-Za-z0-9._/@:+-]+$' AND char_length(cert_path) <= 4096
         AND key_path ~ '^/[A-Za-z0-9._/@:+-]+$' AND char_length(key_path) <= 4096
    ELSE char_length(cert_path) BETWEEN 1 AND 1024 AND key_path = '' END);

-- G5: backups held by Alice (a provider whose target keeps no copy of what it replaces: a Kubernetes Secret). The
-- previous certificate chain and key of one deployment, sealed like every key Alice holds (the Phase 3 envelope, AAD
-- deployment_backups/<deployment id>/ciphertext), written before the change and deleted once the deployment has been
-- final for 7 days. The leaf and key hashes say what the backup holds without opening it (the R48 guard compares them).
-- No row can be deleted while its deployment is not final: a rollback may still need it (SQLSTATE Z1032).
CREATE TABLE deployment_backups (
    deployment_id uuid PRIMARY KEY REFERENCES deployments (id),
    location_id   uuid NOT NULL REFERENCES certificate_locations (id),
    leaf_sha256   text NOT NULL CHECK (leaf_sha256 ~ '^[0-9a-f]{64}$'),
    spki_sha256   text NOT NULL CHECK (spki_sha256 ~ '^[0-9a-f]{64}$'),
    ciphertext    bytea NOT NULL CHECK (octet_length(ciphertext) <= 262144),
    nonce         bytea NOT NULL CHECK (octet_length(nonce) = 12),
    wrapped_dek   bytea NOT NULL,
    key_version   integer NOT NULL CHECK (key_version >= 1),
    created_at    timestamptz NOT NULL
);
CREATE INDEX deployment_backups_location ON deployment_backups (location_id);
-- +goose StatementBegin
CREATE FUNCTION deployment_backups_protect_live() RETURNS trigger LANGUAGE plpgsql
SET search_path = pg_catalog, pg_temp AS $$
BEGIN
    IF EXISTS (SELECT 1 FROM public.deployments d WHERE d.id = OLD.deployment_id AND d.state <> 'done') THEN
        RAISE EXCEPTION 'the backup of an unfinished deployment cannot be deleted' USING ERRCODE = 'Z1032';
    END IF;
    RETURN OLD;
END $$;
-- +goose StatementEnd
CREATE TRIGGER deployment_backups_live BEFORE DELETE ON deployment_backups
    FOR EACH ROW EXECUTE FUNCTION deployment_backups_protect_live();
-- Rows are written once and deleted by the retention; never updated.
GRANT SELECT, INSERT, DELETE ON deployment_backups TO alice_app;

-- +goose Down
-- Correct only on a database without the new targets' data. The Down refuses, with SQLSTATE Z1031, while a target of a
-- new type (deleted ones too: targets are never hard-deleted), a credential of a new purpose, a location of a new kind
-- or a held backup exists; nothing is changed then (goose runs the Down in one transaction).
-- +goose StatementBegin
DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM targets WHERE type IN ('windows', 'f5_bigip', 'kubernetes'))
            OR EXISTS (SELECT 1 FROM credentials WHERE purpose IN ('f5_device', 'kubernetes_cluster'))
            OR EXISTS (SELECT 1 FROM certificate_locations WHERE kind <> 'server_file')
            OR EXISTS (SELECT 1 FROM deployment_backups) THEN
        RAISE EXCEPTION 'cannot migrate down: Windows, BIG-IP or Kubernetes data exists (targets, credentials, locations or held backups); restore a backup taken before 00031' USING ERRCODE = 'Z1031';
    END IF;
END $$;
-- +goose StatementEnd
DROP TABLE deployment_backups;
DROP FUNCTION deployment_backups_protect_live();
ALTER TABLE deployments DROP CONSTRAINT deployments_location_paths;
ALTER TABLE deployments ADD CONSTRAINT deployments_cert_path_check CHECK (cert_path ~ '^/[A-Za-z0-9._/@:+-]+$' AND char_length(cert_path) <= 4096);
ALTER TABLE deployments ADD CONSTRAINT deployments_key_path_check CHECK (key_path ~ '^/[A-Za-z0-9._/@:+-]+$' AND char_length(key_path) <= 4096);
ALTER TABLE deployments DROP COLUMN location_kind;
REVOKE UPDATE (details, verify_address) ON certificate_locations FROM alice_app;
DROP INDEX certificate_locations_locator;
ALTER TABLE certificate_locations DROP CONSTRAINT certificate_locations_kind_shape;
ALTER TABLE certificate_locations DROP COLUMN verify_address;
ALTER TABLE certificate_locations DROP COLUMN details;
ALTER TABLE certificate_locations DROP COLUMN locator;
ALTER TABLE certificate_locations DROP CONSTRAINT certificate_locations_kind_check;
ALTER TABLE certificate_locations ADD CONSTRAINT certificate_locations_kind_check CHECK (kind IN ('server_file'));
-- +goose StatementBegin
CREATE OR REPLACE FUNCTION targets_check_credential() RETURNS trigger LANGUAGE plpgsql
SET search_path = pg_catalog, pg_temp AS $$
BEGIN
    IF TG_OP = 'UPDATE' AND current_user = 'alice_app' AND NEW.type <> 'azure_key_vault' THEN
        RAISE EXCEPTION 'the application cannot change the credential of a server' USING ERRCODE = 'Z1005';
    END IF;
    IF TG_OP = 'UPDATE' AND NEW.credential_id IS NOT DISTINCT FROM OLD.credential_id AND NEW.type IS NOT DISTINCT FROM OLD.type THEN
        RETURN NEW;
    END IF;
    IF NEW.type = 'azure_key_vault' THEN
        IF NOT EXISTS (SELECT 1 FROM public.credentials c WHERE c.id = NEW.credential_id AND c.purpose = 'azure_vault' AND c.target_id = NEW.id) THEN
            RAISE EXCEPTION 'the credential does not belong to the vault' USING ERRCODE = 'Z1006';
        END IF;
    ELSIF NOT EXISTS (SELECT 1 FROM public.credentials c WHERE c.id = NEW.credential_id AND c.purpose = 'platform_ssh') THEN
        RAISE EXCEPTION 'a server uses the platform key' USING ERRCODE = 'Z1006';
    END IF;
    RETURN NEW;
END $$;
-- +goose StatementEnd
ALTER TABLE credentials DROP CONSTRAINT credentials_kind_purpose;
ALTER TABLE credentials ADD CONSTRAINT credentials_kind_purpose CHECK (
    (purpose = 'platform_ssh' AND kind = 'ssh_private_key')
    OR (purpose = 'azure_vault' AND kind IN ('azure_sp_secret', 'azure_sp_cert', 'azure_managed_identity')));
ALTER TABLE credentials DROP CONSTRAINT credentials_target_purpose;
ALTER TABLE credentials ADD CONSTRAINT credentials_target_purpose CHECK ((purpose = 'azure_vault') = (target_id IS NOT NULL));
ALTER TABLE credentials DROP CONSTRAINT credentials_kind_check;
ALTER TABLE credentials ADD CONSTRAINT credentials_kind_check CHECK (kind IN ('ssh_private_key', 'ssh_password_unused', 'azure_sp_secret',
    'azure_sp_cert', 'azure_managed_identity'));
ALTER TABLE credentials DROP CONSTRAINT credentials_purpose_check;
ALTER TABLE credentials ADD CONSTRAINT credentials_purpose_check CHECK (purpose IN ('platform_ssh', 'azure_vault'));
ALTER TABLE targets DROP CONSTRAINT targets_type_check;
ALTER TABLE targets ADD CONSTRAINT targets_type_check CHECK (type IN ('nginx', 'apache', 'haproxy', 'linux', 'azure_key_vault'));
