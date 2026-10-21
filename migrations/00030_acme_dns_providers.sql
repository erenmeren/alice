-- +goose Up
-- Built-in DNS providers for DNS-01 (R57). A DNS publisher (an acme_hooks row) is either the administrator's DNS hook
-- (kind 'webhook', every row before this migration) or a built-in provider that Alice drives through its API:
-- 'cloudflare', 'azure_dns' or 'route53'. A certificate keeps naming its publisher by hook_id, so the certificates,
-- orders, presented records, service policy and cleanup rules are unchanged.
--
-- settings holds a provider's non-secret settings (Azure: sign-in method, tenant, client, subscription, resource group,
-- the sign-in certificate's thumbprint and expiry; Route 53: access key ID, role ARN, external ID; Cloudflare: none);
-- the hook's is '{}'. The sealed secret (AAD acme_hooks/<id>/secret, unchanged) is the hook's shared secret or a
-- provider's credentials as one JSON document (the API token; the client secret or the sign-in certificate's key;
-- the secret access key; for a managed identity a document without a secret). Only a hook has a URL and a CA bundle.
-- The kind of a publisher never changes (its secret's format depends on it): no UPDATE grant on kind.
ALTER TABLE acme_hooks ADD COLUMN kind text NOT NULL DEFAULT 'webhook'
    CHECK (kind IN ('webhook', 'cloudflare', 'azure_dns', 'route53'));
ALTER TABLE acme_hooks ADD COLUMN settings jsonb NOT NULL DEFAULT '{}'::jsonb
    CHECK (jsonb_typeof(settings) = 'object' AND octet_length(settings::text) <= 16384);
ALTER TABLE acme_hooks DROP CONSTRAINT acme_hooks_url_check;
ALTER TABLE acme_hooks ADD CONSTRAINT acme_hooks_url_check CHECK (
    (kind = 'webhook' AND url ~ '^https://[^/@[:space:]]+(/|$)' AND char_length(url) <= 2048)
    OR (kind <> 'webhook' AND url = ''));
ALTER TABLE acme_hooks ADD CONSTRAINT acme_hooks_bundle_kind_check CHECK (kind = 'webhook' OR ca_bundle_pem = '');
ALTER TABLE acme_hooks ADD CONSTRAINT acme_hooks_settings_kind_check CHECK (kind <> 'webhook' OR settings = '{}'::jsonb);
GRANT UPDATE (settings) ON acme_hooks TO alice_app;

-- +goose Down
-- Refuses, with SQLSTATE Z1030, while a built-in DNS provider exists (deleted ones included: their rows and sealed
-- credentials are still used to clean up what they published, and the schema below cannot hold them); nothing is
-- changed then (goose runs the Down in one transaction).
-- +goose StatementBegin
DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM acme_hooks WHERE kind <> 'webhook') THEN
        RAISE EXCEPTION 'cannot migrate down: built-in DNS providers exist (acme_hooks of a kind other than webhook, deleted ones included); restore a backup taken before 00030' USING ERRCODE = 'Z1030';
    END IF;
END $$;
-- +goose StatementEnd
REVOKE UPDATE (settings) ON acme_hooks FROM alice_app;
ALTER TABLE acme_hooks DROP CONSTRAINT acme_hooks_settings_kind_check;
ALTER TABLE acme_hooks DROP CONSTRAINT acme_hooks_bundle_kind_check;
ALTER TABLE acme_hooks DROP CONSTRAINT acme_hooks_url_check;
ALTER TABLE acme_hooks ADD CONSTRAINT acme_hooks_url_check CHECK (url ~ '^https://[^/@[:space:]]+(/|$)' AND char_length(url) <= 2048);
ALTER TABLE acme_hooks DROP COLUMN settings;
ALTER TABLE acme_hooks DROP COLUMN kind;
