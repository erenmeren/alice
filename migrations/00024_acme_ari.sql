-- +goose Up
-- ACME Renewal Information completed (R50, owner decision 2026-10-20; docs/superpowers/rulings/acme-ari.md).
-- ari_renew_at is the time chosen at random in the CA's suggested window of the current certificate (RFC 9773 section
-- 4.2), never later than the local rule: kept while it lies inside the window (a restart or the next run never moves
-- it), chosen again when the window moves or shrinks past it, cleared with the window when a new certificate is issued.
ALTER TABLE acme_certificates ADD COLUMN ari_renew_at timestamptz;
GRANT UPDATE (ari_renew_at) ON acme_certificates TO alice_app;

-- An order's RFC 9773 replaces: the predecessor's ARI identifier (base64url(AKI) "." base64url(serial); '' for a first
-- order or a test run) and what became of it (sent, adopted: an earlier order replacing it was taken over, or why it
-- was not sent or sent again without it); account_url is the CA account the order ran under (recorded with order_url),
-- so a later renewal knows whether its predecessor is this account's. Written while the order runs (00013 freezes a
-- finished order).
ALTER TABLE acme_orders ADD COLUMN replaces text NOT NULL DEFAULT ''
    CHECK (char_length(replaces) <= 512 AND replaces ~ '^([A-Za-z0-9_-]+[.][A-Za-z0-9_-]+)?$');
ALTER TABLE acme_orders ADD COLUMN replaces_outcome text NOT NULL DEFAULT ''
    CHECK (replaces_outcome IN ('', 'sent', 'adopted', 'no_ari', 'other_account', 'already_replaced', 'refused'));
ALTER TABLE acme_orders ADD CONSTRAINT acme_orders_replaces_outcome CHECK ((replaces = '') = (replaces_outcome = ''));
ALTER TABLE acme_orders ADD COLUMN account_url text NOT NULL DEFAULT '' CHECK (char_length(account_url) <= 2048);
GRANT UPDATE (replaces, replaces_outcome, account_url) ON acme_orders TO alice_app;
-- The earlier orders that replaced a certificate (taken over after alreadyReplaced).
CREATE INDEX acme_orders_replaces ON acme_orders (acme_certificate_id, replaces, started_at DESC) WHERE replaces <> '';

-- +goose Down
DROP INDEX acme_orders_replaces;
REVOKE UPDATE (replaces, replaces_outcome, account_url) ON acme_orders FROM alice_app;
ALTER TABLE acme_orders DROP CONSTRAINT acme_orders_replaces_outcome;
ALTER TABLE acme_orders DROP COLUMN account_url;
ALTER TABLE acme_orders DROP COLUMN replaces_outcome;
ALTER TABLE acme_orders DROP COLUMN replaces;
REVOKE UPDATE (ari_renew_at) ON acme_certificates FROM alice_app;
ALTER TABLE acme_certificates DROP COLUMN ari_renew_at;
