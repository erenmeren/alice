-- +goose Up
-- Web server providers, Phase A "Standardize" (spec docs/superpowers/specs/2026-10-17-web-server-providers-design.md §3.2;
-- plan docs/superpowers/plans/2026-10-17-web-server-standard.md, Task 4). The Nginx-only names that are not about
-- deployment become the shared web-server ones; deployment keeps its Nginx names. targets.type is unchanged: the apache
-- (Phase B) and haproxy (Phase C) types come with their own migrations.

-- The facts key nginx becomes web_server and names its software. A JSON null (Alice never writes one) is dropped.
UPDATE targets
SET facts = (facts - 'nginx') || jsonb_build_object('web_server', (facts -> 'nginx') || '{"software": "nginx"}'::jsonb)
WHERE jsonb_typeof(facts -> 'nginx') = 'object';
UPDATE targets SET facts = facts - 'nginx' WHERE facts ? 'nginx';

-- The scan's server-level warning codes. facts.warnings holds providers.Warning as Go writes it (no JSON tags: "Code",
-- "Params"); the order is kept.
UPDATE targets t
SET facts = jsonb_set(t.facts, '{warnings}', (
    SELECT jsonb_agg(CASE WHEN e.w ->> 'Code' IN ('nginx_not_found', 'nginx_profile_missing', 'nginx_config_invalid')
                          THEN jsonb_set(e.w, '{Code}', to_jsonb('web_server_' || substr(e.w ->> 'Code', 7)))
                          ELSE e.w END ORDER BY e.n)
    FROM jsonb_array_elements(t.facts -> 'warnings') WITH ORDINALITY AS e (w, n)))
WHERE jsonb_typeof(t.facts -> 'warnings') = 'array'
  AND EXISTS (SELECT 1 FROM jsonb_array_elements(t.facts -> 'warnings') AS x (w)
              WHERE x.w ->> 'Code' IN ('nginx_not_found', 'nginx_profile_missing', 'nginx_config_invalid'));

-- targets.capabilities is the provider's set when the target was added: Nginx targets gain the ACME HTTP-01 capability
-- (providers.CapHTTP01), in the byte order of CapabilitySet.Sorted.
UPDATE targets
SET capabilities = ARRAY(SELECT u.c FROM unnest(capabilities || '{http01_challenge}'::text[]) AS u (c) ORDER BY u.c COLLATE "C")
WHERE type = 'nginx' AND NOT ('http01_challenge' = ANY (capabilities));

-- A certificate file of any web server (was nginx_file).
ALTER TABLE certificate_locations DROP CONSTRAINT certificate_locations_kind_check;
UPDATE certificate_locations SET kind = 'server_file' WHERE kind = 'nginx_file';
ALTER TABLE certificate_locations ADD CONSTRAINT certificate_locations_kind_check CHECK (kind IN ('server_file'));

-- +goose Down
-- Restores the 00015 shape. Correct while only Nginx is a web server (Phases B and C add their own Down first).
ALTER TABLE certificate_locations DROP CONSTRAINT certificate_locations_kind_check;
UPDATE certificate_locations SET kind = 'nginx_file' WHERE kind = 'server_file';
ALTER TABLE certificate_locations ADD CONSTRAINT certificate_locations_kind_check CHECK (kind IN ('nginx_file'));

UPDATE targets SET capabilities = array_remove(capabilities, 'http01_challenge') WHERE type = 'nginx';

UPDATE targets t
SET facts = jsonb_set(t.facts, '{warnings}', (
    SELECT jsonb_agg(CASE WHEN e.w ->> 'Code' IN ('web_server_not_found', 'web_server_profile_missing', 'web_server_config_invalid')
                          THEN jsonb_set(e.w, '{Code}', to_jsonb('nginx_' || substr(e.w ->> 'Code', 12)))
                          ELSE e.w END ORDER BY e.n)
    FROM jsonb_array_elements(t.facts -> 'warnings') WITH ORDINALITY AS e (w, n)))
WHERE jsonb_typeof(t.facts -> 'warnings') = 'array'
  AND EXISTS (SELECT 1 FROM jsonb_array_elements(t.facts -> 'warnings') AS x (w)
              WHERE x.w ->> 'Code' IN ('web_server_not_found', 'web_server_profile_missing', 'web_server_config_invalid'));

UPDATE targets
SET facts = (facts - 'web_server') || jsonb_build_object('nginx', (facts -> 'web_server') - 'software')
WHERE jsonb_typeof(facts -> 'web_server') = 'object';
UPDATE targets SET facts = facts - 'web_server' WHERE facts ? 'web_server';
