-- +goose Up
-- Scoped role bindings for people (R49 Phase 2, R53; docs/superpowers/specs/2026-10-21-scoped-rbac-and-service-ownership-design.md
-- §12 Phase 2). 00026 created role_bindings and made users.role nullable; from this phase a person may hold roles on
-- services and environments only, or no role at all yet.
--
-- The break-glass account (the administrator the setup wizard created, R10) always keeps a global role: a person
-- without one depends on role bindings, which an emergency account must not. The application refuses removing it
-- first (ALC-USR-0004); this CHECK holds it for every other writer. Every existing row passes (no path set a NULL role
-- before this phase). The design's stricter rule (`role = 'admin'`) is not taken: it would refuse demoting the wizard
-- administrator, which another Administrator may do today (SEC-015 keeps only the last enabled Administrator), and an
-- installation that did would fail this migration (ruling R53 item 2).
ALTER TABLE users ADD CONSTRAINT users_break_glass_global_role CHECK (NOT is_break_glass OR role IS NOT NULL);

-- The service page's Access tab lists the bindings that reach a service, directly or through its environment; the
-- environment foreign key (ON DELETE RESTRICT) is checked through the second index as well.
CREATE INDEX role_bindings_service ON role_bindings (service_id) WHERE service_id IS NOT NULL;
CREATE INDEX role_bindings_environment ON role_bindings (environment_id) WHERE environment_id IS NOT NULL;

-- +goose Down
DROP INDEX role_bindings_environment;
DROP INDEX role_bindings_service;
ALTER TABLE users DROP CONSTRAINT users_break_glass_global_role;
