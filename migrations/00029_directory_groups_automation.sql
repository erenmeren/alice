-- +goose Up
-- Directory groups, automation accounts and API tokens limited to services (R49 Phase 3, R54;
-- docs/superpowers/specs/2026-10-21-scoped-rbac-and-service-ownership-design.md §6). 00026 created the tables and the
-- columns (directory_groups, user_directory_groups, users.auth_source 'automation', api_tokens.service_ids); this
-- migration adds what the phase needs beyond them.

-- An automation account never signs in (design §6.2): no session, no authenticator and no recovery code is ever made
-- for it. The application never tries (every sign-in path matches local, SSO or directory users only); this trigger
-- holds it for every other writer (SQLSTATE Z1029).
-- +goose StatementBegin
CREATE FUNCTION refuse_automation_credentials() RETURNS trigger LANGUAGE plpgsql
SET search_path = pg_catalog, pg_temp AS $$
BEGIN
    IF EXISTS (SELECT 1 FROM public.users u WHERE u.id = NEW.user_id AND u.auth_source = 'automation') THEN
        RAISE EXCEPTION 'an automation account cannot sign in' USING ERRCODE = 'Z1029';
    END IF;
    RETURN NEW;
END $$;
-- +goose StatementEnd
CREATE TRIGGER sessions_no_automation BEFORE INSERT OR UPDATE OF user_id ON sessions
    FOR EACH ROW EXECUTE FUNCTION refuse_automation_credentials();
CREATE TRIGGER user_mfa_no_automation BEFORE INSERT OR UPDATE OF user_id ON user_mfa
    FOR EACH ROW EXECUTE FUNCTION refuse_automation_credentials();
CREATE TRIGGER recovery_codes_no_automation BEFORE INSERT OR UPDATE OF user_id ON recovery_codes
    FOR EACH ROW EXECUTE FUNCTION refuse_automation_credentials();

-- The values seen at sign-in by value: the Groups tab counts the people seen in a group, and the owner teams of Phase 4
-- find a group's members.
CREATE INDEX user_directory_groups_value ON user_directory_groups (value);

-- +goose Down
DROP INDEX user_directory_groups_value;
DROP TRIGGER recovery_codes_no_automation ON recovery_codes;
DROP TRIGGER user_mfa_no_automation ON user_mfa;
DROP TRIGGER sessions_no_automation ON sessions;
DROP FUNCTION refuse_automation_credentials();
