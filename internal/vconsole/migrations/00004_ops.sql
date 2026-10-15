-- +goose Up
-- The newest audit row and its hash: the checkpoint the weekly summary mails to the owner. The
-- notifier has no column grant on audit, so it reads the head only through this function.
-- +goose StatementBegin
CREATE FUNCTION audit_head() RETURNS TABLE (seq bigint, hash text)
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = public, pg_temp AS $$
    SELECT a.seq, a.hash FROM audit a ORDER BY a.seq DESC LIMIT 1
$$;
-- +goose StatementEnd

REVOKE ALL ON FUNCTION audit_head() FROM PUBLIC;
GRANT EXECUTE ON FUNCTION audit_head() TO vendor_owner, vendor_notifier;

-- +goose Down
DROP FUNCTION audit_head();
