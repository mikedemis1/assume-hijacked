-- The protection flags: add only. Applied to every database after 06-risk.sql.
--
-- A flag says that someone in a home depends on electricity (life-support equipment). A home with
-- a flag never gets an automatic disconnection order (01-schema.sql, check_disconnection_order).
-- Losing a flag is the one change that can hurt someone; adding one is always safe. So:
--
--   who             may                                          through
--   --------------  -------------------------------------------  --------------------------------
--   tool role       add a flag for its ticket's home only          api_set_temp_protection (05)
--   anyone else     nothing
--
-- Nobody may change or delete a flag, not even the executor, the approver, a tool role or
-- api_owner: no grant allows it, and behind the grants refuse_flag_change() refuses every UPDATE
-- and every DELETE by any role, and refuse_flags_truncate() refuses TRUNCATE. So a grant added by
-- mistake, or the superuser, still cannot drop a flag directly. A flag is removed only by a
-- database administrator by hand, outside the app, who first switches the trigger off. (The test
-- suite's reset switches triggers off for its own TRUNCATE: tests/conftest.py.)

-- Statement-level, so it refuses even a statement that matches no row. Not SECURITY DEFINER: it
-- runs as the role making the change.
CREATE FUNCTION refuse_flag_change() RETURNS trigger
LANGUAGE plpgsql SET search_path = public, pg_temp AS $$
BEGIN
    RAISE EXCEPTION 'flags cannot be changed or deleted; they can only be added';
END $$;

CREATE TRIGGER flags_no_update BEFORE UPDATE ON flags
    FOR EACH STATEMENT EXECUTE FUNCTION refuse_flag_change();
CREATE TRIGGER flags_no_delete BEFORE DELETE ON flags
    FOR EACH STATEMENT EXECUTE FUNCTION refuse_flag_change();

-- Only the table owner (the superuser) may truncate at all; this refuses it too.
CREATE FUNCTION refuse_flags_truncate() RETURNS trigger
LANGUAGE plpgsql SET search_path = public, pg_temp AS $$
BEGIN
    RAISE EXCEPTION 'cannot truncate %: flags can only be added', TG_TABLE_NAME;
END $$;

CREATE TRIGGER flags_no_truncate BEFORE TRUNCATE ON flags
    FOR EACH STATEMENT EXECUTE FUNCTION refuse_flags_truncate();

REVOKE ALL ON FUNCTION refuse_flag_change(), refuse_flags_truncate() FROM PUBLIC;
