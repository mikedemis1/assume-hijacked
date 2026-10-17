-- The protection flags and who may change them. Applied to every database after 06-risk.sql.
--
-- A flag says that someone in a home depends on electricity (life-support equipment, from the
-- state register). No flag and a fresh register means the home may be disconnected, so losing a
-- flag is the one change that can hurt someone. Adding one is always safe.
--
--   who             may                                          through
--   --------------  -------------------------------------------  --------------------------------
--   register_sync   add a flag; mark the register freshly synced  sync_add_flag, sync_heartbeat
--   tool role       add a flag for its ticket's home only          api_set_temp_protection (05)
--   approver        ask to remove a flag; approve a removal        request_flag_removal,
--                   (the second distinct senior deletes it and      approve_flag_removal
--                   raises an ALERT)
--   anyone else     nothing
--
-- Two NOLOGIN owners, so that the function register-sync calls runs as a role that cannot delete:
--   flags_admin    owns the sync functions: INSERT on flags, the register_sync row. No DELETE.
--   flags_remover  owns the removal functions: DELETE on flags, the removal tables. No INSERT
--                  on flags. The only role with DELETE on flags.
-- Behind the grants, refuse_flag_change() refuses every UPDATE of a flag (moving one to another
-- home is a removal for the first) and every DELETE not made by flags_remover, so a grant added
-- by mistake, or the superuser, still cannot drop a flag directly.
--
-- What the database cannot check (decision 8, v1): that the person behind an approval is a
-- SeniorApprover. The console checks the app role in the staff member's Entra token before it
-- calls approve_flag_removal (as for resume_agents); the database makes sure two distinct people
-- approved, and records them.

-- Statement-level, so it refuses even a statement that matches no row. Not SECURITY DEFINER: it
-- runs as the role making the change, which is flags_remover only inside approve_flag_removal.
-- TRUNCATE is not caught: only the table owner (the superuser) may truncate, and the test suite
-- resets with it.
CREATE FUNCTION refuse_flag_change() RETURNS trigger
LANGUAGE plpgsql SET search_path = public, pg_temp AS $$
BEGIN
    IF TG_OP = 'DELETE' AND current_user = 'flags_remover' THEN
        RETURN NULL;
    END IF;
    RAISE EXCEPTION 'flags cannot be changed or deleted directly; use request_flag_removal and approve_flag_removal';
END $$;

CREATE TRIGGER flags_no_update BEFORE UPDATE ON flags
    FOR EACH STATEMENT EXECUTE FUNCTION refuse_flag_change();
CREATE TRIGGER flags_delete_only_by_removal BEFORE DELETE ON flags
    FOR EACH STATEMENT EXECUTE FUNCTION refuse_flag_change();


-- ---------------------------------------------------------------------------------------------
-- Register sync: add only.
--
-- sync_add_flag adds the flag for one home the register lists, or leaves an existing one as it
-- is. It takes the home's advisory lock first, the one the executor holds from its protection
-- check to the order (and the order trigger takes), so a flag cannot land between the two.
-- An unknown home raises no_data_found, so the sync can count it and go on. The source is a short
-- name such as state_register, never free text that could carry a diagnosis.
CREATE FUNCTION sync_add_flag(p_sp text, p_source text) RETURNS void
LANGUAGE plpgsql SECURITY DEFINER SET search_path = public, pg_temp AS $$
BEGIN
    IF session_user <> 'register_sync' THEN
        RAISE EXCEPTION '% may not sync the register', session_user;
    END IF;
    IF p_source IS NULL OR p_source !~ '^[a-z_]{1,40}$' THEN
        RAISE EXCEPTION 'flag source must be a short name (a-z and _), got %', coalesce(left(p_source, 40), 'NULL');
    END IF;
    IF NOT EXISTS (SELECT 1 FROM public.supply_points WHERE id = p_sp) THEN
        RAISE EXCEPTION 'unknown supply point %', left(p_sp, 40) USING ERRCODE = 'no_data_found';
    END IF;
    PERFORM pg_advisory_xact_lock(hashtext(p_sp));
    INSERT INTO public.flags (supply_point_id, source) VALUES (p_sp, p_source)
    ON CONFLICT (supply_point_id) DO NOTHING;
END $$;

-- The register was read in full and every listed home is flagged. Unflagged homes count as not
-- protected only while this is less than 24 hours old (check_disconnection_order, home_protection,
-- app/executor/protection.py); a sync that fails leaves it to age, and the homes turn UNKNOWN.
CREATE FUNCTION sync_heartbeat() RETURNS void
LANGUAGE plpgsql SECURITY DEFINER SET search_path = public, pg_temp AS $$
BEGIN
    IF session_user <> 'register_sync' THEN
        RAISE EXCEPTION '% may not sync the register', session_user;
    END IF;
    INSERT INTO public.register_sync AS s (id, last_success) VALUES (1, now())
    ON CONFLICT (id) DO UPDATE SET last_success = excluded.last_success;
END $$;


-- ---------------------------------------------------------------------------------------------
-- Removing a flag: a request, then two distinct SeniorApprovers.
--
-- done_at closes a request once it removed its flag, so a later approval on it cannot remove a
-- flag the register adds back afterwards.
CREATE TABLE flag_removal_requests (
    id              serial PRIMARY KEY,
    supply_point_id text NOT NULL REFERENCES supply_points,
    reason          text NOT NULL,
    requested_by    text NOT NULL,
    created_at      timestamptz NOT NULL DEFAULT now(),
    done_at         timestamptz
);

-- approver is stored folded (lower case, no surrounding white space), so the primary key itself
-- refuses one person twice however they spell their id.
CREATE TABLE flag_removal_approvals (
    request_id    int NOT NULL REFERENCES flag_removal_requests,
    approver      text NOT NULL,
    approver_role text NOT NULL CHECK (approver_role = 'SeniorApprover'),
    created_at    timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (request_id, approver)
);

-- The reason stays in the table (staff read it in the console); the event names ids only, since
-- a reason may mention the equipment.
CREATE FUNCTION request_flag_removal(p_sp text, p_reason text, p_by text) RETURNS int
LANGUAGE plpgsql SECURITY DEFINER SET search_path = public, pg_temp AS $$
DECLARE
    v_reason text := btrim(p_reason, E' \t\r\n');
    v_by     text := lower(btrim(p_by, E' \t\r\n'));
    v_id     int;
BEGIN
    IF session_user <> 'approver' THEN
        RAISE EXCEPTION '% may not ask to remove a flag', session_user;
    END IF;
    IF NOT EXISTS (SELECT 1 FROM public.flags WHERE supply_point_id = p_sp) THEN
        RAISE EXCEPTION 'no protection flag on %', left(p_sp, 40);
    END IF;
    IF v_reason IS NULL OR v_reason = '' OR length(v_reason) > 500 THEN
        RAISE EXCEPTION 'a removal needs a reason of 1 to 500 characters';
    END IF;
    IF v_by IS NULL OR v_by = '' THEN
        RAISE EXCEPTION 'a removal needs the requester';
    END IF;
    INSERT INTO public.flag_removal_requests (supply_point_id, reason, requested_by)
    VALUES (p_sp, v_reason, v_by) RETURNING id INTO v_id;
    INSERT INTO public.events (kind, detail)
    VALUES ('flag_removal_requested', format('request=%s supply_point=%s', v_id, p_sp));
    RETURN v_id;
END $$;

-- True when this approval was the second distinct one and the flag is gone. The request row is
-- locked first, so two seniors approving at the same moment are counted one after the other:
-- without the lock each would see only its own approval and neither would remove the flag.
-- The ALERT's actor is flags_remover (the column default, current_user here): the approver role
-- can write events, but only as itself, so a genuine removal alert cannot be forged.
CREATE FUNCTION approve_flag_removal(p_request int, p_approver text) RETURNS boolean
LANGUAGE plpgsql SECURITY DEFINER SET search_path = public, pg_temp AS $$
DECLARE
    v_who text := lower(btrim(p_approver, E' \t\r\n'));
    v_req record;
    v_n   int;
BEGIN
    IF session_user <> 'approver' THEN
        RAISE EXCEPTION '% may not approve a flag removal', session_user;
    END IF;
    IF v_who IS NULL OR v_who = '' THEN
        RAISE EXCEPTION 'a removal approval needs the approver';
    END IF;
    SELECT id, supply_point_id, done_at INTO v_req
    FROM public.flag_removal_requests WHERE id = p_request FOR UPDATE;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'unknown flag removal request %', p_request;
    END IF;
    IF v_req.done_at IS NOT NULL THEN
        RAISE EXCEPTION 'flag removal request % is already done', p_request;
    END IF;
    INSERT INTO public.flag_removal_approvals (request_id, approver, approver_role)
    VALUES (p_request, v_who, 'SeniorApprover')
    ON CONFLICT (request_id, approver) DO NOTHING;
    SELECT count(*) INTO v_n FROM public.flag_removal_approvals WHERE request_id = p_request;
    IF v_n < 2 THEN
        RETURN false;
    END IF;
    DELETE FROM public.flags WHERE supply_point_id = v_req.supply_point_id;
    UPDATE public.flag_removal_requests SET done_at = now() WHERE id = p_request;
    INSERT INTO public.events (kind, detail)
    VALUES ('ALERT', format('protection flag removed supply_point=%s request=%s', v_req.supply_point_id, p_request));
    RETURN true;
END $$;


-- Who holds what. No login role has a grant on flags, register_sync or the removal tables beyond
-- what is listed here; register_sync has none at all, only EXECUTE on its two functions and beat().
GRANT USAGE ON SCHEMA public TO flags_admin, flags_remover;

GRANT SELECT (supply_point_id), INSERT (supply_point_id, source) ON flags TO flags_admin;
GRANT SELECT (id) ON supply_points TO flags_admin;
GRANT SELECT, INSERT (id, last_success), UPDATE (last_success) ON register_sync TO flags_admin;
-- Advisory locks are closed to PUBLIC (03-grants.sql); sync_add_flag takes the home's lock.
GRANT EXECUTE ON FUNCTION pg_advisory_xact_lock(bigint) TO flags_admin;

GRANT SELECT (supply_point_id), DELETE ON flags TO flags_remover;
GRANT SELECT, INSERT (supply_point_id, reason, requested_by), UPDATE (done_at) ON flag_removal_requests
    TO flags_remover;
GRANT USAGE ON SEQUENCE flag_removal_requests_id_seq TO flags_remover;
GRANT SELECT, INSERT (request_id, approver, approver_role) ON flag_removal_approvals TO flags_remover;
GRANT INSERT (kind, detail) ON events TO flags_remover;
GRANT USAGE ON SEQUENCE events_id_seq TO flags_remover;

-- The console lists the open requests and who approved them.
GRANT SELECT ON flag_removal_requests, flag_removal_approvals TO approver;

ALTER FUNCTION sync_add_flag(text, text) OWNER TO flags_admin;
ALTER FUNCTION sync_heartbeat() OWNER TO flags_admin;
ALTER FUNCTION request_flag_removal(text, text, text) OWNER TO flags_remover;
ALTER FUNCTION approve_flag_removal(int, text) OWNER TO flags_remover;
REVOKE ALL ON FUNCTION sync_add_flag(text, text), sync_heartbeat(), request_flag_removal(text, text, text),
    approve_flag_removal(int, text), refuse_flag_change() FROM PUBLIC;
GRANT EXECUTE ON FUNCTION sync_add_flag(text, text), sync_heartbeat() TO register_sync;
GRANT EXECUTE ON FUNCTION request_flag_removal(text, text, text), approve_flag_removal(int, text) TO approver;
