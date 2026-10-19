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
--                   (the second distinct senior, never the          approve_flag_removal
--                   requester, deletes it and raises an ALERT)
--   anyone else     nothing
--
-- Two NOLOGIN owners, so that the function register-sync calls runs as a role that cannot delete:
--   flags_admin    owns the sync functions: INSERT on flags, the register_sync row. No DELETE.
--   flags_remover  owns the removal functions: DELETE on flags, the removal tables. No INSERT
--                  on flags. The only role with DELETE on flags.
-- Behind the grants, refuse_flag_change() refuses every UPDATE of a flag (moving one to another
-- home is a removal for the first) and every DELETE not made by flags_remover, and
-- refuse_register_truncate() refuses TRUNCATE of the four register tables, so a grant added by
-- mistake, or the superuser, still cannot drop a flag directly. (The test suite's reset switches
-- triggers off for its own TRUNCATE: tests/conftest.py.)
--
-- Staff are named by their Entra object id, a UUID. The functions cast the id to uuid, so one
-- person has exactly one spelling: case, braces, a no-break space or a look-alike letter either
-- fold into the same id or are refused, and cannot pass for a second person.
--
-- What the database cannot check (decision 8, v1): that the person behind an approval is a
-- SeniorApprover. The console checks the app role in the staff member's Entra token before it
-- calls approve_flag_removal (as for resume_agents); the database makes sure two distinct people
-- other than the requester approved, and records them.

-- Statement-level, so it refuses even a statement that matches no row. Not SECURITY DEFINER: it
-- runs as the role making the change, which is flags_remover only inside approve_flag_removal.
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

-- Only the table owner (the superuser) may truncate at all; this refuses it too.
CREATE FUNCTION refuse_register_truncate() RETURNS trigger
LANGUAGE plpgsql SET search_path = public, pg_temp AS $$
BEGIN
    RAISE EXCEPTION 'cannot truncate %: the register tables change only through the register functions', TG_TABLE_NAME;
END $$;

CREATE TRIGGER flags_no_truncate BEFORE TRUNCATE ON flags
    FOR EACH STATEMENT EXECUTE FUNCTION refuse_register_truncate();
CREATE TRIGGER register_sync_no_truncate BEFORE TRUNCATE ON register_sync
    FOR EACH STATEMENT EXECUTE FUNCTION refuse_register_truncate();


-- ---------------------------------------------------------------------------------------------
-- Register sync: add only.
--
-- sync_add_flag adds the flag for one home the register lists, or leaves an existing one as it
-- is, and says which: added, present, or unknown (a home this supplier does not serve). Unknown is
-- an answer, not an error: an error message would carry the home id into the server log on every
-- sync, and being on the life-support register is health data. No message here names a home.
-- It takes the home's advisory lock first, the one the executor holds from its protection check
-- to the order (and the order trigger takes), so a flag cannot land between the two. The source
-- is a short name such as state_register, never free text that could carry a diagnosis.
CREATE FUNCTION sync_add_flag(p_sp text, p_source text) RETURNS text
LANGUAGE plpgsql SECURITY DEFINER SET search_path = public, pg_temp AS $$
BEGIN
    IF session_user <> 'register_sync' THEN
        RAISE EXCEPTION '% may not sync the register', session_user;
    END IF;
    IF p_source IS NULL OR p_source !~ '^[a-z_]{1,40}$' THEN
        RAISE EXCEPTION 'flag source must be a short name (a-z and _, at most 40 characters)';
    END IF;
    IF NOT EXISTS (SELECT 1 FROM public.supply_points WHERE id = p_sp) THEN
        RETURN 'unknown';
    END IF;
    PERFORM pg_advisory_xact_lock(hashtext(p_sp));
    INSERT INTO public.flags (supply_point_id, source) VALUES (p_sp, p_source)
    ON CONFLICT (supply_point_id) DO NOTHING;
    IF FOUND THEN
        RETURN 'added';
    END IF;
    RETURN 'present';
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
-- Removing a flag: a request, then two distinct SeniorApprovers who are not the requester.
--
-- A request is raised against the flag the home has at that moment, and removes that flag or
-- nothing. done_at and closed_reason close it:
--   removed     its two approvals removed the flag
--   superseded  another request for the same home removed the flag first
--   stale       the home's flag is newer than the request (put back after a removal), so the
--               request no longer speaks for it
-- A closed request takes no more approvals, so a flag the register or a customer adds back later
-- needs a new request and two new approvals.
CREATE TABLE flag_removal_requests (
    id              serial PRIMARY KEY,
    supply_point_id text NOT NULL REFERENCES supply_points,
    reason          text NOT NULL,
    requested_by    uuid NOT NULL,
    created_at      timestamptz NOT NULL DEFAULT now(),
    done_at         timestamptz,
    closed_reason   text CHECK (closed_reason IN ('removed', 'superseded', 'stale')),
    CHECK ((done_at IS NULL) = (closed_reason IS NULL))
);

-- The primary key refuses one person twice: the approver is a uuid, so every spelling of the same
-- object id is the same value.
CREATE TABLE flag_removal_approvals (
    request_id    int NOT NULL REFERENCES flag_removal_requests,
    approver      uuid NOT NULL,
    approver_role text NOT NULL CHECK (approver_role = 'SeniorApprover'),
    created_at    timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (request_id, approver)
);

CREATE TRIGGER flag_removal_requests_no_truncate BEFORE TRUNCATE ON flag_removal_requests
    FOR EACH STATEMENT EXECUTE FUNCTION refuse_register_truncate();
CREATE TRIGGER flag_removal_approvals_no_truncate BEFORE TRUNCATE ON flag_removal_approvals
    FOR EACH STATEMENT EXECUTE FUNCTION refuse_register_truncate();

-- The reason stays in the table (staff read it in the console); the event names ids only, since
-- a reason may mention the equipment.
--
-- It takes the home's advisory lock first, like every other writer of a home's flag. A request is
-- filed against the flag that exists at that moment (approve_flag_removal compares the request's
-- time with the flag's), so it must not be filed while a removal, or a flag being added back, is
-- half done for the same home.
CREATE FUNCTION request_flag_removal(p_sp text, p_reason text, p_by text) RETURNS int
LANGUAGE plpgsql SECURITY DEFINER SET search_path = public, pg_temp AS $$
DECLARE
    v_reason text := btrim(p_reason, E' \t\r\n');
    v_by     uuid;
    v_id     int;
BEGIN
    IF session_user <> 'approver' THEN
        RAISE EXCEPTION '% may not ask to remove a flag', session_user;
    END IF;
    PERFORM pg_advisory_xact_lock(hashtext(p_sp));
    IF NOT EXISTS (SELECT 1 FROM public.flags WHERE supply_point_id = p_sp) THEN
        RAISE EXCEPTION 'no protection flag on that home';
    END IF;
    IF v_reason IS NULL OR v_reason = '' OR length(v_reason) > 500 THEN
        RAISE EXCEPTION 'a removal needs a reason of 1 to 500 characters';
    END IF;
    IF p_by IS NULL THEN
        RAISE EXCEPTION 'a removal needs the requester';
    END IF;
    BEGIN
        v_by := p_by::uuid;
    EXCEPTION WHEN invalid_text_representation THEN
        RAISE EXCEPTION 'the requester must be an Entra object id (a UUID)';
    END;
    INSERT INTO public.flag_removal_requests (supply_point_id, reason, requested_by)
    VALUES (p_sp, v_reason, v_by) RETURNING id INTO v_id;
    INSERT INTO public.events (kind, detail)
    VALUES ('flag_removal_requested', format('request=%s supply_point=%s', v_id, p_sp));
    RETURN v_id;
END $$;

-- True when this approval was the second distinct one and the flag is gone.
--
-- Locks, in this order: the home's advisory lock, then the request row. The advisory lock is the
-- one every flag writer takes (sync_add_flag, api_set_temp_protection), so the flag cannot be
-- added back between the check below and the delete, and two removals for the same home run one
-- after the other. (SELECT ... FOR UPDATE on flags would need UPDATE on flags, which nobody may
-- hold.) The row lock makes two seniors approving the same request at the same moment count one
-- after the other: without it each would see only its own approval and neither would remove.
-- The ALERT's actor is flags_remover (the column default, current_user here): the approver role
-- can write events, but only as itself, so a genuine removal alert cannot be forged.
CREATE FUNCTION approve_flag_removal(p_request int, p_approver text) RETURNS boolean
LANGUAGE plpgsql SECURITY DEFINER SET search_path = public, pg_temp AS $$
DECLARE
    v_who     uuid;
    v_sp      text;
    v_req     record;
    v_n       int;
    v_removed int;
BEGIN
    IF session_user <> 'approver' THEN
        RAISE EXCEPTION '% may not approve a flag removal', session_user;
    END IF;
    IF p_approver IS NULL THEN
        RAISE EXCEPTION 'a removal approval needs the approver';
    END IF;
    BEGIN
        v_who := p_approver::uuid;
    EXCEPTION WHEN invalid_text_representation THEN
        RAISE EXCEPTION 'the approver must be an Entra object id (a UUID)';
    END;
    SELECT supply_point_id INTO v_sp FROM public.flag_removal_requests WHERE id = p_request;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'unknown flag removal request %', p_request;
    END IF;
    PERFORM pg_advisory_xact_lock(hashtext(v_sp));
    SELECT id, supply_point_id, requested_by, created_at, done_at INTO v_req
    FROM public.flag_removal_requests WHERE id = p_request FOR UPDATE;
    IF v_req.done_at IS NOT NULL THEN
        RAISE EXCEPTION 'flag removal request % is closed', p_request;
    END IF;
    IF v_who = v_req.requested_by THEN
        RAISE EXCEPTION 'the requester of a flag removal cannot approve it';
    END IF;
    -- The flag this request was raised against: one that existed when the request was made.
    IF NOT EXISTS (SELECT 1 FROM public.flags
                   WHERE supply_point_id = v_req.supply_point_id AND created_at <= v_req.created_at) THEN
        UPDATE public.flag_removal_requests SET done_at = now(), closed_reason = 'stale' WHERE id = p_request;
        INSERT INTO public.events (kind, detail)
        VALUES ('flag_removal_closed', format('request=%s supply_point=%s reason=stale', p_request, v_req.supply_point_id));
        RETURN false;
    END IF;
    INSERT INTO public.flag_removal_approvals (request_id, approver, approver_role)
    VALUES (p_request, v_who, 'SeniorApprover')
    ON CONFLICT (request_id, approver) DO NOTHING;
    SELECT count(*) INTO v_n FROM public.flag_removal_approvals WHERE request_id = p_request;
    IF v_n < 2 THEN
        RETURN false;
    END IF;
    DELETE FROM public.flags WHERE supply_point_id = v_req.supply_point_id;
    GET DIAGNOSTICS v_removed = ROW_COUNT;
    IF v_removed <> 1 THEN
        RAISE EXCEPTION 'flag removal request % found no flag to remove', p_request;
    END IF;
    -- This request removed the flag; every other open request for the home spoke for that flag
    -- and is done too.
    UPDATE public.flag_removal_requests
    SET done_at = now(), closed_reason = CASE WHEN id = p_request THEN 'removed' ELSE 'superseded' END
    WHERE supply_point_id = v_req.supply_point_id AND done_at IS NULL;
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
-- Advisory locks are closed to PUBLIC (03-grants.sql); both owners take the home's lock.
GRANT EXECUTE ON FUNCTION pg_advisory_xact_lock(bigint) TO flags_admin, flags_remover;

GRANT SELECT (supply_point_id, created_at), DELETE ON flags TO flags_remover;
GRANT SELECT, INSERT (supply_point_id, reason, requested_by), UPDATE (done_at, closed_reason)
    ON flag_removal_requests TO flags_remover;
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
    approve_flag_removal(int, text), refuse_flag_change(), refuse_register_truncate() FROM PUBLIC;
GRANT EXECUTE ON FUNCTION sync_add_flag(text, text), sync_heartbeat() TO register_sync;
GRANT EXECUTE ON FUNCTION request_flag_removal(text, text, text), approve_flag_removal(int, text) TO approver;
