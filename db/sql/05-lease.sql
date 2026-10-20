-- Leases and the lease-based tool functions. Applied to every database after 03-grants.sql.
--
-- A lease is a random token that ties one agent run to one ticket and a list of tools. The
-- dispatcher opens it when the agent claims a ticket and revokes it when the reply is stored. A
-- tool never names a ticket: it passes the lease to its one api_* function, and the function
-- reads the ticket from the lease. A tool role has no table grant at all (03-grants.sql), so a
-- hijacked tool can reach no other customer's data, and no data once the lease has ended.
--
-- The database keeps only sha256(lease), the lease as UTF-8 text (hashlib.sha256(lease.encode())
-- in Python). A copy of the leases table gives nobody a usable lease.
--
-- Every function here is SECURITY DEFINER (it runs with its owner's privileges) with a fixed
-- search_path, so a caller cannot put its own objects in front of the tables. PostgreSQL grants
-- EXECUTE on a new function to PUBLIC, so each one is revoked from PUBLIC and granted to its
-- callers by name.
--
-- Lease checks use clock_timestamp(), the wall clock of the database server. now() is frozen at
-- the start of a transaction, so a session that opened one early would keep an expired lease
-- alive for as long as it held the transaction.

-- pgcrypto, for gen_random_bytes. In its own schema with no USAGE for anyone but lease_owner:
-- the extension's functions are executable by PUBLIC, but no other role can name them.
CREATE SCHEMA crypto;
CREATE EXTENSION pgcrypto WITH SCHEMA crypto;
REVOKE ALL ON SCHEMA crypto FROM PUBLIC;
GRANT USAGE ON SCHEMA crypto TO lease_owner;
-- The default privileges (01-schema.sql) leave the extension's functions closed too.
GRANT EXECUTE ON FUNCTION crypto.gen_random_bytes(int) TO lease_owner;

CREATE TABLE leases (
    id            bigserial PRIMARY KEY,
    token_hash    bytea UNIQUE NOT NULL,
    ticket_id     int NOT NULL REFERENCES tickets,
    allowed_tools text[] NOT NULL CHECK (
        cardinality(allowed_tools) > 0
        AND allowed_tools <@ ARRAY['read_ticket', 'lookup_account', 'request_disconnection',
                                   'issue_bill_credit', 'set_temp_protection']
    ),
    bound_pod     text,
    expires_at    timestamptz NOT NULL,
    revoked       bool NOT NULL DEFAULT false,
    created_at    timestamptz NOT NULL DEFAULT now()
);

-- Returns the lease once. 32 random bytes as hex; only the hash is stored. 15 minutes is the
-- longest one agent run may take, several times the 300 s activeDeadlineSeconds of its Job.
CREATE FUNCTION open_lease(p_ticket int, p_tools text[], p_bound_pod text) RETURNS text
LANGUAGE plpgsql SECURITY DEFINER SET search_path = public, pg_temp AS $$
DECLARE
    v_lease text := encode(crypto.gen_random_bytes(32), 'hex');
BEGIN
    INSERT INTO public.leases (token_hash, ticket_id, allowed_tools, bound_pod, expires_at)
    VALUES (sha256(convert_to(v_lease, 'UTF8')), p_ticket, p_tools, p_bound_pod,
            clock_timestamp() + interval '15 minutes');
    RETURN v_lease;
END $$;

-- Idempotent: revoking an unknown or already revoked lease changes nothing.
CREATE FUNCTION revoke_lease(p_lease text) RETURNS void
LANGUAGE sql SECURITY DEFINER SET search_path = public, pg_temp AS $$
    UPDATE public.leases SET revoked = true
    WHERE token_hash = sha256(convert_to(p_lease, 'UTF8'));
$$;

-- What a live lease allows. No row for an unknown, expired or revoked lease.
CREATE FUNCTION lease_scope(p_lease text)
RETURNS TABLE(ticket_id int, allowed_tools text[], bound_pod text, expires_at timestamptz)
LANGUAGE sql SECURITY DEFINER SET search_path = public, pg_temp AS $$
    SELECT l.ticket_id, l.allowed_tools, l.bound_pod, l.expires_at
    FROM public.leases l
    WHERE l.token_hash = sha256(convert_to(p_lease, 'UTF8'))
      AND NOT l.revoked
      AND l.expires_at > clock_timestamp();
$$;

GRANT SELECT, INSERT ON leases TO lease_owner;
GRANT UPDATE (revoked) ON leases TO lease_owner;
GRANT USAGE ON SEQUENCE leases_id_seq TO lease_owner;
ALTER FUNCTION open_lease(int, text[], text) OWNER TO lease_owner;
ALTER FUNCTION revoke_lease(text) OWNER TO lease_owner;
ALTER FUNCTION lease_scope(text) OWNER TO lease_owner;
REVOKE ALL ON FUNCTION open_lease(int, text[], text), revoke_lease(text), lease_scope(text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION open_lease(int, text[], text), revoke_lease(text) TO dispatcher;
GRANT EXECUTE ON FUNCTION lease_scope(text) TO gateway, dispatcher;


-- The lease check every tool function starts with, in one place. It returns the lease's ticket,
-- or raises 'lease invalid' (the same text for every case, so a caller learns nothing about which
-- leases exist) unless all of these hold:
--
--   1. The transaction is READ COMMITTED. In REPEATABLE READ or SERIALIZABLE every statement reads
--      the snapshot taken when the transaction started, so a tool that took one while its lease
--      was live would not see the lease being revoked. In READ COMMITTED each statement of this
--      (volatile) function reads a fresh snapshot.
--   2. session_user is the tool's role. session_user is the role that logged in; inside the
--      SECURITY DEFINER api_* functions current_user is their owner (api_owner), so current_user
--      cannot tell who called. A login role cannot change its session_user (only a superuser can,
--      with SET SESSION AUTHORIZATION), and SET ROLE changes current_user only. So a role that was
--      granted another tool's function by mistake, or a member of a tool role, is refused.
--   3. The lease is known, not revoked and not expired (clock_timestamp(), see the top).
--   4. The lease lists the tool.
--
-- p_tool comes from the calling api_* function, where it is a constant. The helper is not SECURITY
-- DEFINER: it runs as its caller, api_owner, and only api_owner may execute it, so no tool role
-- can call it with a tool name of its choosing.
CREATE FUNCTION lease_ticket_for_tool(p_lease text, p_tool text) RETURNS int
LANGUAGE plpgsql SET search_path = public, pg_temp AS $$
DECLARE
    v_ticket int;
BEGIN
    IF current_setting('transaction_isolation') <> 'read committed' THEN
        RAISE EXCEPTION 'lease invalid';
    END IF;
    SELECT l.ticket_id INTO v_ticket FROM public.leases l
    WHERE session_user = 'tool_' || p_tool
      AND l.token_hash = sha256(convert_to(p_lease, 'UTF8'))
      AND NOT l.revoked AND l.expires_at > clock_timestamp()
      AND p_tool = ANY (l.allowed_tools)
    FOR SHARE;
    IF v_ticket IS NULL THEN
        RAISE EXCEPTION 'lease invalid';
    END IF;
    RETURN v_ticket;
END $$;

-- The five tool functions. Each one is granted to exactly one tool role, starts with the lease
-- check above for its own, fixed tool name, and takes no argument that names a ticket, a customer
-- or an account.

CREATE FUNCTION api_read_ticket(p_lease text) RETURNS TABLE(id int, body text)
LANGUAGE plpgsql SECURITY DEFINER SET search_path = public, pg_temp AS $$
DECLARE
    v_ticket int;
BEGIN
    v_ticket := public.lease_ticket_for_tool(p_lease, 'read_ticket');
    RETURN QUERY SELECT t.id, t.body FROM public.tickets t WHERE t.id = v_ticket;
END $$;

-- The ticket owner's account: name, tariff, status, address. Never phone or flags.
CREATE FUNCTION api_lookup_account(p_lease text)
RETURNS TABLE(name text, tariff text, status text, address text)
LANGUAGE plpgsql SECURITY DEFINER SET search_path = public, pg_temp AS $$
DECLARE
    v_ticket int;
BEGIN
    v_ticket := public.lease_ticket_for_tool(p_lease, 'lookup_account');
    RETURN QUERY
        SELECT c.name, a.tariff, a.status, s.address
        FROM public.tickets t
        JOIN public.accounts a ON a.customer_id = t.customer_id
        JOIN public.customers c ON c.id = a.customer_id
        JOIN public.supply_points s ON s.id = a.supply_point_id
        WHERE t.id = v_ticket;
END $$;

-- A move-out request for the ticket owner's account. check_action_request (01-schema.sql) still
-- refuses a date before today (UTC). Returns the request id.
CREATE FUNCTION api_request_moveout(p_lease text, p_date date) RETURNS int
LANGUAGE plpgsql SECURITY DEFINER SET search_path = public, pg_temp AS $$
DECLARE
    v_ticket  int;
    v_account int;
    v_id      int;
BEGIN
    v_ticket := public.lease_ticket_for_tool(p_lease, 'request_disconnection');
    SELECT a.id INTO STRICT v_account
    FROM public.tickets t JOIN public.accounts a ON a.customer_id = t.customer_id
    WHERE t.id = v_ticket;
    BEGIN
        INSERT INTO public.action_requests (kind, ticket_id, account_id, move_out_date, lease_hash)
        VALUES ('move_out', v_ticket, v_account, p_date, sha256(convert_to(p_lease, 'UTF8')))
        RETURNING id INTO v_id;
    EXCEPTION WHEN unique_violation THEN
        RAISE EXCEPTION 'effect already requested';  -- fixed text: no index name, no lease
    END;
    RETURN v_id;
END $$;

-- A credit request for the ticket owner's account. The reason must be on the closed list here
-- too: the tool code checks it first, but a hijacked tool process could skip that check. The
-- amount must be a positive, finite number: numeric takes 'NaN' (which PostgreSQL sorts above
-- every number, so `> 0` alone lets it through) and, since PostgreSQL 14, 'Infinity'. The
-- action_requests column constraint is the backstop. Returns the request id.
CREATE FUNCTION api_request_credit(p_lease text, p_amount numeric, p_reason text, p_evidence int)
RETURNS int
LANGUAGE plpgsql SECURITY DEFINER SET search_path = public, pg_temp AS $$
DECLARE
    v_ticket  int;
    v_account int;
    v_id      int;
BEGIN
    v_ticket := public.lease_ticket_for_tool(p_lease, 'issue_bill_credit');
    IF p_amount IS NULL OR NOT (p_amount > 0 AND p_amount < 'Infinity') THEN
        RAISE EXCEPTION 'credit amount must be a positive finite number';
    END IF;
    IF p_reason IS NULL OR p_reason NOT IN ('duplicate_charge', 'outage', 'late_technician') THEN
        RAISE EXCEPTION 'credit reason is not on the closed list';
    END IF;
    SELECT a.id INTO STRICT v_account
    FROM public.tickets t JOIN public.accounts a ON a.customer_id = t.customer_id
    WHERE t.id = v_ticket;
    BEGIN
        INSERT INTO public.action_requests (kind, ticket_id, account_id, amount_eur, reason, evidence_ref, lease_hash)
        VALUES ('credit', v_ticket, v_account, p_amount, p_reason, p_evidence,
                sha256(convert_to(p_lease, 'UTF8')))
        RETURNING id INTO v_id;
    EXCEPTION WHEN unique_violation THEN
        RAISE EXCEPTION 'effect already requested';  -- fixed text: no index name, no lease
    END;
    RETURN v_id;
END $$;

-- The only way into flags from a tool: adds YES for the ticket owner's home, never
-- removes or downgrades. The advisory lock is the one check_disconnection_order takes, so a flag
-- being added and an order being written for the same home cannot interleave. The event's actor
-- is session_user, the tool role (current_user here is api_owner).
CREATE FUNCTION api_set_temp_protection(p_lease text) RETURNS text
LANGUAGE plpgsql SECURITY DEFINER SET search_path = public, pg_temp AS $$
DECLARE
    v_ticket int;
    v_sp     text;
BEGIN
    v_ticket := public.lease_ticket_for_tool(p_lease, 'set_temp_protection');
    SELECT a.supply_point_id INTO STRICT v_sp
    FROM public.tickets t JOIN public.accounts a ON a.customer_id = t.customer_id
    WHERE t.id = v_ticket;
    PERFORM pg_advisory_xact_lock(hashtext(v_sp));
    INSERT INTO public.flags (supply_point_id, source) VALUES (v_sp, 'customer_declared')
    ON CONFLICT (supply_point_id) DO NOTHING;
    INSERT INTO public.events (kind, actor, detail)
    VALUES ('temp_protection_set', session_user, v_sp);
    RETURN 'recorded';
END $$;

-- api_owner holds exactly what the five functions read and write. Column lists, so not even
-- these functions could read a phone number or a ticket's status by a later edit by mistake.
GRANT SELECT (token_hash, ticket_id, allowed_tools, expires_at, revoked) ON leases TO api_owner;  -- the lease check
GRANT SELECT (id, customer_id, body) ON tickets TO api_owner;
GRANT SELECT (id, name) ON customers TO api_owner;
GRANT SELECT (id, customer_id, supply_point_id, tariff, status) ON accounts TO api_owner;
GRANT SELECT (id, address) ON supply_points TO api_owner;
GRANT INSERT (kind, ticket_id, account_id, amount_eur, reason, evidence_ref, move_out_date, lease_hash)
    ON action_requests TO api_owner;
GRANT SELECT (id) ON action_requests TO api_owner;  -- for RETURNING id
GRANT USAGE ON SEQUENCE action_requests_id_seq TO api_owner;
GRANT SELECT (supply_point_id), INSERT (supply_point_id, source) ON flags TO api_owner;  -- SELECT for ON CONFLICT
GRANT INSERT (kind, actor, detail) ON events TO api_owner;
GRANT USAGE ON SEQUENCE events_id_seq TO api_owner;

ALTER FUNCTION lease_ticket_for_tool(text, text) OWNER TO api_owner;
REVOKE ALL ON FUNCTION lease_ticket_for_tool(text, text) FROM PUBLIC;
ALTER FUNCTION api_read_ticket(text) OWNER TO api_owner;
ALTER FUNCTION api_lookup_account(text) OWNER TO api_owner;
ALTER FUNCTION api_request_moveout(text, date) OWNER TO api_owner;
ALTER FUNCTION api_request_credit(text, numeric, text, int) OWNER TO api_owner;
ALTER FUNCTION api_set_temp_protection(text) OWNER TO api_owner;
REVOKE ALL ON FUNCTION api_read_ticket(text), api_lookup_account(text),
    api_request_moveout(text, date), api_request_credit(text, numeric, text, int),
    api_set_temp_protection(text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION api_read_ticket(text) TO tool_read_ticket;
GRANT EXECUTE ON FUNCTION api_lookup_account(text) TO tool_lookup_account;
GRANT EXECUTE ON FUNCTION api_request_moveout(text, date) TO tool_request_disconnection;
GRANT EXECUTE ON FUNCTION api_request_credit(text, numeric, text, int) TO tool_issue_bill_credit;
GRANT EXECUTE ON FUNCTION api_set_temp_protection(text) TO tool_set_temp_protection;


-- ---------------------------------------------------------------------------------------------
-- What the tool gateway records about every call (app/gateway/proxy.py).
--
-- One row per call that reached the gateway with a lease header, allowed or not. The row holds
-- names and categories only: sha256(lease) as everywhere (never the lease), the tool name, the
-- names of the arguments that were forwarded and of those that were dropped (never a value), and
-- how the call ended:
--
--   ok            the tool answered
--   tool_error    the tool answered with an error (reason: the category the agent was told)
--   denied        a wall refused it (reason: lease, pod_mismatch, paused, descriptor_changed, or
--                 the risk engine's own reason)
--   unavailable   the tool, the risk engine or the database could not be reached (reason says which)
--   risk_timeout  the risk engine did not answer in time. It may still have written "allow" for the
--                 call (and with it used up the lease's one effect), so this is kept apart from a
--                 plain denial: an investigator can see why a later honest call was refused.
--
-- Append only: the gateway holds INSERT on these columns and nothing else, and the trigger is the
-- wall behind the grants (the superuser too cannot change a row; TRUNCATE is not caught, only the
-- table owner may do it, and the test suite resets with it).
CREATE TABLE tool_calls (
    id           bigserial PRIMARY KEY,
    lease_hash   bytea NOT NULL,
    tool         text NOT NULL,
    arg_names    text[] NOT NULL,
    dropped_args text[] NOT NULL,
    outcome      text NOT NULL CHECK (outcome IN ('ok', 'tool_error', 'denied', 'unavailable', 'risk_timeout')),
    reason       text NOT NULL DEFAULT '',
    actor        text NOT NULL DEFAULT current_user,
    created_at   timestamptz NOT NULL DEFAULT now()
);

CREATE FUNCTION refuse_tool_call_change() RETURNS trigger
LANGUAGE plpgsql SET search_path = public, pg_temp AS $$
BEGIN
    RAISE EXCEPTION 'tool_calls is append only';
END $$;

CREATE TRIGGER tool_calls_append_only BEFORE UPDATE OR DELETE ON tool_calls
    FOR EACH STATEMENT EXECUTE FUNCTION refuse_tool_call_change();
REVOKE ALL ON FUNCTION refuse_tool_call_change() FROM PUBLIC;

-- actor and created_at come from the column defaults, so the gateway cannot forge who or when.
GRANT INSERT (lease_hash, tool, arg_names, dropped_args, outcome, reason) ON tool_calls TO gateway;
GRANT USAGE ON SEQUENCE tool_calls_id_seq TO gateway;


-- ---------------------------------------------------------------------------------------------
-- The dispatcher's records (app/dispatcher): which agent run belongs to which ticket, and the
-- reply that went out.
--
-- agent_runs: one row per ticket, ever (UNIQUE ticket_id: one run per ticket, so two claims, or a
-- claim and a Job, can never start the same ticket twice).
--
--   started   the run exists. The dispatcher has created the agent's Job (job_name).
--   claimed   the agent asked for work and was given the lease (lease_hash is sha256 of it).
--   replied   the reply is stored and the lease is revoked.
--   failed    the Job could not be created. Nobody retries it: a person looks at the ticket.
--
-- lease_hash is empty until the claim, which is why the column may be NULL; the CHECK keeps a
-- claimed or replied run from having none. job_name is the one the dispatcher made up
-- (agent-<ticket>-<8 hex>, the same shape the Kubernetes admission policy accepts); the agent's pod is
-- named after it by the Job controller, which is how a claim finds its row.
CREATE TABLE agent_runs (
    id         serial PRIMARY KEY,
    ticket_id  int NOT NULL UNIQUE REFERENCES tickets,
    lease_hash bytea UNIQUE,
    job_name   text UNIQUE CHECK (job_name ~ '^agent-[0-9]{1,18}-[0-9a-f]{8}$'),
    status     text NOT NULL DEFAULT 'started' CHECK (status IN ('started', 'claimed', 'replied', 'failed')),
    created_at timestamptz NOT NULL DEFAULT now(),
    CHECK (status IN ('started', 'failed') OR lease_hash IS NOT NULL)
);

-- replies: the answer to a customer, one per ticket. What is stored passed the reply guard in the
-- dispatcher (outside the agent) and carries the notices the dispatcher added.
--
-- kind says where the text came from, so the console and Grafana can see it:
--   agent     the model's text passed the guard
--   safe      the guard replaced the model's text with SAFE_REPLY
--   template  an effect tool (credit, move-out) was called on the ticket, so the dispatcher stored a
--             fixed template and never the model's text
CREATE TABLE replies (
    ticket_id  int PRIMARY KEY REFERENCES tickets,
    text       text NOT NULL CHECK (text <> '' AND length(text) <= 10000),
    kind       text NOT NULL CHECK (kind IN ('agent', 'safe', 'template')),
    created_at timestamptz NOT NULL DEFAULT now()
);

-- The dispatcher holds column grants and nothing wider: ticket id and status (to pick the next
-- open ticket), the run rows, and the right to add a reply. It cannot read a ticket's text or any
-- customer data, and it cannot change or remove a reply or a run it did not just make.
GRANT SELECT (id, status) ON tickets TO dispatcher;
GRANT SELECT (id, ticket_id, job_name, status, created_at), INSERT (ticket_id, job_name, status),
    UPDATE (lease_hash, status) ON agent_runs TO dispatcher;
GRANT USAGE ON SEQUENCE agent_runs_id_seq TO dispatcher;
GRANT SELECT (ticket_id), INSERT (ticket_id, text, kind) ON replies TO dispatcher;

-- Completion waits behind tool transactions holding the lease row, then closes it before
-- reading the final facts. Successful effects are also read from action_requests because the
-- gateway's audit write follows the tool's commit over a separate connection. Only requests filed
-- after this lease opened count: an earlier run's request on the same ticket is not this run's.
CREATE FUNCTION finish_reply_facts(p_lease text, p_pod text)
RETURNS TABLE(ticket_id int, account_text text, credit_asked bool, moveout_submitted bool,
              effect_attempted bool, request_ids int[])
LANGUAGE plpgsql SECURITY DEFINER SET search_path = public, pg_temp AS $$
DECLARE
    v_ticket int;
    v_opened timestamptz;
    v_hash bytea := sha256(convert_to(p_lease, 'UTF8'));
BEGIN
    IF session_user <> 'dispatcher' OR current_setting('transaction_isolation') <> 'read committed' THEN
        RAISE EXCEPTION 'lease invalid';
    END IF;
    UPDATE public.leases l SET revoked = true
    WHERE l.token_hash = v_hash AND NOT l.revoked AND l.expires_at > clock_timestamp()
      AND l.bound_pod IS NOT DISTINCT FROM p_pod
    RETURNING l.ticket_id, l.created_at INTO v_ticket, v_opened;
    IF v_ticket IS NULL THEN RETURN; END IF;
    RETURN QUERY
      SELECT v_ticket, a.tariff || ' ' || a.status || ' ' || s.address,
        (EXISTS (SELECT 1 FROM public.tool_calls c WHERE c.lease_hash = v_hash AND c.tool = 'issue_bill_credit')
         OR EXISTS (SELECT 1 FROM public.action_requests r WHERE r.ticket_id = v_ticket AND r.kind = 'credit' AND r.created_at >= v_opened)),
        (EXISTS (SELECT 1 FROM public.tool_calls c WHERE c.lease_hash = v_hash AND c.tool = 'request_disconnection' AND c.outcome = 'ok')
         OR EXISTS (SELECT 1 FROM public.action_requests r WHERE r.ticket_id = v_ticket AND r.kind = 'move_out' AND r.created_at >= v_opened)),
        -- Any effect tool called on the lease (whatever it answered), or any request filed: the
        -- dispatcher stores a template then, never the model's text.
        (EXISTS (SELECT 1 FROM public.tool_calls c WHERE c.lease_hash = v_hash
                 AND c.tool IN ('issue_bill_credit', 'request_disconnection'))
         -- the risk engine writes its verdict before it answers, so a call the gateway has not
         -- recorded yet (or could not) still counts
         OR EXISTS (SELECT 1 FROM public.call_assessments a WHERE a.lease_hash = v_hash
                    AND a.tool IN ('issue_bill_credit', 'request_disconnection'))
         OR EXISTS (SELECT 1 FROM public.action_requests r WHERE r.ticket_id = v_ticket AND r.created_at >= v_opened)),
        ARRAY(SELECT r.id FROM public.action_requests r
              WHERE r.ticket_id = v_ticket AND r.created_at >= v_opened ORDER BY r.id)
      FROM public.tickets t JOIN public.accounts a ON a.customer_id = t.customer_id
      JOIN public.supply_points s ON s.id = a.supply_point_id WHERE t.id = v_ticket;
END $$;
GRANT UPDATE (revoked), SELECT (bound_pod, created_at) ON leases TO api_owner;
GRANT SELECT (ticket_id, kind, created_at) ON action_requests TO api_owner;
GRANT SELECT (lease_hash, tool, outcome) ON tool_calls TO api_owner;
ALTER FUNCTION finish_reply_facts(text, text) OWNER TO api_owner;
REVOKE ALL ON FUNCTION finish_reply_facts(text, text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION finish_reply_facts(text, text) TO dispatcher;


-- ---------------------------------------------------------------------------------------------
-- What the agent reports about its own drops (app/agent/core.py, app/dispatcher/main.py).
--
-- The agent has no database access. When it drops an argument the model may not set, or refuses an
-- unknown tool before the gateway, it sends that to the dispatcher with its reply, as names only: the
-- kind, the tool name and the argument names, never a value. The dispatcher checks the list again and
-- writes it with record_agent_events for the lease it resolved itself.
--
-- This is "reported by the agent": a hijacked agent pod could lie or leave events out. It is a
-- best-effort audit; the gateway's own records (tool_calls) stay the authority.
--
-- Append only: nobody holds a table grant (the dispatcher reaches the table only through the
-- function), and the trigger refuses UPDATE and DELETE even from the superuser.
CREATE TABLE agent_events (
    id          bigserial PRIMARY KEY,
    ticket_id   int NOT NULL REFERENCES tickets,
    lease_hash  bytea NOT NULL,
    kind        text NOT NULL CHECK (kind IN ('dropped_argument', 'unknown_tool')),
    tool        text NOT NULL CHECK (tool ~ '^[A-Za-z_][A-Za-z0-9_]{0,63}$'),
    arg_names   text[] NOT NULL CHECK (cardinality(arg_names) <= 16),
    reported_at timestamptz NOT NULL DEFAULT now(),
    source      text NOT NULL DEFAULT 'agent' CHECK (source = 'agent')
);

CREATE FUNCTION refuse_agent_event_change() RETURNS trigger
LANGUAGE plpgsql SET search_path = public, pg_temp AS $$
BEGIN
    RAISE EXCEPTION 'agent_events is append only';
END $$;

CREATE TRIGGER agent_events_append_only BEFORE UPDATE OR DELETE ON agent_events
    FOR EACH STATEMENT EXECUTE FUNCTION refuse_agent_event_change();
REVOKE ALL ON FUNCTION refuse_agent_event_change() FROM PUBLIC;

-- p_events is a JSON array of at most 32 objects {"kind", "tool", "args"} (exactly those keys); kind
-- is one of the two above, tool and every name in args match the identifier shape, and args has at
-- most 16 names. Anything else raises 'agent events invalid' and nothing is written. The ticket is
-- the live lease's, bound to p_pod, as in finish_reply_facts; for any other lease the function
-- returns NULL and writes nothing. Returns how many events were written. Call it before
-- finish_reply_facts, which revokes the lease.
CREATE FUNCTION record_agent_events(p_lease text, p_pod text, p_events jsonb) RETURNS int
LANGUAGE plpgsql SECURITY DEFINER SET search_path = public, pg_temp AS $$
DECLARE
    v_hash   bytea := sha256(convert_to(p_lease, 'UTF8'));
    v_ticket int;
    v_event  jsonb;
    v_name   jsonb;
    v_shape  text := '^[A-Za-z_][A-Za-z0-9_]{0,63}$';
BEGIN
    IF session_user <> 'dispatcher' OR current_setting('transaction_isolation') <> 'read committed' THEN
        RAISE EXCEPTION 'lease invalid';
    END IF;
    IF p_events IS NULL OR jsonb_typeof(p_events) <> 'array' OR jsonb_array_length(p_events) > 32 THEN
        RAISE EXCEPTION 'agent events invalid';
    END IF;
    FOR v_event IN SELECT e FROM jsonb_array_elements(p_events) AS e LOOP
        IF jsonb_typeof(v_event) <> 'object'
           OR (SELECT array_agg(k ORDER BY k) FROM jsonb_object_keys(v_event) AS k) IS DISTINCT FROM ARRAY['args', 'kind', 'tool']
           OR jsonb_typeof(v_event -> 'kind') <> 'string'
           OR (v_event ->> 'kind') NOT IN ('dropped_argument', 'unknown_tool')
           OR jsonb_typeof(v_event -> 'tool') <> 'string'
           OR (v_event ->> 'tool') !~ v_shape
           OR jsonb_typeof(v_event -> 'args') <> 'array'
           OR jsonb_array_length(v_event -> 'args') > 16 THEN
            RAISE EXCEPTION 'agent events invalid';
        END IF;
        FOR v_name IN SELECT n FROM jsonb_array_elements(v_event -> 'args') AS n LOOP
            IF jsonb_typeof(v_name) <> 'string' OR (v_name #>> '{}') !~ v_shape THEN
                RAISE EXCEPTION 'agent events invalid';
            END IF;
        END LOOP;
    END LOOP;
    SELECT l.ticket_id INTO v_ticket FROM public.leases l
    WHERE l.token_hash = v_hash AND NOT l.revoked AND l.expires_at > clock_timestamp()
      AND l.bound_pod IS NOT DISTINCT FROM p_pod;
    IF v_ticket IS NULL THEN RETURN NULL; END IF;
    INSERT INTO public.agent_events (ticket_id, lease_hash, kind, tool, arg_names)
    SELECT v_ticket, v_hash, e ->> 'kind', e ->> 'tool',
           ARRAY(SELECT n #>> '{}' FROM jsonb_array_elements(e -> 'args') AS n)
    FROM jsonb_array_elements(p_events) AS e;
    RETURN jsonb_array_length(p_events);
END $$;

GRANT INSERT (ticket_id, lease_hash, kind, tool, arg_names) ON agent_events TO api_owner;
GRANT USAGE ON SEQUENCE agent_events_id_seq TO api_owner;
ALTER FUNCTION record_agent_events(text, text, jsonb) OWNER TO api_owner;
REVOKE ALL ON FUNCTION record_agent_events(text, text, jsonb) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION record_agent_events(text, text, jsonb) TO dispatcher;
