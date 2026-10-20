-- Risk assessments, the agents' stop switch, the approval floor, the risk engine's read functions
-- and the component heartbeats. Applied to every database after 05-lease.sql.
--
-- The risk engine judges every tool call (call_assessments) and every effect request
-- (risk_assessments) with the rules in app/risk/rules.py. Its verdict on an effect is a tier, and
-- the tier sets how many distinct staff must approve before the effect may happen:
--
--   tier        approvals needed           meaning
--   ----------  -------------------------  ----------------------------------------------------
--   T0          none                       automatic; the executor's own checks still apply
--   T1          1                          one member of staff
--   T2          2 distinct                 two people
--   HUMAN_ONLY  never                      a person handles it outside this system
--   REJECT      never                      refused
--
-- check_credit and check_disconnection_order (01-schema.sql) call check_approval_floor on every
-- row they guard. So the executor cannot write a credit or an order the floor does not allow,
-- whatever its code does, and a console cannot make one person count twice. Only the risk engine
-- writes assessments, one per request, and nobody can change or delete one afterwards: a hijacked
-- executor or console cannot lower a tier after the fact.
--
-- Who counts as staff: the staff table below, the allow-list of Entra object ids. Staff do not log
-- in to PostgreSQL; the console validates their Entra token and passes the object id to
-- approve_request and resume_agents, which refuse an id that is not on the list, is inactive, or
-- lacks the role. The console role cannot write an approval or the list. What the database still
-- cannot check is that the console passed the id of the person who really signed in: a console
-- that is compromised can approve as any listed person, but cannot invent one.

CREATE TABLE risk_assessments (
    id             serial PRIMARY KEY,
    request_id     int UNIQUE NOT NULL REFERENCES action_requests,
    tier           text NOT NULL CHECK (tier IN ('T0', 'T1', 'T2', 'HUMAN_ONLY', 'REJECT')),
    score          int NOT NULL,
    reasons        text[] NOT NULL,
    engine_version text NOT NULL,
    actor          text NOT NULL DEFAULT current_user,
    created_at     timestamptz NOT NULL DEFAULT now()
);

-- One row per tool call the gateway asked about (POST /decide). lease_hash is
-- sha256(lease), the same as leases.token_hash; never the lease itself.
CREATE TABLE call_assessments (
    id         bigserial PRIMARY KEY,
    lease_hash bytea NOT NULL,
    tool       text NOT NULL,
    decision   text NOT NULL CHECK (decision IN ('allow', 'deny', 'pause')),
    reasons    text[] NOT NULL,
    actor      text NOT NULL DEFAULT current_user,
    created_at timestamptz NOT NULL DEFAULT now()
);

-- Append only. Nobody holds UPDATE or DELETE on these tables; this trigger is the wall behind
-- the grants, so a grant added by mistake, or the superuser, still cannot change a verdict.
-- Statement-level, so it refuses even a statement that matches no row. TRUNCATE is not caught:
-- only the table owner (the superuser) may truncate, and the test suite resets with it.
CREATE FUNCTION refuse_assessment_change() RETURNS trigger
LANGUAGE plpgsql SET search_path = public, pg_temp AS $$
BEGIN
    RAISE EXCEPTION '% is append only', TG_TABLE_NAME;
END $$;

CREATE TRIGGER risk_assessments_append_only BEFORE UPDATE OR DELETE ON risk_assessments
    FOR EACH STATEMENT EXECUTE FUNCTION refuse_assessment_change();
CREATE TRIGGER call_assessments_append_only BEFORE UPDATE OR DELETE ON call_assessments
    FOR EACH STATEMENT EXECUTE FUNCTION refuse_assessment_change();

-- The staff allow-list (gap M2). The console role has no privilege on it; only the database
-- superuser or the migration changes it (docs/azure.md, "Staff"). oid is the Entra object id;
-- roles are the app roles, a closed set; active=false takes a person off without deleting the row.
CREATE TABLE staff (
    oid          uuid PRIMARY KEY,
    display_name text NOT NULL,
    roles        text[] NOT NULL CHECK (cardinality(roles) > 0 AND roles <@ ARRAY['Approver', 'SeniorApprover']),
    active       bool NOT NULL DEFAULT true
);
REVOKE ALL ON staff FROM PUBLIC;

-- The stop switch for every agent run. The gateway and the risk engine read it on each tool
-- call. The one row is seeded unpaused (04-seed.sql); there is never a second.
CREATE TABLE agent_control (
    id         int PRIMARY KEY CHECK (id = 1),
    paused     bool NOT NULL,
    reason     text NOT NULL DEFAULT '',
    changed_at timestamptz NOT NULL DEFAULT now()
);

-- The risk engine pauses (repeated denials on one lease, decision 5). Only a person resumes:
-- the console calls resume_agents(oid) after it has checked the SeniorApprover role, and the
-- function checks it again against the staff list. Both functions
-- check session_user, the role that logged in, as well as the grant, so an EXECUTE grant added
-- by mistake to another role is still refused. Each change is written to events with that role
-- as actor. reason is a rule name from app/risk/rules.py, never ticket text.
-- pause_agents writes the row whether or not it exists, so a missing row cannot leave the
-- agents running; the first reason is kept until someone resumes.
CREATE FUNCTION pause_agents(p_reason text) RETURNS void
LANGUAGE plpgsql SECURITY DEFINER SET search_path = public, pg_temp AS $$
BEGIN
    IF session_user <> 'risk_engine' THEN
        RAISE EXCEPTION '% may not pause the agents', session_user;
    END IF;
    INSERT INTO public.agent_control AS c (id, paused, reason)
    VALUES (1, true, left(coalesce(p_reason, ''), 200))
    ON CONFLICT (id) DO UPDATE SET paused = true, reason = excluded.reason, changed_at = now()
    WHERE NOT c.paused;
    IF FOUND THEN
        INSERT INTO public.events (kind, actor, detail)
        VALUES ('agents_paused', session_user, left(coalesce(p_reason, ''), 200));
    END IF;
END $$;

-- The event detail is the object id of the SeniorApprover who resumed.
CREATE FUNCTION resume_agents(p_oid uuid) RETURNS void
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
BEGIN
    IF session_user <> 'approver' THEN
        RAISE EXCEPTION '% may not resume the agents', session_user;
    END IF;
    IF NOT EXISTS (SELECT 1 FROM public.staff s
                   WHERE s.oid = p_oid AND s.active AND 'SeniorApprover' = ANY (s.roles)) THEN
        RAISE EXCEPTION 'only an active SeniorApprover on the staff list may resume the agents';
    END IF;
    UPDATE public.agent_control SET paused = false, reason = '', changed_at = now()
    WHERE id = 1 AND paused;
    IF FOUND THEN
        INSERT INTO public.events (kind, actor, detail) VALUES ('agents_resumed', session_user, p_oid::text);
    END IF;
END $$;

-- The only way an approval is written. The console calls it with the object id from the signed-in
-- person's token. It refuses an id that is not on the staff list or is inactive, and records the
-- highest role the list gives that person, never one the caller names. The request must still be
-- pending. Whether the tier allows an approval at all, and how many distinct people it needs, stay
-- with the console's check and check_approval_floor. The same person approving twice is refused
-- by the primary key (request_id, approver).
CREATE FUNCTION approve_request(p_request int, p_oid uuid) RETURNS void
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE
    v_roles  text[];
    v_role   text;
    v_status text;
BEGIN
    IF session_user <> 'approver' THEN
        RAISE EXCEPTION '% may not approve requests', session_user;
    END IF;
    SELECT s.roles INTO v_roles FROM public.staff s WHERE s.oid = p_oid AND s.active;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'approver is not on the staff list, or is inactive';
    END IF;
    v_role := CASE WHEN 'SeniorApprover' = ANY (v_roles) THEN 'SeniorApprover'
                   WHEN 'Approver' = ANY (v_roles) THEN 'Approver' END;
    IF v_role IS NULL THEN
        RAISE EXCEPTION 'approver has no approving role';
    END IF;
    SELECT r.status INTO v_status FROM public.action_requests r WHERE r.id = p_request;
    IF v_status IS DISTINCT FROM 'pending' THEN
        RAISE EXCEPTION 'request % is not pending', p_request;
    END IF;
    INSERT INTO public.approvals (request_id, approver, approver_role) VALUES (p_request, p_oid, v_role);
END $$;

-- How many distinct approvals a tier needs. No row means no number of approvals allows the
-- effect (HUMAN_ONLY, REJECT, or anything unknown).
CREATE FUNCTION required_approvals(p_tier text) RETURNS TABLE(n int)
LANGUAGE sql IMMUTABLE SET search_path = public, pg_temp AS $$
    SELECT v.n
    FROM (VALUES ('T0', 0), ('T1', 1), ('T2', 2)) AS v(tier, n)
    WHERE v.tier = p_tier;
$$;

-- The approval floor, raised from the credit and order triggers. It raises unless the request has
-- a risk assessment, the tier allows the effect, and enough distinct people approved it after the
-- assessment was written. An approval given
-- before the request had a tier was given without knowing the risk: a console that lets staff
-- approve early, or a hijacked one that approves everything in advance, cannot pre-pay the floor.
-- With p_after, only approvals given after that time count too (orders pass NULL).
-- One person counts once: the primary key already refuses the same approver twice, and the count
-- uses UUID identities, so alternative spellings cannot become separate people.
-- Not SECURITY DEFINER: it runs as the trigger's inserting role (executor), which reads
-- risk_assessments and approvals.
CREATE FUNCTION check_approval_floor(p_request int, p_after timestamptz) RETURNS void
LANGUAGE plpgsql SET search_path = public, pg_temp AS $$
DECLARE
    v_tier     text;
    v_assessed timestamptz;
    v_need     record;
    v_have     int;
BEGIN
    SELECT r.tier, r.created_at INTO v_tier, v_assessed
    FROM public.risk_assessments r WHERE r.request_id = p_request;
    IF v_tier IS NULL THEN
        RAISE EXCEPTION 'request % has no risk assessment', p_request;
    END IF;
    SELECT q.n INTO v_need FROM public.required_approvals(v_tier) q;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'request % is tier %, which no approval allows', p_request, v_tier;
    END IF;
    SELECT count(DISTINCT a.approver) INTO v_have
    FROM public.approvals a
    WHERE a.request_id = p_request
      AND a.created_at > v_assessed
      AND (p_after IS NULL OR a.created_at > p_after);
    IF v_have < v_need.n THEN
        RAISE EXCEPTION 'request % is tier % and needs % distinct %, has %',
            p_request, v_tier, v_need.n,
            CASE WHEN v_need.n = 1 THEN 'approval' ELSE 'approvals' END,
            v_have;
    END IF;
END $$;

-- Who reads and writes. Column lists on INSERT, so actor and created_at always come from the
-- defaults: nobody can forge who assessed or when.
GRANT SELECT ON risk_assessments TO executor, approver, risk_engine;
GRANT INSERT (request_id, tier, score, reasons, engine_version) ON risk_assessments TO risk_engine;
GRANT USAGE ON SEQUENCE risk_assessments_id_seq TO risk_engine;
GRANT SELECT, INSERT (lease_hash, tool, decision, reasons) ON call_assessments TO risk_engine;
GRANT USAGE ON SEQUENCE call_assessments_id_seq TO risk_engine;
GRANT SELECT ON agent_control TO gateway, risk_engine;

-- risk_owner holds exactly what pause_agents and resume_agents write.
GRANT SELECT, INSERT (id, paused, reason), UPDATE (paused, reason, changed_at) ON agent_control TO risk_owner;
GRANT INSERT (kind, actor, detail) ON events TO risk_owner;
GRANT USAGE ON SEQUENCE events_id_seq TO risk_owner;

ALTER FUNCTION pause_agents(text) OWNER TO risk_owner;
ALTER FUNCTION resume_agents(uuid) OWNER TO risk_owner;
ALTER FUNCTION required_approvals(text) OWNER TO risk_owner;
ALTER FUNCTION check_approval_floor(int, timestamptz) OWNER TO risk_owner;
REVOKE ALL ON FUNCTION pause_agents(text), resume_agents(uuid), required_approvals(text),
    check_approval_floor(int, timestamptz), refuse_assessment_change() FROM PUBLIC;
GRANT EXECUTE ON FUNCTION pause_agents(text) TO risk_engine;
GRANT EXECUTE ON FUNCTION resume_agents(uuid) TO approver;

-- The staff list belongs to staff_owner, which nobody logs in as. resume_agents (risk_owner) reads
-- three columns of it; approve_request (staff_owner) reads it as owner and writes only approvals.
-- No login role holds any privilege on the list.
ALTER TABLE staff OWNER TO staff_owner;
GRANT SELECT (oid, roles, active) ON staff TO risk_owner;
GRANT SELECT (id, status) ON action_requests TO staff_owner;
GRANT INSERT (request_id, approver, approver_role) ON approvals TO staff_owner;
ALTER FUNCTION approve_request(int, uuid) OWNER TO staff_owner;
REVOKE ALL ON FUNCTION approve_request(int, uuid) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION approve_request(int, uuid) TO approver;
GRANT EXECUTE ON FUNCTION required_approvals(text) TO executor, approver, risk_engine;
-- The executor runs the credit and order triggers, which call the floor.
GRANT EXECUTE ON FUNCTION check_approval_floor(int, timestamptz) TO executor;


-- ---------------------------------------------------------------------------------------------
-- Effects cannot be changed after the floor let them in.
--
-- check_credit and check_disconnection_order run on INSERT only. An UPDATE would skip them and
-- could move an approved credit to another amount, account or request, or an order to another
-- home. Nobody holds UPDATE on these tables (03-grants.sql); this trigger is the wall behind the
-- grants, so a grant added by mistake, or the superuser, is still refused. Statement-level, so it
-- refuses even an UPDATE that matches no row.
CREATE FUNCTION refuse_effect_change() RETURNS trigger
LANGUAGE plpgsql SET search_path = public, pg_temp AS $$
BEGIN
    RAISE EXCEPTION '% rows cannot be changed; file a new request instead', TG_TABLE_NAME;
END $$;

CREATE TRIGGER credits_no_update BEFORE UPDATE ON credits
    FOR EACH STATEMENT EXECUTE FUNCTION refuse_effect_change();
CREATE TRIGGER disconnection_orders_no_update BEFORE UPDATE ON disconnection_orders
    FOR EACH STATEMENT EXECUTE FUNCTION refuse_effect_change();


-- ---------------------------------------------------------------------------------------------
-- What the risk engine reads (app/risk/service.py).
--
-- The engine judges each tool call (POST /decide) and each pending effect request. It reads the
-- request queue, the charges (evidence) and its own call_assessments directly. Three things it
-- needs only a yes/no or a count of, so it gets a function instead of the table:
--
--   risk_lease_facts(hash, tool)  is this lease live, and does it list the tool? Not the ticket,
--                                 the tool list or the pod (lease_scope gives those to the gateway
--                                 and dispatcher). It takes sha256(lease), so the lease itself
--                                 never leaves the engine.
--   blocked_calls_on_ticket(t)    how many calls of runs on this ticket were blocked: a
--                                 call_assessments row with decision deny or pause, for a lease of
--                                 that ticket, except denials whose only cause was that every agent
--                                 was paused (reasons = {paused}); those say nothing about this
--                                 ticket. Calls the gateway blocks itself (tool_calls, 05-lease.sql)
--                                 do not count yet.
--   home_protection(request)      YES or NO for the home of one move-out request. The
--                                 flags say which homes have life-support equipment (health data);
--                                 the engine learns one category per move-out it assesses, not the
--                                 list. It answers only for a move-out that is still pending and
--                                 has no assessment yet, the one moment the engine needs it, and
--                                 raises for anything else (a credit, a decided or assessed request,
--                                 an unknown id): otherwise the engine could ask about any account
--                                 by pointing at an old request. YES when a flag row exists for the
--                                 home, else NO; nothing else is read.
--
-- Each is SECURITY DEFINER, owned by risk_owner, with a fixed search_path, granted to risk_engine
-- only, and checks session_user too, so a grant added by mistake is still refused.

CREATE FUNCTION risk_lease_facts(p_lease_hash bytea, p_tool text)
RETURNS TABLE(lease_live bool, tool_in_lease bool)
LANGUAGE plpgsql SECURITY DEFINER SET search_path = public, pg_temp AS $$
BEGIN
    IF session_user <> 'risk_engine' THEN
        RAISE EXCEPTION '% may not read lease facts', session_user;
    END IF;
    RETURN QUERY
        SELECT count(*) > 0, coalesce(bool_or(p_tool = ANY (l.allowed_tools)), false)
        FROM public.leases l
        WHERE l.token_hash = p_lease_hash AND NOT l.revoked AND l.expires_at > clock_timestamp();
END $$;

CREATE FUNCTION blocked_calls_on_ticket(p_ticket int) RETURNS int
LANGUAGE plpgsql SECURITY DEFINER SET search_path = public, pg_temp AS $$
BEGIN
    IF session_user <> 'risk_engine' THEN
        RAISE EXCEPTION '% may not count blocked calls', session_user;
    END IF;
    RETURN (
        SELECT count(*)::int
        FROM public.call_assessments c JOIN public.leases l ON l.token_hash = c.lease_hash
        WHERE l.ticket_id = p_ticket
          AND c.decision IN ('deny', 'pause')
          AND c.reasons IS DISTINCT FROM ARRAY['paused']
    ) + (
        SELECT count(*)::int FROM public.tool_calls c JOIN public.leases l ON l.token_hash = c.lease_hash
        WHERE l.ticket_id = p_ticket AND c.outcome = 'denied'
          AND c.reason IN ('unknown_tool', 'pod_mismatch', 'descriptor_changed')
    );
END $$;

CREATE FUNCTION home_protection(p_request int) RETURNS text
LANGUAGE plpgsql SECURITY DEFINER SET search_path = public, pg_temp AS $$
DECLARE
    v_home text;
BEGIN
    IF session_user <> 'risk_engine' THEN
        RAISE EXCEPTION '% may not read home protection', session_user;
    END IF;
    SELECT a.supply_point_id INTO v_home
    FROM public.action_requests r JOIN public.accounts a ON a.id = r.account_id
    WHERE r.id = p_request AND r.kind = 'move_out' AND r.status = 'pending'
      AND NOT EXISTS (SELECT 1 FROM public.risk_assessments k WHERE k.request_id = r.id);
    IF v_home IS NULL THEN
        RAISE EXCEPTION 'request % is not a pending move-out awaiting its assessment', p_request;
    END IF;
    IF EXISTS (SELECT 1 FROM public.flags f WHERE f.supply_point_id = v_home) THEN
        RETURN 'YES';
    END IF;
    RETURN 'NO';
END $$;

-- One allowed effect call per lease, in the database. The engine checks it (one_effect_per_ticket,
-- app/risk/rules.py), but two decisions on one lease at the same moment (a second engine replica)
-- could both read "no effect yet". This index lets only one of them in; the other retries and is
-- denied. The tool names are the short ones the leases list.
CREATE UNIQUE INDEX call_assessments_one_effect_per_lease ON call_assessments (lease_hash)
    WHERE decision = 'allow' AND tool IN ('request_disconnection', 'issue_bill_credit');

-- The engine's own reads. Column lists: only what app/risk/service.py asks for.
GRANT SELECT (id, kind, ticket_id, account_id, amount_eur, reason, evidence_ref, status, created_at, decided_at)
    ON action_requests TO risk_engine;
GRANT SELECT (id, account_id, period, amount_eur) ON charges TO risk_engine;
GRANT SELECT (lease_hash, outcome, reason) ON tool_calls TO risk_engine, risk_owner;

-- risk_owner holds exactly what the three functions read.
GRANT SELECT (token_hash, ticket_id, allowed_tools, expires_at, revoked) ON leases TO risk_owner;
GRANT SELECT (lease_hash, decision, reasons) ON call_assessments TO risk_owner;
-- finish_reply_facts (05-lease.sql, owner api_owner) counts effect-tool verdicts on the lease.
GRANT SELECT (lease_hash, tool) ON call_assessments TO api_owner;
GRANT SELECT (id, kind, account_id, status) ON action_requests TO risk_owner;
GRANT SELECT (request_id) ON risk_assessments TO risk_owner;
GRANT SELECT (id, supply_point_id) ON accounts TO risk_owner;
GRANT SELECT (supply_point_id) ON flags TO risk_owner;

ALTER FUNCTION risk_lease_facts(bytea, text) OWNER TO risk_owner;
ALTER FUNCTION blocked_calls_on_ticket(int) OWNER TO risk_owner;
ALTER FUNCTION home_protection(int) OWNER TO risk_owner;
REVOKE ALL ON FUNCTION risk_lease_facts(bytea, text), blocked_calls_on_ticket(int), home_protection(int),
    refuse_effect_change() FROM PUBLIC;
GRANT EXECUTE ON FUNCTION risk_lease_facts(bytea, text), blocked_calls_on_ticket(int), home_protection(int)
    TO risk_engine;


-- ---------------------------------------------------------------------------------------------
-- Heartbeats. Each long-running component writes its own row on every trip round its
-- loop, so monitoring can see a stopped component from the database too, not only from its
-- /healthz (which dies with it). Only through beat(): no login role has a grant on the table, and
-- beat() writes only the caller's own row, named from session_user (the role that logged in), so
-- a hijacked component cannot keep another one looking alive. last_beat is the database clock.
CREATE TABLE heartbeats (
    component text PRIMARY KEY,
    last_beat timestamptz NOT NULL
);

CREATE FUNCTION beat(p_component text) RETURNS void
LANGUAGE plpgsql SECURITY DEFINER SET search_path = public, pg_temp AS $$
DECLARE
    v_mine text := CASE session_user
        WHEN 'executor'      THEN 'executor'
        WHEN 'risk_engine'   THEN 'risk-engine'
        WHEN 'dispatcher'    THEN 'dispatcher'
        WHEN 'gateway'       THEN 'tool-gateway'
    END;
BEGIN
    IF v_mine IS NULL OR p_component IS DISTINCT FROM v_mine THEN
        RAISE EXCEPTION '% may not beat for %', session_user, coalesce(left(p_component, 40), 'NULL');
    END IF;
    INSERT INTO public.heartbeats AS h (component, last_beat) VALUES (v_mine, clock_timestamp())
    ON CONFLICT (component) DO UPDATE SET last_beat = excluded.last_beat;
END $$;

GRANT SELECT, INSERT (component, last_beat), UPDATE (last_beat) ON heartbeats TO risk_owner;
ALTER FUNCTION beat(text) OWNER TO risk_owner;
REVOKE ALL ON FUNCTION beat(text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION beat(text) TO executor, risk_engine, dispatcher, gateway;

-- Operational status only: the console cannot beat on a stopped component's behalf.
GRANT SELECT (component, last_beat) ON heartbeats TO approver;
GRANT SELECT (paused) ON agent_control TO approver;
GRANT SELECT (id, kind, actor, created_at) ON events TO approver;
GRANT UPDATE (status, decision_reason, decided_at) ON action_requests TO approver;

