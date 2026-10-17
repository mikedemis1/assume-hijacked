-- Risk assessments, the agents' stop switch and the approval floor. Applied to every database
-- after 05-lease.sql. (Heartbeats join this file in task A5.)
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
--   HOLD        2 distinct SeniorApprovers a flood of move-outs; seniors release it
--   HUMAN_ONLY  never                      a person handles it outside this system
--   REJECT      never                      refused
--
-- check_credit and check_disconnection_order (01-schema.sql) call check_approval_floor on every
-- row they guard. So the executor cannot write a credit or an order the floor does not allow,
-- whatever its code does, and a console cannot make one person count twice. Only the risk engine
-- writes assessments, one per request, and nobody can change or delete one afterwards: a hijacked
-- executor or console cannot lower a tier after the fact.
--
-- What the database cannot check (decision 8, v1): that the person behind an approval holds the
-- role the console wrote. Staff do not log in to PostgreSQL; the console validates their Entra
-- token and records the object id and app role.

CREATE TABLE risk_assessments (
    id             serial PRIMARY KEY,
    request_id     int UNIQUE NOT NULL REFERENCES action_requests,
    tier           text NOT NULL CHECK (tier IN ('T0', 'T1', 'T2', 'HUMAN_ONLY', 'HOLD', 'REJECT')),
    score          int NOT NULL,
    reasons        text[] NOT NULL,
    engine_version text NOT NULL,
    actor          text NOT NULL DEFAULT current_user,
    created_at     timestamptz NOT NULL DEFAULT now()
);

-- One row per tool call the gateway asked about (POST /decide, task A5). lease_hash is
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

-- The stop switch for every agent run. The gateway and the risk engine read it on each tool
-- call. The one row is seeded unpaused (04-seed.sql); there is never a second.
CREATE TABLE agent_control (
    id         int PRIMARY KEY CHECK (id = 1),
    paused     bool NOT NULL,
    reason     text NOT NULL DEFAULT '',
    changed_at timestamptz NOT NULL DEFAULT now()
);

-- The risk engine pauses (repeated denials on one lease, decision 5). Only a person resumes:
-- the console calls resume_agents after it has checked the SeniorApprover role. Both functions
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

CREATE FUNCTION resume_agents() RETURNS void
LANGUAGE plpgsql SECURITY DEFINER SET search_path = public, pg_temp AS $$
BEGIN
    IF session_user <> 'approver' THEN
        RAISE EXCEPTION '% may not resume the agents', session_user;
    END IF;
    UPDATE public.agent_control SET paused = false, reason = '', changed_at = now()
    WHERE id = 1 AND paused;
    IF FOUND THEN
        INSERT INTO public.events (kind, actor, detail) VALUES ('agents_resumed', session_user, '');
    END IF;
END $$;

-- How many distinct approvals a tier needs, and whether they must be SeniorApprovers. No row
-- means no number of approvals allows the effect (HUMAN_ONLY, REJECT, or anything unknown).
CREATE FUNCTION required_approvals(p_tier text) RETURNS TABLE(n int, senior bool)
LANGUAGE sql IMMUTABLE SET search_path = public, pg_temp AS $$
    SELECT v.n, v.senior
    FROM (VALUES ('T0', 0, false), ('T1', 1, false), ('T2', 2, false), ('HOLD', 2, true))
         AS v(tier, n, senior)
    WHERE v.tier = p_tier;
$$;

-- The approval floor, raised from the credit and order triggers. It raises unless the request has
-- a risk assessment, the tier allows the effect, and enough distinct people approved it, each a
-- SeniorApprover when the tier asks for one. With p_after, only approvals given after that time
-- count (the occupier notice, for orders); NULL counts them all.
-- One person counts once: the primary key already refuses the same approver twice, and the count
-- folds case and surrounding white space, so 'Staff.Anna ' is still staff.anna.
-- Not SECURITY DEFINER: it runs as the trigger's inserting role (executor), which reads
-- risk_assessments and approvals.
CREATE FUNCTION check_approval_floor(p_request int, p_after timestamptz) RETURNS void
LANGUAGE plpgsql SET search_path = public, pg_temp AS $$
DECLARE
    v_tier text;
    v_need record;
    v_have int;
BEGIN
    SELECT r.tier INTO v_tier FROM public.risk_assessments r WHERE r.request_id = p_request;
    IF v_tier IS NULL THEN
        RAISE EXCEPTION 'request % has no risk assessment', p_request;
    END IF;
    SELECT q.n, q.senior INTO v_need FROM public.required_approvals(v_tier) q;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'request % is tier %, which no approval allows', p_request, v_tier;
    END IF;
    SELECT count(DISTINCT lower(btrim(a.approver, E' \t\r\n'))) INTO v_have
    FROM public.approvals a
    WHERE a.request_id = p_request
      AND (NOT v_need.senior OR a.approver_role = 'SeniorApprover')
      AND (p_after IS NULL OR a.created_at > p_after);
    IF v_have < v_need.n THEN
        RAISE EXCEPTION 'request % is tier % and needs % distinct %, has %',
            p_request, v_tier, v_need.n,
            CASE WHEN v_need.senior THEN 'SeniorApprover approvals'
                 WHEN v_need.n = 1 THEN 'approval'
                 ELSE 'approvals' END,
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
ALTER FUNCTION resume_agents() OWNER TO risk_owner;
ALTER FUNCTION required_approvals(text) OWNER TO risk_owner;
ALTER FUNCTION check_approval_floor(int, timestamptz) OWNER TO risk_owner;
REVOKE ALL ON FUNCTION pause_agents(text), resume_agents(), required_approvals(text),
    check_approval_floor(int, timestamptz), refuse_assessment_change() FROM PUBLIC;
GRANT EXECUTE ON FUNCTION pause_agents(text) TO risk_engine;
GRANT EXECUTE ON FUNCTION resume_agents() TO approver;
GRANT EXECUTE ON FUNCTION required_approvals(text) TO executor, approver, risk_engine;
-- The executor runs the credit and order triggers, which call the floor.
GRANT EXECUTE ON FUNCTION check_approval_floor(int, timestamptz) TO executor;
