-- Row-level security: a backstop behind the grants. Applied to every database after 05-lease.sql.
--
-- The tool roles have no table grants (03-grants.sql); they reach the data only through their
-- api_* function, which runs as api_owner. Should a table grant ever be added to a tool role by
-- mistake, RLS still shows it no row: FORCE applies the policies to the table owner too, and the
-- one policy names only the trusted roles. Superusers bypass RLS, as always in PostgreSQL.
-- Foreign key checks also bypass it, so the tables still reference each other normally.
--
-- The policy is USING (true): it does not scope rows per ticket. The per-ticket scope comes from
-- the lease checked inside each api_* function (05-lease.sql). A role that may read a table at
-- all (executor, approver, ...) keeps reading every row of it, as before.
--
-- The risk tables (06-risk.sql) are here too. They hold security decisions: a verdict a tool
-- could read would tell a hijacked agent which requests pass unseen, and one it could write would
-- skip the humans. No tool role has a grant on them; this keeps it so if one is added by mistake.
-- Heartbeats (06-risk.sql) too: a row a tool could write would keep a stopped component looking
-- alive. And the flags (07-flags.sql): they are health data, and a tool that could write one
-- outside api_set_temp_protection could change which homes look protected.
-- And tool_calls (05-lease.sql), the gateway's record of every call: a tool must not be able to
-- read what was refused or write a row that makes a refusal look like an answer.
-- And the dispatcher's agent_runs and replies (05-lease.sql): a tool must not be able to write the
-- reply a customer gets, or mark a run replied. And agent_events, the agent's report of its own drops.
DO $$
DECLARE
    t text;
BEGIN
    FOREACH t IN ARRAY ARRAY['tickets', 'customers', 'accounts', 'supply_points', 'action_requests', 'leases',
                            'risk_assessments', 'call_assessments', 'agent_control', 'heartbeats',
                            'flags',
                            'tool_calls', 'agent_runs', 'replies', 'agent_events']
    LOOP
        EXECUTE format('ALTER TABLE %I ENABLE ROW LEVEL SECURITY', t);
        EXECUTE format('ALTER TABLE %I FORCE ROW LEVEL SECURITY', t);
        EXECUTE format(
            'CREATE POLICY trusted_all ON %I FOR ALL TO executor, approver, risk_engine, dispatcher, '
            'gateway, api_owner, lease_owner, flags_writer, '
            'risk_owner '
            'USING (true) WITH CHECK (true)', t);
    END LOOP;
END $$;

-- approve_request (06-risk.sql, owner staff_owner) reads the status of one request, nothing else.
CREATE POLICY staff_owner_read ON action_requests FOR SELECT TO staff_owner USING (true);
