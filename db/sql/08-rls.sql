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
-- alive. And the register tables (07-register.sql): the flags are health data, and a tool that
-- could write register_sync or a removal request could make an unprotected home look checked.
-- And tool_calls (05-lease.sql), the gateway's record of every call: a tool must not be able to
-- read what was refused or write a row that makes a refusal look like an answer.
-- And the dispatcher's agent_runs and replies (05-lease.sql): a tool must not be able to write the
-- reply a customer gets, or mark a run replied.
DO $$
DECLARE
    t text;
BEGIN
    FOREACH t IN ARRAY ARRAY['tickets', 'customers', 'accounts', 'supply_points', 'action_requests', 'leases',
                            'risk_assessments', 'call_assessments', 'agent_control', 'heartbeats',
                            'flags', 'register_sync', 'flag_removal_requests', 'flag_removal_approvals',
                            'tool_calls', 'agent_runs', 'replies']
    LOOP
        EXECUTE format('ALTER TABLE %I ENABLE ROW LEVEL SECURITY', t);
        EXECUTE format('ALTER TABLE %I FORCE ROW LEVEL SECURITY', t);
        EXECUTE format(
            'CREATE POLICY trusted_all ON %I FOR ALL TO executor, approver, risk_engine, dispatcher, '
            'gateway, register_sync, api_owner, lease_owner, flags_writer, flags_admin, flags_remover, '
            'risk_owner '
            'USING (true) WITH CHECK (true)', t);
    END LOOP;
END $$;
