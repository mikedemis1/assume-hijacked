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
DO $$
DECLARE
    t text;
BEGIN
    FOREACH t IN ARRAY ARRAY['tickets', 'customers', 'accounts', 'supply_points', 'action_requests', 'leases']
    LOOP
        EXECUTE format('ALTER TABLE %I ENABLE ROW LEVEL SECURITY', t);
        EXECUTE format('ALTER TABLE %I FORCE ROW LEVEL SECURITY', t);
        EXECUTE format(
            'CREATE POLICY trusted_all ON %I FOR ALL TO executor, approver, risk_engine, dispatcher, '
            'gateway, register_sync, api_owner, lease_owner, flags_writer, flags_admin '
            'USING (true) WITH CHECK (true)', t);
    END LOOP;
END $$;
